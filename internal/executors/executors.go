// Package executors is the Go port of open-sse/executors/.
//
// Design note (decoupling): the JS executors read the provider registry
// (PROVIDERS) directly. Here every executor receives a self-contained
// *ProviderInfo per call, so this package does not import Team B's
// internal/providers. The parent wires an adapter:
//
//	providers.Provider  ->  executors.ProviderInfo
//	(ID, Transport.BaseURL/BaseURLs?, Format, URLSuffix, Headers, ForceStream,
//	 Raw["auth"] -> Auth, Raw["retry"] -> Retry, Raw["timeoutMs"], Raw quirks,
//	 Raw["oauth"] clientId/clientSecret/tokenUrl used by refresh grants)
//
// ProviderInfo.BaseURLs is not in Team B's Transport struct (single BaseURL +
// URLSuffix there); multi-endpoint providers (kiro) carry their list in Raw
// under "baseUrls" in the JS registry — the adapter should map it here.
package executors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// Credential is one provider connection's secrets + routing data.
// Port of the JS `credentials` object threaded through chatCore/executors
// (open-sse/handlers/chatCore.js, src/sse/services/auth.js getProviderCredentials).
type Credential struct {
	ConnectionID   string
	ConnectionName string
	APIKey         string
	AccessToken    string
	RefreshToken   string
	// CopilotToken is the short-lived token exchanged from a GitHub token
	// (executors/github.js uses credentials.copilotToken || accessToken).
	CopilotToken string
	// BaseURL mirrors providerSpecificData.baseUrl (per-connection endpoint
	// override used by openai-compatible-*/anthropic-compatible-* nodes).
	BaseURL string
	// ProjectID mirrors credentials.projectId (gemini-cli, antigravity, vertex).
	ProjectID string
	// ExpiresAt is the access-token expiry when known (needs-refresh checks).
	ExpiresAt time.Time
	// NoAuth mirrors executor.noAuth (chatCore skips the refresh path for
	// noAuth providers, chatCore.js: "skip for noAuth providers").
	NoAuth bool
	// Specific is providerSpecificData, preserved verbatim.
	Specific map[string]any
	// RawHeaders are the client's original headers (credentials.rawHeaders),
	// used for anthropic-beta passthrough and claude session-id extraction.
	RawHeaders map[string]string
	// RuntimeTransport is set by chatcore when a multi-endpoint provider has a
	// transport matching the source format (credentials.runtimeTransport).
	RuntimeTransport *TransportOverride
	// OverrideHeaders are per-provider user header overrides from settings
	// (providerOverrides.headers in chatCore) — applied last, they win.
	OverrideHeaders map[string]string
}

// SpecificString reads a string from providerSpecificData.
func (c Credential) SpecificString(key string) string {
	if c.Specific == nil {
		return ""
	}
	if s, ok := c.Specific[key].(string); ok {
		return s
	}
	return ""
}

// TransportOverride mirrors one entry of a registry `transports[]` list as
// resolved by services/provider.js resolveTransport().
type TransportOverride struct {
	BaseURL   string
	URLSuffix string
	Format    string
	Headers   map[string]string
	Auth      *AuthSpec
}

// AuthBranch is one side of a split auth descriptor: {header, scheme}.
type AuthBranch struct {
	Header string `json:"header"`
	Scheme string `json:"scheme"` // "bearer" | "raw"
}

// AuthSpec mirrors registry transport.auth (see executors/default.js
// AUTH_DESCRIPTORS / applyAuth). Two shapes exist in the JS registries:
//   - combined: {combined:true, header, scheme} — one token slot, header is
//     always set (legacy behaviour, even for an empty token).
//   - split: {apiKey:{header,scheme}, oauth:{header,scheme}} — only the
//     branch matching the credential kind is set.
type AuthSpec struct {
	Combined bool        `json:"combined"`
	Header   string      `json:"header"`
	Scheme   string      `json:"scheme"`
	APIKey   *AuthBranch `json:"apiKey"`
	OAuth    *AuthBranch `json:"oauth"`
	// AnthropicVersion: also ensure an anthropic-version header
	// (default.js applyAuth sets ANTHROPIC_API_VERSION when flagged).
	AnthropicVersion bool `json:"anthropicVersion"`
	// Hooks names header hooks in default.js HEADER_HOOKS:
	// kimiHeaders, minimaxHeaders, museHeaders, clineHeaders, kilocodeOrg.
	Hooks []string `json:"hooks"`
}

// RetryEntry mirrors one DEFAULT_RETRY_CONFIG entry (config/runtimeConfig.js):
// {attempts, delayMs}. A bare number in JS means attempts with the legacy
// 2000ms delay — the adapter should normalise that into this struct.
type RetryEntry struct {
	Attempts int
	DelayMs  int
}

// ProviderInfo is everything an executor needs to know about a provider.
// Built by the parent's adapter from Team B's providers.Provider (+Raw).
type ProviderInfo struct {
	ID          string
	BaseURL     string
	BaseURLs    []string // multi-endpoint fallback list (base.js getBaseUrls)
	Format      string   // registry transport.format: openai|claude|gemini|kiro|...
	URLSuffix   string   // registry transport.urlSuffix, e.g. "?beta=true"
	Headers     map[string]string
	ForceStream bool
	NoAuth      bool
	Auth        *AuthSpec
	// Retry is the per-status retry config (config.retry merged over
	// DEFAULT_RETRY_CONFIG by base.js execute()).
	Retry map[int]RetryEntry
	// TimeoutMs is the connect timeout (config.timeoutMs ||
	// FETCH_CONNECT_TIMEOUT_MS=60000).
	TimeoutMs int
	// Quirks is registry transport.quirks, preserved (e.g. dropClientMetadata).
	Quirks map[string]any
	// OAuth client credentials for refresh grants (registry oauth block /
	// PROVIDERS[provider].clientId/clientSecret in the JS config).
	ClientID     string
	ClientSecret string
	// TokenURL is the OAuth token endpoint (registry oauth.tokenUrl).
	TokenURL string
	// Raw preserves every other registry field (endpoints like github's
	// messagesUrl/responsesUrl, gemini-cli's apiClient, transports, ...).
	Raw map[string]any
}

// RawString reads a string field from Raw.
func (p *ProviderInfo) RawString(key string) string {
	if p == nil || p.Raw == nil {
		return ""
	}
	if s, ok := p.Raw[key].(string); ok {
		return s
	}
	return ""
}

// BaseURLs returns the fallback URL list (base.js getBaseUrls:
// config.baseUrls || [config.baseUrl]).
func (p *ProviderInfo) BaseURLsList() []string {
	if p == nil {
		return nil
	}
	if len(p.BaseURLs) > 0 {
		return p.BaseURLs
	}
	if p.BaseURL != "" {
		return []string{p.BaseURL}
	}
	return nil
}

// ExecResult mirrors the JS executor result {response, url, headers,
// transformedBody} plus responseFormat (chatCore.js: result.responseFormat,
// e.g. cursor/commandcode executors emit OpenAI-shaped output regardless of
// the provider's registry format).
type ExecResult struct {
	Response        *http.Response
	URL             string
	Headers         map[string]string // headers actually sent upstream
	TransformedBody []byte            // body actually sent upstream
	ResponseFormat  string            // "" = provider's registry format
}

// Executor is the contract surface (GO_CONTRACT.md Team D).
type Executor interface {
	Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error)
}

// Refresher is implemented by executors that can refresh credentials
// (JS refreshCredentials). Returns nil, nil when refresh is not possible —
// base.js's default. chatcore calls it through its own TokenRefresher
// interface; the parent adapts.
type Refresher interface {
	RefreshCredentials(ctx context.Context, p *ProviderInfo, cred Credential) (*Credential, error)
}

// ErrorParser is implemented by executors with a parseError override
// (codex usage_limit resets, antigravity quota resets, gemini-cli RetryInfo).
type ErrorParser interface {
	ParseError(status int, bodyText string) *ParsedError
}

// ParsedError mirrors the JS parseError result {status, message, resetsAtMs}.
type ParsedError struct {
	Status     int
	Message    string
	ResetsAt   time.Time // zero when unknown
	RetryAfter string    // gemini-cli RetryInfo retryDelay string, when present
}

// Request is the per-call state threaded through executor hooks (the JS
// executors stash per-request state on `this`, e.g. codex _isCompact,
// gemini-cli _currentModel; Go executors are shared, so state lives here).
type Request struct {
	Provider *ProviderInfo
	Cred     Credential
	Model    string
	Stream   bool
	Body     map[string]any // decoded request body (nil when not a JSON object)
	RawBody  []byte
	State    map[string]any // hook-private scratch space
}

// BodyMap decodes a JSON body into a map, preserving unknown fields.
// Returns nil when the body is not a JSON object.
func BodyMap(b []byte) map[string]any {
	m, _ := decodeBody(b)
	return m
}

func decodeBody(b []byte) (map[string]any, bool) {
	if len(b) == 0 {
		return nil, false
	}
	var m map[string]any
	dec := jsonDecoder(b)
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// StreamRequested reports whether the (translated) body asks for streaming.
func StreamRequested(body map[string]any) bool {
	if body == nil {
		return false
	}
	s, _ := body["stream"].(bool)
	return s
}

// ModelOf extracts body.model.
func ModelOf(body map[string]any) string {
	if body == nil {
		return ""
	}
	s, _ := body["model"].(string)
	return s
}

// newUUID returns a random RFC-4122 v4 UUID (JS crypto.randomUUID()).
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is effectively unreachable; fall back to time.
		n := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(n >> (8 * (i % 8)))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var sb strings.Builder
	hexes := hex.EncodeToString(b[:])
	sb.WriteString(hexes[0:8] + "-" + hexes[8:12] + "-" + hexes[12:16] + "-" + hexes[16:20] + "-" + hexes[20:32])
	return sb.String()
}

// getStr is a small typed accessor for map[string]any values.
func getStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// cloneMap shallow-copies a decoded JSON body so transforms never mutate the
// caller's map (JS executors mutate the shared body; chatcore retries with
// the same translatedBody, so the Go port keeps one pristine copy per call
// and clones per upstream attempt, matching base.js transform-per-URL).
func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
