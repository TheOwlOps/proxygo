package chatcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// --- Narrow dependency interfaces (fakes in tests, adapters in prod) ---

// TransportOption is one entry of a provider's multi-endpoint transports
// list (services/provider.js resolveTransport). Auth is opaque here — the
// parent's executor adapter interprets it.
type TransportOption struct {
	Format    string
	BaseURL   string
	URLSuffix string
	Headers   map[string]string
	Auth      any
}

// RuntimeTransport is TransportOption as attached to a Credential
// (credentials.runtimeTransport in chatCore).
type RuntimeTransport = TransportOption

// ProviderInfo is chatcore's view of a provider (registry transport subset).
type ProviderInfo struct {
	ID          string
	Format      string // registry default format
	ForceStream bool
	NoAuth      bool
}

// ModelMeta is the per-(provider, model) data chatCore consults
// (config/providerModels.js getters).
type ModelMeta struct {
	TargetFormat     string   // getModelTargetFormat
	SupportedFormats []string // getModelSupportedFormats (nil = undeclared)
	UpstreamID       string   // getModelUpstreamId ("" = the model itself)
	Type             string   // getModelType: "imageGen" | "tts" | ""
}

// ProviderSource supplies provider/model/combo data.
type ProviderSource interface {
	// Provider resolves a provider id OR alias to its info.
	Provider(idOrAlias string) (ProviderInfo, bool)
	// ResolveProviderAlias maps an alias to a provider id (identity if none).
	ResolveProviderAlias(alias string) string
	// ResolveModelAlias resolves a bare model alias to provider/model.
	ResolveModelAlias(alias string) (provider, model string, ok bool)
	// ModelMeta returns per-model metadata (zero value when unknown).
	ModelMeta(providerID, model string) ModelMeta
	// TargetFormat is services/provider.js getTargetFormat.
	TargetFormat(providerID string, cred Credential) string
	// TransportFor returns the transport matching a format, or nil.
	TransportFor(providerID, format string) *TransportOption
	// Combo returns the member model strings for a combo name.
	Combo(name string) ([]string, bool)
}

// Credential is one provider connection, as threaded through the JS flow.
type Credential struct {
	ConnectionID     string
	ConnectionName   string
	APIKey           string
	AccessToken      string
	RefreshToken     string
	CopilotToken     string
	BaseURL          string
	ProjectID        string
	ExpiresAt        time.Time
	NoAuth           bool
	Specific         map[string]any
	RawHeaders       map[string]string
	RuntimeTransport *RuntimeTransport
	OverrideHeaders  map[string]string
}

// AllRateLimited is returned by Accounts.Next when every account is in
// cooldown (credentials.allRateLimited in src/sse/services/auth.js).
type AllRateLimited struct {
	LastError       string
	RetryAfter      time.Time
	RetryAfterHuman string
}

// Accounts is the credential store + account-health surface
// (src/sse/services/auth.js + tokenRefresh.js + usageDb markings).
type Accounts interface {
	// Next returns the next usable credential for the provider, skipping
	// excluded connection ids. A zero Credential (empty ConnectionID and
	// no tokens) with nil allRL means "no credentials exist".
	Next(provider string, exclude map[string]bool, model, requestedModel string) (Credential, *AllRateLimited, error)
	// RefreshIfNeeded ports checkAndRefreshToken (pre-flight expiry
	// refresh). Errors are non-fatal — return the input credential.
	RefreshIfNeeded(ctx context.Context, provider string, cred Credential) (Credential, error)
	// MarkUnavailable records the failure and reports whether the account
	// loop should fall back to the next account
	// (markAccountUnavailable().shouldFallback).
	MarkUnavailable(cred Credential, status int, errText, provider, model string, resetsAt time.Time) (shouldFallback bool)
	// ClearError clears the account's error state after a success
	// (clearAccountError + onRequestSuccess).
	ClearError(cred Credential, model string)
	// PersistRefreshed stores refreshed tokens (updateProviderCredentials
	// via onCredentialsRefreshed).
	PersistRefreshed(cred Credential, refreshed Credential) error
}

// Translator is Team A's surface, narrowed. TranslateRequest pivots
// through OpenAI like translator/index.js; stream translation wraps the
// upstream SSE body.
type Translator interface {
	TranslateRequest(from, to string, body map[string]any) (map[string]any, error)
	TranslateResponseBody(from, to string, body map[string]any) (map[string]any, error)
	NeedsTranslation(from, to string) bool
	WrapStream(r io.Reader, from, to string) io.Reader
}

// TokenSaver is the RTK hook (rtk/index.js compressMessages) — fail-open:
// implementations must never fail the request.
type TokenSaver interface {
	Compress(body map[string]any, format string, enabled bool)
}

// BodyGuard is the PII-redaction hook (Feature Pack F6) — fail-open:
// implementations must never fail the request. Process may mutate the
// body in place and returns the number of redactions applied.
type BodyGuard interface {
	Process(body map[string]any, format string, enabled bool) int
}

// KeyLimiter is the per-API-key rate-limit / budget hook (Feature Pack
// F3, internal/keylimit). Check runs after the API key is identified,
// before any upstream work; a nil return allows the request (RPM
// consumption happens inside Check when allowed). Nil field = disabled.
type KeyLimiter interface {
	Check(keyID string) *LimitRejection
}

// LimitRejection is a KeyLimiter denial: HTTP 429 rendered in the
// standard /v1 error envelope, with Type distinguishing
// rate_limit_exceeded from budget_exceeded.
type LimitRejection struct {
	Status  int
	Type    string // rate_limit_exceeded | budget_exceeded
	Message string
}

// Response renders the rejection as an OpenAI-style error response.
func (r *LimitRejection) Response() *http.Response {
	status := r.Status
	if status == 0 {
		status = StatusRateLimited
	}
	body := BuildErrorBody(status, r.Message)
	if r.Type != "" {
		if e, ok := body["error"].(map[string]any); ok {
			e["type"] = r.Type
			e["code"] = r.Type
		}
	}
	raw, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header: http.Header{
			"Content-Type":                []string{"application/json"},
			"Access-Control-Allow-Origin": []string{"*"},
		},
		Body: io.NopCloser(strings.NewReader(string(raw))),
	}
}

// Executor runs one upstream attempt (internal/executors under the hood).
type Executor interface {
	Execute(ctx context.Context, provider string, info ProviderInfo, cred Credential, body []byte) (*ExecResult, error)
}

// ExecResult mirrors executors.ExecResult.
type ExecResult struct {
	Response        *http.Response
	URL             string
	Headers         map[string]string
	TransformedBody []byte
	ResponseFormat  string
}

// ExecutorErrorParser is optionally implemented by the Executor adapter to
// surface executor parseError results (codex/antigravity resets).
type ExecutorErrorParser interface {
	ParseError(provider string, status int, bodyText string) *ParsedErrorLike
}

// TokenRefresher performs ONE refresh attempt for a provider credential
// (executor.refreshCredentials). chatcore adds the retry loop
// (services/tokenRefresh.js refreshWithRetry). Returns (nil, nil) when
// refresh is impossible or produced nothing usable.
type TokenRefresher interface {
	Refresh(ctx context.Context, provider string, cred Credential) (*Credential, error)
}

// Settings is the subset of dashboard settings the chat flow reads.
type Settings struct {
	RequireAPIKey       bool
	CCFilterNaming      bool
	RTKEnabled          bool
	PIIRedactionEnabled bool
	ComboStrategy       string // global fallback strategy
	ComboStickyLimit    int
	ComboStrategies     map[string]ComboStrategy
	ProviderThinking    map[string]ThinkingConfig
	ProviderOverrides   map[string]ProviderOverride
}

type ComboStrategy struct {
	FallbackStrategy string
	JudgeModel       string // fusion only (not ported — see combo.go)
}

type ThinkingConfig struct{ Mode string } // auto|on|off|none|low|medium|high

type ProviderOverride struct {
	Headers map[string]string
}

// SettingsSource supplies Settings (nil = zero settings).
type SettingsSource interface{ Settings() Settings }

// APIKeyValidator validates a client API key (services/auth.js
// isValidApiKey). KeyAccessEnforcer applies per-key model restrictions
// (services/keyAccess.js enforceKeyAccess) and returns a denial response
// or nil.
type APIKeyValidator interface{ ValidAPIKey(key string) bool }
type KeyAccessEnforcer interface {
	EnforceKeyAccess(apiKey, modelStr string) *http.Response
}

// Logger is the minimal request logger (src/sse/utils/logger.js subset).
type Logger interface {
	Debug(tag, msg string)
	Info(tag, msg string)
	Warn(tag, msg string)
	Error(tag, msg string)
}

type noopLogger struct{}

func (noopLogger) Debug(string, string) {}
func (noopLogger) Info(string, string)  {}
func (noopLogger) Warn(string, string)  {}
func (noopLogger) Error(string, string) {}

// SleepFunc is the sleeper for refresh/combo delays; replaceable in tests.
var SleepFunc = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error { return SleepFunc(ctx, d) }

// CircuitBreaker is the Feature Pack F2 hook: a per-(provider,
// connection) circuit breaker consulted by the account loop in
// handleSingleModel. Allow=false excludes the credential for this
// request; OnResult reports each attempt's outcome (success = no
// transport error and upstream status < 500 — 429 counts as success,
// rate limits are the cooldown layer's job). Nil on the Service =
// disabled, behavior identical to before the feature.
type CircuitBreaker interface {
	Allow(provider, connID string) bool
	OnResult(provider, connID string, success bool)
}

// Service is the chat flow. Providers and Executor are required; every
// other dependency is optional and degrades like the JS feature flags.
type Service struct {
	Providers  ProviderSource
	Translator Translator
	Executor   Executor
	Accounts   Accounts
	Refresher  TokenRefresher
	TokenSaver TokenSaver
	BodyGuard  BodyGuard
	Breaker    CircuitBreaker
	KeyLimiter KeyLimiter
	// UsageSink receives one UsageEvent per finished attempt
	// (usage recording — the JS saveUsageStats/saveRequestDetail
	// pair). Nil disables recording entirely.
	UsageSink func(UsageEvent)
	Settings  SettingsSource
	Keys      APIKeyValidator
	KeyAccess KeyAccessEnforcer
	// BypassCheck ports utils/bypassHandler.js handleBypassRequest
	// (warmup/title-generation short-circuits); nil = no bypasses.
	BypassCheck func(body map[string]any, model, userAgent string, ccFilterNaming bool) *http.Response
	Logger      Logger

	rotation *comboRotationState
}

// NewService builds a Service with its combo rotation state.
func NewService(s Service) *Service {
	s.rotation = newComboRotationState()
	return &s
}

// BreakerSnapshot returns the circuit breaker's per-key stats for the
// dashboard API, or nil when no breaker is wired (or the wired breaker
// does not expose stats).
func (s *Service) BreakerSnapshot() any {
	if s == nil || s.Breaker == nil {
		return nil
	}
	if sp, ok := s.Breaker.(interface{ Snapshot() any }); ok {
		return sp.Snapshot()
	}
	return nil
}

func (s *Service) log() Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return noopLogger{}
}

func (s *Service) settings() Settings {
	if s.Settings != nil {
		return s.Settings.Settings()
	}
	return Settings{}
}

// ChatRequest is one inbound chat request (already JSON-decoded by the
// server layer).
type ChatRequest struct {
	Body      map[string]any
	Endpoint  string            // request path (source-format detection)
	Headers   map[string]string // lower-cased header names
	APIKey    string
	UserAgent string
}

// HandleChat ports src/sse/handlers/chat.js handleChat: API-key gate,
// combo expansion, then the single-model account loop.
func (s *Service) HandleChat(ctx context.Context, req ChatRequest) (*http.Response, error) {
	if s.rotation == nil {
		s.rotation = newComboRotationState()
	}
	body := req.Body
	if body == nil {
		return ErrorResponse(StatusBadRequest, "Invalid JSON body", nil), nil
	}
	settings := s.settings()

	// Claude Code's [1m] context marker must not reach model resolution.
	modelStr, _ := StripModelContextMarker(strOf(body["model"]))
	if modelStr != strOf(body["model"]) {
		body = cloneBody(body)
		body["model"] = modelStr
	}

	// Enforce API key when enabled in settings.
	if settings.RequireAPIKey {
		if req.APIKey == "" {
			s.log().Warn("AUTH", "Missing API key (requireApiKey=true)")
			return ErrorResponse(StatusUnauthorized, "Missing API key", nil), nil
		}
		if s.Keys != nil && !s.Keys.ValidAPIKey(req.APIKey) {
			s.log().Warn("AUTH", "Invalid API key (requireApiKey=true)")
			return ErrorResponse(StatusUnauthorized, "Invalid API key", nil), nil
		}
	}

	if modelStr == "" {
		s.log().Warn("CHAT", "Missing model")
		return ErrorResponse(StatusBadRequest, "Missing model", nil), nil
	}

	// Per-key access control, checked once on the requested target before
	// bypass, combo expansion and any credential lookup.
	if s.KeyAccess != nil {
		if denied := s.KeyAccess.EnforceKeyAccess(req.APIKey, modelStr); denied != nil {
			return denied, nil
		}
	}

	// Per-key rate limit + budgets (Feature Pack F3): checked once the
	// key is identified, before bypass, combo expansion and any upstream
	// work. Nil limiter or no key presented = no-op.
	if s.KeyLimiter != nil && req.APIKey != "" {
		if rej := s.KeyLimiter.Check(req.APIKey); rej != nil {
			s.log().Warn("AUTH", "API key limit exceeded: "+rej.Message)
			return rej.Response(), nil
		}
	}

	// Bypass naming/warmup requests before combo rotation so they don't
	// waste rotation slots.
	if s.BypassCheck != nil {
		if bypass := s.BypassCheck(body, modelStr, req.UserAgent, settings.CCFilterNaming); bypass != nil {
			return bypass, nil
		}
	}

	// Combo? (getComboModels)
	if s.Providers != nil {
		if comboModels, ok := s.Providers.Combo(modelStr); ok && len(comboModels) > 0 {
			strategy := s.comboStrategyFor(settings, modelStr)
			// NOTE: the "fusion" strategy (panel + judge) is not ported
			// in this phase — it degrades to the fallback loop.
			return s.HandleCombo(ctx, req, comboModels, modelStr, strategy, settings.ComboStickyLimit,
				func(ctx context.Context, r ChatRequest, m string) *http.Response {
					resp, _ := s.handleSingleModel(ctx, r, m, "")
					return resp
				}), nil
		}
	}

	resp, _ := s.handleSingleModel(ctx, req, modelStr, "")
	return resp, nil
}

func (s *Service) comboStrategyFor(settings Settings, comboName string) string {
	if cs, ok := settings.ComboStrategies[comboName]; ok && cs.FallbackStrategy != "" {
		return cs.FallbackStrategy
	}
	if settings.ComboStrategy != "" {
		return settings.ComboStrategy
	}
	return "fallback"
}

// resolveModel ports getModelInfo (services/model.js getModelInfoCore via
// src/sse/services/model.js): provider/model split, model-alias
// resolution, builtin aliases, prefix inference.
func (s *Service) resolveModel(modelStr string) ModelInfo {
	var resolveAlias func(string) string
	if s.Providers != nil {
		resolveAlias = s.Providers.ResolveProviderAlias
	}
	parsed := ParseModelString(modelStr, resolveAlias)
	if !parsed.IsAlias {
		return parsed
	}
	if s.Providers != nil {
		if provider, model, ok := s.Providers.ResolveModelAlias(parsed.Model); ok {
			return ModelInfo{Provider: provider, Model: model}
		}
	}
	if builtin, ok := builtinModelAliases[parsed.Model]; ok {
		p, m := splitProviderModel(builtin)
		if resolveAlias != nil {
			p = resolveAlias(p)
		}
		return ModelInfo{Provider: p, Model: m}
	}
	return ModelInfo{Provider: InferProviderFromModelName(parsed.Model), Model: parsed.Model}
}

// handleSingleModel ports handleSingleModelChat: resolve the model, then
// the account-selection loop over handleChatCore outcomes.
func (s *Service) handleSingleModel(ctx context.Context, req ChatRequest, modelStr, requestedModel string) (*http.Response, error) {
	modelInfo := s.resolveModel(modelStr)

	// Provider unresolvable → maybe a nested combo (a combo member that
	// is itself a combo), else a client error.
	if modelInfo.Provider == "" {
		if s.Providers != nil {
			if comboModels, ok := s.Providers.Combo(modelStr); ok && len(comboModels) > 0 {
				settings := s.settings()
				strategy := s.comboStrategyFor(settings, modelStr)
				return s.HandleCombo(ctx, req, comboModels, modelStr, strategy, settings.ComboStickyLimit,
					func(ctx context.Context, r ChatRequest, m string) *http.Response {
						resp, _ := s.handleSingleModel(ctx, r, m, "")
						return resp
					}), nil
			}
		}
		s.log().Warn("CHAT", "Invalid model format")
		return ErrorResponse(StatusBadRequest, "Invalid model format", nil), nil
	}

	provider, model := modelInfo.Provider, modelInfo.Model
	info := ProviderInfo{ID: provider}
	if s.Providers != nil {
		if pi, ok := s.Providers.Provider(provider); ok {
			info = pi
		}
	}

	// No credential store wired: a single anonymous attempt (local mode).
	if s.Accounts == nil {
		outcome := s.core(ctx, req, info, model, Credential{})
		return outcome.response, nil
	}

	exclude := map[string]bool{}
	var lastError string
	var lastStatus int
	var lastHeaders http.Header

	for {
		if ctx.Err() != nil {
			return ErrorResponse(StatusClientClosedRequest, "Request aborted", nil), nil
		}
		cred, allRL, err := s.Accounts.Next(provider, exclude, model, firstNonEmpty(requestedModel, model))
		if err != nil {
			return ErrorResponse(StatusBadGateway, FormatProviderError(err, provider, model, StatusBadGateway), nil), nil
		}
		if allRL != nil {
			msg := lastError
			if msg == "" {
				msg = allRL.LastError
			}
			if msg == "" {
				msg = "Unavailable"
			}
			return UnavailableResponse(StatusServiceUnavailable,
				"["+provider+"/"+model+"] "+msg, allRL.RetryAfter, allRL.RetryAfterHuman, lastHeaders), nil
		}
		if cred.ConnectionID == "" && cred.APIKey == "" && cred.AccessToken == "" {
			if len(exclude) == 0 {
				s.log().Warn("AUTH", "No active credentials for provider: "+provider)
				return ErrorResponse(StatusNotFound, "No active credentials for provider: "+provider, nil), nil
			}
			msg := lastError
			if msg == "" {
				msg = "All accounts unavailable"
			}
			status := lastStatus
			if status == 0 {
				status = StatusServiceUnavailable
			}
			return ErrorResponse(status, msg, lastHeaders), nil
		}

		// Circuit breaker (Feature Pack F2): an open circuit excludes
		// this credential exactly like a selection exclusion — the loop
		// moves on to the next account (or the all-unavailable result).
		if s.Breaker != nil && cred.ConnectionID != "" && !s.Breaker.Allow(provider, cred.ConnectionID) {
			s.log().Warn("FALLBACK", "ACC:"+cred.ConnectionName+" CIRCUIT OPEN → NEXT ACCOUNT")
			exclude[cred.ConnectionID] = true
			continue
		}

		// Pre-flight token refresh (checkAndRefreshToken). The Accounts
		// contract returns the input credential unchanged on failure.
		if refreshed, rerr := s.Accounts.RefreshIfNeeded(ctx, provider, cred); rerr == nil {
			cred = refreshed
		}

		attemptStart := time.Now()
		outcome := s.core(ctx, req, info, model, cred)
		if s.Breaker != nil && cred.ConnectionID != "" {
			// Success = the upstream answered with no transport error
			// and a status below 500. Transport errors surface from
			// core as 502, so they fail; 429 passes as success (the
			// breaker ignores rate limits); a client abort (499) is a
			// transport outcome, not an upstream success.
			s.Breaker.OnResult(provider, cred.ConnectionID,
				outcome.success || (outcome.status < 500 && outcome.status != StatusClientClosedRequest))
		}
		if outcome.success {
			s.Accounts.ClearError(cred, model)
			if outcome.response != nil && outcome.response.Body != nil {
				outcome.response.Body = s.recordUsageTap(req, provider, model, cred.ConnectionID,
					outcome.response.Body, outcome.response.Header.Get("Content-Type"), attemptStart)
			}
			return outcome.response, nil
		}

		shouldFallback := s.Accounts.MarkUnavailable(cred, outcome.status, outcome.errorText, provider, model, outcome.resetsAt)
		if shouldFallback {
			s.log().Warn("FALLBACK", "ACC:"+cred.ConnectionName+" UNAVAILABLE ("+itoa(outcome.status)+") → NEXT ACCOUNT")
			exclude[cred.ConnectionID] = true
			lastError = outcome.errorText
			lastStatus = outcome.status
			if outcome.response != nil {
				lastHeaders = passthroughHeaders(outcome.response.Header)
			}
			continue
		}
		// Terminal failure for this account with no fallback: record
		// the failed attempt (JS records it as a request detail too).
		s.recordUsageError(req, provider, model, cred.ConnectionID, attemptStart)
		return outcome.response, nil
	}
}

// outcome is the internal form of the JS chatCore result
// {success, status, error, response, resetsAtMs}.
type outcome struct {
	success   bool
	status    int
	errorText string
	resetsAt  time.Time
	response  *http.Response
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func cloneBody(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }

var errAborted = errors.New("request aborted")

// passthroughHeaders selects the upstream headers the JS forwards on
// errors (utils/upstreamHeaders.js upstreamResponseHeaders — retry hints
// and provider metadata; hop-by-hop headers never pass).
func passthroughHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := http.Header{}
	for k, vs := range h {
		lk := strings.ToLower(k)
		if lk == "retry-after" || strings.HasPrefix(lk, "x-ratelimit") || strings.HasPrefix(lk, "x-9router") {
			out[k] = vs
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneResponseBody(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if err != nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return raw
}

func drainBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
