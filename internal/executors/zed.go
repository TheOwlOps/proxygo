package executors

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"proxygo/internal/translator"
)

// ZedExecutor ports open-sse/executors/zed.js (+ shared/zedAuth.js):
// Zed's hosted LLM aggregator at cloud.zed.dev. The wire protocol does NOT
// fit the Base pipeline, so Execute is overridden entirely like the JS:
//
//   - The requested model is resolved against the live GET /models catalog
//     (cached 1h) to learn which upstream Zed fronts for it — Anthropic,
//     OpenAI, Google or xAI — because the provider_request body and the
//     response chunks are shaped in that provider's native format.
//   - Auth is a two-step exchange: the connection's long-lived access
//     token (RSA-decrypted at login time; the executor only ever sees the
//     plaintext) is presented as `Authorization: <userId> <accessToken>`
//     to POST /client/llm_tokens (after resolving the organization via
//     GET /client/users/me when the connection doesn't pin one), yielding
//     a short-lived LLM bearer token (cached 50min) for /completions and
//     /models. A 401 or an x-zed-expired-token / x-zed-outdated-token
//     response header forces one token refresh + retry (zedLlmFetch).
//   - POST /completions carries a thread envelope
//     {thread_id, prompt_id, provider, model, provider_request} where
//     provider_request is the OpenAI body translated into the fronted
//     provider's format via internal/translator (the JS calls the same
//     translator functions directly) and provider is the wire spelling
//     Zed matches exactly: anthropic / open_ai / google / x_ai.
//   - The response is an NDJSON-ish line stream of {"event": <chunk>} /
//     {"status": ...} / [DONE] frames; events are translated back to
//     OpenAI chat chunks (xAI events are already OpenAI-shaped and pass
//     through), so ResponseFormat is "openai".
//
// refreshCredentials is a no-op in the JS (long-lived token, no OAuth
// refresh) — the inherited Base behaviour (nil, nil) matches.

type ZedExecutor struct{ *Base }

func NewZedExecutor() *ZedExecutor {
	z := &ZedExecutor{}
	z.Base = &Base{ProviderID: "zed", Hooks: Hooks{
		ParseError: zedParseError,
	}}
	return z
}

// Zed wire values for the payload `provider` field (zed.js ZED_PROVIDER).
// cloud.zed.dev matches these exactly; an unrecognized value fails the
// whole request with a generic 500 before the model is looked at.
const (
	zedProviderAnthropic = "anthropic"
	zedProviderOpenAI    = "open_ai"
	zedProviderGoogle    = "google"
	zedProviderXAI       = "x_ai"
)

const (
	zedDefaultCloudBase = "https://cloud.zed.dev"
	zedDefaultVersion   = "0.200.0" // JS fallback for config.appVersion

	zedHeaderExpiredToken      = "x-zed-expired-token"
	zedHeaderOutdatedToken     = "x-zed-outdated-token"
	zedHeaderClientStatus      = "x-zed-client-supports-status-messages"
	zedHeaderClientStreamEnded = "x-zed-client-supports-stream-ended-request-completion-status"
	zedHeaderClientSupportsXai = "x-zed-client-supports-x-ai"
	zedHeaderSystemID          = "x-zed-system-id"
	zedLLMTokenTTL             = 50 * time.Minute // LLM_TOKEN_TTL_MS
	zedModelCacheTTL           = time.Hour        // MODEL_CACHE_TTL_MS
)

// --- caches (zedAuth.js module-level Maps) ---

type zedLLMTokenEntry struct {
	token     string
	expiresAt time.Time
}

type zedModelCatalog struct {
	rawByID   map[string]map[string]any
	expiresAt time.Time
}

var (
	zedCacheMu       sync.Mutex
	zedLLMTokenCache = map[string]*zedLLMTokenEntry{}
	zedModelCache    = map[string]*zedModelCatalog{}
)

// zedClearCaches mirrors clearZedCaches (used by tests).
func zedClearCaches() {
	zedCacheMu.Lock()
	defer zedCacheMu.Unlock()
	zedLLMTokenCache = map[string]*zedLLMTokenEntry{}
	zedModelCache = map[string]*zedModelCatalog{}
}

// zedCloudBase resolves the cloud base URL: ProviderInfo.Raw overrides
// (llmBaseUrl / cloudBaseUrl, the JS executor config keys), else the
// registry transport baseUrl (…/completions) with the path stripped,
// else the production default.
func zedCloudBase(p *ProviderInfo) string {
	if p != nil {
		if v := p.RawString("llmBaseUrl"); v != "" {
			return strings.TrimSuffix(v, "/")
		}
		if v := p.RawString("cloudBaseUrl"); v != "" {
			return strings.TrimSuffix(v, "/")
		}
		base := strings.TrimSuffix(p.BaseURL, "/")
		base = strings.TrimSuffix(base, "/completions")
		if base != "" {
			return base
		}
	}
	return zedDefaultCloudBase
}

// zedNormalizeProvider ports normalizeZedProvider: catalog provider value
// first, model-name inference as the fallback.
func zedNormalizeProvider(value, model string) string {
	raw := strings.ToLower(value)
	switch raw {
	case "anthropic":
		return zedProviderAnthropic
	case "openai", "open_ai":
		return zedProviderOpenAI
	case "google", "gemini":
		return zedProviderGoogle
	case "xai", "x_ai", "x-ai":
		return zedProviderXAI
	}
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "claude"):
		return zedProviderAnthropic
	case strings.Contains(m, "gemini"):
		return zedProviderGoogle
	case strings.Contains(m, "grok") || strings.Contains(m, "xai"):
		return zedProviderXAI
	}
	return zedProviderOpenAI
}

// zedFormatForProvider maps a wire provider to the translator format of
// its request/response shapes (zed.js initProviderState / FORMATS).
func zedFormatForProvider(provider string) string {
	switch provider {
	case zedProviderAnthropic:
		return translator.FormatClaude
	case zedProviderGoogle:
		return translator.FormatGemini
	case zedProviderOpenAI:
		return translator.FormatOpenAIResponses
	}
	return translator.FormatOpenAI
}

// --- user auth + organization (zedAuth.js) ---

// zedUserAuthHeader ports buildZedUserAuthHeader:
// "<userId> <accessToken>".
func zedUserAuthHeader(cred Credential) (string, error) {
	userID := cred.SpecificString("userId")
	token := cred.AccessToken
	if token == "" {
		token = cred.APIKey
	}
	if userID == "" || token == "" {
		return "", errors.New("Zed credential is missing userId or accessToken")
	}
	return userID + " " + token, nil
}

func zedSystemID(cred Credential) string {
	return cred.SpecificString("systemId")
}

// zedNormalizeOrgID ports normalizeOrganizationId: a string, a
// single-element array, or an {id} object.
func zedNormalizeOrgID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	case map[string]any:
		if s, ok := t["id"].(string); ok {
			return s
		}
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
	return ""
}

// zedResolveOrgID ports resolveZedOrganizationId: explicit connection
// value first, then the user record's default org, then the personal
// (or first) organization.
func zedResolveOrgID(cred Credential, userInfo map[string]any) string {
	if v := cred.Specific["organizationId"]; v != nil {
		if s := zedNormalizeOrgID(v); s != "" {
			return s
		}
	}
	if v := cred.Specific["defaultOrganizationId"]; v != nil {
		if s := zedNormalizeOrgID(v); s != "" {
			return s
		}
	}
	if userInfo == nil {
		return ""
	}
	if s := zedNormalizeOrgID(userInfo["default_organization_id"]); s != "" {
		return s
	}
	if s := zedNormalizeOrgID(userInfo["defaultOrganizationId"]); s != "" {
		return s
	}
	orgs, _ := userInfo["organizations"].([]any)
	var first map[string]any
	for _, raw := range orgs {
		org, _ := raw.(map[string]any)
		if org == nil {
			continue
		}
		if first == nil {
			first = org
		}
		if b, _ := org["is_personal"].(bool); b {
			return zedNormalizeOrgID(org["id"])
		}
	}
	if first != nil {
		return zedNormalizeOrgID(first["id"])
	}
	return ""
}

// zedFetchJSON is fetchJson from zedAuth.js: JSON in/out, non-2xx becomes
// an error carrying the upstream message.
func zedFetchJSON(ctx context.Context, method, url string, headers map[string]string, body []byte) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if len(raw) > 0 {
		if uerr := unmarshalJSON(raw, &data); uerr != nil || data == nil {
			data = map[string]any{"raw": string(raw)}
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := getStr(data, "message")
		if msg == "" {
			if e, ok := data["error"].(map[string]any); ok {
				msg = getStr(e, "message")
			}
		}
		if msg == "" {
			if s, ok := data["error"].(string); ok {
				msg = s
			}
		}
		if msg == "" {
			msg = string(raw)
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, &zedUpstreamError{Status: resp.StatusCode, Message: msg}
	}
	return data, nil
}

type zedUpstreamError struct {
	Status  int
	Message string
}

func (e *zedUpstreamError) Error() string { return e.Message }

// zedFetchUser ports fetchZedAuthenticatedUser (GET /client/users/me).
func zedFetchUser(ctx context.Context, p *ProviderInfo, cred Credential) (map[string]any, error) {
	auth, err := zedUserAuthHeader(cred)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Accept": "application/json", "Authorization": auth}
	if sid := zedSystemID(cred); sid != "" {
		headers[zedHeaderSystemID] = sid
	}
	return zedFetchJSON(ctx, http.MethodGet, zedCloudBase(p)+"/client/users/me", headers, nil)
}

func zedUserCacheKey(cred Credential, orgID string) string {
	userID := cred.SpecificString("userId")
	if userID == "" {
		userID = "unknown"
	}
	token := cred.AccessToken
	if token == "" {
		token = cred.APIKey
	}
	suffix := token
	if len(suffix) > 16 {
		suffix = suffix[len(suffix)-16:]
	}
	org := orgID
	if org == "" {
		org = "default"
	}
	return userID + ":" + org + ":" + suffix
}

func zedModelCacheKey(cred Credential) string {
	org := zedResolveOrgID(cred, nil)
	if org == "" {
		org = "default"
	}
	userID := cred.SpecificString("userId")
	if userID == "" {
		userID = "unknown"
	}
	token := cred.AccessToken
	if token == "" {
		token = cred.APIKey
	}
	suffix := token
	if len(suffix) > 16 {
		suffix = suffix[len(suffix)-16:]
	}
	return userID + ":" + org + ":" + suffix
}

// zedFetchLLMToken ports fetchZedLlmToken: resolve the org (fetching the
// user record when needed), then POST /client/llm_tokens. Tokens are
// cached for 50 minutes per (user, org, token suffix).
func zedFetchLLMToken(ctx context.Context, p *ProviderInfo, cred Credential, forceRefresh bool) (string, error) {
	orgID := zedResolveOrgID(cred, nil)
	if orgID == "" {
		user, err := zedFetchUser(ctx, p, cred)
		if err != nil {
			return "", err
		}
		orgID = zedResolveOrgID(cred, user)
	}
	if orgID == "" {
		return "", errors.New("No Zed organization selected")
	}
	key := zedUserCacheKey(cred, orgID)
	if !forceRefresh {
		zedCacheMu.Lock()
		if e := zedLLMTokenCache[key]; e != nil && e.expiresAt.After(time.Now()) {
			tok := e.token
			zedCacheMu.Unlock()
			return tok, nil
		}
		zedCacheMu.Unlock()
	}
	auth, err := zedUserAuthHeader(cred)
	if err != nil {
		return "", err
	}
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"Authorization": auth,
	}
	if sid := zedSystemID(cred); sid != "" {
		headers[zedHeaderSystemID] = sid
	}
	body, _ := marshalJSON(map[string]any{"organization_id": orgID})
	data, err := zedFetchJSON(ctx, http.MethodPost, zedCloudBase(p)+"/client/llm_tokens", headers, body)
	if err != nil {
		return "", err
	}
	token := zedTokenValue(data["token"])
	if token == "" {
		return "", errors.New("Zed did not return an LLM token")
	}
	zedCacheMu.Lock()
	zedLLMTokenCache[key] = &zedLLMTokenEntry{token: token, expiresAt: time.Now().Add(zedLLMTokenTTL)}
	zedCacheMu.Unlock()
	return token, nil
}

// zedTokenValue unwraps the token field: a string, [string], or {value}.
func zedTokenValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	case map[string]any:
		if s, ok := t["value"].(string); ok {
			return s
		}
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
	return ""
}

func zedShouldRefreshLLMToken(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == 401 {
		return true
	}
	_, hasExpired := resp.Header[http.CanonicalHeaderKey(zedHeaderExpiredToken)]
	_, hasOutdated := resp.Header[http.CanonicalHeaderKey(zedHeaderOutdatedToken)]
	return hasExpired || hasOutdated
}

// zedLLMRequest ports zedLlmFetch: perform a request against the cloud
// base with the LLM bearer token; on an expired-token signal, refresh
// the token and retry exactly once.
func zedLLMRequest(ctx context.Context, p *ProviderInfo, cred Credential, method, path string, headers map[string]string, body []byte) (*http.Response, error) {
	build := func(force bool) (*http.Response, error) {
		token, err := zedFetchLLMToken(ctx, p, cred, force)
		if err != nil {
			return nil, err
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, zedCloudBase(p)+path, rdr)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return HTTPClient.Do(req)
	}
	resp, err := build(false)
	if err != nil {
		return nil, err
	}
	if zedShouldRefreshLLMToken(resp) {
		drainClose(resp)
		resp2, err := build(true)
		if err != nil {
			return nil, err
		}
		return resp2, nil
	}
	return resp, nil
}

// --- model catalog (resolveZedModels) ---

// zedNormalizeModelID ports normalizeZedModelId: string, [string], {id}.
func zedNormalizeModelID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	case map[string]any:
		if s, ok := t["id"].(string); ok {
			return s
		}
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
	return ""
}

// zedResolveModels ports resolveZedModels: live catalog fetch (GET
// /models through the LLM-token exchange), cached 1h. Returns nil, nil
// when the credential carries no access token (JS behaviour).
func zedResolveModels(ctx context.Context, p *ProviderInfo, cred Credential, forceRefresh bool) (*zedModelCatalog, error) {
	if cred.AccessToken == "" {
		return nil, nil
	}
	key := zedModelCacheKey(cred)
	if !forceRefresh {
		zedCacheMu.Lock()
		if c := zedModelCache[key]; c != nil && c.expiresAt.After(time.Now()) {
			zedCacheMu.Unlock()
			return c, nil
		}
		zedCacheMu.Unlock()
	}
	resp, err := zedLLMRequest(ctx, p, cred, http.MethodGet, "/models", map[string]string{
		"Accept":                   "application/json",
		zedHeaderClientSupportsXai: "true",
	}, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Zed models failed: %d %s", resp.StatusCode, string(raw))
	}
	var data map[string]any
	if uerr := unmarshalJSON(raw, &data); uerr != nil || data == nil {
		return nil, fmt.Errorf("Zed models failed: invalid catalog JSON")
	}
	cat := &zedModelCatalog{rawByID: map[string]map[string]any{}, expiresAt: time.Now().Add(zedModelCacheTTL)}
	if models, ok := data["models"].([]any); ok {
		for _, rawModel := range models {
			m, _ := rawModel.(map[string]any)
			if m == nil {
				continue
			}
			if id := zedNormalizeModelID(m["id"]); id != "" {
				cat.rawByID[id] = m
			}
		}
	}
	zedCacheMu.Lock()
	zedModelCache[key] = cat
	zedCacheMu.Unlock()
	return cat, nil
}

// zedResolveModelProvider ports ZedExecutor.resolveModel: catalog lookup,
// one forced refresh on a miss, model-name inference on any failure.
func (z *ZedExecutor) zedResolveModelProvider(ctx context.Context, p *ProviderInfo, cred Credential, model string) string {
	lookup := func(force bool) (map[string]any, bool) {
		cat, err := zedResolveModels(ctx, p, cred, force)
		if err != nil || cat == nil {
			return nil, false
		}
		raw, ok := cat.rawByID[model]
		return raw, ok
	}
	raw, found := lookup(false)
	if !found {
		raw, found = lookup(true)
	}
	providerValue := ""
	if found && raw != nil {
		providerValue = getStr(raw, "provider")
	}
	return zedNormalizeProvider(providerValue, model)
}

// --- request building (buildProviderRequest) ---

// zedBuildProviderRequest ports buildProviderRequest: translate the
// OpenAI body into the fronted provider's native request shape. The JS
// passes stream=true literally to the Claude/Gemini/Responses
// translators, mirrored by pinning stream on the clone.
func zedBuildProviderRequest(provider, model string, body map[string]any, stream bool) (map[string]any, error) {
	switch provider {
	case zedProviderAnthropic:
		in := cloneMap(body)
		in["stream"] = true
		return translator.TranslateRequest(translator.FormatOpenAI, translator.FormatClaude, in)
	case zedProviderGoogle:
		in := cloneMap(body)
		in["stream"] = true
		out, err := translator.TranslateRequest(translator.FormatOpenAI, translator.FormatGemini, in)
		if err != nil {
			return nil, err
		}
		// Zed's hosted Gemini backend speaks the Vertex safety
		// vocabulary, not the public Gemini enum — drop client-side
		// safetySettings so Zed applies its own defaults (zed.js).
		delete(out, "safetySettings")
		return out, nil
	case zedProviderOpenAI:
		in := cloneMap(body)
		in["stream"] = true
		return translator.TranslateRequest(translator.FormatOpenAI, translator.FormatOpenAIResponses, in)
	default: // xAI is OpenAI-shaped — forward as-is.
		out := cloneMap(body)
		if out == nil {
			out = map[string]any{}
		}
		out["model"] = model
		out["stream"] = stream
		return out, nil
	}
}

// --- execute ---

func (z *ZedExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "zed"}
	}
	bodyMap, _ := decodeBody(body)
	if bodyMap == nil {
		bodyMap = map[string]any{}
	}
	model := ModelOf(bodyMap)
	provider := z.zedResolveModelProvider(ctx, p, cred, model)

	// The JS execute() receives chatCore's stream flag, which mirrors
	// the client body: `stream !== false` for the xAI passthrough.
	stream := true
	if v, ok := bodyMap["stream"].(bool); ok {
		stream = v
	}
	providerReq, err := zedBuildProviderRequest(provider, model, bodyMap, stream)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{
		"provider":         provider,
		"model":            model,
		"provider_request": providerReq,
	}
	if tid, ok := bodyMap["thread_id"]; ok && tid != nil {
		payload["thread_id"] = tid
	} else if sid := cred.SpecificString("_clientSessionId"); sid != "" {
		payload["thread_id"] = sid
	} else if sid := cred.SpecificString("clientSessionId"); sid != "" {
		payload["thread_id"] = sid
	}
	if pid, ok := bodyMap["prompt_id"]; ok && pid != nil {
		payload["prompt_id"] = pid
	}
	payloadBytes, err := marshalJSON(payload)
	if err != nil {
		return nil, err
	}

	version := p.RawString("appVersion")
	if version == "" {
		version = zedDefaultVersion
	}
	headers := map[string]string{
		"Content-Type":             "application/json",
		"Accept":                   "application/x-ndjson, text/event-stream, */*",
		"User-Agent":               "proxygo/zed",
		"x-zed-version":            version,
		zedHeaderClientStatus:      "true",
		zedHeaderClientStreamEnded: "true",
	}
	resp, err := zedLLMRequest(ctx, p, cred, http.MethodPost, "/completions", headers, payloadBytes)
	if err != nil {
		return nil, err
	}
	result := &ExecResult{
		Response: resp,
		URL:      zedCloudBase(p) + "/completions",
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer <zed-llm-token>", // placeholder, as in the JS result
		},
		TransformedBody: payloadBytes,
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Response = zedWrapCompletionStream(resp, provider, model)
		result.ResponseFormat = "openai"
	}
	return result, nil
}

// zedParseError ports ZedExecutor.parseError.
func zedParseError(status int, bodyText string) *ParsedError {
	var parsed map[string]any
	if uerr := unmarshalJSON([]byte(bodyText), &parsed); uerr != nil {
		parsed = nil
	}
	var errObj map[string]any
	if parsed != nil {
		errObj, _ = parsed["error"].(map[string]any)
	}
	code := getStr(parsed, "code")
	if code == "" {
		code = getStr(errObj, "code")
	}
	rawMessage := getStr(parsed, "message")
	if rawMessage == "" {
		rawMessage = getStr(errObj, "message")
	}
	if rawMessage == "" {
		rawMessage = bodyText
	}
	if rawMessage == "" {
		rawMessage = http.StatusText(status)
	}
	if code == "trial_blocked" {
		return &ParsedError{Status: status, Message: "Zed trial access is blocked upstream. The account can list hosted models, but Zed is refusing completions until trial/billing access is enabled or unblocked. Zed says: " + rawMessage}
	}
	if code != "" {
		return &ParsedError{Status: status, Message: "Zed " + code + ": " + rawMessage}
	}
	msg := rawMessage
	if msg == "" {
		msg = fmt.Sprintf("Zed upstream error: %d", status)
	}
	return &ParsedError{Status: status, Message: msg}
}

// --- response stream wrap (wrapZedCompletionStream) ---

// zedUnwrapLine ports unwrapZedLine: one NDJSON line → {event} /
// {status} / {done} / nil.
type zedLinePayload struct {
	event     any
	hasEvent  bool
	status    any
	hasStatus bool
	done      bool
}

func zedUnwrapLine(line string) *zedLinePayload {
	text := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if text == "" {
		return nil
	}
	if strings.HasPrefix(text, "data:") {
		text = strings.TrimSpace(strings.TrimPrefix(text, "data:"))
	}
	if text == "[DONE]" {
		return &zedLinePayload{done: true}
	}
	var parsed any
	if err := unmarshalJSON([]byte(text), &parsed); err != nil {
		return nil
	}
	if m, ok := parsed.(map[string]any); ok {
		if v, present := m["event"]; present {
			return &zedLinePayload{event: v, hasEvent: true}
		}
		if v, present := m["status"]; present {
			return &zedLinePayload{status: v, hasStatus: true}
		}
	}
	return &zedLinePayload{event: parsed, hasEvent: true}
}

// zedNormalizeStatus ports normalizeStatus.
func zedNormalizeStatus(status any) map[string]any {
	switch s := status.(type) {
	case string:
		return map[string]any{"type": s}
	case map[string]any:
		if f, ok := s["failed"].(map[string]any); ok {
			out := map[string]any{"type": "failed"}
			for k, v := range f {
				out[k] = v
			}
			return out
		}
		return s
	}
	return nil
}

func zedErrorChunk(model, message string) map[string]any {
	now := time.Now()
	return map[string]any{
		"id":      fmt.Sprintf("chatcmpl-zed-error-%d", now.UnixMilli()),
		"object":  "chat.completion.chunk",
		"created": now.Unix(),
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{"content": "[Zed error] " + message},
			"finish_reason": "stop",
		}},
	}
}

// zedConvertEvent ports convertProviderEvent: a provider-shaped event →
// OpenAI chunks via the translator stream converters. A nil event is the
// end-of-stream flush. xAI/OpenAI events pass through untouched.
func zedConvertEvent(provider string, event any, state *translator.StreamState) []map[string]any {
	format := zedFormatForProvider(provider)
	if format == translator.FormatOpenAI {
		if event == nil {
			return nil
		}
		if m, ok := event.(map[string]any); ok {
			return []map[string]any{m}
		}
		return nil
	}
	chunk, _ := event.(map[string]any)
	if event != nil && chunk == nil {
		return nil // non-object event in a translated format: drop (JS translator would reject it)
	}
	out, err := translator.TranslateStreamChunk(format, translator.FormatOpenAI, chunk, state)
	if err != nil {
		return nil
	}
	return out
}

func zedWrapCompletionStream(resp *http.Response, provider, model string) *http.Response {
	pr, pw := io.Pipe()
	go func() {
		err := zedConvertStream(resp.Body, pw, provider, model)
		resp.Body.Close()
		_ = pw.CloseWithError(err)
	}()
	return &http.Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header: http.Header{
			"Content-Type":  []string{"text/event-stream"},
			"Cache-Control": []string{"no-cache"},
		},
		Body: pr,
	}
}

func zedConvertStream(r io.Reader, w io.Writer, provider, model string) error {
	state := translator.NewStreamState(zedFormatForProvider(provider))
	if provider == zedProviderXAI {
		state.Model = model // initProviderState sets model only for the OpenAI branch
	}
	done := false
	emit := func(chunks []map[string]any) {
		for _, c := range chunks {
			if c == nil {
				continue
			}
			raw, err := marshalJSON(c)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", raw)
		}
	}
	finish := func() {
		if done {
			return
		}
		emit(zedConvertEvent(provider, nil, state))
		io.WriteString(w, "data: [DONE]\n\n")
		done = true
	}
	processLine := func(line string) {
		if done {
			return
		}
		payload := zedUnwrapLine(line)
		if payload == nil {
			return
		}
		if payload.done {
			finish()
			return
		}
		if payload.hasStatus {
			status := zedNormalizeStatus(payload.status)
			if status == nil {
				return
			}
			_, hasFailed := status["failed"]
			if status["type"] == "failed" || hasFailed {
				failed, _ := status["failed"].(map[string]any)
				if failed == nil {
					failed = status
				}
				message := getStr(failed, "message")
				if message == "" {
					message = getStr(failed, "error")
				}
				if message == "" {
					message = getStr(failed, "code")
				}
				if message == "" {
					message = "request failed"
				}
				emit([]map[string]any{zedErrorChunk(model, message)})
				finish()
			} else if status["type"] == "stream_ended" {
				finish()
			}
			return
		}
		if payload.hasEvent {
			emit(zedConvertEvent(provider, payload.event, state))
		}
	}

	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			processLine(strings.TrimSuffix(line, "\n"))
		}
		if err != nil {
			break
		}
	}
	finish()
	return nil
}
