package executors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ParamStripper, when set by the parent, ports
// translator/concerns/paramSupport.js stripUnsupportedParams (it lives with
// Team A's translator data). Nil = no stripping (the JS strips based on
// per-provider capability tables; behaviour difference is documented in the
// Team D report as an adapter the parent must wire).
var ParamStripper func(providerID, model string, body map[string]any)

// ReasoningInjector, when set by the parent, ports
// utils/reasoningContentInjector.js injectReasoningContent. Nil = body
// passes through unchanged.
var ReasoningInjector func(providerID, model string, body map[string]any) map[string]any

// DefaultExecutor is the port of open-sse/executors/default.js: it handles
// any provider whose registry transport is a plain HTTP endpoint (the vast
// majority — every OpenAI/Claude/Gemini-compatible upstream).
type DefaultExecutor struct {
	*Base
}

// NewDefaultExecutor builds a DefaultExecutor for a provider id.
func NewDefaultExecutor(providerID string) *DefaultExecutor {
	d := &DefaultExecutor{}
	d.Base = &Base{ProviderID: providerID, Hooks: Hooks{
		BuildURL:      d.buildURL,
		BuildHeaders:  d.buildHeaders,
		TransformBody: d.transformBody,
		Refresh:       refreshFromGrantOrSpecial,
	}}
	return d
}

// buildURL ports DefaultExecutor.buildUrl (default.js):
// runtimeTransport → openai-compatible-* → anthropic-compatible-* →
// gemini format (model:action) → urlSuffix → {accountId} substitution.
func (d *DefaultExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	p := req.Provider
	cred := req.Cred
	if rt := cred.RuntimeTransport; rt != nil && rt.BaseURL != "" {
		if rt.URLSuffix != "" {
			return rt.BaseURL + rt.URLSuffix, nil
		}
		return rt.BaseURL, nil
	}
	if strings.HasPrefix(b.ProviderID, "openai-compatible-") {
		base := cred.BaseURL
		if base == "" {
			base = openAICompatBase
		}
		path := "/chat/completions"
		if resolveOpenAICompatibleAPIType(b.ProviderID, cred) == "responses" {
			path = "/responses"
		}
		return strings.TrimSuffix(base, "/") + path, nil
	}
	if strings.HasPrefix(b.ProviderID, "anthropic-compatible-") {
		base := cred.BaseURL
		if base == "" {
			base = anthropicCompatBase
		}
		return strings.TrimSuffix(base, "/") + "/messages", nil
	}
	// gemini-format: build :streamGenerateContent / :generateContent path.
	if p.Format == "gemini" {
		action := "generateContent"
		if req.Stream {
			action = "streamGenerateContent?alt=sse"
		}
		return p.BaseURL + "/" + req.Model + ":" + action, nil
	}
	if p.URLSuffix != "" {
		return p.BaseURL + p.URLSuffix, nil
	}
	u := p.BaseURL
	if strings.Contains(u, "{accountId}") {
		accountID := cred.SpecificString("accountId")
		if accountID == "" {
			return "", &MissingAccountIDError{Provider: b.ProviderID}
		}
		u = strings.Replace(u, "{accountId}", accountID, 1)
	}
	return u, nil
}

// MissingAccountIDError mirrors the JS throw in buildUrl for {accountId} URLs.
type MissingAccountIDError struct{ Provider string }

func (e *MissingAccountIDError) Error() string {
	return e.Provider + " requires accountId in providerSpecificData"
}

// buildHeaders ports DefaultExecutor.buildHeaders (default.js): registry (or
// runtimeTransport) headers + auth descriptor, anthropic-beta merging for
// claude / claude-model anthropic-compatible nodes, Claude OAuth session-id
// alignment, and identity-header stripping for third-party
// anthropic-compatible gateways.
func (d *DefaultExecutor) buildHeaders(b *Base, req *Request, _ string) (map[string]string, error) {
	p := req.Provider
	cred := req.Cred
	rt := cred.RuntimeTransport
	headers := map[string]string{"Content-Type": "application/json"}
	src := p.Headers
	if rt != nil {
		src = rt.Headers
	}
	for k, v := range src {
		headers[k] = v
	}
	var desc *AuthSpec
	switch {
	case rt != nil && rt.Auth != nil:
		desc = rt.Auth
	case p.Auth != nil:
		desc = p.Auth
	default:
		desc = resolveAuthDescriptor(b.ProviderID, p)
	}
	applyAuth(headers, desc, cred)

	// Anthropic-Beta for the claude provider (and claude models behind
	// anthropic-compatible nodes): the JS selects betas per model/body
	// (providers/shared.js selectAnthropicBeta) — the registry header set
	// already carries the full list for `claude`, so here we merge the
	// client's anthropic-beta over it (mergeAnthropicBeta).
	isClaudeModel := strings.HasPrefix(req.Model, "claude-")
	clientBeta := cred.RawHeaders["anthropic-beta"]
	if req.Model != "" && (b.ProviderID == "claude" ||
		(strings.HasPrefix(b.ProviderID, "anthropic-compatible-") && isClaudeModel)) {
		headers["Anthropic-Beta"] = mergeAnthropicBeta(headers["Anthropic-Beta"], clientBeta)
	} else if b.ProviderID == "anthropic" && clientBeta != "" {
		headers["Anthropic-Beta"] = mergeAnthropicBeta(headers["Anthropic-Beta"], clientBeta)
	}

	// Claude OAuth: align x-claude-code-session-id with
	// metadata.user_id.session_id when the header is missing and the token
	// is an OAuth token (sk-ant-oat…).
	if b.ProviderID == "claude" && headers["x-claude-code-session-id"] == "" {
		token := cred.AccessToken
		if token == "" {
			token = cred.APIKey
		}
		if strings.Contains(token, "sk-ant-oat") {
			if sid := claudeSessionIDFromUserID(req.Body); sid != "" {
				headers["x-claude-code-session-id"] = sid
			}
		}
	}

	// Third-party anthropic-compatible gateways: send Bearer alongside
	// x-api-key and strip first-party Claude Code identity headers
	// (default.js, incl. removing claude-code-20250219 from beta lists).
	if strings.HasPrefix(b.ProviderID, "anthropic-compatible-") {
		base := cred.BaseURL
		isOfficial := base == "" || strings.Contains(base, "api.anthropic.com")
		if !isOfficial {
			if cred.APIKey != "" && headers["Authorization"] == "" {
				headers["Authorization"] = "Bearer " + cred.APIKey
			}
			delete(headers, "anthropic-dangerous-direct-browser-access")
			delete(headers, "Anthropic-Dangerous-Direct-Browser-Access")
			delete(headers, "x-app")
			delete(headers, "X-App")
			for _, key := range []string{"anthropic-beta", "Anthropic-Beta"} {
				if v, ok := headers[key]; ok {
					var kept []string
					for _, f := range strings.Split(v, ",") {
						f = strings.TrimSpace(f)
						if f != "" && f != "claude-code-20250219" {
							kept = append(kept, f)
						}
					}
					if len(kept) > 0 {
						headers[key] = strings.Join(kept, ",")
					} else {
						delete(headers, key)
					}
				}
			}
		}
	}

	if req.Stream {
		headers["Accept"] = "text/event-stream"
	}
	return headers, nil
}

var claudeSessionIDRe = regexp.MustCompile(`"session_id"\s*:\s*"([^"]+)"`)

// claudeSessionIDFromUserID ports utils/claudeCloaking.js
// extractClaudeSessionIdFromUserId: metadata.user_id is a JSON string
// carrying session_id.
func claudeSessionIDFromUserID(body map[string]any) string {
	if body == nil {
		return ""
	}
	meta, _ := body["metadata"].(map[string]any)
	if meta == nil {
		return ""
	}
	uid, _ := meta["user_id"].(string)
	if uid == "" {
		return ""
	}
	if m := claudeSessionIDRe.FindStringSubmatch(uid); m != nil {
		return m[1]
	}
	return ""
}

// transformBody ports DefaultExecutor.transformRequest: json_schema
// fallback + Nous attribution, dropClientMetadata quirk, then the
// param-strip / reasoning-inject hooks (wired by the parent, see vars).
func (d *DefaultExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	out := d.applyJSONSchemaFallback(b.ProviderID, d.applyNousAttribution(b, req, body))
	if out != nil {
		if q, _ := req.Provider.Quirks["dropClientMetadata"].(bool); q {
			delete(out, "client_metadata")
		}
		if ParamStripper != nil {
			ParamStripper(b.ProviderID, req.Model, out)
		}
	}
	if ReasoningInjector != nil {
		out = ReasoningInjector(b.ProviderID, req.Model, out)
	}
	return out, nil
}

// applyNousAttribution ports applyNousAttribution (default.js +
// config/appConstants.js NOUS_ATTRIBUTION): only for openai-compatible-*
// nodes pointing at the Nous inference host's /v1/chat/completions.
var nousTags = []string{"product=9router", "client=9router", "user=9router"}

func (d *DefaultExecutor) applyNousAttribution(b *Base, req *Request, body map[string]any) map[string]any {
	if !strings.HasPrefix(b.ProviderID, "openai-compatible-") || req.Cred.APIKey == "" {
		return body
	}
	if tags, present := body["tags"]; present && tags != nil {
		if _, isArr := tags.([]any); !isArr {
			return body
		}
	}
	u, err := d.buildURL(b, req, 0)
	if err != nil {
		return body
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme != "https" ||
		parsed.Hostname() != "inference-api.nousresearch.com" ||
		parsed.Path != "/v1/chat/completions" {
		return body
	}
	var tags []any
	if t, ok := body["tags"].([]any); ok {
		tags = append(tags, t...)
	}
	for _, fallback := range nousTags {
		prefix := fallback[:strings.Index(fallback, "=")+1]
		var filtered []any
		for _, tag := range tags {
			if s, ok := tag.(string); ok && strings.HasPrefix(s, prefix) && strings.TrimSpace(s[len(prefix):]) != "" {
				continue // non-empty attribution value already present
			}
			filtered = append(filtered, tag)
		}
		tags = filtered
		found := false
		for _, tag := range tags {
			if s, ok := tag.(string); ok && strings.HasPrefix(s, prefix) {
				found = true
			}
		}
		if !found {
			tags = append(tags, fallback)
		}
	}
	out := cloneMap(body)
	// Dedupe preserving order (JS: [...new Set(tags)]).
	seen := map[string]bool{}
	var dedup []any
	for _, tag := range tags {
		if s, ok := tag.(string); ok {
			if seen[s] {
				continue
			}
			seen[s] = true
		}
		dedup = append(dedup, tag)
	}
	out["tags"] = dedup
	return out
}

// applyJSONSchemaFallback ports applyJsonSchemaFallback (default.js):
// openai-compatible-* providers without native Structured Output get
// response_format json_schema → json_object + a system-prompt instruction.
func (d *DefaultExecutor) applyJSONSchemaFallback(providerID string, body map[string]any) map[string]any {
	if !strings.HasPrefix(providerID, "openai-compatible-") || body == nil {
		return body
	}
	rf, _ := body["response_format"].(map[string]any)
	if rf == nil || rf["type"] != "json_schema" {
		return body
	}
	js, _ := rf["json_schema"].(map[string]any)
	if js == nil || js["schema"] == nil {
		return body
	}
	schemaJSON, _ := json.MarshalIndent(js["schema"], "", "  ")
	prompt := "You must respond with valid JSON that strictly follows this JSON schema:\n```json\n" +
		string(schemaJSON) + "\n```\nRespond ONLY with the JSON object, no other text."
	var messages []any
	if ms, ok := body["messages"].([]any); ok {
		for _, m := range ms {
			if mm, ok := m.(map[string]any); ok {
				messages = append(messages, cloneMap(mm))
			} else {
				messages = append(messages, m)
			}
		}
	}
	foundSys := false
	for _, m := range messages {
		mm, ok := m.(map[string]any)
		if !ok || mm["role"] != "system" {
			continue
		}
		foundSys = true
		switch c := mm["content"].(type) {
		case string:
			mm["content"] = c + "\n\n" + prompt
		case []any:
			mm["content"] = append(c, map[string]any{"type": "text", "text": "\n\n" + prompt})
		}
		break
	}
	if !foundSys {
		messages = append([]any{map[string]any{"role": "system", "content": prompt}}, messages...)
	}
	out := cloneMap(body)
	out["messages"] = messages
	out["response_format"] = map[string]any{"type": "json_object"}
	return out
}

// --- Token refresh (default.js refreshCredentials + helpers) ---

// refreshResult is the normalised token-endpoint answer.
type refreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // seconds
}

// refreshFromGrantOrSpecial dispatches DefaultExecutor.refreshCredentials:
// config-driven grants for claude/codex/gemini, dedicated flows for
// iflow/kiro/cline/clinepass/kimi/kimi-coding; kilocode has no refresh
// support (device-code flow — JS returns null).
func refreshFromGrantOrSpecial(ctx context.Context, b *Base, p *ProviderInfo, cred Credential) (*Credential, error) {
	if cred.RefreshToken == "" {
		return nil, nil
	}
	var res *refreshResult
	var err error
	switch b.ProviderID {
	case "claude", "codex", "gemini":
		res, err = refreshFromGrant(ctx, p, cred)
	case "iflow":
		res, err = refreshIflow(ctx, p, cred)
	case "kiro":
		res, err = refreshKiro(ctx, p, cred)
	case "cline", "clinepass":
		res, err = refreshCline(ctx, p, cred)
	case "kimi", "kimi-coding":
		res, err = refreshKimi(ctx, p, cred)
	default:
		return nil, nil
	}
	if err != nil || res == nil || res.AccessToken == "" {
		return nil, err
	}
	out := cred
	out.AccessToken = res.AccessToken
	if res.RefreshToken != "" {
		out.RefreshToken = res.RefreshToken
	}
	return &out, nil
}

// refreshFromGrant ports refreshFromGrant: {grant_type, refresh_token,
// client_id[, client_secret for gemini, scope]} encoded as form or JSON
// per registry oauth.refresh.encoding.
func refreshFromGrant(ctx context.Context, p *ProviderInfo, cred Credential) (*refreshResult, error) {
	tokenURL := p.TokenURL
	if tokenURL == "" {
		return nil, nil
	}
	params := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": cred.RefreshToken,
		"client_id":     p.ClientID,
	}
	if p.ID == "gemini" {
		params["client_secret"] = p.ClientSecret
	}
	if scope := oauthRefreshScope(p); scope != "" {
		params["scope"] = scope
	}
	if oauthRefreshEncoding(p) == "json" {
		return postRefreshJSON(ctx, tokenURL, params)
	}
	return postRefreshForm(ctx, tokenURL, params, nil)
}

func oauthRefreshEncoding(p *ProviderInfo) string {
	if p == nil || p.Raw == nil {
		return "form"
	}
	oauth, _ := p.Raw["oauth"].(map[string]any)
	if oauth == nil {
		return "form"
	}
	refresh, _ := oauth["refresh"].(map[string]any)
	if refresh == nil {
		return "form"
	}
	if enc, _ := refresh["encoding"].(string); enc != "" {
		return enc
	}
	return "form"
}

func oauthRefreshScope(p *ProviderInfo) string {
	if p == nil || p.Raw == nil {
		return ""
	}
	oauth, _ := p.Raw["oauth"].(map[string]any)
	if oauth == nil {
		return ""
	}
	refresh, _ := oauth["refresh"].(map[string]any)
	if refresh == nil {
		return ""
	}
	s, _ := refresh["scope"].(string)
	return s
}

func postRefreshForm(ctx context.Context, tokenURL string, params map[string]string, extraHeaders map[string]string) (*refreshResult, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return doRefresh(req)
}

func postRefreshJSON(ctx context.Context, tokenURL string, payload any) (*refreshResult, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return doRefresh(req)
}

func doRefresh(req *http.Request) (*refreshResult, error) {
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil // JS: if (!response.ok) return null
	}
	var tokens map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	return &refreshResult{
		AccessToken:  getStr(tokens, "access_token"),
		RefreshToken: getStr(tokens, "refresh_token"),
		ExpiresIn:    int(getFloat(tokens, "expires_in")),
	}, nil
}

func getFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}

// refreshIflow ports refreshIflow: Basic client auth + form grant.
func refreshIflow(ctx context.Context, p *ProviderInfo, cred Credential) (*refreshResult, error) {
	if p.TokenURL == "" || p.ClientID == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL,
		strings.NewReader(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {cred.RefreshToken},
			"client_id":     {p.ClientID},
			"client_secret": {p.ClientSecret},
		}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(p.ClientID, p.ClientSecret)
	return doRefresh(req)
}

// refreshKiro ports refreshKiro: JSON {refreshToken}; the Kiro token
// endpoint answers in camelCase (accessToken/refreshToken/expiresIn).
func refreshKiro(ctx context.Context, p *ProviderInfo, cred Credential) (*refreshResult, error) {
	if p.TokenURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL,
		strings.NewReader(`{"refreshToken":`+jsonQuote(cred.RefreshToken)+`}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kiro-cli/1.0.0")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}
	var tokens map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	return &refreshResult{
		AccessToken:  getStr(tokens, "accessToken"),
		RefreshToken: getStr(tokens, "refreshToken"),
		ExpiresIn:    int(getFloat(tokens, "expiresIn")),
	}, nil
}

// refreshCline ports refreshCline: JSON grant; payload may be wrapped in
// `data`; bare access tokens get the workos: prefix.
func refreshCline(ctx context.Context, p *ProviderInfo, cred Credential) (*refreshResult, error) {
	refreshURL := p.RawString("refreshUrl")
	if refreshURL == "" {
		refreshURL = p.TokenURL
	}
	if refreshURL == "" {
		return nil, nil
	}
	// Cline answers camelCase (possibly wrapped in `data`), unlike the
	// snake_case grant endpoints, so the request is done manually here.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL,
		strings.NewReader(`{"refreshToken":`+jsonQuote(cred.RefreshToken)+`,"grantType":"refresh_token","clientType":"extension"}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	data := payload
	if inner, ok := payload["data"].(map[string]any); ok {
		data = inner
	}
	access := getStr(data, "accessToken")
	if access != "" && !strings.HasPrefix(access, "workos:") {
		access = "workos:" + access
	}
	return &refreshResult{
		AccessToken:  access,
		RefreshToken: getStr(data, "refreshToken"),
	}, nil
}

// refreshKimi ports refreshKimi: form grant + X-Msh-* device headers.
func refreshKimi(ctx context.Context, p *ProviderInfo, cred Credential) (*refreshResult, error) {
	refreshURL := p.RawString("refreshUrl")
	if refreshURL == "" || p.ClientID == "" {
		return nil, nil
	}
	return postRefreshForm(ctx, refreshURL, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": cred.RefreshToken,
		"client_id":     p.ClientID,
	}, buildKimiHeaders(cred.SpecificString("deviceId")))
}

// jsonQuote marshals a string as a JSON string literal.
func jsonQuote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
