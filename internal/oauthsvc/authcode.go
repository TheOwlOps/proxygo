package oauthsvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Authorization-code providers: buildAuthUrl + exchangeToken + mapTokens
// ports from src/lib/oauth/providers/{claude,codex,xai,gemini-cli,
// antigravity,iflow,gitlab,cline,clinepass,kimchi}.js. Trae/Windsurf/Zed
// live in traewindsurf.go / zed.go (non-standard flows).

func buildAuthURLQuery(base string, params url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + params.Encode()
}

func extraParams(cfg Config, q url.Values) {
	if m, ok := cfg["extraParams"].(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				q.Set(k, s)
			}
		}
	}
}

// prepareConfig ports the providers' prepareConfig hooks. It returns the
// effective config (xai: discovery-resolved endpoints).
func prepareConfig(ctx context.Context, name string, cfg Config, meta map[string]any) (Config, error) {
	switch name {
	case "xai":
		_, tokenURL, err := DiscoverXai(ctx, cfg.StrOr("discoveryUrl", XAIDiscoveryURL))
		if err != nil {
			return nil, err
		}
		out := Config{}
		for k, v := range cfg {
			out[k] = v
		}
		out["tokenUrl"] = tokenURL
		return out, nil
	}
	return cfg, nil
}

// DiscoverXai fetches + validates the xAI OIDC discovery document
// (fetchXaiDiscoveryConfig). Endpoints must sit on x.ai over https.
func DiscoverXai(ctx context.Context, discoveryURL string) (authorizeURL, tokenURL string, err error) {
	status, body, herr := GetJSON(ctx, discoveryURL, nil)
	if herr != nil {
		return "", "", errf("xai discovery fetch failed: %v", herr)
	}
	if status != http.StatusOK {
		return "", "", errf("xai discovery failed: HTTP %d", status)
	}
	authEndpoint, err := ValidateXaiOAuthEndpoint(strOf(body, "authorization_endpoint"), "authorization_endpoint")
	if err != nil {
		return "", "", err
	}
	tokenEndpoint, err := ValidateXaiOAuthEndpoint(strOf(body, "token_endpoint"), "token_endpoint")
	if err != nil {
		return "", "", err
	}
	return authEndpoint, tokenEndpoint, nil
}

// BuildAuthURL ports each provider's buildAuthUrl. cfg must already be
// prepared (xai discovery resolved — see GenerateAuthData).
func BuildAuthURL(name string, cfg Config, redirectURI string, pkce PKCE, meta map[string]any) (string, error) {
	q := url.Values{}
	switch name {
	case "claude":
		q.Set("response_type", "code")
		q.Set("client_id", cfg.Str("clientId"))
		q.Set("redirect_uri", redirectURI)
		q.Set("scope", cfg.ScopeString())
		q.Set("state", pkce.State)
		q.Set("code_challenge", pkce.CodeChallenge)
		q.Set("code_challenge_method", "S256")
		return buildAuthURLQuery(cfg.Str("authorizeUrl"), q), nil
	case "codex":
		q.Set("response_type", "code")
		q.Set("client_id", cfg.Str("clientId"))
		q.Set("redirect_uri", redirectURI)
		q.Set("scope", cfg.ScopeString())
		q.Set("state", pkce.State)
		q.Set("code_challenge", pkce.CodeChallenge)
		q.Set("code_challenge_method", "S256")
		extraParams(cfg, q)
		return buildAuthURLQuery(cfg.Str("authorizeUrl"), q), nil
	case "xai":
		authURL, _, err := DiscoverXai(context.Background(), cfg.StrOr("discoveryUrl", XAIDiscoveryURL))
		if err != nil {
			return "", err
		}
		q.Set("client_id", cfg.Str("clientId"))
		q.Set("code_challenge", pkce.CodeChallenge)
		q.Set("code_challenge_method", "S256")
		q.Set("nonce", pkce.State)
		q.Set("plan", "generic")
		q.Set("redirect_uri", redirectURI)
		q.Set("referrer", "9router")
		q.Set("response_type", "code")
		q.Set("scope", cfg.ScopeString())
		q.Set("state", pkce.State)
		return buildAuthURLQuery(authURL, q), nil
	case "gemini-cli", "antigravity":
		q.Set("client_id", cfg.Str("clientId"))
		q.Set("redirect_uri", redirectURI)
		q.Set("response_type", "code")
		q.Set("scope", cfg.ScopeString())
		q.Set("code_challenge", pkce.CodeChallenge)
		q.Set("code_challenge_method", "S256")
		q.Set("state", pkce.State)
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
		if name == "gemini-cli" {
			q.Set("include_granted_scopes", "true")
		}
		return buildAuthURLQuery(cfg.Str("authorizeUrl"), q), nil
	case "iflow":
		extraParams(cfg, q) // loginMethod + type
		q.Set("redirect", redirectURI)
		q.Set("state", pkce.State)
		q.Set("client_id", cfg.Str("clientId"))
		return buildAuthURLQuery(cfg.Str("authorizeUrl"), q), nil
	case "gitlab":
		base := metaStr(meta, "baseUrl", cfg.StrOr("defaultBaseUrl", "https://gitlab.com"))
		q.Set("client_id", metaStr(meta, "clientId", ""))
		q.Set("redirect_uri", redirectURI)
		q.Set("response_type", "code")
		q.Set("state", pkce.State)
		q.Set("scope", cfg.StrOr("scope", "api read_user"))
		q.Set("code_challenge", pkce.CodeChallenge)
		q.Set("code_challenge_method", cfg.StrOr("codeChallengeMethod", "S256"))
		return buildAuthURLQuery(base+cfg.StrOr("authorizeUrlPath", "/oauth/authorize"), q), nil
	case "cline", "clinepass":
		q.Set("client_type", "extension")
		q.Set("callback_url", redirectURI)
		q.Set("redirect_uri", redirectURI)
		return buildAuthURLQuery(cfg.Str("authorizeUrl"), q), nil
	case "kimchi":
		base := strings.TrimRight(cfg.StrOr("webAppUrl", "https://app.kimchi.dev"), "/")
		q.Set("callback", redirectURI)
		q.Set("state", pkce.State)
		return buildAuthURLQuery(base+"/cli-auth", q), nil
	}
	return "", errf("provider %s does not support authorization code flow", name)
}

func metaStr(meta map[string]any, key, def string) string {
	if meta != nil {
		if s, ok := meta[key].(string); ok && s != "" {
			return s
		}
	}
	return def
}

// ---- exchange implementations. Each returns the provider's mapTokens
// output (camelCase token map in the JS shape). ----

func exchangeClaude(ctx context.Context, cfg Config, code, redirectURI, codeVerifier, state string) (map[string]any, error) {
	// Claude packs "code#state" into the code param.
	if i := strings.Index(code, "#"); i >= 0 {
		if state == "" {
			state = code[i+1:]
		}
		code = code[:i]
	}
	status, raw, _, err := Raw(ctx, http.MethodPost, cfg.Str("tokenUrl"),
		strings.NewReader(mustJSON(map[string]any{
			"code": code, "grant_type": "authorization_code", "client_id": cfg.Str("clientId"),
			"redirect_uri": redirectURI, "code_verifier": codeVerifier, "state": state,
		})), "application/json", map[string]string{"anthropic-beta": "oauth-2025-04-20"})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("Token exchange failed: %s", raw)
	}
	var data map[string]any
	if json.Unmarshal([]byte(raw), &data) != nil {
		return nil, errf("Token exchange failed: invalid JSON response")
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(data, "access_token"))
	SetIf(out, "refreshToken", strOf(data, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(data, "expires_in"))
	if acct, ok := data["account"].(map[string]any); ok {
		SetIf(out, "email", strOf(acct, "email_address"))
	}
	if s := strOf(data, "scope"); s != "" {
		out["scope"] = strings.Fields(s)
	}
	return out, nil
}

func exchangeCodex(ctx context.Context, cfg Config, code, redirectURI, codeVerifier string) (map[string]any, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.Str("clientId")},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	status, data, err := PostForm(ctx, cfg.Str("tokenUrl"), form, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Token exchange failed", status, data, "")
	}
	return mapCodexTokens(data), nil
}

// MapCodexTokens ports codex's mapTokens (also used by the import-token
// route through ExtractCodexAccountInfo).
func mapCodexTokens(data map[string]any) map[string]any {
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(data, "access_token"))
	SetIf(out, "refreshToken", strOf(data, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(data, "expires_in"))
	out["lastRefreshAt"] = float64(time.Now().UnixMilli())
	if idToken := strOf(data, "id_token"); idToken != "" {
		out["idToken"] = idToken
		info := ExtractCodexAccountInfo(idToken)
		SetIf(out, "email", info.Email)
		psd := map[string]any{}
		SetIf(psd, "chatgptAccountId", info.ChatGPTAccountID)
		SetIf(psd, "chatgptPlanType", info.ChatGPTPlanType)
		if len(psd) > 0 {
			out["providerSpecificData"] = psd
		}
	}
	return out
}

func exchangeXai(ctx context.Context, cfg Config, code, redirectURI, codeVerifier string) (map[string]any, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.Str("clientId")},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	status, data, err := PostForm(ctx, cfg.Str("tokenUrl"), form, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Token exchange failed", status, data, "")
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(data, "access_token"))
	SetIf(out, "refreshToken", strOf(data, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(data, "expires_in"))
	out["lastRefreshAt"] = float64(time.Now().UnixMilli())
	email := ""
	if idToken := strOf(data, "id_token"); idToken != "" {
		out["idToken"] = idToken
		email = DecodeXaiIdTokenEmail(idToken)
	}
	if email == "" {
		email = ExtractEmailFromAccessToken(strOf(data, "access_token"))
	}
	SetIf(out, "email", email)
	if email != "" {
		out["providerSpecificData"] = map[string]any{"email": email}
	}
	return out, nil
}

// exchangeGoogle ports gemini-cli/antigravity exchange + postExchange
// (userinfo + loadCodeAssist project resolution).
func exchangeGoogle(ctx context.Context, name string, cfg Config, code, redirectURI, codeVerifier string) (map[string]any, error) {
	if codeVerifier == "" {
		return nil, errf("Missing codeVerifier for %s token exchange. The OAuth session may have expired — please restart the login flow.", name)
	}
	form := url.Values{
		"code":          {code},
		"client_id":     {cfg.Str("clientId")},
		"client_secret": {cfg.Str("clientSecret")},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
	}
	status, data, err := PostForm(ctx, cfg.Str("tokenUrl"), form, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Token exchange failed", status, data, "")
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(data, "access_token"))
	SetIf(out, "refreshToken", strOf(data, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(data, "expires_in"))
	SetIf(out, "idToken", strOf(data, "id_token"))
	SetIf(out, "scope", strOf(data, "scope"))

	accessToken := strOf(data, "access_token")
	// postExchange: userinfo (best effort, matches JS try/catch).
	if cfg.Str("userInfoUrl") != "" {
		if s, info, err := GetJSON(ctx, cfg.Str("userInfoUrl"),
			map[string]string{"Authorization": "Bearer " + accessToken}); err == nil && s == http.StatusOK {
			SetIf(out, "email", strOf(info, "email"))
			SetIf(out, "displayName", strOf(info, "name"))
			SetIf(out, "name", strOf(info, "name"))
		}
	}
	if cfg.Str("loadCodeAssistEndpoint") != "" {
		if projectID := loadCodeAssistProject(ctx, cfg, accessToken); projectID != "" {
			out["projectId"] = projectID
			out["providerSpecificData"] = map[string]any{"projectId": projectID}
		}
	}
	return out, nil
}

func loadCodeAssistProject(ctx context.Context, cfg Config, accessToken string) string {
	ua := cfg.StrOr("loadCodeAssistUserAgent", "google-api-nodejs-client/9.15.1")
	headers := map[string]string{"Authorization": "Bearer " + accessToken, "User-Agent": ua}
	metadata := map[string]any{"ideType": "ANTIGRAVITY", "platform": "PLATFORM_UNSPECIFIED", "pluginType": "GEMINI"}
	status, body, err := PostJSON(ctx, cfg.Str("loadCodeAssistEndpoint"),
		map[string]any{"metadata": metadata}, headers)
	if err == nil && status == http.StatusOK {
		switch v := body["cloudaicompanionProject"].(type) {
		case string:
			if v != "" {
				return v
			}
		case map[string]any:
			if id := strOf(v, "id"); id != "" {
				return id
			}
		}
		// onboardUser fallback: default tier, else LEGACY.
		tierID := "LEGACY"
		if tiers, ok := body["allowedTiers"].([]any); ok {
			for _, t := range tiers {
				if tm, ok := t.(map[string]any); ok {
					if def, _ := tm["isDefault"].(bool); def {
						if id := strOf(tm, "id"); id != "" {
							tierID = id
						}
					}
				}
			}
		}
		if cfg.Str("onboardUserEndpoint") != "" {
			for attempt := 0; attempt < 5; attempt++ {
				s2, b2, err2 := PostJSON(ctx, cfg.Str("onboardUserEndpoint"),
					map[string]any{"tierId": tierID, "metadata": metadata}, headers)
				if err2 == nil && s2 == http.StatusOK {
					if proj, ok := b2["cloudaicompanionProject"].(map[string]any); ok {
						if id := strOf(proj, "id"); id != "" {
							return id
						}
					}
					if done, _ := b2["done"].(bool); done {
						break
					}
				}
				select {
				case <-ctx.Done():
					return ""
				case <-time.After(2 * time.Second):
				}
			}
		}
	}
	return ""
}

func exchangeIflow(ctx context.Context, cfg Config, code, redirectURI string) (map[string]any, error) {
	basic := base64.StdEncoding.EncodeToString([]byte(cfg.Str("clientId") + ":" + cfg.Str("clientSecret")))
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {cfg.Str("clientId")},
		"client_secret": {cfg.Str("clientSecret")},
	}
	status, raw, _, err := Raw(ctx, http.MethodPost, cfg.Str("tokenUrl"), strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded", map[string]string{"Authorization": "Basic " + basic})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("Token exchange failed: %s", raw)
	}
	var data map[string]any
	if json.Unmarshal([]byte(raw), &data) != nil {
		return nil, errf("Token exchange failed: invalid JSON response")
	}
	// postExchange: user info — MUST succeed (carries the API key).
	userInfoURL := cfg.Str("userInfoUrl") + "?accessToken=" + url.QueryEscape(strOf(data, "access_token"))
	s2, info, err := GetJSON(ctx, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	if s2 != http.StatusOK {
		return nil, errf("Failed to fetch user info: HTTP %d", s2)
	}
	if ok, _ := info["success"].(bool); !ok {
		return nil, errf("User info request failed: %s", strOf(info, "message"))
	}
	userInfo, _ := info["data"].(map[string]any)
	apiKey := ""
	email := ""
	displayName := ""
	if userInfo != nil {
		apiKey = strOf(userInfo, "apiKey")
		email = firstStr(strOf(userInfo, "email"), strOf(userInfo, "phone"))
		displayName = firstStr(strOf(userInfo, "nickname"), strOf(userInfo, "name"))
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, errf("Empty API key returned from iFlow")
	}
	if email == "" {
		return nil, errf("Missing account email/phone in user info")
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(data, "access_token"))
	SetIf(out, "refreshToken", strOf(data, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(data, "expires_in"))
	out["apiKey"] = apiKey
	out["email"] = email
	SetIf(out, "displayName", displayName)
	return out, nil
}

func exchangeGitlab(ctx context.Context, cfg Config, code, redirectURI, codeVerifier string, meta map[string]any) (map[string]any, error) {
	base := metaStr(meta, "baseUrl", cfg.StrOr("defaultBaseUrl", "https://gitlab.com"))
	clientID := metaStr(meta, "clientId", "")
	clientSecret := metaStr(meta, "clientSecret", "")
	form := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	status, raw, _, err := Raw(ctx, http.MethodPost, base+cfg.StrOr("tokenUrlPath", "/oauth/token"),
		strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("GitLab token exchange failed: %s", raw)
	}
	var data map[string]any
	if json.Unmarshal([]byte(raw), &data) != nil {
		return nil, errf("GitLab token exchange failed: invalid JSON response")
	}
	user := map[string]any{}
	if s2, u, err := GetJSON(ctx, base+cfg.StrOr("userInfoUrlPath", "/api/v4/user"),
		map[string]string{"Authorization": "Bearer " + strOf(data, "access_token")}); err == nil && s2 == http.StatusOK {
		user = u
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(data, "access_token"))
	SetIf(out, "refreshToken", strOf(data, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(data, "expires_in"))
	SetIf(out, "scope", strOf(data, "scope"))
	out["providerSpecificData"] = map[string]any{
		"username": strOf(user, "username"),
		"email":    firstStr(strOf(user, "email"), strOf(user, "public_email")),
		"name":     strOf(user, "name"),
		"baseUrl":  base,
		"clientId": clientID,
		"authKind": "oauth",
	}
	// The route stores the connection email from tokens.email; gitlab's
	// mapTokens keeps identity inside providerSpecificData only, but the
	// framework copies psd.email through in the JS as well (mapTokens has
	// no top-level email) — keep JS shape exactly.
	return out, nil
}

// exchangeCline ports cline/clinepass exchangeToken: the code is usually a
// base64 JSON token blob; on decode failure it falls back to the HTTP
// token endpoint.
func exchangeCline(ctx context.Context, name string, cfg Config, code, redirectURI string) (map[string]any, error) {
	label := "Cline"
	tokenURL := cfg.Str("tokenExchangeUrl")
	if name == "clinepass" {
		label = "ClinePass"
		tokenURL = cfg.Str("tokenUrl")
	}
	var tokens map[string]any
	decoded, derr := decodeClineBlob(code)
	if derr == nil {
		tokens = decoded
	} else {
		status, data, err := PostJSON(ctx, tokenURL, map[string]any{
			"grant_type": "authorization_code", "code": code,
			"client_type": "extension", "redirect_uri": redirectURI,
		}, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, errf("%s token exchange failed: %s", label, strOf(data, "error_description"))
		}
		tokens = map[string]any{
			"access_token":  strOf(data, "access_token"),
			"refresh_token": strOf(data, "refresh_token"),
		}
		if d, ok := data["data"].(map[string]any); ok {
			if ui, ok := d["userInfo"].(map[string]any); ok {
				tokens["email"] = strOf(ui, "email")
			}
			tokens["expires_at"] = firstStr(strOf(d, "expiresAt"), strOf(data, "expiresAt"))
		} else {
			tokens["expires_at"] = strOf(data, "expiresAt")
		}
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(tokens, "access_token"))
	SetIf(out, "refreshToken", strOf(tokens, "refresh_token"))
	expiresIn := float64(3600)
	if exp := strOf(tokens, "expires_at"); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			expiresIn = float64(int64(time.Until(t).Seconds()))
		}
	}
	out["expiresIn"] = expiresIn
	SetIf(out, "email", strOf(tokens, "email"))
	psd := map[string]any{}
	if v, ok := tokens["firstName"]; ok {
		psd["firstName"] = v
	}
	if v, ok := tokens["lastName"]; ok {
		psd["lastName"] = v
	}
	out["providerSpecificData"] = psd
	return out, nil
}

func decodeClineBlob(code string) (map[string]any, error) {
	b64 := code
	if pad := 4 - (len(b64) % 4); pad != 4 {
		b64 += strings.Repeat("=", pad)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
	}
	text := string(raw)
	lastBrace := strings.LastIndex(text, "}")
	if lastBrace == -1 {
		return nil, errf("No JSON found in decoded code")
	}
	var tokenData map[string]any
	if err := json.Unmarshal([]byte(text[:lastBrace+1]), &tokenData); err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token":  strOf(tokenData, "accessToken"),
		"refresh_token": strOf(tokenData, "refreshToken"),
		"email":         strOf(tokenData, "email"),
		"firstName":     tokenData["firstName"],
		"lastName":      tokenData["lastName"],
		"expires_at":    strOf(tokenData, "expiresAt"),
	}, nil
}

// exchangeKimchi ports the browser_token validation flow.
func exchangeKimchi(ctx context.Context, cfg Config, token string) (map[string]any, error) {
	accessToken := strings.TrimSpace(token)
	if accessToken == "" {
		return nil, errf("Missing Kimchi token")
	}
	validationURL := cfg.StrOr("validationUrl", "https://api.cast.ai/v1/llm/openai/supported-providers")
	status, _, err := GetJSON(ctx, validationURL, map[string]string{"Authorization": "Bearer " + accessToken})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("Kimchi token validation failed: %d", status)
	}
	user := map[string]any{}
	if cfg.Str("userInfoUrl") != "" {
		if s, u, err := GetJSON(ctx, cfg.Str("userInfoUrl"),
			map[string]string{"Authorization": "Bearer " + accessToken}); err == nil && s == http.StatusOK {
			user = u
		}
	}
	userID := ""
	if v, ok := user["id"]; ok {
		userID = fmt.Sprintf("%v", v)
		if f, ok := v.(float64); ok {
			userID = fmt.Sprintf("%d", int64(f))
		}
	}
	username := strOf(user, "username")
	email := strOf(user, "email")
	if email == "" && userID != "" {
		email = "kimchi-user-" + userID
	}
	out := map[string]any{"accessToken": accessToken, "refreshToken": nil}
	if email != "" {
		out["email"] = email
	} else {
		out["email"] = nil
	}
	displayName := firstStr(strOf(user, "name"), username)
	if displayName != "" {
		out["displayName"] = displayName
	} else {
		out["displayName"] = nil
	}
	out["providerSpecificData"] = map[string]any{
		"authMethod": "browser_token",
		"userId":     userID,
		"username":   username,
	}
	return out, nil
}

func mustJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
