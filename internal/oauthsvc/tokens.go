package oauthsvc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Port of the OAuthService dispatch in src/lib/oauth/providers/index.js:
// GenerateAuthData (generateAuthData), ExchangeTokens (exchangeTokens),
// RequestDeviceCode (requestDeviceCode), PollForToken (pollForToken), plus
// a generic RefreshAccessToken the executors' refresh layer can consume
// (the JS refresh logic lives per-executor; the request shapes here follow
// each provider's registry `refresh` block / provider file).

// GenerateAuthData ports generateAuthData: PKCE + provider buildAuthUrl.
// Returns the JS auth-data map {authUrl, state, codeVerifier,
// codeChallenge, redirectUri, flowType, fixedPort?, callbackPath?, ...}.
func GenerateAuthData(ctx context.Context, name, redirectURI string, meta map[string]any) (map[string]any, error) {
	def, ok := GetProvider(name)
	if !ok {
		return nil, errf("Unknown provider: %s", name)
	}
	cfg, err := prepareConfig(ctx, name, ConfigFor(name), meta)
	if err != nil {
		return nil, err
	}
	verifierBytes := def.PKCEVerifierBytes
	if verifierBytes == 0 {
		verifierBytes = 32
	}
	pkce := GeneratePKCE(verifierBytes)
	out := map[string]any{
		"codeVerifier":  pkce.CodeVerifier,
		"codeChallenge": pkce.CodeChallenge,
		"state":         pkce.State,
		"redirectUri":   redirectURI,
		"flowType":      flowTypeOf(def),
	}
	if def.FixedPort > 0 {
		out["fixedPort"] = float64(def.FixedPort)
	}
	if def.CallbackPath != "" {
		out["callbackPath"] = def.CallbackPath
	}

	var authURL string
	switch name {
	case "trae":
		loginURL, traceID, err := TraeLoginGuidance(ctx, cfg)
		if err != nil {
			return nil, err
		}
		authURL = loginURL
		if traceID != "" {
			out["state"] = traceID
		}
	case "windsurf":
		authURL = cfg.StrOr("signinUrl", WindsurfSignInURL)
	case "zed":
		port := 0
		if def.FixedPort > 0 {
			port = def.FixedPort
		}
		if meta != nil {
			if p, ok := meta["nativeAppPort"].(float64); ok && p > 0 {
				port = int(p)
			}
		}
		native, err := CreateZedNativeAuthData(cfg.Str("authorizeUrl"), port)
		if err != nil {
			return nil, err
		}
		authURL = native.AuthURL
		out["codeVerifier"] = native.CodeVerifier
		out["systemId"] = native.SystemID
		out["state"] = native.State
	default:
		u, err := BuildAuthURL(name, cfg, redirectURI, pkce, meta)
		if err != nil {
			return nil, err
		}
		authURL = u
	}
	out["authUrl"] = authURL
	return out, nil
}

func flowTypeOf(def *ProviderDef) string {
	if def.FlowType != "" {
		return def.FlowType
	}
	return FlowAuthorizationCode
}

// ExchangeTokens ports exchangeTokens (code → mapped tokens).
// meta carries per-request values (gitlab baseUrl/clientId/clientSecret,
// zed systemId).
func ExchangeTokens(ctx context.Context, name, code, redirectURI, codeVerifier, state string, meta map[string]any) (map[string]any, error) {
	if _, ok := GetProvider(name); !ok {
		return nil, errf("Unknown provider: %s", name)
	}
	cfg, err := prepareConfig(ctx, name, ConfigFor(name), meta)
	if err != nil {
		return nil, err
	}
	switch name {
	case "claude":
		return exchangeClaude(ctx, cfg, code, redirectURI, codeVerifier, state)
	case "codex":
		return exchangeCodex(ctx, cfg, code, redirectURI, codeVerifier)
	case "xai":
		return exchangeXai(ctx, cfg, code, redirectURI, codeVerifier)
	case "gemini-cli", "antigravity":
		return exchangeGoogle(ctx, name, cfg, code, redirectURI, codeVerifier)
	case "iflow":
		return exchangeIflow(ctx, cfg, code, redirectURI)
	case "gitlab":
		return exchangeGitlab(ctx, cfg, code, redirectURI, codeVerifier, meta)
	case "cline", "clinepass":
		return exchangeCline(ctx, name, cfg, code, redirectURI)
	case "kimchi":
		return exchangeKimchi(ctx, cfg, code)
	case "zed":
		systemID := ""
		if meta != nil {
			systemID = strOf(meta, "systemId")
		}
		return ExchangeZedCode(ctx, code, codeVerifier, systemID)
	}
	return nil, errf("provider %s does not support authorization code flow", name)
}

// RequestDeviceCode ports requestDeviceCode. The engine always generates a
// PKCE pair first (the JS does); the returned map merges the provider's
// device data with codeVerifier.
func RequestDeviceCode(ctx context.Context, name string, options map[string]any) (map[string]any, error) {
	def, ok := GetProvider(name)
	if !ok {
		return nil, errf("Unknown provider: %s", name)
	}
	cfg := ConfigFor(name)
	verifierBytes := def.PKCEVerifierBytes
	if verifierBytes == 0 {
		verifierBytes = 32
	}
	pkce := GeneratePKCE(verifierBytes)
	data, err := requestDeviceCodeImpl(ctx, name, cfg, pkce.CodeChallenge, options)
	if err != nil {
		return nil, err
	}
	if _, has := data["codeVerifier"]; !has {
		data["codeVerifier"] = pkce.CodeVerifier
	}
	return data, nil
}

// PollResult is the framework-level poll outcome (pollForToken return).
type PollResult struct {
	Success          bool
	Tokens           map[string]any
	Error            string
	ErrorDescription string
	Fatal            bool
}

// Pending reports whether the user simply hasn't finished yet.
func (p *PollResult) Pending() bool {
	return !p.Success && (p.Error == "authorization_pending" || p.Error == "slow_down")
}

// PollForToken ports pollForToken.
func PollForToken(ctx context.Context, name, deviceCode, codeVerifier string, extra map[string]any) (*PollResult, error) {
	if _, ok := GetProvider(name); !ok {
		return nil, errf("Unknown provider: %s", name)
	}
	cfg := ConfigFor(name)
	outcome, err := pollImpl(ctx, name, cfg, deviceCode, codeVerifier, extra)
	if err != nil {
		return nil, err
	}
	if outcome.tokens != nil {
		return &PollResult{Success: true, Tokens: outcome.tokens}, nil
	}
	res := &PollResult{Error: outcome.errCode, ErrorDescription: outcome.errDesc, Fatal: outcome.fatal}
	if outcome.pending != "" {
		res.Error = outcome.pending
	}
	if res.Error == "" {
		res.Error = "unknown_error"
	}
	return res, nil
}

// RefreshAccessToken performs a provider refresh_token grant and returns a
// token map in the same shape as ExchangeTokens. cred is the stored
// connection (accessToken/refreshToken/providerSpecificData keys are read
// from the camelCase record shape).
func RefreshAccessToken(ctx context.Context, name string, cred map[string]any) (map[string]any, error) {
	cfg := ConfigFor(name)
	refreshToken := strOf(cred, "refreshToken")
	if refreshToken == "" {
		return nil, errf("Missing refresh token for %s", name)
	}
	psd, _ := cred["providerSpecificData"].(map[string]any)

	switch name {
	case "kiro":
		body, err := KiroRefreshToken(ctx, refreshToken, psd)
		if err != nil {
			return nil, err
		}
		out := map[string]any{}
		SetIf(out, "accessToken", strOf(body, "accessToken"))
		rt := firstStr(strOf(body, "refreshToken"), refreshToken)
		out["refreshToken"] = rt
		SetNumIf(out, "expiresIn", NumPairOf(body, "expiresIn"))
		out["lastRefreshAt"] = float64(time.Now().UnixMilli())
		return out, nil

	case "claude":
		// Registry marks claude's refresh encoding as JSON.
		status, body, err := PostJSON(ctx, cfg.Str("tokenUrl"), map[string]any{
			"grant_type": "refresh_token", "refresh_token": refreshToken,
			"client_id": cfg.Str("clientId"),
		}, map[string]string{"anthropic-beta": "oauth-2025-04-20"})
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Token refresh failed", status, body, "")
		}
		return refreshOut(body, refreshToken, true), nil

	case "gitlab":
		base := cfg.StrOr("defaultBaseUrl", "https://gitlab.com")
		clientID, clientSecret := "", ""
		if psd != nil {
			base = firstStr(strOf(psd, "baseUrl"), base)
			clientID = strOf(psd, "clientId")
			clientSecret = strOf(psd, "clientSecret")
		}
		form := url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
			"client_id": {clientID},
		}
		if clientSecret != "" {
			form.Set("client_secret", clientSecret)
		}
		status, body, err := PostForm(ctx, base+cfg.StrOr("tokenUrlPath", "/oauth/token"), form, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("GitLab token refresh failed", status, body, "")
		}
		return refreshOut(body, refreshToken, false), nil

	case "iflow":
		basic := base64.StdEncoding.EncodeToString([]byte(cfg.Str("clientId") + ":" + cfg.Str("clientSecret")))
		form := url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
			"client_id": {cfg.Str("clientId")}, "client_secret": {cfg.Str("clientSecret")},
		}
		status, body, err := PostForm(ctx, cfg.Str("tokenUrl"), form,
			map[string]string{"Authorization": "Basic " + basic})
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Token refresh failed", status, body, "")
		}
		return refreshOut(body, refreshToken, false), nil

	case "kimi":
		deviceID := ""
		if psd != nil {
			deviceID = strOf(psd, "deviceId")
		}
		status, body, err := PostJSON(ctx, cfg.StrOr("refreshUrl", cfg.Str("tokenUrl")), map[string]any{
			"grant_type": "refresh_token", "refresh_token": refreshToken,
			"client_id": cfg.Str("clientId"),
		}, KimiHeaders(deviceID))
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Kimi token refresh failed", status, body, "")
		}
		return refreshOut(body, refreshToken, false), nil

	case "codebuddy-cn", "codebuddy-intl":
		status, body, err := PostJSON(ctx, cfg.Str("refreshUrl"),
			map[string]any{"refreshToken": refreshToken}, codebuddyHeaders(cfg))
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("CodeBuddy token refresh failed", status, body, "")
		}
		data, _ := body["data"].(map[string]any)
		out := map[string]any{"refreshToken": refreshToken}
		if data != nil {
			SetIf(out, "accessToken", strOf(data, "accessToken"))
			SetIf(out, "refreshToken", strOf(data, "refreshToken"))
		}
		return out, nil

	case "cline", "clinepass":
		status, body, err := PostJSON(ctx, cfg.Str("refreshUrl"), map[string]any{
			"refreshToken": refreshToken, "grantType": "refresh_token",
		}, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Token refresh failed", status, body, "")
		}
		out := refreshOut(body, refreshToken, false)
		if data, ok := body["data"].(map[string]any); ok {
			SetIf(out, "accessToken", strOf(data, "accessToken"))
			SetIf(out, "refreshToken", strOf(data, "refreshToken"))
		}
		return out, nil
	}

	// Generic form refresh for the remaining providers with a token URL
	// (codex, xai, gemini-cli, antigravity, github, grok-cli, minimax, nous).
	tokenURL := cfg.StrOr("refreshUrl", cfg.Str("tokenUrl"))
	if tokenURL == "" {
		return nil, errf("provider %s does not support token refresh", name)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if cid := cfg.Str("clientId"); cid != "" {
		form.Set("client_id", cid)
	}
	if cs := cfg.Str("clientSecret"); cs != "" {
		form.Set("client_secret", cs)
	}
	if name == "codex" {
		form.Set("scope", "openid profile email")
	}
	status, body, err := PostForm(ctx, tokenURL, form, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Token refresh failed", status, body, "")
	}
	out := refreshOut(body, refreshToken, false)
	if name == "codex" || name == "xai" {
		out["lastRefreshAt"] = float64(time.Now().UnixMilli())
		if idToken := strOf(body, "id_token"); idToken != "" {
			out["idToken"] = idToken
		}
	}
	return out, nil
}

func refreshOut(body map[string]any, oldRefresh string, camel bool) map[string]any {
	out := map[string]any{}
	if camel {
		SetIf(out, "accessToken", strOf(body, "accessToken"))
		SetIf(out, "refreshToken", strOf(body, "refreshToken"))
		SetNumIf(out, "expiresIn", NumPairOf(body, "expiresIn"))
	} else {
		SetIf(out, "accessToken", strOf(body, "access_token"))
		SetIf(out, "refreshToken", strOf(body, "refresh_token"))
		SetNumIf(out, "expiresIn", NumPairOf(body, "expires_in"))
	}
	if strOf(out, "refreshToken") == "" {
		out["refreshToken"] = oldRefresh
	}
	return out
}

var _ = strings.TrimSpace
