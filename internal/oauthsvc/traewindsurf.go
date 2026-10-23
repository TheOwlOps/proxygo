package oauthsvc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Ports of src/lib/oauth/providers/trae.js, windsurf.js and the exchange
// helpers the [provider]/[action] route uses for both
// (resolveTraeLoginResult / exchangeWindsurfAuthCode semantics).

// TraeLoginGuidance ports GetLoginGuidance: returns the browser login URL
// and the login_trace_id used as the OAuth state.
func TraeLoginGuidance(ctx context.Context, cfg Config) (loginURL, traceID string, err error) {
	status, body, herr := PostJSON(ctx, cfg.StrOr("loginGuidanceUrl", TraeLoginGuidanceURL),
		map[string]any{"platform": cfg.StrOr("platform", TraePlatform)}, nil)
	if herr != nil {
		return "", "", herr
	}
	if status != http.StatusOK {
		return "", "", TokenError("Trae login guidance failed", status, body, "")
	}
	data := body
	if d, ok := body["data"].(map[string]any); ok {
		data = d
	}
	loginURL = firstStr(strOf(data, "loginUrl"), strOf(data, "LoginUrl"), strOf(data, "url"))
	traceID = firstStr(strOf(data, "loginTraceId"), strOf(data, "loginTraceID"), strOf(data, "login_trace_id"))
	if loginURL == "" {
		return "", "", errf("Trae login guidance returned no login URL")
	}
	return loginURL, traceID, nil
}

// TraeLoginResult is the parsed Trae callback payload.
type TraeLoginResult struct {
	RefreshToken string
	LoginHost    string
	UserID       string
}

// ResolveTraeLoginResult ports resolveTraeLoginResult: the input is either
// a full callback URL carrying the login result params, or a raw refresh
// token pasted by the user.
func ResolveTraeLoginResult(input string) (TraeLoginResult, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return TraeLoginResult{}, errf("Missing Trae login code")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return TraeLoginResult{}, errf("Invalid Trae callback URL")
		}
		q := u.Query()
		res := TraeLoginResult{
			RefreshToken: firstStr(q.Get("refreshToken"), q.Get("RefreshToken"), q.Get("token")),
			LoginHost:    firstStr(q.Get("loginHost"), q.Get("LoginHost"), q.Get("host")),
			UserID:       firstStr(q.Get("userId"), q.Get("UserID"), q.Get("uid")),
		}
		if res.RefreshToken == "" {
			return TraeLoginResult{}, errf("Trae callback URL carries no refresh token")
		}
		return res, nil
	}
	return TraeLoginResult{RefreshToken: raw}, nil
}

// ExchangeTraeLoginResult ports the Trae token exchange + user info fetch.
// Returns the mapped token map used to build the connection.
func ExchangeTraeLoginResult(ctx context.Context, cfg Config, login TraeLoginResult) (map[string]any, error) {
	status, body, err := PostJSON(ctx, cfg.StrOr("exchangeTokenUrl", TraeExchangeTokenURL), map[string]any{
		"ClientID":     cfg.StrOr("clientId", TraeClientID),
		"RefreshToken": login.RefreshToken,
		"ClientSecret": "-",
	}, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Trae token exchange failed", status, body, "")
	}
	data := body
	if d, ok := body["data"].(map[string]any); ok {
		data = d
	}
	accessToken := firstStr(strOf(data, "AccessToken"), strOf(data, "accessToken"), strOf(data, "access_token"))
	if accessToken == "" {
		return nil, errf("Trae token exchange returned no access token")
	}
	out := map[string]any{"accessToken": accessToken}
	refresh := firstStr(strOf(data, "RefreshToken"), strOf(data, "refreshToken"), login.RefreshToken)
	SetIf(out, "refreshToken", refresh)
	if exp, ok := numOf(data, "expiresIn"); ok {
		out["expiresIn"] = exp
	}
	// GetUserInfo (best effort).
	if s, info, err := PostJSON(ctx, cfg.StrOr("userInfoUrl", TraeUserInfoURL), map[string]any{},
		map[string]string{"Authorization": "Bearer " + accessToken}); err == nil && s == http.StatusOK {
		idata := info
		if d, ok := info["data"].(map[string]any); ok {
			idata = d
		}
		SetIf(out, "email", strOf(idata, "email"))
		SetIf(out, "displayName", firstStr(strOf(idata, "name"), strOf(idata, "nickname")))
		if login.UserID == "" {
			login.UserID = strOf(idata, "userId")
		}
	}
	psd := map[string]any{"authMethod": "oauth"}
	SetIf(psd, "loginHost", login.LoginHost)
	SetIf(psd, "userId", login.UserID)
	out["providerSpecificData"] = psd
	return out, nil
}

// ResolveWindsurfCallback ports the windsurf callback parsing: the input is
// a callback URL (?token=<firebase JWT>) or a pasted token / API key.
func ResolveWindsurfCallback(input string) (token string, isJWT bool, err error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", false, errf("Missing Windsurf login code")
	}
	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil {
			return "", false, errf("Invalid Windsurf callback URL")
		}
		raw = firstStr(u.Query().Get("token"), u.Query().Get("access_token"), u.Query().Get("api_key"))
		if raw == "" {
			return "", false, errf("Windsurf callback URL carries no token")
		}
	}
	return raw, strings.Count(raw, ".") == 2 && strings.HasPrefix(raw, "eyJ"), nil
}

// ExchangeWindsurfAuthCode ports exchangeWindsurfAuthCode: a Firebase ID
// token is registered with Windsurf to mint the API key that becomes the
// connection credential. A non-JWT input is treated as an API key already.
func ExchangeWindsurfAuthCode(ctx context.Context, cfg Config, code string) (map[string]any, error) {
	token, isJWT, err := ResolveWindsurfCallback(code)
	if err != nil {
		return nil, err
	}
	if !isJWT {
		return map[string]any{
			"accessToken":          token,
			"providerSpecificData": map[string]any{"authMethod": "api_key"},
		}, nil
	}
	status, body, herr := PostJSON(ctx, cfg.StrOr("registerUrl", WindsurfRegisterURL),
		map[string]any{"firebaseIdToken": token},
		map[string]string{"Connect-Protocol-Version": "1"})
	if herr != nil {
		return nil, herr
	}
	if status != http.StatusOK {
		return nil, TokenError("Windsurf RegisterUser failed", status, body, "")
	}
	apiKey := firstStr(strOf(body, "apiKey"), strOf(body, "api_key"))
	if user, ok := body["user"].(map[string]any); ok && apiKey == "" {
		apiKey = firstStr(strOf(user, "apiKey"), strOf(user, "api_key"))
	}
	if apiKey == "" {
		return nil, errf("Windsurf RegisterUser returned no API key")
	}
	out := map[string]any{
		"accessToken": apiKey,
		"providerSpecificData": map[string]any{
			"authMethod":    "api_key",
			"firebaseToken": token,
		},
	}
	if user, ok := body["user"].(map[string]any); ok {
		SetIf(out, "email", strOf(user, "email"))
		SetIf(out, "displayName", strOf(user, "name"))
	}
	return out, nil
}
