package oauthsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Port of src/lib/oauth/services/kiro.js (KiroService) and
// src/lib/oauth/kiroExternalIdp.js (external IdP normalization).

const (
	kiroAuthServiceBase = "https://prod.us-east-1.auth.desktop.kiro.dev"
	kiroSocialRedirect  = "kiro://kiro.kiroAgent/authenticate-success"
	kiroAPIKeyPrefix    = "aorAAAAAG"
)

var awsRegionRe = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d{1,2}$`)

// AssertValidAWSRegion ports assertValidKiroRegion (SSRF guard).
func AssertValidAWSRegion(region string) (string, error) {
	r := strings.TrimSpace(region)
	if r == "" {
		return "us-east-1", nil
	}
	if !awsRegionRe.MatchString(r) {
		return "", errf("Invalid AWS region: %s", region)
	}
	return r, nil
}

func kiroOIDCEndpoint(region string) string {
	if region == "" || region == "us-east-1" {
		if ep := RegistryOAuth("kiro").Str("ssoOidcEndpoint"); ep != "" {
			return ep
		}
	}
	return "https://oidc." + region + ".amazonaws.com"
}

// KiroRegisterClient ports registerClient (AWS SSO OIDC client/register).
func KiroRegisterClient(ctx context.Context, region string) (clientID, clientSecret string, err error) {
	region, err = AssertValidAWSRegion(region)
	if err != nil {
		return "", "", err
	}
	cfg := RegistryOAuth("kiro")
	status, body, herr := PostJSON(ctx, kiroOIDCEndpoint(region)+"/client/register", map[string]any{
		"clientName": cfg.StrOr("clientName", "kiro-oauth-client"),
		"clientType": cfg.StrOr("clientType", "public"),
		"scopes":     cfg.StrList("scopes"),
		"grantTypes": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"issuerUrl":  cfg.StrOr("issuerUrl", "https://identitycenter.amazonaws.com/ssoins-0000000000000000"),
	}, nil)
	if herr != nil {
		return "", "", herr
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", "", errf("Kiro client registration failed: HTTP %d", status)
	}
	clientID, clientSecret = strOf(body, "clientId"), strOf(body, "clientSecret")
	if clientID == "" || clientSecret == "" {
		return "", "", errf("Kiro registration response missing client credentials")
	}
	return clientID, clientSecret, nil
}

// KiroStartDeviceAuthorization ports startDeviceAuthorization.
func KiroStartDeviceAuthorization(ctx context.Context, clientID, region, startURL string) (map[string]any, error) {
	region, err := AssertValidAWSRegion(region)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"clientId": clientID}
	if startURL != "" {
		payload["startUrl"] = startURL
	}
	status, body, herr := PostJSON(ctx, kiroOIDCEndpoint(region)+"/device_authorization", payload, nil)
	if herr != nil {
		return nil, herr
	}
	if status != http.StatusOK {
		return nil, errf("Kiro device authorization failed: HTTP %d", status)
	}
	return body, nil
}

// KiroPollDeviceToken ports pollForDeviceToken: one attempt; returns
// (tokens, pending, error).
func KiroPollDeviceToken(ctx context.Context, clientID, clientSecret, deviceCode, region string) (map[string]any, bool, error) {
	region, err := AssertValidAWSRegion(region)
	if err != nil {
		return nil, false, err
	}
	status, body, herr := PostJSON(ctx, kiroOIDCEndpoint(region)+"/token", map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"deviceCode":   deviceCode,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
	}, nil)
	if herr != nil {
		return nil, false, herr
	}
	if status == http.StatusBadRequest {
		switch strOf(body, "error") {
		case "authorization_pending", "slow_down":
			return nil, true, nil
		}
	}
	if status != http.StatusOK {
		return nil, false, errf("Kiro token poll failed: %s", firstStr(strOf(body, "error_description"), strOf(body, "error")))
	}
	return body, false, nil
}

// KiroSocialLoginURL ports buildSocialLoginUrl.
func KiroSocialLoginURL(provider, codeChallenge, state string) (string, error) {
	idp := ""
	switch strings.ToLower(provider) {
	case "google":
		idp = "Google"
	case "github":
		idp = "Github"
	default:
		return "", errf("Unsupported Kiro social provider: %s", provider)
	}
	q := url.Values{
		"idp":                   {idp},
		"redirect_uri":          {kiroSocialRedirect},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"prompt":                {"select_account"},
	}
	base := RegistryOAuth("kiro").StrOr("socialLoginUrl", kiroAuthServiceBase+"/login")
	return base + "?" + q.Encode(), nil
}

// KiroSocialExchange ports exchangeSocialCode.
func KiroSocialExchange(ctx context.Context, code, codeVerifier string) (map[string]any, error) {
	status, body, err := PostJSON(ctx, kiroAuthServiceBase+"/oauth/token", map[string]any{
		"code": code, "code_verifier": codeVerifier, "redirect_uri": kiroSocialRedirect,
	}, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Kiro social token exchange failed", status, body, "")
	}
	return body, nil
}

// KiroRefreshToken ports refreshToken: IDC mode (clientId+clientSecret in
// psd) hits the regional OIDC /token endpoint; social mode hits the Kiro
// auth service /refreshToken.
func KiroRefreshToken(ctx context.Context, refreshToken string, psd map[string]any) (map[string]any, error) {
	clientID, clientSecret := "", ""
	region := "us-east-1"
	if psd != nil {
		clientID, _ = psd["clientId"].(string)
		clientSecret, _ = psd["clientSecret"].(string)
		if r, _ := psd["region"].(string); r != "" {
			region = r
		}
	}
	if clientID != "" && clientSecret != "" {
		r, err := AssertValidAWSRegion(region)
		if err != nil {
			return nil, err
		}
		region = r
		status, body, herr := PostJSON(ctx, kiroOIDCEndpoint(region)+"/token", map[string]any{
			"clientId": clientID, "clientSecret": clientSecret,
			"refreshToken": refreshToken, "grantType": "refresh_token",
		}, nil)
		if herr != nil {
			return nil, herr
		}
		if status != http.StatusOK {
			return nil, TokenError("Kiro IDC token refresh failed", status, body, "")
		}
		return body, nil
	}
	status, body, err := PostJSON(ctx, kiroAuthServiceBase+"/refreshToken",
		map[string]any{"refreshToken": refreshToken}, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Kiro token refresh failed", status, body, "")
	}
	return body, nil
}

// KiroValidateImportToken ports validateImportToken (refresh round-trip).
func KiroValidateImportToken(ctx context.Context, refreshToken string, psd map[string]any) (map[string]any, error) {
	return KiroRefreshToken(ctx, refreshToken, psd)
}

// KiroListAvailableProfiles ports listAvailableProfiles → first profile ARN.
func KiroListAvailableProfiles(ctx context.Context, accessToken string) string {
	return FetchKiroProfileArn(ctx, accessToken)
}

// KiroValidateAPIKey ports validateApiKey: ListAvailableModels must return
// at least one model.
func KiroValidateAPIKey(ctx context.Context, apiKey, region string) (map[string]any, error) {
	r, err := AssertValidAWSRegion(region)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("https://q.%s.amazonaws.com/ListAvailableModels?origin=AI_EDITOR", r)
	status, body, herr := GetJSON(ctx, endpoint, map[string]string{
		"Authorization": "Bearer " + apiKey,
		"TokenType":     "API_KEY",
	})
	if herr != nil {
		return nil, herr
	}
	if status != http.StatusOK {
		return nil, TokenError("Kiro API key validation failed", status, body, "")
	}
	models, _ := body["models"].([]any)
	if len(models) == 0 {
		return nil, errf("Kiro API key returned no models")
	}
	return map[string]any{"modelCount": float64(len(models)), "region": r}, nil
}

// KiroExtractEmail ports extractEmailFromIdToken (JWT `email` claim).
func KiroExtractEmail(idToken string) string {
	payload := DecodeJWTPayload(idToken)
	if payload == nil {
		return ""
	}
	return strOf(payload, "email")
}

// KiroClientIDHash ports clientIdHash (sha1 of clientId) used by the SSO
// cache auto-import to find the client registration file.
func KiroClientIDHash(clientID string) string {
	sum := sha256.Sum256([]byte(clientID))
	return hex.EncodeToString(sum[:])
}

// KiroTokenExpiry computes an expiresAt ISO string from a token response
// (expiresIn seconds) — helper for the import routes.
func KiroTokenExpiry(expiresIn float64, ok bool) string {
	if !ok || expiresIn <= 0 {
		expiresIn = 3600
	}
	return time.Now().Add(time.Duration(expiresIn) * time.Second).UTC().Format(time.RFC3339)
}

// NormalizeKiroExternalIdpAuth ports normalizeKiroExternalIdpAuth from
// src/lib/oauth/kiroExternalIdp.js: validates an Entra ID (external IdP)
// Kiro CLI auth blob. Returns the normalized psd-relevant fields.
//
// The JS version additionally parses nested JSON encodings of the blob;
// this port accepts the object shape (already-parsed JSON) and the same
// host allowlist / https rules.
func NormalizeKiroExternalIdpAuth(input map[string]any) (map[string]any, error) {
	if input == nil {
		return nil, errf("Invalid Kiro CLI proxy auth payload")
	}
	tokenEndpoint := strOf(input, "tokenEndpoint")
	if tokenEndpoint == "" {
		tokenEndpoint = strOf(input, "token_endpoint")
	}
	if tokenEndpoint != "" {
		u, err := url.Parse(tokenEndpoint)
		if err != nil || u.Scheme != "https" {
			return nil, errf("Kiro external IdP token endpoint must use https")
		}
		host := strings.ToLower(u.Hostname())
		allowed := map[string]bool{
			"login.microsoftonline.com": true,
			"login.microsoft.com":       true,
			"login.windows.net":         true,
		}
		if !allowed[host] {
			return nil, errf("Kiro external IdP token endpoint host not allowed: %s", host)
		}
	}
	out := map[string]any{}
	for _, k := range []string{"refreshToken", "clientId", "region", "provider", "issuerUrl", "tokenEndpoint", "scopes", "profileArn"} {
		if v := strOf(input, k); v != "" {
			out[k] = v
		}
		if v := strOf(input, camelToSnake(k)); v != "" {
			out[k] = v
		}
	}
	if strOf(out, "refreshToken") == "" {
		return nil, errf("Kiro external IdP auth is missing a refresh token")
	}
	out["authMethod"] = "external_idp"
	return out, nil
}

func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
