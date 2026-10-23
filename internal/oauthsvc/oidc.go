package oauthsvc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Port of src/lib/auth/oidc.js — dashboard OIDC SSO. Settings keys (read by
// the api layer from db settings and passed in): oidcIssuerUrl,
// oidcClientId, oidcClientSecret, oidcScopes, oidcLoginLabel, authMode.
// The ID token is verified against the issuer JWKS with stdlib crypto
// (RS256) — the JS uses jose; the verification steps are identical.

// OIDCRuntimeConfig mirrors getOIDCRuntimeConfig's normalized shape.
type OIDCRuntimeConfig struct {
	Enabled      bool
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       string
	LoginLabel   string
}

// OIDCRuntime builds the runtime config from settings + authMode.
func OIDCRuntime(settings map[string]any, authMode string) OIDCRuntimeConfig {
	get := func(k string) string {
		if settings == nil {
			return ""
		}
		return strOf(settings, k)
	}
	cfg := OIDCRuntimeConfig{
		IssuerURL:    strings.TrimRight(strings.TrimSpace(get("oidcIssuerUrl")), "/"),
		ClientID:     strings.TrimSpace(get("oidcClientId")),
		ClientSecret: strings.TrimSpace(get("oidcClientSecret")),
		Scopes:       strings.TrimSpace(get("oidcScopes")),
		LoginLabel:   strings.TrimSpace(get("oidcLoginLabel")),
	}
	if cfg.Scopes == "" {
		cfg.Scopes = "openid profile email"
	}
	if cfg.LoginLabel == "" {
		cfg.LoginLabel = "Single Sign-On"
	}
	mode := strings.ToLower(strings.TrimSpace(authMode))
	cfg.Enabled = (mode == "oidc" || mode == "both") && cfg.IssuerURL != "" && cfg.ClientID != ""
	return cfg
}

// OIDCDiscovery fetches the issuer discovery document.
func OIDCDiscovery(ctx context.Context, issuerURL string) (map[string]any, error) {
	endpoint := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	status, body, err := GetJSON(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("OIDC discovery failed: HTTP %d", status)
	}
	if strOf(body, "authorization_endpoint") == "" || strOf(body, "token_endpoint") == "" {
		return nil, errf("OIDC discovery document is missing endpoints")
	}
	return body, nil
}

// OIDCBuildAuthorizationURL ports buildOIDCAuthorizationUrl's parameter set.
func OIDCBuildAuthorizationURL(authorizationEndpoint, clientID, redirectURI, scopes, state, nonce, codeChallenge string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return authorizationEndpoint + "?" + q.Encode()
}

// OIDCExchangeCode ports exchangeOIDCCode.
func OIDCExchangeCode(ctx context.Context, tokenEndpoint string, cfg OIDCRuntimeConfig, code, redirectURI, codeVerifier string) (map[string]any, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {cfg.ClientID},
		"code_verifier": {codeVerifier},
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	status, body, err := PostForm(ctx, tokenEndpoint, form, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("OIDC token exchange failed", status, body, "")
	}
	return body, nil
}

// OIDCVerifyIDToken verifies an ID token's RS256 signature against the
// issuer JWKS and validates iss/aud/exp/nonce claims.
func OIDCVerifyIDToken(ctx context.Context, rawToken string, discovery map[string]any, cfg OIDCRuntimeConfig, nonce string) (map[string]any, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errf("Invalid ID token format")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errf("Invalid ID token header")
	}
	var header map[string]any
	if json.Unmarshal(headerRaw, &header) != nil {
		return nil, errf("Invalid ID token header")
	}
	if alg := strOf(header, "alg"); alg != "" && alg != "RS256" {
		return nil, errf("Unsupported ID token alg: %s", alg)
	}
	kid := strOf(header, "kid")

	jwksURI := strOf(discovery, "jwks_uri")
	if jwksURI == "" {
		return nil, errf("OIDC discovery document has no jwks_uri")
	}
	status, jwks, err := GetJSON(ctx, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("JWKS fetch failed: HTTP %d", status)
	}
	keys, _ := jwks["keys"].([]any)
	var pub *rsa.PublicKey
	for _, k := range keys {
		km, ok := k.(map[string]any)
		if !ok {
			continue
		}
		if kid != "" && strOf(km, "kid") != kid {
			continue
		}
		if strOf(km, "kty") != "RSA" {
			continue
		}
		nBytes, err1 := base64.RawURLEncoding.DecodeString(strOf(km, "n"))
		eBytes, err2 := base64.RawURLEncoding.DecodeString(strOf(km, "e"))
		if err1 != nil || err2 != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
		break
	}
	if pub == nil {
		return nil, errf("No matching JWKS key for ID token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errf("Invalid ID token signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errf("ID token signature verification failed")
	}
	claims := DecodeJWTPayload(rawToken)
	if claims == nil {
		return nil, errf("Invalid ID token payload")
	}
	if iss := strOf(claims, "iss"); iss != "" && strings.TrimRight(iss, "/") != strings.TrimRight(cfg.IssuerURL, "/") {
		if discIss := strOf(discovery, "issuer"); discIss == "" || strings.TrimRight(discIss, "/") != strings.TrimRight(iss, "/") {
			return nil, errf("ID token issuer mismatch")
		}
	}
	audOK := false
	switch aud := claims["aud"].(type) {
	case string:
		audOK = aud == cfg.ClientID
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == cfg.ClientID {
				audOK = true
			}
		}
	}
	if !audOK {
		return nil, errf("ID token audience mismatch")
	}
	if exp, ok := numOf(claims, "exp"); ok && time.Now().Unix() > int64(exp) {
		return nil, errf("ID token expired")
	}
	if nonce != "" && strOf(claims, "nonce") != nonce {
		return nil, errf("ID token nonce mismatch")
	}
	return claims, nil
}

// OIDCPickDisplayName / OIDCPickEmail mirror the claim preference order.
func OIDCPickDisplayName(claims map[string]any) string {
	return firstStr(strOf(claims, "name"), strOf(claims, "preferred_username"), strOf(claims, "email"), strOf(claims, "sub"))
}

// OIDCPickEmail mirrors pickOIDCEmail.
func OIDCPickEmail(claims map[string]any) string {
	return firstStr(strOf(claims, "email"), strOf(claims, "preferred_username"), strOf(claims, "upn"))
}

// OIDCProbeClientSecret ports the test route's dummy-code exchange probe:
// returns "ok", "invalid_client" or "invalid_grant" style outcome as an
// error classification string.
func OIDCProbeClientSecret(ctx context.Context, tokenEndpoint string, cfg OIDCRuntimeConfig, redirectURI string) (classification string, status int, err error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"dummy-probe-code"},
		"redirect_uri": {redirectURI},
		"client_id":    {cfg.ClientID},
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	status, body, herr := PostForm(ctx, tokenEndpoint, form, nil)
	if herr != nil {
		return "", 0, herr
	}
	code := strOf(body, "error")
	switch code {
	case "invalid_client":
		return "invalid_client", status, nil
	case "invalid_grant":
		return "invalid_grant", status, nil
	}
	if status >= 200 && status < 300 {
		return "unexpected_success", status, nil
	}
	return firstStr(code, "unknown_error"), status, nil
}

// PublicOrigin mirrors getPublicOrigin: BASE_URL / NEXT_PUBLIC_BASE_URL
// env wins, else the forwarded proto/host of the request.
func PublicOrigin(r *http.Request) string {
	for _, env := range []string{"BASE_URL", "NEXT_PUBLIC_BASE_URL"} {
		if v := strings.TrimRight(strings.TrimSpace(getEnv(env)), "/"); v != "" {
			return v
		}
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return proto + "://" + host
}

func getEnv(k string) string { return os.Getenv(k) }
