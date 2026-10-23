package oauthsvc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
)

// Port of src/lib/oauth/providers/zed.js + src/lib/oauth/utils/zed.js —
// Zed's native-app RSA key-exchange flow:
//   1. Generate an RSA-2048 keypair; the PKCS#1 DER public key (base64url)
//      goes into the zed.dev native_app_signin URL.
//   2. The codeVerifier IS the private key: "zed-rsa-pkcs1:" +
//      base64url(PEM PKCS#1 private key).
//   3. The callback token is RSA-OAEP-SHA256 encrypted to that key
//      (PKCS#1 v1.5 fallback, guarded by a U+FFFD replacement-char check).

const zedPrivateKeyPrefix = "zed-rsa-pkcs1:"

// ZedNativeAuth is the authorize-time material for the Zed flow.
type ZedNativeAuth struct {
	AuthURL      string
	State        string
	CodeVerifier string
	SystemID     string
}

// CreateZedNativeAuthData ports the zed buildAuthUrl preparation.
func CreateZedNativeAuthData(authorizeURL string, nativeAppPort int) (*ZedNativeAuth, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pubDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubB64 := base64.RawURLEncoding.EncodeToString(pubDER)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	verifier := zedPrivateKeyPrefix + base64.RawURLEncoding.EncodeToString(privPEM)
	systemID := newUUID()
	state := GenerateState()
	base := authorizeURL
	if base == "" {
		base = "https://zed.dev/native_app_signin"
	}
	authURL := base + "?native_app_port=" + itoa(nativeAppPort) +
		"&native_app_public_key=" + pubB64 + "&system_id=" + systemID
	return &ZedNativeAuth{AuthURL: authURL, State: state, CodeVerifier: verifier, SystemID: systemID}, nil
}

// DecodeZedPrivateKeyVerifier reverses the verifier encoding.
func DecodeZedPrivateKeyVerifier(verifier string) (*rsa.PrivateKey, error) {
	if !strings.HasPrefix(verifier, zedPrivateKeyPrefix) {
		return nil, errf("Invalid Zed code verifier")
	}
	pemBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(verifier, zedPrivateKeyPrefix))
	if err != nil {
		return nil, errf("Invalid Zed code verifier encoding")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errf("Invalid Zed private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ZedCallbackPayload is the parsed callback token JSON.
type ZedCallbackPayload struct {
	UserID      string
	AccessToken string // still encrypted (base64)
}

// ParseZedCallbackPayload ports parseZedCallbackPayload: the callback
// `token` param is a JSON (possibly URL-encoded) object.
func ParseZedCallbackPayload(raw string) (*ZedCallbackPayload, error) {
	text := strings.TrimSpace(raw)
	if decoded, err := base64.RawURLEncoding.DecodeString(text); err == nil && strings.HasPrefix(strings.TrimSpace(string(decoded)), "{") {
		text = string(decoded)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return nil, errf("Invalid Zed callback payload")
	}
	p := &ZedCallbackPayload{
		UserID:      firstStr(strOf(obj, "user_id"), strOf(obj, "userId")),
		AccessToken: firstStr(strOf(obj, "access_token"), strOf(obj, "accessToken"), strOf(obj, "token")),
	}
	if p.UserID == "" || p.AccessToken == "" {
		return nil, errf("Zed callback payload missing user_id/access_token")
	}
	return p, nil
}

// DecryptZedAccessToken ports decryptZedAccessToken.
func DecryptZedAccessToken(privateKey *rsa.PrivateKey, encryptedB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		ciphertext, err = base64.RawURLEncoding.DecodeString(encryptedB64)
		if err != nil {
			return "", errf("Invalid Zed encrypted token")
		}
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err == nil {
		return string(plain), nil
	}
	plain, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return "", errf("Failed to decrypt Zed access token")
	}
	text := string(plain)
	if strings.ContainsRune(text, '�') {
		return "", errf("Zed access token decryption produced invalid text")
	}
	return text, nil
}

// FetchZedAuthenticatedUser ports fetchZedAuthenticatedUser.
func FetchZedAuthenticatedUser(ctx context.Context, userID, accessToken, systemID string) (map[string]any, error) {
	status, body, err := GetJSON(ctx, "https://cloud.zed.dev/client/users/me", map[string]string{
		"Authorization":   userID + " " + accessToken,
		"x-zed-system-id": systemID,
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("Zed user fetch failed", status, body, "")
	}
	return body, nil
}

// ResolveZedOrganizationID extracts the first organization id from a Zed
// user object ("" when none).
func ResolveZedOrganizationID(user map[string]any) string {
	if user == nil {
		return ""
	}
	if orgs, ok := user["organizations"].([]any); ok && len(orgs) > 0 {
		if m, ok := orgs[0].(map[string]any); ok {
			if id := strOf(m, "id"); id != "" {
				return id
			}
			if f, ok := numOf(m, "id"); ok {
				return itoa(int(f))
			}
		}
	}
	return ""
}

// ExchangeZedCode ports the zed exchangeToken: parse + decrypt + fetch user.
func ExchangeZedCode(ctx context.Context, code, codeVerifier, systemID string) (map[string]any, error) {
	payload, err := ParseZedCallbackPayload(code)
	if err != nil {
		return nil, err
	}
	priv, err := DecodeZedPrivateKeyVerifier(codeVerifier)
	if err != nil {
		return nil, err
	}
	accessToken, err := DecryptZedAccessToken(priv, payload.AccessToken)
	if err != nil {
		return nil, err
	}
	user, err := FetchZedAuthenticatedUser(ctx, payload.UserID, accessToken, systemID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"accessToken": accessToken}
	psd := map[string]any{
		"authMethod": "native_app",
		"userId":     payload.UserID,
		"systemId":   systemID,
	}
	if orgID := ResolveZedOrganizationID(user); orgID != "" {
		psd["organizationId"] = orgID
	}
	out["providerSpecificData"] = psd
	SetIf(out, "email", strOf(user, "email"))
	SetIf(out, "displayName", firstStr(strOf(user, "name"), strOf(user, "github_login")))
	return out, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
