package oauthsvc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func timeNow() time.Time { return time.Now() }

func TestPKCE(t *testing.T) {
	p := GeneratePKCE(32)
	if len(p.CodeVerifier) != 43 {
		t.Fatalf("verifier length = %d, want 43", len(p.CodeVerifier))
	}
	if p.CodeChallenge != GenerateCodeChallenge(p.CodeVerifier) {
		t.Fatal("challenge mismatch")
	}
	if len(p.State) != 43 {
		t.Fatalf("state length = %d, want 43", len(p.State))
	}
	p96 := GeneratePKCE(96)
	if len(p96.CodeVerifier) != 128 {
		t.Fatalf("xai verifier length = %d, want 128", len(p96.CodeVerifier))
	}
}

func makeJWT(payload map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "none"})
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func TestCodexAccountInfo(t *testing.T) {
	tok := makeJWT(map[string]any{
		"email": "dev@example.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acc-123",
			"chatgpt_plan_type":  "plus",
		},
	})
	info := ExtractCodexAccountInfo(tok)
	if info.Email != "dev@example.com" || info.ChatGPTAccountID != "acc-123" || info.ChatGPTPlanType != "plus" {
		t.Fatalf("bad info: %+v", info)
	}
	if got := ExtractEmailFromAccessToken(tok); got != "dev@example.com" {
		t.Fatalf("email = %q", got)
	}
}

func TestGenerateAuthDataClaude(t *testing.T) {
	data, err := GenerateAuthData(context.Background(), "claude", "http://localhost:8080/callback", nil)
	if err != nil {
		t.Fatalf("GenerateAuthData: %v", err)
	}
	authURL, _ := data["authUrl"].(string)
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authUrl: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("missing PKCE params: %s", authURL)
	}
	if q.Get("state") != data["state"] {
		t.Fatal("state mismatch between URL and auth data")
	}
	if q.Get("client_id") == "" {
		t.Fatal("missing client_id (registry config)")
	}
	if data["codeVerifier"] == "" {
		t.Fatal("missing codeVerifier")
	}
}

func TestGenerateAuthDataCodexFixedPort(t *testing.T) {
	data, err := GenerateAuthData(context.Background(), "codex", "http://localhost:1455/auth/callback", nil)
	if err != nil {
		t.Fatalf("GenerateAuthData codex: %v", err)
	}
	if data["fixedPort"] != float64(1455) || data["callbackPath"] != "/auth/callback" {
		t.Fatalf("codex fixed port/callback path wrong: %v", data)
	}
}

func TestExchangeClaudeAgainstMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("anthropic-beta") != "oauth-2025-04-20" {
			t.Errorf("missing anthropic-beta header")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["grant_type"] != "authorization_code" || body["code"] != "code-1" {
			t.Errorf("bad exchange body: %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"scope":"user:inference user:profile","account":{"email_address":"c@example.com"}}`))
	}))
	defer srv.Close()
	TestOverrides = map[string]Config{"claude": {
		"clientId": "cid", "tokenUrl": srv.URL, "authorizeUrl": srv.URL + "/auth",
		"scopes": []any{"user:inference"},
	}}
	defer func() { TestOverrides = nil }()
	tokens, err := ExchangeTokens(context.Background(), "claude", "code-1#state-9", "http://localhost:8080/callback", "verifier-1", "", nil)
	if err != nil {
		t.Fatalf("ExchangeTokens: %v", err)
	}
	if tokens["accessToken"] != "at-1" || tokens["refreshToken"] != "rt-1" || tokens["email"] != "c@example.com" {
		t.Fatalf("bad tokens: %v", tokens)
	}
	if tokens["expiresIn"] != float64(3600) {
		t.Fatalf("expiresIn: %v", tokens["expiresIn"])
	}
}

func TestDeviceFlowGitHubMock(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"dc-1","user_code":"UC-1","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("device_code") == "dc-1" {
			_, _ = w.Write([]byte(`{"access_token":"gh-at","refresh_token":"gh-rt","expires_in":28800,"scope":"read:user"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	TestOverrides = map[string]Config{"github": {
		"clientId": "cid", "deviceCodeUrl": srv.URL + "/device", "tokenUrl": srv.URL + "/token",
		"scopes": []any{"read:user"}, "copilotTokenUrl": srv.URL + "/copilot-missing",
	}}
	defer func() { TestOverrides = nil }()

	data, err := RequestDeviceCode(context.Background(), "github", nil)
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}
	if data["device_code"] != "dc-1" || data["codeVerifier"] == "" {
		t.Fatalf("bad device data: %v", data)
	}
	pending, err := PollForToken(context.Background(), "github", "dc-x", "", nil)
	if err != nil {
		t.Fatalf("PollForToken pending: %v", err)
	}
	if pending.Success || !pending.Pending() {
		t.Fatalf("expected pending, got %+v", pending)
	}
	done, err := PollForToken(context.Background(), "github", "dc-1", "", nil)
	if err != nil {
		t.Fatalf("PollForToken: %v", err)
	}
	if !done.Success || done.Tokens["accessToken"] != "gh-at" {
		t.Fatalf("bad poll result: %+v", done)
	}
}

func TestXiaomiECDHCallbackRoundTrip(t *testing.T) {
	pubB64, privDER, err := XiaomiGenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	if pubB64 == "" || len(privDER) == 0 {
		t.Fatal("empty keypair")
	}
	// Build a callback payload the way the platform does.
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Server public key from SPKI.
	spki, _ := base64.StdEncoding.DecodeString(pubB64)
	serverPub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatalf("parse spki: %v", err)
	}
	ecdhPub, ok := serverPub.(*ecdh.PublicKey)
	if !ok {
		t.Fatal("not an ecdh key")
	}
	shared, err := eph.ECDH(ecdhPub)
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256(shared)
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	plain, _ := json.Marshal(map[string]any{"uid": "u-42", "sk": "sk-test", "url": "https://api.example/v1"})
	sealed := gcm.Seal(nil, nonce, plain, nil)
	wire := append(append(append([]byte{}, nonce...), eph.PublicKey().Bytes()...), sealed...)
	enc := base64.StdEncoding.EncodeToString(wire)
	out, err := XiaomiDecryptCallback(privDER, enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if out["uid"] != "u-42" || out["sk"] != "sk-test" || out["url"] != "https://api.example/v1" {
		t.Fatalf("bad decrypted payload: %v", out)
	}
	authURL := XiaomiBuildAuthorizeURL(pubB64, "http://localhost:58080/", "k")
	if !strings.Contains(authURL, XiaomiPlatformURL+"/authorize?") || !strings.Contains(authURL, "kn=9router") {
		t.Fatalf("bad authorize url: %s", authURL)
	}
}

func TestZedRoundTrip(t *testing.T) {
	native, err := CreateZedNativeAuthData("https://zed.dev/native_app_signin", 58443)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.Contains(native.AuthURL, "native_app_public_key=") || !strings.Contains(native.AuthURL, "system_id="+native.SystemID) {
		t.Fatalf("bad auth url: %s", native.AuthURL)
	}
	priv, err := DecodeZedPrivateKeyVerifier(native.CodeVerifier)
	if err != nil {
		t.Fatalf("decode verifier: %v", err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, []byte("zed-token-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptZedAccessToken(priv, base64.StdEncoding.EncodeToString(ciphertext))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "zed-token-1" {
		t.Fatalf("plain = %q", plain)
	}
	payload, err := ParseZedCallbackPayload(`{"user_id":"42","access_token":"abc"}`)
	if err != nil || payload.UserID != "42" || payload.AccessToken != "abc" {
		t.Fatalf("payload: %+v %v", payload, err)
	}
}

func TestQoderParseExpiry(t *testing.T) {
	if got := QoderParseExpiry(float64(1781594470000), nil); got != 1781594470000 {
		t.Fatalf("numeric: %d", got)
	}
	if got := QoderParseExpiry("1781594470000", nil); got != 1781594470000 {
		t.Fatalf("numeric string: %d", got)
	}
	if got := QoderParseExpiry(nil, float64(0)); got <= 0 {
		t.Fatalf("zero expires_in should be ~now: %d", got)
	}
}

func TestPKCS1PEMRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	verifier := zedPrivateKeyPrefix + base64.RawURLEncoding.EncodeToString(pemBytes)
	back, err := DecodeZedPrivateKeyVerifier(verifier)
	if err != nil || back.D.Cmp(key.D) != 0 {
		t.Fatalf("round trip: %v", err)
	}
}

func TestSAMLHelpers(t *testing.T) {
	cert := "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZZZ\n-----END CERTIFICATE-----"
	formatted := FormatX509Certificate(cert)
	if !strings.HasPrefix(formatted, "-----BEGIN CERTIFICATE-----\n") {
		t.Fatalf("formatted cert: %q", formatted)
	}
	cfg := SAMLRuntime(map[string]any{
		"samlEntryPoint": "https://idp.example.com/sso",
		"samlCert":       cert,
	}, "http://localhost:8080")
	if !SAMLConfigured(cfg) {
		t.Fatal("expected configured")
	}
	meta := GenerateSAMLMetadata(cfg)
	if !strings.Contains(meta, "entityID=\"urn:9router:sp\"") || !strings.Contains(meta, "/api/auth/saml/acs") {
		t.Fatalf("metadata: %s", meta)
	}
	authURL, err := BuildSAMLAuthnRequestURL(cfg, "_req1", timeNow())
	if err != nil {
		t.Fatalf("authn request: %v", err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("SAMLRequest") == "" || u.Query().Get("RelayState") != "_req1" {
		t.Fatalf("authn url: %s", authURL)
	}
	if !SAMLAssertionsVerified {
		t.Fatal("SAMLAssertionsVerified must be true: XMLDSig verification is ported (saml_verify.go)")
	}
}

func TestMimoSessionCodec(t *testing.T) {
	sess := &MimoLoginSession{
		State: "st-1", Region: "cn", CreatedAt: timeNow().UnixMilli(),
		Jar: []MimoCookie{
			{Name: "passToken", Value: "pt-1", Domain: ".xiaomi.com", Path: "/"},
			{Name: "userId", Value: "u-1", Domain: ".xiaomi.com", Path: "/"},
			{Name: "cUserId", Value: "cu-1", Domain: ".xiaomi.com", Path: "/"},
		},
	}
	value, err := EncodeMimoLoginSession(sess)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := DecodeMimoLoginSession(value)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	pt, uid, cuid := back.MimoIdentity()
	if pt != "pt-1" || uid != "u-1" || cuid != "cu-1" {
		t.Fatalf("identity: %q %q %q", pt, uid, cuid)
	}
	if MimoRegionBase("cn") != "https://mimo-server-cn.xiaomimimo.com" || MimoRegionBase("xx") != MimoRegionBases["sgp"] {
		t.Fatal("region base mismatch")
	}
}

func TestValidateXaiEndpoint(t *testing.T) {
	if _, err := ValidateXaiOAuthEndpoint("https://auth.x.ai/oauth2/token", "token"); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
	if _, err := ValidateXaiOAuthEndpoint("https://evil.example.com/token", "token"); err == nil {
		t.Fatal("evil endpoint accepted")
	}
	if _, err := ValidateXaiOAuthEndpoint("http://auth.x.ai/token", "token"); err == nil {
		t.Fatal("http endpoint accepted")
	}
}

func TestKiroRegionGuard(t *testing.T) {
	if _, err := AssertValidAWSRegion("eu-west-1"); err != nil {
		t.Fatalf("valid region: %v", err)
	}
	if _, err := AssertValidAWSRegion("../../etc"); err == nil {
		t.Fatal("bad region accepted")
	}
	if r, _ := AssertValidAWSRegion(""); r != "us-east-1" {
		t.Fatalf("default region = %q", r)
	}
}
