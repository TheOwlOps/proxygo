package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxygo/internal/db"
	"proxygo/internal/oauthsvc"
)

func newOAuthTestEnv(t *testing.T) (*http.ServeMux, *db.Store) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mux := http.NewServeMux()
	RegisterOAuth(mux, Deps{Store: store})
	// Session cookie for protected routes.
	return mux, store
}

func doOAuth(t *testing.T, mux *http.ServeMux, store *db.Store, method, path, body string, authed bool) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:4321"
	if authed {
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: CreateSessionToken(store)})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestOAuthAuthorizeClaudePKCE(t *testing.T) {
	mux, store := newOAuthTestEnv(t)
	rec := doOAuth(t, mux, store, "GET", "/api/oauth/claude/authorize?redirect_uri=http://localhost:8080/callback", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var data map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("json: %v", err)
	}
	authURL, _ := data["authUrl"].(string)
	if !strings.Contains(authURL, "code_challenge=") || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("authUrl missing PKCE: %s", authURL)
	}
	if data["codeVerifier"] == "" || data["state"] == "" {
		t.Fatalf("missing verifier/state: %v", data)
	}
	if !strings.Contains(authURL, "state="+data["state"].(string)) {
		t.Fatalf("state not in authUrl: %s", authURL)
	}
}

func TestOAuthAuthorizeCodexFixedPort(t *testing.T) {
	mux, store := newOAuthTestEnv(t)
	rec := doOAuth(t, mux, store, "GET", "/api/oauth/codex/authorize", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var data map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &data)
	if data["fixedPort"] != float64(1455) {
		t.Fatalf("fixedPort = %v", data["fixedPort"])
	}
}

func TestOAuthExchangeClaudeMockAndPersist(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-x","refresh_token":"rt-x","expires_in":7200,"account":{"email_address":"claude@example.com"}}`))
	}))
	defer tokenSrv.Close()
	oauthsvc.TestOverrides = map[string]oauthsvc.Config{"claude": {
		"clientId": "cid", "tokenUrl": tokenSrv.URL, "authorizeUrl": tokenSrv.URL + "/auth",
		"scopes": []any{"user:inference"},
	}}
	defer func() { oauthsvc.TestOverrides = nil }()

	mux, store := newOAuthTestEnv(t)
	body := `{"code":"code-9","redirectUri":"http://localhost:8080/callback","codeVerifier":"ver-9"}`
	rec := doOAuth(t, mux, store, "POST", "/api/oauth/claude/exchange", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["success"] != true {
		t.Fatalf("resp: %v", resp)
	}
	conn, _ := resp["connection"].(map[string]any)
	if conn["email"] != "claude@example.com" || conn["id"] == "" {
		t.Fatalf("connection summary: %v", conn)
	}
	stored, err := store.GetProviderConnections(db.ConnectionFilter{Provider: "claude"})
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored connections: %v %v", stored, err)
	}
	if stored[0]["accessToken"] != "at-x" || stored[0]["refreshToken"] != "rt-x" {
		t.Fatalf("stored record: %v", stored[0])
	}
	if stored[0]["expiresAt"] == "" || stored[0]["testStatus"] != "active" {
		t.Fatalf("stored record fields: %v", stored[0])
	}
}

func TestOAuthDeviceCodeGitHubMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device":
			_, _ = w.Write([]byte(`{"device_code":"dc-7","user_code":"UC-7","verification_uri":"https://example.com/device","expires_in":900,"interval":5}`))
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"gh-tok","expires_in":28800}`))
		}
	}))
	defer srv.Close()
	oauthsvc.TestOverrides = map[string]oauthsvc.Config{"github": {
		"clientId": "cid", "deviceCodeUrl": srv.URL + "/device", "tokenUrl": srv.URL + "/token",
		"scopes": []any{"read:user"}, "copilotTokenUrl": srv.URL + "/nope",
	}}
	defer func() { oauthsvc.TestOverrides = nil }()

	mux, store := newOAuthTestEnv(t)
	rec := doOAuth(t, mux, store, "GET", "/api/oauth/github/device-code", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("device-code status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var dev map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &dev)
	if dev["device_code"] != "dc-7" || dev["codeVerifier"] == "" {
		t.Fatalf("device data: %v", dev)
	}
	rec = doOAuth(t, mux, store, "POST", "/api/oauth/github/poll", `{"deviceCode":"dc-7","codeVerifier":"v"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["success"] != true {
		t.Fatalf("poll resp: %v", resp)
	}
	stored, _ := store.GetProviderConnections(db.ConnectionFilter{Provider: "github"})
	if len(stored) != 1 || stored[0]["accessToken"] != "gh-tok" {
		t.Fatalf("stored: %v", stored)
	}
}

func TestOAuthCodexImportToken(t *testing.T) {
	mux, store := newOAuthTestEnv(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"tok@example.com","exp":1999999999,"https://api.openai.com/auth":{"chatgpt_account_id":"acc-9","chatgpt_plan_type":"pro"}}`))
	jwt := header + "." + payload + ".sig"
	body := `{"accessToken":"` + jwt + `"}`
	rec := doOAuth(t, mux, store, "POST", "/api/oauth/codex/import-token", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["workspace"] != "acc-9" || resp["plan"] != "pro" {
		t.Fatalf("resp: %v", resp)
	}
	stored, _ := store.GetProviderConnections(db.ConnectionFilter{Provider: "codex"})
	if len(stored) != 1 || stored[0]["authType"] != "access_token" || stored[0]["email"] != "tok@example.com" {
		t.Fatalf("stored: %v", stored)
	}
}

func TestOAuthCodexBulkImport(t *testing.T) {
	mux, store := newOAuthTestEnv(t)
	body := `[{"accessToken":"tok-a","refreshToken":"r-a"},{"refreshToken":"no-access"}]`
	rec := doOAuth(t, mux, store, "POST", "/api/oauth/codex/bulk-import", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["failed"] != float64(1) {
		t.Fatalf("resp: %v", resp)
	}
	stored, _ := store.GetProviderConnections(db.ConnectionFilter{Provider: "codex"})
	if len(stored) != 1 || stored[0]["accessToken"] != "tok-a" {
		t.Fatalf("stored: %v", stored)
	}
	// Tokens must never be echoed back.
	if strings.Contains(rec.Body.String(), "tok-a") {
		t.Fatal("bulk import echoed a token")
	}
}

func TestOAuthCursorImportValidation(t *testing.T) {
	mux, store := newOAuthTestEnv(t)
	// Too-short token → 400.
	rec := doOAuth(t, mux, store, "POST", "/api/oauth/cursor/import",
		`{"accessToken":"short","machineId":"123e4567-e89b-12d3-a456-426614174000"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short token status = %d", rec.Code)
	}
	longToken := strings.Repeat("a", 60)
	body := `{"accessToken":"` + longToken + `","machineId":"123e4567-e89b-12d3-a456-426614174000"}`
	rec = doOAuth(t, mux, store, "POST", "/api/oauth/cursor/import", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status = %d, body = %s", rec.Code, rec.Body.String())
	}
	stored, _ := store.GetProviderConnections(db.ConnectionFilter{Provider: "cursor"})
	if len(stored) != 1 {
		t.Fatalf("stored: %v", stored)
	}
	psd, _ := stored[0]["providerSpecificData"].(map[string]any)
	if psd["machineId"] != "123e4567-e89b-12d3-a456-426614174000" || psd["checksum"] == "" {
		t.Fatalf("psd: %v", psd)
	}
}

func TestOAuthUnknownAction(t *testing.T) {
	mux, store := newOAuthTestEnv(t)
	rec := doOAuth(t, mux, store, "GET", "/api/oauth/claude/bogus-action", "", true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestSAMLMetadataRoute(t *testing.T) {
	mux, _ := newOAuthTestEnv(t)
	req := httptest.NewRequest("GET", "/api/auth/saml/metadata", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "EntityDescriptor") {
		t.Fatalf("metadata body: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/xml") {
		t.Fatalf("content type = %q", ct)
	}
}

func TestOIDCStartNotConfigured(t *testing.T) {
	mux, _ := newOAuthTestEnv(t)
	req := httptest.NewRequest("GET", "/api/auth/oidc/start", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "oidc_not_configured") {
		t.Fatalf("location = %q", loc)
	}
}
