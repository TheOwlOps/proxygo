package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"9router-go/internal/db"
)

type testEnv struct {
	mux   *http.ServeMux
	store *db.Store
	ipSeq int
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("INITIAL_PASSWORD", "")
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mux := http.NewServeMux()
	RegisterAuth(mux, Deps{Store: store})
	return &testEnv{mux: mux, store: store}
}

// do performs a request from a fresh client IP (distinct limiter bucket)
// with a loopback RemoteAddr unless remote=true.
func (e *testEnv) do(t *testing.T, method, path, body string, cookie string, remote bool) *httptest.ResponseRecorder {
	t.Helper()
	e.ipSeq++
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-forwarded-for", "10.0.0."+itoa(e.ipSeq))
	if remote {
		req.RemoteAddr = "203.0.113.9:4321"
	} else {
		req.RemoteAddr = "127.0.0.1:4321"
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func loginCookie(t *testing.T, e *testEnv, password string) string {
	t.Helper()
	rec := e.do(t, "POST", "/api/auth/login", `{"password":"`+password+`"}`, "", false)
	if rec.Code != 200 {
		t.Fatalf("login status %d body %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, "auth_token=") {
			return strings.Split(c, ";")[0]
		}
	}
	t.Fatalf("no auth_token cookie in %v", rec.Header())
	return ""
}

func TestLoginDefaultPasswordLocalAndStatus(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, "POST", "/api/auth/login", `{"password":"123456"}`, "", false)
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	out := decode(t, rec)
	if out["success"] != true || out["mustChangePassword"] != false {
		t.Fatalf("login body %v", out)
	}
	cookie := loginCookie(t, e, "123456")

	rec = e.do(t, "GET", "/api/auth/status", "", cookie, false)
	out = decode(t, rec)
	if out["authenticated"] != true || out["hasPassword"] != false || out["loginMethod"] != "Password" {
		t.Fatalf("status body %v", out)
	}

	// Logout clears the cookie.
	rec = e.do(t, "POST", "/api/auth/logout", "", cookie, false)
	if rec.Code != 200 || decode(t, rec)["success"] != true {
		t.Fatalf("logout %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginWrongPasswordAndLockout(t *testing.T) {
	e := newTestEnv(t)
	// Same client IP for all attempts in this test: use a fixed bucket by
	// re-running with identical XFF — emulate by direct calls.
	doWrong := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"nope"}`))
		req.Header.Set("x-forwarded-for", "10.9.9.9")
		req.RemoteAddr = "127.0.0.1:4321"
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		return rec
	}
	rec := doWrong()
	if rec.Code != 401 {
		t.Fatalf("first wrong: %d %s", rec.Code, rec.Body.String())
	}
	out := decode(t, rec)
	if out["remainingBeforeLock"] != float64(4) {
		t.Fatalf("remaining %v", out)
	}
	for i := 0; i < 3; i++ {
		if rec := doWrong(); rec.Code != 401 {
			t.Fatalf("wrong %d: %d", i, rec.Code)
		}
	}
	// 5th failure engages the lock → 429.
	rec = doWrong()
	if rec.Code != 429 {
		t.Fatalf("5th wrong should lock: %d %s", rec.Code, rec.Body.String())
	}
	out = decode(t, rec)
	if out["retryAfter"] == nil || out["resetHint"] == nil {
		t.Fatalf("lock body %v", out)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
	// Even the correct password is refused while locked.
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"123456"}`))
	req.Header.Set("x-forwarded-for", "10.9.9.9")
	req.RemoteAddr = "127.0.0.1:4321"
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != 429 {
		t.Fatalf("locked correct password: %d", rec.Code)
	}
}

func TestLoginRemoteDefaultPasswordBlocked(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, "POST", "/api/auth/login", `{"password":"123456"}`, "", true)
	if rec.Code != 403 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	out := decode(t, rec)
	if out["mustChangePassword"] != true || out["success"] != false {
		t.Fatalf("body %v", out)
	}
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, "auth_token=") && !strings.HasPrefix(c, "auth_token=;") {
			t.Fatalf("session cookie must not be issued: %s", c)
		}
	}
}

func TestKeysCRUDBehindAuth(t *testing.T) {
	e := newTestEnv(t)
	// No session → 401 (requireLogin defaults on).
	rec := e.do(t, "GET", "/api/keys", "", "", false)
	if rec.Code != 401 {
		t.Fatalf("unauth keys: %d %s", rec.Code, rec.Body.String())
	}
	cookie := loginCookie(t, e, "123456")

	rec = e.do(t, "POST", "/api/keys", `{"name":"k1"}`, cookie, false)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	created := decode(t, rec)
	id, _ := created["id"].(string)
	keyStr, _ := created["key"].(string)
	if id == "" || !strings.HasPrefix(keyStr, "sk-") {
		t.Fatalf("created %v", created)
	}

	rec = e.do(t, "POST", "/api/keys", `{}`, cookie, false)
	if rec.Code != 400 {
		t.Fatalf("create without name: %d", rec.Code)
	}

	rec = e.do(t, "GET", "/api/keys", "", cookie, false)
	list := decode(t, rec)
	keys, _ := list["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("list %v", list)
	}

	rec = e.do(t, "PUT", "/api/keys/"+id, `{"isActive":false}`, cookie, false)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	updated := decode(t, rec)["key"].(map[string]any)
	if updated["isActive"] != false {
		t.Fatalf("updated %v", updated)
	}

	rec = e.do(t, "PUT", "/api/keys/"+id, `{"access":{"restricted":"yes"}}`, cookie, false)
	if rec.Code != 400 {
		t.Fatalf("bad access: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "PUT", "/api/keys/"+id, `{"access":{"restricted":true,"allow":["openai/gpt-4o"," openai/gpt-4o "]}}`, cookie, false)
	if rec.Code != 200 {
		t.Fatalf("good access: %d %s", rec.Code, rec.Body.String())
	}
	acc := decode(t, rec)["key"].(map[string]any)["access"].(map[string]any)
	if acc["restricted"] != true {
		t.Fatalf("access %v", acc)
	}

	rec = e.do(t, "GET", "/api/keys/missing-id", "", cookie, false)
	if rec.Code != 404 {
		t.Fatalf("missing get: %d", rec.Code)
	}
	rec = e.do(t, "DELETE", "/api/keys/"+id, "", cookie, false)
	if rec.Code != 200 || decode(t, rec)["message"] != "Key deleted successfully" {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "DELETE", "/api/keys/"+id, "", cookie, false)
	if rec.Code != 404 {
		t.Fatalf("delete again: %d", rec.Code)
	}
}

func TestSettingsPatchPasswordThenLogin(t *testing.T) {
	e := newTestEnv(t)
	cookie := loginCookie(t, e, "123456")

	// GET settings: no password leak, hasPassword false.
	rec := e.do(t, "GET", "/api/settings", "", cookie, false)
	out := decode(t, rec)
	if _, leaked := out["password"]; leaked {
		t.Fatal("password leaked in GET /api/settings")
	}
	if out["hasPassword"] != false {
		t.Fatalf("hasPassword %v", out)
	}

	// First-time set: no current password needed.
	rec = e.do(t, "PATCH", "/api/settings", `{"newPassword":"newpass123"}`, cookie, false)
	if rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	if _, leaked := decode(t, rec)["password"]; leaked {
		t.Fatal("password leaked in PATCH response")
	}

	// Old default no longer works; the new password does (even remotely,
	// because a stored hash now exists).
	rec = e.do(t, "POST", "/api/auth/login", `{"password":"123456"}`, "", false)
	if rec.Code != 401 {
		t.Fatalf("old password login: %d", rec.Code)
	}
	rec = e.do(t, "POST", "/api/auth/login", `{"password":"newpass123"}`, "", true)
	if rec.Code != 200 {
		t.Fatalf("new password remote login: %d %s", rec.Code, rec.Body.String())
	}

	// Changing again requires the current password.
	cookie2 := loginCookie(t, e, "newpass123")
	rec = e.do(t, "PATCH", "/api/settings", `{"newPassword":"third123"}`, cookie2, false)
	if rec.Code != 400 {
		t.Fatalf("patch without current: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "PATCH", "/api/settings", `{"currentPassword":"wrong","newPassword":"third123"}`, cookie2, false)
	if rec.Code != 401 {
		t.Fatalf("patch wrong current: %d", rec.Code)
	}
	rec = e.do(t, "PATCH", "/api/settings", `{"currentPassword":"newpass123","newPassword":"third123"}`, cookie2, false)
	if rec.Code != 200 {
		t.Fatalf("patch with current: %d %s", rec.Code, rec.Body.String())
	}
	_ = loginCookie(t, e, "third123")

	// Mass-assignment guard: a raw "password" field is ignored (not the
	// hash channel) — login still uses the bcrypt hash set above.
	rec = e.do(t, "PATCH", "/api/settings", `{"password":"plaintext"}`, cookie2, false)
	if rec.Code != 200 {
		t.Fatalf("patch raw password field: %d", rec.Code)
	}
	rec = e.do(t, "POST", "/api/auth/login", `{"password":"plaintext"}`, "", false)
	if rec.Code != 401 {
		t.Fatalf("plaintext password must not work: %d", rec.Code)
	}
}

func TestResetPasswordLocalOnly(t *testing.T) {
	e := newTestEnv(t)
	cookie := loginCookie(t, e, "123456")
	rec := e.do(t, "PATCH", "/api/settings", `{"newPassword":"changed123"}`, cookie, false)
	if rec.Code != 200 {
		t.Fatalf("patch: %d", rec.Code)
	}
	// Remote + session → still blocked (local-only route).
	rec = e.do(t, "POST", "/api/auth/reset-password", "", cookie, true)
	if rec.Code != 403 {
		t.Fatalf("remote reset: %d %s", rec.Code, rec.Body.String())
	}
	// Local + session → allowed; default password works again.
	rec = e.do(t, "POST", "/api/auth/reset-password", "", cookie, false)
	if rec.Code != 200 {
		t.Fatalf("local reset: %d %s", rec.Code, rec.Body.String())
	}
	_ = loginCookie(t, e, "123456")
}

func TestDatabaseExportImportPasswordGate(t *testing.T) {
	e := newTestEnv(t)
	cookie := loginCookie(t, e, "123456")

	rec := e.do(t, "GET", "/api/settings/database", "", cookie, false)
	if rec.Code != 401 {
		t.Fatalf("export without password header: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/settings/database", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("Cookie", cookie)
	req.Header.Set("x-9r-password", "123456")
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	exported := decode(t, rec)
	if _, ok := exported["settings"]; !ok {
		t.Fatalf("export shape %v", exported)
	}

	rec = e.do(t, "POST", "/api/settings/database", `{"password":"wrong"}`, cookie, false)
	if rec.Code != 401 {
		t.Fatalf("import wrong password: %d", rec.Code)
	}
	payload, _ := json.Marshal(map[string]any{"password": "123456", "settings": exported["settings"]})
	rec = e.do(t, "POST", "/api/settings/database", string(payload), cookie, false)
	if rec.Code != 200 || decode(t, rec)["success"] != true {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPricingValidation(t *testing.T) {
	e := newTestEnv(t)
	cookie := loginCookie(t, e, "123456")
	rec := e.do(t, "PATCH", "/api/pricing", `{"openai":{"gpt-4o":{"input":1.5,"output":2}}}`, cookie, false)
	if rec.Code != 200 {
		t.Fatalf("patch pricing: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "PATCH", "/api/pricing", `{"openai":{"gpt-4o":{"bogus":1}}}`, cookie, false)
	if rec.Code != 400 {
		t.Fatalf("invalid field: %d", rec.Code)
	}
	rec = e.do(t, "PATCH", "/api/pricing", `{"openai":{"gpt-4o":{"input":-1}}}`, cookie, false)
	if rec.Code != 400 {
		t.Fatalf("negative value: %d", rec.Code)
	}
	rec = e.do(t, "GET", "/api/pricing", "", cookie, false)
	if rec.Code != 200 {
		t.Fatalf("get pricing: %d", rec.Code)
	}
	rec = e.do(t, "DELETE", "/api/pricing?provider=openai&model=gpt-4o", "", cookie, false)
	if rec.Code != 200 {
		t.Fatalf("delete pricing: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPublicMiscRoutes(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, "GET", "/api/health", "", "", false)
	if rec.Code != 200 || decode(t, rec)["ok"] != true {
		t.Fatalf("health: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("health CORS header missing")
	}
	rec = e.do(t, "GET", "/api/init", "", "", false)
	if rec.Code != 200 || rec.Body.String() != "Initialized" {
		t.Fatalf("init: %d %q", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/api/locale", `{"locale":"vi"}`, "", false)
	if rec.Code != 200 || decode(t, rec)["locale"] != "vi" {
		t.Fatalf("locale: %d %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, "locale=vi") {
			found = true
		}
	}
	if !found {
		t.Fatal("locale cookie not set")
	}
	rec = e.do(t, "POST", "/api/locale", `{"locale":"xx"}`, "", false)
	if rec.Code != 400 {
		t.Fatalf("bad locale: %d", rec.Code)
	}
	// require-login is public and reports defaults.
	rec = e.do(t, "GET", "/api/settings/require-login", "", "", false)
	out := decode(t, rec)
	if rec.Code != 200 || out["requireLogin"] != true {
		t.Fatalf("require-login: %d %v", rec.Code, out)
	}
	// Version is public; latestVersion depends on the network, so only
	// the stable fields are asserted.
	rec = e.do(t, "GET", "/api/version", "", "", false)
	out = decode(t, rec)
	if rec.Code != 200 || out["currentVersion"] != "0.5.104" {
		t.Fatalf("version: %d %v", rec.Code, out)
	}
	// Always-protected lifecycle route refuses without a session.
	rec = e.do(t, "POST", "/api/version/update", "", "", false)
	if rec.Code != 401 {
		t.Fatalf("version/update unauth: %d", rec.Code)
	}
	// With a session but not production → 403 with the JS message.
	cookie := loginCookie(t, e, "123456")
	rec = e.do(t, "POST", "/api/version/update", "", cookie, false)
	if rec.Code != 403 {
		t.Fatalf("version/update non-prod: %d %s", rec.Code, rec.Body.String())
	}
}
