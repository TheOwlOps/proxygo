package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxygo/internal/db"
	"proxygo/internal/keylimit"
)

type keyLimitsEnv struct {
	store *db.Store
	mux   *http.ServeMux
	token string
	keyID string
}

func newKeyLimitsEnv(t *testing.T) *keyLimitsEnv {
	t.Helper()
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rec, err := store.CreateAPIKeyWithKey("limits-test", "machine-1", "sk-limits-api-test")
	if err != nil {
		t.Fatalf("CreateAPIKeyWithKey: %v", err)
	}
	mux := http.NewServeMux()
	RegisterKeyLimitsAPI(mux, Deps{Store: store})
	return &keyLimitsEnv{
		store: store,
		mux:   mux,
		token: CreateSessionToken(store),
		keyID: Str(rec, "id"),
	}
}

func (e *keyLimitsEnv) do(t *testing.T, method, path, body string, auth bool) (int, map[string]any) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: e.token})
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: bad JSON %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

func limitsOf(t *testing.T, body map[string]any) keylimit.Limits {
	t.Helper()
	raw, err := json.Marshal(body["limits"])
	if err != nil {
		t.Fatal(err)
	}
	var lim keylimit.Limits
	if err := json.Unmarshal(raw, &lim); err != nil {
		t.Fatalf("limits shape: %v (%s)", err, raw)
	}
	return lim
}

func TestKeyLimitsAPIRoundTrip(t *testing.T) {
	e := newKeyLimitsEnv(t)
	base := "/api/keys/" + e.keyID + "/limits"

	// Unauthenticated requests are refused by the dashboard guard.
	if code, _ := e.do(t, "GET", base, "", false); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d, want 401", code)
	}

	// No limits stored → all-zero document.
	code, body := e.do(t, "GET", base, "", true)
	if code != 200 || limitsOf(t, body) != (keylimit.Limits{}) {
		t.Fatalf("initial GET = %d %+v", code, body)
	}

	// PUT a full document (flat shape).
	code, body = e.do(t, "PUT", base,
		`{"rpm":10,"dailyTokens":1000,"monthlyTokens":50000,"dailyCostUSD":2.5,"monthlyCostUSD":40}`, true)
	want := keylimit.Limits{RPM: 10, DailyTokens: 1000, MonthlyTokens: 50000, DailyCostUSD: 2.5, MonthlyCostUSD: 40}
	if code != 200 || limitsOf(t, body) != want {
		t.Fatalf("PUT = %d %+v, want limits %+v", code, body, want)
	}

	// GET reflects it, and so does the package-level reader.
	code, body = e.do(t, "GET", base, "", true)
	if code != 200 || limitsOf(t, body) != want {
		t.Fatalf("GET after PUT = %d %+v", code, body)
	}
	stored, err := keylimit.GetLimits(e.store, e.keyID)
	if err != nil || stored != want {
		t.Fatalf("stored limits = %+v, %v", stored, err)
	}

	// PUT also accepts the wrapped {"limits": {...}} shape and replaces.
	code, body = e.do(t, "PUT", base, `{"limits":{"rpm":5}}`, true)
	if code != 200 || limitsOf(t, body) != (keylimit.Limits{RPM: 5}) {
		t.Fatalf("wrapped PUT = %d %+v", code, body)
	}

	// Invalid values are rejected.
	for _, bad := range []string{`{"rpm":-1}`, `{"dailyTokens":1.5}`, `{"dailyCostUSD":"x"}`} {
		if code, _ := e.do(t, "PUT", base, bad, true); code != http.StatusBadRequest {
			t.Fatalf("PUT %s = %d, want 400", bad, code)
		}
	}

	// DELETE clears back to unlimited.
	code, _ = e.do(t, "DELETE", base, "", true)
	if code != 200 {
		t.Fatalf("DELETE = %d", code)
	}
	code, body = e.do(t, "GET", base, "", true)
	if code != 200 || limitsOf(t, body) != (keylimit.Limits{}) {
		t.Fatalf("GET after DELETE = %d %+v", code, body)
	}
}

func TestKeyLimitsAPIUsageSummary(t *testing.T) {
	e := newKeyLimitsEnv(t)
	if err := keylimit.SetLimits(e.store, e.keyID, keylimit.Limits{DailyTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	dayStart := keylimit.StartOfDay(time.Now())
	_, err := e.store.SQL().Exec(
		`INSERT INTO usageHistory(timestamp, provider, model, connectionId, apiKey, endpoint, promptTokens, completionTokens, cost, status, tokens, meta)
		 VALUES(?, 'openai', 'gpt-x', 'c1', 'sk-limits-api-test', '/v1/chat/completions', 100, 50, 1.25, 'ok', '{}', '{}')`,
		dayStart.Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z"))
	if err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	code, body := e.do(t, "GET", "/api/keys/"+e.keyID+"/usage-summary", "", true)
	if code != 200 {
		t.Fatalf("usage-summary = %d %+v", code, body)
	}
	today, ok := body["today"].(map[string]any)
	if !ok {
		t.Fatalf("no today in %+v", body)
	}
	if today["totalTokens"] != float64(150) || today["costUSD"] != 1.25 || today["requests"] != float64(1) {
		t.Fatalf("today = %+v, want 150 tokens / $1.25 / 1 request", today)
	}
	month, ok := body["month"].(map[string]any)
	if !ok || month["totalTokens"] != float64(150) {
		t.Fatalf("month = %+v", body["month"])
	}
	if limitsOf(t, body).DailyTokens != 1000 {
		t.Fatalf("limits in summary = %+v", body["limits"])
	}
}

func TestKeyLimitsAPIUnknownKey(t *testing.T) {
	e := newKeyLimitsEnv(t)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/keys/nope/limits", ""},
		{"PUT", "/api/keys/nope/limits", `{"rpm":1}`},
		{"DELETE", "/api/keys/nope/limits", ""},
		{"GET", "/api/keys/nope/usage-summary", ""},
	} {
		if code, _ := e.do(t, tc.method, tc.path, tc.body, true); code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", tc.method, tc.path, code)
		}
	}
}
