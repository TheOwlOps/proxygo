package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxygo/internal/db"
	"proxygo/internal/respcache"
)

type cacheTestEnv struct {
	mux   *http.ServeMux
	store *db.Store
}

func newCacheTestEnv(t *testing.T, settings db.Record) *cacheTestEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if settings != nil {
		if _, err := store.UpdateSettings(settings); err != nil {
			t.Fatalf("settings: %v", err)
		}
	}
	mux := http.NewServeMux()
	RegisterCacheAPI(mux, Deps{Store: store})
	respcache.Clear()
	t.Cleanup(respcache.Clear)
	return &cacheTestEnv{mux: mux, store: store}
}

func (e *cacheTestEnv) do(t *testing.T, method, path string, cookie bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:4321"
	if cookie {
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: CreateSessionToken(e.store)})
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func TestCacheAPIStatsAndClear(t *testing.T) {
	env := newCacheTestEnv(t, db.Record{"requireLogin": false})
	respcache.Configure(func() (bool, int, int) { return true, 120, 42 })
	defer respcache.Configure(nil)
	base := respcache.StatsSnapshot()
	respcache.Put("k", respcache.Entry{Status: 200, Body: []byte("v")})

	rec := env.do(t, "GET", "/api/cache/stats", false)
	if rec.Code != 200 {
		t.Fatalf("stats status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if out["enabled"] != true || out["ttlSeconds"] != float64(120) || out["maxEntries"] != float64(42) {
		t.Fatalf("stats config = %v", out)
	}
	if out["entries"] != float64(1) || out["stores"] != float64(base.Stores+1) {
		t.Fatalf("stats counters = %v (base stores %d)", out, base.Stores)
	}
	if _, ok := out["hitRate"]; !ok {
		t.Fatalf("stats missing hitRate: %v", out)
	}

	rec = env.do(t, "POST", "/api/cache/clear", false)
	if rec.Code != 200 {
		t.Fatalf("clear status = %d, body %s", rec.Code, rec.Body.String())
	}
	var cleared map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &cleared); err != nil {
		t.Fatalf("decode clear: %v", err)
	}
	if cleared["cleared"] != true || cleared["entries"] != float64(0) {
		t.Fatalf("clear response = %v", cleared)
	}
	if s := respcache.StatsSnapshot(); s.Entries != 0 {
		t.Fatalf("cache not emptied, entries = %d", s.Entries)
	}
}

func TestCacheAPIGuardRequiresSession(t *testing.T) {
	// Default settings: requireLogin is on → no cookie = 401.
	env := newCacheTestEnv(t, nil)
	if rec := env.do(t, "GET", "/api/cache/stats", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stats status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := env.do(t, "POST", "/api/cache/clear", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated clear status = %d, want 401", rec.Code)
	}
	// A valid dashboard session passes.
	if rec := env.do(t, "GET", "/api/cache/stats", true); rec.Code != 200 {
		t.Fatalf("authenticated stats status = %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(t, "POST", "/api/cache/clear", true); rec.Code != 200 {
		t.Fatalf("authenticated clear status = %d", rec.Code)
	}
}
