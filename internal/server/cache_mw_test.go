package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"proxygo/internal/respcache"
	"proxygo/internal/server"
)

// enableRespCache points the package-level cache config at an enabled
// getter and resets the cache; cleanup restores the disabled default.
func enableRespCache(t *testing.T) {
	t.Helper()
	respcache.Configure(func() (bool, int, int) { return true, 300, 100 })
	respcache.Clear()
	t.Cleanup(func() {
		respcache.Configure(nil)
		respcache.Clear()
	})
}

func cachePost(t *testing.T, h http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func jsonHandler(calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Origin", "upstream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[]}`))
	})
}

func TestCacheMiddlewareMissStoreHit(t *testing.T) {
	enableRespCache(t)
	base := respcache.StatsSnapshot()
	var calls atomic.Int32
	h := server.CacheMiddleware(jsonHandler(&calls))

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	r1 := cachePost(t, h, "/v1/chat/completions", body, nil)
	if r1.Code != 200 || calls.Load() != 1 {
		t.Fatalf("first request: code=%d calls=%d", r1.Code, calls.Load())
	}
	if got := r1.Header().Get("x-proxygo-cache"); got != "" {
		t.Fatalf("miss response carried x-proxygo-cache: %q", got)
	}

	// Same request, different JSON key order → same entry, byte replay.
	reordered := `{"messages":[{"content":"hi","role":"user"}],"model":"gpt-4o"}`
	r2 := cachePost(t, h, "/v1/chat/completions", reordered, nil)
	if calls.Load() != 1 {
		t.Fatalf("second request reached upstream (calls=%d), want cache hit", calls.Load())
	}
	if got := r2.Header().Get("x-proxygo-cache"); got != "hit" {
		t.Fatalf("x-proxygo-cache = %q, want hit", got)
	}
	if r2.Code != 200 || r2.Body.String() != r1.Body.String() {
		t.Fatalf("replay mismatch: %d %q vs %d %q", r2.Code, r2.Body.String(), r1.Code, r1.Body.String())
	}
	if got := r2.Header().Get("X-Origin"); got != "upstream" {
		t.Fatalf("stored headers not replayed, X-Origin = %q", got)
	}

	// Counters are process-global and cumulative: assert deltas.
	s := respcache.StatsSnapshot()
	if s.Hits-base.Hits != 1 || s.Misses-base.Misses != 1 || s.Stores-base.Stores != 1 || s.Entries != 1 {
		t.Fatalf("stats delta = %+v (base %+v), want 1 hit / 1 miss / 1 store / 1 entry", s, base)
	}
}

func TestCacheMiddlewareSSEByteReplay(t *testing.T) {
	enableRespCache(t)
	var calls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	h := server.CacheMiddleware(next)

	body := `{"model":"m","stream":true,"messages":[]}`
	r1 := cachePost(t, h, "/v1/chat/completions", body, nil)
	// A non-stream twin of the same request maps to the same entry.
	r2 := cachePost(t, h, "/v1/chat/completions", `{"model":"m","messages":[]}`, nil)
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (SSE response cached + replayed)", calls.Load())
	}
	if r2.Header().Get("x-proxygo-cache") != "hit" {
		t.Fatal("second request was not a cache hit")
	}
	if r2.Body.String() != r1.Body.String() {
		t.Fatalf("SSE replay differs:\n%q\nvs\n%q", r2.Body.String(), r1.Body.String())
	}
	if ct := r2.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("replayed Content-Type = %q", ct)
	}
}

func TestCacheMiddlewareNoCacheHeaderBypasses(t *testing.T) {
	enableRespCache(t)
	var calls atomic.Int32
	h := server.CacheMiddleware(jsonHandler(&calls))
	body := `{"model":"m","messages":[]}`

	cachePost(t, h, "/v1/chat/completions", body, nil) // store
	r := cachePost(t, h, "/v1/chat/completions", body, map[string]string{"x-proxygo-no-cache": "1"})
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (no-cache header must reach upstream)", calls.Load())
	}
	if got := r.Header().Get("x-proxygo-cache"); got != "" {
		t.Fatalf("bypassed response marked as cache hit: %q", got)
	}
	// The bypassed response must not overwrite/poison the entry either:
	// a normal request still hits the original entry exactly once more.
	cachePost(t, h, "/v1/chat/completions", body, nil)
	if calls.Load() != 2 {
		t.Fatalf("calls = %d after normal request, want still 2", calls.Load())
	}
}

func TestCacheMiddlewareErrorStatusNotCached(t *testing.T) {
	enableRespCache(t)
	var calls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
	})
	h := server.CacheMiddleware(next)
	base := respcache.StatsSnapshot()
	body := `{"model":"m","messages":[]}`
	cachePost(t, h, "/v1/responses", body, nil)
	cachePost(t, h, "/v1/responses", body, nil)
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (500 responses must not be cached)", calls.Load())
	}
	if s := respcache.StatsSnapshot(); s.Stores != base.Stores || s.Entries != 0 {
		t.Fatalf("error response stored: %+v (base %+v)", s, base)
	}
}

func TestCacheMiddlewareDisabledPassthrough(t *testing.T) {
	// No Configure at all: default is disabled (opt-in feature).
	respcache.Clear()
	base := respcache.StatsSnapshot()
	var calls atomic.Int32
	h := server.CacheMiddleware(jsonHandler(&calls))
	body := `{"model":"m","messages":[]}`
	r1 := cachePost(t, h, "/v1/chat/completions", body, nil)
	r2 := cachePost(t, h, "/v1/chat/completions", body, nil)
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 while disabled", calls.Load())
	}
	if r1.Header().Get("x-proxygo-cache") != "" || r2.Header().Get("x-proxygo-cache") != "" {
		t.Fatal("disabled cache marked a response")
	}
	if s := respcache.StatsSnapshot(); s.Stores != base.Stores {
		t.Fatalf("disabled cache stored entries: %+v (base %+v)", s, base)
	}
}

func TestCacheMiddlewareAPIKeyIsolation(t *testing.T) {
	enableRespCache(t)
	var calls atomic.Int32
	h := server.CacheMiddleware(jsonHandler(&calls))
	body := `{"model":"m","messages":[]}`
	k1 := map[string]string{"Authorization": "Bearer sk-one"}
	k2 := map[string]string{"Authorization": "Bearer sk-two"}

	cachePost(t, h, "/v1/messages", body, k1)
	cachePost(t, h, "/v1/messages", body, k1) // hit
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 after same-key repeat", calls.Load())
	}
	r := cachePost(t, h, "/v1/messages", body, k2) // different key → miss
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 for a different API key", calls.Load())
	}
	if got := r.Header().Get("x-proxygo-cache"); got != "" {
		t.Fatalf("other key's entry leaked: x-proxygo-cache = %q", got)
	}
}

func TestCacheMiddlewareNonCacheableRequests(t *testing.T) {
	enableRespCache(t)
	var calls atomic.Int32
	h := server.CacheMiddleware(jsonHandler(&calls))
	body := `{"model":"m","messages":[]}`
	// Unsupported path passes through every time.
	cachePost(t, h, "/v1/embeddings", body, nil)
	cachePost(t, h, "/v1/embeddings", body, nil)
	// Non-POST on a chat path passes through.
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Invalid JSON body is not cacheable.
	cachePost(t, h, "/v1/chat/completions", "not json", nil)
	cachePost(t, h, "/v1/chat/completions", "not json", nil)
	if calls.Load() != 5 {
		t.Fatalf("calls = %d, want 5 (nothing cacheable)", calls.Load())
	}
	if s := respcache.StatsSnapshot(); s.Entries != 0 {
		t.Fatalf("non-cacheable requests stored entries: %+v", s)
	}
}
