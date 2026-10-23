package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"9router-go/internal/chatcore"
	"9router-go/internal/db"
)

// fakeChatBreaker implements chatcore.CircuitBreaker + Snapshot() any.
type fakeChatBreaker struct{}

func (fakeChatBreaker) Allow(provider, connID string) bool             { return true }
func (fakeChatBreaker) OnResult(provider, connID string, success bool) {}
func (fakeChatBreaker) Snapshot() any {
	return []map[string]any{{"provider": "openai", "connectionId": "c1", "state": "open", "consecutiveFailures": 5}}
}

func newBreakerTestEnv(t *testing.T, chat *chatcore.Service) (*http.ServeMux, *db.Store) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.UpdateSettings(db.Record{"requireLogin": false}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	mux := http.NewServeMux()
	RegisterBreakerAPI(mux, Deps{Store: store, Chat: chat})
	return mux, store
}

func getBreakerStats(t *testing.T, mux *http.ServeMux) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/breaker/stats", strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:4321"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, opDecode(t, rec)
}

func TestBreakerStatsNoChatService(t *testing.T) {
	mux, _ := newBreakerTestEnv(t, nil)
	code, body := getBreakerStats(t, mux)
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	if body["enabled"] != false {
		t.Fatalf("enabled = %v, want false with no chat service", body["enabled"])
	}
	if circuits, ok := body["circuits"].([]any); !ok || len(circuits) != 0 {
		t.Fatalf("circuits = %v, want empty list", body["circuits"])
	}
}

func TestBreakerStatsBreakerNotWired(t *testing.T) {
	mux, _ := newBreakerTestEnv(t, chatcore.NewService(chatcore.Service{}))
	code, body := getBreakerStats(t, mux)
	if code != 200 || body["enabled"] != false {
		t.Fatalf("code=%d body=%v, want 200 + enabled:false", code, body)
	}
}

func TestBreakerStatsWithBreaker(t *testing.T) {
	svc := chatcore.NewService(chatcore.Service{})
	svc.Breaker = fakeChatBreaker{}
	mux, _ := newBreakerTestEnv(t, svc)
	code, body := getBreakerStats(t, mux)
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	if body["enabled"] != true {
		t.Fatalf("enabled = %v, want true", body["enabled"])
	}
	circuits, ok := body["circuits"].([]any)
	if !ok || len(circuits) != 1 {
		t.Fatalf("circuits = %v", body["circuits"])
	}
	first, _ := circuits[0].(map[string]any)
	if first["provider"] != "openai" || first["state"] != "open" {
		t.Fatalf("circuit[0] = %v", first)
	}
}
