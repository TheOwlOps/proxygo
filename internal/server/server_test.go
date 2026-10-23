package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxygo/internal/db"
	"proxygo/internal/server"
)

func setup(t *testing.T, upstreamURL string) http.Handler {
	t.Helper()
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.UpdateSettings(db.Record{"requireApiKey": false}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	for _, prov := range []string{"openai-compatible-test", "anthropic-compatible-test"} {
		_, err := store.CreateProviderConnection(db.Record{
			"provider": prov, "authType": "apikey", "name": "test-" + prov,
			"apiKey": "sk-test", "isActive": true,
			"providerSpecificData": map[string]any{"baseUrl": upstreamURL},
		})
		if err != nil {
			t.Fatalf("create connection %s: %v", prov, err)
		}
	}
	return server.New(store)
}

func mockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/messages") {
			// Claude-format request → Claude-format reply.
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet","content":[{"type":"text","text":"hi from claude"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi from openai"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
}

func post(t *testing.T, h http.Handler, path, payload string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestHealthAndModels(t *testing.T) {
	up := mockUpstream(t)
	defer up.Close()
	h := setup(t, up.URL)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("health status %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("models status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "openai/gpt-4o") {
		t.Fatalf("models missing openai/gpt-4o: %.200s", rec.Body.String())
	}
}

func TestChatOpenAI(t *testing.T) {
	up := mockUpstream(t)
	defer up.Close()
	h := setup(t, up.URL)
	code, out := post(t, h, "/v1/chat/completions",
		`{"model":"openai-compatible-test/gpt-4o","stream":false,"messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 {
		t.Fatalf("status %d body %v", code, out)
	}
	choices, _ := out["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("choices %v", out)
	}
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "hi from openai" {
		t.Fatalf("content %v", msg)
	}
}

func TestChatClaudeTranslatedBack(t *testing.T) {
	up := mockUpstream(t)
	defer up.Close()
	h := setup(t, up.URL)
	code, out := post(t, h, "/v1/chat/completions",
		`{"model":"anthropic-compatible-test/claude-sonnet-4-5","stream":false,"messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 {
		t.Fatalf("status %d body %v", code, out)
	}
	choices, _ := out["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("expected openai-shaped choices, got %v", out)
	}
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "hi from claude" {
		t.Fatalf("content %v", msg)
	}
}
