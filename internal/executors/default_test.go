package executors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	// Keep retry delays instant in tests.
	SleepFunc = func(ctx context.Context, d time.Duration) error { return nil }
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestDefaultExecutorPassthroughSSE(t *testing.T) {
	var gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	ex := NewDefaultExecutor("openai")
	p := &ProviderInfo{ID: "openai", BaseURL: srv.URL + "/v1/chat/completions", Format: "openai"}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "sk-test"},
		[]byte(`{"model":"gpt-x","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "[DONE]") || !strings.Contains(body, "\"hi\"") {
		t.Fatalf("SSE passthrough body = %q", body)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q", gotCT)
	}
	if res.URL != srv.URL+"/v1/chat/completions" {
		t.Fatalf("url = %q", res.URL)
	}
}

func TestDefaultExecutorURLBuilding(t *testing.T) {
	d := NewDefaultExecutor("x")
	cases := []struct {
		name string
		id   string
		p    *ProviderInfo
		cred Credential
		want string
	}{
		{
			name: "openai-compatible chat",
			id:   "openai-compatible-chat-abc",
			p:    &ProviderInfo{ID: "openai-compatible-chat-abc"},
			cred: Credential{BaseURL: "https://node.example.com/v1/"},
			want: "https://node.example.com/v1/chat/completions",
		},
		{
			name: "openai-compatible responses via apiType",
			id:   "openai-compatible-responses-abc",
			p:    &ProviderInfo{ID: "openai-compatible-responses-abc"},
			cred: Credential{BaseURL: "https://node.example.com/v1", Specific: map[string]any{"apiType": "responses"}},
			want: "https://node.example.com/v1/responses",
		},
		{
			name: "anthropic-compatible messages",
			id:   "anthropic-compatible-abc",
			p:    &ProviderInfo{ID: "anthropic-compatible-abc"},
			cred: Credential{BaseURL: "https://gw.example.com/v1"},
			want: "https://gw.example.com/v1/messages",
		},
		{
			name: "gemini format streaming",
			id:   "gemini",
			p:    &ProviderInfo{ID: "gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta/models", Format: "gemini"},
			cred: Credential{},
			want: "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse",
		},
		{
			name: "url suffix",
			id:   "claude",
			p:    &ProviderInfo{ID: "claude", BaseURL: "https://api.anthropic.com/v1/messages", URLSuffix: "?beta=true", Format: "claude"},
			cred: Credential{},
			want: "https://api.anthropic.com/v1/messages?beta=true",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := NewDefaultExecutor(tc.id)
			req := &Request{Provider: tc.p, Cred: tc.cred, Model: "gemini-2.0-flash", Stream: true, State: map[string]any{}}
			got, err := ex.buildURL(ex.Base, req, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("buildURL = %q, want %q", got, tc.want)
			}
			_ = d
		})
	}
}

func TestDefaultExecutorSplitAuthHeaders(t *testing.T) {
	ex := NewDefaultExecutor("anthropic-compatible-x")
	p := &ProviderInfo{ID: "anthropic-compatible-x", BaseURL: "https://gw.example.com/v1"}
	req := &Request{Provider: p, Cred: Credential{APIKey: "key-1"}, Model: "claude-sonnet-4.5", State: map[string]any{}}
	headers, err := ex.buildHeaders(ex.Base, req, "")
	if err != nil {
		t.Fatal(err)
	}
	if headers["x-api-key"] != "key-1" {
		t.Fatalf("x-api-key = %q", headers["x-api-key"])
	}
	if headers["anthropic-version"] != "2023-06-01" {
		t.Fatalf("anthropic-version = %q", headers["anthropic-version"])
	}
	if headers["Authorization"] != "" {
		t.Fatalf("split auth must not set Authorization for apiKey cred, got %q", headers["Authorization"])
	}
}

func TestApplyAuthCombinedLegacy(t *testing.T) {
	headers := map[string]string{}
	applyAuth(headers, &AuthSpec{Combined: true, Header: "Authorization", Scheme: "bearer"}, Credential{})
	// Legacy JS behaviour: the header is always set, rendering the missing
	// token as the literal string "undefined".
	if headers["Authorization"] != "Bearer undefined" {
		t.Fatalf("combined legacy auth = %q", headers["Authorization"])
	}
}

func TestDefaultExecutorRetryByStatus(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&calls, 1)
		if n < 3 {
			w.WriteHeader(502)
			io.WriteString(w, "bad gateway")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"ok"}`)
	}))
	defer srv.Close()

	ex := NewDefaultExecutor("openai")
	p := &ProviderInfo{ID: "openai", BaseURL: srv.URL, Retry: map[int]RetryEntry{502: {Attempts: 3, DelayMs: 1}}}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "k"}, []byte(`{"model":"m","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if calls != 3 {
		t.Fatalf("upstream calls = %d, want 3 (2 retries)", calls)
	}
}

func TestDefaultExecutor429FallsToNextBaseURL(t *testing.T) {
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		io.WriteString(w, "rate limited")
	}))
	defer srvBad.Close()
	srvGood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"second"}`)
	}))
	defer srvGood.Close()

	ex := &Base{ProviderID: "multi"}
	p := &ProviderInfo{ID: "multi", BaseURLs: []string{srvBad.URL, srvGood.URL}}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "t"}, []byte(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "second") || res.URL != srvGood.URL {
		t.Fatalf("fallback result url=%q body=%q", res.URL, body)
	}
}

func TestJSONSchemaFallback(t *testing.T) {
	ex := NewDefaultExecutor("openai-compatible-chat-1")
	body := map[string]any{
		"model":    "m",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"response_format": map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"schema": map[string]any{"type": "object"}},
		},
	}
	req := &Request{Provider: &ProviderInfo{ID: "openai-compatible-chat-1"}, Cred: Credential{}, Model: "m", Body: body, State: map[string]any{}}
	out, err := ex.transformBody(ex.Base, req)
	if err != nil {
		t.Fatal(err)
	}
	rf := out["response_format"].(map[string]any)
	if rf["type"] != "json_object" {
		t.Fatalf("response_format = %v", rf)
	}
	msgs := out["messages"].([]any)
	if msgs[0].(map[string]any)["role"] != "system" {
		t.Fatalf("schema prompt system message not injected: %v", msgs[0])
	}
}
