package executors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// zedFixture is a fake cloud.zed.dev: user lookup, LLM-token exchange,
// model catalog and completions on one httptest host.
type zedFixture struct {
	mu              sync.Mutex
	tokenSeq        int
	usersMeCalls    int
	llmTokenCalls   int
	llmTokenBodies  []string
	llmTokenAuth    []string
	modelsCalls     int
	completionCalls int
	completionAuth  []string
	completionHeads []http.Header
	completionBody  []byte
	completionsFn   func(call int, w http.ResponseWriter, r *http.Request)
	srv             *httptest.Server
}

func newZedFixture(t *testing.T) *zedFixture {
	t.Helper()
	zedClearCaches()
	f := &zedFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/client/users/me", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.usersMeCalls++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"u1","default_organization_id":"org-42","organizations":[{"id":"org-42","is_personal":true}]}`)
	})
	mux.HandleFunc("/client/llm_tokens", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.llmTokenCalls++
		f.tokenSeq++
		seq := f.tokenSeq
		f.llmTokenBodies = append(f.llmTokenBodies, string(raw))
		f.llmTokenAuth = append(f.llmTokenAuth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"llm-token-`+int64Str(int64(seq))+`"}`)
	})
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.modelsCalls++
		f.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer llm-token-") {
			t.Errorf("models Authorization = %q, want LLM bearer token", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-zed-client-supports-x-ai") != "true" {
			t.Errorf("models missing x-zed-client-supports-x-ai header")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"models":[
			{"id":"grok-4","provider":"x_ai"},
			{"id":"claude-sonnet-4-5","provider":"anthropic"},
			{"id":"gpt-5","provider":"open_ai"},
			{"id":"gemini-2.5-pro","provider":"google"}
		]}`)
	})
	mux.HandleFunc("/completions", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.completionCalls++
		call := f.completionCalls
		f.completionAuth = append(f.completionAuth, r.Header.Get("Authorization"))
		f.completionHeads = append(f.completionHeads, r.Header.Clone())
		f.completionBody = raw
		fn := f.completionsFn
		f.mu.Unlock()
		if fn != nil {
			fn(call, w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, "{\"event\":{\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}}\n[DONE]\n")
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *zedFixture) providerInfo() *ProviderInfo {
	return &ProviderInfo{ID: "zed", BaseURL: f.srv.URL + "/completions", Format: "openai"}
}

func zedTestCred() Credential {
	return Credential{
		AccessToken: "secret-token",
		Specific:    map[string]any{"userId": "42", "organizationId": "org-42"},
	}
}

func TestZedExecutorXAIStreamEndToEnd(t *testing.T) {
	f := newZedFixture(t)
	f.completionsFn = func(call int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, "{\"status\":\"started\"}\n")
		io.WriteString(w, "{\"event\":{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"finish_reason\":null}]}}\n")
		io.WriteString(w, "{\"event\":{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}}\n")
		io.WriteString(w, "{\"event\":{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}}\n")
		io.WriteString(w, "[DONE]\n")
	}
	ex := NewZedExecutor()
	res, err := ex.Execute(context.Background(), f.providerInfo(), zedTestCred(),
		[]byte(`{"model":"grok-4","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "Hello") || !strings.Contains(body, " world") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("wrapped SSE = %q", body)
	}
	if res.ResponseFormat != "openai" {
		t.Fatalf("ResponseFormat = %q, want openai", res.ResponseFormat)
	}
	if res.URL != f.srv.URL+"/completions" {
		t.Fatalf("URL = %q", res.URL)
	}
	// LLM-token exchange used the user auth header + explicit org, so no
	// /client/users/me lookup was needed.
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.usersMeCalls != 0 {
		t.Fatalf("users/me calls = %d, want 0 (org pinned on connection)", f.usersMeCalls)
	}
	if f.llmTokenCalls != 1 {
		t.Fatalf("llm_tokens calls = %d, want 1 (models + completions share the cached token)", f.llmTokenCalls)
	}
	if len(f.llmTokenAuth) == 0 || f.llmTokenAuth[0] != "42 secret-token" {
		t.Fatalf("llm_tokens Authorization = %v, want '<userId> <accessToken>'", f.llmTokenAuth)
	}
	if !strings.Contains(f.llmTokenBodies[0], `"organization_id":"org-42"`) {
		t.Fatalf("llm_tokens body = %s", f.llmTokenBodies[0])
	}
	if len(f.completionAuth) == 0 || f.completionAuth[0] != "Bearer llm-token-1" {
		t.Fatalf("completions Authorization = %v, want LLM bearer", f.completionAuth)
	}
	head := f.completionHeads[0]
	if head.Get("x-zed-client-supports-status-messages") != "true" ||
		head.Get("x-zed-client-supports-stream-ended-request-completion-status") != "true" ||
		head.Get("User-Agent") != "9router/zed" {
		t.Fatalf("completions headers missing zed markers: %v", head)
	}
	// Payload envelope: provider wire spelling + OpenAI passthrough body.
	var payload map[string]any
	if err := unmarshalJSON(f.completionBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["provider"] != "x_ai" || payload["model"] != "grok-4" {
		t.Fatalf("payload provider/model = %v/%v", payload["provider"], payload["model"])
	}
	pr, _ := payload["provider_request"].(map[string]any)
	if pr == nil || pr["stream"] != true {
		t.Fatalf("provider_request = %v", payload["provider_request"])
	}
	if msgs, _ := pr["messages"].([]any); len(msgs) != 1 {
		t.Fatalf("provider_request.messages = %v", pr["messages"])
	}
	var transformed map[string]any
	if err := unmarshalJSON(res.TransformedBody, &transformed); err != nil {
		t.Fatal(err)
	}
	if transformed["provider"] != "x_ai" {
		t.Fatalf("TransformedBody provider = %v", transformed["provider"])
	}
}

func TestZedExecutorOrgResolvedViaUserLookup(t *testing.T) {
	f := newZedFixture(t)
	cred := Credential{AccessToken: "secret-token", Specific: map[string]any{"userId": "42"}}
	ex := NewZedExecutor()
	res, err := ex.Execute(context.Background(), f.providerInfo(), cred,
		[]byte(`{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	f.mu.Lock()
	defer f.mu.Unlock()
	// JS fetchZedLlmToken resolves the org BEFORE the token-cache check,
	// so an unpinned connection re-fetches the user record on every
	// zedLlmFetch (models + completions = 2).
	if f.usersMeCalls != 2 {
		t.Fatalf("users/me calls = %d, want 2 (org resolution precedes cache check)", f.usersMeCalls)
	}
	if !strings.Contains(f.llmTokenBodies[0], `"organization_id":"org-42"`) {
		t.Fatalf("llm_tokens body = %s, want org from user record", f.llmTokenBodies[0])
	}
}

func TestZedExecutorClaudeStreamTranslated(t *testing.T) {
	f := newZedFixture(t)
	f.completionsFn = func(call int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, "{\"event\":{\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}}\n")
		io.WriteString(w, "{\"event\":{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}}\n")
		io.WriteString(w, "{\"event\":{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello from Claude\"}}}\n")
		io.WriteString(w, "{\"event\":{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}}\n")
		io.WriteString(w, "{\"event\":{\"type\":\"message_stop\"}}\n")
	}
	ex := NewZedExecutor()
	res, err := ex.Execute(context.Background(), f.providerInfo(), zedTestCred(),
		[]byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "Hello from Claude") {
		t.Fatalf("claude events not translated to OpenAI chunks: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("translated stream missing finish/[DONE]: %q", body)
	}
	var payload map[string]any
	if err := unmarshalJSON(f.completionBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["provider"] != "anthropic" {
		t.Fatalf("payload provider = %v, want anthropic", payload["provider"])
	}
	pr, _ := payload["provider_request"].(map[string]any)
	if pr == nil {
		t.Fatalf("provider_request missing: %v", payload)
	}
	// Claude-shaped request: max_tokens pinned by the translator, and the
	// OpenAI "messages" content converted to Claude blocks.
	if pr["max_tokens"] == nil {
		t.Fatalf("claude provider_request missing max_tokens: %v", pr)
	}
}

func TestZedExecutorFailedStatusBecomesErrorChunk(t *testing.T) {
	f := newZedFixture(t)
	f.completionsFn = func(call int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, "{\"status\":{\"failed\":{\"message\":\"boom failure\"}}}\n")
	}
	ex := NewZedExecutor()
	res, err := ex.Execute(context.Background(), f.providerInfo(), zedTestCred(),
		[]byte(`{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "[Zed error] boom failure") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("failed status stream = %q", body)
	}
}

func TestZedExecutorLLMTokenRefreshOn401(t *testing.T) {
	f := newZedFixture(t)
	f.completionsFn = func(call int, w http.ResponseWriter, r *http.Request) {
		if call == 1 {
			w.Header().Set("x-zed-expired-token", "true")
			w.WriteHeader(401)
			io.WriteString(w, `{"message":"expired"}`)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, "{\"event\":{\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"after refresh\"}}]}}\n[DONE]\n")
	}
	ex := NewZedExecutor()
	res, err := ex.Execute(context.Background(), f.providerInfo(), zedTestCred(),
		[]byte(`{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "after refresh") {
		t.Fatalf("refreshed stream = %q", body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.completionCalls != 2 {
		t.Fatalf("completions calls = %d, want 2 (initial 401 + retry)", f.completionCalls)
	}
	if f.llmTokenCalls != 2 {
		t.Fatalf("llm_tokens calls = %d, want 2 (initial + forced refresh)", f.llmTokenCalls)
	}
	if f.completionAuth[1] != "Bearer llm-token-2" {
		t.Fatalf("retry Authorization = %q, want fresh token", f.completionAuth[1])
	}
}

func TestZedNormalizeProvider(t *testing.T) {
	cases := []struct {
		value, model, want string
	}{
		{"anthropic", "anything", "anthropic"},
		{"openai", "anything", "open_ai"},
		{"open_ai", "anything", "open_ai"},
		{"gemini", "anything", "google"},
		{"x-ai", "anything", "x_ai"},
		{"", "claude-sonnet-4-5", "anthropic"},
		{"", "gemini-2.5-pro", "google"},
		{"", "grok-4", "x_ai"},
		{"", "gpt-5", "open_ai"},
		{"unknown", "gpt-5", "open_ai"},
	}
	for _, tc := range cases {
		if got := zedNormalizeProvider(tc.value, tc.model); got != tc.want {
			t.Errorf("zedNormalizeProvider(%q, %q) = %q, want %q", tc.value, tc.model, got, tc.want)
		}
	}
}

func TestZedBuildProviderRequestGoogleStripsSafetySettings(t *testing.T) {
	out, err := zedBuildProviderRequest(zedProviderGoogle, "gemini-2.5-pro",
		map[string]any{"model": "gemini-2.5-pro", "messages": []any{map[string]any{"role": "user", "content": "hi"}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := out["safetySettings"]; present {
		t.Fatalf("gemini provider_request must drop safetySettings for Zed: %v", out)
	}
	if _, present := out["contents"]; !present {
		t.Fatalf("gemini provider_request missing contents: %v", out)
	}
}

func TestZedParseError(t *testing.T) {
	ex := NewZedExecutor()
	pe := ex.ParseError(403, `{"code":"trial_blocked","message":"no trial"}`)
	if pe.Status != 403 || !strings.Contains(pe.Message, "Zed trial access is blocked upstream") || !strings.Contains(pe.Message, "no trial") {
		t.Fatalf("trial_blocked parse = %+v", pe)
	}
	pe = ex.ParseError(500, `{"code":"overloaded","message":"try later"}`)
	if pe.Message != "Zed overloaded: try later" {
		t.Fatalf("coded parse = %+v", pe)
	}
	pe = ex.ParseError(502, `raw failure text`)
	if pe.Message != "raw failure text" {
		t.Fatalf("plain parse = %+v", pe)
	}
	// No refresh path: JS refreshCredentials returns null.
	cred, err := ex.RefreshCredentials(context.Background(), &ProviderInfo{ID: "zed"}, zedTestCred())
	if err != nil || cred != nil {
		t.Fatalf("zed refresh = %v, %v; want nil, nil", cred, err)
	}
}
