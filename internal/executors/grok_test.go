package executors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- grok-cli helpers ---

func grokDecodeSentBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("upstream body not JSON: %v (%s)", err, raw)
	}
	return m
}

// --- grok-cli ---

func TestGrokCLIExecutorEndToEnd(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n")
	}))
	defer srv.Close()

	oldClient := HTTPClient
	HTTPClient = srv.Client()
	defer func() { HTTPClient = oldClient }()

	ex := NewGrokCLIExecutor()
	p := &ProviderInfo{
		ID: "grok-cli", BaseURL: srv.URL, Format: "openai-responses",
		Headers: map[string]string{
			"User-Agent":               "grok-shell/1.0.44 (linux; x86_64)",
			"x-grok-client-identifier": "grok-shell",
			"x-grok-client-version":    "1.0.44",
		},
	}
	cred := Credential{
		AccessToken:  "oauth-token",
		ConnectionID: "conn-1",
		Specific:     map[string]any{"email": "a@b.c", "userId": "user-9"},
	}
	body := []byte(`{
		"model":"grok-4.5-high",
		"input":"hello",
		"prompt_cache_key":"sess-123",
		"reasoning_effort":"low",
		"max_tokens": 100,
		"seed": 42,
		"bogus_field": true
	}`)
	res, err := ex.Execute(context.Background(), p, cred, body)
	if err != nil {
		t.Fatal(err)
	}
	out := readBody(t, res.Response)
	if !strings.Contains(out, "response.output_text.delta") {
		t.Fatalf("Responses SSE must pass through untouched, got %q", out)
	}
	if res.ResponseFormat != "" {
		t.Fatalf("grok-cli must not claim a wrapped format, got %q", res.ResponseFormat)
	}

	sent := grokDecodeSentBody(t, gotBody)
	if sent["model"] != "grok-4.5" {
		t.Fatalf("effort virtual model not resolved: model=%v", sent["model"])
	}
	if sent["stream"] != true || sent["store"] != false {
		t.Fatalf("stream/store not forced: stream=%v store=%v", sent["stream"], sent["store"])
	}
	if _, has := sent["max_tokens"]; has {
		t.Fatal("max_tokens must be dropped")
	}
	if _, has := sent["seed"]; has {
		t.Fatal("seed must be dropped")
	}
	if _, has := sent["bogus_field"]; has {
		t.Fatal("non-allowlisted field must be dropped")
	}
	if _, has := sent["reasoning_effort"]; has {
		t.Fatal("reasoning_effort must be consumed and dropped")
	}
	reasoning, _ := sent["reasoning"].(map[string]any)
	if reasoning == nil || reasoning["effort"] != "low" || reasoning["summary"] != "concise" {
		t.Fatalf("reasoning = %v, want effort=low summary=concise", reasoning)
	}
	include, _ := sent["include"].([]any)
	foundEncrypted := false
	for _, v := range include {
		if v == "reasoning.encrypted_content" {
			foundEncrypted = true
		}
	}
	if !foundEncrypted {
		t.Fatalf("include must request reasoning.encrypted_content, got %v", sent["include"])
	}
	input, _ := sent["input"].([]any)
	if len(input) != 1 {
		t.Fatalf("string input must normalise to one item, got %v", sent["input"])
	}
	first, _ := input[0].(map[string]any)
	if first["type"] != "message" || first["role"] != "user" {
		t.Fatalf("normalised input item = %v", first)
	}

	if gotHeaders.Get("Authorization") != "Bearer oauth-token" {
		t.Fatalf("Authorization = %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("X-Grok-Client-Identifier") != "grok-shell" {
		t.Fatalf("client identifier = %q", gotHeaders.Get("X-Grok-Client-Identifier"))
	}
	if gotHeaders.Get("X-Grok-Client-Version") != "1.0.44" {
		t.Fatalf("client version = %q", gotHeaders.Get("X-Grok-Client-Version"))
	}
	if gotHeaders.Get("X-Grok-Session-Id") != "sess-123" {
		t.Fatalf("session id must come from prompt_cache_key, got %q", gotHeaders.Get("X-Grok-Session-Id"))
	}
	if gotHeaders.Get("X-Grok-Conv-Id") != "sess-123" {
		t.Fatalf("conv id must equal session id, got %q", gotHeaders.Get("X-Grok-Conv-Id"))
	}
	if gotHeaders.Get("X-Grok-Req-Id") == "" {
		t.Fatal("x-grok-req-id missing")
	}
	if gotHeaders.Get("X-Grok-Turn-Idx") != "1" {
		t.Fatalf("turn idx = %q, want 1", gotHeaders.Get("X-Grok-Turn-Idx"))
	}
	if gotHeaders.Get("X-Grok-Model-Override") != "grok-4.5" {
		t.Fatalf("model override = %q", gotHeaders.Get("X-Grok-Model-Override"))
	}
	if gotHeaders.Get("X-Email") != "a@b.c" || gotHeaders.Get("X-UserId") != "user-9" {
		t.Fatalf("identity headers email=%q userid=%q", gotHeaders.Get("X-Email"), gotHeaders.Get("X-UserId"))
	}
	if res.URL != srv.URL {
		t.Fatalf("url = %q", res.URL)
	}
}

func TestGrokCLITransformMessagesFallbackAndNoEffortModel(t *testing.T) {
	ex := NewGrokCLIExecutor()
	body := map[string]any{
		"model":    "grok-build",
		"messages": []any{map[string]any{"role": "user", "content": "hey"}},
	}
	req := &Request{
		Provider: &ProviderInfo{ID: "grok-cli"}, Cred: Credential{ConnectionID: "conn-msgs"},
		Model: "grok-build", Body: body, State: map[string]any{},
	}
	out, err := ex.grokTransformBody(ex.Base, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := out["messages"]; has {
		t.Fatal("messages must be consumed into input")
	}
	input, _ := out["input"].([]any)
	if len(input) != 1 {
		t.Fatalf("input = %v", out["input"])
	}
	item, _ := input[0].(map[string]any)
	if item["content"] != "hey" || item["role"] != "user" {
		t.Fatalf("messages fallback item = %v", item)
	}
	// grok-build does not support reasoning effort: no effort key, but the
	// summary + encrypted-content include are still applied.
	reasoning, _ := out["reasoning"].(map[string]any)
	if reasoning == nil || reasoning["summary"] != "concise" {
		t.Fatalf("reasoning = %v", reasoning)
	}
	if _, has := reasoning["effort"]; has {
		t.Fatalf("grok-build must not receive reasoning.effort, got %v", reasoning)
	}
	if out["model"] != "grok-build" {
		t.Fatalf("model = %v", out["model"])
	}
}

func TestGrokCLINormalizeInputAndTools(t *testing.T) {
	nativeID := "rs_123e4567-e89b-42d3-a456-426614174000"
	body := map[string]any{
		"model": "grok-4.5",
		"input": []any{
			// Native reasoning item with encrypted content: kept.
			map[string]any{"type": "reasoning", "id": nativeID, "encrypted_content": "enc"},
			// Non-native reasoning item: dropped.
			map[string]any{"type": "reasoning", "id": "rs_foreign", "encrypted_content": "enc"},
			// Stored id on a message item: stripped (not a native UUID form).
			map[string]any{"type": "message", "role": "user", "content": "hi", "id": "msg_abc"},
			map[string]any{"type": "item_reference", "id": "resp_123"},
			map[string]any{"type": "custom_tool_call", "call_id": "call_1", "name": "run", "input": "ls"},
			// Orphan output (call_404 has no call): dropped by the pairing filter.
			map[string]any{"type": "function_call_output", "call_id": "call_404", "output": "orphan"},
			map[string]any{"type": "function_call_output", "call_id": "call_1", "output": "done"},
		},
		"tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": "get_weather", "description": "weather",
					"parameters": map[string]any{"type": "object", "properties": map[string]any{}},
				},
			},
			map[string]any{"type": "web_search"},
			map[string]any{"type": "bogus_type"},
		},
		"tool_choice": map[string]any{"type": "function", "function": map[string]any{"name": "get_weather"}},
	}
	ex := NewGrokCLIExecutor()
	req := &Request{
		Provider: &ProviderInfo{ID: "grok-cli"}, Cred: Credential{ConnectionID: "conn-norm"},
		Model: "grok-4.5", Body: body, State: map[string]any{},
	}
	out, err := ex.grokTransformBody(ex.Base, req)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := out["input"].([]any)
	var types []string
	for _, raw := range input {
		if m, ok := raw.(map[string]any); ok {
			types = append(types, getStr(m, "type"))
		}
	}
	joined := strings.Join(types, ",")
	if joined != "reasoning,message,function_call,function_call_output" {
		t.Fatalf("normalised input types = %q (%v)", joined, input)
	}
	msgItem, _ := input[1].(map[string]any)
	if _, has := msgItem["id"]; has {
		t.Fatal("stored msg_ id must be stripped from message items")
	}
	callItem, _ := input[2].(map[string]any)
	if callItem["name"] != "run" || callItem["call_id"] != "call_1" {
		t.Fatalf("custom_tool_call not converted: %v", callItem)
	}
	if args, _ := callItem["arguments"].(string); !strings.Contains(args, `"input":"ls"`) {
		t.Fatalf("custom_tool_call arguments = %v", callItem["arguments"])
	}

	tools, _ := out["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools = %v, want flattened function + hosted web_search", out["tools"])
	}
	fn, _ := tools[0].(map[string]any)
	if fn["type"] != "function" || fn["name"] != "get_weather" {
		t.Fatalf("flattened tool = %v", fn)
	}
	if _, has := fn["function"]; has {
		t.Fatal("nested function key must be flattened away")
	}
	hosted, _ := tools[1].(map[string]any)
	if hosted["type"] != "web_search" {
		t.Fatalf("hosted tool must pass through, got %v", hosted)
	}
	choice, _ := out["tool_choice"].(map[string]any)
	if choice == nil || choice["type"] != "function" || choice["name"] != "get_weather" {
		t.Fatalf("tool_choice = %v", out["tool_choice"])
	}
	// grok-4.5 supports effort: default reasoning effort is high.
	reasoning, _ := out["reasoning"].(map[string]any)
	if reasoning["effort"] != "high" {
		t.Fatalf("default effort = %v, want high", reasoning)
	}
}

func TestGrokCLIParseError402(t *testing.T) {
	ex := NewGrokCLIExecutor()
	pe := ex.ParseError(402, `{"code":"personal-team-blocked:spending-limit","error":"Spending limit reached"}`)
	if pe == nil || pe.Status != 402 || pe.Message != "Spending limit reached" {
		t.Fatalf("402 parseError = %+v", pe)
	}
	pe2 := ex.ParseError(500, "boom")
	if pe2 == nil || pe2.Status != 500 || pe2.Message != "boom" {
		t.Fatalf("fallback parseError = %+v", pe2)
	}
}

func TestGrokCLIEffortAndTurnHelpers(t *testing.T) {
	if grokNormalizeEffort("max") != "xhigh" || grokNormalizeEffort("LOW") != "low" ||
		grokNormalizeEffort("") != "high" || grokNormalizeEffort("bogus") != "high" {
		t.Fatal("grokNormalizeEffort mismatch")
	}
	if !grokSupportsReasoningEffort("grok-4.5") || !grokSupportsReasoningEffort("grok-4.5-high") ||
		grokSupportsReasoningEffort("grok-build") || grokSupportsReasoningEffort("grok-4.20") {
		t.Fatal("grokSupportsReasoningEffort mismatch")
	}
	if grokModelUpstreamID("grok-4.5-high") != "grok-4.5" || grokModelUpstreamID("unknown-1") != "unknown-1" {
		t.Fatal("grokModelUpstreamID mismatch")
	}

	input := []any{map[string]any{"role": "user", "type": "message", "content": "hi"}}
	if grokCountUserTurns(input) != 1 || grokCountUserTurns(nil) != 1 {
		t.Fatal("grokCountUserTurns mismatch")
	}
	session := "sess-turn-test"
	first := grokResolveTurnIdx(session, input, session+"|key-a")
	if first != 1 {
		t.Fatalf("first turn = %d, want 1", first)
	}
	// Same request key (a retry of the same body) reuses the turn.
	if again := grokResolveTurnIdx(session, input, session+"|key-a"); again != 1 {
		t.Fatalf("retry turn = %d, want 1", again)
	}
	// A new request in the same session never goes backwards.
	second := grokResolveTurnIdx(session, input, session+"|key-b")
	if second != 2 {
		t.Fatalf("second turn = %d, want 2", second)
	}
}

// --- grok-web ---

func TestGrokWebExecutorStreaming(t *testing.T) {
	var gotCookie, gotStatsig string
	var gotPayload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotStatsig = r.Header.Get("X-Statsig-Id")
		gotPayload, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(200)
		io.WriteString(w, "{\"result\":{\"response\":{\"responseId\":\"r1\",\"llmInfo\":{\"modelHash\":\"fp-abc\"},\"token\":\"Hello \"}}}\n")
		io.WriteString(w, "{\"result\":{\"response\":{\"token\":\"world\"}}}\n")
		io.WriteString(w, "not-json-line\n")
		io.WriteString(w, "{\"result\":{\"response\":{\"token\":\"!\"}}}\n")
	}))
	defer srv.Close()

	oldClient := HTTPClient
	HTTPClient = srv.Client()
	defer func() { HTTPClient = oldClient }()

	ex := NewGrokWebExecutor()
	p := &ProviderInfo{ID: "grok-web", BaseURL: srv.URL, Format: "grok-web"}
	cred := Credential{APIKey: "sso=tok123"}
	body := []byte(`{"model":"grok-4","stream":true,"messages":[
		{"role":"system","content":"Be nice"},
		{"role":"user","content":"Hi there"}
	]}`)
	res, err := ex.Execute(context.Background(), p, cred, body)
	if err != nil {
		t.Fatal(err)
	}
	out := readBody(t, res.Response)
	if res.ResponseFormat != "openai" {
		t.Fatalf("grok-web must report openai format, got %q", res.ResponseFormat)
	}
	if !strings.Contains(out, `"content":"Hello "`) || !strings.Contains(out, `"content":"world"`) {
		t.Fatalf("streamed SSE missing token deltas: %q", out)
	}
	if !strings.Contains(out, `"system_fingerprint":"fp-abc"`) {
		t.Fatalf("streamed SSE missing fingerprint: %q", out)
	}
	if !strings.Contains(out, `"finish_reason":"stop"`) || !strings.Contains(out, "[DONE]") {
		t.Fatalf("streamed SSE missing finish/[DONE]: %q", out)
	}
	if !strings.Contains(out, "chatcmpl-grok-") {
		t.Fatalf("streamed SSE missing grok completion id: %q", out)
	}
	if gotCookie != "sso=tok123" {
		t.Fatalf("Cookie = %q, want sso=tok123 (prefix stripped once)", gotCookie)
	}
	if gotStatsig == "" {
		t.Fatal("x-statsig-id header missing")
	}
	payload := grokDecodeSentBody(t, gotPayload)
	if payload["modelName"] != "grok-4" || payload["modelMode"] != "MODEL_MODE_GROK_4" {
		t.Fatalf("payload model mapping = %v / %v", payload["modelName"], payload["modelMode"])
	}
	if payload["message"] != "system: Be nice\n\nHi there" {
		t.Fatalf("payload message = %q", payload["message"])
	}
	if payload["temporary"] != true || payload["disableMemory"] != true {
		t.Fatalf("payload flags = %v", payload)
	}
}

func TestGrokWebExecutorNonStreaming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "{\"result\":{\"response\":{\"token\":\"Hel\"}}}\n")
		io.WriteString(w, "{\"result\":{\"response\":{\"token\":\"lo\"}}}\n")
	}))
	defer srv.Close()

	ex := NewGrokWebExecutor()
	p := &ProviderInfo{ID: "grok-web", BaseURL: srv.URL, Format: "grok-web"}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "tok"},
		[]byte(`{"model":"grok-3","messages":[{"role":"user","content":"Say hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	out := readBody(t, res.Response)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("non-streaming output not JSON: %v (%q)", err, out)
	}
	if parsed["object"] != "chat.completion" {
		t.Fatalf("object = %v", parsed["object"])
	}
	choices, _ := parsed["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("choices = %v", parsed["choices"])
	}
	choice, _ := choices[0].(map[string]any)
	msg, _ := choice["message"].(map[string]any)
	if msg["content"] != "Hello" {
		t.Fatalf("accumulated content = %q", msg["content"])
	}
	usage, _ := parsed["usage"].(map[string]any)
	// JS quirk: both counts are ceil(len("Hello")/4) = 2.
	if usage["prompt_tokens"] != float64(2) || usage["completion_tokens"] != float64(2) || usage["total_tokens"] != float64(4) {
		t.Fatalf("usage = %v", usage)
	}
}

func TestGrokWebExecutorModelResponseOverridesTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "{\"result\":{\"response\":{\"token\":\"partial\"}}}\n")
		io.WriteString(w, "{\"result\":{\"response\":{\"modelResponse\":{\"message\":\"Full answer\"}}}}\n")
	}))
	defer srv.Close()

	ex := NewGrokWebExecutor()
	p := &ProviderInfo{ID: "grok-web", BaseURL: srv.URL, Format: "grok-web"}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "tok"},
		[]byte(`{"model":"grok-4.1-fast","messages":[{"role":"user","content":"q"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	out := readBody(t, res.Response)
	if !strings.Contains(out, `"content":"Full answer"`) {
		t.Fatalf("modelResponse fullMessage must replace token accumulation: %q", out)
	}
}

func TestGrokWebExecutorValidationAndUpstreamErrors(t *testing.T) {
	ex := NewGrokWebExecutor()
	p := &ProviderInfo{ID: "grok-web", BaseURL: "http://127.0.0.1:1/unused", Format: "grok-web"}

	// Missing messages → synthetic 400, no upstream call.
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "tok"}, []byte(`{"model":"grok-4"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Response.StatusCode != 400 {
		t.Fatalf("missing messages status = %d, want 400", res.Response.StatusCode)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "Missing or empty messages array") {
		t.Fatalf("missing messages body = %q", body)
	}

	// Upstream 403 → auth-failed message with the upstream status preserved.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, "forbidden")
	}))
	defer srv.Close()
	p2 := &ProviderInfo{ID: "grok-web", BaseURL: srv.URL, Format: "grok-web"}
	res2, err := ex.Execute(context.Background(), p2, Credential{APIKey: "expired"},
		[]byte(`{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Response.StatusCode != 403 {
		t.Fatalf("upstream 403 status = %d", res2.Response.StatusCode)
	}
	body2 := readBody(t, res2.Response)
	if !strings.Contains(body2, "Grok auth failed") || !strings.Contains(body2, "HTTP_403") {
		t.Fatalf("upstream 403 body = %q", body2)
	}

	// NDJSON error event in a 200 stream (non-streaming) → 502 GROK_ERROR.
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "{\"error\":{\"message\":\"boom\",\"code\":\"X1\"}}\n")
	}))
	defer srv3.Close()
	p3 := &ProviderInfo{ID: "grok-web", BaseURL: srv3.URL, Format: "grok-web"}
	res3, err := ex.Execute(context.Background(), p3, Credential{APIKey: "tok"},
		[]byte(`{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if res3.Response.StatusCode != 502 {
		t.Fatalf("NDJSON error status = %d, want 502", res3.Response.StatusCode)
	}
	body3 := readBody(t, res3.Response)
	if !strings.Contains(body3, "boom") || !strings.Contains(body3, "GROK_ERROR") {
		t.Fatalf("NDJSON error body = %q", body3)
	}
}

func TestGrokWebModelMapAndMessageParsing(t *testing.T) {
	mini := grokWebLookupModel("grok-3-mini")
	if mini.GrokModel != "grok-3" || mini.ModelMode != "MODEL_MODE_GROK_3_MINI_THINKING" || !mini.IsThinking {
		t.Fatalf("grok-3-mini mapping = %+v", mini)
	}
	unknown := grokWebLookupModel("some-unknown-model")
	if unknown.GrokModel != "grok-4-1-thinking-1129" || unknown.ModelMode != "MODEL_MODE_FAST" {
		t.Fatalf("unknown model must default to grok-4.1-fast mapping, got %+v", unknown)
	}

	msgs := []any{
		map[string]any{"role": "developer", "content": "sys prompt"},
		map[string]any{"role": "user", "content": ""},
		map[string]any{"role": "assistant", "content": []any{
			map[string]any{"type": "text", "text": "prev"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "x"}},
			map[string]any{"type": "text", "text": "answer"},
		}},
		map[string]any{"role": "user", "content": "now?"},
	}
	got := grokParseOpenAIMessages(msgs)
	want := "system: sys prompt\n\nassistant: prev answer\n\nnow?"
	if got != want {
		t.Fatalf("grokParseOpenAIMessages = %q, want %q", got, want)
	}
}
