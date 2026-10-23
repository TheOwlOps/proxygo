package executors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ocCapture records what an executor sent upstream.
type ocCapture struct {
	path   string
	header http.Header
	body   map[string]any
	raw    []byte
}

// ocTestServer returns a fake upstream that records the request and
// answers with a small OpenAI-shaped SSE stream.
func ocTestServer(t *testing.T, cap *ocCapture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.path = r.URL.Path
		cap.header = r.Header.Clone()
		cap.raw = raw
		cap.body = BodyMap(raw)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
}

const ocTestNativeSession = "ses_0123456789abABCDEFGHIJKLMN"

func ocToolsByName(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	tools, _ := body["tools"].([]any)
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		if tool == nil {
			continue
		}
		name := ocToolNameOf(tool)
		if name != "" {
			out[name] = tool
		}
	}
	return out
}

func TestOpencodeFreeChatLane(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeExecutor()
	p := &ProviderInfo{ID: "opencode", BaseURL: srv.URL, Format: "openai"}
	cred := Credential{RawHeaders: map[string]string{"x-opencode-session": ocTestNativeSession}}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"some-chat-model","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("SSE passthrough missing [DONE]: %q", body)
	}
	if cap.path != "/inference/v1/chat/completions" {
		t.Fatalf("path = %q", cap.path)
	}
	if got := cap.header.Get("Authorization"); got != "Bearer public" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := cap.header.Get("User-Agent"); got != ocUA {
		t.Fatalf("User-Agent = %q, want %q", got, ocUA)
	}
	for _, h := range []string{"x-opencode-session", "x-opencode-session-id", "x-session-affinity", "x-session-id"} {
		if got := cap.header.Get(h); got != ocTestNativeSession {
			t.Fatalf("%s = %q, want native session", h, got)
		}
	}
	if got := cap.header.Get("x-opencode-client"); got != "cli" {
		t.Fatalf("x-opencode-client = %q", got)
	}
	if got := cap.header.Get("Accept"); got != "text/event-stream" {
		t.Fatalf("Accept = %q", got)
	}
	if cap.body["stream"] != true {
		t.Fatalf("stream must be forced true, body = %v", cap.body)
	}
	// Fingerprint: exact read/shell definitions appended (chat shape) and
	// the placeholder note becomes the system message.
	tools := ocToolsByName(t, cap.body)
	for _, name := range []string{"read", "shell"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("fingerprint tool %q missing: %v", name, cap.body["tools"])
		}
		fn, _ := tool["function"].(map[string]any)
		if fn == nil || !strings.HasPrefix(getStr(fn, "description"), "Read the contents") && name == "read" {
			t.Fatalf("fingerprint %q not in chat shape / wrong description: %v", name, tool)
		}
	}
	msgs, _ := cap.body["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatal("messages missing")
	}
	first, _ := msgs[0].(map[string]any)
	if first["role"] != "system" || !strings.Contains(getStr(first, "content"), "placeholders") {
		t.Fatalf("placeholder note not prepended: %v", first)
	}
}

func TestOpencodeFreeResponsesLane(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeExecutor()
	p := &ProviderInfo{
		ID: "opencode", BaseURL: srv.URL, Format: "openai",
		Quirks: map[string]any{"forceAutoToolChoiceModels": []any{"muse-spark-1.3-contributor-free"}},
	}
	res, err := ex.Execute(context.Background(), p, Credential{},
		[]byte(`{"model":"muse-spark-1.3-contributor-free","input":"hello","max_tokens":99,"reasoning_effort":"high","tool_choice":"none","tools":[{"type":"function","function":{"name":"lookup","description":"look","parameters":{"type":"object"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.path != "/inference/v1/responses" {
		t.Fatalf("path = %q", cap.path)
	}
	input, _ := cap.body["input"].([]any)
	if len(input) != 1 {
		t.Fatalf("input not normalised: %v", cap.body["input"])
	}
	item, _ := input[0].(map[string]any)
	content, _ := item["content"].([]any)
	part, _ := content[0].(map[string]any)
	if part["text"] != "hello" || part["type"] != "input_text" {
		t.Fatalf("input item = %v", item)
	}
	if cap.body["max_output_tokens"] == nil {
		t.Fatalf("max_output_tokens missing: %v", cap.body)
	}
	if _, has := cap.body["max_tokens"]; has {
		t.Fatal("max_tokens must be deleted")
	}
	if cap.body["store"] != false || cap.body["stream"] != true {
		t.Fatalf("store/stream = %v/%v", cap.body["store"], cap.body["stream"])
	}
	reasoning, _ := cap.body["reasoning"].(map[string]any)
	if reasoning["effort"] != "high" || reasoning["summary"] != "auto" {
		t.Fatalf("reasoning = %v", reasoning)
	}
	if _, has := cap.body["reasoning_effort"]; has {
		t.Fatal("reasoning_effort must be deleted")
	}
	if cap.body["tool_choice"] != "auto" {
		t.Fatalf("tool_choice = %v, want auto (quirk-forced)", cap.body["tool_choice"])
	}
	tools := ocToolsByName(t, cap.body)
	lookup, ok := tools["lookup"]
	if !ok {
		t.Fatalf("caller tool lost: %v", cap.body["tools"])
	}
	if _, hasFn := lookup["function"]; hasFn {
		t.Fatalf("responses tools must be flat: %v", lookup)
	}
	if _, ok := tools["read"]; !ok {
		t.Fatalf("fingerprint read missing: %v", cap.body["tools"])
	}
	if read := tools["read"]; read["strict"] != false {
		t.Fatalf("flat fingerprint tool must carry strict:false: %v", read)
	}
	if instr, _ := cap.body["instructions"].(string); !strings.Contains(instr, "placeholders") {
		t.Fatalf("instructions note missing: %v", cap.body["instructions"])
	}
	// No native/hinted session and no connection: a generated ses_ id.
	if got := cap.header.Get("x-opencode-session"); !ocSessionRe.MatchString(got) {
		t.Fatalf("generated session = %q", got)
	}
}

func TestOpencodeFreeSanitizesResponsesItems(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeExecutor()
	p := &ProviderInfo{ID: "opencode", BaseURL: srv.URL, Format: "openai"}
	body := `{"model":"muse-spark-1.2-contributor-free","input":[` +
		`{"type":"reasoning","encrypted_content":"secret"},` +
		`{"type":"function_call","name":"lookup","call_id":"c1","arguments":{"q":1},"encrypted_content":"x"},` +
		`{"type":"function_call_output","call_id":"c1","output":42}]}`
	res, err := ex.Execute(context.Background(), p, Credential{}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	input, _ := cap.body["input"].([]any)
	if len(input) != 2 {
		t.Fatalf("reasoning item must be dropped, input = %v", cap.body["input"])
	}
	call, _ := input[0].(map[string]any)
	if call["type"] != "function_call" || call["arguments"] != `{"q":1}` {
		t.Fatalf("function_call not coerced: %v", call)
	}
	if _, has := call["encrypted_content"]; has {
		t.Fatal("encrypted_content must be stripped")
	}
	out, _ := input[1].(map[string]any)
	if out["output"] != "42" {
		t.Fatalf("function_call_output.output = %v, want string \"42\"", out["output"])
	}
}

func TestOpencodeFreeMessagesLane(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeExecutor()
	p := &ProviderInfo{ID: "opencode", BaseURL: srv.URL, Format: "openai"}
	res, err := ex.Execute(context.Background(), p, Credential{},
		[]byte(`{"model":"union-alpha","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.path != "/inference/v1/messages" {
		t.Fatalf("path = %q", cap.path)
	}
	if got := cap.header.Get("anthropic-version"); got != anthropicAPIVersion {
		t.Fatalf("anthropic-version = %q", got)
	}
}

func TestOpencodeStableSessionPerConnection(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeExecutor()
	p := &ProviderInfo{ID: "opencode", BaseURL: srv.URL, Format: "openai"}
	cred := Credential{ConnectionID: "conn-oc-1"}
	var sessions []string
	for i := 0; i < 2; i++ {
		res, err := ex.Execute(context.Background(), p, cred,
			[]byte(`{"model":"some-chat-model","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		readBody(t, res.Response)
		sessions = append(sessions, cap.header.Get("x-opencode-session"))
	}
	if sessions[0] == "" || sessions[0] != sessions[1] {
		t.Fatalf("session must be stable per connection: %q vs %q", sessions[0], sessions[1])
	}
	if !ocSessionRe.MatchString(sessions[0]) {
		t.Fatalf("session shape = %q", sessions[0])
	}
}

func TestOpencodeSessionTranslationHelpers(t *testing.T) {
	a := ocTranslateSessionID("some-client-session", "generic")
	b := ocTranslateSessionID("some-client-session", "generic")
	if a != b || !ocSessionRe.MatchString(a) {
		t.Fatalf("translateSessionId not deterministic/ses-shaped: %q vs %q", a, b)
	}
	if got := ocTranslateSessionID(ocTestNativeSession, "generic"); got != ocTestNativeSession {
		t.Fatalf("valid ses_ must pass through, got %q", got)
	}
	g := ocGoTranslatedSession("abc", "generic")
	if !strings.HasPrefix(g, "ses_") || len(g) != 36 {
		t.Fatalf("opencode-go translated session = %q", g)
	}
	if ocGoTranslatedSession("abc", "generic") != g {
		t.Fatal("opencode-go translated session must be deterministic")
	}
}

func TestOpencodeUAHandling(t *testing.T) {
	ex := NewOpencodeExecutor()
	mkReq := func(ua string) *Request {
		return &Request{
			Provider: &ProviderInfo{ID: "opencode", BaseURL: "https://opencode.ai"},
			Cred:     Credential{RawHeaders: map[string]string{"User-Agent": ua, "x-opencode-session": ocTestNativeSession}},
			Model:    "m", Stream: true, State: map[string]any{},
		}
	}
	headers, err := ex.ocBuildHeaders(ex.Base, mkReq("opencode/beta/2.1.0/cli"), "")
	if err != nil {
		t.Fatal(err)
	}
	if headers["User-Agent"] != "opencode/beta/2.1.0/cli" {
		t.Fatalf("valid v2 UA must pass through, got %q", headers["User-Agent"])
	}
	headers, err = ex.ocBuildHeaders(ex.Base, mkReq("opencode/1.18.31"), "")
	if err != nil {
		t.Fatal(err)
	}
	if headers["User-Agent"] != ocUA {
		t.Fatalf("v1 UA must be replaced, got %q", headers["User-Agent"])
	}
}

func TestOpencodeGoResponsesLane(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeGoExecutor()
	p := &ProviderInfo{ID: "opencode-go", BaseURL: srv.URL + "/zen/go/v1/chat/completions", Format: "openai"}
	body := `{"model":"grok-4.6","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"max_tokens":50,"reasoning_effort":"low","tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "ocg-key"}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.path != "/zen/go/v1/responses" {
		t.Fatalf("path = %q", cap.path)
	}
	if got := cap.header.Get("Authorization"); got != "Bearer ocg-key" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := cap.header.Get("x-opencode-session"); !strings.HasPrefix(got, "ses_") || len(got) != 36 {
		t.Fatalf("session = %q, want ses_+32hex", got)
	}
	if cap.body["store"] != false || cap.body["stream"] != true {
		t.Fatalf("store/stream = %v/%v", cap.body["store"], cap.body["stream"])
	}
	if cap.body["max_output_tokens"] == nil {
		t.Fatalf("max_output_tokens missing: %v", cap.body)
	}
	reasoning, _ := cap.body["reasoning"].(map[string]any)
	if reasoning["effort"] != "low" || reasoning["summary"] != "auto" {
		t.Fatalf("reasoning = %v", reasoning)
	}
	tools := ocToolsByName(t, cap.body)
	lookup, ok := tools["lookup"]
	if !ok {
		t.Fatalf("tool lost: %v", cap.body["tools"])
	}
	if _, hasFn := lookup["function"]; hasFn {
		t.Fatalf("responses tools must be flattened: %v", lookup)
	}
	params, _ := lookup["parameters"].(map[string]any)
	if _, hasProps := params["properties"]; !hasProps {
		t.Fatalf("parameters.properties must be filled: %v", params)
	}
}

func TestOpencodeGoChatLanePassthrough(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeGoExecutor()
	p := &ProviderInfo{ID: "opencode-go", BaseURL: srv.URL + "/zen/go/v1/chat/completions", Format: "openai"}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "ocg-key"},
		[]byte(`{"model":"kimi-k2.6","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.path != "/zen/go/v1/chat/completions" {
		t.Fatalf("path = %q", cap.path)
	}
	if _, has := cap.body["store"]; has {
		t.Fatal("chat lane must not gain store")
	}
	if got := cap.header.Get("x-opencode-session"); !strings.HasPrefix(got, "ses_") {
		t.Fatalf("session header missing: %q", got)
	}
	// Native session headers pass through untranslated on opencode-go.
	cap2 := &ocCapture{}
	srv2 := ocTestServer(t, cap2)
	defer srv2.Close()
	p2 := &ProviderInfo{ID: "opencode-go", BaseURL: srv2.URL + "/zen/go/v1/chat/completions", Format: "openai"}
	cred := Credential{APIKey: "k", RawHeaders: map[string]string{"x-opencode-session": "my-native-session"}}
	res2, err := ex.Execute(context.Background(), p2, cred,
		[]byte(`{"model":"kimi-k2.6","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res2.Response)
	if got := cap2.header.Get("x-opencode-session"); got != "my-native-session" {
		t.Fatalf("native session = %q", got)
	}
}

func TestOpencodeZenFreeTierIdentity(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeZenExecutor()
	p := &ProviderInfo{ID: "opencode-zen", BaseURL: srv.URL + "/zen/v1/chat/completions", Format: "openai"}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "oc_sk_real"},
		[]byte(`{"model":"deepseek-v4-flash-free","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.path != "/zen/v1/chat/completions" {
		t.Fatalf("path = %q", cap.path)
	}
	if got := cap.header.Get("Authorization"); got != "Bearer public" {
		t.Fatalf("free-tier Authorization = %q, want Bearer public", got)
	}
	if got := cap.header.Get("x-opencode-request"); !strings.HasPrefix(got, "msg_") {
		t.Fatalf("x-opencode-request = %q, want msg_…", got)
	}
	if got := cap.header.Get("User-Agent"); got != ocZenUA {
		t.Fatalf("User-Agent = %q, want %q", got, ocZenUA)
	}
	if got := cap.header.Get("x-opencode-client"); got != "desktop" {
		t.Fatalf("x-opencode-client = %q", got)
	}
	if got := cap.header.Get("x-opencode-session"); !ocSessionRe.MatchString(got) {
		t.Fatalf("session = %q", got)
	}
	if cap.body["stream"] != true {
		t.Fatalf("stream must be forced true: %v", cap.body)
	}
	tools := ocToolsByName(t, cap.body)
	for _, name := range []string{"bash", "glob", "grep", "read"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("zen fingerprint tool %q missing: %v", name, cap.body["tools"])
		}
		fn, _ := tool["function"].(map[string]any)
		if getStr(fn, "description") != "OpenCode built-in "+name+" tool" {
			t.Fatalf("zen fingerprint %q shape wrong: %v", name, tool)
		}
	}
}

func TestOpencodeZenPaidKeepsKey(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeZenExecutor()
	p := &ProviderInfo{ID: "opencode-zen", BaseURL: srv.URL + "/zen/v1/chat/completions", Format: "openai"}
	cred := Credential{APIKey: "oc_sk_paid", RawHeaders: map[string]string{"User-Agent": "opencode/1.18.31"}}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if got := cap.header.Get("Authorization"); got != "Bearer oc_sk_paid" {
		t.Fatalf("paid Authorization = %q", got)
	}
	if got := cap.header.Get("x-opencode-request"); got != "" {
		t.Fatalf("paid lane must not send x-opencode-request, got %q", got)
	}
	if got := cap.header.Get("User-Agent"); got != "opencode/1.18.31" {
		t.Fatalf("valid downstream UA must pass through, got %q", got)
	}
}

func TestOpencodeZenMuseSparkResponsesLane(t *testing.T) {
	cap := &ocCapture{}
	srv := ocTestServer(t, cap)
	defer srv.Close()

	ex := NewOpencodeZenExecutor()
	p := &ProviderInfo{ID: "opencode-zen", BaseURL: srv.URL + "/zen/v1/chat/completions", Format: "openai"}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "oc_sk_paid"},
		[]byte(`{"model":"muse-spark-1.3","input":"hello","max_completion_tokens":10}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.path != "/zen/v1/responses" {
		t.Fatalf("path = %q", cap.path)
	}
	if cap.body["store"] != false {
		t.Fatalf("store = %v", cap.body["store"])
	}
	if cap.body["max_output_tokens"] == nil {
		t.Fatalf("max_output_tokens missing: %v", cap.body)
	}
	tools := ocToolsByName(t, cap.body)
	for _, name := range []string{"bash", "glob", "grep", "read"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("responses fingerprint %q missing: %v", name, cap.body["tools"])
		}
		if _, hasFn := tool["function"]; hasFn {
			t.Fatalf("responses fingerprint must be flat: %v", tool)
		}
	}
}
