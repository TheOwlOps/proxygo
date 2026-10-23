package executors

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventStreamRoundTrip(t *testing.T) {
	frame := encodeEventFrame(
		map[string]string{":message-type": "event", ":event-type": "assistantResponseEvent"},
		map[string]any{"content": "hello"},
	)
	parsed, err := parseEventFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HeaderString(":event-type") != "assistantResponseEvent" {
		t.Fatalf("event-type = %q", parsed.HeaderString(":event-type"))
	}
	if parsed.Payload["content"] != "hello" {
		t.Fatalf("payload = %v", parsed.Payload)
	}
	// Corrupted CRC must throw, not return partial data.
	bad := append([]byte{}, frame...)
	bad[len(bad)-1] ^= 0xff
	if _, err := parseEventFrame(bad); err == nil {
		t.Fatal("expected CRC error")
	}
}

func TestKiroExecutorConvertsEventStream(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(encodeEventFrame(
		map[string]string{":message-type": "event", ":event-type": "assistantResponseEvent"},
		map[string]any{"content": "Hello "}))
	stream.Write(encodeEventFrame(
		map[string]string{":message-type": "event", ":event-type": "assistantResponseEvent"},
		map[string]any{"content": "world"}))
	stream.Write(encodeEventFrame(
		map[string]string{":message-type": "event", ":event-type": "metricsEvent"},
		map[string]any{"metricsEvent": map[string]any{"inputTokens": 10, "outputTokens": 5}}))
	stream.Write(encodeEventFrame(
		map[string]string{":message-type": "event", ":event-type": "messageStopEvent"},
		map[string]any{"stopReason": "END_TURN"}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-amzn-kiro-agent-mode") != "spec" {
			t.Errorf("missing kiro agent-mode header")
		}
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(200)
		w.Write(stream.Bytes())
	}))
	defer srv.Close()

	ex := NewKiroExecutor()
	p := &ProviderInfo{ID: "kiro", BaseURLs: []string{srv.URL}}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "tok"}, []byte(`{"model":"claude-sonnet-4.5"}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.ResponseFormat != "openai" {
		t.Fatalf("response format = %q", res.ResponseFormat)
	}
	if !strings.Contains(body, "Hello ") || !strings.Contains(body, "world") {
		t.Fatalf("converted SSE missing content: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("converted SSE missing finish_reason stop: %q", body)
	}
	if !strings.Contains(body, `"prompt_tokens":10`) || !strings.Contains(body, `"completion_tokens":5`) {
		t.Fatalf("converted SSE missing metrics usage: %q", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("converted SSE missing [DONE]: %q", body)
	}
}

func TestCommandCodeExecutorNDJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-session-id") == "" {
			t.Errorf("missing x-session-id header")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(200)
		io.WriteString(w, "{\"type\":\"start\"}\n")
		io.WriteString(w, "{\"type\":\"text-delta\",\"text\":\"Hello \"}\n")
		io.WriteString(w, "{\"type\":\"text-delta\",\"text\":\"there\"}\n")
		io.WriteString(w, "{\"type\":\"finish\",\"finishReason\":\"stop\",\"usage\":{\"inputTokens\":7,\"outputTokens\":3}}\n")
	}))
	defer srv.Close()

	ex := NewCommandCodeExecutor()
	p := &ProviderInfo{ID: "commandcode", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "cc-key"}, []byte(`{"model":"cc/model","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.ResponseFormat != "openai" {
		t.Fatalf("response format = %q", res.ResponseFormat)
	}
	if !strings.Contains(body, "Hello ") || !strings.Contains(body, "there") {
		t.Fatalf("NDJSON→SSE missing text: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, `"prompt_tokens":7`) {
		t.Fatalf("NDJSON→SSE missing finish/usage: %q", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("NDJSON→SSE missing [DONE]: %q", body)
	}
}

func TestCommandCodeExecutorEarlyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "{\"type\":\"error\",\"error\":\"rate limit exceeded\"}\n")
	}))
	defer srv.Close()

	ex := NewCommandCodeExecutor()
	p := &ProviderInfo{ID: "commandcode", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "k"}, []byte(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Response.Body.Close()
	if res.Response.StatusCode != 429 {
		t.Fatalf("early NDJSON error status = %d, want 429", res.Response.StatusCode)
	}
}

func TestCodexParseErrorUsageLimit(t *testing.T) {
	ex := NewCodexExecutor()
	resets := time.Now().Add(time.Hour).Unix()
	pe := ex.ParseError(429, `{"error":{"type":"usage_limit_reached","message":"limit hit","resets_at":`+int64Str(resets)+`}}`)
	if pe == nil || pe.ResetsAt.IsZero() {
		t.Fatalf("parseError = %+v", pe)
	}
	if pe.Message != "limit hit" {
		t.Fatalf("message = %q", pe.Message)
	}
}

func TestCodexTransformForcesStreamAndInput(t *testing.T) {
	ex := NewCodexExecutor()
	body := map[string]any{"model": "gpt-5-codex", "input": "hello"}
	req := &Request{Provider: &ProviderInfo{ID: "codex"}, Cred: Credential{ConnectionID: "conn-1"}, Model: "gpt-5-codex", Body: body, State: map[string]any{}}
	out, err := ex.transformBody(ex.Base, req)
	if err != nil {
		t.Fatal(err)
	}
	if out["stream"] != true {
		t.Fatal("codex must force stream=true")
	}
	items := out["input"].([]any)
	first := items[0].(map[string]any)
	if first["role"] != "user" {
		t.Fatalf("string input not normalised: %v", first)
	}
	if out["instructions"] == "" || out["instructions"] == nil {
		t.Fatal("default instructions not injected")
	}
}

func TestBedrockTransformAndFamilyGate(t *testing.T) {
	ex := NewBedrockExecutor("bedrock")
	p := &ProviderInfo{ID: "bedrock", Format: "claude"}
	out := ex.transformBody(p, map[string]any{"model": "us.anthropic.claude-sonnet-4-5", "stream": true, "messages": []any{}})
	if _, has := out["model"]; has {
		t.Fatal("bedrock transform must drop model")
	}
	if out["anthropic_version"] != "bedrock-2023-05-31" {
		t.Fatalf("anthropic_version = %v", out["anthropic_version"])
	}
	url, err := ex.buildURL(p, "us.anthropic.claude-sonnet-4-5-20250929-v1:0", true, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(url, "bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke-with-response-stream") {
		t.Fatalf("bedrock url = %q", url)
	}
	if _, err := ex.buildURL(p, "gpt-5", true, "us-east-1"); err == nil {
		t.Fatal("wrong-family model must be rejected upfront")
	}
}

func TestBedrockSigV4Signing(t *testing.T) {
	req, err := http.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	creds := awsCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret", Region: "us-east-1"}
	signAWSRequest(req, []byte("{}"), creds, "bedrock", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/bedrock/aws4_request") {
		t.Fatalf("authorization = %q", auth)
	}
	if !strings.Contains(auth, "Signature=") || len(strings.Split(auth, "Signature=")[1]) != 64 {
		t.Fatalf("signature malformed: %q", auth)
	}
	if req.Header.Get("X-Amz-Date") != "20240101T000000Z" {
		t.Fatalf("x-amz-date = %q", req.Header.Get("X-Amz-Date"))
	}
}

func TestMinimaxQuotaNormalization(t *testing.T) {
	mk := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	}
	out, err := normalizeMinimaxQuotaResponse(mk(403, `{"error":{"message":"insufficient balance"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.StatusCode != 429 {
		t.Fatalf("quota 403 must normalise to 429, got %d", out.StatusCode)
	}
	out2, err := normalizeMinimaxQuotaResponse(mk(403, `{"error":{"message":"forbidden: bad key"}}`))
	if err != nil {
		t.Fatal(err)
	}
	// "forbidden" alone doesn't name the balance... but note the JS regex
	// includes "limit/quota/…" only; a plain auth refusal passes through.
	if out2.StatusCode != 403 {
		t.Fatalf("auth 403 must pass through, got %d", out2.StatusCode)
	}
}

func TestVertexURLBuilding(t *testing.T) {
	v := NewVertexExecutor("vertex")
	saJSON := `{"type":"service_account","project_id":"proj-1","client_email":"a@b.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}`
	p := &ProviderInfo{ID: "vertex"}
	url, err := v.buildURL(p, Credential{APIKey: saJSON}, "gemini-2.0-flash", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://aiplatform.googleapis.com/v1/projects/proj-1/locations/us-central1/publishers/google/models/gemini-2.0-flash:streamGenerateContent?alt=sse"
	if url != want {
		t.Fatalf("vertex url = %q, want %q", url, want)
	}
	// Raw key, no project: projectless publishers endpoint with ?key=.
	url2, err := v.buildURL(p, Credential{APIKey: "raw-key"}, "gemini-2.0-flash", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(url2, ":generateContent?key=raw-key") {
		t.Fatalf("vertex raw-key url = %q", url2)
	}
}

func TestRegistryFallbackAndAliases(t *testing.T) {
	if _, ok := For("openai").(*DefaultExecutor); !ok {
		t.Fatal("unknown provider must fall back to DefaultExecutor")
	}
	if !HasSpecialised("kiro") || !HasSpecialised("bedrock") || HasSpecialised("openai") {
		t.Fatal("HasSpecialised mismatch")
	}
	if _, ok := For("br").(*BedrockExecutor); !ok {
		t.Fatal("br alias must resolve to BedrockExecutor")
	}
	if _, ok := For("cursor").(*CursorExecutor); !ok {
		t.Fatal("cursor must resolve to CursorExecutor placeholder")
	}
}
