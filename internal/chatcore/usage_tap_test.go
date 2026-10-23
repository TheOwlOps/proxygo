package chatcore

import (
	"io"
	"strings"
	"testing"
	"time"
)

type evCapture struct{ events []UsageEvent }

func (c *evCapture) sink() func(UsageEvent) {
	return func(ev UsageEvent) { c.events = append(c.events, ev) }
}

func TestUsageTapJSONBody(t *testing.T) {
	cap := &evCapture{}
	s := &Service{UsageSink: cap.sink()}
	body := `{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`
	rc := s.recordUsageTap(ChatRequest{APIKey: "sk-x", Endpoint: "/v1/chat/completions"},
		"openai", "gpt-4o", "conn-1", io.NopCloser(strings.NewReader(body)), "application/json", time.Now())
	out, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if string(out) != body {
		t.Fatalf("tap altered bytes: %s", out)
	}
	if len(cap.events) != 1 {
		t.Fatalf("events = %d, want 1", len(cap.events))
	}
	ev := cap.events[0]
	if ev.PromptTokens != 11 || ev.CompletionTokens != 7 {
		t.Fatalf("tokens = %d/%d, want 11/7", ev.PromptTokens, ev.CompletionTokens)
	}
	if ev.Status != "success" || ev.Provider != "openai" || ev.ConnectionID != "conn-1" {
		t.Fatalf("event meta wrong: %+v", ev)
	}
	if _, ok := ev.ResponseBody.(map[string]any); !ok {
		t.Fatalf("response body not captured as JSON: %T", ev.ResponseBody)
	}
}

func TestUsageTapSSEStream(t *testing.T) {
	cap := &evCapture{}
	s := &Service{UsageSink: cap.sink()}
	sse := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\n" +
		"data: [DONE]\n\n"
	rc := s.recordUsageTap(ChatRequest{}, "openai", "gpt-4o", "c1",
		io.NopCloser(strings.NewReader(sse)), "text/event-stream", time.Now())
	out, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(out) != sse {
		t.Fatalf("tap altered stream bytes")
	}
	if len(cap.events) != 1 {
		t.Fatalf("events = %d, want 1", len(cap.events))
	}
	ev := cap.events[0]
	if ev.PromptTokens != 5 || ev.CompletionTokens != 3 {
		t.Fatalf("tokens = %d/%d, want 5/3", ev.PromptTokens, ev.CompletionTokens)
	}
}

func TestUsageTapClaudeShapes(t *testing.T) {
	// Claude JSON body: usage{input_tokens, output_tokens}.
	if p, c, ok := usageFromMap(map[string]any{"usage": map[string]any{"input_tokens": 9.0, "output_tokens": 4.0}}); !ok || p != 9 || c != 4 {
		t.Fatalf("claude body: %d %d %v", p, c, ok)
	}
	// Claude stream message_start: message{usage{...}}.
	if p, c, ok := usageFromMap(map[string]any{"message": map[string]any{"usage": map[string]any{"input_tokens": 2.0, "output_tokens": 1.0}}}); !ok || p != 2 || c != 1 {
		t.Fatalf("claude stream: %d %d %v", p, c, ok)
	}
	// Responses API completed event: response{usage{input_tokens, output_tokens}}.
	if p, c, ok := usageFromMap(map[string]any{"response": map[string]any{"usage": map[string]any{"input_tokens": 6.0, "output_tokens": 2.0}}}); !ok || p != 6 || c != 2 {
		t.Fatalf("responses: %d %d %v", p, c, ok)
	}
	// Gemini: usageMetadata{promptTokenCount, candidatesTokenCount}.
	if p, c, ok := usageFromMap(map[string]any{"usageMetadata": map[string]any{"promptTokenCount": 8.0, "candidatesTokenCount": 3.0}}); !ok || p != 8 || c != 3 {
		t.Fatalf("gemini: %d %d %v", p, c, ok)
	}
}

func TestUsageTapNilSinkPassthrough(t *testing.T) {
	s := &Service{}
	rc := s.recordUsageTap(ChatRequest{}, "p", "m", "c", io.NopCloser(strings.NewReader("x")), "application/json", time.Now())
	out, _ := io.ReadAll(rc)
	if string(out) != "x" {
		t.Fatalf("passthrough altered: %q", out)
	}
}
