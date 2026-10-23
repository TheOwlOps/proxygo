package translator

import (
	"strings"
	"testing"
)

// ---------- OpenAI → Kiro request ----------

func kiroConversationState(t *testing.T, payload Body) Body {
	t.Helper()
	cs := obj(payload, "conversationState")
	if cs == nil {
		t.Fatalf("payload missing conversationState: %#v", payload)
	}
	return cs
}

func TestOpenAIToKiroRequestShape(t *testing.T) {
	clearKiroSessionStores()
	payload, err := TranslateRequest(FormatOpenAI, FormatKiro, Body{
		"model": "claude-sonnet-4-5",
		"messages": []any{
			Body{"role": "system", "content": "You are helpful."},
			Body{"role": "user", "content": "Hello"},
			Body{"role": "assistant", "content": "Hi there"},
			Body{"role": "user", "content": "How are you?"},
		},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	cs := kiroConversationState(t, payload)
	if cs["chatTriggerType"] != "MANUAL" {
		t.Errorf("chatTriggerType = %v", cs["chatTriggerType"])
	}
	if id := str(cs, "conversationId"); id == "" {
		t.Errorf("conversationId empty")
	}
	if payload["profileArn"] != KiroDefaultProfileARN {
		t.Errorf("profileArn = %v, want builder-id default", payload["profileArn"])
	}
	if payload["_kiroUpstreamModel"] != "claude-sonnet-4-5" {
		t.Errorf("_kiroUpstreamModel = %v", payload["_kiroUpstreamModel"])
	}
	ic := obj(payload, "inferenceConfig")
	if ic == nil || intVal(ic["maxTokens"]) != 32000 {
		t.Errorf("inferenceConfig = %#v", ic)
	}

	current := obj(obj(cs, "currentMessage"), "userInputMessage")
	if current == nil {
		t.Fatalf("currentMessage missing: %#v", cs)
	}
	if str(current, "modelId") != "claude-sonnet-4-5" || current["origin"] != "AI_EDITOR" {
		t.Errorf("current userInputMessage = %#v", current)
	}
	if !strings.Contains(str(current, "content"), "How are you?") {
		t.Errorf("current content = %q", str(current, "content"))
	}
	// Volatile time context is injected into the current turn only.
	if !strings.Contains(str(current, "content"), "[Context: Current time is ") {
		t.Errorf("current content missing time context: %q", str(current, "content"))
	}

	history := arr(cs, "history")
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2 (%#v)", len(history), history)
	}
	first, _ := history[0].(map[string]any)
	firstUser := obj(first, "userInputMessage")
	// The system prompt became an <instructions> block inside msg0, and
	// session replay froze the time context into it.
	if !strings.Contains(str(firstUser, "content"), "<instructions>\nYou are helpful.\n</instructions>") {
		t.Errorf("history[0] content = %q", str(firstUser, "content"))
	}
	if !strings.Contains(str(firstUser, "content"), "Hello") {
		t.Errorf("history[0] content missing user text: %q", str(firstUser, "content"))
	}
	second, _ := history[1].(map[string]any)
	if am := obj(second, "assistantResponseMessage"); am == nil || str(am, "content") != "Hi there" {
		t.Errorf("history[1] = %#v", second)
	}
}

func TestOpenAIToKiroToolPairing(t *testing.T) {
	clearKiroSessionStores()
	payload, err := TranslateRequest(FormatOpenAI, FormatKiro, Body{
		"model": "claude-sonnet-4-5",
		"tools": []any{
			Body{"type": "function", "function": Body{
				"name":        "get_weather",
				"description": "Get weather",
				"parameters":  Body{"type": "object", "properties": Body{"city": Body{"type": "string"}}, "required": []any{"city"}},
			}},
		},
		"messages": []any{
			Body{"role": "user", "content": "Weather in Hanoi?"},
			Body{"role": "assistant", "content": "", "tool_calls": []any{
				Body{"id": "call_1", "type": "function", "function": Body{"name": "get_weather", "arguments": `{"city":"Hanoi"}`}},
			}},
			Body{"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
			Body{"role": "user", "content": "Thanks"},
		},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	cs := kiroConversationState(t, payload)
	history := arr(cs, "history")
	if len(history) != 2 {
		t.Fatalf("history len = %d (%#v)", len(history), history)
	}
	assistant, _ := history[1].(map[string]any)
	am := obj(assistant, "assistantResponseMessage")
	uses := arr(am, "toolUses")
	if len(uses) != 1 {
		t.Fatalf("toolUses = %#v", am)
	}
	use, _ := uses[0].(map[string]any)
	if str(use, "toolUseId") != "call_1" || str(use, "name") != "get_weather" {
		t.Errorf("toolUse = %#v", use)
	}
	if input := obj(use, "input"); input == nil || str(input, "city") != "Hanoi" {
		t.Errorf("toolUse input = %#v", use["input"])
	}
	// The tool result rides on the *next* user turn (now the current one).
	current := obj(obj(cs, "currentMessage"), "userInputMessage")
	ctx := obj(current, "userInputMessageContext")
	if ctx == nil {
		t.Fatalf("current missing context: %#v", current)
	}
	results := arr(ctx, "toolResults")
	if len(results) != 1 {
		t.Fatalf("toolResults = %#v", ctx)
	}
	result, _ := results[0].(map[string]any)
	if str(result, "toolUseId") != "call_1" || str(result, "status") != "success" {
		t.Errorf("toolResult = %#v", result)
	}
	specs := arr(ctx, "tools")
	if len(specs) != 1 {
		t.Fatalf("tool specs on current = %#v", ctx)
	}
	spec := obj(specs[0].(map[string]any), "toolSpecification")
	if spec == nil || str(spec, "name") != "get_weather" {
		t.Errorf("toolSpecification = %#v", specs[0])
	}
}

func TestOpenAIToKiroAgenticAndThinkingSuffix(t *testing.T) {
	clearKiroSessionStores()
	payload, err := TranslateRequest(FormatOpenAI, FormatKiro, Body{
		"model": "claude-sonnet-4-5-thinking-agentic",
		"messages": []any{
			Body{"role": "user", "content": "Write a big file"},
		},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if payload["_kiroUpstreamModel"] != "claude-sonnet-4-5" {
		t.Errorf("upstream = %v, want suffixes stripped", payload["_kiroUpstreamModel"])
	}
	cs := kiroConversationState(t, payload)
	// Single-turn conversation: history is empty and the frozen session
	// start IS the current message, so the prefixes land there.
	if history := arr(cs, "history"); len(history) != 0 {
		t.Fatalf("history len = %d (%#v)", len(history), history)
	}
	current := obj(obj(cs, "currentMessage"), "userInputMessage")
	content := str(current, "content")
	if !strings.Contains(content, "<thinking_mode>enabled</thinking_mode>") {
		t.Errorf("current missing thinking prefix: %.120q", content)
	}
	if !strings.Contains(content, "CHUNKED WRITE PROTOCOL") {
		t.Errorf("current missing agentic prompt: %.120q", content)
	}
	if !strings.Contains(content, "Write a big file") {
		t.Errorf("current missing user text: %q", content)
	}
}

func TestOpenAIToKiroSanitizedToolNames(t *testing.T) {
	clearKiroSessionStores()
	payload, err := TranslateRequest(FormatOpenAI, FormatKiro, Body{
		"model": "claude-sonnet-4-5",
		"tools": []any{
			Body{"type": "function", "function": Body{"name": "ext:read/file", "description": "d", "parameters": Body{}}},
		},
		"messages": []any{Body{"role": "user", "content": "go"}},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	m := obj(payload, "_toolNameMap")
	if m == nil || m["ext_read_file"] != "ext:read/file" {
		t.Errorf("_toolNameMap = %#v, want sanitized->original", payload["_toolNameMap"])
	}
}

// ---------- Claude → Kiro request (direct route) ----------

func TestClaudeToKiroRequest(t *testing.T) {
	clearKiroSessionStores()
	payload, err := TranslateRequest(FormatClaude, FormatKiro, Body{
		"model":      "claude-sonnet-4-5",
		"max_tokens": 4096,
		"system":     "You are a coding assistant.",
		"tools": []any{
			Body{"name": "read_file", "description": "Read a file", "input_schema": Body{"type": "object", "properties": Body{"path": Body{"type": "string"}}}},
		},
		"messages": []any{
			Body{"role": "user", "content": []any{Body{"type": "text", "text": "Read x.go"}}},
			Body{"role": "assistant", "content": []any{
				Body{"type": "text", "text": "Sure"},
				Body{"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": Body{"path": "x.go"}},
			}},
			Body{"role": "user", "content": []any{
				Body{"type": "tool_result", "tool_use_id": "toolu_1", "content": []any{Body{"type": "text", "text": "package main"}}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	cs := kiroConversationState(t, payload)
	ic := obj(payload, "inferenceConfig")
	if ic == nil || intVal(ic["maxTokens"]) != 4096 {
		t.Errorf("inferenceConfig = %#v, want maxTokens from body", ic)
	}
	history := arr(cs, "history")
	if len(history) != 2 {
		t.Fatalf("history len = %d (%#v)", len(history), history)
	}
	first, _ := history[0].(map[string]any)
	firstContent := str(obj(first, "userInputMessage"), "content")
	// Claude's system field travels inside msg0 via the content prefix.
	if !strings.Contains(firstContent, "You are a coding assistant.") {
		t.Errorf("history[0] missing system text: %q", firstContent)
	}
	if !strings.Contains(firstContent, "Read x.go") {
		t.Errorf("history[0] = %q", firstContent)
	}
	current := obj(obj(cs, "currentMessage"), "userInputMessage")
	ctx := obj(current, "userInputMessageContext")
	results := arr(ctx, "toolResults")
	if len(results) != 1 {
		t.Fatalf("current toolResults = %#v", ctx)
	}
	result, _ := results[0].(map[string]any)
	if str(result, "toolUseId") != "toolu_1" {
		t.Errorf("toolResult = %#v", result)
	}
	if specs := arr(ctx, "tools"); len(specs) != 1 {
		t.Errorf("current tools = %#v", ctx)
	}
}

// ---------- Kiro events → OpenAI chunks ----------

func TestKiroEventsToOpenAIChunks(t *testing.T) {
	state := NewStreamState(FormatOpenAI)
	state.Model = "claude-sonnet-4-5"
	events := []Body{
		{"assistantResponseEvent": Body{"content": "Hello "}},
		{"assistantResponseEvent": Body{"content": "world"}},
		{"usageEvent": Body{"inputTokens": 10.0, "outputTokens": 5.0}},
		{"messageStopEvent": Body{}},
	}
	var chunks []Body
	for _, ev := range events {
		out, err := TranslateStreamChunk(FormatKiro, FormatOpenAI, ev, state)
		if err != nil {
			t.Fatalf("chunk: %v", err)
		}
		chunks = append(chunks, out...)
	}
	if len(chunks) != 3 {
		t.Fatalf("chunks = %d (%#v)", len(chunks), chunks)
	}
	d0 := obj(arr(chunks[0], "choices")[0].(map[string]any), "delta")
	if str(d0, "role") != "assistant" || str(d0, "content") != "Hello " {
		t.Errorf("chunk0 delta = %#v", d0)
	}
	last := chunks[2]
	choice := arr(last, "choices")[0].(map[string]any)
	if str(choice, "finish_reason") != "stop" {
		t.Errorf("finish_reason = %v", choice["finish_reason"])
	}
	usage := obj(last, "usage")
	if usage == nil || intVal(usage["prompt_tokens"]) != 10 || intVal(usage["completion_tokens"]) != 5 {
		t.Errorf("usage = %#v", last["usage"])
	}
}

func TestKiroToolUseEventToOpenAI(t *testing.T) {
	state := NewStreamState(FormatOpenAI)
	state.ToolNameMap = map[string]string{"mcp_srv_read": "mcp__srv__read"}
	out, err := TranslateStreamChunk(FormatKiro, FormatOpenAI, Body{
		"toolUseEvent": Body{"toolUseId": "call_9", "name": "mcp_srv_read", "input": Body{"path": "x.go"}},
	}, state)
	if err != nil || len(out) != 1 {
		t.Fatalf("out = %v, %v", out, err)
	}
	delta := obj(arr(out[0], "choices")[0].(map[string]any), "delta")
	calls := arr(delta, "tool_calls")
	if len(calls) != 1 {
		t.Fatalf("tool_calls = %#v", delta)
	}
	call, _ := calls[0].(map[string]any)
	fn := obj(call, "function")
	if str(call, "id") != "call_9" || str(fn, "name") != "mcp__srv__read" {
		t.Errorf("tool call = %#v", call)
	}
	if !strings.Contains(str(fn, "arguments"), `"path":"x.go"`) && !strings.Contains(str(fn, "arguments"), `"path": "x.go"`) {
		t.Errorf("arguments = %q", str(fn, "arguments"))
	}
	// Stop after a tool use finishes with tool_calls.
	out, err = TranslateStreamChunk(FormatKiro, FormatOpenAI, Body{"messageStopEvent": Body{}}, state)
	if err != nil || len(out) != 1 {
		t.Fatalf("stop out = %v, %v", out, err)
	}
	choice := arr(out[0], "choices")[0].(map[string]any)
	if str(choice, "finish_reason") != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", choice["finish_reason"])
	}
}

func TestKiroOpenAIChunkPassthroughRestoresNames(t *testing.T) {
	state := NewStreamState(FormatOpenAI)
	state.ToolNameMap = map[string]string{"read_file": "readFile"}
	chunk := Body{
		"object": "chat.completion.chunk",
		"choices": []any{Body{"index": 0, "delta": Body{
			"tool_calls": []any{Body{"index": 0, "function": Body{"name": "read_file", "arguments": ""}}},
		}, "finish_reason": nil}},
	}
	out, err := TranslateStreamChunk(FormatKiro, FormatOpenAI, chunk, state)
	if err != nil || len(out) != 1 {
		t.Fatalf("out = %v, %v", out, err)
	}
	delta := obj(arr(out[0], "choices")[0].(map[string]any), "delta")
	call := arr(delta, "tool_calls")[0].(map[string]any)
	if str(obj(call, "function"), "name") != "readFile" {
		t.Errorf("name not restored: %#v", call)
	}
}

// ---------- Kiro → Claude (direct route) ----------

func TestKiroToClaudeChunks(t *testing.T) {
	state := NewStreamState(FormatClaude)
	chunksIn := []Body{
		{"id": "chatcmpl-42", "model": "claude-sonnet-4-5", "choices": []any{Body{
			"index": 0, "delta": Body{"content": "Hi"}, "finish_reason": nil}}},
		{"id": "chatcmpl-42", "model": "claude-sonnet-4-5", "choices": []any{Body{
			"index":         0,
			"delta":         Body{},
			"finish_reason": "stop"}},
		},
	}
	var events []Body
	for _, c := range chunksIn {
		out, err := TranslateStreamChunk(FormatKiro, FormatClaude, c, state)
		if err != nil {
			t.Fatalf("chunk: %v", err)
		}
		events = append(events, out...)
	}
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, str(e, "type"))
	}
	want := []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("event types = %v, want %v", types, want)
	}
	start := obj(events[0], "message")
	if str(start, "id") != "42" || str(start, "model") != "claude-sonnet-4-5" {
		t.Errorf("message_start = %#v", events[0])
	}
	deltaEv := obj(events[len(events)-2], "delta")
	if str(deltaEv, "stop_reason") != "end_turn" {
		t.Errorf("message_delta = %#v", events[len(events)-2])
	}
}

func TestKiroToClaudeBodyFromEvents(t *testing.T) {
	body, err := TranslateResponse(FormatKiro, FormatClaude, Body{
		"model": "claude-sonnet-4-5",
		"events": []any{
			Body{"assistantResponseEvent": Body{"content": "Answer text"}},
			Body{"toolUseEvent": Body{"toolUseId": "call_1", "name": "get_weather", "input": Body{"city": "Hanoi"}}},
			Body{"usageEvent": Body{"inputTokens": 7.0, "outputTokens": 3.0}},
			Body{"messageStopEvent": Body{}},
		},
	})
	if err != nil {
		t.Fatalf("translate response: %v", err)
	}
	if str(body, "type") != "message" || str(body, "role") != "assistant" {
		t.Fatalf("body = %#v", body)
	}
	content := arr(body, "content")
	if len(content) != 2 {
		t.Fatalf("content = %#v", body["content"])
	}
	textBlock, _ := content[0].(map[string]any)
	if str(textBlock, "type") != "text" || str(textBlock, "text") != "Answer text" {
		t.Errorf("content[0] = %#v", textBlock)
	}
	toolBlock, _ := content[1].(map[string]any)
	if str(toolBlock, "type") != "tool_use" || str(toolBlock, "name") != "get_weather" || str(toolBlock, "id") != "call_1" {
		t.Errorf("content[1] = %#v", toolBlock)
	}
	if input := obj(toolBlock, "input"); input == nil || str(input, "city") != "Hanoi" {
		t.Errorf("tool input = %#v", toolBlock["input"])
	}
	if str(body, "stop_reason") != "tool_use" {
		t.Errorf("stop_reason = %v", body["stop_reason"])
	}
	usage := obj(body, "usage")
	if usage == nil || intVal(usage["input_tokens"]) != 7 || intVal(usage["output_tokens"]) != 3 {
		t.Errorf("usage = %#v", body["usage"])
	}
}

func TestKiroToOpenAIBodyFromEvents(t *testing.T) {
	body, err := TranslateResponse(FormatKiro, FormatOpenAI, Body{
		"events": []any{
			Body{"assistantResponseEvent": Body{"content": "Hello"}},
			Body{"reasoningContentEvent": Body{"text": "thinking..."}},
			Body{"messageStopEvent": Body{}},
		},
	})
	if err != nil {
		t.Fatalf("translate response: %v", err)
	}
	if str(body, "object") != "chat.completion" {
		t.Fatalf("body = %#v", body)
	}
	choice := arr(body, "choices")[0].(map[string]any)
	msg := obj(choice, "message")
	if str(msg, "content") != "Hello" || str(msg, "reasoning_content") != "thinking..." {
		t.Errorf("message = %#v", msg)
	}
	if str(choice, "finish_reason") != "stop" {
		t.Errorf("finish_reason = %v", choice["finish_reason"])
	}
}
