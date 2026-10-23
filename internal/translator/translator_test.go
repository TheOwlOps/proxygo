package translator

import (
	"reflect"
	"testing"
)

// ---------- request: claude -> openai ----------

func TestClaudeToOpenAIRequest(t *testing.T) {
	body := Body{
		"model":      "claude-sonnet-4-5",
		"max_tokens": 1024,
		"system":     "You are helpful.",
		"messages": []any{
			Body{"role": "user", "content": "Hi"},
			Body{"role": "assistant", "content": []any{
				Body{"type": "text", "text": "Let me check."},
				Body{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": Body{"city": "Hanoi"}},
			}},
			Body{"role": "user", "content": []any{
				Body{"type": "tool_result", "tool_use_id": "toolu_1", "content": "sunny"},
			}},
		},
		"tools": []any{
			Body{"name": "get_weather", "description": "Get weather",
				"input_schema": Body{"type": "object", "properties": Body{"city": Body{"type": "string"}}}},
		},
		"tool_choice": Body{"type": "any"},
	}

	out, err := TranslateRequest(FormatClaude, FormatOpenAI, body)
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	// tools present -> adjustMaxTokens raises 1024 to the 32000 floor.
	if got := out["max_tokens"]; got != 32000 {
		t.Errorf("max_tokens = %v, want 32000", got)
	}
	wantMessages := []any{
		Body{"role": "system", "content": "You are helpful."},
		Body{"role": "user", "content": "Hi"},
		Body{"role": "assistant", "content": "Let me check.", "tool_calls": []any{
			Body{"id": "toolu_1", "type": "function", "function": Body{
				"name": "get_weather", "arguments": `{"city":"Hanoi"}`,
			}},
		}},
		Body{"role": "tool", "tool_call_id": "toolu_1", "content": "sunny"},
	}
	if !reflect.DeepEqual(out["messages"], wantMessages) {
		t.Errorf("messages mismatch:\n got: %#v\nwant: %#v", out["messages"], wantMessages)
	}
	wantTools := []any{
		Body{"type": "function", "function": Body{
			"name": "get_weather", "description": "Get weather",
			"parameters": Body{"type": "object", "properties": Body{"city": Body{"type": "string"}}},
		}},
	}
	if !reflect.DeepEqual(out["tools"], wantTools) {
		t.Errorf("tools mismatch:\n got: %#v\nwant: %#v", out["tools"], wantTools)
	}
	if got := out["tool_choice"]; got != "required" {
		t.Errorf("tool_choice = %v, want required", got)
	}
}

// ---------- request: openai -> claude ----------

func TestOpenAIToClaudeRequest(t *testing.T) {
	body := Body{
		"model":      "claude-sonnet-4-5",
		"max_tokens": 2048,
		"messages": []any{
			Body{"role": "system", "content": "Be terse."},
			Body{"role": "user", "content": "Weather in Hanoi?"},
			Body{"role": "assistant", "content": nil, "tool_calls": []any{
				Body{"id": "call_1", "type": "function", "function": Body{
					"name": "get_weather", "arguments": `{"city":"Hanoi"}`,
				}},
			}},
			Body{"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
			Body{"role": "assistant", "content": "It is sunny."},
		},
		"tools": []any{
			Body{"type": "function", "function": Body{
				"name": "get_weather", "description": "Get weather",
				"parameters": Body{"type": "object", "properties": Body{"city": Body{"type": "string"}}},
			}},
		},
	}

	out, err := TranslateRequest(FormatOpenAI, FormatClaude, body)
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	wantSystem := []any{
		Body{"type": "text", "text": ClaudeSystemPrompt},
		Body{"type": "text", "text": "Be terse.", "cache_control": Body{"type": "ephemeral", "ttl": "1h"}},
	}
	if !reflect.DeepEqual(out["system"], wantSystem) {
		t.Errorf("system mismatch:\n got: %#v\nwant: %#v", out["system"], wantSystem)
	}
	wantMessages := []any{
		Body{"role": "user", "content": []any{
			Body{"type": "text", "text": "Weather in Hanoi?"},
		}},
		Body{"role": "assistant", "content": []any{
			Body{"type": "tool_use", "id": "call_1", "name": "get_weather", "input": Body{"city": "Hanoi"}},
		}},
		Body{"role": "user", "content": []any{
			Body{"type": "tool_result", "tool_use_id": "call_1", "content": "sunny"},
		}},
		Body{"role": "assistant", "content": []any{
			Body{"type": "text", "text": "It is sunny.", "cache_control": Body{"type": "ephemeral"}},
		}},
	}
	if !reflect.DeepEqual(out["messages"], wantMessages) {
		t.Errorf("messages mismatch:\n got: %#v\nwant: %#v", out["messages"], wantMessages)
	}
	wantTools := []any{
		Body{"name": "get_weather", "description": "Get weather",
			"input_schema":  Body{"type": "object", "properties": Body{"city": Body{"type": "string"}}},
			"cache_control": Body{"type": "ephemeral", "ttl": "1h"}},
	}
	if !reflect.DeepEqual(out["tools"], wantTools) {
		t.Errorf("tools mismatch:\n got: %#v\nwant: %#v", out["tools"], wantTools)
	}
}

// ---------- request: openai -> gemini ----------

func TestOpenAIToGeminiRequest(t *testing.T) {
	body := Body{
		"model":       "gemini-2.5-flash",
		"temperature": 0.7,
		"max_tokens":  512,
		"messages": []any{
			Body{"role": "system", "content": "Be terse."},
			Body{"role": "user", "content": "Weather?"},
			Body{"role": "assistant", "content": nil, "tool_calls": []any{
				Body{"id": "call_1", "type": "function", "function": Body{
					"name": "get_weather", "arguments": `{"city":"Hanoi"}`,
				}},
			}},
			Body{"role": "tool", "tool_call_id": "call_1", "content": `{"temp":30}`},
			Body{"role": "user", "content": "Thanks"},
		},
		"tools": []any{
			Body{"type": "function", "function": Body{
				"name": "get_weather", "description": "Get weather",
				"parameters": Body{
					"type": "object", "title": "Weather",
					"properties":           Body{"city": Body{"type": "string"}},
					"additionalProperties": false,
				},
			}},
		},
	}

	out, err := TranslateRequest(FormatOpenAI, FormatGemini, body)
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	wantInstruction := Body{"role": "user", "parts": []any{Body{"text": "Be terse."}}}
	if !reflect.DeepEqual(out["systemInstruction"], wantInstruction) {
		t.Errorf("systemInstruction mismatch:\n got: %#v\nwant: %#v", out["systemInstruction"], wantInstruction)
	}
	wantContents := []any{
		Body{"role": "user", "parts": []any{Body{"text": "Weather?"}}},
		Body{"role": "model", "parts": []any{
			Body{
				"functionCall":     Body{"id": "call_1", "name": "get_weather", "args": Body{"city": "Hanoi"}},
				"thoughtSignature": DEFAULT_THINKING_AG_SIGNATURE,
			},
		}},
		// normalizeGeminiContents merges the adjacent user turns
		// (functionResponse + trailing user text) into one content.
		Body{"role": "user", "parts": []any{
			Body{"functionResponse": Body{
				"id": "call_1", "name": "get_weather",
				"response": Body{"result": Body{"temp": 30}},
			}},
			Body{"text": "Thanks"},
		}},
	}
	if !reflect.DeepEqual(out["contents"], wantContents) {
		t.Errorf("contents mismatch:\n got: %#v\nwant: %#v", out["contents"], wantContents)
	}
	genConfig := obj(out, "generationConfig")
	if genConfig["temperature"] != 0.7 || genConfig["maxOutputTokens"] != 512 {
		t.Errorf("generationConfig = %#v", genConfig)
	}
	tools := arr(out, "tools")
	if len(tools) != 1 {
		t.Fatalf("tools = %#v", out["tools"])
	}
	decl := arr(toBody(t, tools[0]), "functionDeclarations")
	if len(decl) != 1 {
		t.Fatalf("functionDeclarations = %#v", tools[0])
	}
	params := obj(toBody(t, decl[0]), "parameters")
	if _, bad := params["additionalProperties"]; bad {
		t.Errorf("schema cleaning left additionalProperties: %#v", params)
	}
	if _, bad := params["title"]; bad {
		t.Errorf("schema cleaning left title: %#v", params)
	}
}

func toBody(t *testing.T, v any) Body {
	t.Helper()
	b, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("not a Body: %#v", v)
	}
	return b
}

// ---------- request: gemini -> openai ----------

func TestGeminiToOpenAIRequest(t *testing.T) {
	body := Body{
		"model":             "gemini-2.5-flash",
		"generationConfig":  Body{"maxOutputTokens": 256, "temperature": 0.2, "topP": 0.9},
		"systemInstruction": Body{"parts": []any{Body{"text": "Be terse."}}},
		"contents": []any{
			Body{"role": "user", "parts": []any{Body{"text": "Weather?"}}},
			Body{"role": "model", "parts": []any{
				Body{"functionCall": Body{"name": "get_weather", "args": Body{"city": "Hanoi"}}},
			}},
			Body{"role": "user", "parts": []any{
				Body{"functionResponse": Body{"name": "get_weather", "response": Body{"result": "sunny"}}},
			}},
		},
		"tools": []any{
			Body{"functionDeclarations": []any{
				Body{"name": "get_weather", "description": "Get weather",
					"parameters": Body{"type": "object", "properties": Body{}}},
			}},
		},
	}

	out, err := TranslateRequest(FormatGemini, FormatOpenAI, body)
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	wantMessages := []any{
		Body{"role": "system", "content": "Be terse."},
		Body{"role": "user", "content": "Weather?"},
		Body{"role": "assistant", "tool_calls": []any{
			Body{"id": "call_get_weather", "type": "function", "function": Body{
				"name": "get_weather", "arguments": `{"city":"Hanoi"}`,
			}},
		}},
		Body{"role": "tool", "tool_call_id": "call_get_weather", "content": `"sunny"`},
	}
	if !reflect.DeepEqual(out["messages"], wantMessages) {
		t.Errorf("messages mismatch:\n got: %#v\nwant: %#v", out["messages"], wantMessages)
	}
	// JS adjustMaxTokens raises max_tokens to the 32000 floor whenever
	// tools are present, so 256 becomes 32000 — ported faithfully.
	if got := out["max_tokens"]; got != 32000 {
		t.Errorf("max_tokens = %v, want 32000 (JS tool floor)", got)
	}
	if got := out["top_p"]; got != 0.9 {
		t.Errorf("top_p = %v, want 0.9", got)
	}
}

// ---------- stream: claude -> openai ----------

func TestClaudeToOpenAIStream(t *testing.T) {
	state := NewStreamState(FormatOpenAI)
	chunks := []Body{
		{"type": "message_start", "message": Body{
			"id": "msg_123", "model": "claude-sonnet-4-5",
			"usage": Body{"input_tokens": 10, "output_tokens": 0, "cache_read_input_tokens": 5},
		}},
		{"type": "content_block_start", "index": 0, "content_block": Body{"type": "text"}},
		{"type": "content_block_delta", "index": 0, "delta": Body{"type": "text_delta", "text": "Hello"}},
		{"type": "content_block_start", "index": 1, "content_block": Body{"type": "tool_use", "id": "toolu_1", "name": "get_weather"}},
		{"type": "content_block_delta", "index": 1, "delta": Body{"type": "input_json_delta", "partial_json": `{"city":`}},
		{"type": "content_block_delta", "index": 1, "delta": Body{"type": "input_json_delta", "partial_json": `"Hanoi"}`}},
		{"type": "message_delta", "delta": Body{"stop_reason": "tool_use"}, "usage": Body{"output_tokens": 20}},
		{"type": "message_stop"},
	}
	var out []Body
	for _, c := range chunks {
		res, err := TranslateStreamChunk(FormatClaude, FormatOpenAI, c, state)
		if err != nil {
			t.Fatalf("TranslateStreamChunk: %v", err)
		}
		out = append(out, res...)
	}
	if len(out) != 6 {
		t.Fatalf("got %d chunks, want 6: %#v", len(out), out)
	}
	deltaOf := func(c Body) Body {
		choices := arr(c, "choices")
		return obj(toBody(t, choices[0]), "delta")
	}
	if d := deltaOf(out[0]); d["role"] != "assistant" {
		t.Errorf("chunk0 delta = %#v", d)
	}
	if d := deltaOf(out[1]); d["content"] != "Hello" {
		t.Errorf("chunk1 delta = %#v", d)
	}
	tc := arr(deltaOf(out[2]), "tool_calls")
	call := toBody(t, tc[0])
	if call["id"] != "toolu_1" || obj(call, "function")["name"] != "get_weather" {
		t.Errorf("tool call start = %#v", call)
	}
	final := out[5]
	choices := arr(final, "choices")
	if fr := toBody(t, choices[0])["finish_reason"]; fr != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", fr)
	}
	usage := obj(final, "usage")
	if usage["prompt_tokens"] != 15 || usage["completion_tokens"] != 20 || usage["total_tokens"] != 35 {
		t.Errorf("usage = %#v, want 15/20/35", usage)
	}
	if details := obj(usage, "prompt_tokens_details"); details["cached_tokens"] != 5 {
		t.Errorf("cached_tokens = %#v", details)
	}
}

// ---------- stream: openai -> claude ----------

func TestOpenAIToClaudeStream(t *testing.T) {
	state := NewStreamState(FormatClaude)
	chunk := func(delta Body, finish any, usage Body) Body {
		c := Body{
			"id": "chatcmpl-abc12345", "model": "gpt-x",
			"choices": []any{Body{"index": 0, "delta": delta, "finish_reason": finish}},
		}
		if usage != nil {
			c["usage"] = usage
		}
		return c
	}
	inputs := []Body{
		chunk(Body{"role": "assistant", "content": "Hi"}, nil, nil),
		chunk(Body{"tool_calls": []any{Body{
			"index": 0, "id": "call_1", "type": "function",
			"function": Body{"name": "get_weather", "arguments": `{"city":`},
		}}}, nil, nil),
		chunk(Body{"tool_calls": []any{Body{
			"index": 0, "function": Body{"arguments": `"Hanoi"}`},
		}}}, nil, nil),
		chunk(Body{}, "tool_calls", Body{"prompt_tokens": 15, "completion_tokens": 20}),
	}
	var out []Body
	for _, c := range inputs {
		res, err := TranslateStreamChunk(FormatOpenAI, FormatClaude, c, state)
		if err != nil {
			t.Fatalf("TranslateStreamChunk: %v", err)
		}
		out = append(out, res...)
	}
	var types []string
	for _, e := range out {
		types = append(types, str(e, "type"))
	}
	wantTypes := []string{
		"message_start",
		"content_block_start", "content_block_delta", // text block
		"content_block_stop",  // text closed for tool block
		"content_block_start", // tool_use block
		"content_block_delta", // buffered args at finish
		"content_block_stop",  // tool block stop
		"message_delta", "message_stop",
	}
	if !reflect.DeepEqual(types, wantTypes) {
		t.Fatalf("event types = %v, want %v", types, wantTypes)
	}
	argsDelta := obj(out[5], "delta")
	if argsDelta["partial_json"] != `{"city":"Hanoi"}` {
		t.Errorf("partial_json = %v", argsDelta["partial_json"])
	}
	md := out[7]
	if got := obj(md, "delta")["stop_reason"]; got != "tool_use" {
		t.Errorf("stop_reason = %v", got)
	}
	if u := obj(md, "usage"); u["input_tokens"] != 15 || u["output_tokens"] != 20 {
		t.Errorf("usage = %#v", u)
	}
}

// ---------- stream: gemini -> openai ----------

func TestGeminiToOpenAIStream(t *testing.T) {
	state := NewStreamState(FormatOpenAI)
	chunk := Body{
		"responseId": "r1", "modelVersion": "gemini-2.5-flash",
		"candidates": []any{Body{
			"content": Body{"role": "model", "parts": []any{
				Body{"text": "Hel"},
				Body{"functionCall": Body{"name": "get_weather", "args": Body{"city": "Hanoi"}}},
			}},
			"finishReason": "STOP",
		}},
		"usageMetadata": Body{"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
	}
	out, err := TranslateStreamChunk(FormatGemini, FormatOpenAI, chunk, state)
	if err != nil {
		t.Fatalf("TranslateStreamChunk: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("got %d chunks, want 4: %#v", len(out), out)
	}
	final := out[3]
	choices := arr(final, "choices")
	if fr := toBody(t, choices[0])["finish_reason"]; fr != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls (gemini STOP + tool call)", fr)
	}
	usage := obj(final, "usage")
	if usage["prompt_tokens"] != 10 || usage["completion_tokens"] != 5 || usage["total_tokens"] != 15 {
		t.Errorf("usage = %#v", usage)
	}
}

// ---------- requests: openai <-> openai-responses ----------

func TestOpenAIToResponsesRequest(t *testing.T) {
	body := Body{
		"model": "gpt-5", "max_tokens": 100, "reasoning_effort": "high",
		"messages": []any{
			Body{"role": "system", "content": "Instr"},
			Body{"role": "user", "content": "Hi"},
			Body{"role": "assistant", "content": "Working", "tool_calls": []any{
				Body{"id": "call_1", "type": "function", "function": Body{
					"name": "get_weather", "arguments": `{"city":"Hanoi"}`,
				}},
			}},
			Body{"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
		},
	}
	out, err := TranslateRequest(FormatOpenAI, FormatOpenAIResponses, body)
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	if out["instructions"] != "Instr" || out["max_output_tokens"] != 100 {
		t.Errorf("instructions/max = %v / %v", out["instructions"], out["max_output_tokens"])
	}
	if r := obj(out, "reasoning"); r["effort"] != "high" || r["summary"] != "auto" {
		t.Errorf("reasoning = %#v", r)
	}
	wantInput := []any{
		Body{"type": "message", "role": "user", "content": []any{
			Body{"type": "input_text", "text": "Hi"},
		}},
		Body{"type": "message", "role": "assistant", "content": []any{
			Body{"type": "output_text", "text": "Working"},
		}},
		Body{"type": "function_call", "call_id": "call_1", "name": "get_weather", "arguments": `{"city":"Hanoi"}`},
		Body{"type": "function_call_output", "call_id": "call_1", "output": "sunny"},
	}
	if !reflect.DeepEqual(out["input"], wantInput) {
		t.Errorf("input mismatch:\n got: %#v\nwant: %#v", out["input"], wantInput)
	}
}

func TestResponsesToOpenAIRequest(t *testing.T) {
	body := Body{
		"model":             "gpt-5",
		"instructions":      "Instr",
		"max_output_tokens": 50,
		"reasoning":         Body{"effort": "low"},
		"input": []any{
			Body{"type": "message", "role": "user", "content": []any{
				Body{"type": "input_text", "text": "Hi"},
			}},
			Body{"type": "function_call", "call_id": "call_1", "name": "get_weather", "arguments": `{"city":"Hanoi"}`},
			Body{"type": "function_call_output", "call_id": "call_1", "output": "sunny"},
		},
	}
	out, err := TranslateRequest(FormatOpenAIResponses, FormatOpenAI, body)
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	if out["max_tokens"] != 50 || out["reasoning_effort"] != "low" {
		t.Errorf("max_tokens/reasoning_effort = %v / %v", out["max_tokens"], out["reasoning_effort"])
	}
	wantMessages := []any{
		Body{"role": "system", "content": "Instr"},
		Body{"role": "user", "content": []any{Body{"type": "text", "text": "Hi"}}},
		Body{"role": "assistant", "content": nil, "tool_calls": []any{
			Body{"id": "call_1", "type": "function", "function": Body{
				"name": "get_weather", "arguments": `{"city":"Hanoi"}`,
			}},
		}},
		Body{"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
	}
	if !reflect.DeepEqual(out["messages"], wantMessages) {
		t.Errorf("messages mismatch:\n got: %#v\nwant: %#v", out["messages"], wantMessages)
	}
	if _, leaked := out["input"]; leaked {
		t.Errorf("responses-only field input leaked: %#v", out["input"])
	}
}

// ---------- stream: openai -> openai-responses ----------

func eventTypes(events []Body) []string {
	var types []string
	for _, e := range events {
		types = append(types, str(e, "event"))
	}
	return types
}

func TestOpenAIToResponsesStream(t *testing.T) {
	state := NewStreamState(FormatOpenAIResponses)
	inputs := []Body{
		{"id": "chatcmpl-xyz", "model": "gpt-5", "choices": []any{Body{
			"index": 0, "delta": Body{"role": "assistant", "content": "Hel"}, "finish_reason": nil,
		}}},
		{"id": "chatcmpl-xyz", "model": "gpt-5", "choices": []any{Body{
			"index": 0, "delta": Body{"content": "lo"}, "finish_reason": "stop",
		}}, "usage": Body{"prompt_tokens": 10, "completion_tokens": 5}},
	}
	var out []Body
	for _, c := range inputs {
		res, err := TranslateStreamChunk(FormatOpenAI, FormatOpenAIResponses, c, state)
		if err != nil {
			t.Fatalf("TranslateStreamChunk: %v", err)
		}
		out = append(out, res...)
	}
	wantTypes := []string{
		"response.created", "response.in_progress",
		"response.output_item.added", "response.content_part.added",
		"response.output_text.delta", "response.output_text.delta",
		"response.output_text.done", "response.content_part.done",
		"response.output_item.done", "response.completed",
	}
	if got := eventTypes(out); !reflect.DeepEqual(got, wantTypes) {
		t.Fatalf("events = %v, want %v", got, wantTypes)
	}
	completed := obj(out[len(out)-1], "data")
	response := obj(completed, "response")
	output := arr(response, "output")
	if len(output) != 1 {
		t.Fatalf("completed output = %#v", response["output"])
	}
	item := toBody(t, output[0])
	content := arr(item, "content")
	if got := toBody(t, content[0])["text"]; got != "Hello" {
		t.Errorf("completed text = %v, want Hello", got)
	}
	if u := obj(response, "usage"); u["input_tokens"] != 10 || u["output_tokens"] != 5 {
		t.Errorf("completed usage = %#v", u)
	}
}

func TestOpenAIToResponsesStreamDeferredCompletion(t *testing.T) {
	// Finish chunk without usage: completion must wait for the nil flush.
	state := NewStreamState(FormatOpenAIResponses)
	res, err := TranslateStreamChunk(FormatOpenAI, FormatOpenAIResponses, Body{
		"id": "chatcmpl-xyz", "model": "gpt-5", "choices": []any{Body{
			"index": 0, "delta": Body{"content": "Hi"}, "finish_reason": "stop",
		}},
	}, state)
	if err != nil {
		t.Fatalf("TranslateStreamChunk: %v", err)
	}
	for _, ty := range eventTypes(res) {
		if ty == "response.completed" {
			t.Fatalf("completion emitted before usage/flush: %v", eventTypes(res))
		}
	}
	flush, err := TranslateStreamChunk(FormatOpenAI, FormatOpenAIResponses, nil, state)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := eventTypes(flush); len(got) == 0 || got[len(got)-1] != "response.completed" {
		t.Errorf("flush events = %v, want trailing response.completed", got)
	}
}

// ---------- stream: openai-responses -> openai ----------

func TestResponsesToOpenAIStream(t *testing.T) {
	state := NewStreamState(FormatOpenAI)
	state.Model = "gpt-5"
	inputs := []Body{
		{"type": "response.output_text.delta", "delta": "Hello"},
		{"type": "response.output_item.added", "item": Body{
			"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "get_weather",
		}},
		{"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": `{"city":"Hanoi"}`},
		{"type": "response.completed", "response": Body{
			"usage": Body{"input_tokens": 10, "output_tokens": 5},
		}},
	}
	var out []Body
	for _, c := range inputs {
		res, err := TranslateStreamChunk(FormatOpenAIResponses, FormatOpenAI, c, state)
		if err != nil {
			t.Fatalf("TranslateStreamChunk: %v", err)
		}
		out = append(out, res...)
	}
	if len(out) != 4 {
		t.Fatalf("got %d chunks, want 4: %#v", len(out), out)
	}
	final := out[3]
	choices := arr(final, "choices")
	if fr := toBody(t, choices[0])["finish_reason"]; fr != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", fr)
	}
	if u := obj(final, "usage"); u["prompt_tokens"] != 10 || u["completion_tokens"] != 5 {
		t.Errorf("usage = %#v", u)
	}
}

// ---------- non-streaming bodies ----------

func TestResponseBodiesRoundTrip(t *testing.T) {
	claudeBody := Body{
		"id": "msg_1", "model": "claude-sonnet-4-5",
		"content": []any{
			Body{"type": "text", "text": "Sunny in Hanoi."},
			Body{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": Body{"city": "Hanoi"}},
		},
		"stop_reason": "tool_use",
		"usage":       Body{"input_tokens": 10, "output_tokens": 5},
	}
	openaiBody, err := TranslateResponse(FormatClaude, FormatOpenAI, claudeBody)
	if err != nil {
		t.Fatalf("TranslateResponse claude->openai: %v", err)
	}
	choice := toBody(t, arr(openaiBody, "choices")[0])
	if choice["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v", choice["finish_reason"])
	}
	msg := obj(choice, "message")
	if msg["content"] != "Sunny in Hanoi." {
		t.Errorf("content = %v", msg["content"])
	}

	back, err := TranslateResponse(FormatOpenAI, FormatClaude, openaiBody)
	if err != nil {
		t.Fatalf("TranslateResponse openai->claude: %v", err)
	}
	if back["stop_reason"] != "tool_use" {
		t.Errorf("round-trip stop_reason = %v", back["stop_reason"])
	}
	content := arr(back, "content")
	if len(content) != 2 {
		t.Fatalf("round-trip content = %#v", back["content"])
	}

	// openai -> responses -> openai
	respBody, err := TranslateResponse(FormatOpenAI, FormatOpenAIResponses, openaiBody)
	if err != nil {
		t.Fatalf("TranslateResponse openai->responses: %v", err)
	}
	if respBody["object"] != "response" || respBody["status"] != "completed" {
		t.Errorf("responses body = %#v", respBody)
	}
	chatBack, err := TranslateResponse(FormatOpenAIResponses, FormatOpenAI, respBody)
	if err != nil {
		t.Fatalf("TranslateResponse responses->openai: %v", err)
	}
	cbChoice := toBody(t, arr(chatBack, "choices")[0])
	if cbChoice["finish_reason"] != "tool_calls" {
		t.Errorf("responses round-trip finish_reason = %v", cbChoice["finish_reason"])
	}

	// gemini body -> openai
	geminiBody := Body{
		"responseId": "r1", "modelVersion": "gemini-2.5-flash",
		"candidates": []any{Body{
			"content":      Body{"role": "model", "parts": []any{Body{"text": "Hello"}}},
			"finishReason": "STOP",
		}},
		"usageMetadata": Body{"promptTokenCount": 3, "candidatesTokenCount": 1, "totalTokenCount": 4},
	}
	fromGemini, err := TranslateResponse(FormatGemini, FormatOpenAI, geminiBody)
	if err != nil {
		t.Fatalf("TranslateResponse gemini->openai: %v", err)
	}
	gChoice := toBody(t, arr(fromGemini, "choices")[0])
	if obj(gChoice, "message")["content"] != "Hello" {
		t.Errorf("gemini content = %#v", gChoice["message"])
	}
	if u := obj(fromGemini, "usage"); u["total_tokens"] != 4 {
		t.Errorf("gemini usage = %#v", u)
	}
}

// ---------- stubs & passthrough ----------

func TestStubs(t *testing.T) {
	// openai->cursor request was fully ported in Phase 2 (Team L).
	cbody, err := TranslateRequest(FormatOpenAI, FormatCursor, Body{
		"model":    "cursor",
		"messages": []any{Body{"role": "user", "content": "hi"}},
	})
	if err != nil || cbody == nil {
		t.Errorf("openai->cursor request = %v, %v; want ported body", cbody, err)
	}
	// cursor -> openai stream is a ported passthrough.
	chunk := Body{"object": "chat.completion.chunk", "choices": []any{}}
	out, err := TranslateStreamChunk(FormatCursor, FormatOpenAI, chunk, NewStreamState(FormatOpenAI))
	if err != nil || len(out) != 1 {
		t.Errorf("cursor passthrough = %v, %v", out, err)
	}
}

// ---------- misc contract surface ----------

func TestDetectFormatByEndpoint(t *testing.T) {
	if f, ok := DetectFormatByEndpoint("/v1/messages", Body{}); !ok || f != FormatClaude {
		t.Errorf("/v1/messages -> %q, %v", f, ok)
	}
	if f, ok := DetectFormatByEndpoint("/v1/responses", Body{}); !ok || f != FormatOpenAIResponses {
		t.Errorf("/v1/responses -> %q, %v", f, ok)
	}
	if _, ok := DetectFormatByEndpoint("/v1/chat/completions", Body{}); ok {
		t.Errorf("/v1/chat/completions without input[] should not detect")
	}
	if !NeedsTranslation(FormatClaude, FormatOpenAI) || NeedsTranslation(FormatOpenAI, FormatOpenAI) {
		t.Errorf("NeedsTranslation wrong")
	}
}

func TestFinishReasonMappings(t *testing.T) {
	cases := []struct{ reason, format, want string }{
		{"end_turn", "claude", "stop"},
		{"max_tokens", "claude", "length"},
		{"tool_use", "claude", "tool_calls"},
		{"refusal", "claude", "content_filter"},
		{"SAFETY", "gemini", "content_filter"},
		{"MAX_TOKENS", "gemini", "length"},
	}
	for _, c := range cases {
		if got := toOpenAIFinish(c.reason, c.format); got != c.want {
			t.Errorf("toOpenAIFinish(%q,%q) = %q, want %q", c.reason, c.format, got, c.want)
		}
	}
	if got := fromOpenAIFinish("content_filter", "claude"); got != "refusal" {
		t.Errorf("fromOpenAIFinish(content_filter, claude) = %q", got)
	}
}
