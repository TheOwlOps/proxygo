package translator

import (
	"sort"
	"strings"
)

// Port of translator/response/kiro-to-openai.js and
// translator/response/kiro-to-claude.js.
//
// The AWS EventStream binary decoding itself lives in the executor (JS
// KiroExecutor, Go internal/executors/eventstream.go) — the chunks this
// file receives are decoded event maps ({assistantResponseEvent: …},
// {toolUseEvent: …}, …), raw event maps carrying an "_eventType"/"event"
// discriminator, or — as in the JS — already-OpenAI-shaped
// chat.completion.chunk objects emitted by the executor, which pass
// through with the client's tool names restored.

// kiroRestoreToolName ports restoreToolName: names come back under the
// client's own names when the request translator sanitized them.
func kiroRestoreToolName(state *StreamState, name string) string {
	if state != nil && state.ToolNameMap != nil {
		if orig, ok := state.ToolNameMap[name]; ok {
			return orig
		}
	}
	return name
}

func kiroChunkMeta(state *StreamState) (id string, created int64, model string) {
	model = state.Model
	if model == "" {
		model = "kiro"
	}
	return state.ResponseID, state.Created, model
}

// kiroToOpenAIChunk ports kiroToOpenAIResponse.
func kiroToOpenAIChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		return nil, nil
	}

	// Already an OpenAI chunk (from the executor transform): return it
	// with the client's tool names restored.
	if str(chunk, "object") == "chat.completion.chunk" && chunk["choices"] != nil {
		if len(state.ToolNameMap) == 0 {
			return []Body{chunk}, nil
		}
		out := deepCopyBody(chunk)
		for _, rawChoice := range arr(out, "choices") {
			choice, _ := rawChoice.(map[string]any)
			if choice == nil {
				continue
			}
			delta := obj(choice, "delta")
			if delta == nil {
				continue
			}
			for _, rawTC := range arr(delta, "tool_calls") {
				tc, _ := rawTC.(map[string]any)
				if tc == nil {
					continue
				}
				if fn := obj(tc, "function"); fn != nil && str(fn, "name") != "" {
					fn["name"] = kiroRestoreToolName(state, str(fn, "name"))
				}
			}
		}
		return []Body{out}, nil
	}

	data := chunk
	if state.ResponseID == "" {
		state.ResponseID = "chatcmpl-" + itoa64(nowMillis())
		state.Created = nowUnix()
		state.ChunkIndex = 0
	}
	eventType := str(data, "_eventType")
	if eventType == "" {
		eventType = str(data, "event")
	}
	id, created, model := kiroChunkMeta(state)

	if eventType == "assistantResponseEvent" || data["assistantResponseEvent"] != nil {
		content := ""
		if inner := obj(data, "assistantResponseEvent"); inner != nil {
			content = str(inner, "content")
		}
		if content == "" {
			content = str(data, "content")
		}
		if content == "" {
			return nil, nil
		}
		delta := Body{"content": content}
		if state.ChunkIndex == 0 {
			delta = Body{"role": RoleAssistant, "content": content}
		}
		state.ChunkIndex++
		return []Body{buildChunk(id, created, model, delta, nil)}, nil
	}

	if eventType == "reasoningContentEvent" || data["reasoningContentEvent"] != nil {
		reasoning := obj(data, "reasoningContentEvent")
		if reasoning == nil {
			reasoning = data
		}
		content := str(reasoning, "text")
		if content == "" {
			content = str(reasoning, "content")
		}
		if content == "" {
			content = str(data, "content")
		}
		if content == "" {
			return nil, nil
		}
		delta := reasoningDelta(content)
		if state.ChunkIndex == 0 {
			delta = Body{"role": RoleAssistant, "reasoning_content": content}
		}
		state.ChunkIndex++
		return []Body{buildChunk(id, created, model, delta, nil)}, nil
	}

	if eventType == "toolUseEvent" || data["toolUseEvent"] != nil {
		state.HadToolUse = true
		toolUse := obj(data, "toolUseEvent")
		if toolUse == nil {
			toolUse = data
		}
		toolCallID := str(toolUse, "toolUseId")
		if toolCallID == "" {
			toolCallID = fallbackToolCallID(-1)
		}
		toolName := kiroRestoreToolName(state, str(toolUse, "name"))
		toolInput := toolUse["input"]
		if toolInput == nil {
			toolInput = Body{}
		}
		delta := Body{
			"tool_calls": []any{Body{
				"index": 0,
				"id":    toolCallID,
				"type":  OpenAIBlockFunction,
				"function": Body{
					"name":      toolName,
					"arguments": stringifyJSON(toolInput),
				},
			}},
		}
		if state.ChunkIndex == 0 {
			delta["role"] = RoleAssistant
		}
		state.ChunkIndex++
		return []Body{buildChunk(id, created, model, delta, nil)}, nil
	}

	if eventType == "messageStopEvent" || eventType == "done" || data["messageStopEvent"] != nil {
		reason := "stop"
		if state.HadToolUse {
			reason = "tool_use"
		}
		finishReason := toOpenAIFinish(reason, "kiro")
		state.FinishReason = finishReason
		out := buildChunk(id, created, model, Body{}, finishReason)
		if state.Usage != nil {
			out["usage"] = state.Usage
		}
		return []Body{out}, nil
	}

	if eventType == "usageEvent" || data["usageEvent"] != nil {
		raw := obj(data, "usageEvent")
		if raw == nil {
			raw = data
		}
		if usage := toOpenAIUsage(raw, "kiro"); usage != nil {
			state.Usage = usage
		}
		return nil, nil
	}

	return nil, nil
}

// kiroToOpenAIBody is the non-streaming counterpart: the JS assembles
// bodies by running chunks through its stream layer, so this aggregates
// a decoded event list (body["events"]) the same way. An already-OpenAI
// completion body passes through untouched.
func kiroToOpenAIBody(body Body) (Body, error) {
	if body["choices"] != nil {
		return body, nil
	}
	var events []any
	if ev, ok := body["events"].([]any); ok {
		events = ev
	} else if body["assistantResponseEvent"] != nil || body["toolUseEvent"] != nil ||
		body["reasoningContentEvent"] != nil || body["messageStopEvent"] != nil || body["usageEvent"] != nil {
		events = []any{body}
	} else {
		return body, nil
	}

	state := NewStreamState(FormatOpenAI)
	var content, reasoning strings.Builder
	var toolCalls []any
	finishReason := ""
	var usage Body
	for _, rawEvent := range events {
		event, _ := rawEvent.(map[string]any)
		if event == nil {
			continue
		}
		chunks, err := kiroToOpenAIChunk(event, state)
		if err != nil {
			return nil, err
		}
		for _, chunk := range chunks {
			choices := arr(chunk, "choices")
			if len(choices) == 0 {
				continue
			}
			choice, _ := choices[0].(map[string]any)
			if choice == nil {
				continue
			}
			if delta := obj(choice, "delta"); delta != nil {
				content.WriteString(str(delta, "content"))
				reasoning.WriteString(str(delta, "reasoning_content"))
				toolCalls = append(toolCalls, arr(delta, "tool_calls")...)
			}
			if fr := str(choice, "finish_reason"); fr != "" {
				finishReason = fr
			}
			if u := obj(chunk, "usage"); u != nil {
				usage = u
			}
		}
	}
	if finishReason == "" {
		finishReason = OpenAIFinishStop
	}
	message := Body{"role": RoleAssistant, "content": content.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolCalls) > 0 {
		var calls []any
		for _, rawTC := range toolCalls {
			tc, _ := rawTC.(map[string]any)
			if tc == nil {
				continue
			}
			calls = append(calls, Body{
				"id":   str(tc, "id"),
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":      str(obj(tc, "function"), "name"),
					"arguments": str(obj(tc, "function"), "arguments"),
				},
			})
		}
		if len(calls) > 0 {
			message["tool_calls"] = calls
		}
	}
	model := str(body, "model")
	if model == "" {
		model = "kiro"
	}
	out := Body{
		"id":     state.ResponseID,
		"object": "chat.completion",
		"model":  model,
		"choices": []any{Body{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
	}
	if state.Created != 0 {
		out["created"] = state.Created
	}
	if usage != nil {
		out["usage"] = usage
	} else if state.Usage != nil {
		out["usage"] = state.Usage
	}
	return out, nil
}

// ---------- Kiro → Claude (direct route; input chunks are OpenAI-shaped) --

// kiroToClaudeStopReason ports convertFinishReason in kiro-to-claude.js.
func kiroToClaudeStopReason(reason string) string {
	switch reason {
	case OpenAIFinishStop:
		return ClaudeStopEndTurn
	case OpenAIFinishLength:
		return ClaudeStopMaxTokens
	case OpenAIFinishToolCalls:
		return ClaudeStopToolUse
	default:
		return ClaudeStopEndTurn
	}
}

// kiroToClaudeChunk ports kiroToClaudeResponse: OpenAI chunks (emitted
// by the Kiro executor) → Claude SSE events.
func kiroToClaudeChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		return nil, nil
	}
	choices := arr(chunk, "choices")
	if len(choices) == 0 {
		return nil, nil
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		return nil, nil
	}
	data := chunk
	delta := obj(choice, "delta")
	if delta == nil {
		delta = Body{}
	}
	var results []Body

	// Track usage if present on the chunk.
	if usage := obj(data, "usage"); usage != nil {
		u := Body{
			"input_tokens":  intVal(usage["prompt_tokens"]),
			"output_tokens": intVal(usage["completion_tokens"]),
		}
		cacheRead, hasCacheRead := usage["cache_read_input_tokens"], false
		if _, ok := cacheRead.(float64); ok {
			hasCacheRead = true
		} else if details := obj(usage, "prompt_tokens_details"); details != nil {
			if v, ok := details["cached_tokens"].(float64); ok {
				cacheRead, hasCacheRead = v, true
			}
		}
		if hasCacheRead {
			u["cache_read_input_tokens"] = intVal(cacheRead)
		}
		cacheCreation, hasCacheCreation := usage["cache_creation_input_tokens"], false
		if _, ok := cacheCreation.(float64); ok {
			hasCacheCreation = true
		} else if details := obj(usage, "prompt_tokens_details"); details != nil {
			if v, ok := details["cache_creation_tokens"].(float64); ok {
				cacheCreation, hasCacheCreation = v, true
			}
		}
		if hasCacheCreation {
			u["cache_creation_input_tokens"] = intVal(cacheCreation)
		}
		state.Usage = u
	}

	// First chunk → message_start.
	if !state.MessageStartSent {
		state.MessageStartSent = true
		msgID := strings.Replace(str(data, "id"), "chatcmpl-", "", 1)
		if msgID == "" {
			msgID = "msg_" + itoa64(nowMillis())
		}
		state.MessageID = msgID
		state.Model = str(data, "model")
		if state.Model == "" {
			state.Model = "kiro"
		}
		state.NextBlockIndex = 0
		results = append(results, Body{
			"type": "message_start",
			"message": Body{
				"id":            state.MessageID,
				"type":          "message",
				"role":          RoleAssistant,
				"model":         state.Model,
				"content":       []any{},
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage":         Body{"input_tokens": 0, "output_tokens": 0},
			},
		})
	}

	// Reasoning / thinking content.
	reasoningContent := str(delta, "reasoning_content")
	if reasoningContent == "" {
		reasoningContent = str(delta, "reasoning")
	}
	if reasoningContent != "" {
		stopTextBlock(state, &results)
		if !state.ThinkingBlockStarted {
			state.ThinkingBlockIndex = state.NextBlockIndex
			state.NextBlockIndex++
			state.ThinkingBlockStarted = true
			results = append(results, Body{
				"type":          "content_block_start",
				"index":         state.ThinkingBlockIndex,
				"content_block": Body{"type": ClaudeBlockThinking, "thinking": ""},
			})
		}
		results = append(results, Body{
			"type":  "content_block_delta",
			"index": state.ThinkingBlockIndex,
			"delta": Body{"type": "thinking_delta", "thinking": reasoningContent},
		})
	}

	// Regular text content.
	if text := str(delta, "content"); text != "" {
		stopThinkingBlock(state, &results)
		if !state.TextBlockStarted {
			state.TextBlockIndex = state.NextBlockIndex
			state.NextBlockIndex++
			state.TextBlockStarted = true
			state.TextBlockClosed = false
			results = append(results, Body{
				"type":          "content_block_start",
				"index":         state.TextBlockIndex,
				"content_block": Body{"type": ClaudeBlockText, "text": ""},
			})
		}
		results = append(results, Body{
			"type":  "content_block_delta",
			"index": state.TextBlockIndex,
			"delta": Body{"type": "text_delta", "text": text},
		})
	}

	// Tool calls.
	for _, rawTC := range arr(delta, "tool_calls") {
		tc, _ := rawTC.(map[string]any)
		if tc == nil {
			continue
		}
		idx := intVal(tc["index"])
		if id := str(tc, "id"); id != "" {
			stopThinkingBlock(state, &results)
			stopTextBlock(state, &results)
			toolBlockIndex := state.NextBlockIndex
			state.NextBlockIndex++
			name := kiroRestoreToolName(state, str(obj(tc, "function"), "name"))
			state.ToolCalls[idx] = &ToolCallState{ID: id, Name: name, BlockIndex: toolBlockIndex}
			results = append(results, Body{
				"type":  "content_block_start",
				"index": toolBlockIndex,
				"content_block": Body{
					"type":  ClaudeBlockToolUse,
					"id":    id,
					"name":  name,
					"input": Body{},
				},
			})
		}
		if args := str(obj(tc, "function"), "arguments"); args != "" {
			if _, exists := state.ToolCalls[idx]; exists {
				state.ToolArgBuffers[idx] += args
			}
		}
	}

	// Finish.
	if finishReason := str(choice, "finish_reason"); finishReason != "" {
		stopThinkingBlock(state, &results)
		stopTextBlock(state, &results)

		indices := make([]int, 0, len(state.ToolCalls))
		for idx := range state.ToolCalls {
			indices = append(indices, idx)
		}
		sort.Ints(indices)
		for _, idx := range indices {
			toolInfo := state.ToolCalls[idx]
			if buffered := state.ToolArgBuffers[idx]; buffered != "" {
				results = append(results, Body{
					"type":  "content_block_delta",
					"index": toolInfo.BlockIndex,
					"delta": Body{"type": "input_json_delta", "partial_json": buffered},
				})
			}
			results = append(results, Body{
				"type":  "content_block_stop",
				"index": toolInfo.BlockIndex,
			})
		}

		state.FinishReason = finishReason
		finalUsage := state.Usage
		if finalUsage == nil {
			finalUsage = Body{"input_tokens": 0, "output_tokens": 0}
		}
		results = append(results, Body{
			"type":  "message_delta",
			"delta": Body{"stop_reason": kiroToClaudeStopReason(finishReason)},
			"usage": finalUsage,
		})
		results = append(results, Body{"type": "message_stop"})
	}

	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// kiroToClaudeBody ports kiroToClaudeNonStreaming: an aggregated
// OpenAI-shaped completion → a Claude message body.
func kiroToClaudeBody(body Body) (Body, error) {
	data := body
	if data["choices"] == nil {
		converted, err := kiroToOpenAIBody(body)
		if err != nil {
			return nil, err
		}
		data = converted
	}
	nameMap := toStringMap(data["_toolNameMap"])

	var choice Body
	if choices := arr(data, "choices"); len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	var message Body
	if choice != nil {
		message = obj(choice, "message")
	}
	if message == nil {
		message = Body{}
	}

	content := []any{}
	if text := str(message, "content"); text != "" {
		content = append(content, Body{"type": ClaudeBlockText, "text": text})
	}
	for _, rawTC := range arr(message, "tool_calls") {
		tc, _ := rawTC.(map[string]any)
		if tc == nil {
			continue
		}
		fn := obj(tc, "function")
		var input any = Body{}
		if fn != nil {
			switch args := fn["arguments"].(type) {
			case string:
				if parsed, ok := safeParseJSON(args, nil).(map[string]any); ok {
					input = parsed
				}
			case map[string]any:
				input = args
			}
		}
		id := str(tc, "id")
		if id == "" {
			id = "toolu_" + itoa64(nowMillis())
		}
		name := ""
		if fn != nil {
			name = str(fn, "name")
		}
		if orig, ok := nameMap[name]; ok {
			name = orig
		}
		content = append(content, Body{
			"type":  ClaudeBlockToolUse,
			"id":    id,
			"name":  name,
			"input": input,
		})
	}

	usage := obj(data, "usage")
	outUsage := Body{
		"input_tokens":  intVal(getAny(usage, "prompt_tokens")),
		"output_tokens": intVal(getAny(usage, "completion_tokens")),
	}
	if usage != nil {
		if v, ok := usage["cache_read_input_tokens"].(float64); ok {
			outUsage["cache_read_input_tokens"] = int(v)
		} else if details := obj(usage, "prompt_tokens_details"); details != nil {
			if v, ok := details["cached_tokens"].(float64); ok {
				outUsage["cache_read_input_tokens"] = int(v)
			}
		}
		if v, ok := usage["cache_creation_input_tokens"].(float64); ok {
			outUsage["cache_creation_input_tokens"] = int(v)
		} else if details := obj(usage, "prompt_tokens_details"); details != nil {
			if v, ok := details["cache_creation_tokens"].(float64); ok {
				outUsage["cache_creation_input_tokens"] = int(v)
			}
		}
	}

	finishReason := OpenAIFinishStop
	if choice != nil && str(choice, "finish_reason") != "" {
		finishReason = str(choice, "finish_reason")
	}
	model := str(data, "model")
	if model == "" {
		model = "kiro"
	}
	return Body{
		"id":          "msg_" + itoa64(nowMillis()),
		"type":        "message",
		"role":        RoleAssistant,
		"content":     content,
		"model":       model,
		"stop_reason": kiroToClaudeStopReason(finishReason),
		"usage":       outUsage,
	}, nil
}

func getAny(m Body, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

func toStringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}
