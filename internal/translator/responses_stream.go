package translator

import (
	"sort"
	"strings"
)

// ---------- stream: openai -> openai-responses ----------
// Port of response/openai-responses.js openaiToOpenAIResponsesResponse.
// Each output Body is one Responses event envelope: {"event": ..., "data":
// {...event payload including sequence_number...}}, exactly as the JS
// returns {event, data} objects to its SSE writer.

type responsesEmitter struct {
	state  *StreamState
	events []Body
}

func (e *responsesEmitter) emit(eventType string, data Body) {
	e.state.Seq++
	data["sequence_number"] = e.state.Seq
	cp := Body{"type": eventType}
	for k, v := range data {
		cp[k] = v
	}
	e.events = append(e.events, Body{"event": eventType, "data": cp})
}

// toResponsesUsage ports toResponsesUsage from response/openai-responses.js.
func toResponsesUsage(usage Body) Body {
	if usage == nil {
		return nil
	}
	findInt := func(keys ...string) (int64, bool) {
		for _, k := range keys {
			if v, ok := intNum(usage[k]); ok {
				return v, true
			}
		}
		return 0, false
	}
	inputTokens, okIn := findInt("input_tokens", "prompt_tokens")
	outputTokens, okOut := findInt("output_tokens", "completion_tokens")
	if !okIn || !okOut || inputTokens+outputTokens <= 0 {
		return nil
	}
	out := Body{
		"input_tokens":  int(inputTokens),
		"output_tokens": int(outputTokens),
		"total_tokens":  int(inputTokens + outputTokens),
	}
	findNested := func(key string, parents ...string) (int64, bool) {
		for _, parent := range parents {
			if d := obj(usage, parent); d != nil {
				if v, ok := intNum(d[key]); ok {
					return v, true
				}
			}
		}
		return 0, false
	}
	if cached, ok := findNested("cached_tokens", "input_tokens_details", "prompt_tokens_details"); ok {
		out["input_tokens_details"] = Body{"cached_tokens": int(cached)}
	}
	if reasoning, ok := findNested("reasoning_tokens", "output_tokens_details", "completion_tokens_details"); ok {
		out["output_tokens_details"] = Body{"reasoning_tokens": int(reasoning)}
	}
	return out
}

func openaiToResponsesChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		return flushResponsesEvents(state), nil
	}
	if usage := toResponsesUsage(obj(chunk, "usage")); usage != nil {
		state.ResponsesUsage = usage
	}
	choices := arr(chunk, "choices")
	if len(choices) == 0 {
		if state.CompletionPending && state.ResponsesUsage != nil {
			return flushResponsesEvents(state), nil
		}
		return nil, nil
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		return nil, nil
	}
	idx := intVal(choice["index"])
	delta := obj(choice, "delta")
	if delta == nil {
		delta = Body{}
	}

	e := &responsesEmitter{state: state}

	if !state.Started {
		state.Started = true
		if id := str(chunk, "id"); id != "" {
			state.ResponseID = "resp_" + id
		}
		e.emit("response.created", Body{
			"response": Body{
				"id": state.ResponseID, "object": "response", "created_at": state.Created,
				"status": "in_progress", "background": false, "error": nil, "output": []any{},
			},
		})
		e.emit("response.in_progress", Body{
			"response": Body{
				"id": state.ResponseID, "object": "response", "created_at": state.Created,
				"status": "in_progress",
			},
		})
	}

	if reasoningText := extractReasoningText(delta); reasoningText != "" {
		startResponsesReasoning(state, e, idx)
		emitResponsesReasoningDelta(state, e, reasoningText)
	}

	if content := str(delta, "content"); content != "" {
		if strings.Contains(content, "<think>") {
			state.InThinking = true
			content = strings.Replace(content, "<think>", "", 1)
			startResponsesReasoning(state, e, idx)
		}
		if strings.Contains(content, "</think>") {
			parts := strings.Split(content, "</think>")
			thinkPart := parts[0]
			textPart := strings.Join(parts[1:], "</think>")
			if thinkPart != "" {
				emitResponsesReasoningDelta(state, e, thinkPart)
			}
			closeResponsesReasoning(state, e)
			state.InThinking = false
			content = textPart
		}
		if state.InThinking && content != "" {
			emitResponsesReasoningDelta(state, e, content)
			return e.events, nil
		}
		if content != "" {
			closeResponsesReasoning(state, e)
			emitResponsesTextContent(state, e, idx, content)
		}
	}

	if toolCalls := arr(delta, "tool_calls"); len(toolCalls) > 0 {
		closeResponsesReasoning(state, e)
		closeResponsesMessage(state, e, idx)
		for _, tv := range toolCalls {
			if tc, ok := tv.(map[string]any); ok {
				emitResponsesToolCall(state, e, tc)
			}
		}
	}

	if finishReason := str(choice, "finish_reason"); finishReason != "" {
		for i := range state.MsgItemAdded {
			closeResponsesMessage(state, e, i)
		}
		closeResponsesReasoning(state, e)
		for i := range state.FuncCallIDs {
			closeResponsesToolCall(state, e, i)
		}
		flushReachesUs := state.TargetFormat == FormatOpenAI
		if state.ResponsesUsage != nil || !flushReachesUs {
			sendResponsesCompleted(state, e)
		} else {
			state.CompletionPending = true
		}
	}

	return e.events, nil
}

func startResponsesReasoning(state *StreamState, e *responsesEmitter, idx int) {
	if state.ReasoningID == "" {
		state.ReasoningID = "rs_" + state.ResponseID + "_" + itoa(idx)
		state.ReasoningIndex = idx
		e.emit("response.output_item.added", Body{
			"output_index": idx,
			"item":         Body{"id": state.ReasoningID, "type": ResponsesItemReasoning, "summary": []any{}},
		})
		e.emit("response.reasoning_summary_part.added", Body{
			"item_id": state.ReasoningID, "output_index": idx, "summary_index": 0,
			"part": Body{"type": ResponsesItemSummaryText, "text": ""},
		})
		state.ReasoningPartAdded = true
	}
}

func emitResponsesReasoningDelta(state *StreamState, e *responsesEmitter, text string) {
	if text == "" {
		return
	}
	state.ReasoningBuf += text
	e.emit("response.reasoning_summary_text.delta", Body{
		"item_id": state.ReasoningID, "output_index": state.ReasoningIndex,
		"summary_index": 0, "delta": text,
	})
}

func closeResponsesReasoning(state *StreamState, e *responsesEmitter) {
	if state.ReasoningID != "" && !state.ReasoningDone {
		state.ReasoningDone = true
		e.emit("response.reasoning_summary_text.done", Body{
			"item_id": state.ReasoningID, "output_index": state.ReasoningIndex,
			"summary_index": 0, "text": state.ReasoningBuf,
		})
		e.emit("response.reasoning_summary_part.done", Body{
			"item_id": state.ReasoningID, "output_index": state.ReasoningIndex,
			"summary_index": 0,
			"part":          Body{"type": ResponsesItemSummaryText, "text": state.ReasoningBuf},
		})
		item := Body{
			"id": state.ReasoningID, "type": ResponsesItemReasoning,
			"summary": []any{Body{"type": ResponsesItemSummaryText, "text": state.ReasoningBuf}},
		}
		e.emit("response.output_item.done", Body{
			"output_index": state.ReasoningIndex, "item": item,
		})
		recordCompletedOutputItem(state, state.ReasoningIndex, item)
	}
}

func emitResponsesTextContent(state *StreamState, e *responsesEmitter, idx int, content string) {
	msgID := "msg_" + state.ResponseID + "_" + itoa(idx)
	if !state.MsgItemAdded[idx] {
		state.MsgItemAdded[idx] = true
		e.emit("response.output_item.added", Body{
			"output_index": idx,
			"item":         Body{"id": msgID, "type": ResponsesItemMessage, "content": []any{}, "role": RoleAssistant},
		})
	}
	if !state.MsgContentAdded[idx] {
		state.MsgContentAdded[idx] = true
		e.emit("response.content_part.added", Body{
			"item_id": msgID, "output_index": idx, "content_index": 0,
			"part": Body{"type": ResponsesItemOutputText, "annotations": []any{}, "logprobs": []any{}, "text": ""},
		})
	}
	e.emit("response.output_text.delta", Body{
		"item_id": msgID, "output_index": idx, "content_index": 0,
		"delta": content, "logprobs": []any{},
	})
	state.MsgTextBuf[idx] += content
}

func closeResponsesMessage(state *StreamState, e *responsesEmitter, idx int) {
	if state.MsgItemAdded[idx] && !state.MsgItemDone[idx] {
		state.MsgItemDone[idx] = true
		fullText := state.MsgTextBuf[idx]
		msgID := "msg_" + state.ResponseID + "_" + itoa(idx)
		e.emit("response.output_text.done", Body{
			"item_id": msgID, "output_index": idx, "content_index": 0,
			"text": fullText, "logprobs": []any{},
		})
		e.emit("response.content_part.done", Body{
			"item_id": msgID, "output_index": idx, "content_index": 0,
			"part": Body{"type": ResponsesItemOutputText, "annotations": []any{}, "logprobs": []any{}, "text": fullText},
		})
		item := Body{
			"id":   msgID,
			"type": ResponsesItemMessage,
			"content": []any{Body{
				"type": ResponsesItemOutputText, "annotations": []any{}, "logprobs": []any{}, "text": fullText,
			}},
			"role": RoleAssistant,
		}
		e.emit("response.output_item.done", Body{
			"output_index": idx, "item": item,
		})
		recordCompletedOutputItem(state, idx, item)
	}
}

func isResponsesCustomTool(state *StreamState, name string) bool {
	return name != "" && state.CustomToolNames[name]
}

func extractCustomToolInput(argumentsText string) string {
	if argumentsText == "" {
		return ""
	}
	parsed := safeParseJSON(argumentsText, nil)
	if m, ok := parsed.(map[string]any); ok {
		if s, ok := m["input"].(string); ok {
			return s
		}
	}
	return argumentsText
}

func emitResponsesToolCall(state *StreamState, e *responsesEmitter, tc Body) {
	tcIdx := intVal(tc["index"])
	newCallID := str(tc, "id")
	fn := obj(tc, "function")
	funcName := ""
	if fn != nil {
		funcName = str(fn, "name")
	}
	if funcName != "" {
		state.FuncNames[tcIdx] = funcName
	}
	if newCallID != "" {
		state.FuncCallIDs[tcIdx] = newCallID
	}
	callID := state.FuncCallIDs[tcIdx]
	if !state.FuncItemAdded[tcIdx] && callID != "" && state.FuncNames[tcIdx] != "" {
		state.FuncItemAdded[tcIdx] = true
		custom := isResponsesCustomTool(state, state.FuncNames[tcIdx])
		item := Body{
			"id":      prefixForCustom(custom) + "_" + callID,
			"call_id": callID,
			"name":    state.FuncNames[tcIdx],
		}
		if custom {
			item["type"] = ResponsesItemCustomToolCall
			item["input"] = ""
		} else {
			item["type"] = ResponsesItemFunctionCall
			item["arguments"] = ""
		}
		e.emit("response.output_item.added", Body{
			"output_index": tcIdx, "item": item,
		})
	}
	if fn != nil && str(fn, "arguments") != "" {
		args := str(fn, "arguments")
		refCallID := callID
		if refCallID == "" {
			refCallID = newCallID
		}
		if state.FuncItemAdded[tcIdx] && refCallID != "" && !isResponsesCustomTool(state, state.FuncNames[tcIdx]) {
			e.emit("response.function_call_arguments.delta", Body{
				"item_id": "fc_" + refCallID, "output_index": tcIdx, "delta": args,
			})
		}
		state.FuncArgsBuf[tcIdx] += args
	}
}

func prefixForCustom(custom bool) string {
	if custom {
		return "ctc"
	}
	return "fc"
}

func closeResponsesToolCall(state *StreamState, e *responsesEmitter, idx int) {
	callID := state.FuncCallIDs[idx]
	if callID == "" || state.FuncItemDone[idx] {
		return
	}
	args := state.FuncArgsBuf[idx]
	if args == "" {
		args = "{}"
	}
	custom := isResponsesCustomTool(state, state.FuncNames[idx])
	prefix := prefixForCustom(custom)
	var item Body
	if custom {
		input := extractCustomToolInput(args)
		e.emit("response.custom_tool_call_input.delta", Body{
			"item_id": prefix + "_" + callID, "output_index": idx, "delta": input,
		})
		e.emit("response.custom_tool_call_input.done", Body{
			"item_id": prefix + "_" + callID, "output_index": idx, "input": input,
		})
		item = Body{
			"id": prefix + "_" + callID, "type": ResponsesItemCustomToolCall,
			"input": input, "call_id": callID, "name": state.FuncNames[idx],
		}
	} else {
		e.emit("response.function_call_arguments.done", Body{
			"item_id": prefix + "_" + callID, "output_index": idx, "arguments": args,
		})
		item = Body{
			"id": prefix + "_" + callID, "type": ResponsesItemFunctionCall,
			"arguments": args, "call_id": callID, "name": state.FuncNames[idx],
		}
	}
	e.emit("response.output_item.done", Body{
		"output_index": idx, "item": item,
	})
	recordCompletedOutputItem(state, idx, item)
	state.FuncItemDone[idx] = true
	state.FuncArgsDone[idx] = true
}

func recordCompletedOutputItem(state *StreamState, outputIndex int, item Body) {
	state.CompletedOutputItems[outputIndex] = item
}

func collectCompletedOutputItems(state *StreamState) []any {
	if len(state.CompletedOutputItems) == 0 {
		return []any{}
	}
	keys := make([]int, 0, len(state.CompletedOutputItems))
	for k := range state.CompletedOutputItems {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, state.CompletedOutputItems[k])
	}
	return out
}

func sendResponsesCompleted(state *StreamState, e *responsesEmitter) {
	if state.CompletedSent {
		return
	}
	state.CompletedSent = true
	response := Body{
		"id": state.ResponseID, "object": "response", "created_at": state.Created,
		"status": "completed", "background": false, "error": nil,
		"output": collectCompletedOutputItems(state),
	}
	if state.ResponsesUsage != nil {
		response["usage"] = state.ResponsesUsage
	}
	e.emit("response.completed", Body{"response": response})
}

func flushResponsesEvents(state *StreamState) []Body {
	if state.CompletedSent {
		return nil
	}
	e := &responsesEmitter{state: state}
	for i := range state.MsgItemAdded {
		closeResponsesMessage(state, e, i)
	}
	closeResponsesReasoning(state, e)
	for i := range state.FuncCallIDs {
		closeResponsesToolCall(state, e, i)
	}
	sendResponsesCompleted(state, e)
	return e.events
}

// ---------- stream: openai-responses -> openai ----------
// Port of openaiResponsesToOpenAIResponse in response/openai-responses.js.

func computeResponsesFinishReason(state *StreamState) string {
	if state.ToolCallIndex > 0 || state.CurrentToolCallID != "" {
		return OpenAIFinishToolCalls
	}
	return OpenAIFinishStop
}

func responsesChunkMeta(state *StreamState) (string, int64, string) {
	model := state.Model
	if model == "" {
		model = ModelFallback
	}
	return state.ChatID, state.Created, model
}

func responsesToOpenAIChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		if state.FinishReasonSent || !state.Started {
			return nil, nil
		}
		finishReason := computeResponsesFinishReason(state)
		state.FinishReasonSent = true
		state.FinishReason = finishReason
		id := state.ChatID
		if id == "" {
			id = "chatcmpl-" + itoa64(nowMillis())
		}
		created := state.Created
		if created == 0 {
			created = nowUnix()
		}
		model := state.Model
		if model == "" {
			model = ModelFallback
		}
		final := buildChunk(id, created, model, Body{}, finishReason)
		if state.Usage != nil {
			final["usage"] = state.Usage
		}
		return []Body{final}, nil
	}

	eventType := str(chunk, "type")
	if eventType == "" {
		eventType = str(chunk, "event")
	}
	data := obj(chunk, "data")
	if data == nil {
		data = chunk
	}

	if !state.Started {
		state.Started = true
		state.ChatID = "chatcmpl-" + itoa64(nowMillis())
		state.Created = nowUnix()
		state.ToolCallIndex = 0
		state.CurrentToolCallID = ""
	}

	switch eventType {
	case "response.output_text.delta":
		text := str(data, "delta")
		if text == "" {
			return nil, nil
		}
		id, created, model := responsesChunkMeta(state)
		return []Body{buildChunk(id, created, model, Body{"content": text}, nil)}, nil

	case "response.output_text.done":
		return nil, nil

	case "response.output_item.added":
		item := obj(data, "item")
		if item == nil || (str(item, "type") != ResponsesItemFunctionCall && str(item, "type") != "custom_tool_call") {
			return nil, nil
		}
		state.CurrentToolCallID = str(item, "call_id")
		if state.CurrentToolCallID == "" {
			state.CurrentToolCallID = fallbackToolCallID(-1)
		}
		key := str(item, "id")
		if key == "" {
			key = str(data, "item_id")
		}
		if key == "" {
			key = state.CurrentToolCallID
		}
		var idx int
		if existing, ok := state.RespToolChatIndex[key]; ok {
			idx = existing
		} else {
			idx = state.ToolCallIndex
			state.ToolCallIndex++
			if key != "" {
				state.RespToolChatIndex[key] = idx
			}
		}
		id, created, model := responsesChunkMeta(state)
		return []Body{buildChunk(id, created, model, Body{
			"tool_calls": []any{Body{
				"index": idx,
				"id":    state.CurrentToolCallID,
				"type":  OpenAIBlockFunction,
				"function": Body{
					"name":      str(item, "name"),
					"arguments": "",
				},
			}},
		}, nil)}, nil

	case "response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
		argsDelta := str(data, "delta")
		if argsDelta == "" {
			return nil, nil
		}
		idx := 0
		if itemID := str(data, "item_id"); itemID != "" {
			if known, ok := state.RespToolChatIndex[itemID]; ok {
				idx = known
			} else {
				idx = state.ToolCallIndex - 1
				if idx < 0 {
					idx = 0
				}
			}
		} else {
			idx = state.ToolCallIndex - 1
			if idx < 0 {
				idx = 0
			}
		}
		state.RespToolArgsEmitted[idx] = true
		id, created, model := responsesChunkMeta(state)
		return []Body{buildChunk(id, created, model, Body{
			"tool_calls": []any{Body{
				"index":    idx,
				"function": Body{"arguments": argsDelta},
			}},
		}, nil)}, nil

	case "response.output_item.done":
		item := obj(data, "item")
		if item == nil || (str(item, "type") != ResponsesItemFunctionCall && str(item, "type") != "custom_tool_call") {
			return nil, nil
		}
		key := str(item, "id")
		if key == "" {
			key = str(data, "item_id")
		}
		idx := 0
		if known, ok := state.RespToolChatIndex[key]; ok {
			idx = known
		} else {
			idx = state.ToolCallIndex - 1
			if idx < 0 {
				idx = 0
			}
		}
		if fullArgs := str(item, "arguments"); fullArgs != "" && !state.RespToolArgsEmitted[idx] {
			state.RespToolArgsEmitted[idx] = true
			id, created, model := responsesChunkMeta(state)
			return []Body{buildChunk(id, created, model, Body{
				"tool_calls": []any{Body{
					"index":    idx,
					"function": Body{"arguments": fullArgs},
				}},
			}, nil)}, nil
		}
		return nil, nil

	case "response.completed", "response.done":
		if resp := obj(data, "response"); resp != nil {
			if usage := obj(resp, "usage"); usage != nil {
				inputTokens := intVal(usage["input_tokens"])
				if v, ok := num(usage, "prompt_tokens"); ok {
					inputTokens = int(v)
				}
				outputTokens := intVal(usage["output_tokens"])
				if v, ok := num(usage, "completion_tokens"); ok {
					outputTokens = int(v)
				}
				cacheRead := 0
				if details := obj(usage, "input_tokens_details"); details != nil {
					cacheRead = intVal(details["cached_tokens"])
				}
				if v, ok := num(usage, "cache_read_input_tokens"); ok {
					cacheRead = int(v)
				}
				state.Usage = buildUsage(inputTokens, outputTokens, inputTokens+outputTokens, cacheRead, 0, 0)
			}
		}
		if state.FinishReasonSent {
			return nil, nil
		}
		finishReason := computeResponsesFinishReason(state)
		state.FinishReasonSent = true
		state.FinishReason = finishReason
		id, created, model := responsesChunkMeta(state)
		final := buildChunk(id, created, model, Body{}, finishReason)
		if state.Usage != nil {
			final["usage"] = state.Usage
		}
		return []Body{final}, nil

	case "error", "response.failed":
		if state.FinishReasonSent {
			return nil, nil
		}
		errObj := obj(data, "error")
		if errObj == nil {
			if resp := obj(data, "response"); resp != nil {
				errObj = obj(resp, "error")
			}
		}
		if errObj == nil {
			return nil, nil
		}
		state.Error = errObj
		state.FinishReasonSent = true
		id := state.ChatID
		if id == "" {
			id = "chatcmpl-" + itoa64(nowMillis())
		}
		created := state.Created
		if created == 0 {
			created = nowUnix()
		}
		model := state.Model
		if model == "" {
			model = ModelFallback
		}
		msg := str(errObj, "message")
		if msg == "" {
			msg = stringifyJSON(errObj)
		}
		return []Body{buildChunk(id, created, model,
			Body{"content": "[Error] " + msg}, OpenAIFinishStop)}, nil

	case "response.reasoning_summary_text.delta":
		text := str(data, "delta")
		if text == "" {
			return nil, nil
		}
		id, created, model := responsesChunkMeta(state)
		return []Body{buildChunk(id, created, model, reasoningDelta(text), nil)}, nil
	}

	return nil, nil
}

// ---------- non-streaming bodies: openai <-> openai-responses ----------

func openaiToResponsesBody(body Body) (Body, error) {
	choices := arr(body, "choices")
	var choice Body
	if len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	var output []any
	finishReason := OpenAIFinishStop
	if choice != nil {
		if fr := str(choice, "finish_reason"); fr != "" {
			finishReason = fr
		}
		msg := obj(choice, "message")
		if msg != nil {
			if rc := str(msg, "reasoning_content"); rc != "" {
				output = append(output, Body{
					"type":    ResponsesItemReasoning,
					"summary": []any{Body{"type": ResponsesItemSummaryText, "text": rc}},
				})
			}
			text := ""
			var contentParts []any
			switch content := msg["content"].(type) {
			case string:
				text = content
			case []any:
				for _, pv := range content {
					if part, ok := pv.(map[string]any); ok && str(part, "type") == OpenAIBlockText {
						text += str(part, "text")
					}
				}
			}
			if text != "" {
				contentParts = append(contentParts, Body{
					"type": ResponsesItemOutputText, "annotations": []any{}, "logprobs": []any{}, "text": text,
				})
			}
			if len(contentParts) > 0 {
				output = append(output, Body{
					"type": ResponsesItemMessage, "role": RoleAssistant, "content": contentParts,
				})
			}
			for _, tv := range arr(msg, "tool_calls") {
				tc, ok := tv.(map[string]any)
				if !ok {
					continue
				}
				fn := obj(tc, "function")
				if fn == nil {
					continue
				}
				output = append(output, Body{
					"type":      ResponsesItemFunctionCall,
					"call_id":   str(tc, "id"),
					"name":      str(fn, "name"),
					"arguments": coerceResponsesArguments(fn["arguments"]),
				})
			}
		}
	}
	_ = finishReason
	id := str(body, "id")
	respID := id
	if !strings.HasPrefix(respID, "resp_") {
		respID = "resp_" + id
	}
	out := Body{
		"id":         respID,
		"object":     "response",
		"created_at": intVal(body["created"]),
		"status":     "completed",
		"model":      str(body, "model"),
		"output":     output,
	}
	if out["output"] == nil {
		out["output"] = []any{}
	}
	if usage := obj(body, "usage"); usage != nil {
		u := Body{
			"input_tokens":  intVal(usage["prompt_tokens"]),
			"output_tokens": intVal(usage["completion_tokens"]),
			"total_tokens":  intVal(usage["total_tokens"]),
		}
		if details := obj(usage, "prompt_tokens_details"); details != nil {
			if ct, ok := num(details, "cached_tokens"); ok {
				u["input_tokens_details"] = Body{"cached_tokens": int(ct)}
			}
		}
		if details := obj(usage, "completion_tokens_details"); details != nil {
			if rt, ok := num(details, "reasoning_tokens"); ok {
				u["output_tokens_details"] = Body{"reasoning_tokens": int(rt)}
			}
		}
		out["usage"] = u
	}
	return out, nil
}

func responsesToOpenAIBody(body Body) (Body, error) {
	message := Body{"role": RoleAssistant}
	var textParts []string
	var toolCalls []any
	var reasoningParts []string
	for _, iv := range arr(body, "output") {
		item, ok := iv.(map[string]any)
		if !ok {
			continue
		}
		switch str(item, "type") {
		case ResponsesItemMessage:
			for _, cv := range arr(item, "content") {
				if c, ok := cv.(map[string]any); ok && str(c, "type") == ResponsesItemOutputText {
					textParts = append(textParts, str(c, "text"))
				}
			}
		case ResponsesItemFunctionCall, ResponsesItemCustomToolCall:
			args := str(item, "arguments")
			if str(item, "type") == ResponsesItemCustomToolCall {
				args = stringifyJSON(Body{"input": str(item, "input")})
			}
			toolCalls = append(toolCalls, Body{
				"id":   str(item, "call_id"),
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":      str(item, "name"),
					"arguments": args,
				},
			})
		case ResponsesItemReasoning:
			for _, sv := range arr(item, "summary") {
				if s, ok := sv.(map[string]any); ok {
					reasoningParts = append(reasoningParts, str(s, "text"))
				}
			}
		}
	}
	text := strings.Join(textParts, "")
	if text != "" {
		message["content"] = text
	} else {
		message["content"] = nil
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	if joined := strings.Join(reasoningParts, ""); joined != "" {
		message["reasoning_content"] = joined
	}
	finishReason := OpenAIFinishStop
	if len(toolCalls) > 0 {
		finishReason = OpenAIFinishToolCalls
	}
	id := strings.TrimPrefix(str(body, "id"), "resp_")
	out := Body{
		"id":      "chatcmpl-" + id,
		"object":  "chat.completion",
		"created": intVal(body["created_at"]),
		"model":   str(body, "model"),
		"choices": []any{Body{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
	}
	if usage := obj(body, "usage"); usage != nil {
		u := Body{
			"prompt_tokens":     intVal(usage["input_tokens"]),
			"completion_tokens": intVal(usage["output_tokens"]),
			"total_tokens":      intVal(usage["total_tokens"]),
		}
		if details := obj(usage, "input_tokens_details"); details != nil {
			if ct, ok := num(details, "cached_tokens"); ok {
				u["prompt_tokens_details"] = Body{"cached_tokens": int(ct)}
			}
		}
		out["usage"] = u
	}
	return out, nil
}

func init() {
	Register(FormatOpenAI, FormatOpenAIResponses, nil, openaiToResponsesChunk)
	Register(FormatOpenAIResponses, FormatOpenAI, nil, responsesToOpenAIChunk)
	registerBody(FormatOpenAI, FormatOpenAIResponses, openaiToResponsesBody)
	registerBody(FormatOpenAIResponses, FormatOpenAI, responsesToOpenAIBody)
}
