package translator

import (
	"regexp"
	"strings"
)

// ---------- stream: claude -> openai (response/claude-to-openai.js) ----------

func claudeChunk(state *StreamState, delta Body, finishReason any) Body {
	return buildChunk("chatcmpl-"+state.MessageID, nowUnix(), state.Model, delta, finishReason)
}

func claudeToOpenAIChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		return nil, nil
	}
	var results []Body
	event := str(chunk, "type")

	switch event {
	case "message_start":
		msg := obj(chunk, "message")
		if id := str(msg, "id"); id != "" {
			state.MessageID = id
		} else {
			state.MessageID = "msg_" + itoa64(nowMillis())
		}
		state.Model = str(msg, "model")
		state.ToolCallIndex = 0
		if startUsage := obj(msg, "usage"); startUsage != nil {
			inputTokens := intVal(startUsage["input_tokens"])
			cacheRead := intVal(startUsage["cache_read_input_tokens"])
			cacheCreation := intVal(startUsage["cache_creation_input_tokens"])
			promptTokens := inputTokens + cacheRead + cacheCreation
			usage := Body{
				"prompt_tokens":     promptTokens,
				"completion_tokens": 0,
				"total_tokens":      promptTokens,
				"input_tokens":      inputTokens,
				"output_tokens":     0,
			}
			if cacheRead > 0 {
				usage["cache_read_input_tokens"] = cacheRead
			}
			if cacheCreation > 0 {
				usage["cache_creation_input_tokens"] = cacheCreation
			}
			state.Usage = usage
		}
		results = append(results, claudeChunk(state, Body{"role": RoleAssistant}, nil))

	case "content_block_start":
		block := obj(chunk, "content_block")
		idx := intVal(chunk["index"])
		if str(block, "type") == ClaudeBlockServerToolUse {
			state.ServerToolBlockIndex = idx
			break
		}
		switch str(block, "type") {
		case ClaudeBlockText:
			state.TextBlockStarted = true
		case ClaudeBlockToolUse:
			toolCallIndex := state.ToolCallIndex
			state.ToolCallIndex++
			toolName := str(block, "name")
			if state.ToolNameMap != nil {
				if orig, ok := state.ToolNameMap[toolName]; ok {
					toolName = orig
				}
			}
			tc := &ToolCallState{
				Index: toolCallIndex,
				ID:    str(block, "id"),
				Name:  toolName,
			}
			state.ToolCalls[idx] = tc
			results = append(results, claudeChunk(state, Body{
				"tool_calls": []any{Body{
					"index": toolCallIndex,
					"id":    tc.ID,
					"type":  OpenAIBlockFunction,
					"function": Body{
						"name":      toolName,
						"arguments": "",
					},
				}},
			}, nil))
		}

	case "content_block_delta":
		if intVal(chunk["index"]) == state.ServerToolBlockIndex {
			break
		}
		delta := obj(chunk, "delta")
		switch str(delta, "type") {
		case "text_delta":
			if t := str(delta, "text"); t != "" {
				results = append(results, claudeChunk(state, Body{"content": t}, nil))
			}
		case "thinking_delta":
			if t := str(delta, "thinking"); t != "" {
				results = append(results, claudeChunk(state, reasoningDelta(t), nil))
			}
		case "input_json_delta":
			if pj := str(delta, "partial_json"); pj != "" {
				if tc := state.ToolCalls[intVal(chunk["index"])]; tc != nil {
					tc.Args += pj
					results = append(results, claudeChunk(state, Body{
						"tool_calls": []any{Body{
							"index": tc.Index,
							"id":    tc.ID,
							"function": Body{
								"arguments": pj,
							},
						}},
					}, nil))
				}
			}
		}

	case "content_block_stop":
		if intVal(chunk["index"]) == state.ServerToolBlockIndex {
			state.ServerToolBlockIndex = -1
			break
		}
		state.TextBlockStarted = false
		state.ThinkingBlockStarted = false

	case "message_delta":
		if usage := obj(chunk, "usage"); usage != nil {
			prev := state.Usage
			get := func(key string, fallback int) int {
				if has(usage, key) {
					return intVal(usage[key])
				}
				return fallback
			}
			prevIn, prevCR, prevCC := 0, 0, 0
			if prev != nil {
				prevIn = intVal(prev["input_tokens"])
				prevCR = intVal(prev["cache_read_input_tokens"])
				prevCC = intVal(prev["cache_creation_input_tokens"])
			}
			inputTokens := get("input_tokens", prevIn)
			outputTokens := get("output_tokens", 0)
			cacheRead := get("cache_read_input_tokens", prevCR)
			cacheCreation := get("cache_creation_input_tokens", prevCC)
			promptTokens := inputTokens + cacheRead + cacheCreation
			merged := Body{
				"prompt_tokens":     promptTokens,
				"completion_tokens": outputTokens,
				"total_tokens":      promptTokens + outputTokens,
				"input_tokens":      inputTokens,
				"output_tokens":     outputTokens,
			}
			if cacheRead > 0 {
				merged["cache_read_input_tokens"] = cacheRead
			}
			if cacheCreation > 0 {
				merged["cache_creation_input_tokens"] = cacheCreation
			}
			state.Usage = merged
		}

		if delta := obj(chunk, "delta"); delta != nil && str(delta, "stop_reason") != "" {
			state.FinishReason = toOpenAIFinish(str(delta, "stop_reason"), "claude")
			if str(delta, "stop_reason") == ClaudeStopRefusal {
				if sd := obj(delta, "stop_details"); sd != nil {
					if note := str(sd, "explanation"); note != "" {
						results = append(results, claudeChunk(state, Body{"content": note}, nil))
					}
				}
			}
			finalChunk := claudeChunk(state, Body{}, state.FinishReason)
			if state.Usage != nil {
				finalChunk["usage"] = toOpenAIUsage(Body{
					"input_tokens":                intVal(state.Usage["input_tokens"]),
					"output_tokens":               intVal(state.Usage["output_tokens"]),
					"cache_read_input_tokens":     intVal(state.Usage["cache_read_input_tokens"]),
					"cache_creation_input_tokens": intVal(state.Usage["cache_creation_input_tokens"]),
				}, "claude")
			}
			results = append(results, finalChunk)
			state.FinishReasonSent = true
		}

	case "message_stop":
		if !state.FinishReasonSent {
			finishReason := state.FinishReason
			if finishReason == "" {
				if len(state.ToolCalls) > 0 {
					finishReason = OpenAIFinishToolCalls
				} else {
					finishReason = OpenAIFinishStop
				}
			}
			finalChunk := claudeChunk(state, Body{}, finishReason)
			if state.Usage != nil {
				in := intVal(state.Usage["input_tokens"])
				out := intVal(state.Usage["output_tokens"])
				finalChunk["usage"] = Body{
					"prompt_tokens":     in,
					"completion_tokens": out,
					"total_tokens":      in + out,
				}
			}
			results = append(results, finalChunk)
			state.FinishReasonSent = true
		}
	}

	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// ---------- stream: openai -> claude (response/openai-to-claude.js) ----------

// legacyClaudeOAuthToolPrefix is the old "proxy_" prefix the JS response
// translator strips defensively; the current request port emits no prefix.
const legacyClaudeOAuthToolPrefix = "proxy_"

var digitsRe = regexp.MustCompile(`^\d+$`)
var intRe = regexp.MustCompile(`^-?\d+$`)
var pdfPagesRe = regexp.MustCompile(`^\d+(?:-\d+)?$`)

// sanitizeToolArgs ports sanitizeToolArgs + sanitizeReadArgs.
func sanitizeToolArgs(toolName, argsJSON string) string {
	parsed := safeParseJSON(argsJSON, nil)
	args, ok := parsed.(map[string]any)
	if !ok {
		return argsJSON
	}
	name := strings.TrimPrefix(toolName, legacyClaudeOAuthToolPrefix)
	if name == "Read" {
		sanitizeReadArgs(args)
	}
	return stringifyJSON(args)
}

func sanitizeReadArgs(args Body) {
	if s, ok := args["limit"].(string); ok && digitsRe.MatchString(s) {
		args["limit"] = intVal(safeParseJSON(s, 0))
	}
	if s, ok := args["offset"].(string); ok && intRe.MatchString(s) {
		args["offset"] = intVal(safeParseJSON(s, 0))
	}
	if _, isNum := numVal(args["limit"]); isNum {
		limit := intVal(args["limit"])
		if limit > 2000 {
			args["limit"] = 2000
		} else if limit < 1 {
			delete(args, "limit")
		}
	}
	if _, isNum := numVal(args["offset"]); isNum && intVal(args["offset"]) < 0 {
		args["offset"] = 0
	}
	if _, present := args["pages"]; present {
		filePath, _ := args["file_path"].(string)
		pages, _ := args["pages"].(string)
		valid := filePath != "" && strings.HasSuffix(strings.ToLower(filePath), ".pdf") && pdfPagesRe.MatchString(pages)
		if !valid {
			delete(args, "pages")
		}
	}
}

func stopThinkingBlock(state *StreamState, results *[]Body) {
	if !state.ThinkingBlockStarted {
		return
	}
	*results = append(*results, Body{
		"type": "content_block_stop", "index": state.ThinkingBlockIndex,
	})
	state.ThinkingBlockStarted = false
}

func stopTextBlock(state *StreamState, results *[]Body) {
	if !state.TextBlockStarted || state.TextBlockClosed {
		return
	}
	state.TextBlockClosed = true
	*results = append(*results, Body{
		"type": "content_block_stop", "index": state.TextBlockIndex,
	})
	state.TextBlockStarted = false
}

func openaiToClaudeChunk(chunk Body, state *StreamState) ([]Body, error) {
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
	delta := obj(choice, "delta")

	var results []Body

	if usage := obj(chunk, "usage"); usage != nil {
		promptTokens := intVal(usage["prompt_tokens"])
		outputTokens := intVal(usage["completion_tokens"])
		var cacheRead, cacheCreate int
		if details := obj(usage, "prompt_tokens_details"); details != nil {
			cacheRead = intVal(details["cached_tokens"])
			cacheCreate = intVal(details["cache_creation_tokens"])
		}
		inputTokens := promptTokens - cacheRead - cacheCreate
		u := Body{"input_tokens": inputTokens, "output_tokens": outputTokens}
		if cacheRead > 0 {
			u["cache_read_input_tokens"] = cacheRead
		}
		if cacheCreate > 0 {
			u["cache_creation_input_tokens"] = cacheCreate
		}
		state.Usage = u
	}

	if !state.MessageStartSent {
		state.MessageStartSent = true
		id := strings.Replace(str(chunk, "id"), "chatcmpl-", "", 1)
		if id == "" {
			id = "msg_" + itoa64(nowMillis())
		}
		if id == "" || id == "chat" || len(id) < 8 {
			id = "msg_" + itoa64(nowMillis())
			if ef := obj(chunk, "extend_fields"); ef != nil {
				if v := str(ef, "requestId"); v != "" {
					id = v
				} else if v := str(ef, "traceId"); v != "" {
					id = v
				}
			}
		}
		state.MessageID = id
		state.Model = str(chunk, "model")
		if state.Model == "" {
			state.Model = ModelFallback
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

	if delta != nil {
		if reasoningContent := extractReasoningText(delta); reasoningContent != "" {
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

		if content := str(delta, "content"); content != "" {
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
				"delta": Body{"type": "text_delta", "text": content},
			})
		}

		for _, tv := range arr(delta, "tool_calls") {
			tc, ok := tv.(map[string]any)
			if !ok {
				continue
			}
			idx := intVal(tc["index"])
			if tcID := str(tc, "id"); tcID != "" {
				if _, exists := state.ToolCalls[idx]; !exists {
					stopThinkingBlock(state, &results)
					stopTextBlock(state, &results)
					blockIndex := state.NextBlockIndex
					state.NextBlockIndex++
					fn := obj(tc, "function")
					name := ""
					if fn != nil {
						name = str(fn, "name")
					}
					state.ToolCalls[idx] = &ToolCallState{ID: tcID, Name: name, BlockIndex: blockIndex}
					toolName := strings.TrimPrefix(name, legacyClaudeOAuthToolPrefix)
					results = append(results, Body{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": Body{
							"type":  ClaudeBlockToolUse,
							"id":    tcID,
							"name":  toolName,
							"input": Body{},
						},
					})
				}
			}
			if fn := obj(tc, "function"); fn != nil && str(fn, "arguments") != "" {
				if _, exists := state.ToolCalls[idx]; exists {
					state.ToolArgBuffers[idx] += str(fn, "arguments")
				}
			}
		}
	}

	if finishReason := str(choice, "finish_reason"); finishReason != "" {
		stopThinkingBlock(state, &results)
		stopTextBlock(state, &results)

		// Emit buffered args + stop per tool call, in index order.
		for idx := 0; idx < len(state.ToolCalls)+maxToolIndex(state)+1; idx++ {
			toolInfo, exists := state.ToolCalls[idx]
			if !exists {
				continue
			}
			if buffered := state.ToolArgBuffers[idx]; buffered != "" {
				results = append(results, Body{
					"type":  "content_block_delta",
					"index": toolInfo.BlockIndex,
					"delta": Body{"type": "input_json_delta", "partial_json": sanitizeToolArgs(toolInfo.Name, buffered)},
				})
			}
			results = append(results, Body{
				"type": "content_block_stop", "index": toolInfo.BlockIndex,
			})
		}

		state.FinishReason = finishReason
		finalUsage := state.Usage
		if finalUsage == nil {
			finalUsage = Body{"input_tokens": 0, "output_tokens": 0}
		}
		results = append(results, Body{
			"type":  "message_delta",
			"delta": Body{"stop_reason": fromOpenAIFinish(finishReason, "claude")},
			"usage": finalUsage,
		})
		results = append(results, Body{"type": "message_stop"})
	}

	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

func maxToolIndex(state *StreamState) int {
	max := 0
	for idx := range state.ToolCalls {
		if idx > max {
			max = idx
		}
	}
	return max
}

// ---------- non-streaming bodies: claude <-> openai ----------
// The JS assembles non-streaming bodies from the chunk stream; these
// converters produce the same final object directly.

func claudeToOpenAIBody(body Body) (Body, error) {
	message := Body{"role": RoleAssistant}
	var textParts []string
	var toolCalls []any
	var reasoningParts []string
	for _, bv := range arr(body, "content") {
		block, ok := bv.(map[string]any)
		if !ok {
			continue
		}
		switch str(block, "type") {
		case ClaudeBlockText:
			textParts = append(textParts, str(block, "text"))
		case ClaudeBlockThinking:
			reasoningParts = append(reasoningParts, str(block, "thinking"))
		case ClaudeBlockToolUse:
			input := block["input"]
			if input == nil {
				input = Body{}
			}
			toolCalls = append(toolCalls, Body{
				"id":   str(block, "id"),
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":      str(block, "name"),
					"arguments": stringifyJSON(input),
				},
			})
		}
	}
	if len(textParts) > 0 {
		message["content"] = strings.Join(textParts, "")
	} else {
		message["content"] = nil
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	if len(reasoningParts) > 0 {
		message["reasoning_content"] = strings.Join(reasoningParts, "")
	}
	id := str(body, "id")
	out := Body{
		"id":      "chatcmpl-" + id,
		"object":  "chat.completion",
		"created": nowUnix(),
		"model":   str(body, "model"),
		"choices": []any{Body{
			"index":         0,
			"message":       message,
			"finish_reason": toOpenAIFinish(str(body, "stop_reason"), "claude"),
		}},
	}
	if id == "" {
		out["id"] = "chatcmpl-" + itoa64(nowMillis())
	}
	if usage := obj(body, "usage"); usage != nil {
		out["usage"] = toOpenAIUsage(usage, "claude")
	}
	return out, nil
}

func openaiToClaudeBody(body Body) (Body, error) {
	choices := arr(body, "choices")
	var choice Body
	if len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	var content []any
	finishReason := OpenAIFinishStop
	if choice != nil {
		if fr := str(choice, "finish_reason"); fr != "" {
			finishReason = fr
		}
		msg := obj(choice, "message")
		if msg != nil {
			if s, isStr := msg["content"].(string); isStr && s != "" {
				content = append(content, Body{"type": ClaudeBlockText, "text": s})
			} else if parts := arr(msg, "content"); parts != nil {
				for _, pv := range parts {
					if part, ok := pv.(map[string]any); ok && str(part, "type") == OpenAIBlockText {
						content = append(content, Body{"type": ClaudeBlockText, "text": str(part, "text")})
					}
				}
			}
			if rc := str(msg, "reasoning_content"); rc != "" {
				content = append([]any{Body{"type": ClaudeBlockThinking, "thinking": rc}}, content...)
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
				var input any = Body{}
				if args := fn["arguments"]; args != nil {
					input = safeParseJSON(args, Body{})
				}
				content = append(content, Body{
					"type":  ClaudeBlockToolUse,
					"id":    str(tc, "id"),
					"name":  strings.TrimPrefix(str(fn, "name"), legacyClaudeOAuthToolPrefix),
					"input": input,
				})
			}
		}
	}
	if content == nil {
		content = []any{}
	}
	id := strings.TrimPrefix(str(body, "id"), "chatcmpl-")
	out := Body{
		"id":          id,
		"type":        "message",
		"role":        RoleAssistant,
		"model":       str(body, "model"),
		"content":     content,
		"stop_reason": fromOpenAIFinish(finishReason, "claude"),
	}
	if usage := obj(body, "usage"); usage != nil {
		prompt := intVal(usage["prompt_tokens"])
		output := intVal(usage["completion_tokens"])
		var cacheRead, cacheCreate int
		if details := obj(usage, "prompt_tokens_details"); details != nil {
			cacheRead = intVal(details["cached_tokens"])
			cacheCreate = intVal(details["cache_creation_tokens"])
		}
		u := Body{
			"input_tokens":  prompt - cacheRead - cacheCreate,
			"output_tokens": output,
		}
		if cacheRead > 0 {
			u["cache_read_input_tokens"] = cacheRead
		}
		if cacheCreate > 0 {
			u["cache_creation_input_tokens"] = cacheCreate
		}
		out["usage"] = u
	}
	return out, nil
}

func init() {
	Register(FormatClaude, FormatOpenAI, claudeToOpenAIRequest, claudeToOpenAIChunk)
	Register(FormatOpenAI, FormatClaude, openaiToClaudeRequest, openaiToClaudeChunk)
	registerBody(FormatClaude, FormatOpenAI, claudeToOpenAIBody)
	registerBody(FormatOpenAI, FormatClaude, openaiToClaudeBody)
}
