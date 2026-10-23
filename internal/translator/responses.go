package translator

import (
	"strings"
	"sync/atomic"
)

// ---------- formats/responsesApi.js helpers ----------

const maxResponsesCallIDLen = 64

var responsesCallIDSeq atomic.Int64

// normalizeResponsesInput ports normalizeResponsesInput; nil means the
// input was neither a string nor an array (JS returns null).
func normalizeResponsesInput(input any) []any {
	switch in := input.(type) {
	case string:
		text := in
		if strings.TrimSpace(text) == "" {
			text = "..."
		}
		return []any{Body{
			"type":    ResponsesItemMessage,
			"role":    RoleUser,
			"content": []any{Body{"type": ResponsesItemInputText, "text": text}},
		}}
	case []any:
		if len(in) == 0 {
			return []any{Body{
				"type":    ResponsesItemMessage,
				"role":    RoleUser,
				"content": []any{Body{"type": ResponsesItemInputText, "text": "..."}},
			}}
		}
		return in
	}
	return nil
}

// clampResponsesCallID ports clampResponsesCallId.
func clampResponsesCallID(id string) string {
	if id == "" {
		return "call_" + itoa64(nowMillis()) + "_" + itoa64(responsesCallIDSeq.Add(1))
	}
	if len(id) > maxResponsesCallIDLen {
		return id[:maxResponsesCallIDLen]
	}
	return id
}

// coerceResponsesArguments ports coerceResponsesArguments.
func coerceResponsesArguments(value any) string {
	if value == nil {
		return "{}"
	}
	if s, ok := value.(string); ok {
		if s == "" {
			return "{}"
		}
		if parsed := safeParseJSON(s, nil); parsed != nil {
			return s
		}
		return "{}"
	}
	return stringifyJSON(value)
}

// coerceResponsesOutput ports coerceResponsesOutput.
func coerceResponsesOutput(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	case []any:
		var sb strings.Builder
		for _, c := range v {
			if cm, ok := c.(map[string]any); ok {
				if t, hasText := cm["text"]; hasText && t != nil {
					sb.WriteString(stringOrJSON(t))
				} else {
					sb.WriteString(stringifyJSON(c))
				}
			} else {
				sb.WriteString(stringifyJSON(c))
			}
		}
		return sb.String()
	default:
		return stringifyJSON(value)
	}
}

// normalizeToolParameters ports normalizeToolParameters.
func normalizeToolParameters(params Body) Body {
	if params == nil {
		return Body{"type": "object", "properties": Body{}}
	}
	if str(params, "type") == "object" && !has(params, "properties") {
		cp := deepCopyBody(params)
		cp["properties"] = Body{}
		return cp
	}
	return params
}

// ---------- request: openai-responses -> openai (request/openai-responses.js) ----------

func responsesToOpenAIRequest(body Body) (Body, error) {
	if !has(body, "input") {
		return body, nil
	}
	inputItems := normalizeResponsesInput(body["input"])
	if inputItems == nil {
		return body, nil
	}

	result := deepCopyBody(body)
	var messages []any

	if instructions := str(body, "instructions"); instructions != "" {
		messages = append(messages, Body{"role": RoleSystem, "content": instructions})
	}

	var currentAssistant Body
	var currentToolCalls []any
	var pendingToolResults []any
	pendingReasoning := ""
	pendingReasoningEncrypted := ""
	var additionalTools []any
	customToolNames := map[string]bool{}
	var customToolNameList []any

	extractReasoningTextFromItem := func(item Body) string {
		if summary := arr(item, "summary"); summary != nil {
			var texts []string
			for _, sv := range summary {
				if sm, ok := sv.(map[string]any); ok && str(sm, "text") != "" {
					texts = append(texts, str(sm, "text"))
				}
			}
			if len(texts) > 0 {
				return strings.Join(texts, "\n")
			}
		}
		if content := arr(item, "content"); content != nil {
			var texts []string
			for _, cv := range content {
				if cm, ok := cv.(map[string]any); ok && str(cm, "text") != "" {
					texts = append(texts, str(cm, "text"))
				}
			}
			if len(texts) > 0 {
				return strings.Join(texts, "\n")
			}
		}
		return ""
	}
	attachPendingReasoning := func(msg Body) {
		if pendingReasoning != "" {
			msg["reasoning_content"] = pendingReasoning
		}
		if pendingReasoningEncrypted != "" {
			msg["encrypted_content"] = pendingReasoningEncrypted
		}
		pendingReasoning = ""
		pendingReasoningEncrypted = ""
	}
	flushAssistant := func() {
		if currentAssistant != nil {
			messages = append(messages, currentAssistant)
			currentAssistant = nil
			currentToolCalls = nil
		}
	}
	flushToolResults := func() {
		messages = append(messages, pendingToolResults...)
		pendingToolResults = nil
	}

	for _, iv := range inputItems {
		item, ok := iv.(map[string]any)
		if !ok {
			continue
		}
		itemType := str(item, "type")
		if itemType == "" && has(item, "role") {
			itemType = ResponsesItemMessage
		}

		switch itemType {
		case ResponsesItemMessage:
			flushAssistant()
			flushToolResults()
			var content any
			if parts := arr(item, "content"); parts != nil {
				var mapped []any
				for _, cv := range parts {
					c, ok := cv.(map[string]any)
					if !ok {
						mapped = append(mapped, cv)
						continue
					}
					switch str(c, "type") {
					case ResponsesItemInputText, ResponsesItemOutputText:
						mapped = append(mapped, Body{"type": OpenAIBlockText, "text": str(c, "text")})
					case ResponsesItemInputImage:
						url := str(c, "image_url")
						if url == "" {
							url = str(c, "file_id")
						}
						detail := str(c, "detail")
						if detail == "" {
							detail = "auto"
						}
						mapped = append(mapped, Body{
							"type":      OpenAIBlockImageURL,
							"image_url": Body{"url": url, "detail": detail},
						})
					default:
						mapped = append(mapped, c)
					}
				}
				content = mapped
			} else {
				content = item["content"]
			}
			msg := Body{"role": str(item, "role"), "content": content}
			if str(item, "role") == RoleAssistant {
				attachPendingReasoning(msg)
			} else {
				pendingReasoning = ""
				pendingReasoningEncrypted = ""
			}
			messages = append(messages, msg)

		case ResponsesItemFunctionCall, ResponsesItemCustomToolCall:
			if currentAssistant == nil {
				currentAssistant = Body{"role": RoleAssistant, "content": nil, "tool_calls": []any{}}
				attachPendingReasoning(currentAssistant)
			}
			name := str(item, "name")
			if name == "" || strings.TrimSpace(name) == "" {
				continue
			}
			if itemType == ResponsesItemCustomToolCall && !customToolNames[name] {
				customToolNames[name] = true
				customToolNameList = append(customToolNameList, name)
			}
			var toolInput any
			if itemType == ResponsesItemCustomToolCall {
				if s, ok := item["input"].(string); ok {
					toolInput = Body{"input": s}
				} else {
					toolInput = Body{"input": stringifyJSON(item["input"])}
				}
				if item["input"] == nil {
					toolInput = Body{"input": stringifyJSON("")}
				}
			} else {
				toolInput = item["arguments"]
			}
			arguments := ""
			if s, ok := toolInput.(string); ok {
				arguments = s
			} else if toolInput == nil {
				arguments = "{}"
			} else {
				arguments = stringifyJSON(toolInput)
			}
			currentToolCalls = append(arr(currentAssistant, "tool_calls"), Body{
				"id":   str(item, "call_id"),
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":      name,
					"arguments": arguments,
				},
			})
			currentAssistant["tool_calls"] = currentToolCalls

		case ResponsesItemFunctionCallOutput, ResponsesItemCustomToolCallOutput:
			flushAssistant()
			flushToolResults()
			var contentStr string
			if s, ok := item["output"].(string); ok {
				contentStr = s
			} else {
				contentStr = stringifyJSON(item["output"])
			}
			messages = append(messages, Body{
				"role": RoleTool, "tool_call_id": str(item, "call_id"), "content": contentStr,
			})

		case ResponsesItemAdditionalTools:
			additionalTools = append(additionalTools, arr(item, "tools")...)

		case ResponsesItemReasoning:
			if txt := extractReasoningTextFromItem(item); txt != "" {
				if pendingReasoning != "" {
					pendingReasoning += "\n" + txt
				} else {
					pendingReasoning = txt
				}
			}
			if enc := str(item, "encrypted_content"); enc != "" {
				pendingReasoningEncrypted = enc
			}
		}
	}
	flushAssistant()
	flushToolResults()
	result["messages"] = messages

	responseTools := append(append([]any{}, arr(body, "tools")...), additionalTools...)
	if len(responseTools) > 0 {
		var converted []any
		for _, tv := range responseTools {
			tool, ok := tv.(map[string]any)
			if !ok {
				continue
			}
			if obj(tool, "function") != nil {
				converted = append(converted, tool)
				continue
			}
			name := str(tool, "name")
			if name == "" || strings.TrimSpace(name) == "" {
				continue
			}
			if str(tool, "type") == "custom" {
				if !customToolNames[name] {
					customToolNames[name] = true
					customToolNameList = append(customToolNameList, name)
				}
				var formatHint []string
				if format := obj(tool, "format"); format != nil {
					if s := str(format, "syntax"); s != "" {
						formatHint = append(formatHint, s)
					}
					if s := str(format, "definition"); s != "" {
						formatHint = append(formatHint, s)
					}
				}
				description := strings.Join(
					filterNonEmpty([]string{stringOrEmpty(tool["description"]), strings.Join(formatHint, "\n")}),
					"\n\n")
				converted = append(converted, Body{
					"type": OpenAIBlockFunction,
					"function": Body{
						"name":        name,
						"description": description,
						"parameters": Body{
							"type": "object",
							"properties": Body{
								"input": Body{"type": "string", "description": "Raw freeform input for this custom tool"},
							},
							"required":             []any{"input"},
							"additionalProperties": false,
						},
					},
				})
				continue
			}
			convertedTool := Body{
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":        name,
					"description": stringOrEmpty(tool["description"]),
					"parameters":  normalizeToolParameters(obj(tool, "parameters")),
				},
			}
			if has(tool, "strict") {
				obj(convertedTool, "function")["strict"] = tool["strict"]
			}
			converted = append(converted, convertedTool)
		}
		result["tools"] = converted
	}
	if len(customToolNameList) > 0 {
		result["_customToolNames"] = customToolNameList
	}

	if has(result, "max_output_tokens") {
		if !has(result, "max_tokens") {
			result["max_tokens"] = result["max_output_tokens"]
		}
		delete(result, "max_output_tokens")
	}
	delete(result, "input")
	delete(result, "instructions")
	delete(result, "include")
	delete(result, "prompt_cache_key")
	delete(result, "store")
	if reasoning := obj(result, "reasoning"); reasoning != nil {
		if effort := str(reasoning, "effort"); effort != "" {
			result["reasoning_effort"] = effort
		}
	}
	delete(result, "reasoning")
	delete(result, "client_metadata")
	return result, nil
}

func filterNonEmpty(items []string) []string {
	var out []string
	for _, s := range items {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// extractInstructionsText ports extractInstructionsText.
func extractInstructionsText(content any) string {
	if s, ok := content.(string); ok {
		return s
	}
	if parts, ok := content.([]any); ok {
		var texts []string
		for _, cv := range parts {
			c, _ := cv.(map[string]any)
			if c == nil {
				continue
			}
			if t := str(c, "text"); t != "" {
				texts = append(texts, t)
			} else if t := str(c, "content"); t != "" {
				texts = append(texts, t)
			}
		}
		return strings.Join(texts, "\n")
	}
	return ""
}

// buildReasoningInputItem ports buildReasoningInputItem.
func buildReasoningInputItem(msg Body) Body {
	encrypted := ""
	if s := str(msg, "encrypted_content"); s != "" {
		encrypted = s
	} else if s := str(msg, "reasoning_encrypted_content"); s != "" {
		encrypted = s
	} else if r := obj(msg, "reasoning"); r != nil {
		encrypted = str(r, "encrypted_content")
	}
	summaryText := ""
	if rc := str(msg, "reasoning_content"); strings.TrimSpace(rc) != "" {
		summaryText = rc
	} else if r := msg["reasoning"]; r != nil {
		if s, ok := r.(string); ok && strings.TrimSpace(s) != "" {
			summaryText = s
		}
	}
	if summaryText == "" {
		if details := arr(msg, "reasoning_details"); details != nil {
			var texts []string
			for _, dv := range details {
				d, _ := dv.(map[string]any)
				if d == nil {
					continue
				}
				if t := str(d, "text"); t != "" {
					texts = append(texts, t)
				} else if t := str(d, "content"); t != "" {
					texts = append(texts, t)
				}
			}
			summaryText = strings.Join(texts, "\n")
		}
	}
	if encrypted == "" && summaryText == "" {
		return nil
	}
	item := Body{"type": ResponsesItemReasoning}
	if summaryText != "" {
		item["summary"] = []any{Body{"type": ResponsesItemSummaryText, "text": summaryText}}
	}
	if encrypted != "" {
		item["encrypted_content"] = encrypted
	}
	return item
}

const maxToolNameLen = 128

// ---------- request: openai -> openai-responses (request/openai-responses.js) ----------

func openaiToResponsesRequest(body Body) (Body, error) {
	model := str(body, "model")
	if has(body, "input") {
		out := deepCopyBody(body)
		out["model"] = model
		out["stream"] = true
		if !has(out, "max_output_tokens") {
			if has(out, "max_completion_tokens") {
				out["max_output_tokens"] = out["max_completion_tokens"]
			} else if has(out, "max_tokens") {
				out["max_output_tokens"] = out["max_tokens"]
			}
		}
		delete(out, "max_tokens")
		delete(out, "max_completion_tokens")
		return out, nil
	}

	result := Body{
		"model":  model,
		"input":  []any{},
		"stream": true,
		"store":  false,
	}
	var input []any
	hasSystemMessage := false

	for _, mv := range arr(body, "messages") {
		msg, ok := mv.(map[string]any)
		if !ok {
			continue
		}
		role := str(msg, "role")

		if role == RoleSystem || role == RoleDeveloper {
			if !hasSystemMessage {
				result["instructions"] = extractInstructionsText(msg["content"])
				hasSystemMessage = true
			}
			continue
		}

		if role == RoleUser || role == RoleAssistant {
			if role == RoleAssistant {
				if item := buildReasoningInputItem(msg); item != nil {
					input = append(input, item)
				}
			}
			contentType := ResponsesItemInputText
			if role == RoleAssistant {
				contentType = ResponsesItemOutputText
			}
			var content []any
			switch c := msg["content"].(type) {
			case string:
				content = []any{Body{"type": contentType, "text": c}}
			case []any:
				for _, pv := range c {
					part, ok := pv.(map[string]any)
					if !ok {
						continue
					}
					switch str(part, "type") {
					case OpenAIBlockText:
						content = append(content, Body{"type": contentType, "text": str(part, "text")})
					case OpenAIBlockImageURL:
						var url, detail string
						switch iu := part["image_url"].(type) {
						case string:
							url = iu
						case map[string]any:
							url = str(iu, "url")
							detail = str(iu, "detail")
						}
						if detail == "" {
							detail = "auto"
						}
						content = append(content, Body{
							"type": ResponsesItemInputImage, "image_url": url, "detail": detail,
						})
					case ResponsesItemInputImage:
						content = append(content, part)
					default:
						text := part["text"]
						if text == nil {
							text = part["content"]
						}
						if text == nil {
							text = stringifyJSON(part)
						}
						textStr, isStr := text.(string)
						if !isStr {
							textStr = stringifyJSON(text)
						}
						content = append(content, Body{"type": contentType, "text": textStr})
					}
				}
			}
			if len(content) > 0 {
				input = append(input, Body{
					"type": ResponsesItemMessage, "role": role, "content": content,
				})
			}
		}

		if role == RoleAssistant {
			for _, tv := range arr(msg, "tool_calls") {
				tc, ok := tv.(map[string]any)
				if !ok {
					continue
				}
				fn := obj(tc, "function")
				if fn == nil {
					continue
				}
				name := strings.TrimSpace(str(fn, "name"))
				if name == "" {
					continue
				}
				if len(name) > maxToolNameLen {
					name = name[:maxToolNameLen]
				}
				input = append(input, Body{
					"type":      ResponsesItemFunctionCall,
					"call_id":   clampResponsesCallID(str(tc, "id")),
					"name":      name,
					"arguments": coerceResponsesArguments(fn["arguments"]),
				})
			}
		}

		if role == RoleTool {
			input = append(input, Body{
				"type":    ResponsesItemFunctionCallOutput,
				"call_id": clampResponsesCallID(str(msg, "tool_call_id")),
				"output":  coerceResponsesOutput(msg["content"]),
			})
		}
	}
	result["input"] = input

	if !hasSystemMessage {
		result["instructions"] = ""
	}

	if tools := arr(body, "tools"); tools != nil {
		var out []any
		for _, tv := range tools {
			tool, ok := tv.(map[string]any)
			if !ok {
				continue
			}
			if str(tool, "type") == OpenAIBlockFunction {
				fn := obj(tool, "function")
				name := ""
				var description string
				var params Body
				var strict any
				hasStrict := false
				if fn != nil {
					name = strings.TrimSpace(str(fn, "name"))
					description = stringOrEmpty(fn["description"])
					params = normalizeToolParameters(obj(fn, "parameters"))
					if has(fn, "strict") {
						strict = fn["strict"]
						hasStrict = true
					}
				}
				if name == "" {
					continue
				}
				if len(name) > maxToolNameLen {
					name = name[:maxToolNameLen]
				}
				converted := Body{
					"type":        OpenAIBlockFunction,
					"name":        name,
					"description": description,
					"parameters":  params,
				}
				if hasStrict {
					converted["strict"] = strict
				}
				out = append(out, converted)
				continue
			}
			out = append(out, tool)
		}
		result["tools"] = out
	}

	if has(body, "temperature") {
		result["temperature"] = body["temperature"]
	}
	if has(body, "max_output_tokens") {
		result["max_output_tokens"] = body["max_output_tokens"]
	} else if has(body, "max_completion_tokens") {
		result["max_output_tokens"] = body["max_completion_tokens"]
	} else if has(body, "max_tokens") {
		result["max_output_tokens"] = body["max_tokens"]
	}
	if has(body, "top_p") {
		result["top_p"] = body["top_p"]
	}
	if has(body, "reasoning") {
		result["reasoning"] = body["reasoning"]
	}
	if has(body, "reasoning_effort") {
		result["reasoning"] = Body{"effort": body["reasoning_effort"], "summary": "auto"}
	}
	if has(body, "service_tier") {
		result["service_tier"] = body["service_tier"]
	}
	if has(body, "prompt_cache_key") {
		result["prompt_cache_key"] = body["prompt_cache_key"]
	}
	return result, nil
}

func init() {
	Register(FormatOpenAIResponses, FormatOpenAI, responsesToOpenAIRequest, nil)
	Register(FormatOpenAI, FormatOpenAIResponses, openaiToResponsesRequest, nil)
}
