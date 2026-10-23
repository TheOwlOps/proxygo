package translator

import (
	"strings"
)

// ---------- request: gemini -> openai (request/gemini-to-openai.js) ----------

func geminiToOpenAIRequest(body Body) (Body, error) {
	result := Body{
		"model":    str(body, "model"),
		"messages": []any{},
		"stream":   streamOrDefault(body),
	}

	if config := obj(body, "generationConfig"); config != nil {
		if v, ok := num(config, "maxOutputTokens"); ok && v != 0 {
			tempBody := Body{"max_tokens": int(v), "tools": body["tools"]}
			result["max_tokens"] = adjustMaxTokens(tempBody, 0)
		}
		if has(config, "temperature") {
			result["temperature"] = config["temperature"]
		}
		if has(config, "topP") {
			result["top_p"] = config["topP"]
		}
	}

	if has(body, "systemInstruction") {
		if text := extractGeminiText(body["systemInstruction"]); text != "" {
			result["messages"] = append(arr(result, "messages"),
				Body{"role": RoleSystem, "content": text})
		}
	}

	if contents := arr(body, "contents"); contents != nil {
		out := arr(result, "messages")
		for _, cv := range contents {
			content, ok := cv.(map[string]any)
			if !ok {
				continue
			}
			if converted := convertGeminiContent(content); converted != nil {
				out = append(out, converted)
			}
		}
		result["messages"] = out
	}

	if tools := arr(body, "tools"); tools != nil {
		out := []any{}
		for _, tv := range tools {
			tool, _ := tv.(map[string]any)
			if tool == nil {
				continue
			}
			for _, fv := range arr(tool, "functionDeclarations") {
				fn, _ := fv.(map[string]any)
				if fn == nil {
					continue
				}
				params := obj(fn, "parameters")
				if params == nil {
					params = Body{"type": "object", "properties": Body{}}
				}
				out = append(out, Body{
					"type": OpenAIBlockFunction,
					"function": Body{
						"name":        str(fn, "name"),
						"description": stringOrEmpty(fn["description"]),
						"parameters":  params,
					},
				})
			}
		}
		result["tools"] = out
	}
	return result, nil
}

func convertGeminiContent(content Body) Body {
	role := RoleAssistant
	if str(content, "role") == GeminiRoleUser {
		role = RoleUser
	}
	parts := arr(content, "parts")
	if parts == nil {
		return nil
	}
	var textParts []any
	var toolCalls []any

	for _, pv := range parts {
		part, ok := pv.(map[string]any)
		if !ok {
			continue
		}
		if has(part, "text") {
			textParts = append(textParts, Body{"type": OpenAIBlockText, "text": str(part, "text")})
		}
		if inline := obj(part, "inlineData"); inline != nil {
			textParts = append(textParts, Body{
				"type":      OpenAIBlockImageURL,
				"image_url": Body{"url": encodeDataURI(str(inline, "mimeType"), str(inline, "data"))},
			})
		}
		if fc := obj(part, "functionCall"); fc != nil {
			id := str(fc, "id")
			if id == "" {
				id = "call_" + str(fc, "name")
			}
			args := fc["args"]
			if args == nil {
				args = Body{}
			}
			toolCalls = append(toolCalls, Body{
				"id":   id,
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":      str(fc, "name"),
					"arguments": stringifyJSON(args),
				},
			})
		}
		if fr := obj(part, "functionResponse"); fr != nil {
			id := str(fr, "id")
			if id == "" {
				id = "call_" + str(fr, "name")
			}
			var respContent any
			if resp := obj(fr, "response"); resp != nil {
				if has(resp, "result") {
					respContent = resp["result"]
				} else {
					respContent = resp
				}
			}
			if respContent == nil {
				respContent = Body{}
			}
			return Body{
				"role":         RoleTool,
				"tool_call_id": id,
				"content":      stringifyJSON(respContent),
			}
		}
	}

	if len(toolCalls) > 0 {
		out := Body{"role": RoleAssistant}
		if len(textParts) > 0 {
			if len(textParts) == 1 {
				if p, ok := textParts[0].(map[string]any); ok {
					out["content"] = str(p, "text")
				}
			} else {
				out["content"] = textParts
			}
		}
		out["tool_calls"] = toolCalls
		return out
	}
	if len(textParts) > 0 {
		return Body{"role": role, "content": collapseTextParts(textParts)}
	}
	return nil
}

func extractGeminiText(content any) string {
	if s, ok := content.(string); ok {
		return s
	}
	if c, ok := content.(map[string]any); ok {
		if parts := arr(c, "parts"); parts != nil {
			var sb strings.Builder
			for _, pv := range parts {
				if p, ok := pv.(map[string]any); ok {
					sb.WriteString(str(p, "text"))
				}
			}
			return sb.String()
		}
	}
	return ""
}

// ---------- request: openai -> gemini (request/openai-to-gemini.js) ----------
// Port of openaiToGeminiBase + openaiToGeminiRequest (standard API shape;
// the gemini-cli/antigravity Cloud Code envelopes need credentials and a
// session store, so FormatGeminiCLI requests register the same base
// conversion and the envelope wrap is a TODO — see register block).
// The thought-signature store is likewise absent: cached signatures are
// never found, so the first function call of a turn carries the default
// AG signature exactly as the JS does for an uncached call.

func openaiToGeminiRequest(body Body) (Body, error) {
	return openaiToGeminiBase(str(body, "model"), body, DEFAULT_THINKING_AG_SIGNATURE), nil
}

func openaiToGeminiBase(model string, body Body, signature string) Body {
	result := Body{
		"model":            model,
		"contents":         []any{},
		"generationConfig": Body{},
		"safetySettings":   defaultSafetySettings(),
	}
	genConfig := obj(result, "generationConfig")

	allowSampling := !isGemini4Model(model)
	if allowSampling && has(body, "temperature") {
		genConfig["temperature"] = body["temperature"]
	}
	if allowSampling && has(body, "top_p") {
		genConfig["topP"] = body["top_p"]
	}
	if allowSampling && has(body, "top_k") {
		genConfig["topK"] = body["top_k"]
	}
	if has(body, "max_tokens") {
		genConfig["maxOutputTokens"] = body["max_tokens"]
	}

	messages := arr(body, "messages")

	tcID2Name := map[string]string{}
	toolResponses := map[string][]any{}
	for _, mv := range messages {
		msg, _ := mv.(map[string]any)
		if msg == nil {
			continue
		}
		if str(msg, "role") == RoleAssistant {
			for _, tv := range arr(msg, "tool_calls") {
				if tc, ok := tv.(map[string]any); ok && str(tc, "type") == OpenAIBlockFunction {
					if fn := obj(tc, "function"); fn != nil && str(tc, "id") != "" {
						tcID2Name[str(tc, "id")] = str(fn, "name")
					}
				}
			}
		}
		if str(msg, "role") == RoleTool && str(msg, "tool_call_id") != "" {
			id := str(msg, "tool_call_id")
			toolResponses[id] = append(toolResponses[id], msg["content"])
		}
	}
	toolResponseCursor := map[string]int{}
	uniquifier := &toolCallIDUniquifier{used: map[string]bool{}}

	var contents []any
	for i, mv := range messages {
		msg, _ := mv.(map[string]any)
		if msg == nil {
			continue
		}
		role := str(msg, "role")
		content := msg["content"]

		switch {
		case role == RoleSystem && len(messages) > 1:
			text := ""
			if s, ok := content.(string); ok {
				text = s
			} else {
				text = extractTextContent(content, "")
			}
			result["systemInstruction"] = Body{
				"role":  GeminiRoleUser,
				"parts": []any{Body{"text": text}},
			}
		case role == RoleUser || (role == RoleSystem && len(messages) == 1):
			if parts := convertOpenAIContentToParts(content); len(parts) > 0 {
				contents = append(contents, Body{"role": GeminiRoleUser, "parts": parts})
			}
		case role == RoleAssistant:
			var parts []any
			if rc := str(msg, "reasoning_content"); rc != "" {
				parts = append(parts, Body{"thought": true, "text": rc})
				parts = append(parts, Body{"thoughtSignature": signature, "text": ""})
			}
			if content != nil {
				text := ""
				if s, ok := content.(string); ok {
					text = s
				} else {
					text = extractTextContent(content, "")
				}
				if text != "" {
					parts = append(parts, Body{"text": text})
				}
			}

			toolCalls := arr(msg, "tool_calls")
			if toolCalls == nil {
				if len(parts) > 0 {
					contents = append(contents, Body{"role": GeminiRoleModel, "parts": parts})
				}
				continue
			}

			type callRef struct{ origID, emitID, name string }
			var callRefs []callRef
			firstFunctionCallSeen := false
			for _, tv := range toolCalls {
				tc, ok := tv.(map[string]any)
				if !ok || str(tc, "type") != OpenAIBlockFunction {
					continue
				}
				fn := obj(tc, "function")
				if fn == nil {
					continue
				}
				var args any = Body{}
				if fn["arguments"] != nil {
					if parsed := safeParseJSON(fn["arguments"], nil); parsed != nil {
						args = parsed
					}
				}
				// No signature store in the port: cachedSig is always nil,
				// so the first call gets the fallback signature.
				callSig := ""
				if !firstFunctionCallSeen {
					callSig = signature
				}
				firstFunctionCallSeen = true
				emitID := uniquifier.next(str(tc, "id"))
				part := Body{
					"functionCall": Body{
						"id":   emitID,
						"name": sanitizeGeminiFunctionName(str(fn, "name")),
						"args": args,
					},
				}
				if callSig != "" {
					part["thoughtSignature"] = callSig
				}
				parts = append(parts, part)
				callRefs = append(callRefs, callRef{origID: str(tc, "id"), emitID: emitID, name: str(fn, "name")})
			}

			if len(parts) > 0 {
				contents = append(contents, Body{"role": GeminiRoleModel, "parts": parts})
			}

			isIntermediate := i < len(messages)-1
			hasActualResponses := false
			for _, ref := range callRefs {
				if toolResponseCursor[ref.origID] < len(toolResponses[ref.origID]) {
					hasActualResponses = true
				}
			}
			if hasActualResponses || isIntermediate {
				var toolParts []any
				for _, ref := range callRefs {
					queue := toolResponses[ref.origID]
					cursor := toolResponseCursor[ref.origID]
					var resp any = ""
					if cursor < len(queue) {
						resp = queue[cursor]
						toolResponseCursor[ref.origID] = cursor + 1
					}
					name := ref.name
					if name == "" {
						name = tcID2Name[ref.origID]
					}
					if name == "" {
						idParts := strings.Split(ref.origID, "-")
						if len(idParts) > 2 {
							name = strings.Join(idParts[:len(idParts)-2], "-")
						} else {
							name = ref.origID
						}
					}
					parsedResp := safeParseJSON(resp, nil)
					var resultVal any
					if parsedResp == nil {
						resultVal = Body{"result": resp}
					} else if _, isObj := parsedResp.(map[string]any); isObj {
						resultVal = parsedResp
					} else if _, isArr := parsedResp.([]any); isArr {
						resultVal = parsedResp
					} else {
						resultVal = Body{"result": parsedResp}
					}
					toolParts = append(toolParts, Body{
						"functionResponse": Body{
							"id":       ref.emitID,
							"name":     sanitizeGeminiFunctionName(name),
							"response": Body{"result": resultVal},
						},
					})
				}
				if len(toolParts) > 0 {
					contents = append(contents, Body{"role": GeminiRoleUser, "parts": toolParts})
				}
			}
		}
	}

	if tools := arr(body, "tools"); len(tools) > 0 {
		var declarations []any
		for _, tv := range tools {
			t, _ := tv.(map[string]any)
			if t == nil {
				continue
			}
			if str(t, "name") != "" && has(t, "input_schema") {
				schema := deepCopyValue(t["input_schema"])
				if schema == nil {
					schema = Body{"type": "object", "properties": Body{}}
				}
				declarations = append(declarations, Body{
					"name":        sanitizeGeminiFunctionName(str(t, "name")),
					"description": stringOrEmpty(t["description"]),
					"parameters":  cleanJSONSchemaForAntigravity(schema),
				})
			} else if str(t, "type") == OpenAIBlockFunction && obj(t, "function") != nil {
				fn := obj(t, "function")
				schema := deepCopyValue(fn["parameters"])
				if schema == nil {
					schema = Body{"type": "object", "properties": Body{}}
				}
				declarations = append(declarations, Body{
					"name":        sanitizeGeminiFunctionName(str(fn, "name")),
					"description": stringOrEmpty(fn["description"]),
					"parameters":  cleanJSONSchemaForAntigravity(schema),
				})
			}
		}
		if len(declarations) > 0 {
			result["tools"] = []any{Body{"functionDeclarations": declarations}}
		}
	}

	result["contents"] = normalizeGeminiContents(contents, model)
	return result
}

// ---------- stream: gemini -> openai (response/gemini-to-openai.js) ----------
// The JS stores thought signatures in a service-side store keyed by call
// id; the port keeps the pending signature in StreamState only (the
// store itself belongs to the services layer, out of this package).

func geminiChunkMeta(state *StreamState) (string, int64, string) {
	return "chatcmpl-" + state.MessageID, nowUnix(), state.Model
}

func emitGeminiFunctionCall(fc Body, state *StreamState, signature string) Body {
	rawName := str(fc, "name")
	fcName := rawName
	if state.ToolNameMap != nil {
		if orig, ok := state.ToolNameMap[rawName]; ok {
			fcName = orig
		}
	}
	args := fc["args"]
	if args == nil {
		args = Body{}
	}
	toolCallIndex := state.FunctionIndex
	state.FunctionIndex++
	callID := str(fc, "id")
	if callID == "" {
		callID = fcName + "-" + itoa64(nowMillis()) + "-" + itoa(toolCallIndex)
	}
	_ = signature // stored server-side in the JS; see note above.
	toolCall := Body{
		"id":    callID,
		"index": toolCallIndex,
		"type":  OpenAIBlockFunction,
		"function": Body{
			"name":      fcName,
			"arguments": stringifyJSON(args),
		},
	}
	state.GeminiToolCallCount++
	id, created, model := geminiChunkMeta(state)
	return buildChunk(id, created, model, Body{"tool_calls": []any{toolCall}}, nil)
}

func geminiToOpenAIChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		return nil, nil
	}
	response := obj(chunk, "response")
	if response == nil {
		response = chunk
	}
	candidates := arr(response, "candidates")
	if len(candidates) == 0 {
		return nil, nil
	}
	candidate, _ := candidates[0].(map[string]any)
	if candidate == nil {
		return nil, nil
	}
	content := obj(candidate, "content")

	var results []Body

	if state.MessageID == "" {
		if id := str(response, "responseId"); id != "" {
			state.MessageID = id
		} else {
			state.MessageID = "msg_" + itoa64(nowMillis())
		}
		// JS: state.model = response.modelVersion || state.model || "gemini"
		if mv := str(response, "modelVersion"); mv != "" {
			state.Model = mv
		}
		if state.Model == "" {
			state.Model = "gemini"
		}
		state.FunctionIndex = 0
		state.GeminiToolCallCount = 0
		id, created, model := geminiChunkMeta(state)
		results = append(results, buildChunk(id, created, model, Body{"role": RoleAssistant}, nil))
	}

	if content != nil {
		for _, pv := range arr(content, "parts") {
			part, ok := pv.(map[string]any)
			if !ok {
				continue
			}
			sig := str(part, "thoughtSignature")
			if sig == "" {
				sig = str(part, "thought_signature")
			}
			hasSig := sig != ""
			if hasSig {
				state.PendingThoughtSignature = sig
			}
			isThought, _ := part["thought"].(bool)

			if hasSig {
				hasText := has(part, "text") && str(part, "text") != ""
				hasCall := obj(part, "functionCall") != nil
				if !hasText && !hasCall {
					continue
				}
				if hasText {
					id, created, model := geminiChunkMeta(state)
					var delta Body
					if isThought {
						delta = reasoningDelta(str(part, "text"))
					} else {
						delta = Body{"content": str(part, "text")}
					}
					results = append(results, buildChunk(id, created, model, delta, nil))
				}
				if hasCall {
					results = append(results, emitGeminiFunctionCall(obj(part, "functionCall"), state, sig))
					state.PendingThoughtSignature = ""
				}
				continue
			}

			if has(part, "text") && str(part, "text") != "" {
				id, created, model := geminiChunkMeta(state)
				var delta Body
				if isThought {
					delta = reasoningDelta(str(part, "text"))
				} else {
					delta = Body{"content": str(part, "text")}
				}
				results = append(results, buildChunk(id, created, model, delta, nil))
			}

			if fc := obj(part, "functionCall"); fc != nil {
				s := state.PendingThoughtSignature
				results = append(results, emitGeminiFunctionCall(fc, state, s))
				state.PendingThoughtSignature = ""
			}

			inline := obj(part, "inlineData")
			if inline == nil {
				inline = obj(part, "inline_data")
			}
			if inline != nil && str(inline, "data") != "" {
				mime := str(inline, "mimeType")
				if mime == "" {
					mime = str(inline, "mime_type")
				}
				if mime == "" {
					mime = DefaultImageMIME
				}
				id, created, model := geminiChunkMeta(state)
				results = append(results, buildChunk(id, created, model, Body{
					"images": []any{Body{
						"type":      OpenAIBlockImageURL,
						"image_url": Body{"url": encodeDataURI(mime, str(inline, "data"))},
					}},
				}, nil))
			}
		}
	}

	usageMeta := obj(response, "usageMetadata")
	if usageMeta == nil {
		usageMeta = obj(chunk, "usageMetadata")
	}
	if usageMeta != nil {
		if u := toOpenAIUsage(usageMeta, "gemini"); u != nil {
			state.Usage = u
		}
	}

	if finishReason := str(candidate, "finishReason"); finishReason != "" {
		mapped := toOpenAIFinish(finishReason, "gemini")
		if mapped == OpenAIFinishStop && state.GeminiToolCallCount > 0 {
			mapped = OpenAIFinishToolCalls
		}
		id, created, model := geminiChunkMeta(state)
		finalChunk := buildChunk(id, created, model, Body{}, mapped)
		if state.Usage != nil {
			finalChunk["usage"] = state.Usage
		}
		results = append(results, finalChunk)
		state.FinishReason = mapped
	}

	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// ---------- stream: openai -> gemini ----------
// NOTE: the JS has no openai->gemini response translator (Gemini-format
// clients are served by the gemini executors directly, and openai->gemini
// exists only for antigravity envelopes). This converter is an addition
// for contract symmetry: text/reasoning stream as parts, tool-call
// argument fragments are buffered and emitted as complete functionCall
// parts at finish, since Gemini chunks cannot carry partial JSON args.

func openaiToGeminiChunk(chunk Body, state *StreamState) ([]Body, error) {
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
	if state.MessageID == "" {
		state.MessageID = str(chunk, "id")
		state.Model = str(chunk, "model")
	}
	delta := obj(choice, "delta")

	var parts []any
	if delta != nil {
		if rc := extractReasoningText(delta); rc != "" {
			parts = append(parts, Body{"text": rc, "thought": true})
		}
		if content := str(delta, "content"); content != "" {
			parts = append(parts, Body{"text": content})
		}
		for _, tv := range arr(delta, "tool_calls") {
			tc, ok := tv.(map[string]any)
			if !ok {
				continue
			}
			idx := intVal(tc["index"])
			entry := state.ToolCalls[idx]
			if entry == nil {
				entry = &ToolCallState{Index: idx, ID: str(tc, "id")}
				state.ToolCalls[idx] = entry
			}
			if fn := obj(tc, "function"); fn != nil {
				if n := str(fn, "name"); n != "" {
					entry.Name = n
				}
				entry.Args += str(fn, "arguments")
			}
		}
	}

	candidate := Body{}
	if len(parts) > 0 {
		candidate["content"] = Body{"role": GeminiRoleModel, "parts": parts}
	}

	finishReason := str(choice, "finish_reason")
	if finishReason != "" {
		// Flush buffered tool calls as complete functionCall parts.
		var callParts []any
		for idx := 0; idx <= maxToolIndex(state); idx++ {
			entry := state.ToolCalls[idx]
			if entry == nil || entry.Name == "" {
				continue
			}
			var args any = Body{}
			if entry.Args != "" {
				if parsed := safeParseJSON(entry.Args, nil); parsed != nil {
					args = parsed
				}
			}
			fc := Body{"name": entry.Name, "args": args}
			if entry.ID != "" {
				fc["id"] = entry.ID
			}
			callParts = append(callParts, Body{"functionCall": fc})
		}
		if len(callParts) > 0 {
			content := obj(candidate, "content")
			if content == nil {
				content = Body{"role": GeminiRoleModel, "parts": []any{}}
				candidate["content"] = content
			}
			content["parts"] = append(arr(content, "parts"), callParts...)
		}
		if len(state.ToolCalls) > 0 && finishReason == OpenAIFinishStop {
			finishReason = OpenAIFinishToolCalls
		}
		candidate["finishReason"] = fromOpenAIToGeminiFinish(finishReason)
		state.FinishReason = finishReason
	}

	if usage := obj(chunk, "usage"); usage != nil {
		state.Usage = usage
	}
	if state.Usage != nil && finishReason != "" {
		meta := Body{
			"promptTokenCount":     intVal(state.Usage["prompt_tokens"]),
			"candidatesTokenCount": intVal(state.Usage["completion_tokens"]),
			"totalTokenCount":      intVal(state.Usage["total_tokens"]),
		}
		if details := obj(state.Usage, "completion_tokens_details"); details != nil {
			if rt := intVal(details["reasoning_tokens"]); rt != 0 {
				meta["thoughtsTokenCount"] = rt
			}
		}
		candidate["usageMetadata"] = meta
		_ = candidate
	}

	if len(candidate) == 0 {
		return nil, nil
	}
	out := Body{"candidates": []any{candidate}}
	if usageMeta := obj(candidate, "usageMetadata"); usageMeta != nil {
		out["usageMetadata"] = usageMeta
		delete(candidate, "usageMetadata")
	}
	if id := str(chunk, "id"); id != "" {
		out["responseId"] = id
	}
	if m := str(chunk, "model"); m != "" {
		out["modelVersion"] = m
	}
	return []Body{out}, nil
}

// ---------- non-streaming bodies: gemini <-> openai ----------

func geminiToOpenAIBody(body Body) (Body, error) {
	resp := body
	candidates := arr(resp, "candidates")
	var candidate Body
	if len(candidates) > 0 {
		candidate, _ = candidates[0].(map[string]any)
	}
	message := Body{"role": RoleAssistant}
	var textParts []string
	var contentParts []any
	var toolCalls []any
	var reasoningParts []string
	finishReason := OpenAIFinishStop
	if candidate != nil {
		if content := obj(candidate, "content"); content != nil {
			for _, pv := range arr(content, "parts") {
				part, ok := pv.(map[string]any)
				if !ok {
					continue
				}
				isThought, _ := part["thought"].(bool)
				if has(part, "text") {
					if isThought {
						reasoningParts = append(reasoningParts, str(part, "text"))
					} else {
						textParts = append(textParts, str(part, "text"))
					}
				}
				if fc := obj(part, "functionCall"); fc != nil {
					id := str(fc, "id")
					if id == "" {
						id = "call_" + str(fc, "name")
					}
					args := fc["args"]
					if args == nil {
						args = Body{}
					}
					toolCalls = append(toolCalls, Body{
						"id":   id,
						"type": OpenAIBlockFunction,
						"function": Body{
							"name":      str(fc, "name"),
							"arguments": stringifyJSON(args),
						},
					})
				}
				inline := obj(part, "inlineData")
				if inline == nil {
					inline = obj(part, "inline_data")
				}
				if inline != nil && str(inline, "data") != "" {
					mime := str(inline, "mimeType")
					if mime == "" {
						mime = str(inline, "mime_type")
					}
					if mime == "" {
						mime = DefaultImageMIME
					}
					contentParts = append(contentParts, Body{
						"type":      OpenAIBlockImageURL,
						"image_url": Body{"url": encodeDataURI(mime, str(inline, "data"))},
					})
				}
			}
		}
		if fr := str(candidate, "finishReason"); fr != "" {
			finishReason = toOpenAIFinish(fr, "gemini")
		}
	}
	text := strings.Join(textParts, "")
	if len(contentParts) > 0 {
		var parts []any
		if text != "" {
			parts = append(parts, Body{"type": OpenAIBlockText, "text": text})
		}
		parts = append(parts, contentParts...)
		message["content"] = parts
	} else if text != "" {
		message["content"] = text
	} else {
		message["content"] = nil
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
		if finishReason == OpenAIFinishStop {
			finishReason = OpenAIFinishToolCalls
		}
	}
	if len(reasoningParts) > 0 {
		message["reasoning_content"] = strings.Join(reasoningParts, "")
	}
	id := str(resp, "responseId")
	out := Body{
		"id":      "chatcmpl-" + id,
		"object":  "chat.completion",
		"created": nowUnix(),
		"model":   str(resp, "modelVersion"),
		"choices": []any{Body{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
	}
	if id == "" {
		out["id"] = "chatcmpl-" + itoa64(nowMillis())
	}
	if usageMeta := obj(resp, "usageMetadata"); usageMeta != nil {
		out["usage"] = toOpenAIUsage(usageMeta, "gemini")
	}
	return out, nil
}

func openaiToGeminiBody(body Body) (Body, error) {
	choices := arr(body, "choices")
	var choice Body
	if len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	var parts []any
	finishReason := OpenAIFinishStop
	if choice != nil {
		if fr := str(choice, "finish_reason"); fr != "" {
			finishReason = fr
		}
		msg := obj(choice, "message")
		if msg != nil {
			if rc := str(msg, "reasoning_content"); rc != "" {
				parts = append(parts, Body{"text": rc, "thought": true})
			}
			switch content := msg["content"].(type) {
			case string:
				if content != "" {
					parts = append(parts, Body{"text": content})
				}
			case []any:
				parts = append(parts, convertOpenAIContentToParts(content)...)
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
				var args any = Body{}
				if fn["arguments"] != nil {
					if parsed := safeParseJSON(fn["arguments"], nil); parsed != nil {
						args = parsed
					}
				}
				fc := Body{"name": str(fn, "name"), "args": args}
				if id := str(tc, "id"); id != "" {
					fc["id"] = id
				}
				parts = append(parts, Body{"functionCall": fc})
			}
		}
	}
	if parts == nil {
		parts = []any{}
	}
	candidate := Body{
		"content":      Body{"role": GeminiRoleModel, "parts": parts},
		"finishReason": fromOpenAIToGeminiFinish(finishReason),
		"index":        0,
	}
	out := Body{
		"candidates":   []any{candidate},
		"modelVersion": str(body, "model"),
	}
	if id := str(body, "id"); id != "" {
		out["responseId"] = strings.TrimPrefix(id, "chatcmpl-")
	}
	if usage := obj(body, "usage"); usage != nil {
		meta := Body{
			"promptTokenCount":     intVal(usage["prompt_tokens"]),
			"candidatesTokenCount": intVal(usage["completion_tokens"]),
			"totalTokenCount":      intVal(usage["total_tokens"]),
		}
		if details := obj(usage, "prompt_tokens_details"); details != nil {
			if ct := intVal(details["cached_tokens"]); ct != 0 {
				meta["cachedContentTokenCount"] = ct
			}
		}
		out["usageMetadata"] = meta
	}
	return out, nil
}

func init() {
	Register(FormatGemini, FormatOpenAI, geminiToOpenAIRequest, geminiToOpenAIChunk)
	Register(FormatGeminiCLI, FormatOpenAI, geminiToOpenAIRequest, geminiToOpenAIChunk)
	Register(FormatAntigravity, FormatOpenAI, nil, geminiToOpenAIChunk)
	Register(FormatVertex, FormatOpenAI, nil, geminiToOpenAIChunk)
	Register(FormatOpenAI, FormatGemini, openaiToGeminiRequest, openaiToGeminiChunk)
	// gemini-cli requests use the base conversion; the Cloud Code
	// envelope wrap (credentials/session) is TODO — see gemini.go note.
	Register(FormatOpenAI, FormatGeminiCLI, openaiToGeminiRequest, nil)
	registerBody(FormatGemini, FormatOpenAI, geminiToOpenAIBody)
	registerBody(FormatOpenAI, FormatGemini, openaiToGeminiBody)
}
