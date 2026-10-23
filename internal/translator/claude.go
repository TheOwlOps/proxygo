package translator

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ---------- request: claude -> openai (request/claude-to-openai.js) ----------

var billingHeaderRe = regexp.MustCompile(`(?i)^x-anthropic-billing-header:[^\n]*(?:\r?\n)?`)

func stripAnthropicBillingHeader(text string) string {
	if text == "" {
		return ""
	}
	return billingHeaderRe.ReplaceAllString(text, "")
}

func claudeToOpenAIRequest(body Body) (Body, error) {
	result := Body{
		"model":    str(body, "model"),
		"messages": []any{},
		"stream":   streamOrDefault(body),
	}
	if v, ok := num(body, "max_tokens"); ok && v != 0 {
		result["max_tokens"] = adjustMaxTokens(body, 0)
	}
	if has(body, "temperature") {
		result["temperature"] = body["temperature"]
	}

	if has(body, "system") {
		var systemContent string
		switch sys := body["system"].(type) {
		case []any:
			var parts []string
			for _, sv := range sys {
				if sb, ok := sv.(map[string]any); ok {
					if t := stripAnthropicBillingHeader(str(sb, "text")); t != "" {
						parts = append(parts, t)
					}
				}
			}
			systemContent = strings.Join(parts, "\n")
		case string:
			systemContent = stripAnthropicBillingHeader(sys)
		}
		if systemContent != "" {
			result["messages"] = append(arr(result, "messages"),
				Body{"role": RoleSystem, "content": systemContent})
		}
	}

	if messages := arr(body, "messages"); messages != nil {
		out := arr(result, "messages")
		for _, mv := range messages {
			msg, ok := mv.(map[string]any)
			if !ok {
				continue
			}
			converted := convertClaudeMessage(msg)
			out = append(out, converted...)
		}
		result["messages"] = out
	}

	fixMissingToolResponsesOpenAI(result)

	if tools := arr(body, "tools"); tools != nil {
		var out []any
		for _, tv := range tools {
			tool, _ := tv.(map[string]any)
			params := obj(tool, "input_schema")
			if params == nil {
				params = Body{"type": "object", "properties": Body{}}
			}
			out = append(out, Body{
				"type": OpenAIBlockFunction,
				"function": Body{
					"name":        str(tool, "name"),
					"description": stringOrEmpty(tool["description"]),
					"parameters":  params,
				},
			})
		}
		result["tools"] = out
	}

	if has(body, "tool_choice") {
		result["tool_choice"] = convertClaudeToolChoice(body["tool_choice"])
	}
	if has(body, "reasoning_effort") {
		result["reasoning_effort"] = body["reasoning_effort"]
	} else if reasoning := obj(body, "reasoning"); reasoning != nil && has(reasoning, "effort") {
		result["reasoning_effort"] = reasoning["effort"]
	}
	if has(body, "reasoning") {
		result["reasoning"] = body["reasoning"]
	}
	return result, nil
}

// streamOrDefault reads body.stream, defaulting to true like the JS
// translateRequest(stream=true) parameter.
func streamOrDefault(body Body) bool {
	if v, ok := body["stream"].(bool); ok {
		return v
	}
	if has(body, "stream") {
		return truthy(body["stream"])
	}
	return true
}

// fixMissingToolResponsesOpenAI ports the local variant in
// claude-to-openai.js (contiguous tool replies, "[No response received]").
func fixMissingToolResponsesOpenAI(result Body) {
	messages := arr(result, "messages")
	for i := 0; i < len(messages); i++ {
		msg, _ := messages[i].(map[string]any)
		if msg == nil || str(msg, "role") != RoleAssistant {
			continue
		}
		toolCalls := arr(msg, "tool_calls")
		if len(toolCalls) == 0 {
			continue
		}
		var ids []string
		for _, tv := range toolCalls {
			if tc, ok := tv.(map[string]any); ok {
				ids = append(ids, str(tc, "id"))
			}
		}
		responded := map[string]bool{}
		insertPos := i + 1
		for j := i + 1; j < len(messages); j++ {
			next, _ := messages[j].(map[string]any)
			if next != nil && str(next, "role") == RoleTool && str(next, "tool_call_id") != "" {
				responded[str(next, "tool_call_id")] = true
				insertPos = j + 1
			} else {
				break
			}
		}
		var missing []any
		for _, id := range ids {
			if !responded[id] {
				missing = append(missing, Body{
					"role": RoleTool, "tool_call_id": id, "content": "[No response received]",
				})
			}
		}
		if len(missing) > 0 {
			tail := append([]any{}, messages[insertPos:]...)
			messages = append(messages[:insertPos], append(missing, tail...)...)
			i = insertPos + len(missing) - 1
		}
	}
	result["messages"] = messages
}

func systemReminderText(content any) string {
	var parts []string
	switch c := content.(type) {
	case []any:
		for _, cv := range c {
			if block, ok := cv.(map[string]any); ok && str(block, "type") == ClaudeBlockText {
				parts = append(parts, str(block, "text"))
			}
		}
	case string:
		parts = []string{c}
	}
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	text := strings.Join(nonEmpty, "\n")
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return "<instructions>\n" + text + "\n</instructions>"
}

// convertClaudeMessage returns 0..n OpenAI messages, like the JS version.
func convertClaudeMessage(msg Body) []any {
	content := msg["content"]
	if content != nil {
		if _, isArr := content.([]any); !isArr {
			if _, isStr := content.(string); !isStr {
				content = []any{content}
				msg = deepCopyBody(msg)
				msg["content"] = content
			}
		}
	}

	if str(msg, "role") == RoleSystem {
		text := systemReminderText(content)
		if text == "" {
			return nil
		}
		return []any{Body{"role": RoleUser, "content": text}}
	}

	role := RoleAssistant
	if r := str(msg, "role"); r == RoleUser || r == RoleTool {
		role = RoleUser
	}

	if s, isStr := content.(string); isStr {
		return []any{Body{"role": role, "content": s}}
	}

	parts, ok := content.([]any)
	if !ok {
		return nil
	}
	var textParts []any
	var toolCalls []any
	var toolResults []any

	for _, bv := range parts {
		block, ok := bv.(map[string]any)
		if !ok {
			continue
		}
		switch str(block, "type") {
		case ClaudeBlockText:
			textParts = append(textParts, Body{"type": OpenAIBlockText, "text": str(block, "text")})
		case ClaudeBlockImage:
			if src := obj(block, "source"); src != nil && str(src, "type") == "base64" {
				textParts = append(textParts, Body{
					"type":      OpenAIBlockImageURL,
					"image_url": Body{"url": encodeDataURI(str(src, "media_type"), str(src, "data"))},
				})
			}
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
		case ClaudeBlockToolResult:
			resultContent := ""
			var resultImages []any
			switch c := block["content"].(type) {
			case string:
				resultContent = c
			case []any:
				var texts []string
				for _, cv := range c {
					cb, _ := cv.(map[string]any)
					if cb == nil {
						continue
					}
					if str(cb, "type") == ClaudeBlockImage {
						if src := obj(cb, "source"); src != nil && str(src, "type") == "base64" {
							resultImages = append(resultImages, Body{
								"type":      OpenAIBlockImageURL,
								"image_url": Body{"url": encodeDataURI(str(src, "media_type"), str(src, "data"))},
							})
						}
					}
					if str(cb, "type") == ClaudeBlockText {
						texts = append(texts, str(cb, "text"))
					}
				}
				resultContent = strings.Join(texts, "\n")
				if resultContent == "" && len(resultImages) == 0 {
					resultContent = stringifyJSON(c)
				}
			default:
				if block["content"] != nil {
					resultContent = stringifyJSON(block["content"])
				}
			}
			toolResults = append(toolResults, Body{
				"role": RoleTool, "tool_call_id": str(block, "tool_use_id"), "content": resultContent,
			})
			if len(resultImages) > 0 {
				textParts = append(textParts, Body{
					"type": OpenAIBlockText,
					"text": "[Image from tool result " + str(block, "tool_use_id") + "]",
				})
				textParts = append(textParts, resultImages...)
			}
		}
	}

	if len(toolResults) > 0 {
		if len(textParts) > 0 {
			return append(toolResults, Body{"role": RoleUser, "content": collapseTextParts(textParts)})
		}
		return toolResults
	}
	if len(toolCalls) > 0 {
		out := Body{"role": RoleAssistant}
		if len(textParts) > 0 {
			out["content"] = collapseTextParts(textParts)
		}
		out["tool_calls"] = toolCalls
		return []any{out}
	}
	if len(textParts) > 0 {
		return []any{Body{"role": role, "content": collapseTextParts(textParts)}}
	}
	if len(parts) == 0 {
		return []any{Body{"role": role, "content": ""}}
	}
	return nil
}

func convertClaudeToolChoice(choice any) any {
	if choice == nil {
		return "auto"
	}
	if s, ok := choice.(string); ok {
		return s
	}
	if c, ok := choice.(map[string]any); ok {
		switch str(c, "type") {
		case "auto":
			return "auto"
		case "any":
			return "required"
		case "tool":
			return Body{"type": OpenAIBlockFunction, "function": Body{"name": str(c, "name")}}
		default:
			return "auto"
		}
	}
	return "auto"
}

// ---------- request: openai -> claude (request/openai-to-claude.js) ----------

// claudeOAuthToolPrefix is "" in the JS (CLAUDE_OAUTH_TOOL_PREFIX), kept
// as a named constant so the mapping logic survives a future prefix.
const claudeOAuthToolPrefix = ""

func openaiToClaudeRequest(body Body) (Body, error) {
	toolNameMap := map[string]string{}
	// JS passes the model's real maxOutput ceiling from the capabilities
	// table; that table belongs to the providers package, so the port
	// uses adjustMaxTokens' conservative default ceiling (64000).
	result := Body{
		"model":      str(body, "model"),
		"max_tokens": adjustMaxTokens(body, 0),
		"stream":     streamOrDefault(body),
	}
	if has(body, "temperature") {
		result["temperature"] = body["temperature"]
	}

	var messages []any
	var systemParts []string

	if raw := arr(body, "messages"); raw != nil {
		for _, mv := range raw {
			if msg, ok := mv.(map[string]any); ok && str(msg, "role") == RoleSystem {
				if s, isStr := msg["content"].(string); isStr {
					systemParts = append(systemParts, s)
				} else {
					systemParts = append(systemParts, extractTextContent(msg["content"], "\n"))
				}
			}
		}

		var currentRole string
		var currentParts []any
		flush := func() {
			if currentRole != "" && len(currentParts) > 0 {
				messages = append(messages, Body{"role": currentRole, "content": currentParts})
				currentParts = nil
			}
		}

		for _, mv := range raw {
			msg, ok := mv.(map[string]any)
			if !ok || str(msg, "role") == RoleSystem {
				continue
			}
			newRole := RoleAssistant
			if r := str(msg, "role"); r == RoleUser || r == RoleTool {
				newRole = RoleUser
			}
			blocks := claudeBlocksFromMessage(msg, toolNameMap)
			hasToolUse, hasToolResult := false, false
			for _, bv := range blocks {
				if b, ok := bv.(map[string]any); ok {
					if str(b, "type") == ClaudeBlockToolUse {
						hasToolUse = true
					}
					if str(b, "type") == ClaudeBlockToolResult {
						hasToolResult = true
					}
				}
			}

			if hasToolResult {
				var toolResultBlocks, otherBlocks []any
				for _, bv := range blocks {
					if b, ok := bv.(map[string]any); ok && str(b, "type") == ClaudeBlockToolResult {
						toolResultBlocks = append(toolResultBlocks, bv)
					} else {
						otherBlocks = append(otherBlocks, bv)
					}
				}
				flush()
				if len(toolResultBlocks) > 0 {
					messages = append(messages, Body{"role": RoleUser, "content": toolResultBlocks})
				}
				if len(otherBlocks) > 0 {
					currentRole = newRole
					currentParts = append(currentParts, otherBlocks...)
				}
				continue
			}

			if currentRole != newRole {
				flush()
				currentRole = newRole
			}
			currentParts = append(currentParts, blocks...)
			if hasToolUse {
				flush()
			}
		}
		flush()

		// cache_control on the last block of the last assistant message.
		for i := len(messages) - 1; i >= 0; i-- {
			message, _ := messages[i].(map[string]any)
			if message == nil || str(message, "role") != RoleAssistant {
				continue
			}
			content := arr(message, "content")
			if len(content) == 0 {
				continue
			}
			valid := map[string]bool{
				ClaudeBlockText: true, ClaudeBlockToolUse: true,
				ClaudeBlockToolResult: true, ClaudeBlockImage: true,
			}
			for j := len(content) - 1; j >= 0; j-- {
				if block, ok := content[j].(map[string]any); ok && valid[str(block, "type")] {
					block["cache_control"] = Body{"type": "ephemeral"}
					break
				}
			}
			break
		}
	}
	result["messages"] = messages

	if rf := obj(body, "response_format"); rf != nil {
		switch str(rf, "type") {
		case "json_schema":
			if js := obj(rf, "json_schema"); js != nil && has(js, "schema") {
				schemaJSON := stringifyJSONIndent(js["schema"])
				systemParts = append(systemParts, "You must respond with valid JSON that strictly follows this JSON schema:\n```json\n"+schemaJSON+"\n```\nRespond ONLY with the JSON object, no other text.")
			}
		case "json_object":
			systemParts = append(systemParts, "You must respond with valid JSON. Respond ONLY with a JSON object, no other text.")
		}
	}

	claudeCodePrompt := Body{"type": ClaudeBlockText, "text": ClaudeSystemPrompt}
	if len(systemParts) > 0 {
		result["system"] = []any{
			claudeCodePrompt,
			Body{"type": ClaudeBlockText, "text": strings.Join(systemParts, "\n"),
				"cache_control": Body{"type": "ephemeral", "ttl": "1h"}},
		}
	} else {
		result["system"] = []any{claudeCodePrompt}
	}

	if tools := arr(body, "tools"); tools != nil {
		var out []any
		for _, tv := range tools {
			tool, ok := tv.(map[string]any)
			if !ok {
				continue
			}
			if t := str(tool, "type"); t != "" && t != OpenAIBlockFunction {
				out = append(out, tool)
				continue
			}
			toolData := obj(tool, "function")
			if toolData == nil {
				toolData = tool
			}
			originalName := str(toolData, "name")
			toolName := claudeOAuthToolPrefix + originalName
			toolNameMap[toolName] = originalName
			params := obj(toolData, "parameters")
			if params == nil {
				params = obj(toolData, "input_schema")
			}
			if params == nil {
				params = Body{"type": "object", "properties": Body{}, "required": []any{}}
			}
			out = append(out, Body{
				"name":         toolName,
				"description":  stringOrEmpty(toolData["description"]),
				"input_schema": params,
			})
		}
		if len(out) > 0 {
			if last, ok := out[len(out)-1].(map[string]any); ok {
				last["cache_control"] = Body{"type": "ephemeral", "ttl": "1h"}
			}
		}
		result["tools"] = out
	}

	if has(body, "tool_choice") {
		result["tool_choice"] = convertOpenAIToolChoice(body["tool_choice"])
	}
	if len(toolNameMap) > 0 {
		result["_toolNameMap"] = toolNameMap
	}
	return result, nil
}

// stringifyJSONIndent mirrors JSON.stringify(v, null, 2).
func stringifyJSONIndent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return stringifyJSON(v)
	}
	return string(b)
}

func claudeBlocksFromMessage(msg Body, toolNameMap map[string]string) []any {
	var blocks []any
	role := str(msg, "role")

	switch role {
	case RoleTool:
		blocks = append(blocks, Body{
			"type": ClaudeBlockToolResult, "tool_use_id": str(msg, "tool_call_id"), "content": msg["content"],
		})
	case RoleUser:
		if s, isStr := msg["content"].(string); isStr {
			if s != "" {
				blocks = append(blocks, Body{"type": ClaudeBlockText, "text": s})
			}
		} else if parts := arr(msg, "content"); parts != nil {
			for _, pv := range parts {
				part, ok := pv.(map[string]any)
				if !ok {
					continue
				}
				switch str(part, "type") {
				case OpenAIBlockText:
					if t := str(part, "text"); t != "" {
						blocks = append(blocks, Body{"type": ClaudeBlockText, "text": t})
					}
				case ClaudeBlockToolResult:
					b := Body{
						"type": ClaudeBlockToolResult, "tool_use_id": str(part, "tool_use_id"), "content": part["content"],
					}
					if truthy(part["is_error"]) {
						b["is_error"] = part["is_error"]
					}
					blocks = append(blocks, b)
				case OpenAIBlockImageURL:
					url := ""
					if iu := obj(part, "image_url"); iu != nil {
						url = str(iu, "url")
					}
					if mime, data, ok := parseDataURI(url); ok {
						blocks = append(blocks, Body{
							"type":   ClaudeBlockImage,
							"source": Body{"type": "base64", "media_type": mime, "data": data},
						})
					} else if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
						blocks = append(blocks, Body{
							"type":   ClaudeBlockImage,
							"source": Body{"type": "url", "url": url},
						})
					}
				case OpenAIBlockImage:
					if has(part, "source") {
						blocks = append(blocks, Body{"type": ClaudeBlockImage, "source": part["source"]})
					}
				case OpenAIBlockFile:
					if file := obj(part, "file"); file != nil {
						if mime, data, ok := parseDataURI(str(file, "file_data")); ok && mime == "application/pdf" {
							blocks = append(blocks, Body{
								"type":   ClaudeBlockDocument,
								"source": Body{"type": "base64", "media_type": mime, "data": data},
							})
						}
					}
				}
			}
		}
	case RoleAssistant:
		if parts := arr(msg, "content"); parts != nil {
			for _, pv := range parts {
				part, ok := pv.(map[string]any)
				if !ok {
					continue
				}
				switch str(part, "type") {
				case OpenAIBlockText:
					if t := str(part, "text"); t != "" {
						blocks = append(blocks, Body{"type": ClaudeBlockText, "text": t})
					}
				case ClaudeBlockToolUse:
					blocks = append(blocks, Body{
						"type": ClaudeBlockToolUse, "id": str(part, "id"), "name": str(part, "name"), "input": part["input"],
					})
				case ClaudeBlockThinking:
					cp := deepCopyBody(part)
					delete(cp, "cache_control")
					blocks = append(blocks, cp)
				}
			}
		} else if has(msg, "content") && msg["content"] != nil {
			text := ""
			if s, isStr := msg["content"].(string); isStr {
				text = s
			} else {
				text = extractTextContent(msg["content"], "\n")
			}
			if text != "" {
				blocks = append(blocks, Body{"type": ClaudeBlockText, "text": text})
			}
		}
		for _, tv := range arr(msg, "tool_calls") {
			tc, ok := tv.(map[string]any)
			if !ok || str(tc, "type") != OpenAIBlockFunction {
				continue
			}
			fn := obj(tc, "function")
			if fn == nil {
				continue
			}
			toolName := claudeOAuthToolPrefix + str(fn, "name")
			var input any = fn["arguments"]
			if fn["arguments"] != nil {
				input = safeParseJSON(fn["arguments"], fn["arguments"])
			}
			blocks = append(blocks, Body{
				"type": ClaudeBlockToolUse, "id": str(tc, "id"), "name": toolName, "input": input,
			})
		}
	}
	return blocks
}

var claudeToolChoiceTypes = map[string]bool{"auto": true, "any": true, "tool": true, "none": true}

// convertOpenAIToolChoice ports convertOpenAIToolChoice from
// openai-to-claude.js, including its never-leak-an-unknown-type rule.
func convertOpenAIToolChoice(choice any) any {
	if choice == nil {
		return Body{"type": "auto"}
	}
	if s, ok := choice.(string); ok {
		if s == "required" {
			return Body{"type": "any"}
		}
		return Body{"type": "auto"}
	}
	if c, ok := choice.(map[string]any); ok {
		if fn := obj(c, "function"); fn != nil && str(fn, "name") != "" {
			return Body{"type": "tool", "name": str(fn, "name")}
		}
		if claudeToolChoiceTypes[str(c, "type")] {
			return c
		}
	}
	return Body{"type": "auto"}
}

// ---------- prepareClaudeRequest, provider-independent subset ----------
// Port of formats/claude.js prepareClaudeRequest + fixToolUseOrdering +
// ensureTrailingUserTurn, minus everything that needs a provider id,
// capabilities table, API key or session (cloaking, thinking-signature
// handling, built-in tool filtering, output_config quirks).

func hasValidClaudeContent(msg Body) bool {
	contentful := map[string]bool{
		ClaudeBlockToolUse: true, ClaudeBlockToolResult: true, ClaudeBlockImage: true,
		ClaudeBlockDocument: true, ClaudeBlockContainerUpload: true,
	}
	isContentful := func(block Body) bool {
		if block == nil {
			return false
		}
		if str(block, "type") == ClaudeBlockText {
			return strings.TrimSpace(str(block, "text")) != ""
		}
		return contentful[str(block, "type")]
	}
	switch c := msg["content"].(type) {
	case string:
		return strings.TrimSpace(c) != ""
	case map[string]any:
		return isContentful(c)
	case []any:
		for _, bv := range c {
			if block, ok := bv.(map[string]any); ok && isContentful(block) {
				return true
			}
		}
	}
	return false
}

// fixToolUseOrdering ports fixToolUseOrdering from formats/claude.js.
func fixToolUseOrdering(messages []any) []any {
	if len(messages) <= 1 {
		return messages
	}
	for _, mv := range messages {
		msg, _ := mv.(map[string]any)
		if msg == nil || str(msg, "role") != RoleAssistant {
			continue
		}
		content := arr(msg, "content")
		if content == nil {
			continue
		}
		hasToolUse := false
		for _, bv := range content {
			if b, ok := bv.(map[string]any); ok && str(b, "type") == ClaudeBlockToolUse {
				hasToolUse = true
			}
		}
		if !hasToolUse {
			continue
		}
		var newContent []any
		foundToolUse := false
		for _, bv := range content {
			b, _ := bv.(map[string]any)
			btype := ""
			if b != nil {
				btype = str(b, "type")
			}
			switch {
			case btype == ClaudeBlockToolUse:
				foundToolUse = true
				newContent = append(newContent, bv)
			case btype == ClaudeBlockThinking || btype == ClaudeBlockRedactedThinking:
				newContent = append(newContent, bv)
			case !foundToolUse:
				newContent = append(newContent, bv)
			}
		}
		msg["content"] = newContent
	}

	var merged []any
	for _, mv := range messages {
		msg, _ := mv.(map[string]any)
		if msg == nil {
			merged = append(merged, mv)
			continue
		}
		if len(merged) > 0 {
			last, _ := merged[len(merged)-1].(map[string]any)
			if last != nil && str(last, "role") == str(msg, "role") {
				toBlocks := func(c any) []any {
					if a, ok := c.([]any); ok {
						return a
					}
					return []any{Body{"type": ClaudeBlockText, "text": stringOrEmpty(c)}}
				}
				lastContent := toBlocks(last["content"])
				msgContent := toBlocks(msg["content"])
				var toolResults, others []any
				for _, bv := range append(append([]any{}, lastContent...), msgContent...) {
					if b, ok := bv.(map[string]any); ok && str(b, "type") == ClaudeBlockToolResult {
						toolResults = append(toolResults, bv)
					} else {
						others = append(others, bv)
					}
				}
				last["content"] = append(toolResults, others...)
				continue
			}
		}
		content := msg["content"]
		if _, isArr := content.([]any); !isArr {
			msg["content"] = []any{Body{"type": ClaudeBlockText, "text": stringOrEmpty(content)}}
		} else {
			msg["content"] = append([]any{}, content.([]any)...)
		}
		merged = append(merged, msg)
	}
	return merged
}

// ensureTrailingUserTurn ports ensureTrailingUserTurn from formats/claude.js.
func ensureTrailingUserTurn(messages []any, originalLastRole string) []any {
	if len(messages) == 0 || originalLastRole == RoleAssistant {
		return messages
	}
	last, _ := messages[len(messages)-1].(map[string]any)
	if last == nil || str(last, "role") != RoleAssistant {
		return messages
	}
	return append(messages, Body{
		"role":    RoleUser,
		"content": []any{Body{"type": ClaudeBlockText, "text": "Continue."}},
	})
}

func prepareClaudeRequestLite(body Body, clientLastRole string) Body {
	// System: strip all cache_control, re-anchor the last block at 1h.
	if sys := arr(body, "system"); sys != nil {
		var out []any
		for i, sv := range sys {
			block, ok := sv.(map[string]any)
			if !ok {
				out = append(out, sv)
				continue
			}
			cp := deepCopyBody(block)
			delete(cp, "cache_control")
			if i == len(sys)-1 {
				cp["cache_control"] = Body{"type": "ephemeral", "ttl": "1h"}
			}
			out = append(out, cp)
		}
		body["system"] = out
	}

	if messages := arr(body, "messages"); messages != nil {
		originalLastRole := clientLastRole
		var filtered []any
		for i, mv := range messages {
			msg, ok := mv.(map[string]any)
			if !ok {
				continue
			}
			// Wrap bare content-block objects (normalizeMessageContent).
			if c, isObj := msg["content"].(map[string]any); isObj {
				cp := deepCopyBody(c)
				delete(cp, "cache_control")
				msg["content"] = []any{cp}
			}
			if content := arr(msg, "content"); content != nil {
				for _, bv := range content {
					if block, ok := bv.(map[string]any); ok {
						delete(block, "cache_control")
					}
				}
			}
			isFinalAssistant := i == len(messages)-1 && str(msg, "role") == RoleAssistant
			if isFinalAssistant || hasValidClaudeContent(msg) {
				filtered = append(filtered, msg)
			}
		}
		filtered = fixToolUseOrdering(filtered)
		filtered = ensureTrailingUserTurn(filtered, originalLastRole)
		body["messages"] = filtered

		// cache_control on the last block of the last assistant message.
		for i := len(filtered) - 1; i >= 0; i-- {
			msg, _ := filtered[i].(map[string]any)
			if msg == nil || str(msg, "role") != RoleAssistant {
				continue
			}
			content := arr(msg, "content")
			done := false
			for j := len(content) - 1; j >= 0; j-- {
				if block, ok := content[j].(map[string]any); ok {
					t := str(block, "type")
					if t != ClaudeBlockThinking && t != ClaudeBlockRedactedThinking {
						block["cache_control"] = Body{"type": "ephemeral"}
						done = true
						break
					}
				}
			}
			if done {
				break
			}
		}
	}

	// Tools: strip cache_control, re-anchor the last cacheable tool at 1h.
	if tools := arr(body, "tools"); tools != nil {
		lastCacheable := -1
		for i, tv := range tools {
			if tool, ok := tv.(map[string]any); ok {
				if deferLoading, _ := tool["defer_loading"].(bool); !deferLoading {
					lastCacheable = i
				}
			}
		}
		var out []any
		for i, tv := range tools {
			tool, ok := tv.(map[string]any)
			if !ok {
				out = append(out, tv)
				continue
			}
			cp := deepCopyBody(tool)
			delete(cp, "cache_control")
			if i == lastCacheable {
				cp["cache_control"] = Body{"type": "ephemeral", "ttl": "1h"}
			}
			out = append(out, cp)
		}
		body["tools"] = out
		if len(out) == 0 {
			delete(body, "tools")
			delete(body, "tool_choice")
		}
	}
	return body
}
