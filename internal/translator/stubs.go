package translator

import (
	"fmt"
	"strings"
)

// ---------- kiro / cursor registration ----------
//
// Kiro is fully ported (Phase 2, Team M): see kiro_request.go,
// kiro_response.go, kiro_conversation.go, kiro_session.go and
// kiro_constants.go. The registrations live in the init() below so the
// wiring stays next to the cursor pairs.
//
// Cursor (request/openai-to-cursor.js, response/cursor-to-openai.js):
// both sides are ported (Phase 2, Team L). The request side rewrites
// OpenAI messages into Cursor's ask/agent text shapes — tool outputs
// become <tool_result> text blocks because Cursor can loop when they
// are sent as protobuf tool_results with partial schema mismatches.
// The protobuf framing itself happens in the executor
// (internal/executors, cursor_protobuf.go). The response side is a
// documented passthrough, because CursorExecutor already emits
// OpenAI-shaped chunks.

func todoStub(pair, what string) error {
	return fmt.Errorf("translator: TODO %s not ported (%s)", pair, what)
}

// ---------- openai -> cursor request (request/openai-to-cursor.js) ----------

// extractCursorContent ports extractContent(): string content as-is,
// otherwise the concatenation of OpenAI text parts.
func extractCursorContent(content any) string {
	switch c := content.(type) {
	case string:
		return c
	case []any:
		var sb strings.Builder
		for _, part := range c {
			pm, ok := part.(map[string]any)
			if !ok {
				continue
			}
			if str(pm, "type") == OpenAIBlockText {
				if text, ok := pm["text"].(string); ok {
					sb.WriteString(text)
				}
			}
		}
		return sb.String()
	}
	return ""
}

// sanitizeToolResultText strips non-printable control chars that can
// produce backend request errors (tab/LF/CR are kept, like the JS
// regex /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g).
func sanitizeToolResultText(text string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		if r == 0x7f {
			return -1
		}
		return r
	}, text)
}

var cursorXMLEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
)

func buildToolResultBlock(toolName, toolCallID, resultText string) string {
	if toolName == "" {
		toolName = "tool"
	}
	cleanResult := sanitizeToolResultText(resultText)
	return strings.Join([]string{
		"<tool_result>",
		"<tool_name>" + cursorXMLEscaper.Replace(toolName) + "</tool_name>",
		"<tool_call_id>" + cursorXMLEscaper.Replace(toolCallID) + "</tool_call_id>",
		"<result>" + cursorXMLEscaper.Replace(cleanResult) + "</result>",
		"</tool_result>",
	}, "\n")
}

// normalizeToolCallID ports normalizeToolCallId(): first line only.
func normalizeToolCallID(id any) string {
	s, ok := id.(string)
	if !ok {
		return ""
	}
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

// convertCursorMessages ports convertMessages() from
// openai-to-cursor.js.
func convertCursorMessages(messages []any) []any {
	result := []any{}

	// Map of tool_call_id -> tool name from assistant tool calls (the
	// raw id and its normalized first-line form are both remembered).
	toolCallMeta := map[string]string{}
	rememberToolMeta := func(toolCallID, toolName string) {
		if toolCallID == "" {
			return
		}
		if toolName == "" {
			toolName = "tool"
		}
		toolCallMeta[toolCallID] = toolName
		if normalized := normalizeToolCallID(toolCallID); normalized != "" && normalized != toolCallID {
			toolCallMeta[normalized] = toolName
		}
	}
	for _, item := range messages {
		msg, ok := item.(map[string]any)
		if !ok || str(msg, "role") != RoleAssistant {
			continue
		}
		for _, tcItem := range arr(msg, "tool_calls") {
			tc, ok := tcItem.(map[string]any)
			if !ok {
				continue
			}
			name := "tool"
			if fn := obj(tc, "function"); fn != nil {
				if n := str(fn, "name"); n != "" {
					name = n
				}
			}
			rememberToolMeta(str(tc, "id"), name)
		}
		if content, ok := msg["content"].([]any); ok {
			for _, partItem := range content {
				part, ok := partItem.(map[string]any)
				if !ok || str(part, "type") != ClaudeBlockToolUse {
					continue
				}
				name := str(part, "name")
				if name == "" {
					name = "tool"
				}
				rememberToolMeta(str(part, "id"), name)
			}
		}
	}

	for _, item := range messages {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role := str(msg, "role")
		switch role {
		case RoleSystem:
			result = append(result, Body{
				"role":    RoleUser,
				"content": "[System Instructions]\n" + extractCursorContent(msg["content"]),
			})

		case RoleTool:
			toolCallID := str(msg, "tool_call_id")
			toolName := str(msg, "name")
			if toolName == "" {
				toolName = toolCallMeta[toolCallID]
			}
			if toolName == "" {
				toolName = "tool"
			}
			result = append(result, Body{
				"role":    RoleUser,
				"content": buildToolResultBlock(toolName, toolCallID, extractCursorContent(msg["content"])),
			})

		case RoleUser, RoleAssistant:
			if role == RoleUser {
				if content, ok := msg["content"].([]any); ok {
					var parts []string
					for _, blockItem := range content {
						block, ok := blockItem.(map[string]any)
						if !ok {
							continue
						}
						switch str(block, "type") {
						case ClaudeBlockText:
							if text, ok := block["text"].(string); ok {
								parts = append(parts, text)
							}
						case ClaudeBlockToolResult:
							toolCallID := str(block, "tool_use_id")
							toolName, found := toolCallMeta[toolCallID]
							if !found {
								toolName, found = toolCallMeta[normalizeToolCallID(toolCallID)]
							}
							if !found || toolName == "" {
								toolName = "tool"
							}
							parts = append(parts, buildToolResultBlock(toolName, toolCallID, extractCursorContent(block["content"])))
						}
					}
					var nonEmpty []string
					for _, part := range parts {
						if part != "" {
							nonEmpty = append(nonEmpty, part)
						}
					}
					if joined := strings.Join(nonEmpty, "\n"); joined != "" {
						result = append(result, Body{"role": RoleUser, "content": joined})
					}
					continue
				}
			}

			content := extractCursorContent(msg["content"])

			if role == RoleAssistant {
				if toolCalls := arr(msg, "tool_calls"); len(toolCalls) > 0 {
					mapped := make([]any, 0, len(toolCalls))
					for _, tcItem := range toolCalls {
						tc, ok := tcItem.(map[string]any)
						if !ok {
							mapped = append(mapped, tcItem)
							continue
						}
						rest := Body{}
						for k, v := range tc {
							if k != "index" {
								rest[k] = v
							}
						}
						mapped = append(mapped, rest)
					}
					result = append(result, Body{
						"role":       RoleAssistant,
						"content":    content,
						"tool_calls": mapped,
					})
					continue
				}
				if contentParts, ok := msg["content"].([]any); ok {
					var extracted []any
					for _, blockItem := range contentParts {
						block, ok := blockItem.(map[string]any)
						if !ok || str(block, "type") != ClaudeBlockToolUse {
							continue
						}
						id := str(block, "id")
						if id == "" {
							continue
						}
						name := str(block, "name")
						if name == "" {
							name = "tool"
						}
						input := block["input"]
						if input == nil {
							input = Body{}
						}
						extracted = append(extracted, Body{
							"id":   id,
							"type": OpenAIBlockFunction,
							"function": Body{
								"name":      name,
								"arguments": stringifyJSON(input),
							},
						})
					}
					if len(extracted) > 0 {
						result = append(result, Body{
							"role":       RoleAssistant,
							"content":    content,
							"tool_calls": extracted,
						})
					} else if content != "" {
						result = append(result, Body{"role": RoleAssistant, "content": content})
					}
					continue
				}
			}

			if content != "" {
				result = append(result, Body{"role": role, "content": content})
			}
		}
	}

	return result
}

// openaiToCursorRequest ports openaiToCursorRequest(): converts the
// messages and strips OpenAI/Anthropic-specific fields, pinning
// max_tokens to DEFAULT_MIN_TOKENS like the JS.
func openaiToCursorRequest(body Body) (Body, error) {
	out := Body{}
	for k, v := range body {
		out[k] = v
	}
	for _, key := range []string{"user", "metadata", "tool_choice", "stream_options", "system"} {
		delete(out, key)
	}
	out["messages"] = convertCursorMessages(arr(body, "messages"))
	out["max_tokens"] = float64(DefaultMinTokens)
	return out, nil
}

// cursorToOpenAIChunk ports response/cursor-to-openai.js: a passthrough,
// because the Cursor executor already emits OpenAI format.
func cursorToOpenAIChunk(chunk Body, state *StreamState) ([]Body, error) {
	if chunk == nil {
		return nil, nil
	}
	return []Body{chunk}, nil
}

func cursorToOpenAIBody(body Body) (Body, error) {
	return body, nil
}

func init() {
	// Kiro — real port (kiro_request.go / kiro_response.go). The direct
	// kiro->claude route is registered too: like the JS, it converts the
	// executor's OpenAI-shaped chunks straight to Claude events.
	Register(FormatOpenAI, FormatKiro, openAIToKiroRequest, nil)
	Register(FormatClaude, FormatKiro, claudeToKiroRequest, nil)
	Register(FormatKiro, FormatOpenAI, nil, kiroToOpenAIChunk)
	Register(FormatKiro, FormatClaude, nil, kiroToClaudeChunk)
	registerBody(FormatKiro, FormatOpenAI, kiroToOpenAIBody)
	registerBody(FormatKiro, FormatClaude, kiroToClaudeBody)
	Register(FormatOpenAI, FormatCursor, openaiToCursorRequest, nil)
	Register(FormatCursor, FormatOpenAI, nil, cursorToOpenAIChunk)
	registerBody(FormatCursor, FormatOpenAI, cursorToOpenAIBody)
}
