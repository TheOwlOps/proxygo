package translator

import (
	"fmt"
	"strings"
	"time"
)

// Port of translator/request/openai-to-kiro.js and
// translator/request/claude-to-kiro.js (the direct claude:kiro route).
//
// Scope notes (Go ReqFn contract passes only the body — no credentials,
// no headers):
//   - profileArn: JS picks credentials.providerSpecificData.profileArn,
//     falling back to the shared default for OAuth/social and to "" for
//     account-bound auth (api_key/idc/external_idp). Without credentials
//     the Go port always emits the Builder ID default; the executor layer
//     still overrides via the x-amzn-codewhisperer-profile-arn header
//     when the connection carries its own ARN.
//   - session identity is resolved from body fields only (see
//     kiro_session.go); the continuation id warms the same store the JS
//     maintains but, as in JS, is not part of the wire payload.
//   - _kiroUpstreamModel / _toolNameMap ride on the returned Body like
//     the JS in-process payload (JS marks the former non-enumerable and
//     keeps the latter as a Map; a JSON round-trip downstream will treat
//     them as plain fields — executor adapters should strip them).

// ---------- OpenAI → Kiro message conversion ----------

func kiroImageFormat(mimeType string) string {
	parts := strings.Split(mimeType, "/")
	if len(parts) > 1 && parts[1] != "" {
		return parts[1]
	}
	return mimeType
}

// convertOpenAIMessagesToKiro ports convertMessages() from
// openai-to-kiro.js: system/tool → user, consecutive same-role merging,
// the last user turn popped as currentMessage.
func convertOpenAIMessagesToKiro(messages []any, model string) (history []Body, currentMessage Body) {
	var pendingUserContent, pendingAssistantContent []string
	var pendingToolResults []any
	var pendingImages []any
	currentRole := ""

	flushPending := func() {
		if currentRole == RoleUser {
			content := strings.TrimSpace(strings.Join(pendingUserContent, "\n\n"))
			if content == "" {
				content = kiroEmptyUserContent(len(pendingToolResults) > 0)
			}
			userMsg := Body{"content": content, "modelId": ""}
			if len(pendingImages) > 0 {
				userMsg["images"] = pendingImages
			}
			if len(pendingToolResults) > 0 {
				userMsg["userInputMessageContext"] = Body{"toolResults": pendingToolResults}
			}
			turn := Body{"userInputMessage": userMsg}
			history = append(history, turn)
			currentMessage = turn
			pendingUserContent = nil
			pendingToolResults = nil
			pendingImages = nil
		} else if currentRole == RoleAssistant {
			content := strings.TrimSpace(strings.Join(pendingAssistantContent, "\n\n"))
			if content == "" {
				content = "..."
			}
			history = append(history, Body{"assistantResponseMessage": Body{"content": content}})
			pendingAssistantContent = nil
		}
	}

	for _, rawMsg := range messages {
		msg, _ := rawMsg.(map[string]any)
		if msg == nil {
			continue
		}
		rawRole := str(msg, "role")
		wasSystem := rawRole == RoleSystem
		role := rawRole
		if role == RoleSystem || role == RoleTool {
			role = RoleUser
		}
		if role != currentRole && currentRole != "" {
			flushPending()
		}
		currentRole = role

		if role == RoleUser {
			content := ""
			if s, ok := msg["content"].(string); ok {
				content = s
			} else if blocks, ok := msg["content"].([]any); ok {
				var textParts []string
				for _, rawBlock := range blocks {
					block, _ := rawBlock.(map[string]any)
					if block == nil {
						continue
					}
					btype := str(block, "type")
					_, hasText := block["text"].(string)
					if btype == OpenAIBlockText || hasText {
						textParts = append(textParts, str(block, "text"))
					} else if btype == OpenAIBlockImageURL {
						url := ""
						if iu := obj(block, "image_url"); iu != nil {
							url = str(iu, "url")
						}
						if mime, b64, ok := parseDataURI(url); ok {
							pendingImages = append(pendingImages, Body{
								"format": kiroImageFormat(mime),
								"source": Body{"bytes": b64},
							})
						} else if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
							textParts = append(textParts, "[Image: "+url+"]")
						}
					} else if btype == ClaudeBlockImage {
						if src := obj(block, "source"); src != nil && str(src, "type") == "base64" {
							if data := str(src, "data"); data != "" {
								mediaType := str(src, "media_type")
								if mediaType == "" {
									mediaType = DefaultImageMIME
								}
								pendingImages = append(pendingImages, Body{
									"format": kiroImageFormat(mediaType),
									"source": Body{"bytes": data},
								})
							}
						}
					}
				}
				content = strings.Join(textParts, "\n")

				for _, rawBlock := range blocks {
					block, _ := rawBlock.(map[string]any)
					if block == nil || str(block, "type") != ClaudeBlockToolResult {
						continue
					}
					text := ""
					switch bc := block["content"].(type) {
					case []any:
						var parts []string
						for _, c := range bc {
							if cm, ok := c.(map[string]any); ok {
								parts = append(parts, str(cm, "text"))
							} else {
								parts = append(parts, "")
							}
						}
						text = strings.Join(parts, "\n")
					case string:
						text = bc
					}
					status := "success"
					if truthy(block["is_error"]) {
						status = "error"
					}
					pendingToolResults = append(pendingToolResults, Body{
						"toolUseId": block["tool_use_id"],
						"status":    status,
						"content":   []any{Body{"text": text}},
					})
				}
			}

			if rawRole == RoleTool {
				toolContent, _ := msg["content"].(string)
				status := "success"
				if truthy(msg["is_error"]) || str(msg, "status") == "error" {
					status = "error"
				}
				pendingToolResults = append(pendingToolResults, Body{
					"toolUseId": msg["tool_call_id"],
					"status":    status,
					"content":   []any{Body{"text": toolContent}},
				})
			} else if content != "" {
				if wasSystem {
					content = "<instructions>\n" + content + "\n</instructions>"
				}
				pendingUserContent = append(pendingUserContent, content)
			}
		} else if role == RoleAssistant {
			textContent := ""
			var toolUses []any
			if blocks, ok := msg["content"].([]any); ok {
				var textBlocks []string
				for _, rawBlock := range blocks {
					block, _ := rawBlock.(map[string]any)
					if block == nil {
						continue
					}
					switch str(block, "type") {
					case OpenAIBlockText:
						textBlocks = append(textBlocks, str(block, "text"))
					case ClaudeBlockToolUse:
						toolUses = append(toolUses, block)
					}
				}
				textContent = strings.TrimSpace(strings.Join(textBlocks, "\n"))
			} else if s, ok := msg["content"].(string); ok {
				textContent = strings.TrimSpace(s)
			}
			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				toolUses = tcs
			}
			if textContent != "" {
				pendingAssistantContent = append(pendingAssistantContent, textContent)
			}
			if len(toolUses) > 0 {
				flushPending()
				if len(history) > 0 {
					if last := kiroAssistantMsg(history[len(history)-1]); last != nil {
						mapped := make([]any, 0, len(toolUses))
						for _, rawTC := range toolUses {
							tc, _ := rawTC.(map[string]any)
							if tc == nil {
								continue
							}
							id := str(tc, "id")
							if id == "" {
								id = newKiroUUID()
							}
							if fn := obj(tc, "function"); fn != nil {
								mapped = append(mapped, Body{
									"toolUseId": id,
									"name":      str(fn, "name"),
									"input":     safeParseJSON(fn["arguments"], Body{}),
								})
							} else {
								input := tc["input"]
								if input == nil {
									input = Body{}
								}
								mapped = append(mapped, Body{
									"toolUseId": id,
									"name":      str(tc, "name"),
									"input":     input,
								})
							}
						}
						last["toolUses"] = mapped
					}
				}
				currentRole = ""
			}
		}
	}

	if currentRole != "" {
		flushPending()
	}

	// Pop the last user turn as currentMessage (skip trailing assistants).
	for i := len(history) - 1; i >= 0; i-- {
		if kiroUserMsg(history[i]) != nil {
			currentMessage = history[i]
			history = append(history[:i], history[i+1:]...)
			break
		}
	}

	for _, item := range history {
		if ui := kiroUserMsg(item); ui != nil {
			if ctx := obj(ui, "userInputMessageContext"); ctx != nil && len(ctx) == 0 {
				delete(ui, "userInputMessageContext")
			}
			if str(ui, "modelId") == "" {
				ui["modelId"] = model
			}
		}
	}

	// Merge consecutive user turns (JS merges content + context
	// toolResults/tools here; images are merged later by the
	// canonicalizer's normalizeTurns).
	var merged []Body
	for _, current := range history {
		curUser := kiroUserMsg(current)
		if curUser != nil && len(merged) > 0 {
			if prevUser := kiroUserMsg(merged[len(merged)-1]); prevUser != nil {
				prevUser["content"] = str(prevUser, "content") + "\n\n" + str(curUser, "content")
				curCtx := obj(curUser, "userInputMessageContext")
				if curCtx != nil {
					prevCtx := obj(prevUser, "userInputMessageContext")
					if prevCtx == nil {
						prevUser["userInputMessageContext"] = curCtx
					} else {
						if tr := arr(curCtx, "toolResults"); len(tr) > 0 {
							prevCtx["toolResults"] = append(arr(prevCtx, "toolResults"), tr...)
						}
						if tl := arr(curCtx, "tools"); len(tl) > 0 {
							prevCtx["tools"] = append(arr(prevCtx, "tools"), tl...)
						}
					}
				}
				continue
			}
		}
		merged = append(merged, current)
	}
	history = merged

	if currentMessage == nil {
		currentMessage = Body{"userInputMessage": Body{"content": "", "modelId": model}}
	}
	return history, currentMessage
}

// ---------- Claude → Kiro message conversion ----------

// convertClaudeMessagesToKiro ports convertClaudeMessagesToKiro() from
// claude-to-kiro.js.
func convertClaudeMessagesToKiro(messages []any, model string) (history []Body, currentMessage Body) {
	var pendingUserContent, pendingAssistantContent []string
	var pendingToolResults []any
	var pendingImages []any
	currentRole := ""

	flushPending := func() {
		if currentRole == RoleUser {
			content := strings.TrimSpace(strings.Join(pendingUserContent, "\n\n"))
			if content == "" {
				content = kiroEmptyUserContent(len(pendingToolResults) > 0)
			}
			userMsg := Body{"content": content, "modelId": model}
			if len(pendingImages) > 0 {
				userMsg["images"] = pendingImages
			}
			if len(pendingToolResults) > 0 {
				userMsg["userInputMessageContext"] = Body{"toolResults": pendingToolResults}
			}
			turn := Body{"userInputMessage": userMsg}
			history = append(history, turn)
			currentMessage = turn
			pendingUserContent = nil
			pendingToolResults = nil
			pendingImages = nil
		} else if currentRole == RoleAssistant {
			content := strings.TrimSpace(strings.Join(pendingAssistantContent, "\n\n"))
			if content == "" {
				content = "..."
			}
			history = append(history, Body{"assistantResponseMessage": Body{"content": content}})
			pendingAssistantContent = nil
		}
	}

	for _, rawMsg := range messages {
		msg, _ := rawMsg.(map[string]any)
		if msg == nil {
			continue
		}
		role := str(msg, "role")
		if role != currentRole && currentRole != "" {
			flushPending()
		}
		currentRole = role

		if role == RoleUser {
			if s, ok := msg["content"].(string); ok {
				pendingUserContent = append(pendingUserContent, s)
			} else if blocks, ok := msg["content"].([]any); ok {
				for _, rawBlock := range blocks {
					block, _ := rawBlock.(map[string]any)
					if block == nil {
						continue
					}
					switch str(block, "type") {
					case ClaudeBlockText:
						pendingUserContent = append(pendingUserContent, str(block, "text"))
					case ClaudeBlockImage:
						if src := obj(block, "source"); src != nil && str(src, "type") == "base64" {
							mediaType := str(src, "media_type")
							if mediaType == "" {
								mediaType = DefaultImageMIME
							}
							pendingImages = append(pendingImages, Body{
								"format": kiroImageFormat(mediaType),
								"source": Body{"bytes": str(src, "data")},
							})
						}
					case ClaudeBlockToolResult:
						resultContent := ""
						switch bc := block["content"].(type) {
						case string:
							resultContent = bc
						case []any:
							hasImage := false
							for _, rawC := range bc {
								c, _ := rawC.(map[string]any)
								if c == nil {
									continue
								}
								if str(c, "type") == ClaudeBlockImage {
									if src := obj(c, "source"); src != nil && str(src, "type") == "base64" {
										hasImage = true
										mediaType := str(src, "media_type")
										if mediaType == "" {
											mediaType = DefaultImageMIME
										}
										pendingImages = append(pendingImages, Body{
											"format": kiroImageFormat(mediaType),
											"source": Body{"bytes": str(src, "data")},
										})
									}
								}
							}
							var texts []string
							for _, rawC := range bc {
								if c, ok := rawC.(map[string]any); ok && str(c, "type") == ClaudeBlockText {
									texts = append(texts, str(c, "text"))
								}
							}
							resultContent = strings.Join(texts, "\n")
							if resultContent == "" {
								if hasImage {
									resultContent = "(image attached)"
								} else {
									resultContent = stringifyJSON(block["content"])
								}
							}
						default:
							if block["content"] != nil {
								resultContent = stringifyJSON(block["content"])
							}
						}
						status := "success"
						if truthy(block["is_error"]) {
							status = "error"
						}
						pendingToolResults = append(pendingToolResults, Body{
							"toolUseId": block["tool_use_id"],
							"status":    status,
							"content":   []any{Body{"text": resultContent}},
						})
					}
				}
			}
		} else if role == RoleAssistant {
			textContent := ""
			var toolUses []any
			if s, ok := msg["content"].(string); ok {
				textContent = s
			} else if blocks, ok := msg["content"].([]any); ok {
				for _, rawBlock := range blocks {
					block, _ := rawBlock.(map[string]any)
					if block == nil {
						continue
					}
					switch str(block, "type") {
					case ClaudeBlockText:
						textContent += str(block, "text")
					case ClaudeBlockToolUse:
						input := block["input"]
						if input == nil {
							input = Body{}
						}
						toolUses = append(toolUses, Body{
							"toolUseId": block["id"],
							"name":      str(block, "name"),
							"input":     input,
						})
					}
				}
			}
			if textContent != "" {
				pendingAssistantContent = append(pendingAssistantContent, textContent)
			}
			if len(toolUses) > 0 {
				flushPending()
				if len(history) > 0 {
					if last := kiroAssistantMsg(history[len(history)-1]); last != nil {
						last["toolUses"] = toolUses
					}
				}
				currentRole = ""
			}
		}
	}

	if currentRole != "" {
		flushPending()
	}

	for i := len(history) - 1; i >= 0; i-- {
		if kiroUserMsg(history[i]) != nil {
			currentMessage = history[i]
			history = append(history[:i], history[i+1:]...)
			break
		}
	}

	for _, item := range history {
		if ui := kiroUserMsg(item); ui != nil {
			if ctx := obj(ui, "userInputMessageContext"); ctx != nil && len(ctx) == 0 {
				delete(ui, "userInputMessageContext")
			}
			if str(ui, "modelId") == "" {
				ui["modelId"] = model
			}
		}
	}

	var merged []Body
	for _, current := range history {
		curUser := kiroUserMsg(current)
		if curUser != nil && len(merged) > 0 {
			if prevUser := kiroUserMsg(merged[len(merged)-1]); prevUser != nil {
				prevUser["content"] = str(prevUser, "content") + "\n\n" + str(curUser, "content")
				curCtx := obj(curUser, "userInputMessageContext")
				if curCtx != nil {
					prevCtx := obj(prevUser, "userInputMessageContext")
					if prevCtx == nil {
						prevUser["userInputMessageContext"] = curCtx
					} else {
						if tr := arr(curCtx, "toolResults"); len(tr) > 0 {
							prevCtx["toolResults"] = append(arr(prevCtx, "toolResults"), tr...)
						}
						if tl := arr(curCtx, "tools"); len(tl) > 0 {
							prevCtx["tools"] = append(arr(prevCtx, "tools"), tl...)
						}
					}
				}
				continue
			}
		}
		merged = append(merged, current)
	}
	history = merged

	if currentMessage == nil {
		currentMessage = Body{"userInputMessage": Body{"content": "", "modelId": model}}
	}
	return history, currentMessage
}

// extractClaudeSystemText ports extractClaudeSystemText.
func extractClaudeSystemText(system any) string {
	switch s := system.(type) {
	case string:
		return s
	case []any:
		var parts []string
		for _, item := range s {
			switch v := item.(type) {
			case string:
				if v != "" {
					parts = append(parts, v)
				}
			case map[string]any:
				if t := str(v, "text"); t != "" {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// ---------- payload assembly (shared by both request translators) -----

// finalizeKiroPayload runs session replay + canonicalization and builds
// the GenerateAssistantResponse payload, mirroring the tail of both JS
// request translators. claudeShape selects the claude variant's
// images/context spread behaviour.
func finalizeKiroPayload(body, thinkingBody Body, intent kiroModelIntent, history []Body, currentMessage Body, toolSpecs []any, nameMap map[string]string, systemPrompt string, maxTokens int, claudeShape bool, direction string) (Body, error) {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	currentTimeContext := "[Context: Current time is " + timestamp + "]"
	contentPrefix := systemPrompt
	if contentPrefix != "" {
		contentPrefix += "\n\n"
	}
	contentPrefix += currentTimeContext

	sessionID, ephemeral := resolveKiroSessionIdentity(body)
	_ = resolveKiroContinuationID(sessionID, ephemeral)

	replayHistory, replayCurrent := applyKiroSessionReplay(
		sessionID, intent.upstream, systemPrompt, contentPrefix, currentTimeContext, history, currentMessage)
	canonHistory, canonCurrent, valid, errs := canonicalizeKiroConversation(
		replayHistory, replayCurrent, intent.upstream, toolSpecs, nameMap)
	if !valid {
		// JS returns null and chatCore turns it into a 400 without an
		// upstream call; the error names the offending turns.
		return nil, fmt.Errorf("translator: kiro: refusing invalid conversation (%s): %s",
			direction, strings.Join(errs, ", "))
	}

	currentUser := kiroUserMsg(canonCurrent)
	uim := Body{
		"content": str(currentUser, "content"),
		"modelId": intent.upstream,
		"origin":  "AI_EDITOR",
	}
	images := arr(currentUser, "images")
	ctx := obj(currentUser, "userInputMessageContext")
	if claudeShape {
		if ctx != nil {
			uim["userInputMessageContext"] = ctx
		}
		if currentUser["images"] != nil {
			uim["images"] = images
		}
	} else {
		if len(images) > 0 {
			uim["images"] = images
		}
		if ctx != nil {
			uim["userInputMessageContext"] = ctx
		}
	}

	historyAny := make([]any, 0, len(canonHistory))
	for _, turn := range canonHistory {
		historyAny = append(historyAny, turn)
	}

	payload := Body{
		"conversationState": Body{
			"chatTriggerType": "MANUAL",
			"conversationId":  sessionID,
			"currentMessage":  Body{"userInputMessage": uim},
			"history":         historyAny,
		},
	}

	// No credentials in scope: the shared Builder ID default (see the
	// scope note at the top of this file).
	if arn := resolveDefaultProfileArn(""); arn != "" {
		payload["profileArn"] = arn
	}
	if fields := buildKiroAdditionalModelRequestFieldsForModel(thinkingBody, intent.upstream); fields != nil {
		payload["additionalModelRequestFields"] = fields
	}

	inference := Body{"maxTokens": maxTokens}
	if v := body["temperature"]; v != nil {
		inference["temperature"] = v
	}
	if v := body["top_p"]; v != nil {
		inference["topP"] = v
	}
	payload["inferenceConfig"] = inference

	payload["_kiroUpstreamModel"] = intent.upstream
	restored := map[string]any{}
	for original, sanitized := range nameMap {
		if original != sanitized {
			restored[sanitized] = original
		}
	}
	if len(restored) > 0 {
		payload["_toolNameMap"] = restored
	}
	return payload, nil
}

// openAIToKiroRequest ports openaiToKiroRequest (request/openai-to-kiro.js).
func openAIToKiroRequest(body Body) (Body, error) {
	model := str(body, "model")
	intent := resolveKiroModelIntent(model)
	thinkingBody := applyKiroThinkingOverride(body, intent.thinkingOverride)
	budget, hasBudget := resolveKiroThinkingBudget(thinkingBody, intent.model)
	nativeGPT := usesKiroNativeGptEffort(thinkingBody, intent.upstream)

	toolSpecs, nameMap := normalizeKiroToolSpecs(arr(body, "tools"))
	history, currentMessage := convertOpenAIMessagesToKiro(arr(body, "messages"), intent.upstream)

	var parts []string
	if hasBudget && !nativeGPT {
		parts = append(parts, buildThinkingSystemPrefix(budget))
	}
	if intent.agentic {
		parts = append(parts, KiroAgenticSystemPrompt)
	}
	systemPrompt := strings.Join(parts, "\n\n")

	return finalizeKiroPayload(body, thinkingBody, intent, history, currentMessage, toolSpecs, nameMap,
		systemPrompt, 32000, false, "openai → kiro")
}

// claudeToKiroRequest ports claudeToKiroRequest (request/claude-to-kiro.js),
// the direct route that skips the OpenAI pivot.
func claudeToKiroRequest(body Body) (Body, error) {
	model := str(body, "model")
	intent := resolveKiroModelIntent(model)
	thinkingBody := applyKiroThinkingOverride(body, intent.thinkingOverride)
	budget, hasBudget := resolveKiroThinkingBudget(thinkingBody, intent.model)
	nativeGPT := usesKiroNativeGptEffort(thinkingBody, intent.upstream)

	toolSpecs, nameMap := normalizeKiroToolSpecs(arr(body, "tools"))
	history, currentMessage := convertClaudeMessagesToKiro(arr(body, "messages"), intent.upstream)

	var parts []string
	if hasBudget && !nativeGPT {
		parts = append(parts, buildThinkingSystemPrefix(budget))
	}
	if intent.agentic {
		parts = append(parts, KiroAgenticSystemPrompt)
	}
	if sys := extractClaudeSystemText(body["system"]); sys != "" {
		parts = append(parts, sys)
	}
	systemPrompt := strings.Join(parts, "\n\n")

	maxTokens := 32000
	if mt, ok := num(body, "max_tokens"); ok && mt != 0 {
		maxTokens = int(mt)
	}
	return finalizeKiroPayload(body, thinkingBody, intent, history, currentMessage, toolSpecs, nameMap,
		systemPrompt, maxTokens, true, "claude → kiro")
}
