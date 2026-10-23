package translator

import (
	"regexp"
	"strings"
)

// Port of translator/concerns/kiroConversation.js: Kiro tool-spec
// normalization and the conversation canonicalizer that enforces Kiro's
// wire rules (alternating turns, adjacent one-to-one tool use/result
// pairs, specs only on the current message).

const (
	// KiroToolResultsPlaceholder is the user-turn text for a turn that
	// only carries tool results (see the JS comment: it must not read
	// like a user instruction).
	KiroToolResultsPlaceholder = "Tool results provided."
	// KiroEmptyUserPlaceholder fills a user turn with no text of its own.
	KiroEmptyUserPlaceholder = "continue"
)

// kiroEmptyUserContent ports kiroEmptyUserContent.
func kiroEmptyUserContent(hasToolResults bool) string {
	if hasToolResults {
		return KiroToolResultsPlaceholder
	}
	return KiroEmptyUserPlaceholder
}

var (
	kiroToolIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	kiroToolNameStripRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)
)

// kiroTextOf ports the concern's text(): string passthrough, nil → "",
// anything else JSON-stringified.
func kiroTextOf(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return stringifyJSON(v)
	}
}

func kiroAppendText(target Body, extra string) {
	if extra == "" {
		return
	}
	if cur := str(target, "content"); cur != "" {
		target["content"] = cur + "\n\n" + extra
	} else {
		target["content"] = extra
	}
}

// trimCodePoints ports [...value].slice(0, limit).join("") (rune-wise).
func trimCodePoints(value string, limit int) string {
	r := []rune(value)
	if len(r) > limit {
		r = r[:limit]
	}
	return string(r)
}

func kiroUniqueToolName(rawName string, index int, usedNames map[string]bool) string {
	cleaned := strings.TrimSpace(rawName)
	cleaned = kiroToolNameStripRe.ReplaceAllString(cleaned, "_")
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		cleaned = "tool_" + itoa(index+1)
	}
	base := trimCodePoints(cleaned, KiroToolNameMaxLength)
	candidate := base
	for suffix := 2; usedNames[candidate]; suffix++ {
		tail := "_" + itoa(suffix)
		runes := []rune(base)
		if len(runes) > KiroToolNameMaxLength-len([]rune(tail)) {
			runes = runes[:KiroToolNameMaxLength-len([]rune(tail))]
		}
		candidate = string(runes) + tail
	}
	usedNames[candidate] = true
	return candidate
}

func cleanKiroSchemaValue(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = cleanKiroSchemaValue(e)
		}
		return out
	case map[string]any:
		cleaned := Body{}
		for k, child := range t {
			if k == "additionalProperties" {
				continue
			}
			if k == "required" {
				if arr, ok := child.([]any); ok && len(arr) == 0 {
					continue
				}
			}
			cleaned[k] = cleanKiroSchemaValue(child)
		}
		return cleaned
	default:
		return v
	}
}

func normalizeKiroRootSchema(schema any) Body {
	var src Body
	if m, ok := schema.(map[string]any); ok {
		src = deepCopyBody(m)
	}
	cleaned, _ := cleanKiroSchemaValue(src).(map[string]any)
	if cleaned == nil {
		cleaned = Body{}
	}
	cleaned["type"] = "object"
	props, ok := cleaned["properties"].(map[string]any)
	if !ok || props == nil {
		props = Body{}
		cleaned["properties"] = props
	}
	if req, ok := cleaned["required"].([]any); ok {
		seen := map[string]bool{}
		var out []any
		for _, name := range req {
			s, ok := name.(string)
			if !ok || seen[s] {
				continue
			}
			if _, has := props[s]; has {
				seen[s] = true
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			delete(cleaned, "required")
		} else {
			cleaned["required"] = out
		}
	}
	return cleaned
}

// normalizeKiroToolSpecs ports normalizeKiroToolSpecs: OpenAI- or
// Claude-shaped tool definitions → Kiro toolSpecification list, plus the
// original→sanitized name map.
func normalizeKiroToolSpecs(tools []any) (specs []any, nameMap map[string]string) {
	nameMap = map[string]string{}
	usedNames := map[string]bool{}
	for index, raw := range tools {
		tool, _ := raw.(map[string]any)
		if tool == nil {
			continue
		}
		fn := obj(tool, "function")
		// JS: tool.function?.name ?? tool.name — a missing/nullish
		// function.name falls through to tool.name; a present non-string
		// name fails the typeof check and the tool is skipped.
		var rawName string
		nameResolved := false
		if fn != nil {
			if v, present := fn["name"]; present && v != nil {
				nameResolved = true
				rawName, _ = v.(string)
			}
		}
		if !nameResolved {
			rawName = str(tool, "name")
		}
		if strings.TrimSpace(rawName) == "" {
			continue
		}
		if _, dup := nameMap[rawName]; dup {
			continue
		}
		name := kiroUniqueToolName(rawName, index, usedNames)
		nameMap[rawName] = name

		var rawDesc any
		if fn != nil && fn["description"] != nil {
			rawDesc = fn["description"]
		} else if tool["description"] != nil {
			rawDesc = tool["description"]
		}
		desc := kiroTextOf(rawDesc)
		if desc == "" {
			desc = "Tool: " + rawName
		}
		desc = trimCodePoints(desc, KiroToolDescriptionMaxLength)

		var schema any
		if fn != nil && fn["parameters"] != nil {
			schema = fn["parameters"]
		} else if tool["parameters"] != nil {
			schema = tool["parameters"]
		} else if tool["input_schema"] != nil {
			schema = tool["input_schema"]
		}
		specs = append(specs, Body{
			"toolSpecification": Body{
				"name":        name,
				"description": desc,
				"inputSchema": Body{"json": normalizeKiroRootSchema(schema)},
			},
		})
	}
	return specs, nameMap
}

// ---------- turn helpers ----------

func kiroUserMsg(turn Body) Body {
	if turn == nil {
		return nil
	}
	return obj(turn, "userInputMessage")
}

func kiroAssistantMsg(turn Body) Body {
	if turn == nil {
		return nil
	}
	return obj(turn, "assistantResponseMessage")
}

func kiroToolCallText(toolUse Body) string {
	name := "unknown"
	input := any(Body{})
	if toolUse != nil {
		if n := str(toolUse, "name"); n != "" {
			name = n
		}
		if v := toolUse["input"]; v != nil {
			input = v
		}
	}
	return "[Tool call: " + name + "(" + kiroTextOf(input) + ")]"
}

// kiroPartText ports text(part?.text ?? part).
func kiroPartText(part any) string {
	if m, ok := part.(map[string]any); ok {
		if v, present := m["text"]; present && v != nil {
			return kiroTextOf(v)
		}
	}
	return kiroTextOf(part)
}

func kiroToolResultText(toolResult Body) string {
	var content string
	if parts, ok := toolResult["content"].([]any); ok {
		var texts []string
		for _, part := range parts {
			if t := kiroPartText(part); t != "" {
				texts = append(texts, t)
			}
		}
		content = strings.Join(texts, "\n")
	} else {
		content = kiroTextOf(toolResult["content"])
	}
	label := "[Tool result"
	if str(toolResult, "status") == "error" {
		label += " (error)"
	}
	return label + ": " + content + "]"
}

func kiroMergeUser(target, source Body) {
	kiroAppendText(target, str(source, "content"))
	if imgs, ok := source["images"].([]any); ok && len(imgs) > 0 {
		existing, _ := target["images"].([]any)
		target["images"] = append(existing, imgs...)
	}
	srcCtx := obj(source, "userInputMessageContext")
	if srcCtx == nil {
		return
	}
	results, ok := srcCtx["toolResults"].([]any)
	if !ok || len(results) == 0 {
		return
	}
	ctx := obj(target, "userInputMessageContext")
	if ctx == nil {
		ctx = Body{}
		target["userInputMessageContext"] = ctx
	}
	existing, _ := ctx["toolResults"].([]any)
	ctx["toolResults"] = append(existing, results...)
}

func kiroMergeAssistant(target, source Body) {
	kiroAppendText(target, str(source, "content"))
	if uses, ok := source["toolUses"].([]any); ok && len(uses) > 0 {
		existing, _ := target["toolUses"].([]any)
		target["toolUses"] = append(existing, uses...)
	}
}

func kiroNormalizeTurns(history []Body, currentMessage Body, modelID string) []Body {
	rawTurns := make([]Body, 0, len(history)+1)
	rawTurns = append(rawTurns, history...)
	if currentMessage != nil {
		rawTurns = append(rawTurns, currentMessage)
	}
	var turns []Body
	for _, raw := range rawTurns {
		if raw == nil {
			continue
		}
		user := kiroUserMsg(raw)
		assistant := kiroAssistantMsg(raw)
		if (user != nil) == (assistant != nil) {
			continue
		}
		var turn Body
		if user != nil {
			turn = Body{"userInputMessage": deepCopyBody(user)}
		} else {
			turn = Body{"assistantResponseMessage": deepCopyBody(assistant)}
		}
		if len(turns) > 0 {
			prev := turns[len(turns)-1]
			if kiroUserMsg(turn) != nil && kiroUserMsg(prev) != nil {
				kiroMergeUser(kiroUserMsg(prev), kiroUserMsg(turn))
				continue
			}
			if kiroAssistantMsg(turn) != nil && kiroAssistantMsg(prev) != nil {
				kiroMergeAssistant(kiroAssistantMsg(prev), kiroAssistantMsg(turn))
				continue
			}
		}
		turns = append(turns, turn)
	}

	if len(turns) > 0 && kiroAssistantMsg(turns[0]) != nil {
		turns = append([]Body{{"userInputMessage": Body{"content": "continue", "modelId": modelID}}}, turns...)
	}
	if len(turns) == 0 || kiroAssistantMsg(turns[len(turns)-1]) != nil {
		turns = append(turns, Body{"userInputMessage": Body{"content": "continue", "modelId": modelID}})
	}

	for _, turn := range turns {
		if ui := kiroUserMsg(turn); ui != nil {
			content := strings.TrimSpace(kiroTextOf(ui["content"]))
			if content == "" {
				ctx := obj(ui, "userInputMessageContext")
				content = kiroEmptyUserContent(ctx != nil && len(arr(ctx, "toolResults")) > 0)
			}
			ui["content"] = content
			if str(ui, "modelId") == "" {
				ui["modelId"] = modelID
			}
			if ctx := obj(ui, "userInputMessageContext"); ctx != nil && ctx["tools"] != nil {
				delete(ctx, "tools")
			}
		} else if am := kiroAssistantMsg(turn); am != nil {
			content := strings.TrimSpace(kiroTextOf(am["content"]))
			if content == "" {
				content = "..."
			}
			am["content"] = content
		}
	}
	return turns
}

// ---------- tool pair reconciliation ----------

type kiroRepairs struct {
	missingResults  int
	orphanResults   int
	invalidToolUses int
}

func kiroRawID(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func kiroReserveToolID(value string, turnIndex, callIndex int, name string, usedIDs map[string]bool) string {
	sanitized := kiroToolNameStripRe.ReplaceAllString(kiroRawID(value), "")
	generated := "call_msg" + itoa(turnIndex) + "_tc" + itoa(callIndex) + "_" + name
	if name == "" {
		generated = "call_msg" + itoa(turnIndex) + "_tc" + itoa(callIndex) + "_tool"
	}
	base := sanitized
	if !kiroToolIDPattern.MatchString(sanitized) || sanitized == "" {
		base = generated
	}
	base = trimCodePoints(base, KiroToolIDMaxLength)
	candidate := base
	for suffix := 2; usedIDs[candidate]; suffix++ {
		tail := "_" + itoa(suffix)
		runes := []rune(base)
		if len(runes) > KiroToolIDMaxLength-len([]rune(tail)) {
			runes = runes[:KiroToolIDMaxLength-len([]rune(tail))]
		}
		candidate = string(runes) + tail
	}
	usedIDs[candidate] = true
	return candidate
}

// normalizeKiroToolInput ports normalizeToolInput; ok=false mirrors the
// JS null (unrepresentable input).
func normalizeKiroToolInput(input any) (any, bool) {
	switch t := input.(type) {
	case map[string]any:
		return deepCopyBody(t), true
	case string:
		parsed := safeParseJSON(t, nil)
		if m, ok := parsed.(map[string]any); ok {
			return m, true
		}
		return nil, false
	case nil:
		return Body{}, true
	default:
		return nil, false
	}
}

// normalizeKiroToolResult ports normalizeToolResult.
func normalizeKiroToolResult(result Body) Body {
	var content []any
	if parts, ok := result["content"].([]any); ok {
		for _, part := range parts {
			content = append(content, Body{"text": kiroPartText(part)})
		}
	} else {
		content = []any{Body{"text": kiroTextOf(result["content"])}}
	}
	if len(content) == 0 {
		content = []any{Body{"text": ""}}
	}
	status := "success"
	if str(result, "status") == "error" {
		status = "error"
	}
	return Body{
		"toolUseId": kiroRawID(result["toolUseId"]),
		"status":    status,
		"content":   content,
	}
}

func kiroFlattenResults(userMessage Body, results []Body) {
	for _, result := range results {
		kiroAppendText(userMessage, kiroToolResultText(result))
	}
}

func kiroCleanUserContext(userMessage Body) {
	ctx := obj(userMessage, "userInputMessageContext")
	if ctx == nil {
		return
	}
	if len(arr(ctx, "toolResults")) == 0 {
		delete(ctx, "toolResults")
	}
	if len(arr(ctx, "tools")) == 0 {
		delete(ctx, "tools")
	}
	if len(ctx) == 0 {
		delete(userMessage, "userInputMessageContext")
	}
}

type kiroCallRecord struct {
	call       Body
	callIndex  int
	key        string
	mappedName string
	input      any
	inputValid bool
	result     Body
}

func kiroReconcileToolPair(assistant, user Body, turnIndex int, nameMap map[string]string, specNames map[string]bool, usedIDs map[string]bool, repairs *kiroRepairs) {
	var calls []any
	if assistant != nil {
		calls, _ = assistant["toolUses"].([]any)
	}
	var results []Body
	if ctx := obj(user, "userInputMessageContext"); ctx != nil {
		for _, r := range arr(ctx, "toolResults") {
			if rm, ok := r.(map[string]any); ok {
				results = append(results, normalizeKiroToolResult(rm))
			}
		}
	}
	if len(calls) == 0 {
		if len(results) > 0 {
			kiroFlattenResults(user, results)
			repairs.orphanResults += len(results)
		}
		if ctx := obj(user, "userInputMessageContext"); ctx != nil {
			delete(ctx, "toolResults")
		}
		kiroCleanUserContext(user)
		return
	}

	queues := map[string][]*kiroCallRecord{}
	var records []*kiroCallRecord
	for callIndex, rawCall := range calls {
		call, _ := rawCall.(map[string]any)
		key := ""
		var rawName string
		if call != nil {
			key = kiroRawID(call["toolUseId"])
			rawName = str(call, "name")
		}
		mappedName := rawName
		if mapped, ok := nameMap[rawName]; ok {
			mappedName = mapped
		}
		var input any
		var inputValid bool
		if call != nil {
			input, inputValid = normalizeKiroToolInput(call["input"])
		}
		rec := &kiroCallRecord{call: call, callIndex: callIndex, key: key, mappedName: mappedName, input: input, inputValid: inputValid}
		queues[key] = append(queues[key], rec)
		records = append(records, rec)
	}

	var orphanResults []Body
	for _, result := range results {
		queue := queues[kiroRawID(result["toolUseId"])]
		var rec *kiroCallRecord
		for _, cand := range queue {
			if cand.result == nil {
				rec = cand
				break
			}
		}
		if rec != nil {
			rec.result = result
		} else {
			orphanResults = append(orphanResults, result)
		}
	}

	var keptCalls, keptResults []any
	for _, rec := range records {
		hasSpec := rec.mappedName != "" && specNames[rec.mappedName]
		valid := rec.result != nil && hasSpec && rec.inputValid
		if !valid {
			toolUse := Body{"name": rec.mappedName}
			if rec.call != nil {
				toolUse["input"] = rec.call["input"]
			}
			kiroAppendText(assistant, kiroToolCallText(toolUse))
			if rec.result == nil {
				repairs.missingResults++
			}
			if !(hasSpec && rec.inputValid) {
				repairs.invalidToolUses++
			}
			if rec.result != nil {
				kiroFlattenResults(user, []Body{rec.result})
				repairs.orphanResults++
			}
			continue
		}
		toolUseID := kiroReserveToolID(rec.key, turnIndex, rec.callIndex, rec.mappedName, usedIDs)
		keptCalls = append(keptCalls, Body{
			"toolUseId": toolUseID,
			"name":      rec.mappedName,
			"input":     rec.input,
		})
		keptResult := deepCopyBody(rec.result)
		keptResult["toolUseId"] = toolUseID
		keptResults = append(keptResults, keptResult)
	}

	if len(orphanResults) > 0 {
		kiroFlattenResults(user, orphanResults)
		repairs.orphanResults += len(orphanResults)
	}

	if len(keptCalls) > 0 {
		assistant["toolUses"] = keptCalls
	} else {
		delete(assistant, "toolUses")
	}
	ctx := obj(user, "userInputMessageContext")
	if ctx == nil {
		ctx = Body{}
		user["userInputMessageContext"] = ctx
	}
	if len(keptResults) > 0 {
		ctx["toolResults"] = keptResults
	} else {
		delete(ctx, "toolResults")
	}
	kiroCleanUserContext(user)
}

// ---------- validation ----------

func kiroSpecNames(toolSpecs []any) map[string]bool {
	names := map[string]bool{}
	for _, spec := range toolSpecs {
		if sm, ok := spec.(map[string]any); ok {
			if ts := obj(sm, "toolSpecification"); ts != nil {
				if n := str(ts, "name"); n != "" {
					names[n] = true
				}
			}
		}
	}
	return names
}

// validateKiroConversation ports validateKiroConversation (no mutation).
func validateKiroConversation(history []Body, currentMessage Body, toolSpecs []any) (bool, []string) {
	var errs []string
	var turns []Body
	for _, t := range history {
		if t != nil {
			turns = append(turns, t)
		}
	}
	if currentMessage != nil {
		turns = append(turns, currentMessage)
	}
	specNames := kiroSpecNames(toolSpecs)
	usedIDs := map[string]bool{}

	for index, turn := range turns {
		expectedUser := index%2 == 0
		isUser := kiroUserMsg(turn) != nil
		if isUser != expectedUser {
			errs = append(errs, "role:"+itoa(index))
		}
		if !isUser {
			assistant := kiroAssistantMsg(turn)
			var calls []any
			if assistant != nil {
				calls, _ = assistant["toolUses"].([]any)
			}
			var results []any
			if index+1 < len(turns) {
				if next := kiroUserMsg(turns[index+1]); next != nil {
					if ctx := obj(next, "userInputMessageContext"); ctx != nil {
						results = arr(ctx, "toolResults")
					}
				}
			}
			callIDs := make([]string, 0, len(calls))
			for _, c := range calls {
				if cm, ok := c.(map[string]any); ok {
					callIDs = append(callIDs, kiroRawID(cm["toolUseId"]))
				}
			}
			resultIDs := map[string]bool{}
			for _, r := range results {
				if rm, ok := r.(map[string]any); ok {
					resultIDs[kiroRawID(rm["toolUseId"])] = true
				}
			}
			mismatch := len(calls) != len(results)
			if !mismatch {
				for _, id := range callIDs {
					if !resultIDs[id] {
						mismatch = true
						break
					}
				}
			}
			if mismatch {
				errs = append(errs, "pair:"+itoa(index))
			}
			for _, c := range calls {
				cm, _ := c.(map[string]any)
				if cm == nil {
					continue
				}
				id := kiroRawID(cm["toolUseId"])
				if id == "" || usedIDs[id] {
					errs = append(errs, "id:"+itoa(index))
				}
				usedIDs[id] = true
				if !specNames[str(cm, "name")] {
					errs = append(errs, "spec:"+itoa(index))
				}
			}
		} else if index == 0 {
			if ui := kiroUserMsg(turn); ui != nil {
				if ctx := obj(ui, "userInputMessageContext"); ctx != nil && len(arr(ctx, "toolResults")) > 0 {
					errs = append(errs, "orphan:0")
				}
			}
		}
	}
	if ui := kiroUserMsg(currentMessage); ui == nil || str(ui, "content") == "" {
		errs = append(errs, "current")
	}
	return len(errs) == 0, errs
}

func kiroFlattenAllStructuredTools(turns []Body, repairs *kiroRepairs) {
	for _, turn := range turns {
		if am := kiroAssistantMsg(turn); am != nil {
			if uses, ok := am["toolUses"].([]any); ok && len(uses) > 0 {
				for _, rawCall := range uses {
					call, _ := rawCall.(map[string]any)
					kiroAppendText(am, kiroToolCallText(call))
				}
				repairs.invalidToolUses += len(uses)
				delete(am, "toolUses")
			}
		}
		if ui := kiroUserMsg(turn); ui != nil {
			if ctx := obj(ui, "userInputMessageContext"); ctx != nil {
				if rawResults := arr(ctx, "toolResults"); len(rawResults) > 0 {
					var results []Body
					for _, r := range rawResults {
						if rm, ok := r.(map[string]any); ok {
							results = append(results, rm)
						}
					}
					kiroFlattenResults(ui, results)
					repairs.orphanResults += len(rawResults)
					delete(ctx, "toolResults")
					kiroCleanUserContext(ui)
				}
			}
		}
	}
}

// canonicalizeKiroConversation ports canonicalizeKiroConversation.
func canonicalizeKiroConversation(history []Body, currentMessage Body, modelID string, toolSpecs []any, nameMap map[string]string) (outHistory []Body, outCurrent Body, valid bool, errs []string) {
	turns := kiroNormalizeTurns(history, currentMessage, modelID)
	repairs := &kiroRepairs{}
	specNames := kiroSpecNames(toolSpecs)
	usedIDs := map[string]bool{}

	for index := 0; index < len(turns); index += 2 {
		user := kiroUserMsg(turns[index])
		if user == nil {
			continue
		}
		if index == 0 {
			if ctx := obj(user, "userInputMessageContext"); ctx != nil {
				if rawResults := arr(ctx, "toolResults"); len(rawResults) > 0 {
					var results []Body
					for _, r := range rawResults {
						if rm, ok := r.(map[string]any); ok {
							results = append(results, rm)
						}
					}
					kiroFlattenResults(user, results)
					repairs.orphanResults += len(rawResults)
					delete(ctx, "toolResults")
					kiroCleanUserContext(user)
				}
			}
		}
		var assistant, nextUser Body
		if index+1 < len(turns) {
			assistant = kiroAssistantMsg(turns[index+1])
		}
		if index+2 < len(turns) {
			nextUser = kiroUserMsg(turns[index+2])
		}
		if assistant != nil && nextUser != nil {
			kiroReconcileToolPair(assistant, nextUser, index+1, nameMap, specNames, usedIDs, repairs)
		}
	}

	finalCurrent := turns[len(turns)-1]
	finalUser := kiroUserMsg(finalCurrent)
	if finalUser != nil {
		ctx := obj(finalUser, "userInputMessageContext")
		if ctx == nil {
			ctx = Body{}
			finalUser["userInputMessageContext"] = ctx
		}
		if len(toolSpecs) > 0 {
			ctx["tools"] = deepCopyValue(toolSpecs)
		}
		kiroCleanUserContext(finalUser)
	}

	finalHistory := turns[:len(turns)-1]
	valid, errs = validateKiroConversation(finalHistory, finalCurrent, toolSpecs)
	if !valid {
		kiroFlattenAllStructuredTools(turns, repairs)
		finalHistory = turns[:len(turns)-1]
		valid, errs = validateKiroConversation(finalHistory, finalCurrent, toolSpecs)
	}
	_ = repairs // JS returns repairs for diagnostics; the payload path only needs validity.
	return finalHistory, finalCurrent, valid, errs
}
