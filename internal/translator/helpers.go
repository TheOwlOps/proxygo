package translator

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// ---------- generic Body accessors ----------

// str returns m[key] as a string ("" when absent or not a string).
func str(m Body, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// num returns m[key] as float64; JSON-decoded numbers and Go int/float
// values are all accepted.
func num(m Body, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	return numVal(m[key])
}

func numVal(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// intNum is numVal plus an integral check, mirroring JS Number.isInteger.
func intNum(v any) (int64, bool) {
	f, ok := numVal(v)
	if !ok || f != float64(int64(f)) {
		return 0, false
	}
	return int64(f), true
}

// intVal converts any JSON number to a Go int for output bodies.
func intVal(v any) int {
	f, _ := numVal(v)
	return int(f)
}

// obj returns m[key] as a Body (nil when absent or not an object).
func obj(m Body, key string) Body {
	if m == nil {
		return nil
	}
	o, _ := m[key].(map[string]any)
	return o
}

// arr returns m[key] as a slice (nil when absent or not an array).
func arr(m Body, key string) []any {
	if m == nil {
		return nil
	}
	a, _ := m[key].([]any)
	return a
}

// has reports whether key is present and non-nil (JS `!== undefined`).
func has(m Body, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	return ok && v != nil
}

// truthy mirrors JS truthiness for the value kinds found in bodies.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	default:
		if f, ok := numVal(v); ok {
			return f != 0
		}
		return true
	}
}

func deepCopyBody(b Body) Body {
	if b == nil {
		return nil
	}
	return deepCopyValue(b).(map[string]any)
}

func deepCopyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCopyValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCopyValue(val)
		}
		return out
	default:
		return v
	}
}

// ---------- JSON (concerns/json.js) ----------

// safeParseJSON ports safeParseJSON: non-strings pass through, parse
// errors yield the fallback.
func safeParseJSON(s any, fallback any) any {
	text, ok := s.(string)
	if !ok {
		return s
	}
	var out any
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return fallback
	}
	return normalizeNumbers(out)
}

// normalizeNumbers converts json.Number leaves to float64/int so bodies
// behave like JS-parsed JSON (numbers are plain numbers downstream).
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return int(i)
		}
		f, _ := t.Float64()
		return f
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeNumbers(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = normalizeNumbers(val)
		}
		return t
	default:
		return v
	}
}

// stringifyJSON mirrors JSON.stringify for body values (compact);
// a string value is quoted, exactly like JSON.stringify.
func stringifyJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---------- image data URIs (concerns/image.js) ----------

func encodeDataURI(mimeType, base64 string) string {
	return "data:" + mimeType + ";base64," + base64
}

var dataURIRe = regexp.MustCompile(`(?s)^data:([^;]+);base64,(.+)$`)

// parseDataURI ports parseDataUri; ok=false when not a data URI.
func parseDataURI(url string) (mimeType, base64 string, ok bool) {
	m := dataURIRe.FindStringSubmatch(url)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// ---------- message (concerns/message.js) ----------

// collapseTextParts ports collapseTextParts: a lone text part becomes a
// plain string, otherwise the part array is returned as-is.
func collapseTextParts(parts []any) any {
	if len(parts) == 1 {
		if p, ok := parts[0].(map[string]any); ok && str(p, "type") == OpenAIBlockText {
			return str(p, "text")
		}
	}
	return parts
}

// extractTextContent ports extractTextContent (formats/gemini.js).
func extractTextContent(content any, separator string) string {
	if s, ok := content.(string); ok {
		return s
	}
	if parts, ok := content.([]any); ok {
		var texts []string
		for _, c := range parts {
			if p, ok := c.(map[string]any); ok && str(p, "type") == OpenAIBlockText {
				texts = append(texts, str(p, "text"))
			}
		}
		return strings.Join(texts, separator)
	}
	return ""
}

// ---------- chunk (concerns/chunk.js) ----------

// buildChunk ports buildChunk: an OpenAI chat.completion.chunk.
func buildChunk(id string, created int64, model string, delta Body, finishReason any) Body {
	return Body{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []any{Body{
			"index":         0,
			"delta":         delta,
			"finish_reason": finishReason,
		}},
	}
}

func nowUnix() int64   { return time.Now().Unix() }
func nowMillis() int64 { return time.Now().UnixMilli() }

// ---------- finish reasons (concerns/finishReason.js) ----------

// toOpenAIFinish ports toOpenAIFinish.
func toOpenAIFinish(reason, format string) string {
	switch format {
	case "claude":
		switch reason {
		case ClaudeStopEndTurn:
			return OpenAIFinishStop
		case ClaudeStopMaxTokens:
			return OpenAIFinishLength
		case ClaudeStopToolUse:
			return OpenAIFinishToolCalls
		case ClaudeStopStopSequence:
			return OpenAIFinishStop
		case ClaudeStopRefusal:
			return OpenAIFinishContentFilter
		default:
			return OpenAIFinishStop
		}
	case "commandcode":
		switch reason {
		case "stop":
			return OpenAIFinishStop
		case "length":
			return OpenAIFinishLength
		case "tool-calls", "tool_use":
			return OpenAIFinishToolCalls
		case "content-filter":
			return OpenAIFinishContentFilter
		case "error":
			return OpenAIFinishStop
		default:
			if reason != "" {
				return reason
			}
			return OpenAIFinishStop
		}
	case "gemini":
		switch strings.ToUpper(reason) {
		case GeminiFinishStop:
			return OpenAIFinishStop
		case GeminiFinishMaxTokens:
			return OpenAIFinishLength
		case GeminiFinishSafety, GeminiFinishRecitation, GeminiFinishBlocklist, GeminiFinishProhibitedContent:
			return OpenAIFinishContentFilter
		default:
			return OpenAIFinishStop
		}
	case "kiro", "ollama":
		switch reason {
		case "tool_calls", "tool_use":
			return OpenAIFinishToolCalls
		case "length", "max_tokens":
			return OpenAIFinishLength
		default:
			return OpenAIFinishStop
		}
	default:
		if reason != "" {
			return reason
		}
		return OpenAIFinishStop
	}
}

// fromOpenAIFinish ports fromOpenAIFinish.
func fromOpenAIFinish(reason, format string) string {
	switch format {
	case "claude":
		switch reason {
		case OpenAIFinishStop:
			return ClaudeStopEndTurn
		case OpenAIFinishLength:
			return ClaudeStopMaxTokens
		case OpenAIFinishToolCalls:
			return ClaudeStopToolUse
		case OpenAIFinishContentFilter:
			return ClaudeStopRefusal
		default:
			return ClaudeStopEndTurn
		}
	default:
		return reason
	}
}

// fromOpenAIToGeminiFinish maps an OpenAI finish_reason to a Gemini
// finishReason (used only by the openai->gemini chunk converter, which
// has no JS counterpart; see gemini.go).
func fromOpenAIToGeminiFinish(reason string) string {
	switch reason {
	case OpenAIFinishLength:
		return GeminiFinishMaxTokens
	case OpenAIFinishContentFilter:
		return GeminiFinishSafety
	default:
		return GeminiFinishStop
	}
}

// ---------- usage (concerns/usage.js) ----------

// buildUsage ports buildUsage: detail sub-objects appear only when > 0.
func buildUsage(promptTokens, completionTokens, totalTokens, cachedTokens, cacheCreationTokens, reasoningTokens int) Body {
	usage := Body{
		"prompt_tokens":     promptTokens,
		"completion_tokens": completionTokens,
		"total_tokens":      totalTokens,
	}
	if cachedTokens > 0 || cacheCreationTokens > 0 {
		details := Body{}
		if cachedTokens > 0 {
			details["cached_tokens"] = cachedTokens
		}
		if cacheCreationTokens > 0 {
			details["cache_creation_tokens"] = cacheCreationTokens
		}
		usage["prompt_tokens_details"] = details
	}
	if reasoningTokens > 0 {
		usage["completion_tokens_details"] = Body{"reasoning_tokens": reasoningTokens}
	}
	return usage
}

// toOpenAIUsage ports toOpenAIUsage for the claude/gemini/kiro/ollama/
// commandcode extractors; nil when the kind or raw object is unknown.
func toOpenAIUsage(raw Body, kind string) Body {
	if raw == nil {
		return nil
	}
	n := func(key string) int {
		f, _ := num(raw, key)
		return int(f)
	}
	switch kind {
	case "claude":
		input, output := n("input_tokens"), n("output_tokens")
		cacheRead, cacheCreate := n("cache_read_input_tokens"), n("cache_creation_input_tokens")
		prompt := input + cacheRead + cacheCreate
		return buildUsage(prompt, output, prompt+output, cacheRead, cacheCreate, 0)
	case "gemini":
		cached := n("cachedContentTokenCount")
		prompt := n("promptTokenCount")
		thoughts := n("thoughtsTokenCount")
		total := n("totalTokenCount")
		candidates := n("candidatesTokenCount")
		if candidates == 0 && total > 0 {
			candidates = total - prompt - thoughts
			if candidates < 0 {
				candidates = 0
			}
		}
		return buildUsage(prompt, candidates+thoughts, total, cached, 0, thoughts)
	case "kiro":
		input, output := n("inputTokens"), n("outputTokens")
		cached := n("cache_read_input_tokens")
		if cached == 0 {
			cached = n("cachedTokens")
		}
		if cached == 0 {
			cached = n("cached_tokens")
		}
		return buildUsage(input, output, input+output, cached, n("cache_creation_input_tokens"), 0)
	case "ollama":
		input, output := n("prompt_eval_count"), n("eval_count")
		return buildUsage(input, output, input+output, n("prompt_eval_cached_count"), 0, 0)
	case "commandcode":
		input, output := n("inputTokens"), n("outputTokens")
		total := input + output
		if v, ok := num(raw, "totalTokens"); ok {
			total = int(v)
		}
		return buildUsage(input, output, total, 0, 0, 0)
	}
	return nil
}

// ---------- reasoning (concerns/reasoning.js) ----------

// reasoningDelta ports reasoningDelta (without the role variant).
func reasoningDelta(text string) Body {
	return Body{"reasoning_content": text}
}

// extractReasoningText ports extractReasoningText across vendor shapes.
func extractReasoningText(delta Body) string {
	if delta == nil {
		return ""
	}
	if s := str(delta, "reasoning_content"); s != "" {
		return s
	}
	if s := str(delta, "reasoning"); s != "" {
		return s
	}
	if details := arr(delta, "reasoning_details"); details != nil {
		var sb strings.Builder
		for _, d := range details {
			if s, ok := d.(string); ok {
				sb.WriteString(s)
			} else if dm, ok := d.(map[string]any); ok {
				if t := str(dm, "text"); t != "" {
					sb.WriteString(t)
				} else {
					sb.WriteString(str(dm, "content"))
				}
			}
		}
		return sb.String()
	}
	return ""
}

// ---------- max tokens (formats/maxTokens.js) ----------

// adjustMaxTokens ports adjustMaxTokens. ceiling<=0 means the JS default
// parameter (DefaultMaxTokens).
func adjustMaxTokens(body Body, ceiling int) int {
	if ceiling <= 0 {
		ceiling = DefaultMaxTokens
	}
	maxTokens := DefaultMaxTokens
	if v, ok := num(body, "max_tokens"); ok && v != 0 {
		maxTokens = int(v)
	}
	if tools := arr(body, "tools"); len(tools) > 0 && maxTokens < DefaultMinTokens {
		maxTokens = DefaultMinTokens
	}
	if thinking := obj(body, "thinking"); thinking != nil {
		if budget, ok := num(thinking, "budget_tokens"); ok && budget != 0 {
			if maxTokens <= int(budget) {
				maxTokens = int(budget) + 1024
			}
		}
	}
	if maxTokens > ceiling {
		maxTokens = ceiling
	}
	return maxTokens
}

// ---------- tool calls (concerns/toolCall.js) ----------

var toolIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func sanitizeToolID(id string) string {
	if id == "" {
		return ""
	}
	var sb strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func generateToolCallID(msgIndex, tcIndex int, toolName string) string {
	name := ""
	if toolName != "" {
		name = "_" + sanitizeToolID(toolName)
	}
	return "call_msg" + itoa(msgIndex) + "_tc" + itoa(tcIndex) + name
}

// fallbackToolCallID ports fallbackToolCallId (index<0 mirrors undefined).
func fallbackToolCallID(index int) string {
	if index < 0 {
		return "call_" + itoa64(nowMillis())
	}
	return "call_" + itoa(index) + "_" + itoa64(nowMillis())
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func itoa64(i int64) string { return itoa(int(i)) }

// ensureToolCallIds ports ensureToolCallIds.
func ensureToolCallIds(body Body) Body {
	messages := arr(body, "messages")
	if messages == nil {
		return body
	}
	for i, mv := range messages {
		msg, ok := mv.(map[string]any)
		if !ok {
			continue
		}
		if str(msg, "role") == RoleAssistant {
			for j, tv := range arr(msg, "tool_calls") {
				tc, ok := tv.(map[string]any)
				if !ok {
					continue
				}
				id := str(tc, "id")
				if id == "" || !toolIDPattern.MatchString(id) {
					if s := sanitizeToolID(id); s != "" {
						tc["id"] = s
					} else {
						fnName := ""
						if fn := obj(tc, "function"); fn != nil {
							fnName = str(fn, "name")
						}
						tc["id"] = generateToolCallID(i, j, fnName)
					}
				}
				if !has(tc, "type") || tc["type"] == nil {
					tc["type"] = OpenAIBlockFunction
				}
				if fn := obj(tc, "function"); fn != nil {
					if args, present := fn["arguments"]; present && args != nil {
						if _, isStr := args.(string); !isStr {
							fn["arguments"] = stringifyJSON(args)
						}
					}
				}
			}
		}
		if str(msg, "role") == RoleTool {
			if id := str(msg, "tool_call_id"); id != "" && !toolIDPattern.MatchString(id) {
				if s := sanitizeToolID(id); s != "" {
					msg["tool_call_id"] = s
				} else {
					msg["tool_call_id"] = generateToolCallID(i, 0, "")
				}
			}
		}
		for k, bv := range arr(msg, "content") {
			block, ok := bv.(map[string]any)
			if !ok {
				continue
			}
			if str(block, "type") == ClaudeBlockToolUse {
				if id := str(block, "id"); id != "" && !toolIDPattern.MatchString(id) {
					if s := sanitizeToolID(id); s != "" {
						block["id"] = s
					} else {
						block["id"] = generateToolCallID(i, k, str(block, "name"))
					}
				}
			}
			if str(block, "type") == ClaudeBlockToolResult {
				if id := str(block, "tool_use_id"); id != "" && !toolIDPattern.MatchString(id) {
					if s := sanitizeToolID(id); s != "" {
						block["tool_use_id"] = s
					} else {
						block["tool_use_id"] = generateToolCallID(i, k, "")
					}
				}
			}
		}
	}
	return body
}

func getToolCallIDs(msg Body) []string {
	if str(msg, "role") != RoleAssistant {
		return nil
	}
	var ids []string
	for _, tv := range arr(msg, "tool_calls") {
		if tc, ok := tv.(map[string]any); ok {
			if id := str(tc, "id"); id != "" {
				ids = append(ids, id)
			}
		}
	}
	for _, bv := range arr(msg, "content") {
		if block, ok := bv.(map[string]any); ok && str(block, "type") == ClaudeBlockToolUse {
			if id := str(block, "id"); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func hasToolResults(msg Body, ids []string) bool {
	if msg == nil || len(ids) == 0 {
		return false
	}
	contains := func(id string) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
	if str(msg, "role") == RoleTool && contains(str(msg, "tool_call_id")) {
		return true
	}
	if str(msg, "role") == RoleUser {
		for _, bv := range arr(msg, "content") {
			if block, ok := bv.(map[string]any); ok && str(block, "type") == ClaudeBlockToolResult && contains(str(block, "tool_use_id")) {
				return true
			}
		}
	}
	return false
}

// fixMissingToolResponses ports the global fixMissingToolResponses from
// concerns/toolCall.js (the immediate-next-message variant).
func fixMissingToolResponses(body Body) Body {
	messages := arr(body, "messages")
	if messages == nil {
		return body
	}
	var out []any
	for i, mv := range messages {
		msg, _ := mv.(map[string]any)
		out = append(out, mv)
		ids := getToolCallIDs(msg)
		if len(ids) == 0 {
			continue
		}
		var next Body
		if i+1 < len(messages) {
			next, _ = messages[i+1].(map[string]any)
		}
		if next != nil && !hasToolResults(next, ids) {
			for _, id := range ids {
				out = append(out, Body{"role": RoleTool, "tool_call_id": id, "content": ""})
			}
		}
	}
	body["messages"] = out
	return body
}

// ---------- filter to OpenAI format (formats/openai.js) ----------

// filterToOpenAIFormat ports filterToOpenAIFormat. preserveCacheControl
// mirrors opts.preserveCacheControl (a provider quirk in the JS; the Go
// pipeline has no provider context, so callers pass false).
func filterToOpenAIFormat(body Body, preserveCacheControl bool) Body {
	messages := arr(body, "messages")
	if messages == nil {
		return body
	}
	stripBlock := func(block Body) Body {
		out := Body{}
		for k, v := range block {
			if k == "signature" {
				continue
			}
			if k == "cache_control" && !preserveCacheControl {
				continue
			}
			out[k] = v
		}
		return out
	}
	inList := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}

	var mapped []any
	for _, mv := range messages {
		msg, ok := mv.(map[string]any)
		if !ok {
			mapped = append(mapped, mv)
			continue
		}
		if str(msg, "role") == RoleDeveloper {
			cp := deepCopyBody(msg)
			cp["role"] = RoleSystem
			msg = cp
		}
		role := str(msg, "role")
		if role == RoleTool {
			mapped = append(mapped, msg)
			continue
		}
		if role == RoleAssistant && has(msg, "tool_calls") {
			mapped = append(mapped, msg)
			continue
		}
		content := msg["content"]
		if _, isStr := content.(string); isStr {
			mapped = append(mapped, msg)
			continue
		}
		if parts, isArr := content.([]any); isArr {
			var filtered []any
			for _, bv := range parts {
				block, ok := bv.(map[string]any)
				if !ok {
					continue
				}
				btype := str(block, "type")
				if btype == ClaudeBlockThinking || btype == ClaudeBlockRedactedThinking {
					continue
				}
				if inList(validOpenAIContentTypes, btype) {
					filtered = append(filtered, stripBlock(block))
				} else if btype == ClaudeBlockToolUse {
					continue
				} else if btype == ClaudeBlockToolResult {
					filtered = append(filtered, stripBlock(block))
				}
			}
			if len(filtered) == 0 {
				filtered = append(filtered, Body{"type": OpenAIBlockText, "text": ""})
			}
			cp := deepCopyBody(msg)
			cp["content"] = filtered
			mapped = append(mapped, cp)
			continue
		}
		mapped = append(mapped, msg)
	}

	var kept []any
	for _, mv := range mapped {
		msg, ok := mv.(map[string]any)
		if !ok {
			kept = append(kept, mv)
			continue
		}
		role := str(msg, "role")
		if role == RoleTool {
			kept = append(kept, mv)
			continue
		}
		if role == RoleAssistant && has(msg, "tool_calls") {
			kept = append(kept, mv)
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if strings.TrimSpace(content) != "" {
				kept = append(kept, mv)
			}
		case []any:
			keep := false
			for _, bv := range content {
				block, ok := bv.(map[string]any)
				if !ok {
					continue
				}
				if str(block, "type") == OpenAIBlockText {
					if strings.TrimSpace(str(block, "text")) != "" {
						keep = true
					}
				} else {
					keep = true
				}
			}
			if keep {
				kept = append(kept, mv)
			}
		default:
			kept = append(kept, mv)
		}
	}
	body["messages"] = kept

	if tools := arr(body, "tools"); tools != nil && len(tools) == 0 {
		delete(body, "tools")
	}
	if tools := arr(body, "tools"); len(tools) > 0 {
		var normalized []any
		for _, tv := range tools {
			tool, ok := tv.(map[string]any)
			if !ok {
				normalized = append(normalized, tv)
				continue
			}
			if str(tool, "type") == OpenAIBlockFunction && obj(tool, "function") != nil {
				normalized = append(normalized, tool)
				continue
			}
			if str(tool, "name") != "" && (has(tool, "input_schema") || has(tool, "description")) {
				params := obj(tool, "input_schema")
				if params == nil {
					params = Body{"type": "object", "properties": Body{}}
				}
				normalized = append(normalized, Body{
					"type": OpenAIBlockFunction,
					"function": Body{
						"name":        str(tool, "name"),
						"description": stringOrEmpty(tool["description"]),
						"parameters":  params,
					},
				})
				continue
			}
			if decls := arr(tool, "functionDeclarations"); decls != nil {
				for _, dv := range decls {
					fn, _ := dv.(map[string]any)
					params := obj(fn, "parameters")
					if params == nil {
						params = Body{"type": "object", "properties": Body{}}
					}
					normalized = append(normalized, Body{
						"type": OpenAIBlockFunction,
						"function": Body{
							"name":        str(fn, "name"),
							"description": stringOrEmpty(fn["description"]),
							"parameters":  params,
						},
					})
				}
				continue
			}
			normalized = append(normalized, tool)
		}
		body["tools"] = normalized
	}

	if choice := obj(body, "tool_choice"); choice != nil {
		switch str(choice, "type") {
		case "auto":
			body["tool_choice"] = "auto"
		case "any":
			body["tool_choice"] = "required"
		case "tool":
			if name := str(choice, "name"); name != "" {
				body["tool_choice"] = Body{
					"type":     OpenAIBlockFunction,
					"function": Body{"name": name},
				}
			}
		}
	}
	return body
}

// stringOrEmpty mirrors JS String(v || "").
func stringOrEmpty(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil || v == false {
		return ""
	}
	return stringifyJSON(v)
}
