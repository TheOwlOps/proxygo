package executors

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// grok-cli (open-sse/executors/grok-cli.js)
// ============================================================================
//
// GrokCliExecutor talks to the Grok CLI backend
// (https://cli-chat-proxy.grok.com/v1/responses) with the OpenAI Responses
// API. Auth is the OAuth device-code access token (Bearer). Unlike
// DefaultExecutor it:
//   - forces stream=true / store=false and prunes the body to the Responses
//     API allowlist,
//   - normalises Responses `input` (string/messages fallback, stored-item-id
//     stripping, reasoning/function-call item cleanup, orphan output drop),
//   - flattens Chat-Completions tools to the Responses flat shape while
//     passing hosted tools (web_search, x_search, …) through,
//   - resolves virtual effort models (grok-4.5-high → grok-4.5 + effort) and
//     injects reasoning {summary:"concise"[, effort]} plus
//     include:["reasoning.encrypted_content"],
//   - sends the CLI fingerprint headers (x-grok-session-id/-conv-id/-req-id/
//     -turn-idx/-model-override, x-email, x-userid, client id/version),
//   - parses 402 spending-limit errors with their code surfaced in the
//     message path (ParsedError has no code field in the Go contract).
//
// The upstream Responses SSE stream passes through untouched — the response
// format stays the registry format ("openai-responses"), so WrapResponse is
// not used and ResponseFormat is left "".
//
// Session/turn state: the JS keeps this._current* fields mutated by
// transformRequest and read by buildHeaders; the Go port carries the same
// values in Request.State (transform runs before headers in Base.Execute).
// getModelUpstreamId("gcli"/"grok-cli") is reproduced with a static table of
// the registry models for this provider (the only entries carrying an
// upstreamModelId are the effort-suffixed virtual models).
//
// The JS execute() lazy machine-id agent id is dead code in practice:
// transformRequest overwrites this._agentId with the connection's
// deviceId/agentId (or null) before buildHeaders runs, so the effective
// wire behaviour — x-grok-agent-id only when the connection provides one —
// is what is ported here.

const (
	grokCLIDefaultBaseURL    = "https://cli-chat-proxy.grok.com/v1/responses"
	grokCLIClientIdentifier  = "grok-shell" // GROK_CLI_CLIENT_IDENTIFIER
	grokCLIVersion           = "1.0.44"     // GROK_CLI_VERSION
	grokCLIUserAgent         = "grok-shell/1.0.44 (linux; x86_64)"
	grokCLIDefaultClientID   = "b1a00492-073a-47ea-816f-4c329264a828"
	grokCLIDefaultTokenURL   = "https://auth.x.ai/oauth2/token"
	grokCLITurnStoreMax      = 5000 // GROK_CLI_TURN_STORE_MAX
	grokSessionTTL           = 2 * time.Hour
	grokSessionEntryMaxChars = 256
)

var (
	grokServerIDRe       = regexp.MustCompile(`^(rs|fc|resp|msg)_`)
	grokNativeItemIDRe   = regexp.MustCompile(`(?i)^(?:rs|msg|fc)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	grokEffortModel45Re  = regexp.MustCompile(`^grok-4\.5(?:$|-)`)
	grokThinkingSuffixRe = regexp.MustCompile(`\([^()]+\)\s*$`)
	grokClaudeSessionRe  = regexp.MustCompile(`_session_([a-f0-9-]+)$`)
)

// grokHostedToolTypes mirrors HOSTED_TOOL_TYPES in grok-cli.js.
var grokHostedToolTypes = map[string]bool{
	"web_search": true, "x_search": true, "web_search_preview": true,
	"file_search": true, "image_generation": true, "code_interpreter": true,
	"mcp": true, "local_shell": true,
}

// grokResponsesAllowlist mirrors RESPONSES_API_ALLOWLIST in grok-cli.js.
var grokResponsesAllowlist = map[string]bool{
	"model": true, "input": true, "instructions": true, "tools": true,
	"tool_choice": true, "stream": true, "store": true, "reasoning": true,
	"include": true, "temperature": true, "top_p": true,
	"max_output_tokens": true, "parallel_tool_calls": true, "text": true,
	"metadata": true, "prompt_cache_key": true,
}

var grokEffortLevels = map[string]bool{"low": true, "medium": true, "high": true, "xhigh": true}

// grokCLIModelUpstream mirrors getModelUpstreamId for the grok-cli registry
// models: id → upstreamModelId (identity when the entry declares none).
var grokCLIModelUpstream = map[string]string{
	"grok-build":      "grok-build",
	"grok-4.5":        "grok-4.5",
	"grok-4.5-high":   "grok-4.5",
	"grok-4.5-medium": "grok-4.5",
	"grok-4.5-low":    "grok-4.5",
	"grok-4.5-xhigh":  "grok-4.5",
}

// --- Session / turn stores (sessionManager.js + grok-cli.js turn store) ---

type grokSessionEntry struct {
	sessionID string
	lastUsed  time.Time
}

type grokTurnEntry struct {
	turn     int
	lastUsed time.Time
}

var (
	grokStoreMu               sync.Mutex
	grokConnSessionStore      = map[string]grokSessionEntry{}
	grokAssistantSessionStore = map[string]grokSessionEntry{}
	grokTurnStore             = map[string]grokTurnEntry{}
	grokRequestTurnStore      = map[string]int{}
)

// grokGenerateBinaryStyleID ports generateBinaryStyleId:
// crypto.randomUUID() + Date.now().
func grokGenerateBinaryStyleID() string {
	return newUUID() + strconv.FormatInt(time.Now().UnixMilli(), 10)
}

// grokNormalizeSessionCandidate ports normalizeSessionId (trim, ≤256 chars).
func grokNormalizeSessionCandidate(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > grokSessionEntryMaxChars {
		return ""
	}
	return v
}

// grokHeaderValue does a case-insensitive lookup in raw client headers.
func grokHeaderValue(headers map[string]string, key string) string {
	if headers == nil {
		return ""
	}
	if v, ok := headers[key]; ok {
		if s := grokNormalizeSessionCandidate(v); s != "" {
			return s
		}
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			if s := grokNormalizeSessionCandidate(v); s != "" {
				return s
			}
		}
	}
	return ""
}

// grokExtractClaudeCodeSession ports extractClaudeCodeSession: the
// metadata.user_id may end in _session_<uuid> or be a JSON string carrying
// session_id.
func grokExtractClaudeCodeSession(userID string) string {
	if userID == "" {
		return ""
	}
	if m := grokClaudeSessionRe.FindStringSubmatch(userID); m != nil {
		return m[1]
	}
	if strings.HasPrefix(userID, "{") {
		var parsed map[string]any
		if unmarshalJSON([]byte(userID), &parsed) == nil {
			return grokNormalizeSessionCandidate(getStr(parsed, "session_id"))
		}
	}
	return ""
}

// grokDeriveSessionID ports deriveSessionId: a per-connection generated id,
// stable for the process lifetime (subject to the session TTL cleanup).
func grokDeriveSessionID(connectionID string) string {
	if connectionID == "" {
		return grokGenerateBinaryStyleID()
	}
	grokStoreMu.Lock()
	defer grokStoreMu.Unlock()
	if e, ok := grokConnSessionStore[connectionID]; ok {
		e.lastUsed = time.Now()
		grokConnSessionStore[connectionID] = e
		return e.sessionID
	}
	if len(grokConnSessionStore) >= 1000 {
		for k := range grokConnSessionStore {
			delete(grokConnSessionStore, k)
			break
		}
	}
	id := grokGenerateBinaryStyleID()
	grokConnSessionStore[connectionID] = grokSessionEntry{sessionID: id, lastUsed: time.Now()}
	return id
}

// grokAccumulateAssistantText ports accumulateAssistantText (cap 50 chars).
func grokAccumulateAssistantText(body map[string]any) string {
	var items []any
	if arr, ok := body["messages"].([]any); ok {
		items = arr
	} else if arr, ok := body["input"].([]any); ok {
		items = arr
	}
	var sb strings.Builder
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if item == nil || item["role"] != "assistant" {
			continue
		}
		switch c := item["content"].(type) {
		case string:
			sb.WriteString(c)
		case []any:
			for _, praw := range c {
				part, _ := praw.(map[string]any)
				if part == nil {
					continue
				}
				if t := getStr(part, "text"); t != "" {
					sb.WriteString(t)
				} else if t := getStr(part, "output"); t != "" {
					sb.WriteString(t)
				}
			}
		}
		if sb.Len() >= 50 {
			break
		}
	}
	return sb.String()
}

// grokAssistantTextSessionID ports assistantTextSessionId: a session id
// keyed on the first 50 chars of accumulated assistant text (min 50 chars).
func grokAssistantTextSessionID(scope, connectionID string, body map[string]any) string {
	text := grokAccumulateAssistantText(body)
	if len(text) < 50 {
		return ""
	}
	runes := []rune(text)
	if len(runes) > 50 {
		runes = runes[:50]
	}
	sum := sha256.Sum256([]byte(scope + ":" + connectionID + ":" + string(runes)))
	key := hex.EncodeToString(sum[:])[:16]
	grokStoreMu.Lock()
	defer grokStoreMu.Unlock()
	if e, ok := grokAssistantSessionStore[key]; ok {
		e.lastUsed = time.Now()
		grokAssistantSessionStore[key] = e
		return e.sessionID
	}
	if len(grokAssistantSessionStore) >= 5000 {
		for k := range grokAssistantSessionStore {
			delete(grokAssistantSessionStore, k)
			break
		}
	}
	id := grokGenerateBinaryStyleID()
	grokAssistantSessionStore[key] = grokSessionEntry{sessionID: id, lastUsed: time.Now()}
	return id
}

// grokResolveSessionID ports resolveGrokCliSessionId → resolveSessionId
// (utils/sessionManager.js) restricted to the explicit body subset the JS
// passes ({prompt_cache_key, session_id, conversation_id, metadata}) with
// scope "grok-cli".
func grokResolveSessionID(cred Credential, body map[string]any) string {
	var meta map[string]any
	if body != nil {
		meta, _ = body["metadata"].(map[string]any)
	}
	userID := ""
	if meta != nil {
		userID = getStr(meta, "user_id")
	}
	// Client session: Claude Code identity wins (header survives translation).
	if claude := grokExtractClaudeCodeSession(userID); claude != "" {
		return "claude:" + claude
	}
	if claude := grokHeaderValue(cred.RawHeaders, "x-claude-code-session-id"); claude != "" {
		return "claude:" + claude
	}
	for _, k := range []string{"x-session-id", "session-id", "session_id", "x-amp-thread-id"} {
		if v := grokHeaderValue(cred.RawHeaders, k); v != "" {
			return v
		}
	}
	if v := grokHeaderValue(cred.RawHeaders, "x-client-request-id"); v != "" {
		return v
	}
	if body != nil {
		for _, k := range []string{"prompt_cache_key", "session_id", "conversation_id"} {
			if v := grokNormalizeSessionCandidate(getStr(body, k)); v != "" {
				return v
			}
		}
	}
	if v := grokNormalizeSessionCandidate(userID); v != "" {
		return v
	}
	if v := grokAssistantTextSessionID("grok-cli", cred.ConnectionID, body); v != "" {
		return v
	}
	if v := grokNormalizeSessionCandidate(cred.SpecificString("workspaceId")); v != "" {
		return v
	}
	return grokDeriveSessionID(cred.ConnectionID)
}

// grokCountUserTurns ports countGrokCliUserTurns.
func grokCountUserTurns(input []any) int {
	n := 0
	for _, raw := range input {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		typ := getStr(item, "type")
		if item["role"] == "user" && (typ == "" || typ == "message") {
			n++
		}
	}
	if n < 1 {
		return 1
	}
	return n
}

// grokResolveTurnIdx ports resolveGrokCliTurnIdx. The JS keys its
// retry-reuse WeakMap by request-body object identity; the Go port keys it
// by a hash of the normalised input, which reproduces the same behaviour
// for the Base retry loop (each attempt re-transforms a pristine clone of
// the same body, yielding the same hash) — a genuinely new request whose
// input is byte-identical to the previous one reuses the turn instead of
// advancing it (documented divergence).
func grokResolveTurnIdx(sessionID string, input []any, requestKey string) int {
	fromInput := grokCountUserTurns(input)
	if sessionID == "" {
		return fromInput
	}
	grokStoreMu.Lock()
	defer grokStoreMu.Unlock()
	if requestKey != "" {
		if turn, ok := grokRequestTurnStore[requestKey]; ok {
			return turn
		}
	}
	now := time.Now()
	prev := 0
	if e, ok := grokTurnStore[sessionID]; ok {
		if now.Sub(e.lastUsed) <= grokSessionTTL {
			prev = e.turn
		}
		delete(grokTurnStore, sessionID)
	}
	turn := fromInput
	if prev > 0 {
		turn = prev
		if requestKey != "" {
			turn = prev + 1
		}
		if fromInput > turn {
			turn = fromInput
		}
	}
	for len(grokTurnStore) >= grokCLITurnStoreMax {
		for k := range grokTurnStore {
			delete(grokTurnStore, k)
			break
		}
	}
	grokTurnStore[sessionID] = grokTurnEntry{turn: turn, lastUsed: now}
	if requestKey != "" {
		if len(grokRequestTurnStore) >= grokCLITurnStoreMax {
			for k := range grokRequestTurnStore {
				delete(grokRequestTurnStore, k)
				break
			}
		}
		grokRequestTurnStore[requestKey] = turn
	}
	return turn
}

// grokNormalizeEffort ports normalizeGrokCliEffort.
func grokNormalizeEffort(value string) string {
	effort := strings.ToLower(strings.TrimSpace(value))
	if effort == "max" {
		return "xhigh"
	}
	if grokEffortLevels[effort] {
		return effort
	}
	return "high"
}

// grokSupportsReasoningEffort ports supportsGrokCliReasoningEffort
// (config/grokCli.js): only grok-4.5* models accept reasoning effort.
func grokSupportsReasoningEffort(model string) bool {
	return grokEffortModel45Re.MatchString(model)
}

// grokModelUpstreamID ports getModelUpstreamId for this provider's registry
// models (see grokCLIModelUpstream), including the "(level)" thinking
// suffix split/re-append behaviour.
func grokModelUpstreamID(modelID string) string {
	suffix := ""
	base := modelID
	if loc := grokThinkingSuffixRe.FindStringIndex(modelID); loc != nil {
		suffix = modelID[loc[0]:loc[1]]
		base = strings.TrimSpace(modelID[:loc[0]])
	}
	if upstream, ok := grokCLIModelUpstream[base]; ok {
		return upstream + suffix
	}
	return base + suffix
}

// grokResolveEffortFromModel ports resolveEffortFromModel.
func grokResolveEffortFromModel(modelID string) string {
	for _, level := range []string{"low", "medium", "high", "xhigh"} {
		if strings.HasSuffix(modelID, "-"+level) {
			return level
		}
	}
	return ""
}

// grokStringifyToolOutput ports stringifyGrokCliToolOutput.
func grokStringifyToolOutput(output any) string {
	if output == nil {
		return ""
	}
	if s, ok := output.(string); ok {
		return s
	}
	raw, err := marshalJSON(output)
	if err != nil {
		return ""
	}
	return string(raw)
}

// grokIsNativeItemID ports isNativeGrokCliItemId.
func grokIsNativeItemID(id string) bool {
	return grokNativeItemIDRe.MatchString(id)
}

// grokNormalizeResponsesInput ports normalizeResponsesInput
// (translator/formats/responsesApi.js): string → one message item, empty
// array → placeholder item, non-empty array passes through, anything else
// returns nil (caller leaves the original value untouched).
func grokNormalizeResponsesInput(input any) []any {
	switch v := input.(type) {
	case string:
		text := v
		if strings.TrimSpace(text) == "" {
			text = "..."
		}
		return []any{map[string]any{
			"type": "message", "role": "user",
			"content": []any{map[string]any{"type": "input_text", "text": text}},
		}}
	case []any:
		if len(v) == 0 {
			return []any{map[string]any{
				"type": "message", "role": "user",
				"content": []any{map[string]any{"type": "input_text", "text": "..."}},
			}}
		}
		return v
	}
	return nil
}

// grokNormalizeInputItem ports normalizeGrokCliInputItem. Returns nil when
// the item must be dropped.
func grokNormalizeInputItem(raw any) any {
	item, _ := raw.(map[string]any)
	if item == nil {
		return raw
	}
	clean := make(map[string]any, len(item))
	for k, v := range item {
		if k == "internal_chat_message_metadata_passthrough" {
			continue
		}
		clean[k] = v
	}
	switch getStr(item, "type") {
	case "reasoning":
		id, _ := item["id"].(string)
		if !grokIsNativeItemID(id) {
			return nil
		}
		if _, ok := item["encrypted_content"].(string); !ok {
			return nil
		}
		return clean
	case "custom_tool_call":
		callID := getStr(item, "call_id")
		if callID == "" {
			callID = getStr(item, "id")
		}
		name := strings.TrimSpace(getStr(item, "name"))
		if callID == "" || name == "" {
			return nil
		}
		input, present := item["input"]
		if !present || input == nil {
			input = item["arguments"]
		}
		args, _ := marshalJSON(map[string]any{"input": grokStringifyToolOutput(input)})
		return map[string]any{
			"type": "function_call", "call_id": callID, "name": name,
			"arguments": string(args),
		}
	case "custom_tool_call_output", "function_call_output":
		callID := getStr(item, "call_id")
		if callID == "" {
			callID = getStr(item, "id")
		}
		if callID == "" {
			return nil
		}
		return map[string]any{
			"type": "function_call_output", "call_id": callID,
			"output": grokStringifyToolOutput(item["output"]),
		}
	case "function_call":
		callID := getStr(item, "call_id")
		if callID == "" {
			callID = getStr(item, "id")
		}
		name := strings.TrimSpace(getStr(item, "name"))
		if callID == "" || name == "" {
			return nil
		}
		out := map[string]any{"type": "function_call", "call_id": callID, "name": name}
		if id, ok := item["id"].(string); ok && grokIsNativeItemID(id) {
			out["id"] = id
		}
		if args, ok := item["arguments"].(string); ok {
			out["arguments"] = args
		} else {
			args := item["arguments"]
			if args == nil {
				args = map[string]any{}
			}
			raw, _ := marshalJSON(args)
			out["arguments"] = string(raw)
		}
		if status, ok := item["status"].(string); ok {
			out["status"] = status
		}
		return out
	}
	return clean
}

// grokNormalizeInput ports normalizeGrokCliInput: per-item cleanup plus
// dropping function_call_output items whose call has been dropped/absent.
func grokNormalizeInput(body map[string]any) {
	input, ok := body["input"].([]any)
	if !ok {
		return
	}
	var normalized []any
	for _, raw := range input {
		if item := grokNormalizeInputItem(raw); item != nil {
			normalized = append(normalized, item)
		}
	}
	callIDs := map[string]bool{}
	for _, raw := range normalized {
		if item, _ := raw.(map[string]any); item != nil && item["type"] == "function_call" {
			if cid := getStr(item, "call_id"); cid != "" {
				callIDs[cid] = true
			}
		}
	}
	out := normalized[:0]
	for _, raw := range normalized {
		if item, _ := raw.(map[string]any); item != nil && item["type"] == "function_call_output" {
			if !callIDs[getStr(item, "call_id")] {
				continue
			}
		}
		out = append(out, raw)
	}
	body["input"] = out
}

// grokStripStoredItemReferences ports stripStoredItemReferences.
func grokStripStoredItemReferences(body map[string]any) {
	input, ok := body["input"].([]any)
	if !ok {
		return
	}
	out := input[:0]
	for _, raw := range input {
		if s, ok := raw.(string); ok && grokServerIDRe.MatchString(s) {
			continue
		}
		if item, _ := raw.(map[string]any); item != nil {
			if item["type"] == "item_reference" {
				continue
			}
			if id, ok := item["id"].(string); ok && grokServerIDRe.MatchString(id) && !grokIsNativeItemID(id) {
				delete(item, "id")
			}
		}
		out = append(out, raw)
	}
	body["input"] = out
}

// grokTruncateRunes mirrors JS String.slice(0, n) (UTF-16 units; runes are
// the closest Go equivalent for the ASCII tool names seen in practice).
func grokTruncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// grokNormalizeTools ports normalizeGrokCliTools: flatten Chat-Completions
// tools to the Responses flat shape; hosted tools pass through untouched.
func grokNormalizeTools(body map[string]any) {
	tools, ok := body["tools"].([]any)
	if !ok || len(tools) == 0 {
		delete(body, "tools")
		delete(body, "tool_choice")
		return
	}
	validNames := map[string]bool{}
	hostedTypes := map[string]bool{}
	var kept []any
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		if tool == nil {
			continue
		}
		typ := getStr(tool, "type")
		if typ != "function" {
			if grokHostedToolTypes[typ] {
				hostedTypes[typ] = true
				kept = append(kept, raw)
				continue
			}
			_, hasFn := tool["function"]
			_, hasName := tool["name"].(string)
			if !((typ == "" && hasFn) || typ == "" || hasName) {
				continue
			}
		}
		_, hasFnKey := tool["function"]
		if !(typ == "function" || typ == "" || hasFnKey) {
			if _, isStr := tool["name"].(string); !isStr {
				if grokHostedToolTypes[typ] {
					kept = append(kept, raw)
				}
				continue
			}
		}
		var fn map[string]any
		if f, ok := tool["function"].(map[string]any); ok {
			fn = f
		}
		rawName := getStr(tool, "name")
		if rawName == "" && fn != nil {
			rawName = getStr(fn, "name")
		}
		name := strings.TrimSpace(rawName)
		if name == "" {
			continue
		}
		description := getStr(tool, "description")
		if description == "" && fn != nil {
			description = getStr(fn, "description")
		}
		var parameters any
		if typ == "custom" {
			parameters = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{"type": "string"},
				},
				"required": []any{"input"},
			}
		} else if p, ok := tool["parameters"].(map[string]any); ok {
			parameters = p
		} else if fn != nil {
			if p, ok := fn["parameters"].(map[string]any); ok {
				parameters = p
			}
		}
		if parameters == nil {
			parameters = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		for k := range tool {
			delete(tool, k)
		}
		tool["type"] = "function"
		tool["name"] = grokTruncateRunes(name, 128)
		if description != "" {
			tool["description"] = description
		}
		tool["parameters"] = parameters
		validNames[tool["name"].(string)] = true
		kept = append(kept, raw)
	}
	body["tools"] = kept
	if len(kept) == 0 {
		delete(body, "tools")
		delete(body, "tool_choice")
		return
	}
	choice, _ := body["tool_choice"].(map[string]any)
	if choice == nil {
		return
	}
	choiceType := getStr(choice, "type")
	switch choiceType {
	case "function", "custom":
		rawName := getStr(choice, "name")
		if rawName == "" {
			if fn, ok := choice["function"].(map[string]any); ok {
				rawName = getStr(fn, "name")
			}
		}
		name := grokTruncateRunes(strings.TrimSpace(rawName), 128)
		if name == "" || !validNames[name] {
			delete(body, "tool_choice")
		} else {
			body["tool_choice"] = map[string]any{"type": "function", "name": name}
		}
	default:
		if !hostedTypes[choiceType] {
			delete(body, "tool_choice")
		}
	}
}

// GrokCLIExecutor is the Go port of GrokCliExecutor.
type GrokCLIExecutor struct{ *Base }

// NewGrokCLIExecutor builds the grok-cli executor.
func NewGrokCLIExecutor() *GrokCLIExecutor {
	e := &GrokCLIExecutor{}
	e.Base = &Base{ProviderID: "grok-cli", Hooks: Hooks{
		BuildURL:      e.grokBuildURL,
		BuildHeaders:  e.grokBuildHeaders,
		TransformBody: e.grokTransformBody,
		ParseError:    e.grokParseError,
		Refresh:       grokCLIRefresh,
	}}
	return e
}

func (e *GrokCLIExecutor) grokBuildURL(b *Base, req *Request, urlIndex int) (string, error) {
	if urls := req.Provider.BaseURLsList(); urlIndex < len(urls) && urls[urlIndex] != "" {
		return urls[urlIndex], nil
	}
	if req.Provider.BaseURL != "" {
		return req.Provider.BaseURL, nil
	}
	return grokCLIDefaultBaseURL, nil
}

// grokRawString reads a registry value from ProviderInfo.Raw, tolerating a
// nested "transport" map (the parent adapter preserves registry fields
// verbatim in one of those two shapes).
func grokRawString(p *ProviderInfo, key string) string {
	if p == nil {
		return ""
	}
	if s := p.RawString(key); s != "" {
		return s
	}
	if p.Raw != nil {
		if t, ok := p.Raw["transport"].(map[string]any); ok {
			if s, ok := t[key].(string); ok {
				return s
			}
		}
	}
	return ""
}

func (e *GrokCLIExecutor) grokBuildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	// super.buildHeaders: Content-Type + registry headers + Bearer auth.
	headers := baseBuildHeaders(b.ProviderID, req)
	if headers["User-Agent"] == "" {
		headers["User-Agent"] = grokCLIUserAgent
	}
	// Static fingerprint: config.clientIdentifier/clientVersion win, then
	// the header already present, then the built-in constants.
	if v := grokRawString(req.Provider, "clientIdentifier"); v != "" {
		headers["x-grok-client-identifier"] = v
	} else if headers["x-grok-client-identifier"] == "" {
		headers["x-grok-client-identifier"] = grokCLIClientIdentifier
	}
	if v := grokRawString(req.Provider, "clientVersion"); v != "" {
		headers["x-grok-client-version"] = v
	} else if headers["x-grok-client-version"] == "" {
		headers["x-grok-client-version"] = grokCLIVersion
	}

	sessionID, _ := req.State["grokSessionId"].(string)
	if sessionID == "" {
		sessionID = req.Cred.ConnectionID
	}
	if sessionID == "" {
		sessionID = newUUID()
	}
	reqID, _ := req.State["grokReqId"].(string)
	if reqID == "" {
		reqID = newUUID()
	}
	headers["x-grok-session-id"] = sessionID
	headers["x-grok-conv-id"] = sessionID
	headers["x-grok-req-id"] = reqID
	turn := 1
	if t, ok := req.State["grokTurnIdx"].(int); ok && t > 0 {
		turn = t
	}
	headers["x-grok-turn-idx"] = strconv.Itoa(turn)
	if agentID, _ := req.State["grokAgentId"].(string); agentID != "" {
		headers["x-grok-agent-id"] = agentID
	}
	if model, _ := req.State["grokModel"].(string); model != "" {
		headers["x-grok-model-override"] = model
	}
	// Identity: providerSpecificData carries email/userId for OAuth
	// connections (mapTokens also stores them top-level in the JS
	// credentials object — the Go Credential has no such fields, so only
	// the Specific copies exist here).
	if email := req.Cred.SpecificString("email"); email != "" {
		headers["x-email"] = email
	}
	userID := req.Cred.SpecificString("userId")
	if userID == "" {
		userID = req.Cred.SpecificString("providerUserId")
	}
	if userID != "" {
		headers["x-userid"] = userID
	}
	return headers, nil
}

// grokParseError ports GrokCliExecutor.parseError: 402 bodies carry a
// machine-readable code (e.g. personal-team-blocked:spending-limit); the Go
// ParsedError has no code field, so the code is folded into the message
// only when the body provided no human message. Non-402 falls back to base.
func (e *GrokCLIExecutor) grokParseError(status int, bodyText string) *ParsedError {
	if status == 402 && bodyText != "" {
		var parsed map[string]any
		if unmarshalJSON([]byte(bodyText), &parsed) == nil && parsed != nil {
			msg := getStr(parsed, "error")
			if msg == "" {
				msg = getStr(parsed, "message")
			}
			if msg == "" {
				msg = bodyText
			}
			return &ParsedError{Status: 402, Message: msg}
		}
	}
	return nil // base default
}

func (e *GrokCLIExecutor) grokTransformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	cred := req.Cred

	// Session / request ids for headers.
	sessionID := grokResolveSessionID(cred, body)
	req.State["grokSessionId"] = sessionID
	req.State["grokReqId"] = newUUID()
	agentID := cred.SpecificString("deviceId")
	if agentID == "" {
		agentID = cred.SpecificString("agentId")
	}
	if agentID != "" {
		req.State["grokAgentId"] = agentID
	} else {
		delete(req.State, "grokAgentId")
	}

	// Normalize Responses input.
	if normalized := grokNormalizeResponsesInput(body["input"]); normalized != nil {
		body["input"] = normalized
	}

	// Chat-Completions clients arrive with messages[] — soft fallback.
	inputArr, _ := body["input"].([]any)
	if body["input"] == nil || (inputArr != nil && len(inputArr) == 0) {
		if msgs, ok := body["messages"].([]any); ok && len(msgs) > 0 {
			var mapped []any
			for _, raw := range msgs {
				m, _ := raw.(map[string]any)
				role := "user"
				var content any = ""
				if m != nil {
					if r := getStr(m, "role"); r != "" {
						role = r
					}
					content = m["content"]
				}
				text, isStr := content.(string)
				if !isStr {
					if content == nil {
						// JS: JSON.stringify(m.content ?? "") → `""`.
						text = `""`
					} else {
						text = grokStringifyToolOutput(content)
					}
				}
				mapped = append(mapped, map[string]any{
					"type": "message", "role": role, "content": text,
				})
			}
			body["input"] = mapped
			delete(body, "messages")
		} else {
			body["input"] = []any{map[string]any{"type": "message", "role": "user", "content": "..."}}
		}
	}

	// role:"system" stays as-is (Grok CLI does not convert to developer).
	grokNormalizeInput(body)
	grokStripStoredItemReferences(body)
	grokNormalizeTools(body)

	// Turn index after input is finalized.
	finalInput, _ := body["input"].([]any)
	reqKeyRaw, _ := marshalJSON(body["input"])
	reqKeySum := sha256.Sum256(reqKeyRaw)
	req.State["grokTurnIdx"] = grokResolveTurnIdx(sessionID, finalInput, sessionID+"|"+hex.EncodeToString(reqKeySum[:]))

	body["stream"] = true
	body["store"] = false

	// Resolve upstream model id (strip effort suffix virtual models).
	modelArg := req.Model
	bodyModel := getStr(body, "model")
	effective := bodyModel
	if effective == "" {
		effective = modelArg
	}
	modelEffort := grokResolveEffortFromModel(effective)
	resolvedModel := effective
	if modelEffort != "" {
		resolvedModel = strings.TrimSuffix(resolvedModel, "-"+modelEffort)
	}
	resolvedModel = grokModelUpstreamID(resolvedModel)
	body["model"] = resolvedModel
	req.State["grokModel"] = resolvedModel

	// Reasoning effort priority: explicit > reasoning_effort > model
	// suffix > default high.
	supports := grokSupportsReasoningEffort(resolvedModel)
	reasoning, isObj := body["reasoning"].(map[string]any)
	if !isObj || reasoning == nil {
		reasoning = map[string]any{"summary": "concise"}
		if supports {
			effortSource := getStr(body, "reasoning_effort")
			if effortSource == "" {
				effortSource = modelEffort
			}
			reasoning["effort"] = grokNormalizeEffort(effortSource)
		}
		body["reasoning"] = reasoning
	} else {
		if supports {
			effortSource := getStr(reasoning, "effort")
			if effortSource == "" {
				effortSource = getStr(body, "reasoning_effort")
			}
			if effortSource == "" {
				effortSource = modelEffort
			}
			reasoning["effort"] = grokNormalizeEffort(effortSource)
		} else {
			delete(reasoning, "effort")
		}
		if getStr(reasoning, "summary") == "" {
			reasoning["summary"] = "concise"
		}
	}
	delete(body, "reasoning_effort")

	// Encrypted reasoning for multi-turn continuity.
	if reasoning != nil {
		if effort, _ := reasoning["effort"].(string); effort != "none" {
			var include []any
			if arr, ok := body["include"].([]any); ok {
				include = arr
			}
			found := false
			for _, v := range include {
				if v == "reasoning.encrypted_content" {
					found = true
				}
			}
			if !found {
				include = append(include, "reasoning.encrypted_content")
			}
			body["include"] = include
		}
	}

	// Drop Chat-Completions leftovers that Responses rejects.
	for _, k := range []string{
		"messages", "max_tokens", "max_completion_tokens", "n", "seed",
		"logprobs", "top_logprobs", "frequency_penalty", "presence_penalty",
		"logit_bias", "user", "stream_options", "prompt_cache_retention",
		"safety_identifier", "previous_response_id",
	} {
		delete(body, k)
	}
	for k := range body {
		if !grokResponsesAllowlist[k] {
			delete(body, k)
		}
	}
	return body, nil
}

// grokCLIRefresh ports GrokCliExecutor.refreshCredentials →
// refreshProviderCredentials("grok-cli", …): the standard OAuth
// refresh_token grant against the provider's token endpoint (form-encoded,
// client_id only — the grok-cli OAuth client is public).
func grokCLIRefresh(ctx context.Context, b *Base, p *ProviderInfo, cred Credential) (*Credential, error) {
	if cred.RefreshToken == "" {
		return nil, nil
	}
	tokenURL := p.TokenURL
	if tokenURL == "" {
		tokenURL = grokCLIDefaultTokenURL
	}
	clientID := p.ClientID
	if clientID == "" {
		clientID = grokCLIDefaultClientID
	}
	res, err := postRefreshForm(ctx, tokenURL, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": cred.RefreshToken,
		"client_id":     clientID,
	}, nil)
	if err != nil || res == nil || res.AccessToken == "" {
		return nil, err
	}
	out := cred
	out.AccessToken = res.AccessToken
	if res.RefreshToken != "" {
		out.RefreshToken = res.RefreshToken
	}
	return &out, nil
}

// ============================================================================
// grok-web (open-sse/executors/grok-web.js)
// ============================================================================
//
// GrokWebExecutor is a bespoke executor (the JS overrides execute()
// entirely): it POSTs a grok.com app-chat payload to
// https://grok.com/rest/app-chat/conversations/new with an SSO cookie
// (credentials.apiKey, "sso=" prefix stripped) and browser-fingerprint
// headers, then translates the NDJSON event stream into OpenAI
// chat.completion(.chunk) output — ResponseFormat is therefore "openai".
//
// Faithful quirks preserved from the JS:
//   - extractContent's thinkOpened flag is never set to true upstream, so
//     the thinking branch is dead: modelResponse messages are yielded as
//     fullMessage only (and are ignored entirely in streaming mode).
//   - Non-streaming usage charges both prompt and completion tokens from
//     the response length (ceil(len/4) each).
//   - Model defaults to grok-4.1-fast for unmapped model ids.
//
// LIVE-UNVERIFIED: a real grok.com SSO session is required to verify this
// end-to-end; only the protocol + fixture tests cover it here.

const (
	grokWebDefaultURL = "https://grok.com/rest/app-chat/conversations/new"
	grokWebUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)

type grokWebModelInfo struct {
	GrokModel  string
	ModelMode  string
	IsThinking bool
}

// grokWebModelMap mirrors MODEL_MAP in grok-web.js.
var grokWebModelMap = map[string]grokWebModelInfo{
	"grok-3":            {GrokModel: "grok-3", ModelMode: "MODEL_MODE_GROK_3", IsThinking: false},
	"grok-3-mini":       {GrokModel: "grok-3", ModelMode: "MODEL_MODE_GROK_3_MINI_THINKING", IsThinking: true},
	"grok-3-thinking":   {GrokModel: "grok-3", ModelMode: "MODEL_MODE_GROK_3_THINKING", IsThinking: true},
	"grok-4":            {GrokModel: "grok-4", ModelMode: "MODEL_MODE_GROK_4", IsThinking: false},
	"grok-4-mini":       {GrokModel: "grok-4-mini", ModelMode: "MODEL_MODE_GROK_4_MINI_THINKING", IsThinking: true},
	"grok-4-thinking":   {GrokModel: "grok-4", ModelMode: "MODEL_MODE_GROK_4_THINKING", IsThinking: true},
	"grok-4-heavy":      {GrokModel: "grok-4", ModelMode: "MODEL_MODE_HEAVY", IsThinking: true},
	"grok-4.1-mini":     {GrokModel: "grok-4-1-thinking-1129", ModelMode: "MODEL_MODE_GROK_4_1_MINI_THINKING", IsThinking: true},
	"grok-4.1-fast":     {GrokModel: "grok-4-1-thinking-1129", ModelMode: "MODEL_MODE_FAST", IsThinking: false},
	"grok-4.1-expert":   {GrokModel: "grok-4-1-thinking-1129", ModelMode: "MODEL_MODE_EXPERT", IsThinking: true},
	"grok-4.1-thinking": {GrokModel: "grok-4-1-thinking-1129", ModelMode: "MODEL_MODE_GROK_4_1_THINKING", IsThinking: true},
	"grok-4.2":          {GrokModel: "grok-420", ModelMode: "MODEL_MODE_GROK_420", IsThinking: false},
	"grok-4.20":         {GrokModel: "grok-420", ModelMode: "MODEL_MODE_GROK_420", IsThinking: false},
	"grok-4.20-beta":    {GrokModel: "grok-420", ModelMode: "MODEL_MODE_GROK_420", IsThinking: false},
}

// grokWebLookupModel returns the mapping for a model id, defaulting to
// grok-4.1-fast exactly like the JS.
func grokWebLookupModel(model string) grokWebModelInfo {
	if info, ok := grokWebModelMap[model]; ok {
		return info
	}
	return grokWebModelMap["grok-4.1-fast"]
}

// grokRandomString ports randomString (lowercase letters, optionally
// alphanumeric), backed by crypto/rand.
func grokRandomString(length int, alphanumeric bool) string {
	chars := "abcdefghijklmnopqrstuvwxyz"
	if alphanumeric {
		chars += "0123456789"
	}
	var sb strings.Builder
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		for i := 0; i < length; i++ {
			sb.WriteByte(chars[i%len(chars)])
		}
		return sb.String()
	}
	for _, b := range buf {
		sb.WriteByte(chars[int(b)%len(chars)])
	}
	return sb.String()
}

// grokGenerateStatsigID ports generateStatsigId: a base64-encoded fake
// TypeError message (the statsig id grok.com expects).
func grokGenerateStatsigID() string {
	var msg string
	coin := make([]byte, 1)
	_, _ = rand.Read(coin)
	if coin[0]%2 == 0 {
		msg = `e:TypeError: Cannot read properties of null (reading 'children["` + grokRandomString(5, true) + `"]')`
	} else {
		msg = `e:TypeError: Cannot read properties of undefined (reading '` + grokRandomString(10, false) + `')`
	}
	return base64.StdEncoding.EncodeToString([]byte(msg))
}

// grokRandomHex ports randomHex (crypto-backed lowercase hex).
func grokRandomHex(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", nBytes*2)
	}
	return hex.EncodeToString(buf)
}

// grokParseOpenAIMessages ports parseOpenAIMessages: flatten the message
// list into one prompt string — the last user message stays bare, every
// other message is prefixed "role: ".
func grokParseOpenAIMessages(messages []any) string {
	type grokMsg struct{ role, text string }
	var extracted []grokMsg
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg == nil {
			continue
		}
		role := getStr(msg, "role")
		if role == "" {
			role = "user"
		}
		if role == "developer" {
			role = "system"
		}
		content := ""
		switch c := msg["content"].(type) {
		case string:
			content = c
		case []any:
			var parts []string
			for _, praw := range c {
				part, _ := praw.(map[string]any)
				if part != nil && part["type"] == "text" {
					parts = append(parts, getStr(part, "text"))
				}
			}
			content = strings.Join(parts, " ")
		}
		if strings.TrimSpace(content) == "" {
			continue
		}
		extracted = append(extracted, grokMsg{role: role, text: content})
	}
	lastUserIdx := -1
	for i := len(extracted) - 1; i >= 0; i-- {
		if extracted[i].role == "user" {
			lastUserIdx = i
			break
		}
	}
	var parts []string
	for i, m := range extracted {
		if i == lastUserIdx {
			parts = append(parts, m.text)
		} else {
			parts = append(parts, m.role+": "+m.text)
		}
	}
	return strings.Join(parts, "\n\n")
}

// grokValueString renders an NDJSON scalar the way the JS would surface it
// in a delta/message slot (strings pass through; other JSON values are
// re-encoded).
func grokValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		raw, err := marshalJSON(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// grokNestedString walks nested objects for a string leaf.
func grokNestedString(m map[string]any, keys ...string) string {
	cur := m
	for i, k := range keys {
		if cur == nil {
			return ""
		}
		if i == len(keys)-1 {
			return getStr(cur, k)
		}
		cur, _ = cur[k].(map[string]any)
	}
	return ""
}

// grokWebEventState carries extractContent's per-stream state. thinkOpened
// is carried for fidelity but, as in the JS, is never set to true.
type grokWebEventState struct {
	fingerprint string
	responseID  string
	thinkOpened bool
}

// grokExtractEvent ports one step of extractContent: given one NDJSON
// event, report the delta / fullMessage / error it yields (if any),
// updating the fingerprint/responseId state.
func grokExtractEvent(event map[string]any, st *grokWebEventState) (delta string, hasDelta bool, full string, hasFull bool, errMsg string, hasErr bool) {
	if rawErr, present := event["error"]; present && rawErr != nil {
		msg := ""
		if errObj, ok := rawErr.(map[string]any); ok {
			msg = getStr(errObj, "message")
			if msg == "" {
				msg = "Grok error: " + grokValueString(errObj["code"])
			}
		} else if s, ok := rawErr.(string); ok {
			msg = s
		}
		if msg == "" {
			msg = "Grok error: "
		}
		return "", false, "", false, msg, true
	}
	result, _ := event["result"].(map[string]any)
	if result == nil {
		return
	}
	resp, _ := result["response"].(map[string]any)
	if resp == nil {
		return
	}
	if mh := grokNestedString(resp, "llmInfo", "modelHash"); mh != "" && st.fingerprint == "" {
		st.fingerprint = mh
	}
	if rid := getStr(resp, "responseId"); rid != "" {
		st.responseID = rid
	}
	if mr, ok := resp["modelResponse"].(map[string]any); ok && mr != nil {
		// JS: the thinking branch requires thinkOpened, which is never
		// set — modelResponse only ever yields fullMessage.
		if _, present := mr["message"]; present {
			full = grokValueString(mr["message"])
			hasFull = true
		}
		if mh := grokNestedString(mr, "metadata", "llm_info", "modelHash"); mh != "" {
			st.fingerprint = mh
		}
		return
	}
	if tok, present := resp["token"]; present && tok != nil {
		return grokValueString(tok), true, "", false, "", false
	}
	return
}

// grokWebJSONResponse builds a synthetic JSON HTTP response (the JS
// executor returns `new Response(JSON.stringify(...))` in these paths).
func grokWebJSONResponse(status int, v map[string]any) *http.Response {
	raw, _ := marshalJSON(v)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(raw))),
	}
}

// grokWebErrorResult wraps a synthetic error response as an ExecResult.
func grokWebErrorResult(status int, message, code string, url string, headers map[string]string, payload []byte) *ExecResult {
	body := map[string]any{
		"error": map[string]any{"message": message, "type": "upstream_error"},
	}
	if code != "" {
		body["error"].(map[string]any)["code"] = code
	}
	return &ExecResult{
		Response:        grokWebJSONResponse(status, body),
		URL:             url,
		Headers:         headers,
		TransformedBody: payload,
	}
}

// grokWebChunk builds one OpenAI chat.completion.chunk object (sseChunk
// payload shape from grok-web.js buildStreamingResponse).
func grokWebChunk(cid string, created int64, model, fingerprint string, delta map[string]any, finish any) map[string]any {
	fp := any(nil)
	if fingerprint != "" {
		fp = fingerprint
	}
	return map[string]any{
		"id": cid, "object": "chat.completion.chunk", "created": created,
		"model": model, "system_fingerprint": fp,
		"choices": []any{map[string]any{
			"index": 0, "delta": delta, "finish_reason": finish, "logprobs": nil,
		}},
	}
}

func grokWriteSSE(w io.Writer, chunk map[string]any) {
	raw, _ := marshalJSON(chunk)
	_, _ = io.WriteString(w, "data: "+string(raw)+"\n\n")
}

// grokConvertWebStream ports buildStreamingResponse: NDJSON in, OpenAI
// SSE chunks out. fullMessage events are ignored in streaming mode (the
// JS only handles delta/thinking/error/done chunks).
func grokConvertWebStream(r io.Reader, w io.Writer, model, cid string, created int64, isThinking bool) {
	_ = isThinking // only used by the (dead) thinking branch in the JS
	grokWriteSSE(w, grokWebChunk(cid, created, model, "", map[string]any{"role": "assistant"}, nil))
	st := &grokWebEventState{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event map[string]any
		if unmarshalJSON([]byte(line), &event) != nil || event == nil {
			continue
		}
		delta, hasDelta, _, _, errMsg, hasErr := grokExtractEvent(event, st)
		if hasErr {
			grokWriteSSE(w, grokWebChunk(cid, created, model, st.fingerprint,
				map[string]any{"content": "[Error: " + errMsg + "]"}, nil))
			break
		}
		if hasDelta && delta != "" {
			grokWriteSSE(w, grokWebChunk(cid, created, model, st.fingerprint,
				map[string]any{"content": delta}, nil))
		}
	}
	if err := scanner.Err(); err != nil {
		grokWriteSSE(w, grokWebChunk(cid, created, model, "",
			map[string]any{"content": "[Stream error: " + err.Error() + "]"}, "stop"))
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		return
	}
	grokWriteSSE(w, grokWebChunk(cid, created, model, st.fingerprint, map[string]any{}, "stop"))
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
}

// grokCollectWebResponse ports buildNonStreamingResponse's accumulation:
// token deltas concatenate, a modelResponse fullMessage replaces them.
func grokCollectWebResponse(r io.Reader, isThinking bool) (content string, fingerprint string, errMsg string) {
	_ = isThinking
	st := &grokWebEventState{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event map[string]any
		if unmarshalJSON([]byte(line), &event) != nil || event == nil {
			continue
		}
		delta, hasDelta, full, hasFull, eMsg, hasErr := grokExtractEvent(event, st)
		if hasErr {
			return "", st.fingerprint, eMsg
		}
		if hasFull && full != "" {
			content = full
		} else if hasDelta && delta != "" {
			content += delta
		}
	}
	return content, st.fingerprint, ""
}

// GrokWebExecutor is the Go port of GrokWebExecutor (bespoke Execute).
type GrokWebExecutor struct{ *Base }

// NewGrokWebExecutor builds the grok-web executor.
func NewGrokWebExecutor() *GrokWebExecutor {
	e := &GrokWebExecutor{}
	e.Base = &Base{ProviderID: "grok-web"}
	return e
}

func grokWebURL(p *ProviderInfo) string {
	if p != nil {
		if urls := p.BaseURLsList(); len(urls) > 0 && urls[0] != "" {
			return urls[0]
		}
	}
	return grokWebDefaultURL
}

// Execute ports GrokWebExecutor.execute (see the type comment for the
// protocol and preserved quirks).
func (e *GrokWebExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "grok-web"}
	}
	url := grokWebURL(p)
	bodyMap, _ := decodeBody(body)

	var messages []any
	if bodyMap != nil {
		messages, _ = bodyMap["messages"].([]any)
	}
	if len(messages) == 0 {
		res := grokWebErrorResult(400, "Missing or empty messages array", "", url, map[string]string{}, body)
		// Match the JS error shape: type invalid_request (no code field).
		res.Response = grokWebJSONResponse(400, map[string]any{
			"error": map[string]any{"message": "Missing or empty messages array", "type": "invalid_request"},
		})
		return res, nil
	}

	model := ModelOf(bodyMap)
	info := grokWebLookupModel(model)

	message := grokParseOpenAIMessages(messages)
	if strings.TrimSpace(message) == "" {
		res := grokWebErrorResult(400, "Empty query after processing", "", url, map[string]string{}, body)
		res.Response = grokWebJSONResponse(400, map[string]any{
			"error": map[string]any{"message": "Empty query after processing", "type": "invalid_request"},
		})
		return res, nil
	}
	stream := StreamRequested(bodyMap) || p.ForceStream

	grokPayload := map[string]any{
		"temporary": true, "modelName": info.GrokModel, "modelMode": info.ModelMode,
		"message":                     message,
		"fileAttachments":             []any{},
		"imageAttachments":            []any{},
		"disableSearch":               false,
		"enableImageGeneration":       false,
		"returnImageBytes":            false,
		"returnRawGrokInXaiRequest":   false,
		"enableImageStreaming":        false,
		"imageGenerationCount":        0,
		"forceConcise":                false,
		"toolOverrides":               map[string]any{},
		"enableSideBySide":            true,
		"sendFinalMetadata":           true,
		"isReasoning":                 false,
		"disableTextFollowUps":        false,
		"disableMemory":               true,
		"forceSideBySide":             false,
		"isAsyncChat":                 false,
		"disableSelfHarmShortCircuit": false,
		"deviceEnvInfo": map[string]any{
			"darkModeEnabled": false, "devicePixelRatio": 2,
			"screenWidth": 2056, "screenHeight": 1329,
			"viewportWidth": 2056, "viewportHeight": 1083,
		},
	}
	payload, err := marshalJSON(grokPayload)
	if err != nil {
		return nil, err
	}

	traceID := grokRandomHex(16)
	spanID := grokRandomHex(8)
	headers := map[string]string{
		"Accept":             "*/*",
		"Accept-Encoding":    "gzip, deflate, br, zstd",
		"Accept-Language":    "en-US,en;q=0.9",
		"Baggage":            "sentry-environment=production,sentry-release=d6add6fb0460641fd482d767a335ef72b9b6abb8,sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c",
		"Cache-Control":      "no-cache",
		"Content-Type":       "application/json",
		"Origin":             "https://grok.com",
		"Pragma":             "no-cache",
		"Referer":            "https://grok.com/",
		"Sec-Ch-Ua":          `"Google Chrome";v="136", "Chromium";v="136", "Not(A:Brand";v="24"`,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": `"macOS"`,
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"User-Agent":         grokWebUserAgent,
		"x-statsig-id":       grokGenerateStatsigID(),
		"x-xai-request-id":   newUUID(),
		"traceparent":        "00-" + traceID + "-" + spanID + "-00",
	}
	// SSO cookie: credentials.apiKey in the JS; the Go credential may also
	// carry it in providerSpecificData (sso/cookie). Strip an "sso=" prefix
	// the user may have pasted along with the value.
	token := cred.APIKey
	if token == "" {
		token = cred.SpecificString("sso")
	}
	if token == "" {
		token = cred.SpecificString("cookie")
	}
	if token == "" {
		token = cred.AccessToken
	}
	if token != "" {
		token = strings.TrimPrefix(token, "sso=")
		headers["Cookie"] = "sso=" + token
	}
	for k, v := range cred.OverrideHeaders {
		headers[k] = v
	}

	resp, err := doPost(ctx, url, headers, payload, connectTimeout(p))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return grokWebErrorResult(502, "Grok connection failed: "+err.Error(), "", url, headers, payload), nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.StatusCode
		drainClose(resp)
		errMsg := "Grok returned HTTP " + strconv.Itoa(status)
		switch status {
		case 401, 403:
			errMsg = "Grok auth failed — SSO cookie may be expired. Re-paste your sso cookie value from grok.com."
		case 429:
			errMsg = "Grok rate limited. Wait a moment and retry, or rotate cookies."
		}
		return grokWebErrorResult(status, errMsg, "HTTP_"+strconv.Itoa(status), url, headers, payload), nil
	}
	if resp.Body == nil {
		return grokWebErrorResult(502, "Grok returned empty response body", "", url, headers, payload), nil
	}

	cid := "chatcmpl-grok-" + newUUID()[:12]
	created := nowUnix()

	if stream {
		pr, pw := io.Pipe()
		go func() {
			grokConvertWebStream(resp.Body, pw, model, cid, created, info.IsThinking)
			resp.Body.Close()
			_ = pw.Close()
		}()
		return &ExecResult{
			Response: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type":      []string{"text/event-stream"},
					"Cache-Control":     []string{"no-cache"},
					"X-Accel-Buffering": []string{"no"},
				},
				Body: pr,
			},
			URL: url, Headers: headers, TransformedBody: payload,
			ResponseFormat: "openai",
		}, nil
	}

	content, fingerprint, errMsg := grokCollectWebResponse(resp.Body, info.IsThinking)
	resp.Body.Close()
	if errMsg != "" {
		return grokWebErrorResult(502, errMsg, "GROK_ERROR", url, headers, payload), nil
	}
	// JS usage quirk: both token counts derive from the response length.
	tokens := (len([]rune(content)) + 3) / 4
	msg := map[string]any{"role": "assistant", "content": content}
	fp := any(nil)
	if fingerprint != "" {
		fp = fingerprint
	}
	finalResp := grokWebJSONResponse(200, map[string]any{
		"id": cid, "object": "chat.completion", "created": created,
		"model": model, "system_fingerprint": fp,
		"choices": []any{map[string]any{
			"index": 0, "message": msg, "finish_reason": "stop", "logprobs": nil,
		}},
		"usage": map[string]any{
			"prompt_tokens": tokens, "completion_tokens": tokens,
			"total_tokens": tokens * 2,
		},
	})
	return &ExecResult{
		Response: finalResp, URL: url, Headers: headers,
		TransformedBody: payload, ResponseFormat: "openai",
	}, nil
}
