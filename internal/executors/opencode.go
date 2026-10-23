package executors

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Ports of open-sse/executors/opencode.js, opencode-go.js and
// opencode-zen.js — the OpenCode family. All three revolve around a stable
// x-opencode-session identity plus model-dependent endpoint lanes:
//
//   - opencode (free tier): bespoke BaseExecutor. Bearer public auth, v2 CLI
//     fingerprint headers, /inference/v1 lanes (responses for Muse Spark,
//     messages for union-alpha, chat otherwise), always stream:true, exact
//     read/shell fingerprint tools (utils/opencodeFingerprint.js).
//   - opencode-go: DefaultExecutor + /zen/go/v1/responses lane for
//     responses-target models (config/providerModels getModelTargetFormat),
//     translated ses_<sha256> session header, Responses body reshaping.
//   - opencode-zen: DefaultExecutor + /zen/v1/responses lane for Muse Spark
//     only, UA spoofing, simple bash/glob/grep/read fingerprint quartet, and
//     free-tier (-free) models forced onto the Bearer public identity with
//     an x-opencode-request id.
//
// Go-interface adaptations (documented divergences, same precedent as
// codex.go): the JS prepareRequestCredentials({providerSessionId,
// clientTool}) inputs have no counterpart in the Go Executor contract, so
// they are read from Credential.Specific ("providerSessionId" /
// "clientTool", default "generic") when the parent supplies them, and the
// session itself is resolved lazily per Request and cached in req.State.
// utils/sessionManager.js resolveSessionId is ported in the ocResolve*
// helpers below (client-header/body extraction, assistant-text store,
// per-connection derive store). The fingerprint rename map's response-side
// restoration (restoreToolNames) is translator/chatcore territory in Go —
// only the request side is ported. getThinkingLevels (providers/
// thinkingLevels.js + capabilities data) is not available to this
// package, so opencode's reasoning-effort clamp for max/ultra runs with an
// unknown level set and therefore never clamps (JS behaves the same when
// getThinkingLevels returns null).

const (
	ocSessionHeader    = "x-opencode-session"
	ocMaxSessionLength = 256
	ocMaxToolNameLen   = 128
	ocBase62Chars      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// opencode.js: OpenCode v2 UA shape; upstream rejects the v1 form.
	ocUA = "opencode/latest/2.0.26/cli"
	// opencode-zen.js OPENCODE_UA (v1 shape is fine on the Zen lane).
	ocZenUA                = "opencode/1.18.31"
	ocGoResponsesFallback  = "https://opencode.ai/zen/go/v1/responses"
	ocZenResponsesFallback = "https://opencode.ai/zen/v1/responses"
	ocFreeBaseFallback     = "https://opencode.ai"
	ocSessionTTL           = 2 * time.Hour // MEMORY_CONFIG.sessionTtlMs
)

var (
	ocSessionRe        = regexp.MustCompile(`^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$`)
	ocThinkingSuffixRe = regexp.MustCompile(`\([^()]+\)\s*$`)
	ocMuseSparkRe      = regexp.MustCompile(`(?i)^muse[-_]?spark($|[-_:.\s])`)
	ocFreeTierRe       = regexp.MustCompile(`(?i)-free$`)
	// opencode.js hasValidOpencodeVersion: anchored v2 shape.
	ocV2UARe = regexp.MustCompile(`(?i)^opencode/[a-z0-9-]+/(\d+)\.\d+\.\d+/[a-z0-9-]+$`)
	// opencode-zen.js hasValidOpencodeVersion: unanchored, >= 1.17.
	ocZenUARe         = regexp.MustCompile(`(?i)opencode/(\d+)\.(\d+)(?:\.(\d+))?`)
	ocClaudeSessionRe = regexp.MustCompile(`_session_([a-f0-9-]+)$`)
	ocAntigravityRe   = regexp.MustCompile(`(?i)^[a-z]+/([0-9a-f-]{36})/`)
	// Family fallback of getModelTargetFormat (providers/models/helpers.js
	// OPENCODE_FAMILIES): grok/gpt/muse-spark unknown ids target responses.
	ocFamilyResponsesRe = regexp.MustCompile(`(?i)^(grok|gpt|muse[-_]?spark)`)
	ocCallIDSeq         int64
)

// --- shared model helpers ---

// ocBaseModelID strips the thinking suffix "model(level)".
func ocBaseModelID(model string) string {
	return strings.TrimSpace(ocThinkingSuffixRe.ReplaceAllString(model, ""))
}

func ocModelBaseSegment(model string) string {
	base := ocBaseModelID(model)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return base
}

// ocIsMuseSparkModel ports providers/models/helpers.js isMuseSparkModel.
func ocIsMuseSparkModel(model string) bool {
	if model == "" {
		return false
	}
	return ocMuseSparkRe.MatchString(ocModelBaseSegment(model))
}

// ocIsFreeTierModel ports isOpencodeFreeTierModel ("-free" suffix).
func ocIsFreeTierModel(model string) bool {
	if model == "" {
		return false
	}
	return ocFreeTierRe.MatchString(ocModelBaseSegment(model))
}

// --- session id generation (opencode.js / opencode-zen.js) ---

func ocUnstableRandom() string {
	var b [14]byte
	if _, err := rand.Read(b[:]); err != nil {
		n := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(n >> (8 * (i % 8)))
		}
	}
	var sb strings.Builder
	for i := 0; i < 14; i++ {
		sb.WriteByte(ocBase62Chars[int(b[i])%62])
	}
	return sb.String()
}

// ocDescendingTimeHex ports descendingTimeHex: 12 hex of
// ~(time*0x1000 + counter), low 48 bits.
func ocDescendingTimeHex(tm, counter int64) string {
	v := (uint64(tm)*0x1000 + uint64(counter)) & ((1 << 48) - 1)
	return fmt.Sprintf("%012x", (^v)&((1<<48)-1))
}

var (
	ocGenMu      sync.Mutex
	ocGenLastTs  int64
	ocGenCounter int64
)

// ocGenerateSessionID ports opencode.js generateSessionId (real counter
// per timestamp — upstream rejects large counters).
func ocGenerateSessionID(ts int64) string {
	ocGenMu.Lock()
	if ts != ocGenLastTs {
		ocGenLastTs = ts
		ocGenCounter = 0
	}
	ocGenCounter++
	counter := ocGenCounter
	ocGenMu.Unlock()
	return "ses_" + ocDescendingTimeHex(ts, counter) + ocUnstableRandom()
}

// ocZenGenerateSessionID ports opencode-zen.js generateSessionId
// (counter pinned to 1).
func ocZenGenerateSessionID(ts int64) string {
	return "ses_" + ocDescendingTimeHex(ts, 1) + ocUnstableRandom()
}

// ocGenerateRequestID ports opencode-zen.js generateRequestId.
func ocGenerateRequestID(ts int64) string {
	v := uint64(ts)*0x1000 + 1
	var hexPart strings.Builder
	for i := 0; i < 6; i++ {
		shift := uint(40 - 8*i)
		fmt.Fprintf(&hexPart, "%02x", byte((v>>shift)&0xff))
	}
	return "msg_" + hexPart.String() + ocUnstableRandom()
}

// ocTranslateSessionID ports translateSessionId (identical in
// opencode.js and opencode-zen.js): valid ses_ ids pass through, anything
// else is hashed deterministically (counter pinned to 1).
func ocTranslateSessionID(sessionID, clientTool string) string {
	if ocSessionRe.MatchString(strings.TrimSpace(sessionID)) {
		return strings.TrimSpace(sessionID)
	}
	if clientTool == "" {
		clientTool = "generic"
	}
	digest := sha256.Sum256([]byte("opencode\x00" + clientTool + "\x00" + sessionID))
	var tm int64
	for i := 0; i < 5; i++ {
		tm = tm<<8 | int64(digest[i])
	}
	tm &= (1 << 36) - 1
	var sb strings.Builder
	for i := 6; i < 20; i++ {
		sb.WriteByte(ocBase62Chars[int(digest[i])%62])
	}
	return "ses_" + ocDescendingTimeHex(tm, 1) + sb.String()
}

// ocGoTranslatedSession ports opencode-go.js translatedSession:
// ses_ + first 32 hex chars of sha256("opencode-go\0<tool>\0<id>").
func ocGoTranslatedSession(sessionID, clientTool string) string {
	if clientTool == "" {
		clientTool = "generic"
	}
	sum := sha256.Sum256([]byte("opencode-go\x00" + clientTool + "\x00" + sessionID))
	return "ses_" + hex.EncodeToString(sum[:])[:32]
}

// --- session stores (utils/sessionManager.js + opencode.js stable map) ---

type ocSessionEntry struct {
	id       string
	lastUsed time.Time
}

type ocSessionStore struct {
	mu    sync.Mutex
	max   int
	items map[string]*ocSessionEntry
	order []string
}

func ocNewSessionStore(max int) *ocSessionStore {
	return &ocSessionStore{max: max, items: map[string]*ocSessionEntry{}}
}

func (s *ocSessionStore) get(key string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[key]
	if !ok {
		return "", false
	}
	if now.Sub(e.lastUsed) > ocSessionTTL {
		s.deleteLocked(key)
		return "", false
	}
	e.lastUsed = now
	s.touchLocked(key)
	return e.id, true
}

func (s *ocSessionStore) put(key, id string, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.items[key]; ok {
		e.lastUsed = now
		s.touchLocked(key)
		return e.id
	}
	for len(s.items) >= s.max && len(s.order) > 0 {
		s.deleteLocked(s.order[0])
	}
	s.items[key] = &ocSessionEntry{id: id, lastUsed: now}
	s.order = append(s.order, key)
	return id
}

func (s *ocSessionStore) touchLocked(key string) {
	for i, k := range s.order {
		if k == key {
			s.order = append(append([]string{}, s.order[:i]...), s.order[i+1:]...)
			break
		}
	}
	s.order = append(s.order, key)
}

func (s *ocSessionStore) deleteLocked(key string) {
	delete(s.items, key)
	for i, k := range s.order {
		if k == key {
			s.order = append(append([]string{}, s.order[:i]...), s.order[i+1:]...)
			break
		}
	}
}

var (
	ocDeriveStore    = ocNewSessionStore(1000) // sessionManager deriveSessionId
	ocAssistantStore = ocNewSessionStore(5000) // sessionManager assistant-text
	ocStableStore    = ocNewSessionStore(1000) // opencode.js stableOpencodeSessions
)

// ocBinaryStyleID ports sessionManager generateBinaryStyleId.
func ocBinaryStyleID() string {
	return newUUID() + strconv.FormatInt(time.Now().UnixMilli(), 10)
}

// ocRawHeader reads a client raw header case-insensitively.
func ocRawHeader(cred Credential, name string) string {
	if v, ok := cred.RawHeaders[name]; ok {
		return v
	}
	for k, v := range cred.RawHeaders {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func ocNormalizeSession(value string) string {
	n := strings.TrimSpace(value)
	if n == "" || len(n) > ocMaxSessionLength {
		return ""
	}
	return n
}

// ocNativeSession reads x-opencode-session from the raw headers; when
// requireRegex is set (opencode / opencode-zen) only ses_-shaped values
// count as native (opencode-go accepts any normalised value).
func ocNativeSession(cred Credential, requireRegex bool) string {
	for k, v := range cred.RawHeaders {
		if strings.EqualFold(k, ocSessionHeader) {
			n := ocNormalizeSession(v)
			if n == "" {
				return ""
			}
			if requireRegex && !ocSessionRe.MatchString(n) {
				return ""
			}
			return n
		}
	}
	return ""
}

func ocClientTool(cred Credential) string {
	if t := cred.SpecificString("clientTool"); t != "" {
		return t
	}
	return "generic"
}

func ocProviderSessionID(cred Credential) string {
	return ocNormalizeSession(cred.SpecificString("providerSessionId"))
}

// ocExtractClaudeSession ports extractClaudeCodeSession.
func ocExtractClaudeSession(userID string) string {
	if userID == "" {
		return ""
	}
	if m := ocClaudeSessionRe.FindStringSubmatch(userID); m != nil {
		return m[1]
	}
	if strings.HasPrefix(userID, "{") {
		var obj map[string]any
		if unmarshalJSON([]byte(userID), &obj) == nil {
			return ocNormalizeSession(getStr(obj, "session_id"))
		}
	}
	return ""
}

// ocExtractClientSessionID ports sessionManager extractClientSessionId
// (scope is never "kiro" for the OpenCode family).
func ocExtractClientSessionID(cred Credential, body map[string]any) string {
	meta, _ := body["metadata"].(map[string]any)
	if claude := ocExtractClaudeSession(getStr(meta, "user_id")); claude != "" {
		return "claude:" + claude
	}
	if h := ocNormalizeSession(ocRawHeader(cred, "x-claude-code-session-id")); h != "" {
		return "claude:" + h
	}
	// Antigravity envelope (body.request.sessionId / requestId pattern).
	if reqObj, _ := body["request"].(map[string]any); reqObj != nil {
		if v, present := reqObj["sessionId"]; present && v != nil {
			if s := ocNormalizeSession(fmt.Sprint(v)); s != "" {
				return "antigravity:" + s
			}
		}
	}
	if rid := getStr(body, "requestId"); rid != "" {
		if m := ocAntigravityRe.FindStringSubmatch(rid); m != nil {
			if s := ocNormalizeSession(m[1]); s != "" {
				return "antigravity:" + s
			}
		}
	}
	for _, key := range []string{"x-session-id", "session-id", "session_id", "x-amp-thread-id"} {
		if v := ocNormalizeSession(ocRawHeader(cred, key)); v != "" {
			return v
		}
	}
	if v := ocNormalizeSession(ocRawHeader(cred, "x-client-request-id")); v != "" {
		return v
	}
	if v := ocNormalizeSession(getStr(body, "prompt_cache_key")); v != "" {
		return v
	}
	if v := ocNormalizeSession(getStr(body, "session_id")); v != "" {
		return v
	}
	if v := ocNormalizeSession(getStr(body, "conversation_id")); v != "" {
		return v
	}
	if meta != nil {
		if v := ocNormalizeSession(getStr(meta, "user_id")); v != "" {
			return v
		}
	}
	return ""
}

// ocAssistantText ports sessionManager accumulateAssistantText (cap 50).
func ocAssistantText(body map[string]any) string {
	var items []any
	if m, ok := body["messages"].([]any); ok {
		items = m
	} else if in, ok := body["input"].([]any); ok {
		items = in
	}
	var sb strings.Builder
	for _, raw := range items {
		msg, _ := raw.(map[string]any)
		if msg == nil || msg["role"] != "assistant" {
			continue
		}
		switch c := msg["content"].(type) {
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

// ocResolveSessionID ports sessionManager resolveSessionId:
// client session → assistant-text hash → per-connection derived id.
func ocResolveSessionID(cred Credential, body map[string]any, scope string) string {
	if client := ocExtractClientSessionID(cred, body); client != "" {
		return client
	}
	if text := ocAssistantText(body); len(text) >= 50 {
		runes := []rune(text)
		if len(runes) > 50 {
			runes = runes[:50]
		}
		sum := sha256.Sum256([]byte(scope + ":" + cred.ConnectionID + ":" + string(runes)))
		key := hex.EncodeToString(sum[:])[:16]
		now := time.Now()
		if id, ok := ocAssistantStore.get(key, now); ok {
			return id
		}
		return ocAssistantStore.put(key, ocBinaryStyleID(), now)
	}
	// deriveSessionId(connectionId)
	now := time.Now()
	if cred.ConnectionID != "" {
		if id, ok := ocDeriveStore.get(cred.ConnectionID, now); ok {
			return id
		}
		return ocDeriveStore.put(cred.ConnectionID, ocBinaryStyleID(), now)
	}
	return ocBinaryStyleID()
}

// ocBodyHasSessionHints ports opencode.js bodyHasSessionHints.
func ocBodyHasSessionHints(body map[string]any) bool {
	if body == nil {
		return false
	}
	if strings.TrimSpace(getStr(body, "session_id")) != "" {
		return true
	}
	if strings.TrimSpace(getStr(body, "conversation_id")) != "" {
		return true
	}
	if strings.TrimSpace(getStr(body, "prompt_cache_key")) != "" {
		return true
	}
	if meta, _ := body["metadata"].(map[string]any); meta != nil &&
		strings.TrimSpace(getStr(meta, "user_id")) != "" {
		return true
	}
	if reqObj, _ := body["request"].(map[string]any); reqObj != nil {
		if v, present := reqObj["sessionId"]; present && v != nil && fmt.Sprint(v) != "" {
			return true
		}
	}
	return len(ocAssistantText(body)) >= 50
}

// ocStableSessionID ports opencode.js stableSessionId + identityKey.
func ocStableSessionID(cred Credential) string {
	key := "opencode:default"
	if cred.ConnectionID != "" {
		id := cred.ConnectionID
		if len(id) > 128 {
			id = id[:128]
		}
		key = "opencode:conn:" + id
	} else {
		auth := ocRawHeader(cred, "authorization")
		if auth == "" {
			auth = ocRawHeader(cred, "x-api-key")
		}
		if auth != "" {
			sum := sha256.Sum256([]byte(auth))
			key = "opencode:auth:" + hex.EncodeToString(sum[:])[:32]
		}
	}
	now := time.Now()
	if id, ok := ocStableStore.get(key, now); ok {
		return id
	}
	return ocStableStore.put(key, ocGenerateSessionID(now.UnixMilli()), now)
}

// ocResolveOpencodeSession ports opencode.js resolveOpencodeSession.
func ocResolveOpencodeSession(cred Credential, body map[string]any) string {
	if native := ocNativeSession(cred, true); native != "" {
		return native
	}
	incoming := ocNormalizeSession(ocRawHeader(cred, ocSessionHeader))
	hinted := incoming
	if hinted == "" {
		hinted = ocProviderSessionID(cred)
	}
	if hinted != "" {
		return ocTranslateSessionID(hinted, ocClientTool(cred))
	}
	if cred.ConnectionID != "" || ocBodyHasSessionHints(body) {
		if via := ocResolveSessionID(cred, body, "opencode"); via != "" {
			return ocTranslateSessionID(via, ocClientTool(cred))
		}
	}
	return ocStableSessionID(cred)
}

// --- Responses body reshaping (translator/formats/responsesApi.js) ---

// ocNormalizeResponsesInput ports normalizeResponsesInput.
func ocNormalizeResponsesInput(input any) (any, bool) {
	switch v := input.(type) {
	case string:
		text := v
		if strings.TrimSpace(text) == "" {
			text = "..."
		}
		return []any{ocResponsesPlaceholderItem(text)}, true
	case []any:
		if len(v) == 0 {
			return []any{ocResponsesPlaceholderItem("...")}, true
		}
		return v, true
	}
	return nil, false
}

func ocResponsesPlaceholderItem(text string) map[string]any {
	return map[string]any{
		"type": "message", "role": "user",
		"content": []any{map[string]any{"type": "input_text", "text": text}},
	}
}

// ocClampResponsesCallID ports clampResponsesCallId (max 64).
func ocClampResponsesCallID(id any) string {
	s, ok := id.(string)
	if !ok || s == "" {
		seq := atomic.AddInt64(&ocCallIDSeq, 1)
		return fmt.Sprintf("call_%d_%d", time.Now().UnixMilli(), seq)
	}
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// ocCoerceResponsesArguments ports coerceResponsesArguments.
func ocCoerceResponsesArguments(v any) string {
	if v == nil {
		return "{}"
	}
	if s, ok := v.(string); ok {
		if s == "" {
			return "{}"
		}
		if json.Valid([]byte(s)) {
			return s
		}
		return "{}"
	}
	raw, err := marshalJSON(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// ocCoerceResponsesOutput ports coerceResponsesOutput.
func ocCoerceResponsesOutput(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	if arr, ok := v.([]any); ok {
		var sb strings.Builder
		for _, c := range arr {
			if part, ok := c.(map[string]any); ok {
				if t, present := part["text"]; present && t != nil {
					if s, ok := t.(string); ok {
						sb.WriteString(s)
						continue
					}
				}
			}
			if raw, err := marshalJSON(c); err == nil {
				sb.WriteString(string(raw))
			} else {
				sb.WriteString(fmt.Sprint(c))
			}
		}
		return sb.String()
	}
	if raw, err := marshalJSON(v); err == nil {
		return string(raw)
	}
	return fmt.Sprint(v)
}

func ocToolNameOf(tool map[string]any) string {
	if tool == nil {
		return ""
	}
	if s, ok := tool["name"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	if fn, ok := tool["function"].(map[string]any); ok {
		if s, ok := fn["name"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// ocNormalizeResponsesTools ports normalizeResponsesTools (identical in
// all three JS files): flatten chat tool declarations into the Responses
// flat shape, drop nameless/hosted tools, prune dangling tool_choice.
func ocNormalizeResponsesTools(body map[string]any) {
	tools, ok := body["tools"].([]any)
	if !ok {
		return
	}
	valid := map[string]bool{}
	out := make([]any, 0, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok || tool == nil {
			continue
		}
		var fn map[string]any
		if f, ok := tool["function"].(map[string]any); ok {
			fn = f
		}
		rawName, _ := tool["name"].(string)
		if rawName == "" && fn != nil {
			rawName, _ = fn["name"].(string)
		}
		name := strings.TrimSpace(rawName)
		if name == "" {
			continue
		}
		desc, _ := tool["description"].(string)
		if desc == "" && fn != nil {
			desc, _ = fn["description"].(string)
		}
		var params map[string]any
		if p, ok := tool["parameters"].(map[string]any); ok {
			params = p
		} else if fn != nil {
			if p, ok := fn["parameters"].(map[string]any); ok {
				params = p
			}
		}
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		} else if params["type"] == "object" {
			if _, present := params["properties"]; !present || params["properties"] == nil {
				params = cloneMap(params)
				params["properties"] = map[string]any{}
			}
		}
		if len(name) > ocMaxToolNameLen {
			name = name[:ocMaxToolNameLen]
		}
		nt := map[string]any{"type": "function", "name": name, "parameters": params}
		if desc != "" {
			nt["description"] = desc
		}
		valid[name] = true
		out = append(out, nt)
	}
	body["tools"] = out
	if choice, ok := body["tool_choice"].(map[string]any); ok && choice["type"] == "function" {
		n := ""
		if s, ok := choice["name"].(string); ok {
			n = strings.TrimSpace(s)
		}
		if n == "" || !valid[n] {
			delete(body, "tool_choice")
		}
	}
}

// ocSanitizeResponsesItems ports sanitizeResponsesItems (identical in all
// three JS files): drop prior reasoning items (their encrypted_content is
// bound to the issuing account), clamp/coerce function-call payloads.
func ocSanitizeResponsesItems(body map[string]any) {
	input, ok := body["input"].([]any)
	if !ok {
		return
	}
	out := make([]any, 0, len(input))
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || item == nil {
			out = append(out, raw)
			continue
		}
		if item["type"] == "reasoning" {
			continue
		}
		delete(item, "encrypted_content")
		delete(item, "reasoning_encrypted_content")
		switch item["type"] {
		case "function_call":
			name, _ := item["name"].(string)
			if strings.TrimSpace(name) == "" {
				continue
			}
			name = strings.TrimSpace(name)
			if len(name) > ocMaxToolNameLen {
				name = name[:ocMaxToolNameLen]
			}
			item["name"] = name
			item["call_id"] = ocClampResponsesCallID(item["call_id"])
			item["arguments"] = ocCoerceResponsesArguments(item["arguments"])
		case "function_call_output":
			item["call_id"] = ocClampResponsesCallID(item["call_id"])
			item["output"] = ocCoerceResponsesOutput(item["output"])
		}
		out = append(out, item)
	}
	body["input"] = out
}

// ocMigrateResponsesTokens ports the max_tokens → max_output_tokens
// migration shared by all three executors' responses lanes.
func ocMigrateResponsesTokens(body map[string]any) {
	if _, present := body["max_output_tokens"]; !present {
		if v, present := body["max_completion_tokens"]; present {
			body["max_output_tokens"] = v
		} else if v, present := body["max_tokens"]; present {
			body["max_output_tokens"] = v
		}
	}
	delete(body, "max_tokens")
	delete(body, "max_completion_tokens")
}

// ocResponsesReasoning ports the reasoning_effort → reasoning conversion
// shared by opencode-go.js and opencode-zen.js.
func ocResponsesReasoning(body map[string]any) {
	if _, present := body["reasoning_effort"]; present {
		if _, hasReasoning := body["reasoning"]; !hasReasoning {
			body["reasoning"] = map[string]any{
				"effort":  body["reasoning_effort"],
				"summary": "auto",
			}
		}
	}
	if r, ok := body["reasoning"].(map[string]any); ok {
		// JS: if (!reasoning.summary) reasoning.summary = "auto".
		switch v := r["summary"].(type) {
		case nil:
			r["summary"] = "auto"
		case string:
			if v == "" {
				r["summary"] = "auto"
			}
		case bool:
			if !v {
				r["summary"] = "auto"
			}
		}
	}
	delete(body, "reasoning_effort")
}

// ocResponsesLaneBody applies the shared responses-lane reshaping used by
// opencode-go / opencode-zen (input normalise + placeholder, token
// migration, reasoning conversion, forced streaming, store=false). Tool
// handling differs per executor and stays with the caller.
func ocResponsesLaneBody(body map[string]any) {
	if normalized, ok := ocNormalizeResponsesInput(body["input"]); ok {
		body["input"] = normalized
	}
	if arr, ok := body["input"].([]any); !ok || len(arr) == 0 {
		body["input"] = []any{ocResponsesPlaceholderItem("...")}
	}
	ocMigrateResponsesTokens(body)
	ocResponsesReasoning(body)
	body["stream"] = true
	body["store"] = false
}

// ocResponsesURL derives the /responses endpoint for opencode-go /
// opencode-zen. JS hardcodes the production URL; here a responses
// RuntimeTransport wins when present (chatcore resolved it from the same
// registry, so in production it IS the JS constant), otherwise the lane
// is derived from the provider base URL (…/chat/completions or
// …/messages → …/responses), falling back to the JS constant.
func ocResponsesURL(req *Request, fallback string) string {
	if rt := req.Cred.RuntimeTransport; rt != nil && rt.Format == "openai-responses" && rt.BaseURL != "" {
		return rt.BaseURL
	}
	base := ""
	if req.Provider != nil {
		base = req.Provider.BaseURL
	}
	trimmed := strings.TrimSuffix(base, "/")
	for _, suffix := range []string{"/chat/completions", "/messages", "/responses"} {
		if strings.HasSuffix(trimmed, suffix) {
			return strings.TrimSuffix(trimmed, suffix) + "/responses"
		}
	}
	if trimmed == "" || strings.Contains(trimmed, "opencode.ai") {
		return fallback
	}
	return trimmed + "/responses"
}

// --- opencode.js fingerprint tools (utils/opencodeFingerprint.js) ---

var ocFingerprintToolNames = []string{"read", "shell"}

// ocFingerprintDef returns the verbatim OpenCode v2.0.26 CLI definition
// for a fingerprint tool (upstream compares description + parameters).
func ocFingerprintDef(name string) (string, map[string]any) {
	switch name {
	case "read":
		return "Read the contents of a file or directory. Supports text files, images, and PDFs. Images and PDFs are presented directly to the model. Each text line is prefixed by its 1-based line number as <line>: <content>. The prefix is for reference and is not part of the file content. Directory entries are returned one per line. Use offset and limit to read large files or directories in sections. Prefer one larger read over many small slices, and use grep to find specific content in large files.",
			map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":   map[string]any{"type": "string", "description": "File or directory to read"},
					"offset": map[string]any{"type": "integer", "minimum": 0, "description": "The line or directory entry to start reading from (1-based)"},
					"limit":  map[string]any{"type": "integer", "minimum": 0, "description": "The maximum number of lines or directory entries to read (defaults to and capped at 2000)"},
				},
				"required":             []any{"path"},
				"additionalProperties": false,
			}
	case "shell":
		return "Execute a shell command and return its output. Commands run on Linux using bash. Quote file paths containing spaces or special characters. Prefer dedicated tools over shell commands when possible. When output is large, the full result is saved to a file and a truncated preview is returned. Rely on automatic truncation unless filtering the output is more useful. Commands accept an optional timeout, background commands have no timeout by default. Background commands return immediately, and you will be notified when they complete.",
			map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command":    map[string]any{"type": "string", "description": "Shell command string to execute"},
					"workdir":    map[string]any{"type": "string", "description": "Working directory to execute the command in. Defaults to the current working directory. When possible, avoid changing directories in the command and set the working directory here instead."},
					"timeout":    map[string]any{"type": "integer", "minimum": 0, "description": "Timeout in milliseconds. Set to 0 to disable the timeout. Defaults to 120000 for foreground commands. Background commands have no timeout by default."},
					"background": map[string]any{"type": "boolean", "description": "Run the command in the background and return immediately (useful for dev servers and long-running builds). You do not need to use '&' at the end of the command when using this parameter. You will be notified when it completes. DO NOT poll for completion."},
				},
				"required":             []any{"command"},
				"additionalProperties": false,
			}
	}
	return "", nil
}

func ocFingerprintKey(name string) string {
	trimmed := strings.TrimSpace(name)
	for _, n := range ocFingerprintToolNames {
		if trimmed == n {
			return n
		}
	}
	return ""
}

func ocCanonicalJSON(v any) string {
	raw, err := marshalJSON(v)
	if err != nil {
		return ""
	}
	// Re-marshal through a generic decode so json.Number / int shapes
	// normalise the same way on both sides of the comparison.
	var generic any
	dec := jsonDecoder(raw)
	if err := dec.Decode(&generic); err != nil {
		return string(raw)
	}
	out, err := marshalJSON(generic)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// ocIsFingerprintDefinition ports isFingerprintDefinition.
func ocIsFingerprintDefinition(tool map[string]any, key string) bool {
	holder := tool
	if fn, ok := tool["function"].(map[string]any); ok && fn != nil {
		holder = fn
	}
	wantDesc, wantParams := ocFingerprintDef(key)
	desc, _ := holder["description"].(string)
	if desc != wantDesc {
		return false
	}
	return ocCanonicalJSON(holder["parameters"]) == ocCanonicalJSON(wantParams)
}

// ocApplyFingerprintTools ports applyFingerprintTools(body, flat):
// conceal conflicting caller tools under an alias, append OpenCode's
// exact definitions for the missing names, retarget tool_choice and
// history calls, and note the placeholders in the prompt. The returned
// rename map (sent → original) mirrors the JS WeakMap entry; the Go
// response pipeline cannot consume it (see file header), so callers
// currently discard it.
func ocApplyFingerprintTools(body map[string]any, flat bool) map[string]string {
	rename := map[string]string{}
	if body == nil {
		return rename
	}
	var tools []any
	if t, ok := body["tools"].([]any); ok {
		tools = t
	}
	// concealFingerprintToolNames
	taken := map[string]bool{}
	for _, raw := range tools {
		if tool, ok := raw.(map[string]any); ok {
			if n := ocToolNameOf(tool); n != "" {
				taken[n] = true
			}
		}
	}
	seen := map[string]bool{}
	concealed := make([]any, 0, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok || tool == nil {
			concealed = append(concealed, raw)
			continue
		}
		key := ocFingerprintKey(ocToolNameOf(tool))
		if key == "" {
			concealed = append(concealed, raw)
			continue
		}
		if seen[key] {
			continue // duplicate declaration: keep the first only
		}
		seen[key] = true
		if ocIsFingerprintDefinition(tool, key) {
			concealed = append(concealed, raw)
			continue
		}
		alias := key + "_client"
		for i := 2; taken[alias]; i++ {
			alias = key + "_client" + strconv.Itoa(i)
		}
		taken[alias] = true
		rename[alias] = key
		renamed := cloneMap(tool)
		if fn, ok := renamed["function"].(map[string]any); ok && fn != nil {
			nfn := cloneMap(fn)
			nfn["name"] = alias
			renamed["function"] = nfn
		} else {
			renamed["name"] = alias
		}
		concealed = append(concealed, renamed)
	}
	tools = concealed
	// appendMissingFingerprintTools
	var appended []string
	for _, name := range ocFingerprintToolNames {
		found := false
		for _, raw := range tools {
			if tool, ok := raw.(map[string]any); ok && ocFingerprintKey(ocToolNameOf(tool)) == name {
				found = true
				break
			}
		}
		if found {
			continue
		}
		desc, params := ocFingerprintDef(name)
		if flat {
			tools = append(tools, map[string]any{
				"type": "function", "name": name, "description": desc,
				"parameters": params, "strict": false,
			})
		} else {
			tools = append(tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": name, "description": desc, "parameters": params,
				},
			})
		}
		appended = append(appended, name)
	}
	body["tools"] = tools
	// retargetToolChoice + aliasHistoryToolCalls
	if len(rename) > 0 {
		byOriginal := map[string]string{}
		for alias, orig := range rename {
			byOriginal[orig] = alias
		}
		if choice, ok := body["tool_choice"].(map[string]any); ok && choice != nil {
			if n, ok := choice["name"].(string); ok {
				if alias, hit := byOriginal[strings.TrimSpace(n)]; hit {
					nc := cloneMap(choice)
					nc["name"] = alias
					body["tool_choice"] = nc
				}
			} else if fn, ok := choice["function"].(map[string]any); ok && fn != nil {
				if n, ok := fn["name"].(string); ok {
					if alias, hit := byOriginal[strings.TrimSpace(n)]; hit {
						nc := cloneMap(choice)
						nfn := cloneMap(fn)
						nfn["name"] = alias
						nc["function"] = nfn
						body["tool_choice"] = nc
					}
				}
			}
		}
		if input, ok := body["input"].([]any); ok {
			for i, raw := range input {
				item, ok := raw.(map[string]any)
				if !ok || item == nil || item["type"] != "function_call" {
					continue
				}
				if n, ok := item["name"].(string); ok {
					if alias, hit := byOriginal[n]; hit {
						ni := cloneMap(item)
						ni["name"] = alias
						input[i] = ni
					}
				}
			}
		}
		if msgs, ok := body["messages"].([]any); ok {
			for i, raw := range msgs {
				msg, ok := raw.(map[string]any)
				if !ok || msg == nil {
					continue
				}
				calls, ok := msg["tool_calls"].([]any)
				if !ok {
					continue
				}
				nmsg := cloneMap(msg)
				ncalls := make([]any, len(calls))
				copy(ncalls, calls)
				for j, craw := range calls {
					call, ok := craw.(map[string]any)
					if !ok || call == nil {
						continue
					}
					fn, _ := call["function"].(map[string]any)
					if fn == nil {
						continue
					}
					if n, ok := fn["name"].(string); ok {
						if alias, hit := byOriginal[n]; hit {
							ncall := cloneMap(call)
							nfn := cloneMap(fn)
							nfn["name"] = alias
							ncall["function"] = nfn
							ncalls[j] = ncall
						}
					}
				}
				nmsg["tool_calls"] = ncalls
				msgs[i] = nmsg
			}
		}
	}
	// noteUnavailableTools
	if len(appended) > 0 {
		var quoted []string
		for _, n := range appended {
			quoted = append(quoted, "`"+n+"`")
		}
		list := strings.Join(quoted, " or ")
		var note string
		if len(appended) > 1 {
			note = "Do not call the " + list + " tools; they are placeholders that do nothing. Use the other tools you have been given instead."
		} else {
			note = "Do not call the " + list + " tool; it is a placeholder that does nothing. Use the other tools you have been given instead."
		}
		if flat {
			if instr, ok := body["instructions"].(string); ok && strings.TrimSpace(instr) != "" {
				body["instructions"] = instr + "\n\n" + note
			} else {
				body["instructions"] = note
			}
		} else if msgs, ok := body["messages"].([]any); ok {
			if _, hasSystem := body["system"]; !hasSystem {
				noted := false
				if len(msgs) > 0 {
					if first, ok := msgs[0].(map[string]any); ok && first["role"] == "system" {
						if content, ok := first["content"].(string); ok {
							nf := cloneMap(first)
							nf["content"] = content + "\n\n" + note
							body["messages"] = append([]any{nf}, msgs[1:]...)
							noted = true
						}
					}
				}
				if !noted {
					body["messages"] = append([]any{map[string]any{"role": "system", "content": note}}, msgs...)
				}
			}
		}
	}
	if flat {
		if _, present := body["tool_choice"]; !present {
			body["tool_choice"] = "auto"
		}
	}
	return rename
}

// --- opencode-zen.js fingerprint quartet (simple stub variant) ---

var ocZenFingerprintTools = []string{"bash", "glob", "grep", "read"}

func ocZenEnsureFingerprintTools(body map[string]any, flat bool) {
	if body == nil {
		return
	}
	var tools []any
	if t, ok := body["tools"].([]any); ok {
		tools = t
	} else {
		tools = []any{}
	}
	present := map[string]bool{}
	for _, raw := range tools {
		if tool, ok := raw.(map[string]any); ok {
			if n := ocToolNameOf(tool); n != "" {
				present[n] = true
			}
		}
	}
	for _, name := range ocZenFingerprintTools {
		if present[name] {
			continue
		}
		desc := "OpenCode built-in " + name + " tool"
		params := map[string]any{"type": "object", "properties": map[string]any{}}
		if flat {
			tools = append(tools, map[string]any{
				"type": "function", "name": name, "description": desc, "parameters": params,
			})
		} else {
			tools = append(tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": name, "description": desc, "parameters": params,
				},
			})
		}
		present[name] = true
	}
	body["tools"] = tools
}

// --- opencode (free) executor ---

// OpencodeExecutor ports open-sse/executors/opencode.js: a bespoke
// BaseExecutor for the OpenCode free tier (/inference/v1). Live-unverified:
// the free-tier gates (session shape, fingerprint definitions, UA) are
// ported from the JS + its live-probe comments, but no account/session was
// available here to re-verify end to end.
type OpencodeExecutor struct{ *Base }

func NewOpencodeExecutor() *OpencodeExecutor {
	e := &OpencodeExecutor{}
	e.Base = &Base{ProviderID: "opencode", Hooks: Hooks{
		BuildURL:      e.ocBuildURL,
		BuildHeaders:  e.ocBuildHeaders,
		TransformBody: e.ocTransformBody,
	}}
	return e
}

var ocResponsesModelIDs = map[string]bool{
	"muse-spark-1.2-contributor-free": true,
	"muse-spark-1.3-contributor-free": true,
}

var ocMessagesModelIDs = map[string]bool{"union-alpha": true}

func ocIsResponsesModel(model string) bool {
	base := ocBaseModelID(model)
	return ocResponsesModelIDs[base] || ocIsMuseSparkModel(base)
}

func ocIsMessagesModel(model string) bool {
	return ocMessagesModelIDs[ocBaseModelID(model)]
}

func (e *OpencodeExecutor) ocModel(req *Request) string {
	if req.Model != "" {
		return req.Model
	}
	return getStr(req.Body, "model")
}

func (e *OpencodeExecutor) ocBuildURL(b *Base, req *Request, urlIndex int) (string, error) {
	base := req.Provider.BaseURL
	if base == "" {
		base = ocFreeBaseFallback
	}
	base = strings.TrimSuffix(base, "/")
	model := e.ocModel(req)
	switch {
	case ocIsResponsesModel(model):
		return base + "/inference/v1/responses", nil
	case ocIsMessagesModel(model):
		return base + "/inference/v1/messages", nil
	default:
		return base + "/inference/v1/chat/completions", nil
	}
}

func (e *OpencodeExecutor) ocSession(req *Request) string {
	if req.State != nil {
		if s, ok := req.State["ocSession"].(string); ok && s != "" {
			return s
		}
	}
	s := ocResolveOpencodeSession(req.Cred, req.Body)
	if req.State != nil {
		req.State["ocSession"] = s
	}
	return s
}

func (e *OpencodeExecutor) ocBuildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	downstreamUA := ocRawHeader(req.Cred, "user-agent")
	ua := ocUA
	if m := ocV2UARe.FindStringSubmatch(downstreamUA); m != nil {
		if major, err := strconv.Atoi(m[1]); err == nil && major >= 2 {
			ua = downstreamUA
		}
	}
	session := e.ocSession(req)
	client := ocRawHeader(req.Cred, "x-opencode-client")
	if client == "" {
		client = "cli"
	}
	project := ocRawHeader(req.Cred, "x-opencode-project")
	if project == "" {
		project = "global"
	}
	accept := "*/*"
	if req.Stream {
		accept = "text/event-stream"
	}
	headers := map[string]string{
		"Content-Type":          "application/json",
		"Authorization":         "Bearer public",
		"User-Agent":            ua,
		"x-opencode-client":     client,
		"x-opencode-session":    session,
		"x-opencode-session-id": session,
		"x-session-affinity":    session,
		"x-session-id":          session,
		"x-opencode-project":    project,
		"Accept":                accept,
	}
	if strings.HasSuffix(url, "/messages") {
		headers["anthropic-version"] = anthropicAPIVersion
	}
	return headers, nil
}

// ocNormalizeReasoning ports opencode.js normalizeOpencodeReasoning.
// supportedLevels stands in for getThinkingLevels("opencode", model),
// whose capability data lives outside this package: nil = unknown, in
// which case the JS clamp (guarded on a non-empty level list) never runs.
func ocNormalizeReasoning(model string, body map[string]any, supportedLevels []string) {
	var current map[string]any
	if r, ok := body["reasoning"].(map[string]any); ok {
		current = r
	}
	requested, isStr := body["reasoning_effort"].(string)
	if !isStr {
		if current != nil {
			requested, isStr = current["effort"].(string)
		}
	}
	if !isStr {
		return
	}
	effort := strings.ToLower(strings.TrimSpace(requested))
	if (effort == "max" || effort == "ultra") && len(supportedLevels) > 0 {
		contains := false
		for _, l := range supportedLevels {
			if l == effort {
				contains = true
			}
		}
		if !contains {
			hasMax, hasXhigh := false, false
			for _, l := range supportedLevels {
				if l == "max" {
					hasMax = true
				}
				if l == "xhigh" {
					hasXhigh = true
				}
			}
			if effort == "ultra" && hasMax {
				effort = "max"
			} else if hasXhigh {
				effort = "xhigh"
			}
		}
	}
	reasoning := cloneMap(current)
	if reasoning == nil {
		reasoning = map[string]any{}
	}
	reasoning["effort"] = effort
	if s, _ := reasoning["summary"].(string); s == "" {
		reasoning["summary"] = "auto"
	}
	body["reasoning"] = reasoning
	delete(body, "reasoning_effort")
}

func (e *OpencodeExecutor) ocTransformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	model := e.ocModel(req)
	if model != "" {
		if _, present := body["model"]; !present {
			body["model"] = model
		}
	}
	// Free tier rejects non-streaming requests; always stream upstream
	// and let the handler layer aggregate for non-stream clients.
	body["stream"] = true
	if ocIsResponsesModel(model) {
		// Force tool_choice "auto" only for models the registry quirks
		// flag (PROVIDERS.opencode quirks.forceAutoToolChoiceModels);
		// JS: `"tool_choice" in body && body.tool_choice !== "auto"`.
		if tc, present := body["tool_choice"]; present {
			if s, ok := tc.(string); !ok || s != "auto" {
				if ocQuirkForceAutoModel(req.Provider, model) {
					body["tool_choice"] = "auto"
				}
			}
		}
		if normalized, ok := ocNormalizeResponsesInput(body["input"]); ok {
			body["input"] = normalized
		}
		if arr, ok := body["input"].([]any); !ok || len(arr) == 0 {
			body["input"] = []any{ocResponsesPlaceholderItem("...")}
		}
		ocMigrateResponsesTokens(body)
		ocNormalizeReasoning(model, body, nil)
		body["stream"] = true
		body["store"] = false
		ocNormalizeResponsesTools(body)
		ocSanitizeResponsesItems(body)
		ocApplyFingerprintTools(body, true)
	} else {
		ocApplyFingerprintTools(body, false)
	}
	if ReasoningInjector != nil {
		if out := ReasoningInjector(b.ProviderID, model, body); out != nil {
			return out, nil
		}
	}
	return body, nil
}

// ocQuirkForceAutoModel reads quirks.forceAutoToolChoiceModels from the
// provider registry data carried in ProviderInfo.Quirks.
func ocQuirkForceAutoModel(p *ProviderInfo, model string) bool {
	if p == nil || p.Quirks == nil {
		return false
	}
	list, ok := p.Quirks["forceAutoToolChoiceModels"].([]any)
	if !ok {
		return false
	}
	base := ocBaseModelID(model)
	for _, v := range list {
		if s, ok := v.(string); ok && s == base {
			return true
		}
	}
	return false
}

// --- opencode-go executor ---

// OpencodeGoExecutor ports open-sse/executors/opencode-go.js:
// DefaultExecutor with a forced /zen/go/v1/responses lane for
// responses-target models and a translated session header.
// Live-unverified (no OpenCode Go subscription available here).
type OpencodeGoExecutor struct{ *DefaultExecutor }

func NewOpencodeGoExecutor() *OpencodeGoExecutor {
	e := &OpencodeGoExecutor{DefaultExecutor: NewDefaultExecutor("opencode-go")}
	defURL := e.Base.Hooks.BuildURL
	defTransform := e.Base.Hooks.TransformBody
	e.Base.Hooks.BuildURL = func(b *Base, req *Request, urlIndex int) (string, error) {
		if ocGoIsResponsesModel(req.Model) {
			return ocResponsesURL(req, ocGoResponsesFallback), nil
		}
		return defURL(b, req, urlIndex)
	}
	defHeaders := e.Base.Hooks.BuildHeaders
	e.Base.Hooks.BuildHeaders = func(b *Base, req *Request, url string) (map[string]string, error) {
		headers, err := defHeaders(b, req, url)
		if err != nil {
			return nil, err
		}
		headers[ocSessionHeader] = e.ocGoSession(req)
		return headers, nil
	}
	e.Base.Hooks.TransformBody = func(b *Base, req *Request) (map[string]any, error) {
		out, err := defTransform(b, req)
		if err != nil || out == nil {
			return out, err
		}
		model := req.Model
		if model == "" {
			model = getStr(out, "model")
		}
		if !ocGoIsResponsesModel(model) {
			return out, nil
		}
		ocResponsesLaneBody(out)
		ocNormalizeResponsesTools(out)
		ocSanitizeResponsesItems(out)
		return out, nil
	}
	return e
}

// ocGoIsResponsesModel ports getModelTargetFormat("opencode-go", model)
// == FORMATS.OPENAI_RESPONSES: the Muse Spark rule first, then the
// registry entry's targetFormat (the responses-only entries are the
// grok-4.5/4.6/4.7, gpt-5.6-luna, gpt-6-luna and muse-spark contributor
// ids — all matched by the family rule below), then the family fallback
// for unknown ids (^(grok|gpt|muse-spark) → responses). Audited against
// providers/registry/opencode-go.js: no registered non-responses model
// matches the family rule, so the composition is exact for the current
// registry. A responses RuntimeTransport also counts (chatcore resolved
// it from the same catalogue).
func ocGoIsResponsesModel(model string) bool {
	if model == "" {
		return false
	}
	if ocIsMuseSparkModel(model) {
		return true
	}
	return ocFamilyResponsesRe.MatchString(ocModelBaseSegment(model))
}

func (e *OpencodeGoExecutor) ocGoSession(req *Request) string {
	if req.State != nil {
		if s, ok := req.State["ocGoSession"].(string); ok && s != "" {
			return s
		}
	}
	var session string
	if native := ocNativeSession(req.Cred, false); native != "" {
		session = native
	} else {
		resolved := ocProviderSessionID(req.Cred)
		if resolved == "" {
			resolved = ocResolveSessionID(req.Cred, req.Body, "opencode-go")
		}
		session = ocGoTranslatedSession(resolved, ocClientTool(req.Cred))
	}
	if req.State != nil {
		req.State["ocGoSession"] = session
	}
	return session
}

// --- opencode-zen executor ---

// OpencodeZenExecutor ports open-sse/executors/opencode-zen.js:
// DefaultExecutor with a forced /zen/v1/responses lane for Muse Spark,
// UA/session header spoofing, the fingerprint quartet, and the free-tier
// identity switch. Live-unverified (no Zen key available here).
type OpencodeZenExecutor struct{ *DefaultExecutor }

func NewOpencodeZenExecutor() *OpencodeZenExecutor {
	e := &OpencodeZenExecutor{DefaultExecutor: NewDefaultExecutor("opencode-zen")}
	defURL := e.Base.Hooks.BuildURL
	e.Base.Hooks.BuildURL = func(b *Base, req *Request, urlIndex int) (string, error) {
		if ocIsMuseSparkModel(req.Model) {
			return ocResponsesURL(req, ocZenResponsesFallback), nil
		}
		return defURL(b, req, urlIndex)
	}
	defHeaders := e.Base.Hooks.BuildHeaders
	e.Base.Hooks.BuildHeaders = func(b *Base, req *Request, url string) (map[string]string, error) {
		headers, err := defHeaders(b, req, url)
		if err != nil {
			return nil, err
		}
		downstreamUA := ocRawHeader(req.Cred, "user-agent")
		ua := ocZenUA
		if ocZenHasValidVersion(downstreamUA) {
			ua = downstreamUA
		}
		headers["User-Agent"] = ua
		client := ocRawHeader(req.Cred, "x-opencode-client")
		if client == "" {
			client = "desktop"
		}
		headers["x-opencode-client"] = client
		project := ocRawHeader(req.Cred, "x-opencode-project")
		if project == "" {
			project = "global"
		}
		headers["x-opencode-project"] = project
		headers[ocSessionHeader] = e.ocZenSession(req)
		if ocIsFreeTierModel(req.Model) {
			// Free-tier models are gated behind the attested identity
			// even on the keyed lane.
			headers["Authorization"] = "Bearer public"
			headers["x-opencode-request"] = ocGenerateRequestID(time.Now().UnixMilli())
		}
		return headers, nil
	}
	defTransform := e.Base.Hooks.TransformBody
	e.Base.Hooks.TransformBody = func(b *Base, req *Request) (map[string]any, error) {
		out, err := defTransform(b, req)
		if err != nil || out == nil {
			return out, err
		}
		// Free-tier gate: upstream 403s stream:false.
		out["stream"] = true
		model := req.Model
		if model == "" {
			model = getStr(out, "model")
		}
		if !ocIsMuseSparkModel(model) {
			ocZenEnsureFingerprintTools(out, false)
			return out, nil
		}
		ocResponsesLaneBody(out)
		ocZenEnsureFingerprintTools(out, true)
		ocNormalizeResponsesTools(out)
		ocSanitizeResponsesItems(out)
		return out, nil
	}
	return e
}

// ocZenHasValidVersion ports opencode-zen.js hasValidOpencodeVersion
// (opencode >= 1.17 anywhere in the UA string).
func ocZenHasValidVersion(ua string) bool {
	m := ocZenUARe.FindStringSubmatch(ua)
	if m == nil {
		return false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 1 || (major == 1 && minor >= 17)
}

func (e *OpencodeZenExecutor) ocZenSession(req *Request) string {
	if req.State != nil {
		if s, ok := req.State["ocZenSession"].(string); ok && s != "" {
			return s
		}
	}
	var session string
	if native := ocNativeSession(req.Cred, true); native != "" {
		session = native
	} else {
		resolved := ocProviderSessionID(req.Cred)
		if resolved == "" {
			resolved = ocResolveSessionID(req.Cred, req.Body, "opencode-zen")
		}
		session = ocTranslateSessionID(resolved, ocClientTool(req.Cred))
	}
	if req.State != nil {
		req.State["ocZenSession"] = session
	}
	return session
}
