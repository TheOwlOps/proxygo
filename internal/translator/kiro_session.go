package translator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session handling for Kiro requests — port of the deterministic parts of
// utils/sessionManager.js (scope "kiro") and utils/kiroSessionReplay.js.
//
// The JS functions take (headers, credentials/connectionId); the Go ReqFn
// contract passes only the body, so identity is resolved from body fields
// alone: a client-provided session id wins; otherwise the Kiro scope is
// ephemeral (a fresh binary-style id per request, exactly like the JS
// scope:"kiro" fallback). Header-carried ids (x-session-id,
// x-claude-code-session-id) cannot be seen here and are the caller's
// concern — documented in the team report.

var (
	kiroSessionMu        sync.Mutex
	kiroContinuationByID = map[string]string{}
	kiroSessionStarts    = map[string]kiroSessionStart{}
)

const (
	kiroMaxContinuationSessions = 5000
	kiroMaxSessionStarts        = 5000
)

type kiroSessionStart struct {
	sessionStart Body
	modelID      string
	systemPrompt string
	lastUsed     time.Time
}

// newKiroUUID returns a random RFC 4122 v4 UUID (uuid package in JS).
func newKiroUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is effectively unreachable; fall back to a
		// time/hash mix so id generation never fails the request.
		sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(b[:], sum[:16])
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}

// generateBinaryStyleID ports generateBinaryStyleId: randomUUID + Date.now().
func generateBinaryStyleID() string {
	return newKiroUUID() + strconv.FormatInt(time.Now().UnixMilli(), 10)
}

// normalizeSessionID ports normalizeSessionId (trim, 256-char cap).
func normalizeSessionID(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 256 {
		return ""
	}
	return s
}

var claudeCodeSessionRe = regexp.MustCompile(`_session_([a-f0-9-]+)$`)

// extractClaudeCodeSession ports extractClaudeCodeSession: the
// metadata.user_id tail `_session_<uuid>`, or a JSON user_id's session_id.
func extractClaudeCodeSession(userID string) string {
	if userID == "" {
		return ""
	}
	if m := claudeCodeSessionRe.FindStringSubmatch(userID); m != nil {
		return m[1]
	}
	if strings.HasPrefix(userID, "{") {
		if parsed, ok := safeParseJSON(userID, nil).(map[string]any); ok {
			return normalizeSessionID(parsed["session_id"])
		}
	}
	return ""
}

// extractKiroClientSessionID ports extractClientSessionId for scope
// "kiro" using body fields only: Claude Code metadata → prompt_cache_key
// → session_id → conversation_id. (Antigravity + header sources are
// unreachable from a body-only translator.)
func extractKiroClientSessionID(body Body) string {
	if meta := obj(body, "metadata"); meta != nil {
		if claude := extractClaudeCodeSession(str(meta, "user_id")); claude != "" {
			return "claude:" + claude
		}
	}
	if v := normalizeSessionID(body["prompt_cache_key"]); v != "" {
		return v
	}
	if v := normalizeSessionID(body["session_id"]); v != "" {
		return v
	}
	if v := normalizeSessionID(body["conversation_id"]); v != "" {
		return v
	}
	return ""
}

// resolveKiroSessionIdentity ports resolveSessionIdentity for scope
// "kiro": a client session id is stable; otherwise the id is one-shot
// (ephemeral) — the JS never falls back to a per-connection id for Kiro.
func resolveKiroSessionIdentity(body Body) (sessionID string, ephemeral bool) {
	if client := extractKiroClientSessionID(body); client != "" {
		return client, false
	}
	return generateBinaryStyleID(), true
}

// resolveKiroContinuationID ports resolveContinuationId: stable per
// session id, random when ephemeral. (In the JS request translators the
// result warms this store; the wire payload itself carries no
// continuation id — kept for parity so the executor layer can adopt the
// same store semantics later.)
func resolveKiroContinuationID(sessionID string, ephemeral bool) string {
	if ephemeral {
		return newKiroUUID()
	}
	key := "kiro::" + sessionID
	kiroSessionMu.Lock()
	defer kiroSessionMu.Unlock()
	if existing, ok := kiroContinuationByID[key]; ok {
		return existing
	}
	if len(kiroContinuationByID) >= kiroMaxContinuationSessions {
		for k := range kiroContinuationByID {
			delete(kiroContinuationByID, k)
			break
		}
	}
	id := newKiroUUID()
	kiroContinuationByID[key] = id
	return id
}

// ---------- session replay (utils/kiroSessionReplay.js) ----------

func kiroEnsureUserModelID(msg Body, modelID string) {
	if ui := obj(msg, "userInputMessage"); ui != nil && str(ui, "modelId") == "" && modelID != "" {
		ui["modelId"] = modelID
	}
}

func kiroEnsureHistoryModelIDs(history []Body, modelID string) {
	for _, item := range history {
		kiroEnsureUserModelID(item, modelID)
	}
}

func kiroPrefixUserMessage(message Body, contentPrefix, modelID string) Body {
	out := deepCopyBody(message)
	if out == nil {
		out = Body{}
	}
	ui := obj(out, "userInputMessage")
	if ui == nil {
		ui = Body{"content": ""}
		out["userInputMessage"] = ui
	}
	kiroEnsureUserModelID(out, modelID)
	if contentPrefix != "" {
		content := str(ui, "content")
		if content != "" {
			ui["content"] = contentPrefix + "\n\n" + content
		} else {
			ui["content"] = contentPrefix
		}
	}
	return out
}

func kiroFindFirstUserIndex(history []Body) int {
	for i, item := range history {
		if obj(item, "userInputMessage") != nil {
			return i
		}
	}
	return -1
}

func kiroHasToolResults(msg Body) bool {
	ui := obj(msg, "userInputMessage")
	if ui == nil {
		return false
	}
	ctx := obj(ui, "userInputMessageContext")
	return ctx != nil && len(arr(ctx, "toolResults")) > 0
}

func kiroCanReplaceSessionStart(history []Body, firstUserIndex int) bool {
	return firstUserIndex == 0 && !kiroHasToolResults(history[firstUserIndex])
}

// applyKiroSessionReplay ports applyKiroSessionReplay: freeze the first
// user message (msg0) per conversation, replay it verbatim on later
// turns, and inject only the volatile current-time prefix into the
// current turn. The JS store is keyed connectionId:conversationId; with
// no credentials in scope the Go store keys on conversationId alone.
func applyKiroSessionReplay(conversationID, modelID, systemPrompt, contentPrefix, currentContentPrefix string, history []Body, currentMessage Body) (outHistory []Body, outCurrent Body) {
	key := ":" + conversationID
	baseHistory := make([]Body, 0, len(history))
	for _, h := range history {
		baseHistory = append(baseHistory, deepCopyBody(h))
	}
	baseCurrent := deepCopyBody(currentMessage)
	if baseCurrent == nil {
		baseCurrent = Body{"userInputMessage": Body{"content": ""}}
	}

	kiroSessionMu.Lock()
	existing, hasExisting := kiroSessionStarts[key]
	if conversationID == "" {
		hasExisting = false
	}
	kiroSessionMu.Unlock()

	if hasExisting && existing.modelID == modelID && existing.systemPrompt == systemPrompt {
		kiroSessionMu.Lock()
		existing.lastUsed = time.Now()
		kiroSessionStarts[key] = existing
		kiroSessionMu.Unlock()
		firstUserIndex := kiroFindFirstUserIndex(baseHistory)
		sessionStart := deepCopyBody(existing.sessionStart)
		kiroEnsureUserModelID(sessionStart, modelID)
		if kiroCanReplaceSessionStart(baseHistory, firstUserIndex) {
			baseHistory[firstUserIndex] = sessionStart
		} else {
			baseHistory = append([]Body{sessionStart}, baseHistory...)
			if len(baseHistory) == 1 {
				baseHistory = append(baseHistory, Body{"assistantResponseMessage": Body{"content": "..."}})
			}
		}
		kiroEnsureHistoryModelIDs(baseHistory, modelID)
		return baseHistory, kiroPrefixUserMessage(baseCurrent, currentContentPrefix, modelID)
	}

	firstUserIndex := kiroFindFirstUserIndex(baseHistory)
	var sessionStart Body
	var nextCurrent Body
	switch {
	case kiroCanReplaceSessionStart(baseHistory, firstUserIndex):
		sessionStart = kiroPrefixUserMessage(baseHistory[firstUserIndex], contentPrefix, modelID)
		baseHistory[firstUserIndex] = deepCopyBody(sessionStart)
		nextCurrent = kiroPrefixUserMessage(baseCurrent, currentContentPrefix, modelID)
	case firstUserIndex >= 0:
		sessionStart = kiroPrefixUserMessage(Body{"userInputMessage": Body{"content": "", "modelId": modelID}}, contentPrefix, modelID)
		baseHistory = append([]Body{deepCopyBody(sessionStart)}, baseHistory...)
		nextCurrent = kiroPrefixUserMessage(baseCurrent, currentContentPrefix, modelID)
	default:
		sessionStart = kiroPrefixUserMessage(baseCurrent, contentPrefix, modelID)
		nextCurrent = deepCopyBody(sessionStart)
	}

	if conversationID != "" {
		kiroSessionMu.Lock()
		if len(kiroSessionStarts) >= kiroMaxSessionStarts {
			for k := range kiroSessionStarts {
				delete(kiroSessionStarts, k)
				break
			}
		}
		kiroSessionStarts[key] = kiroSessionStart{
			sessionStart: deepCopyBody(sessionStart),
			modelID:      modelID,
			systemPrompt: systemPrompt,
			lastUsed:     time.Now(),
		}
		kiroSessionMu.Unlock()
	}

	kiroEnsureHistoryModelIDs(baseHistory, modelID)
	return baseHistory, nextCurrent
}

// clearKiroSessionStores resets the session stores (test parity with
// clearSessionStore / clearKiroSessionReplayStore).
func clearKiroSessionStores() {
	kiroSessionMu.Lock()
	defer kiroSessionMu.Unlock()
	kiroContinuationByID = map[string]string{}
	kiroSessionStarts = map[string]kiroSessionStart{}
}
