package mitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"9router-go/internal/db"
)

// Port of src/mitm/handlers/kiro.js (580 LOC) + the Kiro branch of
// src/mitm/server.js (extractModel + getMappedModel gating).
//
// Flow (identical to JS): a Kiro IDE CodeWhisperer chat request whose
// model resolves through the MITM alias map is converted to an OpenAI
// chat request, forwarded to the 9Router gateway itself
// (/v1/chat/completions, fetchRouter), and the OpenAI SSE reply is
// re-encoded as AWS EventStream binary frames for the IDE. Requests
// whose model is not in the alias map never reach this handler —
// handle() passes them through to the real Kiro endpoint unmapped.
//
// The conversions here are the handler-local ones from kiro.js; the
// open-sse translators (internal/translator) solve the inverse
// problem (OpenAI→CodeWhisperer for the Kiro provider) and are not
// used by the JS handler either.

// ─── debug trace (kiro.js dbg, dev only) ─────────────────────────────────────

func kiroDbg(format string, args ...any) {
	if os.Getenv("NODE_ENV") != "development" {
		return
	}
	dir := filepath.Join(db.DataDir(), "logs", "mitm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "kiro-debug.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// ─── model extraction + alias gating (server.js / config.js) ────────────────

// kiroExtractModel ports config.js extractModel for the Kiro body form:
// conversationState.currentMessage.userInputMessage.modelId. Binary
// bodies and unparseable JSON yield "" (JS returns the URL model,
// which is nil for Kiro endpoints).
func kiroExtractModel(body []byte) string {
	if isBinaryData(body) {
		return ""
	}
	var parsed struct {
		ConversationState *struct {
			CurrentMessage *struct {
				UserInputMessage *struct {
					ModelID string `json:"modelId"`
				} `json:"userInputMessage"`
			} `json:"currentMessage"`
		} `json:"conversationState"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	if parsed.ConversationState == nil || parsed.ConversationState.CurrentMessage == nil ||
		parsed.ConversationState.CurrentMessage.UserInputMessage == nil {
		return ""
	}
	return parsed.ConversationState.CurrentMessage.UserInputMessage.ModelID
}

// isBinaryData ports config.js isBinaryData (>30% non-printable bytes
// in the first 100 bytes).
func isBinaryData(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	sample := buf
	if len(sample) > 100 {
		sample = sample[:100]
	}
	nonPrintable := 0
	for _, b := range sample {
		if b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D {
			nonPrintable++
		}
		if b > 0x7E {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(sample)) > 0.3
}

// kiroMappedModel ports server.js getMappedModel("kiro", model): exact
// then prefix match over the DB alias map (via the shared hooks).
// MODEL_SYNONYMS and MODEL_PATTERNS have no kiro entries in config.js,
// so no synonym/pattern stage applies. Returns "" when the model is
// not mapped — the caller must passthrough (unlike GetMappedModel,
// whose fall-back-to-original semantics serve the antigravity/copilot
// handlers whose JS counterparts always rewrite).
func kiroMappedModel(body []byte) string {
	model := kiroExtractModel(body)
	if model == "" || hooks.aliasFor == nil {
		return ""
	}
	aliases, ok := hooks.aliasFor("kiro")
	if !ok || aliases == nil {
		return ""
	}
	lookup := strings.TrimPrefix(model, "models/")
	if v := aliases[lookup]; v != "" {
		return v
	}
	// Prefix match fallback (JS iterates Object.keys insertion order;
	// Go map order is unspecified — with several matching prefixes the
	// winner may differ from JS, same trade-off as models.go).
	for k, v := range aliases {
		if k != "" && v != "" && (strings.HasPrefix(lookup, k) || strings.HasPrefix(k, lookup)) {
			return v
		}
	}
	return ""
}

// ─── AWS EventStream frame builder (kiro.js) ────────────────────────────────
// CRC32 is the standard IEEE polynomial (0xEDB88320) — hash/crc32's
// ChecksumIEEE is byte-identical to the table implementation in JS.

// encodeEventStreamHeader encodes one string header:
// [nameLen 1B][name][type=7 1B][valueLen 2B][value].
func encodeEventStreamHeader(name, value string) []byte {
	buf := make([]byte, 0, 1+len(name)+1+2+len(value))
	buf = append(buf, byte(len(name)))
	buf = append(buf, name...)
	buf = append(buf, 7) // string type
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(value)))
	buf = append(buf, lb[:]...)
	buf = append(buf, value...)
	return buf
}

// buildEventStreamFrame builds one frame with the three Smithy system
// headers (:message-type event, :event-type, :content-type).
func buildEventStreamFrame(eventType string, payload any, contentType string) []byte {
	if contentType == "" {
		contentType = "application/json"
	}
	var payloadBuf []byte
	switch p := payload.(type) {
	case string:
		payloadBuf = []byte(p)
	case []byte:
		payloadBuf = p
	default:
		payloadBuf, _ = json.Marshal(p)
	}
	headersBuf := bytes.Join([][]byte{
		encodeEventStreamHeader(":message-type", "event"),
		encodeEventStreamHeader(":event-type", eventType),
		encodeEventStreamHeader(":content-type", contentType),
	}, nil)
	totalLen := 4 + 4 + 4 + len(headersBuf) + len(payloadBuf) + 4
	frame := make([]byte, totalLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(headersBuf)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[0:8]))
	copy(frame[12:], headersBuf)
	copy(frame[12+len(headersBuf):], payloadBuf)
	binary.BigEndian.PutUint32(frame[totalLen-4:], crc32.ChecksumIEEE(frame[:totalLen-4]))
	return frame
}

// buildInitialResponseFrame: the real Kiro Runtime always starts the
// stream with this frame (capture of IDE 1.0.228).
func buildInitialResponseFrame(conversationID string) []byte {
	return buildEventStreamFrame("initial-response",
		struct {
			ConversationID string `json:"conversationId"`
		}{ConversationID: conversationID},
		"application/x-amz-json-1.0")
}

// ─── response translator state (kiro.js initKiroState) ──────────────────────

type kiroToolInit struct {
	id   string
	name string
}

type kiroState struct {
	modelID     string
	toolCallIni map[int]kiroToolInit
	hasToolCall bool
	finishSent  bool
	usage       map[string]any
	inThink     bool
	thinkBuf    string
	initialSent bool
}

func initKiroState(modelID string) *kiroState {
	return &kiroState{modelID: modelID, toolCallIni: map[int]kiroToolInit{}}
}

// withInitialFrame prepends the initial-response frame once per
// stream (kiro.js withInitialFrame).
func (st *kiroState) withInitialFrame(frames [][]byte) [][]byte {
	if st.initialSent {
		if len(frames) == 0 {
			return nil
		}
		return frames
	}
	st.initialSent = true
	out := make([][]byte, 0, len(frames)+1)
	out = append(out, buildInitialResponseFrame(""))
	out = append(out, frames...)
	return out
}

// extractThinking ports kiro.js extractThinking — including its
// quirks: the close tag is searched case-sensitively (JS indexOf with
// the lowercased tag), before/after are trimmed and joined with "",
// and a second block's thinking content is dropped by the recursion.
var thinkStartRe = regexp.MustCompile(`(?i)<thinking>|<think>`)

func extractThinking(text string, state *kiroState) (thinking, rest *string) {
	if text == "" {
		return nil, nil
	}
	working := text
	if state.inThink && state.thinkBuf != "" {
		working = state.thinkBuf + working
		state.thinkBuf = ""
		state.inThink = false
	}
	loc := thinkStartRe.FindStringIndex(working)
	if loc == nil {
		return nil, &working
	}
	tag := strings.ToLower(working[loc[0]:loc[1]])
	closeTag := "</thinking>"
	if tag == "<think>" {
		closeTag = "</think>"
	}
	startIdx := loc[0]
	rel := strings.Index(working[startIdx+len(tag):], closeTag)
	if rel == -1 {
		state.inThink = true
		state.thinkBuf = working[startIdx:]
		before := strings.TrimSpace(working[:startIdx])
		if before == "" {
			return nil, nil
		}
		return nil, &before
	}
	endIdx := startIdx + len(tag) + rel
	thinkContent := working[startIdx+len(tag) : endIdx]
	before := strings.TrimSpace(working[:startIdx])
	after := strings.TrimSpace(working[endIdx+len(closeTag):])
	restJoined := ""
	if before != "" || after != "" {
		restJoined = before + after
	}
	var recText *string
	if restJoined != "" {
		fresh := &kiroState{}
		_, recText = extractThinking(restJoined, fresh)
	}
	var thinkPtr *string
	if thinkContent != "" {
		thinkPtr = &thinkContent
	}
	if recText == nil || *recText == "" {
		return thinkPtr, nil
	}
	return thinkPtr, recText
}

// ─── CodeWhisperer → OpenAI conversion (kiro.js) ────────────────────────────

var inlineImageMIMEByFormat = map[string]string{
	"png": "image/png", "jpeg": "image/jpeg", "jpg": "image/jpeg",
	"gif": "image/gif", "webp": "image/webp",
}

type cwToolResult struct {
	ToolUseID string `json:"toolUseId"`
	Content   []struct {
		Text string `json:"text"`
	} `json:"content"`
}

type cwImage struct {
	Format string `json:"format"`
	Source *struct {
		Bytes string `json:"bytes"`
	} `json:"source"`
}

type cwToolUse struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

type cwUserInputMessage struct {
	Content string    `json:"content"`
	ModelID string    `json:"modelId"`
	Images  []cwImage `json:"images"`
	Context *struct {
		ToolResults []cwToolResult    `json:"toolResults"`
		Tools       []json.RawMessage `json:"tools"`
	} `json:"userInputMessageContext"`
}

type cwAssistantMessage struct {
	Content  string      `json:"content"`
	ToolUses []cwToolUse `json:"toolUses"`
}

type cwHistoryItem struct {
	UserInputMessage         *cwUserInputMessage `json:"userInputMessage"`
	AssistantResponseMessage *cwAssistantMessage `json:"assistantResponseMessage"`
}

type cwBody struct {
	ConversationState struct {
		History        []cwHistoryItem `json:"history"`
		CurrentMessage *struct {
			UserInputMessage *cwUserInputMessage `json:"userInputMessage"`
		} `json:"currentMessage"`
	} `json:"conversationState"`
}

// safeArgsString ports kiro.js safeArgsString: OpenAI expects
// function.arguments as a JSON string, never an object. The raw source
// text is compacted (JSON.stringify equivalent) to preserve key order.
func safeArgsString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return "{}"
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "{}"
	}
	return buf.String()
}

func convertUserInputMessage(uim *cwUserInputMessage) []map[string]any {
	out := []map[string]any{}
	var toolResults []cwToolResult
	if uim.Context != nil {
		toolResults = uim.Context.ToolResults
	}
	for _, tr := range toolResults {
		parts := make([]string, 0, len(tr.Content))
		for _, c := range tr.Content {
			parts = append(parts, c.Text)
		}
		out = append(out, map[string]any{
			"role":         "tool",
			"tool_call_id": tr.ToolUseID,
			"content":      strings.Join(parts, "\n"),
		})
	}
	var imageParts []any
	for _, image := range uim.Images {
		mime, ok := inlineImageMIMEByFormat[image.Format]
		if !ok || image.Source == nil || image.Source.Bytes == "" {
			continue
		}
		imageParts = append(imageParts, map[string]any{
			"type":      "image_url",
			"image_url": map[string]any{"url": "data:" + mime + ";base64," + image.Source.Bytes},
		})
	}
	text := strings.TrimSpace(uim.Content)
	if len(imageParts) > 0 {
		content := []any{}
		if text != "" {
			content = append(content, map[string]any{"type": "text", "text": text})
		}
		content = append(content, imageParts...)
		out = append(out, map[string]any{"role": "user", "content": content})
	} else if text != "" || len(toolResults) == 0 {
		out = append(out, map[string]any{"role": "user", "content": text})
	}
	return out
}

func convertAssistantResponseMessage(arm *cwAssistantMessage) map[string]any {
	if len(arm.ToolUses) > 0 {
		calls := make([]any, 0, len(arm.ToolUses))
		for _, tu := range arm.ToolUses {
			id := tu.ToolUseID
			if id == "" {
				id = fmt.Sprintf("call_%d", time.Now().UnixMilli())
			}
			calls = append(calls, map[string]any{
				"id":   id,
				"type": "function",
				"function": map[string]any{
					"name":      tu.Name,
					"arguments": safeArgsString(tu.Input),
				},
			})
		}
		var content any
		if arm.Content != "" {
			content = arm.Content
		}
		return map[string]any{"role": "assistant", "content": content, "tool_calls": calls}
	}
	return map[string]any{"role": "assistant", "content": arm.Content}
}

func codeWhispererToMessages(body *cwBody) []map[string]any {
	messages := []map[string]any{}
	for i := range body.ConversationState.History {
		item := &body.ConversationState.History[i]
		if item.UserInputMessage != nil {
			messages = append(messages, convertUserInputMessage(item.UserInputMessage)...)
		} else if item.AssistantResponseMessage != nil {
			messages = append(messages, convertAssistantResponseMessage(item.AssistantResponseMessage))
		}
	}
	if cm := body.ConversationState.CurrentMessage; cm != nil && cm.UserInputMessage != nil {
		messages = append(messages, convertUserInputMessage(cm.UserInputMessage)...)
	}
	return messages
}

func extractTools(body *cwBody) []map[string]any {
	var cwTools []json.RawMessage
	if cm := body.ConversationState.CurrentMessage; cm != nil && cm.UserInputMessage != nil &&
		cm.UserInputMessage.Context != nil {
		cwTools = cm.UserInputMessage.Context.Tools
	}
	if len(cwTools) == 0 {
		for i := range body.ConversationState.History {
			uim := body.ConversationState.History[i].UserInputMessage
			if uim != nil && uim.Context != nil && len(uim.Context.Tools) > 0 {
				cwTools = uim.Context.Tools
				break
			}
		}
	}
	if len(cwTools) == 0 {
		return nil
	}
	out := []map[string]any{}
	for _, item := range cwTools {
		var wrap struct {
			ToolSpecification json.RawMessage `json:"toolSpecification"`
		}
		_ = json.Unmarshal(item, &wrap)
		specRaw := item
		if len(wrap.ToolSpecification) > 0 {
			specRaw = wrap.ToolSpecification
		}
		var spec struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			InputSchema *struct {
				JSON json.RawMessage `json:"json"`
			} `json:"inputSchema"`
		}
		_ = json.Unmarshal(specRaw, &spec)
		desc := spec.Description
		if desc == "" {
			name := spec.Name
			if name == "" {
				name = "unknown"
			}
			desc = "Tool: " + name
		}
		var params any = map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}}
		if spec.InputSchema != nil && len(spec.InputSchema.JSON) > 0 &&
			string(spec.InputSchema.JSON) != "null" {
			params = spec.InputSchema.JSON
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        spec.Name,
				"description": desc,
				"parameters":  params,
			},
		})
	}
	return out
}

// ─── OpenAI SSE chunk → EventStream frames (kiro.js convertOpenAIToKiro) ────

type kiroContentEvent struct {
	Content string `json:"content"`
	ModelID string `json:"modelId"`
}

type kiroToolEvent struct {
	Name      string `json:"name"`
	ToolUseID string `json:"toolUseId"`
}

type kiroToolFragmentEvent struct {
	Input     string `json:"input"`
	Name      string `json:"name"`
	ToolUseID string `json:"toolUseId"`
}

type kiroToolStopEvent struct {
	Name      string `json:"name"`
	Stop      bool   `json:"stop"`
	ToolUseID string `json:"toolUseId"`
}

type kiroUsageEvent struct {
	InputTokens  int64 `json:"inputTokens"`
	OutputTokens int64 `json:"outputTokens"`
}

func numField(m map[string]any, key string) int64 {
	if v, ok := m[key].(float64); ok {
		return int64(v)
	}
	return 0
}

func strField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// convertOpenAIToKiro converts one parsed OpenAI chunk (nil = flush)
// to EventStream frames — kiro.js convertOpenAIToKiro.
func convertOpenAIToKiro(chunk map[string]any, state *kiroState) [][]byte {
	if chunk == nil {
		if state.finishSent {
			return nil
		}
		if state.inThink && state.thinkBuf != "" {
			state.inThink = false
			thinking := state.thinkBuf
			state.thinkBuf = ""
			modelID := state.modelID
			if modelID == "" {
				modelID = "kiro-unknown"
			}
			return state.withInitialFrame([][]byte{
				buildEventStreamFrame("reasoningContentEvent",
					kiroContentEvent{Content: thinking, ModelID: modelID}, ""),
			})
		}
		return state.withInitialFrame([][]byte{
			buildEventStreamFrame("messageStopEvent", struct{}{}, ""),
		})
	}

	frames := [][]byte{}
	var choice map[string]any
	var delta map[string]any
	if choices, ok := chunk["choices"].([]any); ok && len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	if choice != nil {
		delta, _ = choice["delta"].(map[string]any)
	}
	if delta == nil {
		delta = map[string]any{}
	}

	if state.modelID == "" {
		if m := strField(chunk, "model"); m != "" {
			state.modelID = m
		}
	}
	modelID := state.modelID
	if modelID == "" {
		modelID = "unknown"
	}

	if usage, ok := chunk["usage"].(map[string]any); ok && usage != nil {
		state.usage = usage
	}

	if toolCalls, ok := delta["tool_calls"].([]any); ok {
		state.hasToolCall = true
		for _, raw := range toolCalls {
			tc, _ := raw.(map[string]any)
			if tc == nil {
				continue
			}
			idx := int(numField(tc, "index"))
			fn, _ := tc["function"].(map[string]any)
			tcID := strField(tc, "id")
			fnName := ""
			fnArgs := ""
			if fn != nil {
				fnName = strField(fn, "name")
				fnArgs = strField(fn, "arguments")
			}
			_, seen := state.toolCallIni[idx]
			if tcID != "" && fnName != "" && !seen {
				state.toolCallIni[idx] = kiroToolInit{id: tcID, name: fnName}
				kiroDbg("toolUseEvent init: %s (%s)", fnName, tcID)
				frames = append(frames, buildEventStreamFrame("toolUseEvent",
					kiroToolEvent{Name: fnName, ToolUseID: tcID}, ""))
			}
			if fnArgs != "" {
				init := state.toolCallIni[idx]
				name := init.name
				if name == "" {
					name = fnName
				}
				id := init.id
				if id == "" {
					id = tcID
				}
				preview := fnArgs
				if len(preview) > 100 {
					preview = preview[:100]
				}
				kiroDbg("toolUseEvent fragment: %s", preview)
				frames = append(frames, buildEventStreamFrame("toolUseEvent",
					kiroToolFragmentEvent{Input: fnArgs, Name: name, ToolUseID: id}, ""))
			}
		}
	}

	if rc := strField(delta, "reasoning_content"); rc != "" {
		frames = append(frames, buildEventStreamFrame("reasoningContentEvent",
			kiroContentEvent{Content: rc, ModelID: modelID}, ""))
	}

	if content := strField(delta, "content"); content != "" {
		thinking, text := extractThinking(content, state)
		if thinking != nil && *thinking != "" {
			frames = append(frames, buildEventStreamFrame("reasoningContentEvent",
				kiroContentEvent{Content: *thinking, ModelID: modelID}, ""))
		}
		if text != nil && *text != "" {
			frames = append(frames, buildEventStreamFrame("assistantResponseEvent",
				kiroContentEvent{Content: *text, ModelID: modelID}, ""))
		}
	}

	if choice != nil && strField(choice, "finish_reason") != "" {
		frames = append(frames, emitKiroFinish(state)...)
	}

	if len(frames) == 0 {
		if !state.initialSent {
			return state.withInitialFrame(nil)
		}
		return nil
	}
	return state.withInitialFrame(frames)
}

// emitKiroFinish ports kiro.js emitFinish: stop:true per tool for
// tool-call responses, messageStopEvent otherwise, then usageEvent.
func emitKiroFinish(state *kiroState) [][]byte {
	frames := [][]byte{}
	if state.hasToolCall {
		// JS: Object.keys (integer keys ascending numerically) then
		// .sort() (lexicographic on the string forms).
		idxs := make([]int, 0, len(state.toolCallIni))
		for idx := range state.toolCallIni {
			idxs = append(idxs, idx)
		}
		sort.Ints(idxs)
		keys := make([]string, 0, len(idxs))
		for _, idx := range idxs {
			keys = append(keys, fmt.Sprint(idx))
		}
		sort.Strings(keys)
		for _, k := range keys {
			var idx int
			fmt.Sscanf(k, "%d", &idx)
			tc := state.toolCallIni[idx]
			frames = append(frames, buildEventStreamFrame("toolUseEvent",
				kiroToolStopEvent{Name: tc.name, Stop: true, ToolUseID: tc.id}, ""))
		}
	} else {
		frames = append(frames, buildEventStreamFrame("messageStopEvent", struct{}{}, ""))
	}
	state.finishSent = true
	if state.usage != nil {
		frames = append(frames, buildEventStreamFrame("usageEvent", kiroUsageEvent{
			InputTokens:  numField(state.usage, "prompt_tokens"),
			OutputTokens: numField(state.usage, "completion_tokens"),
		}, ""))
	}
	state.toolCallIni = map[int]kiroToolInit{}
	return frames
}

// ─── intercept entry point (kiro.js intercept + base.js pipe) ───────────────

// isBinaryEventStream ports kiro.js isBinaryEventStream (prelude
// sanity checks on the first frame header).
func isBinaryEventStream(buf []byte) bool {
	if len(buf) < 12 {
		return false
	}
	totalLen := binary.BigEndian.Uint32(buf[0:4])
	headersLen := binary.BigEndian.Uint32(buf[4:8])
	return totalLen > 12 && totalLen < 1000000 && int64(headersLen) < int64(totalLen)-12
}

// writeKiroError writes the JS handler error shape
// ({error:{message,type:"mitm_error",handler:"kiro"}}).
func writeKiroError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": err.Error(),
			"type":    "mitm_error",
			"handler": "kiro",
		},
	})
}

// interceptKiro is handlers/kiro.js intercept(): convert the
// CodeWhisperer body to OpenAI, forward to the router, and re-encode
// the SSE reply as EventStream frames.
func (s *mitmServer) interceptKiro(w http.ResponseWriter, r *http.Request, body []byte, mappedModel string) {
	if isBinaryEventStream(body) {
		writeKiroError(w, fmt.Errorf(
			"Binary EventStream format detected (%dB) - request should use passthrough instead of intercept", len(body)))
		return
	}
	var parsed cwBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		writeKiroError(w, err)
		return
	}
	messages := codeWhispererToMessages(&parsed)
	if len(messages) == 0 {
		writeKiroError(w, errors.New("codeWhispererToMessages produced 0 messages — check request body"))
		return
	}
	tools := extractTools(&parsed)
	openaiBody := map[string]any{
		"model":    mappedModel,
		"messages": messages,
		"stream":   true,
	}
	if len(tools) > 0 {
		openaiBody["tools"] = tools
		openaiBody["tool_choice"] = "auto"
	}
	out, _ := json.Marshal(openaiBody)
	resp, err := s.fetchRouter(out, "/v1/chat/completions", r.Header)
	if err != nil {
		writeKiroError(w, err)
		return
	}
	defer resp.Body.Close()
	state := initKiroState(mappedModel)
	pipeTransformedEventStream(resp, w, state)
}

// pipeTransformedEventStream ports base.js pipeTransformedEventStream
// with convertOpenAIToKiro as the transform: read router SSE lines,
// convert each parsed chunk, write binary frames, flush at EOF.
func pipeTransformedEventStream(resp *http.Response, w http.ResponseWriter, state *kiroState) {
	w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	writeFrames := func(frames [][]byte) {
		for _, f := range frames {
			_, _ = w.Write(f)
		}
		if len(frames) > 0 && fl != nil {
			fl.Flush()
		}
	}

	// JS splits each decoded chunk on "\n" and keeps the remainder
	// buffered; a trailing line without "\n" at EOF is never parsed.
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		feedKiroSSELine(line, state, writeFrames)
	}
	writeFrames(convertOpenAIToKiro(nil, state))
}

func feedKiroSSELine(line string, state *kiroState, writeFrames func([][]byte)) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || !strings.HasPrefix(trimmed, "data:") {
		return
	}
	data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
	if data == "[DONE]" {
		return
	}
	var chunk map[string]any
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return // JS: skip unparseable lines
	}
	writeFrames(convertOpenAIToKiro(chunk, state))
}
