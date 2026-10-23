package executors

// Port of the AgentService half of open-sse/executors/cursor.js:
// agent.v1.AgentService/Run over a duplex HTTP/2 Connect stream.
//
// The IDE-context handshake IS implemented here: request_context acks,
// Kv get/set acks, MCP tool-call surfacing, and rejection of IDE builtin
// exec requests. What cannot be verified without a real Cursor account
// is only that Cursor's production servers accept this client — the
// wire behaviour is fixture-tested against a local HTTP/2 server.
//
// Proxy note: the JS guards this h2 path with proxyIntentFailed()
// because Node's http2 bypasses its proxy-aware fetch. The Go
// Credential contract carries no proxy options, so there is no proxy
// configuration to honour or refuse here; if proxy fields are ever
// added to Credential, the fail-closed guard must be re-applied on
// this path (see cursor.js #4333).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const agentRunPath = "/agent.v1.AgentService/Run"

// Connect frame flags (COMPRESS_FLAG in cursor.js).
const (
	connectFlagNone        = 0x00
	connectFlagGzip        = 0x01
	connectFlagTrailer     = 0x02
	connectFlagGzipTrailer = 0x03
)

// Empty-turn recovery knobs, env-tunable exactly like the JS.
var (
	cursorEmptyTurnMaxRetries = envIntDefault("CURSOR_EMPTY_TURN_MAX_RETRIES", 1, true)
	cursorTailOnlyThreshold   = envIntDefault("CURSOR_TAIL_ONLY_THRESHOLD", 80, false)
	cursorEmptyTurnRetryDelay = time.Duration(envIntDefault("CURSOR_EMPTY_TURN_RETRY_DELAY_MS", 400, true)) * time.Millisecond
)

func envIntDefault(name string, def int, allowZero bool) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if allowZero {
		if n >= 0 {
			return n
		}
		return def
	}
	if n > 0 {
		return n
	}
	return def
}

// ---------- message views over the raw request body ----------

// cursorAgentMessage is the executor's view of one body message
// (role + content in string or part-array form + tool call metadata).
type cursorAgentMessage struct {
	Role       string
	Content    any // string | []any | nil
	ToolCalls  []map[string]any
	ToolCallID string // role:"tool" messages
}

func cursorAgentMessagesFromBody(body map[string]any) []cursorAgentMessage {
	raw, _ := body["messages"].([]any)
	out := make([]cursorAgentMessage, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		msg := cursorAgentMessage{Role: getStr(m, "role"), Content: m["content"]}
		if tcs, ok := m["tool_calls"].([]any); ok {
			for _, tcItem := range tcs {
				if tc, ok := tcItem.(map[string]any); ok {
					msg.ToolCalls = append(msg.ToolCalls, tc)
				}
			}
		}
		msg.ToolCallID = getStr(m, "tool_call_id")
		out = append(out, msg)
	}
	return out
}

// textFromContent ports the executor's textFromContent(): string
// content as-is; part arrays keep text parts joined with "\n".
func cursorTextFromContent(content any) string {
	if s, ok := content.(string); ok {
		return s
	}
	parts, ok := content.([]any)
	if !ok {
		return ""
	}
	var texts []string
	for _, part := range parts {
		pm, ok := part.(map[string]any)
		if !ok {
			continue
		}
		if getStr(pm, "type") == "text" {
			if t, ok := pm["text"].(string); ok {
				texts = append(texts, t)
			}
		}
	}
	return strings.Join(texts, "\n")
}

func cursorIsTextPart(part any) bool {
	if part == nil {
		return true
	}
	if _, ok := part.(string); ok {
		return true
	}
	pm, ok := part.(map[string]any)
	if !ok {
		return false
	}
	return getStr(pm, "type") == "text"
}

// IsAgentCapableRequest ports isAgentCapableRequest(): every message
// must be text-only for AgentService; image parts need the legacy
// ChatService protobuf path.
func IsAgentCapableRequest(body map[string]any) bool {
	raw, ok := body["messages"].([]any)
	if !ok || len(raw) == 0 {
		return false
	}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		switch content := m["content"].(type) {
		case nil, string:
			// ok
		case []any:
			for _, part := range content {
				if !cursorIsTextPart(part) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// ---------- AgentRun frame building ----------

func encodeHistoryMessage(msg cursorAgentMessage) []byte {
	content := cursorTextFromContent(msg.Content)
	var extras []string
	if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
		for _, tc := range msg.ToolCalls {
			name := "tool"
			args := "{}"
			if fn, ok := tc["function"].(map[string]any); ok {
				if n := getStr(fn, "name"); n != "" {
					name = n
				}
				if a := getStr(fn, "arguments"); a != "" {
					args = a
				}
			}
			extras = append(extras, "[tool_call id="+getStr(tc, "id")+" name="+name+" args="+args+"]")
		}
	}
	if msg.Role == "tool" {
		extras = append(extras, "[tool_result id="+msg.ToolCallID+"]")
	}
	joined := append([]string{}, extras...)
	var bodyParts []string
	if content != "" {
		bodyParts = append(bodyParts, content)
	}
	bodyParts = append(bodyParts, joined...)
	textBody := strings.Join(bodyParts, "\n")
	if textBody == "" {
		return nil
	}
	text := pbStr(1, textBody)
	if msg.Role == "assistant" {
		return pbLen(2, pbLen(1, pbLen(1, text)))
	}
	return pbLen(1, pbLen(1, pbLen(1, text)))
}

// BuildAgentRunFrame ports buildAgentRunFrame().
func BuildAgentRunFrame(messages []cursorAgentMessage, model string, tools []CursorToolDef, reasoningEffort string) []byte {
	// custom_system_prompt (RunRequest field 8) makes AgentService
	// return an empty turn; system text folds into the user message.
	var systemParts []string
	var chatMessages []cursorAgentMessage
	for _, m := range messages {
		if m.Role == "system" {
			if t := cursorTextFromContent(m.Content); t != "" {
				systemParts = append(systemParts, t)
			}
			continue
		}
		chatMessages = append(chatMessages, m)
	}
	system := strings.Join(systemParts, "\n\n")

	currentIndex := -1
	for i, m := range chatMessages {
		if m.Role == "user" {
			currentIndex = i
		}
	}
	var current *cursorAgentMessage
	historyEnd := -1
	if currentIndex >= 0 {
		current = &chatMessages[currentIndex]
		historyEnd = currentIndex
	} else if len(chatMessages) > 0 {
		current = &chatMessages[len(chatMessages)-1]
		historyEnd = len(chatMessages) - 1
	}
	var history [][]byte
	if historyEnd > 0 {
		for _, m := range chatMessages[:historyEnd] {
			if enc := encodeHistoryMessage(m); enc != nil {
				history = append(history, enc)
			}
		}
	}
	rawUser := ""
	if current != nil {
		rawUser = cursorTextFromContent(current.Content)
	}
	if rawUser == "" {
		rawUser = "Continue."
	}
	userText := rawUser
	if system != "" {
		userText = system + "\n\n" + rawUser
	}

	userMessage := pbConcat(
		pbStr(1, userText),
		pbStr(2, cursorNewUUID()),
		pbLen(3, []byte{}),
		pbVar(4, 1),
	)
	var userActionParts [][]byte
	userActionParts = append(userActionParts, pbLen(1, userMessage))
	if len(history) > 0 {
		var histParts [][]byte
		for _, entry := range history {
			histParts = append(histParts, pbLen(1, entry))
		}
		userActionParts = append(userActionParts, pbLen(7, pbConcat(histParts...)))
	}
	userAction := pbConcat(userActionParts...)
	conversationAction := pbLen(1, userAction)

	effort := strings.ToLower(reasoningEffort)
	effortValue := effort
	if effort == "ultra" {
		effortValue = "max"
	} else if effort == "minimal" {
		effortValue = "low"
	}
	var parameter []byte
	if effortValue != "" && effortValue != "none" {
		paramName := "effort"
		if gptModelRe.MatchString(model) {
			paramName = "reasoning"
		}
		parameter = pbLen(3, pbConcat(pbStr(1, paramName), pbStr(2, effortValue)))
	}
	requestedModelParts := [][]byte{pbStr(1, model), pbVar(7, 1)}
	if parameter != nil {
		requestedModelParts = append(requestedModelParts, parameter)
	}
	requestedModel := pbConcat(requestedModelParts...)
	modelDetails := pbConcat(pbStr(1, model), pbStr(3, model), pbStr(4, model))
	mcpTools := EncodeMcpTools(tools)
	runParts := [][]byte{
		pbLen(1, []byte{}),
		pbLen(2, conversationAction),
		pbLen(3, modelDetails),
	}
	if len(mcpTools) > 0 {
		runParts = append(runParts, pbLen(4, mcpTools))
	}
	runParts = append(runParts, pbLen(9, requestedModel))
	runRequest := pbConcat(runParts...)
	return WrapConnectRPCFrame(pbLen(1, runRequest), false)
}

var gptModelRe = regexp.MustCompile(`(?i)gpt-`)

// tailOnlyCursorMessages ports tailOnlyCursorMessages(): minimal tail
// for wedged long sessions.
func tailOnlyCursorMessages(messages []cursorAgentMessage) []cursorAgentMessage {
	if len(messages) == 0 {
		return messages
	}
	var systemMessages []cursorAgentMessage
	var chatMessages []cursorAgentMessage
	for _, m := range messages {
		if m.Role == "system" {
			if !strings.Contains(cursorTextFromContent(m.Content), "[ProxyGo]") {
				systemMessages = append(systemMessages, m)
			}
			continue
		}
		chatMessages = append(chatMessages, m)
	}
	anchor := len(chatMessages) - 1
	for i := len(chatMessages) - 1; i >= 0; i-- {
		if chatMessages[i].Role == "user" || chatMessages[i].Role == "tool" {
			anchor = i
			break
		}
	}
	tailStart := anchor
	if anchor > 0 && chatMessages[anchor-1].Role == "assistant" {
		tailStart = anchor - 1
	}
	if tailStart < 0 {
		tailStart = 0
	}
	tail := chatMessages[tailStart:]
	note := cursorAgentMessage{
		Role:    "system",
		Content: fmt.Sprintf("[ProxyGo] Long session: %d messages trimmed to the latest turn. Answer the current request; re-read files if needed.", len(messages)),
	}
	out := append([]cursorAgentMessage{}, systemMessages...)
	out = append(out, note)
	out = append(out, tail...)
	return out
}

func shouldRetryEmptyTurn(messageCount int) bool {
	return messageCount >= cursorTailOnlyThreshold
}

// ---------- exec / kv handshake ----------

func execIDs(execRequest *pbMessage) (uint64, string) {
	id := execRequest.firstVarint(1)
	execID := execRequest.firstString(15)
	return id, execID
}

func wrapExecClientMessage(execMsgID uint64, execID string, resultField int, resultPayload []byte) []byte {
	var parts [][]byte
	if execMsgID != 0 {
		parts = append(parts, pbVar(1, execMsgID))
	}
	parts = append(parts, pbStr(15, execID))
	parts = append(parts, pbLen(resultField, resultPayload))
	// AgentClientMessage.exec_client_message = field 2.
	return WrapConnectRPCFrame(pbLen(2, pbConcat(parts...)), false)
}

func createRequestContextResponse(execRequest *pbMessage) []byte {
	id, execID := execIDs(execRequest)
	requestContextSuccess := pbLen(1, []byte{})
	requestContextResult := pbLen(1, requestContextSuccess)
	return wrapExecClientMessage(id, execID, 10, requestContextResult)
}

// execResultField maps ExecServerMessage variant → ExecClientMessage
// result field (same numbers), from cursor.js EXEC_RESULT_FIELD.
var execResultField = map[int]int{
	2: 2, 3: 3, 4: 4, 5: 5, 7: 7, 8: 8, 9: 9, 16: 16, 20: 20, 23: 23,
}

// rejectExecRequest builds the rejection ack for an IDE exec request,
// or nil bytes when the variant has no mapped result field.
func rejectExecRequest(execRequest *pbMessage) []byte {
	id, execID := execIDs(execRequest)
	variant := 0
	for _, field := range execRequest.keys() {
		if field != 1 && field != 15 {
			variant = field
			break
		}
	}
	resultField, ok := execResultField[variant]
	if variant == 0 || !ok {
		return nil
	}
	// Diagnostics has no rejected variant — empty success unblocks.
	if variant == 9 {
		return wrapExecClientMessage(id, execID, 9, []byte{})
	}
	rejected := pbLen(2, pbStr(2, "Tool not available in this environment. Use the MCP tools provided instead."))
	return wrapExecClientMessage(id, execID, resultField, rejected)
}

// EncodeKvClientMessage ports encodeKvClientMessage():
// AgentClientMessage.kv_client_message = field 3.
func EncodeKvClientMessage(kvID uint64, resultField int, resultPayload, metadata []byte) []byte {
	var parts [][]byte
	if kvID != 0 {
		parts = append(parts, pbVar(1, kvID))
	}
	parts = append(parts, pbLen(resultField, resultPayload))
	if len(metadata) > 0 {
		parts = append(parts, pbLen(4, metadata))
	}
	return WrapConnectRPCFrame(pbLen(3, pbConcat(parts...)), false)
}

// ---------- agent frame stream decoding ----------

// agentFrameDecoder incrementally splits a byte stream into Connect
// frame payloads (decodeAgentFrames): gzip frames are decompressed,
// trailer frames skipped.
type agentFrameDecoder struct {
	pending []byte
}

func (d *agentFrameDecoder) feed(chunk []byte, onFrame func(payload []byte) error) error {
	d.pending = append(d.pending, chunk...)
	for len(d.pending) >= 5 {
		flags := d.pending[0]
		length := int(d.pending[1])<<24 | int(d.pending[2])<<16 | int(d.pending[3])<<8 | int(d.pending[4])
		if len(d.pending) < 5+length {
			break
		}
		payload := d.pending[5 : 5+length]
		d.pending = d.pending[5+length:]
		if flags&connectFlagGzip != 0 {
			dec, err := gunzipBytes(payload)
			if err != nil {
				return err
			}
			payload = dec
		}
		if flags&connectFlagTrailer != 0 {
			continue
		}
		if err := onFrame(payload); err != nil {
			return err
		}
	}
	return nil
}

// ---------- duplex HTTP/2 session ----------

// cursorAgentSession is one AgentService Run stream: request body is an
// io.Pipe fed with Connect frames while the response body is read —
// the Go equivalent of Node http2's duplex request stream. Built on
// golang.org/x/net/http2's Transport, which speaks HTTP/2 over TLS.
type cursorAgentSession struct {
	resp   *http.Response
	pw     *io.PipeWriter
	cancel context.CancelFunc
	body   io.ReadCloser

	respCh chan agentDialResult
	once   sync.Once
}

type agentDialResult struct {
	resp *http.Response
	err  error
}

// openCursorAgentSession starts the Run RPC and writes the first frame
// before waiting for response headers (the Node client writes its
// request frame immediately; servers may not emit headers first).
func openCursorAgentSession(ctx context.Context, url string, headers map[string]string, firstFrame []byte) (*cursorAgentSession, error) {
	reqCtx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, pr)
	if err != nil {
		cancel()
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	s := &cursorAgentSession{pw: pw, cancel: cancel, respCh: make(chan agentDialResult, 1)}
	go func() {
		resp, err := cursorHTTPClient().Do(req)
		s.respCh <- agentDialResult{resp: resp, err: err}
	}()
	if len(firstFrame) > 0 {
		if _, err := pw.Write(firstFrame); err != nil {
			cancel()
			return nil, err
		}
	}
	return s, nil
}

// awaitHeaders blocks until the server sends response headers.
func (s *cursorAgentSession) awaitHeaders() (*http.Response, error) {
	res := <-s.respCh
	if res.err != nil {
		s.cancel()
		return nil, res.err
	}
	s.resp = res.resp
	s.body = res.resp.Body
	return res.resp, nil
}

// write sends one frame mid-stream (handshake acks).
func (s *cursorAgentSession) write(frame []byte) {
	if s.pw != nil {
		_, _ = s.pw.Write(frame)
	}
}

// read returns the next response chunk.
func (s *cursorAgentSession) read(buf []byte) (int, error) {
	if s.body == nil {
		return 0, io.EOF
	}
	return s.body.Read(buf)
}

// end half-closes the request body (Node req.end()).
func (s *cursorAgentSession) end() {
	s.once.Do(func() {
		if s.pw != nil {
			_ = s.pw.Close()
		}
	})
}

// close tears the session down.
func (s *cursorAgentSession) close() {
	s.end()
	if s.body != nil {
		_ = s.body.Close()
	}
	s.cancel()
}

// ---------- events ----------

type cursorAgentToolCall struct {
	ID        string
	Name      string
	Arguments string
}

type cursorAgentEvent struct {
	Type         string // "text" | "thinking" | "tool_call" | "error" | "done"
	Text         string
	ToolCall     *cursorAgentToolCall
	FinishReason string
}

type cursorAgentEventHandler func(ev cursorAgentEvent)

// cursorAgentTurn holds per-attempt stream state (consume() locals).
type cursorAgentTurn struct {
	session       *cursorAgentSession
	finished      bool
	thinkingAcc   string
	emittedVis    int
	emittedText   bool
	composerModel bool
	onEvent       cursorAgentEventHandler
}

// isComposerModel ports isComposerModel().
func isComposerModel(model string) bool {
	modelID := model
	if idx := strings.LastIndex(modelID, "/"); idx >= 0 {
		modelID = modelID[idx+1:]
	}
	lower := strings.ToLower(modelID)
	return lower == "composer" || strings.HasPrefix(lower, "composer-")
}

// visibleComposerContentFromThinking ports
// visibleComposerContentFromThinking().
func visibleComposerContentFromThinking(thinking string) string {
	if thinking == "" {
		return ""
	}
	endIdx := strings.LastIndex(thinking, "</think>")
	if endIdx < 0 {
		return ""
	}
	return strings.TrimLeft(thinking[endIdx+len("</think>"):], " \t\r\n")
	// JS trimStart() trims all whitespace; the set above covers what
	// Cursor emits in practice (spaces/newlines/tabs/CR).
}

func (t *cursorAgentTurn) flushThinkingFallback() {
	if t.emittedText || t.thinkingAcc == "" {
		return
	}
	var fallback string
	if t.composerModel {
		fallback = visibleComposerContentFromThinking(t.thinkingAcc)
	} else {
		fallback = strings.TrimSpace(t.thinkingAcc)
	}
	if fallback != "" {
		t.emittedText = true
		t.onEvent(cursorAgentEvent{Type: "text", Text: fallback})
	}
}

func (t *cursorAgentTurn) finishTurn() {
	t.flushThinkingFallback()
	t.finished = true
	if t.emittedText {
		t.onEvent(cursorAgentEvent{Type: "done"})
	} else {
		t.onEvent(cursorAgentEvent{Type: "error", Text: "Cursor AgentService returned an empty turn"})
	}
}

// handlePayload processes one AgentServerMessage payload.
func (t *cursorAgentTurn) handlePayload(payload []byte) {
	serverMessage := pbDecodeMessage(payload)

	// AgentServerMessage.interaction_update (field 1).
	if serverMessage.has(1) {
		update := pbDecodeMessage(serverMessage.firstBytes(1))
		if update.has(1) {
			textDelta := pbDecodeMessage(update.firstBytes(1)).firstString(1)
			if textDelta != "" {
				t.emittedText = true
				t.onEvent(cursorAgentEvent{Type: "text", Text: textDelta})
			}
		}
		if update.has(4) {
			thinkingDelta := pbDecodeMessage(update.firstBytes(4)).firstString(1)
			if thinkingDelta != "" {
				t.thinkingAcc += thinkingDelta
				if t.composerModel {
					visible := visibleComposerContentFromThinking(t.thinkingAcc)
					if len(visible) > t.emittedVis {
						deltaContent := visible[t.emittedVis:]
						t.emittedVis = len(visible)
						t.emittedText = true
						t.onEvent(cursorAgentEvent{Type: "text", Text: deltaContent})
					}
				}
			}
		}
		if update.has(14) {
			t.finishTurn()
		}
	}

	// KvServerMessage (field 4): get/set blob — ack so stream proceeds.
	if serverMessage.has(4) {
		kv := pbDecodeMessage(serverMessage.firstBytes(4))
		kvID := kv.firstVarint(1)
		metadata := kv.firstBytes(4)
		if kv.has(2) {
			t.session.write(EncodeKvClientMessage(kvID, 2, pbLen(1, []byte{}), metadata))
		} else if kv.has(3) {
			t.session.write(EncodeKvClientMessage(kvID, 3, []byte{}, metadata))
		}
	}

	// ExecServerMessage (field 2): IDE context / tool requests.
	if serverMessage.has(2) {
		execRequest := pbDecodeMessage(serverMessage.firstBytes(2))
		if execRequest.has(10) {
			t.session.write(createRequestContextResponse(execRequest))
		} else if execRequest.has(11) {
			mcp := DecodeMcpArgs(execRequest.firstBytes(11))
			name := mcp.ToolName
			if name == "" {
				name = mcp.Name
			}
			if name != "" {
				id := mcp.ToolCallID
				if id == "" {
					id = "call_" + cursorNewUUID()
				}
				argsJSON := "{}"
				if b, err := marshalJSON(mcp.Args); err == nil && len(b) > 0 {
					argsJSON = string(b)
				}
				t.finished = true
				t.onEvent(cursorAgentEvent{Type: "tool_call", ToolCall: &cursorAgentToolCall{
					ID: id, Name: name, Arguments: argsJSON,
				}})
				t.onEvent(cursorAgentEvent{Type: "done", FinishReason: "tool_calls"})
			} else {
				t.finished = true
				t.onEvent(cursorAgentEvent{Type: "error", Text: "Cursor AgentService requested an unsupported IDE tool"})
			}
		} else {
			if rejection := rejectExecRequest(execRequest); rejection != nil {
				t.session.write(rejection)
			} else {
				t.finished = true
				t.onEvent(cursorAgentEvent{Type: "error", Text: "Cursor AgentService requested an unsupported IDE tool"})
			}
		}
	}
}

// consume reads the session to completion (or finish) — ports consume().
func (t *cursorAgentTurn) consume() error {
	defer func() {
		t.session.end()
		t.session.close()
	}()
	decoder := &agentFrameDecoder{}
	buf := make([]byte, 32*1024)
	for !t.finished {
		n, err := t.session.read(buf)
		if n > 0 {
			ferr := decoder.feed(buf[:n], func(payload []byte) error {
				if t.finished {
					return nil
				}
				t.handlePayload(payload)
				return nil
			})
			if ferr != nil {
				return ferr
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	if !t.finished {
		t.finishTurn()
	}
	return nil
}

// cursorAgentRunner drives one logical agent request with the
// empty-turn retry policy (runWithRetry in the JS).
type cursorAgentRunner struct {
	ctx      context.Context
	url      string
	headers  map[string]string
	model    string // resolved run model
	origMsg  []cursorAgentMessage
	tools    []CursorToolDef
	effort   string
	composer bool

	session *cursorAgentSession
}

// openSession opens a fresh h2 session with a Run frame for msgs and
// validates the response status. On non-200 it returns the JS-style
// error ExecResult body text via errResult (already built).
func (r *cursorAgentRunner) openSession(msgs []cursorAgentMessage) (*cursorAgentSession, *http.Response, error) {
	frame := BuildAgentRunFrame(msgs, r.model, r.tools, r.effort)
	session, err := openCursorAgentSession(r.ctx, r.url, r.headers, frame)
	if err != nil {
		return nil, nil, err
	}
	resp, err := session.awaitHeaders()
	if err != nil {
		session.close()
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		var errText strings.Builder
		readBuf := make([]byte, 32*1024)
		for {
			n, rerr := session.read(readBuf)
			if n > 0 {
				errText.Write(readBuf[:n])
			}
			if rerr != nil {
				break
			}
		}
		session.close()
		status := resp.StatusCode
		if status == 0 {
			status = 500 // JS: status || HTTP_STATUS.SERVER_ERROR
		}
		return nil, &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(fmt.Sprintf(
				`{"error":{"message":%s,"type":"api_error"}}`,
				strconv.Quote("Cursor AgentService "+strconv.Itoa(resp.StatusCode)+": "+firstNonEmpty(errText.String(), "request failed")),
			))),
		}, nil
	}
	return session, nil, nil
}

// runWithRetry ports runWithRetry(): events stream live; empty-turn
// errors are withheld while a tail-only retry is still available.
// firstSession must already be open (headers validated). A transport
// failure inside a turn aborts the run (the JS promise rejects), so it
// is returned rather than surfaced as an error event.
func (r *cursorAgentRunner) runWithRetry(firstSession *cursorAgentSession, onEvent cursorAgentEventHandler) error {
	outputStarted := false
	wrapped := func(ev cursorAgentEvent) {
		if ev.Type == "text" || ev.Type == "thinking" || ev.Type == "tool_call" {
			outputStarted = true
		}
		onEvent(ev)
	}
	session := firstSession
	workingMessages := r.origMsg
	attempt := 0
	for {
		var turnError *cursorAgentEvent
		turn := &cursorAgentTurn{
			session:       session,
			composerModel: r.composer,
			onEvent: func(ev cursorAgentEvent) {
				if ev.Type == "error" {
					cp := ev
					turnError = &cp
				} else {
					wrapped(ev)
				}
			},
		}
		if err := turn.consume(); err != nil {
			return err
		}
		if turnError != nil &&
			shouldRetryEmptyTurn(len(r.origMsg)) &&
			!outputStarted &&
			attempt < cursorEmptyTurnMaxRetries &&
			r.ctx.Err() == nil {
			attempt++
			workingMessages = tailOnlyCursorMessages(r.origMsg)
			newSession, errResp, err := r.openSession(workingMessages)
			if err != nil {
				return err
			}
			if errResp != nil {
				// JS: a non-200 retry surfaces the withheld error.
				wrapped(*turnError)
				return nil
			}
			session = newSession
			if cursorEmptyTurnRetryDelay > 0 {
				select {
				case <-r.ctx.Done():
					wrapped(*turnError)
					return nil
				case <-time.After(cursorEmptyTurnRetryDelay):
				}
			}
			continue
		}
		if turnError != nil {
			wrapped(*turnError)
		}
		return nil
	}
}
