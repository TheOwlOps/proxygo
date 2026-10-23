package executors

// Port of open-sse/executors/cursor.js (Phase 2 — the Phase 1
// placeholder is gone). Two upstream paths, exactly like the JS:
//
//   - AgentService (agent.api5.cursor.sh, HTTP/2-only): used for
//     text-only requests; duplex Connect stream with the IDE-context
//     handshake — see cursor_agent.go.
//   - ChatService (api2.cursor.sh StreamUnifiedChatWithTools): the
//     legacy buffered protobuf path for non-text (e.g. image) bodies —
//     see cursor_protobuf.go for the wire codec.
//
// Both paths emit OpenAI-shaped responses, so ExecResult.ResponseFormat
// is "openai" and the cursor→openai translator stays a passthrough.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const (
	cursorDefaultBaseURL       = "https://api2.cursor.sh"
	cursorDefaultChatPath      = "/aiserver.v1.ChatService/StreamUnifiedChatWithTools"
	cursorDefaultAgentEndpoint = "https://agent.api5.cursor.sh"
	cursorHTTP2Timeout         = 60 * time.Second // JS makeHttp2Request HTTP2_TIMEOUT_MS
)

// cursorH2Transport is the shared HTTP/2 transport for every Cursor
// call. Package-level so tests can point it at a local h2 server.
var cursorH2Transport http.RoundTripper = &http2.Transport{}

func cursorHTTPClient() *http.Client {
	return &http.Client{Transport: cursorH2Transport}
}

func readAllBody(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

// CursorExecutor executes Cursor requests.
type CursorExecutor struct{ *Base }

func NewCursorExecutor() *CursorExecutor {
	c := &CursorExecutor{}
	c.Base = &Base{ProviderID: "cursor"}
	return c
}

// cursorOAuthString reads a string from the provider's oauth block
// (registry oauth: agentEndpoint, modelsEndpoint, …).
func cursorOAuthString(p *ProviderInfo, key string) string {
	if p == nil || p.Raw == nil {
		return ""
	}
	oauth, ok := p.Raw["oauth"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := oauth[key].(string)
	return s
}

// cursorTransportString reads a string from the transport block
// (chatPath lives there in the registry).
func cursorTransportString(p *ProviderInfo, key string) string {
	if p == nil || p.Raw == nil {
		return ""
	}
	if s := p.RawString(key); s != "" {
		return s
	}
	transport, ok := p.Raw["transport"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := transport[key].(string)
	return s
}

func cursorAgentEndpoint(p *ProviderInfo) string {
	if ep := cursorOAuthString(p, "agentEndpoint"); ep != "" {
		return ep
	}
	return cursorDefaultAgentEndpoint
}

// CursorBuildURL mirrors buildUrl: config.baseUrl + config.chatPath.
func CursorBuildURL(p *ProviderInfo) string {
	base := cursorDefaultBaseURL
	chatPath := cursorDefaultChatPath
	if p != nil {
		if p.BaseURL != "" {
			base = p.BaseURL
		}
		if cp := cursorTransportString(p, "chatPath"); cp != "" {
			chatPath = cp
		}
	}
	return base + chatPath
}

// buildHeaders ports CursorExecutor.buildHeaders: throws the machine-id
// error before any network call, like the JS.
func (c *CursorExecutor) buildHeaders(cred Credential) (map[string]string, error) {
	machineID := cred.SpecificString("machineId")
	if machineID == "" {
		return nil, errors.New("Machine ID is required for Cursor API")
	}
	ghostMode := cred.SpecificString("ghostMode") != "false"
	return BuildCursorHeaders(cred.AccessToken, machineID, ghostMode), nil
}

// Execute implements Executor.
func (c *CursorExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "cursor"}
	}
	bodyMap, _ := decodeBody(body)
	if bodyMap == nil {
		bodyMap = map[string]any{}
	}
	model := ModelOf(bodyMap)
	// JS executor semantics: streaming unless stream === false.
	stream := bodyMap["stream"] != false

	if IsAgentCapableRequest(bodyMap) {
		result, err := c.executeAgent(ctx, p, cred, bodyMap, model, stream)
		if err != nil {
			// JS execute() catch: a 500 connection_error result, so
			// chatcore can classify/fall back like any upstream failure.
			return &ExecResult{
				Response:        cursorJSONResponse(500, map[string]any{"error": map[string]any{"message": err.Error(), "type": "connection_error", "code": ""}}),
				URL:             cursorAgentEndpoint(p) + agentRunPath,
				Headers:         map[string]string{},
				TransformedBody: body,
			}, nil
		}
		return result, nil
	}
	return c.executeLegacy(ctx, p, cred, bodyMap, body, model, stream)
}

// ---------- legacy ChatService path ----------

func (c *CursorExecutor) executeLegacy(ctx context.Context, p *ProviderInfo, cred Credential, bodyMap map[string]any, rawBody []byte, model string, stream bool) (*ExecResult, error) {
	url := CursorBuildURL(p)
	headers, err := c.buildHeaders(cred)
	if err != nil {
		return nil, err
	}
	transformed := c.transformRequest(model, bodyMap, cred)

	reqCtx, cancel := context.WithTimeout(ctx, cursorHTTP2Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(transformed))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cursorHTTPClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &ExecResult{
			Response:        cursorJSONResponse(500, map[string]any{"error": map[string]any{"message": err.Error(), "type": "connection_error", "code": ""}}),
			URL:             url,
			Headers:         headers,
			TransformedBody: rawBody,
		}, nil
	}
	defer resp.Body.Close()
	respBody, err := readAllBody(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		errorText := string(respBody)
		if errorText == "" {
			errorText = "Unknown error" // JS: body?.toString() || "Unknown error"
		}
		errResp := cursorJSONResponse(resp.StatusCode, map[string]any{"error": map[string]any{
			"message": fmt.Sprintf("[%d]: %s", resp.StatusCode, errorText),
			"type":    "invalid_request_error",
			"code":    "",
		}})
		return &ExecResult{Response: errResp, URL: url, Headers: headers, TransformedBody: rawBody}, nil
	}

	var out *http.Response
	if stream {
		out = transformProtobufToSSE(respBody, model, bodyMap)
	} else {
		out = transformProtobufToJSON(respBody, model, bodyMap)
	}
	return &ExecResult{
		Response:        out,
		URL:             url,
		Headers:         headers,
		TransformedBody: rawBody,
		ResponseFormat:  "openai",
	}, nil
}

// transformRequest ports transformRequest(): messages were already
// translated by chatcore (openai→cursor) — do NOT translate again.
func (c *CursorExecutor) transformRequest(model string, body map[string]any, cred Credential) []byte {
	messages := cursorMessagesFromBody(body)
	tools := cursorToolsFromBody(body)
	var reasoningEffort string
	if s, ok := body["reasoning_effort"].(string); ok {
		reasoningEffort = s
	}
	// Force Agent mode for Claude Code clients (issue #643 in the JS).
	ua := ""
	if cred.RawHeaders != nil {
		ua = cred.RawHeaders["user-agent"]
	}
	forceAgentMode := strings.Contains(ua, "claude-cli") || strings.Contains(ua, "claude-code") || strings.Contains(ua, "Claude Code")
	return GenerateCursorBody(messages, model, tools, reasoningEffort, forceAgentMode)
}

// cursorMessagesFromBody converts decoded body messages to the
// protobuf encoder's view.
func cursorMessagesFromBody(body map[string]any) []CursorMessage {
	raw, _ := body["messages"].([]any)
	out := make([]CursorMessage, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		msg := CursorMessage{Role: getStr(m, "role")}
		switch content := m["content"].(type) {
		case string:
			msg.Content = content
		case []any:
			msg.Content = cursorExtractTextContent(content)
		}
		if tcs, ok := m["tool_calls"].([]any); ok {
			msg.ToolCallCount = len(tcs)
		}
		if trs, ok := m["tool_results"].([]any); ok {
			for _, trItem := range trs {
				trm, ok := trItem.(map[string]any)
				if !ok {
					continue
				}
				tr := CursorToolResult{
					ToolCallID:    getStr(trm, "tool_call_id"),
					ToolName:      firstNonEmpty(getStr(trm, "tool_name"), getStr(trm, "name")),
					RawArgs:       getStr(trm, "raw_args"),
					ResultContent: firstNonEmpty(getStr(trm, "result_content"), getStr(trm, "result")),
				}
				if tr.RawArgs == "" {
					tr.RawArgs = "{}"
				}
				if idx, ok := trm["tool_index"].(float64); ok {
					tr.ToolIndex = int(idx)
				} else if idx, ok := trm["index"].(float64); ok {
					tr.ToolIndex = int(idx)
				}
				msg.ToolResults = append(msg.ToolResults, tr)
			}
		}
		out = append(out, msg)
	}
	return out
}

// cursorExtractTextContent joins text parts (translator's
// extractContent semantics) for array message content.
func cursorExtractTextContent(parts []any) string {
	var sb strings.Builder
	for _, part := range parts {
		pm, ok := part.(map[string]any)
		if !ok {
			continue
		}
		if getStr(pm, "type") == "text" {
			if t, ok := pm["text"].(string); ok {
				sb.WriteString(t)
			}
		}
	}
	return sb.String()
}

// cursorToolsFromBody converts OpenAI tool definitions to CursorToolDef
// (tool.function?.name || tool.name, …).
func cursorToolsFromBody(body map[string]any) []CursorToolDef {
	raw, _ := body["tools"].([]any)
	out := make([]CursorToolDef, 0, len(raw))
	for _, item := range raw {
		tm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		def := CursorToolDef{}
		src := tm
		if fn, ok := tm["function"].(map[string]any); ok {
			src = fn
		}
		def.Name = firstNonEmpty(getStr(src, "name"), getStr(tm, "name"))
		def.Description = firstNonEmpty(getStr(src, "description"), getStr(tm, "description"))
		if params, ok := src["parameters"].(map[string]any); ok {
			def.InputSchema = params
		} else if params, ok := tm["input_schema"].(map[string]any); ok {
			def.InputSchema = params
		}
		out = append(out, def)
	}
	return out
}

// ---------- AgentService path ----------

func (c *CursorExecutor) executeAgent(ctx context.Context, p *ProviderInfo, cred Credential, bodyMap map[string]any, model string, stream bool) (*ExecResult, error) {
	// JS throws "Cursor AgentService endpoint is not configured" when
	// the registry oauth block lacks agentEndpoint; the registry value
	// is exactly this constant, so fall back to it when Raw was not
	// populated by the adapter.
	endpoint := cursorAgentEndpoint(p)
	url := endpoint + agentRunPath
	headers, err := c.buildHeaders(cred)
	if err != nil {
		return nil, err
	}

	originalMessages := cursorAgentMessagesFromBody(bodyMap)
	tools := cursorToolsFromBody(bodyMap)

	// "Auto (Server Picks)"/"default" is a picker alias, not a model id.
	runModel := model
	if model == "default" || model == "auto" {
		if catalog := ResolveCursorModels(ctx, p, cred); catalog != nil {
			if selection, ok := ResolveAutoModelSelection(catalog); ok {
				runModel = selection
			}
		}
	}
	effort := ""
	if s, ok := bodyMap["reasoning_effort"].(string); ok && s != "" {
		effort = s
	} else if reasoning, ok := bodyMap["reasoning"].(map[string]any); ok {
		effort = getStr(reasoning, "effort")
	}

	runner := &cursorAgentRunner{
		ctx:      ctx,
		url:      url,
		headers:  headers,
		model:    runModel,
		origMsg:  originalMessages,
		tools:    tools,
		effort:   effort,
		composer: isComposerModel(model),
	}
	session, errResp, err := runner.openSession(originalMessages)
	if err != nil {
		return nil, fmt.Errorf("Cursor AgentService request failed: %w", err)
	}
	if errResp != nil {
		return &ExecResult{
			Response:        errResp,
			URL:             url,
			Headers:         headers,
			TransformedBody: mustJSON(bodyMap),
			ResponseFormat:  "openai",
		}, nil
	}

	responseID := "chatcmpl-msg_" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	created := time.Now().Unix()

	if !stream {
		return c.collectAgentJSON(runner, session, url, headers, bodyMap, model, responseID, created)
	}
	return c.streamAgentSSE(runner, session, url, headers, bodyMap, model, responseID, created), nil
}

// collectAgentJSON is the stream === false branch of executeAgent.
func (c *CursorExecutor) collectAgentJSON(runner *cursorAgentRunner, session *cursorAgentSession, url string, headers map[string]string, bodyMap map[string]any, model, responseID string, created int64) (*ExecResult, error) {
	var content, reasoning strings.Builder
	var agentError string
	var toolCalls []map[string]any
	finishReason := "stop"
	err := runner.runWithRetry(session, func(ev cursorAgentEvent) {
		switch ev.Type {
		case "text":
			content.WriteString(ev.Text)
		case "thinking":
			reasoning.WriteString(ev.Text)
		case "tool_call":
			toolCalls = append(toolCalls, map[string]any{
				"id":   ev.ToolCall.ID,
				"type": "function",
				"function": map[string]any{
					"name":      ev.ToolCall.Name,
					"arguments": ev.ToolCall.Arguments,
				},
			})
			finishReason = "tool_calls"
		case "error":
			agentError = ev.Text
		case "done":
			if ev.FinishReason != "" {
				finishReason = ev.FinishReason
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if agentError != "" {
		return &ExecResult{
			Response:        cursorJSONResponse(400, map[string]any{"error": map[string]any{"message": agentError, "type": "api_error"}}),
			URL:             url,
			Headers:         headers,
			TransformedBody: mustJSON(bodyMap),
			ResponseFormat:  "openai",
		}, nil
	}
	message := map[string]any{"role": "assistant"}
	if content.Len() > 0 {
		message["content"] = content.String()
	} else {
		message["content"] = nil
	}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	completion := map[string]any{
		"id":      responseID,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
		"usage": cursorEstimateUsage(bodyMap, content.Len()),
	}
	return &ExecResult{
		Response:        cursorJSONResponse(200, completion),
		URL:             url,
		Headers:         headers,
		TransformedBody: mustJSON(bodyMap),
		ResponseFormat:  "openai",
	}, nil
}

// streamAgentSSE is the streaming branch of executeAgent: returns a
// response whose body is fed by the retry-aware event loop.
func (c *CursorExecutor) streamAgentSSE(runner *cursorAgentRunner, session *cursorAgentSession, url string, headers map[string]string, bodyMap map[string]any, model, responseID string, created int64) *ExecResult {
	pr, pw := io.Pipe()
	go func() {
		write := func(s string) { _, _ = io.WriteString(pw, s) }
		err := runner.runWithRetry(session, func(ev cursorAgentEvent) {
			switch ev.Type {
			case "text":
				write(cursorChatChunkSSE(responseID, created, model, map[string]any{"content": ev.Text}, nil))
			case "thinking":
				write(cursorChatChunkSSE(responseID, created, model, map[string]any{"reasoning_content": ev.Text}, nil))
			case "tool_call":
				write(cursorChatChunkSSE(responseID, created, model, map[string]any{
					"tool_calls": []any{map[string]any{
						"index": 0,
						"id":    ev.ToolCall.ID,
						"type":  "function",
						"function": map[string]any{
							"name":      ev.ToolCall.Name,
							"arguments": ev.ToolCall.Arguments,
						},
					}},
				}, nil))
			case "error":
				// An SSE error frame, not a content delta (JS comment).
				write(cursorSSEChunk(map[string]any{"error": map[string]any{"message": ev.Text, "type": "api_error"}}))
				write(cursorSSEDone)
			case "done":
				fr := ev.FinishReason
				if fr == "" {
					fr = "stop"
				}
				write(cursorChatChunkSSE(responseID, created, model, map[string]any{}, fr))
				write(cursorSSEDone)
			}
		})
		if err != nil {
			// JS errors the stream (controller.error). The Go pipe
			// equivalent closes with the error after an error frame so
			// downstream sees a well-formed terminal state.
			write(cursorSSEChunk(map[string]any{"error": map[string]any{"message": err.Error(), "type": "api_error"}}))
			write(cursorSSEDone)
		}
		_ = pw.Close()
	}()
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}, "Connection": []string{"keep-alive"}},
		Body:       pr,
	}
	return &ExecResult{
		Response:        resp,
		URL:             url,
		Headers:         headers,
		TransformedBody: mustJSON(bodyMap),
		ResponseFormat:  "openai",
	}
}

// ---------- shared response helpers ----------

const cursorSSEDone = "data: [DONE]\n\n"

func cursorSSEChunk(v map[string]any) string {
	b, _ := json.Marshal(v)
	return "data: " + string(b) + "\n\n"
}

// cursorChatChunkSSE ports chatChunkSse(): finishReason nil → JSON null.
func cursorChatChunkSSE(id string, created int64, model string, delta map[string]any, finishReason any) string {
	return cursorSSEChunk(map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         delta,
			"finish_reason": finishReason,
		}},
	})
}

func cursorJSONResponse(status int, v map[string]any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func mustJSON(v map[string]any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// cursorEstimateUsage ports estimateUsage(body, contentLength, OPENAI)
// including addBufferToUsage's +2000 buffer tokens.
func cursorEstimateUsage(body map[string]any, contentLength int) map[string]any {
	inputTokens := 0
	if body != nil {
		if b, err := json.Marshal(body); err == nil {
			inputTokens = int(math.Ceil(float64(len(b)) / 4))
		}
	}
	outputTokens := 0
	if contentLength > 0 {
		outputTokens = contentLength / 4
		if outputTokens < 1 {
			outputTokens = 1
		}
	}
	const bufferTokens = 2000
	return map[string]any{
		"prompt_tokens":     inputTokens + bufferTokens,
		"completion_tokens": outputTokens,
		"total_tokens":      inputTokens + outputTokens + bufferTokens,
		"estimated":         true,
	}
}

// createErrorResponse ports createErrorResponse() from cursor.js:
// a Connect JSON error payload → OpenAI error response.
func createCursorErrorResponse(jsonError map[string]any) *http.Response {
	errObj, _ := jsonError["error"].(map[string]any)
	errorMsg := "API Error"
	var debugError string
	if details, ok := errObj["details"].([]any); ok && len(details) > 0 {
		if d0, ok := details[0].(map[string]any); ok {
			if debug, ok := d0["debug"].(map[string]any); ok {
				if det, ok := debug["details"].(map[string]any); ok {
					if title := getStr(det, "title"); title != "" {
						errorMsg = title
					} else if detail := getStr(det, "detail"); detail != "" {
						errorMsg = detail
					}
				}
				debugError = getStr(debug, "error")
			}
		}
	}
	if errorMsg == "API Error" {
		if msg := getStr(errObj, "message"); msg != "" {
			errorMsg = msg
		}
	}
	isRateLimit := getStr(errObj, "code") == "resource_exhausted"
	status := 400
	errType := "api_error"
	if isRateLimit {
		status = 429
		errType = "rate_limit_error"
	}
	code := debugError
	if code == "" {
		code = "unknown"
	}
	return cursorJSONResponse(status, map[string]any{"error": map[string]any{
		"message": errorMsg,
		"type":    errType,
		"code":    code,
	}})
}

// parseJSONErrorFrame reports whether a frame payload is a JSON error
// object, returning it parsed (the transforms' `payload[0] === '{'`
// byte-guard + `"error"` check).
func parseJSONErrorFrame(payload []byte) (map[string]any, bool) {
	if len(payload) == 0 || payload[0] != 0x7b {
		return nil, false
	}
	text := string(payload)
	if !strings.Contains(text, `"error"`) {
		return nil, false
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

// ---------- legacy response transforms ----------

type cursorToolAccum struct {
	id       string
	typ      string
	name     string
	args     string
	isLast   bool
	index    int
	hasIndex bool
}

// transformProtobufToJSON ports transformProtobufToJSON().
func transformProtobufToJSON(buf []byte, model string, body map[string]any) *http.Response {
	responseID := "chatcmpl-cursor-" + fmt.Sprintf("%d", time.Now().UnixMilli())
	created := time.Now().Unix()

	offset := 0
	var totalContent, totalThinking strings.Builder
	var toolCalls []map[string]any
	toolCallsMap := map[string]*cursorToolAccum{}
	var toolOrder []*cursorToolAccum
	finalizedIDs := map[string]bool{}

	for offset < len(buf) {
		frame := readCursorFrame(buf, offset)
		if frame.status == "done" {
			break
		}
		offset = frame.offset
		if frame.status == "skip" {
			continue
		}
		payload := frame.payload

		if parsed, isErr := parseJSONErrorFrame(payload); isErr {
			hasContent := totalContent.Len() > 0 || len(toolCallsMap) > 0
			if hasContent {
				break
			}
			return createCursorErrorResponse(parsed)
		}

		// ExtractTextFromResponse's error field is always null in the
		// JS (decode failures surface only via debug logs) — no branch.
		result := ExtractTextFromResponse(payload)
		if result.ToolCall != nil {
			tc := result.ToolCall
			if existing, ok := toolCallsMap[tc.ID]; ok {
				existing.args += tc.FunctionArgs
				existing.isLast = tc.IsLast
			} else {
				acc := &cursorToolAccum{id: tc.ID, typ: tc.Type, name: tc.FunctionName, args: tc.FunctionArgs, isLast: tc.IsLast}
				toolCallsMap[tc.ID] = acc
				toolOrder = append(toolOrder, acc)
			}
			if tc.IsLast {
				finalToolCall := toolCallsMap[tc.ID]
				finalizedIDs[tc.ID] = true
				toolCalls = append(toolCalls, map[string]any{
					"id":   finalToolCall.id,
					"type": finalToolCall.typ,
					"function": map[string]any{
						"name":      finalToolCall.name,
						"arguments": finalToolCall.args,
					},
				})
			}
		}
		if result.HasText {
			totalContent.WriteString(result.Text)
		}
		if result.HasThinking {
			totalThinking.WriteString(result.Thinking)
		}
	}

	visibleComposerContent := ""
	if isComposerModel(model) {
		visibleComposerContent = visibleComposerContentFromThinking(totalThinking.String())
	}
	finalContent := totalContent.String()
	if finalContent == "" {
		finalContent = visibleComposerContent
	}

	for _, acc := range toolOrder {
		if !finalizedIDs[acc.id] {
			toolCalls = append(toolCalls, map[string]any{
				"id":   acc.id,
				"type": acc.typ,
				"function": map[string]any{
					"name":      acc.name,
					"arguments": acc.args,
				},
			})
		}
	}

	message := map[string]any{"role": "assistant"}
	if finalContent != "" {
		message["content"] = finalContent
	} else {
		message["content"] = nil
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	completion := map[string]any{
		"id":      responseID,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
		"usage": cursorEstimateUsage(body, len(finalContent)),
	}
	return cursorJSONResponse(200, completion)
}

// transformProtobufToSSE ports transformProtobufToSSE().
func transformProtobufToSSE(buf []byte, model string, body map[string]any) *http.Response {
	responseID := "chatcmpl-cursor-" + fmt.Sprintf("%d", time.Now().UnixMilli())
	created := time.Now().Unix()

	var chunks []string
	offset := 0
	var totalContent, totalThinking strings.Builder
	emittedComposerThinkingLen := 0
	var toolCalls []*cursorToolAccum
	toolCallsMap := map[string]*cursorToolAccum{}
	finalizedIDs := map[string]bool{}
	emittedToolCallIDs := map[string]bool{}

	emitChunk := func(delta map[string]any, finish any) {
		chunks = append(chunks, cursorChatChunkSSE(responseID, created, model, delta, finish))
	}

	for offset < len(buf) {
		frame := readCursorFrame(buf, offset)
		if frame.status == "done" {
			break
		}
		offset = frame.offset
		if frame.status == "skip" {
			continue
		}
		payload := frame.payload

		if parsed, isErr := parseJSONErrorFrame(payload); isErr {
			hasContent := len(chunks) > 0 || totalContent.Len() > 0 || len(toolCallsMap) > 0
			if hasContent {
				break
			}
			return createCursorErrorResponse(parsed)
		}

		result := ExtractTextFromResponse(payload)

		if result.ToolCall != nil {
			tc := result.ToolCall
			if len(chunks) == 0 {
				emitChunk(map[string]any{"role": "assistant", "content": ""}, nil)
			}
			if existing, ok := toolCallsMap[tc.ID]; ok {
				existing.args += tc.FunctionArgs
				existing.isLast = tc.IsLast
				if tc.FunctionArgs != "" {
					emittedToolCallIDs[tc.ID] = true
					emitChunk(map[string]any{
						"tool_calls": []any{map[string]any{
							"index": existing.index,
							"id":    tc.ID,
							"type":  "function",
							"function": map[string]any{
								"name":      tc.FunctionName,
								"arguments": tc.FunctionArgs,
							},
						}},
					}, nil)
				}
			} else {
				toolCallIndex := len(toolCalls)
				acc := &cursorToolAccum{id: tc.ID, typ: tc.Type, name: tc.FunctionName, args: tc.FunctionArgs, isLast: tc.IsLast, index: toolCallIndex, hasIndex: true}
				finalizedIDs[tc.ID] = true
				toolCalls = append(toolCalls, acc)
				toolCallsMap[tc.ID] = acc
				emittedToolCallIDs[tc.ID] = true
				emitChunk(map[string]any{
					"tool_calls": []any{map[string]any{
						"index": toolCallIndex,
						"id":    tc.ID,
						"type":  "function",
						"function": map[string]any{
							"name":      tc.FunctionName,
							"arguments": tc.FunctionArgs,
						},
					}},
				}, nil)
			}
		}

		if result.HasText && result.Text != "" {
			totalContent.WriteString(result.Text)
			delta := map[string]any{"content": result.Text}
			if len(chunks) == 0 && len(toolCalls) == 0 {
				delta = map[string]any{"role": "assistant", "content": result.Text}
			}
			emitChunk(delta, nil)
		}

		if isComposerModel(model) && result.HasThinking && result.Thinking != "" {
			totalThinking.WriteString(result.Thinking)
			visibleContent := visibleComposerContentFromThinking(totalThinking.String())
			if len(visibleContent) > emittedComposerThinkingLen {
				deltaContent := visibleContent[emittedComposerThinkingLen:]
				emittedComposerThinkingLen = len(visibleContent)
				totalContent.WriteString(deltaContent)
				delta := map[string]any{"content": deltaContent}
				if len(chunks) == 0 && len(toolCalls) == 0 {
					delta = map[string]any{"role": "assistant", "content": deltaContent}
				}
				emitChunk(delta, nil)
			}
		}
	}

	// Finalize remaining tool calls (stream may have ended without
	// isLast=true). JS iterates the map in insertion order; in this
	// transform every tool call is inserted into toolCalls on first
	// sight, so insertion order == toolCalls order.
	for _, acc := range orderedToolAccums(toolCallsMap, toolCalls) {
		if !finalizedIDs[acc.id] {
			toolCallIndex := len(toolCalls)
			acc.index = toolCallIndex
			acc.hasIndex = true
			toolCalls = append(toolCalls, acc)
			if !emittedToolCallIDs[acc.id] {
				emitChunk(map[string]any{
					"tool_calls": []any{map[string]any{
						"index": toolCallIndex,
						"id":    acc.id,
						"type":  "function",
						"function": map[string]any{
							"name":      acc.name,
							"arguments": acc.args,
						},
					}},
				}, nil)
			}
		}
	}

	if len(chunks) == 0 && len(toolCalls) == 0 {
		emitChunk(map[string]any{"role": "assistant", "content": ""}, nil)
	}

	usage := cursorEstimateUsage(body, totalContent.Len())
	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	finalChunk := map[string]any{
		"id":      responseID,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": finishReason,
		}},
		"usage": usage,
	}
	chunks = append(chunks, cursorSSEChunk(finalChunk), cursorSSEDone)

	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}, "Connection": []string{"keep-alive"}},
		Body:       io.NopCloser(strings.NewReader(strings.Join(chunks, ""))),
	}
}

// orderedToolAccums returns map values in insertion order. The SSE
// transform inserts every new tool call into `toolCalls` on first
// sight, so insertion order == toolCalls order followed by any
// not-yet-listed accumulators (none in practice); kept for parity with
// the JS Map iteration in the finalize loop.
func orderedToolAccums(m map[string]*cursorToolAccum, order []*cursorToolAccum) []*cursorToolAccum {
	seen := map[string]bool{}
	var out []*cursorToolAccum
	for _, acc := range order {
		if _, ok := m[acc.id]; ok && !seen[acc.id] {
			seen[acc.id] = true
			out = append(out, acc)
		}
	}
	return out
}
