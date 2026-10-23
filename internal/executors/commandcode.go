package executors

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// CommandCodeExecutor ports open-sse/executors/commandcode.js: talks to
// the CommandCode generate endpoint with a per-request x-session-id; the
// upstream answers AI SDK v5 NDJSON (one JSON event per line, no `data:`
// prefix), which is translated here into OpenAI chat.completion.chunk SSE
// so downstream handlers consume it without further format translation.
// ResponseFormat is therefore "openai".
type CommandCodeExecutor struct{ *Base }

func NewCommandCodeExecutor() *CommandCodeExecutor {
	c := &CommandCodeExecutor{}
	c.Base = &Base{ProviderID: "commandcode", Hooks: Hooks{
		BuildHeaders:  c.buildHeaders,
		TransformBody: c.transformBody,
		ParseError:    c.parseError,
		WrapResponse:  c.wrapResponse,
	}}
	return c
}

func (c *CommandCodeExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range req.Provider.Headers {
		headers[k] = v
	}
	headers["x-session-id"] = newUUID()
	token := req.Cred.APIKey
	if token == "" {
		token = req.Cred.AccessToken
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	if req.Stream {
		headers["Accept"] = "text/event-stream"
	}
	return headers, nil
}

func (c *CommandCodeExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	if req.Body != nil {
		req.Body["stream"] = true // upstream is always streaming (commandcode.js)
	}
	return req.Body, nil
}

// parseError ports CommandCodeExecutor.parseError: the error object may
// carry its own code/statusCode.
func (c *CommandCodeExecutor) parseError(status int, bodyText string) *ParsedError {
	var parsed map[string]any
	if unmarshalJSON([]byte(bodyText), &parsed) != nil || parsed == nil {
		return &ParsedError{Status: status, Message: bodyText}
	}
	errObj, _ := parsed["error"].(map[string]any)
	src := errObj
	if src == nil {
		src = parsed
	}
	msg := getStr(src, "message")
	if msg == "" {
		msg = getStr(parsed, "message")
	}
	if msg == "" {
		msg = bodyText
	}
	code := status
	if v := getFloat(src, "code"); v != 0 {
		code = int(v)
	} else if v := getFloat(src, "statusCode"); v != 0 {
		code = int(v)
	}
	return &ParsedError{Status: code, Message: msg}
}

// parseCommandCodeError ports parseCommandCodeError: classify an NDJSON
// error event into an HTTP status + OpenAI error type.
func parseCommandCodeError(event map[string]any) (int, string, string) {
	message := ""
	statusCode := 0
	typ := "server_error"
	switch v := event["error"].(type) {
	case map[string]any:
		message = getStr(v, "message")
		if message == "" {
			message = getStr(v, "error")
		}
		if message == "" {
			raw, _ := marshalJSON(v)
			message = string(raw)
		}
		if n := getFloat(v, "statusCode"); n != 0 {
			statusCode = int(n)
		} else if n := getFloat(v, "status"); n != 0 {
			statusCode = int(n)
		}
		if t := getStr(v, "type"); t != "" {
			typ = t
		}
	case string:
		message = v
	case nil:
		if m := getStr(event, "message"); m != "" {
			message = m
		}
	default:
		raw, _ := marshalJSON(v)
		message = string(raw)
	}
	if n := getFloat(event, "statusCode"); n != 0 {
		statusCode = int(n)
	}
	if statusCode < 400 || statusCode > 599 {
		lower := strings.ToLower(message)
		switch {
		case strings.Contains(lower, "rate limit"), strings.Contains(lower, "too many requests"):
			statusCode, typ = 429, "rate_limit_error"
		case strings.Contains(lower, "unauthorized"), strings.Contains(lower, "invalid api key"), strings.Contains(lower, "authentication"):
			statusCode, typ = 401, "authentication_error"
		case strings.Contains(lower, "payment required"), strings.Contains(lower, "billing"):
			statusCode, typ = 402, "billing_error"
		case strings.Contains(lower, "quota"), strings.Contains(lower, "forbidden"), strings.Contains(lower, "permission"):
			statusCode, typ = 403, "permission_error"
		case strings.Contains(lower, "not found"):
			statusCode, typ = 404, "invalid_request_error"
		default:
			statusCode, typ = 503, "server_error"
		}
	}
	if message == "" {
		message = "CommandCode upstream error"
	}
	return statusCode, message, typ
}

// wrapResponse ports inspectAndWrapCommandCodeResponse: peek the NDJSON
// head — an early `error` event becomes a real HTTP error response (so
// chatcore can fall back); otherwise the stream is replayed through the
// NDJSON→SSE translator. (The JS additionally retries the whole execute
// up to 2× when the wrapped response is 502/503/504; that retry is left
// to the base retry config + chatcore account fallback — see report.)
func (c *CommandCodeExecutor) wrapResponse(resp *http.Response, req *Request) (*http.Response, string, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Body == nil {
		return resp, "", nil
	}
	br := bufio.NewReaderSize(resp.Body, 32*1024)
	var buffered bytes.Buffer
	var detectedError map[string]any
	decided := false
	for !decided && buffered.Len() < 256*1024 {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			buffered.Write(line)
			trimmed := strings.TrimSpace(string(line))
			if strings.HasPrefix(trimmed, "data:") {
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			}
			if trimmed != "" && trimmed != "[DONE]" {
				var event map[string]any
				if unmarshalJSON([]byte(trimmed), &event) == nil && event != nil {
					switch getStr(event, "type") {
					case "error":
						detectedError = event
						decided = true
					case "text-delta", "reasoning-delta", "tool-input-start", "tool-call", "finish", "finish-step":
						decided = true
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	if detectedError != nil {
		resp.Body.Close()
		statusCode, message, typ := parseCommandCodeError(detectedError)
		raw, _ := marshalJSON(map[string]any{
			"error": map[string]any{
				"message": "[CommandCode error: " + message + "]",
				"type":    typ,
				"code":    statusCode,
			},
		})
		return &http.Response{
			StatusCode: statusCode,
			Status:     http.StatusText(statusCode),
			Header:     http.Header{"Content-Type": []string{"application/json"}, "Access-Control-Allow-Origin": []string{"*"}},
			Body:       io.NopCloser(strings.NewReader(string(raw))),
		}, "", nil
	}
	combined := io.MultiReader(bytes.NewReader(buffered.Bytes()), br)
	pr, pw := io.Pipe()
	go func() {
		err := convertCommandCodeNDJSON(combined, pw, req.Model)
		resp.Body.Close()
		_ = pw.CloseWithError(err)
	}()
	return &http.Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}},
		Body:       pr,
	}, "openai", nil
}

type commandCodeState struct {
	responseID    string
	created       int64
	model         string
	chunkIndex    int
	toolIndex     int
	toolIndexByID map[string]int
	finishReason  string
	usage         map[string]any
}

// convertCommandCodeNDJSON ports wrapNdjsonAsOpenAISse +
// translator/response/commandcode-to-openai.js (main event cases).
func convertCommandCodeNDJSON(r io.Reader, w io.Writer, model string) error {
	state := &commandCodeState{
		responseID:    "chatcmpl-cc",
		model:         model,
		toolIndexByID: map[string]int{},
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	emit := func(chunks []map[string]any) {
		for _, chunk := range chunks {
			raw, _ := marshalJSON(chunk)
			io.WriteString(w, "data: "+string(raw)+"\n\n")
		}
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
		if line == "" || line == "[DONE]" {
			continue
		}
		var event map[string]any
		if unmarshalJSON([]byte(line), &event) != nil || event == nil {
			continue
		}
		emit(commandCodeEventToChunks(event, state))
	}
	_, err := io.WriteString(w, "data: [DONE]\n\n")
	return err
}

func (s *commandCodeState) chunk(delta map[string]any, finish any, usage map[string]any) map[string]any {
	c := map[string]any{
		"id":      s.responseID,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	}
	if usage != nil {
		c["usage"] = usage
	}
	return c
}

func commandCodeEventToChunks(event map[string]any, s *commandCodeState) []map[string]any {
	if s.created == 0 {
		s.created = nowUnix()
		s.responseID = "chatcmpl-" + int64Str(s.created)
		if s.model == "" {
			s.model = firstNonEmpty(getStr(event, "model"), "commandcode")
		}
	}
	var out []map[string]any
	switch getStr(event, "type") {
	case "text-delta":
		text := getStr(event, "text")
		if text == "" {
			text = getStr(event, "delta")
		}
		if text == "" {
			break
		}
		delta := map[string]any{"content": text}
		if s.chunkIndex == 0 {
			delta["role"] = "assistant"
		}
		s.chunkIndex++
		out = append(out, s.chunk(delta, nil, nil))
	case "reasoning-delta":
		text := getStr(event, "text")
		if text == "" {
			break
		}
		delta := map[string]any{"reasoning_content": text}
		if s.chunkIndex == 0 {
			delta["role"] = "assistant"
		}
		s.chunkIndex++
		out = append(out, s.chunk(delta, nil, nil))
	case "tool-input-start":
		id := getStr(event, "id")
		if id == "" {
			id = getStr(event, "toolCallId")
		}
		if id == "" {
			id = "call_cc_" + int64Str(int64(s.toolIndex))
		}
		idx, seen := s.toolIndexByID[id]
		if !seen {
			idx = s.toolIndex
			s.toolIndex++
			s.toolIndexByID[id] = idx
		}
		delta := map[string]any{"tool_calls": []any{map[string]any{
			"index": idx, "id": id, "type": "function",
			"function": map[string]any{"name": getStr(event, "toolName"), "arguments": ""},
		}}}
		if s.chunkIndex == 0 {
			delta["role"] = "assistant"
		}
		s.chunkIndex++
		out = append(out, s.chunk(delta, nil, nil))
	case "tool-input-delta":
		id := getStr(event, "id")
		if id == "" {
			id = getStr(event, "toolCallId")
		}
		idx, seen := s.toolIndexByID[id]
		if !seen {
			break
		}
		delta := map[string]any{"tool_calls": []any{map[string]any{
			"index": idx, "function": map[string]any{"arguments": getStr(event, "delta")},
		}}}
		s.chunkIndex++
		out = append(out, s.chunk(delta, nil, nil))
	case "tool-call":
		id := getStr(event, "toolCallId")
		if id == "" {
			id = getStr(event, "id")
		}
		idx, seen := s.toolIndexByID[id]
		if !seen {
			idx = s.toolIndex
			s.toolIndex++
			s.toolIndexByID[id] = idx
		}
		args := ""
		if input, present := event["input"]; present {
			if str, ok := input.(string); ok {
				args = str
			} else {
				raw, _ := marshalJSON(input)
				args = string(raw)
			}
		}
		delta := map[string]any{"tool_calls": []any{map[string]any{
			"index": idx, "id": id, "type": "function",
			"function": map[string]any{"name": getStr(event, "toolName"), "arguments": args},
		}}}
		if s.chunkIndex == 0 {
			delta["role"] = "assistant"
		}
		s.chunkIndex++
		out = append(out, s.chunk(delta, nil, nil))
	case "finish-step", "finish":
		if fr := getStr(event, "finishReason"); fr != "" {
			s.finishReason = commandCodeFinishReason(fr)
		}
		if u, ok := event["usage"].(map[string]any); ok {
			s.usage = commandCodeUsage(u)
		}
		if getStr(event, "type") == "finish" {
			out = append(out, s.chunk(map[string]any{}, firstNonEmpty(s.finishReason, "stop"), s.usage))
		}
	case "error":
		statusCode, message, _ := parseCommandCodeError(event)
		raw, _ := marshalJSON(map[string]any{
			"error": map[string]any{"message": message, "code": statusCode, "type": "server_error"},
		})
		_ = raw
		out = append(out, map[string]any{
			"id": s.responseID, "object": "error", "error": map[string]any{"message": message, "code": statusCode},
		})
	}
	return out
}

// commandCodeFinishReason maps AI SDK finish reasons to OpenAI
// (translator/concerns/finishReason.js toOpenAIFinish subset).
func commandCodeFinishReason(r string) string {
	switch r {
	case "stop", "end-turn":
		return "stop"
	case "tool-calls", "tool_use":
		return "tool_calls"
	case "length", "max-tokens":
		return "length"
	case "content-filter":
		return "content_filter"
	default:
		return "stop"
	}
}

// commandCodeUsage converts AI SDK usage {inputTokens, outputTokens,
// totalTokens} to OpenAI usage (translator/concerns/usage.js toOpenAIUsage).
func commandCodeUsage(u map[string]any) map[string]any {
	prompt := int(getFloat(u, "inputTokens"))
	if prompt == 0 {
		prompt = int(getFloat(u, "prompt_tokens"))
	}
	completion := int(getFloat(u, "outputTokens"))
	if completion == 0 {
		completion = int(getFloat(u, "completion_tokens"))
	}
	total := int(getFloat(u, "totalTokens"))
	if total == 0 {
		total = prompt + completion
	}
	return map[string]any{"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total}
}
