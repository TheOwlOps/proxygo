package executors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TraeExecutor ports open-sse/executors/trae.js: the Trae SOLO remote
// agent API.
//  1. POST {base}/chat_sessions → {code:0, data:{chat_session_id, message_id}}
//  2. GET  {base}/chat_sessions/{id}/events?reply_to_message_id={message_id}
//     → SSE. Assistant text streams in `plan_item` events under the
//     `thought` field (cumulative per plan-item id, longest wins);
//     `token_usage` carries usage; `done` ends the turn; `error` is an
//     upstream error.
//
// Auth: `Authorization: Cloud-IDE-JWT <jwt>` where the JWT is
// credentials.accessToken. Identity fields for common_params come from
// providerSpecificData (Credential.Specific): appLanguage, userRegion,
// appVersion, webId, userIdentity, bizUserId, userUniqueId, scope,
// tenant, region, aiRegion. Refresh returns nil (JS: the Cloud-IDE-JWT
// refresh via ExchangeToken lives in the token-refresh service).
//
// Live-unverified: needs a real Trae Cloud-IDE-JWT (~14-day lifetime).
type TraeExecutor struct{ *Base }

const traeDefaultBaseURL = "https://core-normal.trae.ai/api/remote/v1"
const traeUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

func traeStreamTimeout() time.Duration {
	if v := os.Getenv("TRAE_STREAM_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 300000 * time.Millisecond
}

func traeBase(p *ProviderInfo) string {
	base := ""
	if p != nil {
		base = p.BaseURL
	}
	if base == "" {
		base = traeDefaultBaseURL
	}
	return strings.TrimSuffix(base, "/")
}

// traeFlattenQuery ports flattenQuery: the whole conversation is flattened
// into one JSON-encoded string of typed content blocks.
func traeFlattenQuery(messages []any) string {
	var parts []string
	for _, raw := range messages {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		var content string
		switch c := m["content"].(type) {
		case string:
			content = c
		case []any:
			var sb strings.Builder
			for _, praw := range c {
				switch p := praw.(type) {
				case string:
					sb.WriteString(p)
				case map[string]any:
					if t, ok := p["text"].(string); ok {
						sb.WriteString(t)
					}
				}
			}
			content = sb.String()
		}
		switch getStr(m, "role") {
		case "system":
			parts = append(parts, "[System]\n"+content)
		case "assistant":
			parts = append(parts, "[Assistant]\n"+content)
		default:
			parts = append(parts, content)
		}
	}
	raw, _ := marshalJSON([]any{map[string]any{"type": "text", "data": map[string]any{"content": strings.Join(parts, "\n\n")}}})
	return string(raw)
}

type traeModeInfo struct {
	mode      string
	strategy  string
	modelName string
}

// traeResolveMode ports resolveMode.
func traeResolveMode(model string) traeModeInfo {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "work" || m == "auto-work" || m == "solo-work" {
		return traeModeInfo{mode: "work", strategy: "auto", modelName: ""}
	}
	auto := m == "" || m == "auto"
	modelName := ""
	if !auto {
		modelName = model
	}
	strategy := "manual"
	if auto {
		strategy = "auto"
	}
	return traeModeInfo{mode: "code", strategy: strategy, modelName: modelName}
}

func traePStr(cred Credential, key, fallback string) string {
	if v := cred.SpecificString(key); v != "" {
		return v
	}
	return fallback
}

// traeCommonParams ports commonParams: a JSON-encoded string embedded in
// initial_message. Built in JS key order.
func traeCommonParams(cred Credential, mode, sessionID string) string {
	region := traePStr(cred, "region", "US-East")
	aiRegion := cred.SpecificString("aiRegion")
	if aiRegion == "" {
		aiRegion = region
	}
	fields := []struct {
		k string
		v any
	}{
		{"language", "en-us"},
		{"app_language", traePStr(cred, "appLanguage", "en")},
		{"quality", "stable"},
		{"app_version", traePStr(cred, "appVersion", "1.0.0.1229")},
		{"web_id", cred.SpecificString("webId")},
		{"user_identity", traePStr(cred, "userIdentity", "Free")},
		{"is_freshman", "0"},
		{"biz_user_id", cred.SpecificString("bizUserId")},
		{"user_unique_id", cred.SpecificString("userUniqueId")},
		{"scope", traePStr(cred, "scope", "marscode-us")},
		{"tenant", traePStr(cred, "tenant", "marscode")},
		{"region", region},
		{"aiRegion", aiRegion},
		{"is_privacy_mode", 0},
		{"privacy_mode", "off"},
		{"solo_chat_mode", mode},
	}
	if sessionID != "" {
		fields = append(fields, struct {
			k string
			v any
		}{"biz_session_id", sessionID})
	}
	var sb strings.Builder
	sb.WriteString("{")
	for i, f := range fields {
		if i > 0 {
			sb.WriteString(",")
		}
		raw, _ := marshalJSON(f.v)
		sb.WriteString(strconv.Quote(f.k) + ":" + string(raw))
	}
	sb.WriteString("}")
	return sb.String()
}

func traeBuildHeaders(cred Credential, stream bool) map[string]string {
	accept := "application/json"
	if stream {
		accept = "text/event-stream"
	}
	return map[string]string{
		"Authorization":          "Cloud-IDE-JWT " + cred.AccessToken,
		"Content-Type":           "application/json",
		"X-Trae-Client-Type":     "web",
		"X-Preferenced-Language": traePStr(cred, "appLanguage", "en"),
		"x-user-region":          traePStr(cred, "userRegion", "US"),
		"Referer":                "https://solo.trae.ai/",
		"User-Agent":             traeUserAgent,
		"Accept":                 accept,
	}
}

func traeFlexString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case jsonNumber:
		return t.String()
	case float64:
		return strconv.FormatInt(int64(t), 10)
	}
	return ""
}

type traeSession struct {
	sessionID string
	messageID string
}

// traeCreateSession ports createSession.
func traeCreateSession(ctx context.Context, p *ProviderInfo, headers map[string]string, query, model string, cred Credential) (*traeSession, error) {
	mi := traeResolveMode(model)
	body := map[string]any{
		"mode":           mi.mode,
		"environment_id": "default",
		"initial_message": map[string]any{
			"chat_session_id":          "",
			"content":                  []any{},
			"query":                    query,
			"model_name":               mi.modelName,
			"agent_type":               "solo_agent_remote",
			"model_selection_strategy": mi.strategy,
			"common_params":            traeCommonParams(cred, mi.mode, ""),
		},
		"env":                 "remote",
		"auto_create_project": false,
		"origin":              "web",
	}
	payload, err := marshalJSON(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, traeBase(p)+"/chat_sessions", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("[%d] %s", resp.StatusCode, string(text))
	}
	var parsed map[string]any
	if err := unmarshalJSON(text, &parsed); err != nil {
		return nil, err
	}
	if code := getFloat(parsed, "code"); code != 0 {
		raw, _ := marshalJSON(parsed)
		return nil, fmt.Errorf("Trae create_session: %s", string(raw))
	}
	data, _ := parsed["data"].(map[string]any)
	return &traeSession{sessionID: traeFlexString(data["chat_session_id"]), messageID: traeFlexString(data["message_id"])}, nil
}

// traeTurnState is the shared per-turn state from execute(): plan_item
// thoughts are cumulative per id (longest wins); render emits only the
// newly-grown suffix of the concatenated text.
type traeTurnState struct {
	order    []string
	thoughts map[string]string
	sent     int
	usage    map[string]any
	errEvent map[string]any
}

func newTraeTurnState() *traeTurnState {
	return &traeTurnState{thoughts: map[string]string{}}
}

func (s *traeTurnState) renderNewText(data map[string]any) string {
	pid := traeFlexString(data["id"])
	if pid == "" {
		return ""
	}
	if _, ok := s.thoughts[pid]; !ok {
		s.order = append(s.order, pid)
	}
	t := getStr(data, "thought")
	if len(t) >= len(s.thoughts[pid]) {
		s.thoughts[pid] = t
	}
	var sb strings.Builder
	for _, id := range s.order {
		sb.WriteString(s.thoughts[id])
	}
	full := sb.String()
	piece := ""
	if len(full) >= s.sent {
		piece = full[s.sent:]
	}
	s.sent = len(full)
	return piece
}

func (s *traeTurnState) content() string {
	var sb strings.Builder
	for _, id := range s.order {
		sb.WriteString(s.thoughts[id])
	}
	return sb.String()
}

// traeOnEvent applies one event to the state; onPiece is called with new
// text for plan_items (streaming path). Returns true when the turn ends.
func (s *traeTurnState) traeOnEvent(ev string, data map[string]any, onPiece func(string)) bool {
	switch ev {
	case "error":
		s.errEvent = data
		return true
	case "token_usage":
		s.usage = data
	case "plan_item":
		piece := s.renderNewText(data)
		if piece != "" && onPiece != nil {
			onPiece(piece)
		}
	}
	return ev == "done"
}

// traeStreamEvents ports streamEvents: GET the events SSE, invoking
// onEvent per frame until it returns true, the stream ends, or the
// 300s (TRAE_STREAM_TIMEOUT_MS) timeout fires.
func traeStreamEvents(ctx context.Context, p *ProviderInfo, headers map[string]string, sessionID, replyTo string, onEvent func(ev string, data map[string]any) bool) error {
	urlStr := traeBase(p) + "/chat_sessions/" + sessionID + "/events?reply_to_message_id=" + url.QueryEscape(replyTo)
	tctx, cancel := context.WithTimeout(ctx, traeStreamTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		if tctx.Err() != nil && ctx.Err() == nil {
			return fmt.Errorf("trae stream timeout")
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Body == nil {
		return fmt.Errorf("[%d] events stream failed", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	ev := ""
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
			switch {
			case strings.HasPrefix(line, "event:"):
				ev = strings.TrimSpace(line[len("event:"):])
			case strings.HasPrefix(line, "data:"):
				payload := strings.TrimSpace(line[len("data:"):])
				var data map[string]any
				if uerr := unmarshalJSON([]byte(payload), &data); uerr != nil || data == nil {
					data = map[string]any{"_raw": payload}
				}
				if onEvent(ev, data) {
					return nil
				}
			case line == "":
				ev = ""
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if tctx.Err() != nil && ctx.Err() == nil {
				return fmt.Errorf("trae stream timeout")
			}
			return err
		}
	}
}

func traeErrorResponse(status int, message string) *http.Response {
	raw, _ := marshalJSON(map[string]any{"error": map[string]any{"message": message, "type": "api_error", "code": ""}})
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status),
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(string(raw))),
	}
}

func traeUsageMap(usage map[string]any) map[string]any {
	return map[string]any{
		"prompt_tokens":     int(getFloat(usage, "prompt_tokens")),
		"completion_tokens": int(getFloat(usage, "completion_tokens")),
		"total_tokens":      int(getFloat(usage, "total_tokens")),
	}
}

func NewTraeExecutor() *TraeExecutor {
	e := &TraeExecutor{}
	e.Base = &Base{ProviderID: "trae"}
	return e
}

func (e *TraeExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "trae"}
	}
	bodyMap, _ := decodeBody(body)
	// JS: stream is a separate execute() arg and defaults to streaming
	// (`stream !== false`); the body flag is the Go-side carrier for it.
	stream := true
	if v, ok := bodyMap["stream"].(bool); ok {
		stream = v
	}
	model := ModelOf(bodyMap)
	headers := traeBuildHeaders(cred, stream)
	for k, v := range cred.OverrideHeaders {
		headers[k] = v
	}
	rawMessages, _ := bodyMap["messages"].([]any)
	query := traeFlattenQuery(rawMessages)
	responseID := fmt.Sprintf("chatcmpl-trae-%d", time.Now().UnixMilli())
	created := nowUnix()
	base := traeBase(p)

	session, err := traeCreateSession(ctx, p, headers, query, model, cred)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &ExecResult{Response: traeErrorResponse(502, err.Error()), URL: base, Headers: headers, TransformedBody: body, ResponseFormat: "openai"}, nil
	}

	state := newTraeTurnState()

	if stream {
		pr, pw := io.Pipe()
		go func() {
			emit := func(obj map[string]any) {
				raw, _ := marshalJSON(obj)
				_, _ = io.WriteString(pw, "data: "+string(raw)+"\n\n")
			}
			chunk := func(choices []any, extra map[string]any) map[string]any {
				obj := map[string]any{"id": responseID, "object": "chat.completion.chunk", "created": created, "model": model, "choices": choices}
				for k, v := range extra {
					obj[k] = v
				}
				return obj
			}
			emit(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}}, nil))
			err := traeStreamEvents(ctx, p, headers, session.sessionID, session.messageID, func(ev string, data map[string]any) bool {
				return state.traeOnEvent(ev, data, func(piece string) {
					emit(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}, "finish_reason": nil}}, nil))
				})
			})
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			if state.errEvent != nil {
				msg := fmt.Sprintf("trae %v: %v", traeFlexString(state.errEvent["code"]), getStr(state.errEvent, "message"))
				// JS error chunk carries code as-is (may be numeric); the
				// rendered message matches `trae ${code}: ${message}`.
				if c, ok := state.errEvent["code"]; ok {
					msg = fmt.Sprintf("trae %v: %s", c, getStr(state.errEvent, "message"))
				}
				emit(chunk([]any{}, map[string]any{"error": map[string]any{"message": msg, "type": "api_error"}}))
			} else {
				emit(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}, nil))
				if state.usage != nil {
					emit(chunk([]any{}, map[string]any{"usage": traeUsageMap(state.usage)}))
				}
			}
			_, _ = io.WriteString(pw, "data: [DONE]\n\n")
			_ = pw.Close()
		}()
		return &ExecResult{
			Response: &http.Response{
				StatusCode: 200, Status: "200 OK",
				Header: http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}, "Connection": []string{"keep-alive"}},
				Body:   pr,
			},
			URL: base, Headers: headers, TransformedBody: body, ResponseFormat: "openai",
		}, nil
	}

	// Non-streaming: drive to completion, return chat.completion JSON.
	if err := traeStreamEvents(ctx, p, headers, session.sessionID, session.messageID, func(ev string, data map[string]any) bool {
		return state.traeOnEvent(ev, data, nil)
	}); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &ExecResult{Response: traeErrorResponse(502, err.Error()), URL: base, Headers: headers, TransformedBody: body, ResponseFormat: "openai"}, nil
	}
	if state.errEvent != nil {
		msg := fmt.Sprintf("trae %v: %s", state.errEvent["code"], getStr(state.errEvent, "message"))
		return &ExecResult{Response: traeErrorResponse(502, msg), URL: base, Headers: headers, TransformedBody: body, ResponseFormat: "openai"}, nil
	}
	out := map[string]any{
		"id": responseID, "object": "chat.completion", "created": created, "model": model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": state.content()}, "finish_reason": "stop"}},
	}
	if state.usage != nil {
		out["usage"] = traeUsageMap(state.usage)
	}
	raw, _ := marshalJSON(out)
	return &ExecResult{
		Response: &http.Response{
			StatusCode: 200, Status: "200 OK",
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(string(raw))),
		},
		URL: base, Headers: headers, TransformedBody: body, ResponseFormat: "openai",
	}, nil
}
