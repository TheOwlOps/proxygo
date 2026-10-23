package executors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PerplexityWebExecutor ports open-sse/executors/perplexity-web.js: the
// Perplexity web SSE endpoint (rest/sse/perplexity_ask). Auth is the web
// session: credentials.accessToken as Bearer, else credentials.apiKey as
// the __Secure-next-auth.session-token cookie value. The upstream answers
// its own block-based SSE (markdown_block chunks, plan_block thinking
// steps); this executor converts it to OpenAI chat chunks / a
// chat.completion JSON, so ResponseFormat is "openai".
//
// Session continuation: the JS keeps an in-process cache mapping a hash
// of the conversation history to the last backend_uuid, so a follow-up
// turn can be sent as a bare query with last_backend_uuid set. That cache
// is ported (pplxSessionCache, 1h TTL, 200 entries, FNV-1a key).
//
// Live-unverified: needs a real Perplexity Pro/Max session cookie.
type PerplexityWebExecutor struct{ *Base }

const pplxDefaultEndpoint = "https://www.perplexity.ai/rest/sse/perplexity_ask"
const pplxAPIVersion = "2.18"
const pplxUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var pplxModelMap = map[string][2]string{
	"pplx-auto":     {"concise", "pplx_pro"},
	"pplx-sonar":    {"copilot", "experimental"},
	"pplx-gpt":      {"copilot", "gpt54"},
	"pplx-gemini":   {"copilot", "gemini31pro_high"},
	"pplx-sonnet":   {"copilot", "claude46sonnet"},
	"pplx-opus":     {"copilot", "claude46opus"},
	"pplx-nemotron": {"copilot", "nv_nemotron_3_super"},
}

var pplxThinkingMap = map[string]string{
	"pplx-gpt":    "gpt54_thinking",
	"pplx-sonnet": "claude46sonnetthinking",
	"pplx-opus":   "claude46opusthinking",
}

var (
	pplxCitationRe   = regexp.MustCompile(`\[\d+\]`)
	pplxGrokTagRe    = regexp.MustCompile(`(?s)<grok:[^>]*>.*?</grok:[^>]*>`)
	pplxGrokSelfRe   = regexp.MustCompile(`<grok:[^>]*/>`)
	pplxXMLDeclRe    = regexp.MustCompile(`<[?]xml[^?]*[?]>`)
	pplxResponseTag  = regexp.MustCompile(`(?i)</?response\b[^>]*>`)
	pplxMultiSpaceRe = regexp.MustCompile(` {2,}`)
	pplxMultiNLRe    = regexp.MustCompile(`\n{3,}`)
)

const pplxSessionMaxAgeMs = 3600_000
const pplxSessionMaxEntries = 200

type pplxSessionEntry struct {
	backendUUID string
	ts          time.Time
}

var pplxSessionCache = struct {
	sync.Mutex
	m map[string]pplxSessionEntry
}{m: map[string]pplxSessionEntry{}}

type pplxHistoryMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// pplxSessionKey ports sessionKey: FNV-1a over "role:content" lines.
// (JS iterates UTF-16 code units; this iterates bytes — identical for
// ASCII, and the cache is process-local so only self-consistency matters.)
func pplxSessionKey(history []pplxHistoryMsg) string {
	parts := make([]string, len(history))
	for i, h := range history {
		parts[i] = h.Role + ":" + h.Content
	}
	joined := strings.Join(parts, "\n")
	hash := uint32(0x811c9dc5)
	for i := 0; i < len(joined); i++ {
		hash ^= uint32(joined[i])
		hash *= 0x01000193
	}
	return fmt.Sprintf("%08x", hash)
}

func pplxSessionLookup(history []pplxHistoryMsg) string {
	if len(history) == 0 {
		return ""
	}
	key := pplxSessionKey(history)
	pplxSessionCache.Lock()
	defer pplxSessionCache.Unlock()
	entry, ok := pplxSessionCache.m[key]
	if !ok {
		return ""
	}
	if time.Since(entry.ts).Milliseconds() > pplxSessionMaxAgeMs {
		delete(pplxSessionCache.m, key)
		return ""
	}
	return entry.backendUUID
}

func pplxSessionStore(history []pplxHistoryMsg, currentMsg, responseText, backendUUID string) {
	if backendUUID == "" {
		return
	}
	full := append(append([]pplxHistoryMsg{}, history...),
		pplxHistoryMsg{Role: "user", Content: currentMsg},
		pplxHistoryMsg{Role: "assistant", Content: responseText})
	key := pplxSessionKey(full)
	pplxSessionCache.Lock()
	defer pplxSessionCache.Unlock()
	pplxSessionCache.m[key] = pplxSessionEntry{backendUUID: backendUUID, ts: time.Now()}
	if len(pplxSessionCache.m) > pplxSessionMaxEntries {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, v := range pplxSessionCache.m {
			if first || v.ts.Before(oldest) {
				oldest, oldestKey, first = v.ts, k, false
			}
		}
		delete(pplxSessionCache.m, oldestKey)
	}
}

// pplxCleanResponse ports cleanResponse.
func pplxCleanResponse(text string, strip bool) string {
	t := pplxXMLDeclRe.ReplaceAllString(text, "")
	t = pplxCitationRe.ReplaceAllString(t, "")
	t = pplxGrokTagRe.ReplaceAllString(t, "")
	t = pplxGrokSelfRe.ReplaceAllString(t, "")
	t = pplxResponseTag.ReplaceAllString(t, "")
	if strip {
		t = pplxMultiSpaceRe.ReplaceAllString(t, " ")
		t = pplxMultiNLRe.ReplaceAllString(t, "\n\n")
		t = strings.TrimSpace(t)
	}
	return t
}

type pplxParsed struct {
	systemMsg  string
	history    []pplxHistoryMsg
	currentMsg string
}

// pplxParseMessages ports parseOpenAIMessages.
func pplxParseMessages(messages []any) pplxParsed {
	var out pplxParsed
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
		var content string
		switch c := msg["content"].(type) {
		case string:
			content = c
		case []any:
			var parts []string
			for _, part := range c {
				pm, _ := part.(map[string]any)
				if pm != nil && pm["type"] == "text" {
					parts = append(parts, getStr(pm, "text"))
				}
			}
			content = strings.Join(parts, " ")
		}
		if strings.TrimSpace(content) == "" {
			continue
		}
		if role == "system" {
			out.systemMsg += content + "\n"
		} else if role == "user" || role == "assistant" {
			out.history = append(out.history, pplxHistoryMsg{Role: role, Content: content})
		}
	}
	if n := len(out.history); n > 0 && out.history[n-1].Role == "user" {
		out.currentMsg = out.history[n-1].Content
		out.history = out.history[:n-1]
	}
	return out
}

// pplxFormatToolsHint ports formatToolsHint.
func pplxFormatToolsHint(tools []any) string {
	if len(tools) == 0 {
		return ""
	}
	lines := make([]string, 0, len(tools))
	for _, raw := range tools {
		t, _ := raw.(map[string]any)
		if t == nil {
			continue
		}
		fn, _ := t["function"].(map[string]any)
		if fn == nil {
			fn = t
		}
		name := getStr(fn, "name")
		if name == "" {
			name = "unnamed"
		}
		desc := getStr(fn, "description")
		if i := strings.Index(desc, "\n"); i >= 0 {
			desc = desc[:i]
		}
		if r := []rune(desc); len(r) > 200 {
			desc = string(r[:200])
		}
		lines = append(lines, "- "+name+": "+desc)
	}
	return "Available tools (reference only, cannot invoke):\n" + strings.Join(lines, "\n")
}

// pplxBuildQuery ports buildQuery. The JSON object is built in JS key
// order (instructions, history, query) for determinism.
func pplxBuildQuery(parsed pplxParsed, followUpUUID string, tools []any) string {
	if followUpUUID != "" {
		return parsed.currentMsg
	}
	var instr []string
	if strings.TrimSpace(parsed.systemMsg) != "" {
		instr = append(instr, strings.TrimSpace(parsed.systemMsg))
	}
	if hint := pplxFormatToolsHint(tools); hint != "" {
		instr = append(instr, hint)
	}
	instr = append(instr, "You have built-in web search. Answer questions directly using search results.")
	var sb strings.Builder
	sb.WriteString("{")
	instrJSON, _ := marshalJSON(instr)
	sb.WriteString(`"instructions":` + string(instrJSON))
	if len(parsed.history) > 0 {
		histJSON, _ := marshalJSON(parsed.history)
		sb.WriteString(`,"history":` + string(histJSON))
	}
	if parsed.currentMsg != "" {
		qJSON, _ := marshalJSON(parsed.currentMsg)
		sb.WriteString(`,"query":` + string(qJSON))
	} else if len(parsed.history) == 0 {
		sb.WriteString(`,"query":""`)
	}
	sb.WriteString("}")
	jsonStr := sb.String()
	if len(jsonStr) > 96000 {
		jsonStr = jsonStr[len(jsonStr)-96000:]
	}
	return jsonStr
}

// pplxBuildRequestBody ports buildPplxRequestBody.
func pplxBuildRequestBody(query, mode, modelPref, followUpUUID string) map[string]any {
	tz := time.Now().Location().String()
	if tz == "Local" {
		if env := os.Getenv("TZ"); env != "" {
			tz = env
		} else {
			tz = "UTC"
		}
	}
	var lastUUID any
	if followUpUUID != "" {
		lastUUID = followUpUUID
	}
	return map[string]any{
		"query_str": query,
		"params": map[string]any{
			"query_str":             query,
			"search_focus":          "internet",
			"mode":                  mode,
			"model_preference":      modelPref,
			"sources":               []any{"web"},
			"attachments":           []any{},
			"frontend_uuid":         newUUID(),
			"frontend_context_uuid": newUUID(),
			"version":               pplxAPIVersion,
			"language":              "en-US",
			"timezone":              tz,
			"search_recency_filter": nil,
			"is_incognito":          true,
			"use_schematized_api":   true,
			"last_backend_uuid":     lastUUID,
		},
	}
}

// pplxTruthy emulates JS truthiness for error_code values.
func pplxTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case jsonNumber:
		f, _ := t.Float64()
		return f != 0
	}
	return v != nil
}

func pplxErrorResponse(status int, body map[string]any) *http.Response {
	raw, _ := marshalJSON(body)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(raw))),
	}
}

func pplxErrBody(message, typ string, code any) map[string]any {
	errObj := map[string]any{"message": message, "type": typ}
	if code != nil {
		errObj["code"] = code
	}
	return map[string]any{"error": errObj}
}

// pplxChunk is one item yielded by extractContent in the JS.
type pplxChunk struct {
	delta       string
	answer      string
	thinking    string
	errMsg      string
	backendUUID string
	done        bool
	hasDelta    bool
	hasAnswer   bool
}

// pplxReadSSEEvents ports readPplxSseEvents: invokes fn per parsed JSON
// event; stops on [DONE], "event: end_of_stream", or EOF.
func pplxReadSSEEvents(r io.Reader, fn func(ev map[string]any) bool) {
	reader := bufio.NewReader(r)
	var dataLines []string
	flush := func() (map[string]any, bool, bool) {
		if len(dataLines) == 0 {
			return nil, false, false
		}
		payload := strings.Join(dataLines, "\n")
		dataLines = nil
		trimmed := strings.TrimSpace(payload)
		if trimmed == "" {
			return nil, false, false
		}
		if trimmed == "[DONE]" {
			return nil, true, false
		}
		var ev map[string]any
		if err := unmarshalJSON([]byte(trimmed), &ev); err != nil || ev == nil {
			return nil, false, false
		}
		return ev, false, true
	}
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
			switch {
			case line == "":
				ev, done, ok := flush()
				if done {
					return
				}
				if ok && !fn(ev) {
					return
				}
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimLeft(line[5:], " \t"))
			case line == "event: end_of_stream":
				return
			}
		}
		if err != nil {
			break
		}
	}
	if len(dataLines) > 0 {
		if ev, done, ok := flush(); ok && !done {
			fn(ev)
		}
	}
}

// pplxExtractContent ports extractContent: walks events, invoking fn per
// chunk; returns false from fn to stop early.
func pplxExtractContent(r io.Reader, fn func(pplxChunk) bool) {
	fullAnswer := ""
	backendUUID := ""
	seenLen := 0
	seenThinking := map[string]bool{}

	emit := func(c pplxChunk) bool {
		if backendUUID != "" {
			c.backendUUID = backendUUID
		}
		return fn(c)
	}

	pplxReadSSEEvents(r, func(event map[string]any) bool {
		if getStr(event, "error_message") != "" || pplxTruthy(event["error_code"]) {
			msg := getStr(event, "error_message")
			if msg == "" {
				msg = fmt.Sprintf("Perplexity error: %v", event["error_code"])
			}
			return emit(pplxChunk{errMsg: msg, done: true})
		}
		if u := getStr(event, "backend_uuid"); u != "" {
			backendUUID = u
		}
		blocks, _ := event["blocks"].([]any)
		for _, braw := range blocks {
			block, _ := braw.(map[string]any)
			if block == nil {
				continue
			}
			usage := getStr(block, "intended_usage")

			if usage == "pro_search_steps" {
				if pb, _ := block["plan_block"].(map[string]any); pb != nil {
					steps, _ := pb["steps"].([]any)
					for _, sraw := range steps {
						step, _ := sraw.(map[string]any)
						if step == nil {
							continue
						}
						switch getStr(step, "step_type") {
						case "SEARCH_WEB":
							if swc, _ := step["search_web_content"].(map[string]any); swc != nil {
								queries, _ := swc["queries"].([]any)
								for _, qraw := range queries {
									q, _ := qraw.(map[string]any)
									qr := getStr(q, "query")
									if qr != "" && !seenThinking[qr] {
										seenThinking[qr] = true
										if !emit(pplxChunk{thinking: "Searching: " + qr}) {
											return false
										}
									}
								}
							}
						case "READ_RESULTS":
							if rrc, _ := step["read_results_content"].(map[string]any); rrc != nil {
								urls, _ := rrc["urls"].([]any)
								if len(urls) > 3 {
									urls = urls[:3]
								}
								for _, uraw := range urls {
									u, _ := uraw.(string)
									if u != "" && !seenThinking[u] {
										seenThinking[u] = true
										if !emit(pplxChunk{thinking: "Reading: " + u}) {
											return false
										}
									}
								}
							}
						}
					}
				}
			}
			if usage == "plan" {
				if pb, _ := block["plan_block"].(map[string]any); pb != nil {
					goals, _ := pb["goals"].([]any)
					for _, graw := range goals {
						goal, _ := graw.(map[string]any)
						desc := getStr(goal, "description")
						if desc != "" && !seenThinking[desc] {
							seenThinking[desc] = true
							if !emit(pplxChunk{thinking: desc}) {
								return false
							}
						}
					}
				}
			}

			if !strings.Contains(usage, "markdown") {
				continue
			}
			mb, _ := block["markdown_block"].(map[string]any)
			if mb == nil {
				continue
			}
			chunksRaw, _ := mb["chunks"].([]any)
			if len(chunksRaw) == 0 {
				continue
			}
			var chunkParts []string
			for _, craw := range chunksRaw {
				if s, ok := craw.(string); ok {
					chunkParts = append(chunkParts, s)
				}
			}
			chunkText := strings.Join(chunkParts, "")
			if getStr(mb, "progress") == "DONE" {
				fullAnswer = chunkText
			} else {
				cumulative := fullAnswer + chunkText
				if len(cumulative) > seenLen {
					delta := cumulative[seenLen:]
					fullAnswer = cumulative
					seenLen = len(cumulative)
					if !emit(pplxChunk{delta: delta, answer: fullAnswer, hasDelta: true, hasAnswer: true}) {
						return false
					}
				}
			}
		}

		if len(blocks) == 0 {
			if t, ok := event["text"].(string); ok {
				t = strings.TrimSpace(t)
				if len(t) > seenLen {
					delta := t[seenLen:]
					fullAnswer = t
					seenLen = len(t)
					if !emit(pplxChunk{delta: delta, answer: fullAnswer, hasDelta: true, hasAnswer: true}) {
						return false
					}
				}
			}
		}
		if event["final"] == true || getStr(event, "status") == "COMPLETED" {
			return false
		}
		return true
	})
	emit(pplxChunk{answer: fullAnswer, hasAnswer: true, done: true})
}

func pplxSSEChunkJSON(cid string, created int64, model string, delta map[string]any, finish any) string {
	chunk := map[string]any{
		"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
		"system_fingerprint": nil,
		"choices":            []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish, "logprobs": nil}},
	}
	raw, _ := marshalJSON(chunk)
	return "data: " + string(raw) + "\n\n"
}

func NewPerplexityWebExecutor() *PerplexityWebExecutor {
	e := &PerplexityWebExecutor{}
	e.Base = &Base{ProviderID: "perplexity-web"}
	return e
}

func (e *PerplexityWebExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "perplexity-web"}
	}
	endpoint := p.BaseURL
	if endpoint == "" {
		endpoint = pplxDefaultEndpoint
	}
	bodyMap, _ := decodeBody(body)
	stream := StreamRequested(bodyMap)
	// The JS receives `stream` as a separate arg; when the body carries no
	// explicit flag, chatCore's value is what matters — StreamRequested
	// (false) mirrors a non-streaming client call.

	rawMessages, _ := bodyMap["messages"].([]any)
	if len(rawMessages) == 0 {
		resp := pplxErrorResponse(400, pplxErrBody("Missing or empty messages array", "invalid_request", nil))
		return &ExecResult{Response: resp, URL: endpoint, Headers: map[string]string{}, TransformedBody: body, ResponseFormat: "openai"}, nil
	}

	thinking := false
	if v, ok := bodyMap["thinking"].(bool); ok && v {
		thinking = true
	}
	if v, present := bodyMap["reasoning_effort"]; present && v != nil && v != "none" {
		thinking = true
	}
	model := ModelOf(bodyMap)
	var mode, modelPref string
	if thinking {
		if pref, ok := pplxThinkingMap[model]; ok {
			mode, modelPref = "copilot", pref
		}
	}
	if modelPref == "" {
		if pair, ok := pplxModelMap[model]; ok {
			mode, modelPref = pair[0], pair[1]
		} else {
			mode, modelPref = "copilot", model
		}
	}

	parsed := pplxParseMessages(rawMessages)
	followUpUUID := pplxSessionLookup(parsed.history)
	tools, _ := bodyMap["tools"].([]any)
	query := pplxBuildQuery(parsed, followUpUUID, tools)
	if strings.TrimSpace(query) == "" {
		resp := pplxErrorResponse(400, pplxErrBody("Empty query after processing", "invalid_request", nil))
		return &ExecResult{Response: resp, URL: endpoint, Headers: map[string]string{}, TransformedBody: body, ResponseFormat: "openai"}, nil
	}

	pplxBody := pplxBuildRequestBody(query, mode, modelPref, followUpUUID)
	payload, err := marshalJSON(pplxBody)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "text/event-stream",
		"Origin":           "https://www.perplexity.ai",
		"Referer":          "https://www.perplexity.ai/",
		"User-Agent":       pplxUserAgent,
		"X-App-ApiClient":  "default",
		"X-App-ApiVersion": pplxAPIVersion,
	}
	if cred.AccessToken != "" {
		headers["Authorization"] = "Bearer " + cred.AccessToken
	} else if cred.APIKey != "" {
		headers["Cookie"] = "__Secure-next-auth.session-token=" + cred.APIKey
	}
	for k, v := range cred.OverrideHeaders {
		headers[k] = v
	}

	resp, err := doPost(ctx, endpoint, headers, payload, connectTimeout(p))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errResp := pplxErrorResponse(502, pplxErrBody("Perplexity connection failed: "+err.Error(), "upstream_error", nil))
		return &ExecResult{Response: errResp, URL: endpoint, Headers: headers, TransformedBody: payload, ResponseFormat: "openai"}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.StatusCode
		drainClose(resp)
		errMsg := fmt.Sprintf("Perplexity returned HTTP %d", status)
		if status == 401 || status == 403 {
			errMsg = "Perplexity auth failed — session cookie may be expired. Re-paste your __Secure-next-auth.session-token."
		} else if status == 429 {
			errMsg = "Perplexity rate limited. Wait a moment and retry."
		}
		errResp := pplxErrorResponse(status, pplxErrBody(errMsg, "upstream_error", fmt.Sprintf("HTTP_%d", status)))
		return &ExecResult{Response: errResp, URL: endpoint, Headers: headers, TransformedBody: payload, ResponseFormat: "openai"}, nil
	}
	if resp.Body == nil {
		errResp := pplxErrorResponse(502, pplxErrBody("Perplexity returned empty response body", "upstream_error", nil))
		return &ExecResult{Response: errResp, URL: endpoint, Headers: headers, TransformedBody: payload, ResponseFormat: "openai"}, nil
	}

	cid := "chatcmpl-pplx-" + newUUID()[:12]
	created := nowUnix()
	result := &ExecResult{URL: endpoint, Headers: headers, TransformedBody: payload, ResponseFormat: "openai"}

	if stream {
		pr, pw := io.Pipe()
		go func() {
			defer resp.Body.Close()
			_, _ = io.WriteString(pw, pplxSSEChunkJSON(cid, created, model, map[string]any{"role": "assistant"}, nil))
			fullAnswer := ""
			respBackendUUID := ""
			pplxExtractContent(resp.Body, func(chunk pplxChunk) bool {
				if chunk.backendUUID != "" {
					respBackendUUID = chunk.backendUUID
				}
				if chunk.errMsg != "" {
					_, _ = io.WriteString(pw, pplxSSEChunkJSON(cid, created, model, map[string]any{"content": "[Error: " + chunk.errMsg + "]"}, nil))
					return false
				}
				if chunk.thinking != "" {
					_, _ = io.WriteString(pw, pplxSSEChunkJSON(cid, created, model, map[string]any{"reasoning_content": chunk.thinking + "\n"}, nil))
					return true
				}
				if chunk.done {
					if chunk.hasAnswer {
						fullAnswer = chunk.answer
					}
					return false
				}
				if chunk.hasDelta && chunk.delta != "" {
					if dt := pplxCleanResponse(chunk.delta, false); dt != "" {
						_, _ = io.WriteString(pw, pplxSSEChunkJSON(cid, created, model, map[string]any{"content": dt}, nil))
					}
				}
				if chunk.hasAnswer {
					fullAnswer = chunk.answer
				}
				return true
			})
			_, _ = io.WriteString(pw, pplxSSEChunkJSON(cid, created, model, map[string]any{}, "stop"))
			_, _ = io.WriteString(pw, "data: [DONE]\n\n")
			pplxSessionStore(parsed.history, parsed.currentMsg, pplxCleanResponse(fullAnswer, true), respBackendUUID)
			_ = pw.Close()
		}()
		result.Response = &http.Response{
			StatusCode: 200, Status: "200 OK",
			Header: http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}, "X-Accel-Buffering": []string{"no"}},
			Body:   pr,
		}
		return result, nil
	}

	// Non-streaming: buildNonStreamingResponse.
	fullAnswer := ""
	respBackendUUID := ""
	var thinkingParts []string
	var pplxErr string
	pplxExtractContent(resp.Body, func(chunk pplxChunk) bool {
		if chunk.backendUUID != "" {
			respBackendUUID = chunk.backendUUID
		}
		if chunk.errMsg != "" {
			pplxErr = chunk.errMsg
			return false
		}
		if chunk.thinking != "" {
			thinkingParts = append(thinkingParts, chunk.thinking)
			return true
		}
		if chunk.done {
			if chunk.hasAnswer {
				fullAnswer = chunk.answer
			}
			return false
		}
		if chunk.hasAnswer {
			fullAnswer = chunk.answer
		}
		return true
	})
	resp.Body.Close()
	if pplxErr != "" {
		result.Response = pplxErrorResponse(502, pplxErrBody(pplxErr, "upstream_error", "PPLX_ERROR"))
		return result, nil
	}
	fullAnswer = pplxCleanResponse(fullAnswer, true)
	pplxSessionStore(parsed.history, parsed.currentMsg, fullAnswer, respBackendUUID)
	msg := map[string]any{"role": "assistant", "content": fullAnswer}
	if len(thinkingParts) > 0 {
		msg["reasoning_content"] = strings.Join(thinkingParts, "\n")
	}
	promptTokens := (len(parsed.currentMsg) + 3) / 4
	completionTokens := (len(fullAnswer) + 3) / 4
	out, _ := marshalJSON(map[string]any{
		"id": cid, "object": "chat.completion", "created": created, "model": model, "system_fingerprint": nil,
		"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": "stop", "logprobs": nil}},
		"usage":   map[string]any{"prompt_tokens": promptTokens, "completion_tokens": completionTokens, "total_tokens": promptTokens + completionTokens},
	})
	result.Response = &http.Response{
		StatusCode: 200, Status: "200 OK",
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(string(out))),
	}
	return result, nil
}
