package executors

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CodexExecutor ports open-sse/executors/codex.js: OpenAI Codex backend
// (Responses API). Ported: request normalisation (string→array input,
// system→developer, stored-item-id stripping, forced streaming, default
// instructions), identity headers (session_id, originator,
// ChatGPT-Account-ID), /compact URL suffix, usage_limit_reached error
// parsing, and the SSE peek retry for transient overloaded events.
//
// TODO (report): remote-image prefetching (prefetchImages — Codex backend
// cannot fetch remote images; needs an image fetch helper), the
// responses-lite model table + hosted web_search tool reshaping
// (providerModels data owned by Team B), and resolveCacheSessionId's
// assistant-text/workspace/machine-id session derivation (only the
// explicit session_id/conversation_id + connection sources are ported).
type CodexExecutor struct{ *Base }

const codexDefaultInstructionsFallback = "You are Codex, a coding agent based on GPT-5. You and the user share the same workspace and collaborate to achieve the user's goals."

var (
	codexSSERetryPatterns          = []string{"server_is_overloaded", "service_unavailable_error"}
	codexSSEAccountFallbackPattern = []string{"selected model is at capacity", "model_at_capacity"}
	codexSSEUserOutputPatterns     = []string{
		"event: response.output_text.delta",
		"event: response.function_call_arguments.delta",
		`"type":"response.output_text.delta"`,
		`"type":"response.function_call_arguments.delta"`,
	}
	codexServerIDRe = regexp.MustCompile(`^(rs|fc|resp|msg)_`)
)

const codexSSEPeekBytes = 256 * 1024
const codexModelCapacityMessage = "Selected model is at capacity. Please try a different model."

func NewCodexExecutor() *CodexExecutor {
	c := &CodexExecutor{}
	c.Base = &Base{ProviderID: "codex", Hooks: Hooks{
		BuildURL:      c.buildURL,
		BuildHeaders:  c.buildHeaders,
		TransformBody: c.transformBody,
		ParseError:    c.parseError,
		Refresh:       refreshFromGrantOrSpecial,
	}}
	return c
}

func (c *CodexExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	urls := req.Provider.BaseURLsList()
	u := req.Provider.BaseURL
	if urlIndex < len(urls) {
		u = urls[urlIndex]
	}
	if compact, _ := req.State["compact"].(bool); compact {
		u += "/compact"
	}
	return u, nil
}

func (c *CodexExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	headers := baseBuildHeaders(b.ProviderID, req)
	if sid, _ := req.State["sessionId"].(string); sid != "" {
		headers["session_id"] = sid
	} else if req.Cred.ConnectionID != "" {
		headers["session_id"] = req.Cred.ConnectionID
	} else {
		headers["session_id"] = "default"
	}
	if headers["originator"] == "" {
		headers["originator"] = "codex_cli_rs"
	}
	accountID := req.Cred.SpecificString("workspaceId")
	if accountID == "" {
		accountID = req.Cred.SpecificString("chatgptAccountId")
	}
	if accountID == "" {
		accountID = req.Cred.SpecificString("accountId")
	}
	if accountID != "" && headers["ChatGPT-Account-ID"] == "" {
		headers["ChatGPT-Account-ID"] = accountID
	}
	return headers, nil
}

// transformBody ports CodexExecutor.transformRequest (subset listed in the
// type comment).
func (c *CodexExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	if v, ok := body["_compact"].(bool); ok && v {
		req.State["compact"] = true
	}
	delete(body, "_compact")
	delete(body, "_autoCodexWebSearch") // hosted-search reshaping: TODO

	// Session id: explicit body fields win (see type comment for the rest).
	if sid := getStr(body, "session_id"); sid != "" {
		req.State["sessionId"] = sid
	} else if sid := getStr(body, "conversation_id"); sid != "" {
		req.State["sessionId"] = sid
	}

	// Normalise input: string → one message item; missing/empty → the
	// placeholder message (Codex API rejects empty input).
	switch input := body["input"].(type) {
	case string:
		body["input"] = []any{map[string]any{
			"type": "message", "role": "user",
			"content": []any{map[string]any{"type": "input_text", "text": input}},
		}}
	case []any:
		if len(input) == 0 {
			body["input"] = []any{codexPlaceholderInput()}
		}
	default:
		if body["input"] == nil {
			body["input"] = []any{codexPlaceholderInput()}
		}
	}
	if items, ok := body["input"].([]any); ok {
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			// System prompts stay in input as role=developer so they remain
			// in the cacheable prefix (convertSystemToDeveloperRole).
			if item["role"] == "system" {
				item["role"] = "developer"
			}
			// Strip server-generated item IDs — Codex /responses cannot
			// resolve them when store=false.
			if id, ok := item["id"].(string); ok && codexServerIDRe.MatchString(id) {
				delete(item, "id")
			}
		}
	}

	// Codex API requires streaming.
	body["stream"] = true

	// Default instructions when the client provided none. The full text
	// lives in config/codexInstructions.js; the registry adapter may carry
	// it as Raw["defaultInstructions"].
	if instr, _ := body["instructions"].(string); strings.TrimSpace(instr) == "" {
		if di := req.Provider.RawString("defaultInstructions"); di != "" {
			body["instructions"] = di
		} else {
			body["instructions"] = codexDefaultInstructionsFallback
		}
	}
	return body, nil
}

func codexPlaceholderInput() map[string]any {
	return map[string]any{
		"type": "message", "role": "user",
		"content": []any{map[string]any{"type": "input_text", "text": "..."}},
	}
}

// parseError ports CodexExecutor.parseError: usage_limit_reached 429s carry
// a precise resetsAt (resets_at epoch or resets_in_seconds).
func (c *CodexExecutor) parseError(status int, bodyText string) *ParsedError {
	if status == 429 && bodyText != "" {
		var parsed map[string]any
		if unmarshalJSON([]byte(bodyText), &parsed) == nil {
			errObj, _ := parsed["error"].(map[string]any)
			if errObj != nil && errObj["type"] == "usage_limit_reached" {
				now := time.Now()
				var resets time.Time
				if secs := getFloat(errObj, "resets_at"); secs > 0 {
					if t := time.Unix(int64(secs), 0); t.After(now) {
						resets = t
					}
				}
				if resets.IsZero() {
					if secs := getFloat(errObj, "resets_in_seconds"); secs > 0 {
						resets = now.Add(time.Duration(secs) * time.Second)
					}
				}
				if !resets.IsZero() {
					msg := getStr(errObj, "message")
					if msg == "" {
						msg = bodyText
					}
					return &ParsedError{Status: 429, Message: msg, ResetsAt: resets}
				}
			}
		}
	}
	return nil // fall back to base parseError
}

// Execute adds the SSE peek retry loop over Base.Execute (codex.js
// execute): a 200 whose first SSE events are transient-overload errors is
// retried with the 503 retry config; a model-at-capacity event becomes a
// synthetic 503 so chatcore falls back to the next account.
func (c *CodexExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	cfg := retryConfigFor(p)
	entry := resolveRetryEntryPtr(cfg, 503)
	attempt := 0
	for {
		result, err := c.Base.Execute(ctx, p, cred, body)
		if err != nil || result == nil || result.Response == nil {
			return result, err
		}
		matched, accountFallback, message, err := c.peekSSETransient(result.Response)
		if err != nil || matched == "" {
			return result, err
		}
		if accountFallback {
			result.Response = codexSSEErrorResponse(503, firstNonEmpty(message, codexModelCapacityMessage))
			return result, nil
		}
		if attempt >= entry.Attempts {
			result.Response = codexSSEErrorResponse(503, firstNonEmpty(message, matched))
			return result, nil
		}
		attempt++
		if serr := SleepFunc(ctx, time.Duration(entry.DelayMs)*time.Millisecond); serr != nil {
			return nil, serr
		}
	}
}

// peekSSETransient reads the head of an SSE body looking for transient
// error events before any user output. When nothing matches, the read
// prefix is replayed into the response body so no bytes are lost
// (codex.js _peekSseTransientError).
func (c *CodexExecutor) peekSSETransient(resp *http.Response) (matched string, accountFallback bool, message string, err error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Body == nil {
		return "", false, "", nil
	}
	br := bufio.NewReaderSize(resp.Body, 32*1024)
	var buf bytes.Buffer
	lower := ""
	for buf.Len() < codexSSEPeekBytes {
		b, rerr := br.ReadByte()
		if rerr != nil {
			break
		}
		buf.WriteByte(b)
		lower = strings.ToLower(buf.String())
		if hit := findSubstring(lower, codexSSEAccountFallbackPattern); hit != "" {
			resp.Body.Close()
			return hit, true, extractSSEErrorMessage(buf.String(), hit), nil
		}
		if hit := findSubstring(lower, codexSSERetryPatterns); hit != "" {
			resp.Body.Close()
			return hit, false, extractSSEErrorMessage(buf.String(), hit), nil
		}
		if findSubstring(lower, codexSSEUserOutputPatterns) != "" {
			break
		}
	}
	// Replay: buffered prefix + the rest of the stream.
	resp.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf.Bytes()), br), closer: resp.Body}
	return "", false, "", nil
}

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (r *replayBody) Close() error { return r.closer.Close() }

func findSubstring(haystack string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return n
		}
	}
	return ""
}

// extractSSEErrorMessage pulls `error.message`/"message" out of the first
// JSON payload in the peeked SSE text (approximation of codex.js
// extractSseErrorMessage).
func extractSSEErrorMessage(text, _ string) string {
	start := strings.Index(text, "{")
	if start < 0 {
		return ""
	}
	var obj map[string]any
	if unmarshalJSON([]byte(text[start:]), &obj) != nil {
		// Payload may be followed by more events; try progressively.
		for end := len(text); end > start; end-- {
			if text[end-1] == '}' && unmarshalJSON([]byte(text[start:end]), &obj) == nil {
				break
			}
		}
	}
	if obj == nil {
		return ""
	}
	if e, ok := obj["error"].(map[string]any); ok {
		if m := getStr(e, "message"); m != "" {
			return m
		}
	}
	return getStr(obj, "message")
}

func codexSSEErrorResponse(status int, message string) *http.Response {
	raw, _ := marshalJSON(map[string]any{
		"error": map[string]any{"message": message, "type": "server_error", "code": status},
	})
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(raw))),
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
