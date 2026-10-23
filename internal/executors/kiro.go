package executors

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// KiroExecutor ports open-sse/executors/kiro.js: AWS CodeWhisperer streaming
// API over AWS EventStream binary framing, decoded here into OpenAI-shaped
// SSE (the binary format does not round-trip through the translator — see
// open-sse/AGENTS.md pitfalls).
//
// Ported: endpoint ordering (amazonaws surfaces first, q.* first, region
// rewrite), auth headers (api_key / external_idp TokenType variants, SSO
// bearer, profile ARN), endpoint-fallback statuses {401,403,404}+429, and
// the EventStream→SSE conversion for assistant/reasoning/code/tool events
// with metrics/context usage.
//
// TODO (documented in the Team D report): the JS "integrity gate" —
// tool-call repair retries, buffered-tool validation bounds and the
// terminal-provenance diagnostics object — is not ported; tool input
// fragments are accumulated and validated as JSON objects, and unusable
// tool calls are dropped (same end behaviour as JS emitTools' per-tool
// validation, without the repair-retry loop).
type KiroExecutor struct{ *Base }

const kiroCodeWhispererTarget = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse"

var kiroFallbackStatuses = map[int]bool{401: true, 403: true, 404: true}

func NewKiroExecutor() *KiroExecutor {
	k := &KiroExecutor{}
	k.Base = &Base{ProviderID: "kiro", Hooks: Hooks{
		BuildURL:     k.buildURL,
		BuildHeaders: k.buildHeaders,
		ShouldRetry:  k.shouldRetry,
		WrapResponse: k.wrapResponse,
		Refresh:      refreshFromGrantOrSpecial,
	}}
	return k
}

var kiroRegionRe = regexp.MustCompile(`([a-z]+)\.[a-z0-9-]+\.amazonaws\.com`)

// orderedBaseURLs ports getOrderedBaseUrls: Amazon surfaces first (q.*
// before the rest), then the kiro.dev gateway; regionalise amazonaws hosts
// when the connection carries a non-default region. (kiro.js: the legacy
// kiro.dev path gateway answers modern payloads with terminal 400s, while
// Amazon surfaces reject foreign tokens with 401/403 which DO fall through.)
func (k *KiroExecutor) orderedBaseURLs(req *Request) []string {
	baseURLs := req.Provider.BaseURLsList()
	region := strings.TrimSpace(req.Cred.SpecificString("region"))
	if region == "" {
		region = "us-east-1"
	}
	regionalize := func(u string) string {
		if region != "us-east-1" && strings.Contains(u, "amazonaws.com") {
			return kiroRegionRe.ReplaceAllString(u, "${1}."+region+".amazonaws.com")
		}
		return u
	}
	var amazon, others, q, rest []string
	for _, u := range baseURLs {
		if strings.Contains(u, "amazonaws.com") {
			amazon = append(amazon, regionalize(u))
		} else {
			others = append(others, u)
		}
	}
	for _, u := range amazon {
		if strings.Contains(u, "://q.") {
			q = append(q, u)
		} else {
			rest = append(rest, u)
		}
	}
	if len(q) > 0 {
		return append(append(q, rest...), others...)
	}
	return append(amazon, others...)
}

func (k *KiroExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	urls := k.orderedBaseURLs(req)
	if urlIndex < len(urls) {
		return urls[urlIndex], nil
	}
	if len(urls) > 0 {
		return urls[0], nil
	}
	return req.Provider.BaseURL, nil
}

// shouldRetry ports KiroExecutor.shouldRetry: base 429 rule OR endpoint
// fallback statuses {401,403,404} while another surface remains. A payload-
// invalid 400 stays terminal (kiro.js comment).
func (k *KiroExecutor) shouldRetry(status, urlIndex, fallbackCount int) bool {
	hasFallback := urlIndex+1 < fallbackCount
	return (status == 429 && hasFallback) || (hasFallback && kiroFallbackStatuses[status])
}

// buildHeaders ports KiroExecutor.buildHeaders.
func (k *KiroExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	headers := map[string]string{}
	for k2, v := range req.Provider.Headers {
		headers[k2] = v
	}
	headers["Amz-Sdk-Request"] = "attempt=1; max=3"
	headers["Amz-Sdk-Invocation-Id"] = newUUID()
	if strings.Contains(url, "://codewhisperer.") {
		headers["X-Amz-Target"] = kiroCodeWhispererTarget
	}
	cred := req.Cred
	authMethod := cred.SpecificString("authMethod")
	isAPIKey := authMethod == "api_key"
	isExternalIdp := authMethod == "external_idp"
	apiKey := cred.APIKey
	if apiKey == "" && isAPIKey {
		apiKey = cred.AccessToken
	}
	if isAPIKey && apiKey != "" {
		headers["Authorization"] = "Bearer " + apiKey
		headers["TokenType"] = "API_KEY"
	} else if cred.AccessToken != "" {
		headers["Authorization"] = "Bearer " + cred.AccessToken
		if isExternalIdp {
			headers["TokenType"] = "EXTERNAL_IDP"
		}
	}
	if cred.AccessToken != "" {
		headers["x-amz-sso-bearer"] = cred.AccessToken
	}
	headers["x-amzn-kiro-agent-mode"] = "spec"
	headers["x-amzn-codewhisperer-machine-id"] = "kiro-desktop"
	if arn := cred.SpecificString("profileArn"); arn != "" {
		headers["x-amzn-codewhisperer-profile-arn"] = arn
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/json"
	}
	return headers, nil
}

// wrapResponse converts a successful EventStream body into OpenAI SSE.
// Errors are returned untransformed so chatcore can classify the status
// and trigger account fallback/cooldown (kiro.js execute comment).
func (k *KiroExecutor) wrapResponse(resp *http.Response, req *Request) (*http.Response, string, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, "", nil
	}
	pr, pw := io.Pipe()
	go func() {
		err := convertKiroEventStream(resp.Body, pw, req.Model)
		resp.Body.Close()
		_ = pw.CloseWithError(err)
	}()
	out := &http.Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}},
		Body:       pr,
	}
	return out, "openai", nil
}

type kiroTool struct {
	id     string
	name   string
	parts  []string
	object map[string]any
	kind   string // "string" | "object"
}

// convertKiroEventStream ports transformEventStreamToSSE's event handling
// (kiro.js processEvent): assistant content (with <thinking>…</thinking>
// spans lifted out), reasoning, code, tool accumulation, stop reasons and
// usage (metricsEvent wins; contextUsageEvent estimates prompt tokens).
func convertKiroEventStream(r io.Reader, w io.Writer, model string) error {
	er := &eventStreamReader{r: r}
	responseID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixMilli())
	created := time.Now().Unix()
	chunkIndex := 0
	inThinking := false
	hasToolCalls := false
	sawToolUse := false
	stopReason := ""
	tools := map[string]*kiroTool{}
	var toolOrder []*kiroTool
	totalContentLen := 0
	var usage map[string]any
	contextPct := -1.0

	emit := func(delta map[string]any, finish any, usageVal map[string]any) {
		chunk := map[string]any{
			"id":      responseID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		}
		if usageVal != nil {
			chunk["usage"] = usageVal
		}
		if chunkIndex == 0 {
			if _, hasRole := delta["role"]; !hasRole {
				// First chunk carries the assistant role (JS emitDelta).
				nd := map[string]any{"role": "assistant"}
				for k, v := range delta {
					nd[k] = v
				}
				chunk["choices"] = []any{map[string]any{"index": 0, "delta": nd, "finish_reason": finish}}
			}
		}
		chunkIndex++
		raw, _ := marshalJSON(chunk)
		fmt.Fprintf(w, "data: %s\n\n", raw)
	}

	finish := func() error {
		// Emit accumulated tool calls (JS emitTools at finish).
		toolIdx := 0
		for _, tool := range toolOrder {
			var inputRaw string
			switch tool.kind {
			case "object":
				raw, _ := marshalJSON(tool.object)
				inputRaw = string(raw)
			case "string":
				joined := strings.Join(tool.parts, "")
				var parsed map[string]any
				if err := unmarshalJSON([]byte(joined), &parsed); err != nil || parsed == nil {
					continue // drop unusable tool call (JS per-tool validation)
				}
				inputRaw = joined
			default:
				continue
			}
			emit(map[string]any{"tool_calls": []any{map[string]any{
				"index": toolIdx, "id": tool.id, "type": "function",
				"function": map[string]any{"name": tool.name, "arguments": ""},
			}}}, nil, nil)
			emit(map[string]any{"tool_calls": []any{map[string]any{
				"index": toolIdx, "function": map[string]any{"arguments": inputRaw},
			}}}, nil, nil)
			totalContentLen += len(tool.name) + len(inputRaw)
			hasToolCalls = true
			toolIdx++
		}
		fr := kiroFinishReason(stopReason, sawToolUse, hasToolCalls)
		if usage == nil {
			// Estimate like the JS finish(): prompt from context usage,
			// completion from content length / 4.
			usage = map[string]any{}
			prompt := 0
			if contextPct >= 0 {
				prompt = int(contextPct / 100 * 200000) // default context window 200k
			}
			completion := totalContentLen / 4
			if (hasToolCalls || totalContentLen > 0) && completion == 0 {
				completion = 1
			}
			usage["prompt_tokens"] = prompt
			usage["completion_tokens"] = completion
			usage["total_tokens"] = prompt + completion
		}
		emit(map[string]any{}, fr, usage)
		_, err := io.WriteString(w, "data: [DONE]\n\n")
		return err
	}

	for {
		frame, err := er.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Corrupt frame: emit an SSE error frame rather than silently
			// truncating (JS fail() with corrupt_eventstream_frame).
			emitSSEError(w, "corrupt_eventstream_frame", err.Error())
			return nil
		}
		msgType := frame.HeaderString(":message-type")
		if msgType == "error" || msgType == "exception" {
			msg := getStr(frame.Payload, "message")
			if msg == "" {
				msg = "Kiro upstream sent an EventStream " + msgType
			}
			emitSSEError(w, "kiro_upstream_eventstream_error", msg)
			return nil
		}
		eventType := frame.HeaderString(":event-type")
		payload := frame.Payload
		switch eventType {
		case "assistantResponseEvent":
			content := getStr(payload, "content")
			if inThinking {
				end := strings.Index(content, "</thinking>")
				if end < 0 {
					content = ""
				} else {
					inThinking = false
					content = strings.TrimPrefix(content[end+11:], "\n")
				}
			} else if start := strings.Index(content, "<thinking>"); start >= 0 {
				if end := strings.Index(content[start+10:], "</thinking>"); end < 0 {
					inThinking = true
					content = content[:start]
				} else {
					content = content[:start] + strings.TrimPrefix(content[start+10+end+11:], "\n")
				}
			}
			if content != "" {
				totalContentLen += len(content)
				emit(map[string]any{"content": content}, nil, nil)
			}
		case "reasoningContentEvent":
			var v map[string]any
			if inner, ok := payload["reasoningContentEvent"].(map[string]any); ok {
				v = inner
			} else {
				v = payload
			}
			content := getStr(v, "text")
			if content == "" {
				content = getStr(v, "content")
			}
			if content != "" {
				totalContentLen += len(content)
				emit(map[string]any{"reasoning_content": content}, nil, nil)
			}
		case "codeEvent":
			content := getStr(payload, "content")
			if content != "" {
				totalContentLen += len(content)
				emit(map[string]any{"content": content}, nil, nil)
			}
		case "toolUseEvent":
			sawToolUse = true
			var values []any
			if arr, ok := payload["toolUseEvent"].([]any); ok {
				values = arr
			} else {
				values = []any{payload}
			}
			// JS payload may also BE the tool object/array directly.
			if _, hasName := payload["name"]; !hasName {
				if inner, ok := payload["toolUseEvent"].(map[string]any); ok {
					values = []any{inner}
				}
			}
			for _, raw := range values {
				value, _ := raw.(map[string]any)
				if value == nil {
					continue
				}
				name := strings.TrimSpace(getStr(value, "name"))
				if name == "" {
					continue
				}
				id := getStr(value, "toolUseId")
				if id == "" {
					id = fmt.Sprintf("call_%d_%d", created, len(toolOrder)+1)
				}
				tool := tools[id]
				if tool == nil {
					tool = &kiroTool{id: id, name: name}
					tools[id] = tool
					toolOrder = append(toolOrder, tool)
				}
				switch input := value["input"].(type) {
				case string:
					tool.kind = "string"
					tool.parts = append(tool.parts, input)
				case map[string]any:
					tool.kind = "object"
					tool.object = input
				}
			}
		case "messageStopEvent":
			if r := getStr(payload, "stopReason"); r != "" {
				stopReason = r
			} else if r := getStr(payload, "stop_reason"); r != "" {
				stopReason = r
			}
		case "metadataEvent", "MetadataEvent":
			var md map[string]any
			if inner, ok := payload["metadataEvent"].(map[string]any); ok {
				md = inner
			} else if inner, ok := payload["metadata"].(map[string]any); ok {
				md = inner
			} else {
				md = payload
			}
			if r := getStr(md, "stopReason"); r != "" {
				stopReason = r
			}
		case "contextUsageEvent":
			if pct, ok := payload["contextUsagePercentage"].(float64); ok {
				contextPct = pct
			} else if n, ok := payload["contextUsagePercentage"].(jsonNumber); ok {
				f, _ := n.Float64()
				contextPct = f
			}
		case "metricsEvent":
			var m map[string]any
			if inner, ok := payload["metricsEvent"].(map[string]any); ok {
				m = inner
			} else {
				m = payload
			}
			prompt := int(getFloat(m, "inputTokens"))
			completion := int(getFloat(m, "outputTokens"))
			if prompt > 0 || completion > 0 {
				usage = map[string]any{
					"prompt_tokens":     prompt,
					"completion_tokens": completion,
					"total_tokens":      prompt + completion,
				}
			}
		}
	}
	return finish()
}

// kiroFinishReason maps Kiro stop reasons to OpenAI finish_reason
// (JS normalizeStopReason/mergeStopReason subset).
func kiroFinishReason(stopReason string, sawToolUse, hasToolCalls bool) string {
	switch strings.ToUpper(strings.ReplaceAll(stopReason, "-", "_")) {
	case "TOOL_USE":
		return "tool_calls"
	case "MAX_TOKENS", "MAX_TOKENS_REACHED":
		return "length"
	case "CONTENT_FILTERED", "GUARDRAIL_INTERVENED":
		return "content_filter"
	case "END_TURN", "STOP_SEQUENCE", "COMPLETE", "":
		if hasToolCalls || (sawToolUse && stopReason == "") {
			if hasToolCalls {
				return "tool_calls"
			}
		}
		return "stop"
	default:
		if hasToolCalls {
			return "tool_calls"
		}
		return "stop"
	}
}

// emitSSEError writes an OpenAI-shaped SSE error frame.
func emitSSEError(w io.Writer, code, message string) {
	raw, _ := marshalJSON(map[string]any{
		"error": map[string]any{"message": message, "code": code, "type": "server_error"},
	})
	fmt.Fprintf(w, "data: %s\n\n", raw)
}
