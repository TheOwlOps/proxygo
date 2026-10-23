package executors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Smaller specialised executors from open-sse/executors/, grouped here.
// Each is a thin variation over Default/Base behaviour.

// --- ollama-local (executors/ollama-local.js) ---

// OllamaLocalExecutor: DefaultExecutor with the URL replaced by the local
// Ollama host's /api/chat.
type OllamaLocalExecutor struct{ *DefaultExecutor }

func NewOllamaLocalExecutor() *OllamaLocalExecutor {
	o := &OllamaLocalExecutor{DefaultExecutor: NewDefaultExecutor("ollama-local")}
	o.Base.Hooks.BuildURL = func(b *Base, req *Request, urlIndex int) (string, error) {
		return resolveOllamaLocalHost(req.Cred) + "/api/chat", nil
	}
	return o
}

// resolveOllamaLocalHost mirrors config/providers.js resolveOllamaLocalHost:
// per-connection host override, else the local default.
func resolveOllamaLocalHost(cred Credential) string {
	if h := cred.SpecificString("ollamaHost"); h != "" {
		return strings.TrimSuffix(h, "/")
	}
	if h := cred.SpecificString("baseUrl"); h != "" {
		return strings.TrimSuffix(h, "/")
	}
	if cred.BaseURL != "" {
		return strings.TrimSuffix(cred.BaseURL, "/")
	}
	return "http://localhost:11434"
}

// --- iflow (executors/iflow.js) ---

// IFlowExecutor: iFlow API with an HMAC-SHA256 request signature
// (HMAC(userAgent:sessionId:timestamp, apiKey)) in the headers.
type IFlowExecutor struct{ *Base }

func NewIFlowExecutor() *IFlowExecutor {
	f := &IFlowExecutor{}
	f.Base = &Base{ProviderID: "iflow", Hooks: Hooks{
		BuildURL: func(b *Base, req *Request, urlIndex int) (string, error) {
			return req.Provider.BaseURL, nil
		},
		BuildHeaders:  f.buildHeaders,
		TransformBody: f.transformBody,
		Refresh:       refreshFromGrantOrSpecial,
	}}
	return f
}

// createIFlowSignature ports createIFlowSignature.
func createIFlowSignature(userAgent, sessionID string, timestamp int64, apiKey string) string {
	if apiKey == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(userAgent + ":" + sessionID + ":" + strconv.FormatInt(timestamp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (f *IFlowExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	sessionID := "session-" + newUUID()
	timestamp := time.Now().UnixMilli()
	userAgent := req.Provider.Headers["User-Agent"]
	if userAgent == "" {
		userAgent = "iFlow-Cli"
	}
	apiKey := req.Cred.APIKey
	if apiKey == "" {
		apiKey = req.Cred.AccessToken
	}
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range req.Provider.Headers {
		headers[k] = v
	}
	headers["session-id"] = sessionID
	headers["x-iflow-timestamp"] = strconv.FormatInt(timestamp, 10)
	headers["x-iflow-signature"] = createIFlowSignature(userAgent, sessionID, timestamp, apiKey)
	if apiKey != "" {
		headers["Authorization"] = "Bearer " + apiKey
	}
	if req.Stream {
		headers["Accept"] = "text/event-stream"
	}
	return headers, nil
}

func (f *IFlowExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	// Inject stream_options for streaming requests to get usage data.
	if req.Stream {
		if _, hasMsgs := body["messages"]; hasMsgs {
			if _, has := body["stream_options"]; !has {
				body["stream_options"] = map[string]any{"include_usage": true}
			}
		}
	}
	return body, nil
}

// --- kimchi (executors/kimchi.js) ---

// KimchiExecutor: DefaultExecutor + a body-cleaning transform (top-level
// system merge, Anthropic-only field drops, cache_control/signature
// stripping). The Anthropic-backed model check uses the model name only —
// the JS also consults cached kimchi model metadata (services/kimchiModels)
// which is Team B/provider data; name matching covers the same ids in
// practice (TODO in report).
type KimchiExecutor struct{ *DefaultExecutor }

var kimchiGatewayDrops = []string{
	"anthropic_version", "anthropic_beta", "client_metadata", "mcp_servers",
	"stop_sequences", "thinking", "top_k",
}

var kimchiAnthropicModelRe = regexp.MustCompile(`(^|[-_/])(claude|anthropic)([-_/]|$)`)

func NewKimchiExecutor() *KimchiExecutor {
	k := &KimchiExecutor{DefaultExecutor: NewDefaultExecutor("kimchi")}
	defaultTransform := k.Base.Hooks.TransformBody
	k.Base.Hooks.TransformBody = func(b *Base, req *Request) (map[string]any, error) {
		out, err := defaultTransform(b, req)
		if err != nil || out == nil {
			return out, err
		}
		kimchiClean(out, req.Model)
		return out, nil
	}
	return k
}

func kimchiClean(body map[string]any, model string) {
	// Merge top-level `system` into messages, then drop it.
	if sys, present := body["system"]; present {
		if msgs, ok := body["messages"].([]any); ok {
			text := kimchiSystemToText(sys)
			if text != "" {
				found := false
				for _, raw := range msgs {
					msg, _ := raw.(map[string]any)
					if msg == nil || msg["role"] != "system" {
						continue
					}
					found = true
					switch c := msg["content"].(type) {
					case string:
						msg["content"] = text + "\n\n" + c
					case []any:
						msg["content"] = append([]any{map[string]any{"type": "text", "text": text}}, c...)
					}
					break
				}
				if !found {
					body["messages"] = append([]any{map[string]any{"role": "system", "content": text}}, msgs...)
				}
			}
		}
	}
	for _, key := range kimchiGatewayDrops {
		delete(body, key)
	}
	delete(body, "system")
	if kimchiAnthropicModelRe.MatchString(strings.ToLower(model)) {
		delete(body, "reasoning_effort")
		delete(body, "reasoning")
		delete(body, "thinking")
	}
	// Strip cache_control / signature artifacts from messages and tools.
	if msgs, ok := body["messages"].([]any); ok {
		for _, raw := range msgs {
			msg, _ := raw.(map[string]any)
			if msg == nil {
				continue
			}
			delete(msg, "cache_control")
			if parts, ok := msg["content"].([]any); ok {
				for i, praw := range parts {
					part, _ := praw.(map[string]any)
					if part == nil {
						continue
					}
					clean := cloneMap(part)
					delete(clean, "cache_control")
					delete(clean, "signature")
					parts[i] = clean
				}
			}
			// Strip long reasoning_content echoes (>8 chars — placeholder
			// threshold in the JS).
			if msg["role"] == "assistant" {
				if rc, ok := msg["reasoning_content"].(string); ok && len(rc) > 8 {
					delete(msg, "reasoning_content")
				}
			}
		}
	}
	if tools, ok := body["tools"].([]any); ok {
		for i, raw := range tools {
			if tool, _ := raw.(map[string]any); tool != nil {
				clean := cloneMap(tool)
				delete(clean, "cache_control")
				tools[i] = clean
			}
		}
	}
}

func kimchiSystemToText(system any) string {
	switch v := system.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		var parts []string
		for _, raw := range v {
			switch p := raw.(type) {
			case string:
				parts = append(parts, p)
			case map[string]any:
				if t := getStr(p, "text"); t != "" {
					parts = append(parts, t)
				}
			}
		}
		return strings.TrimSpace(strings.Join(parts, "\n"))
	}
	return ""
}

// --- minimax-code (executors/minimax-code.js) ---

// MinimaxCodeExecutor: DefaultExecutor whose 402/403 responses naming a
// balance/quota problem are normalised to 429 so chatcore's refresh path
// doesn't keep retrying a half-spent account (a 403 that does NOT name the
// balance is a real auth refusal and passes through untouched).
type MinimaxCodeExecutor struct{ *DefaultExecutor }

var minimaxQuotaRe = regexp.MustCompile(`(?i)insufficient|balance|credit|quota|exhaust|limit|余额|积分|额度|不足|用完|上限`)

func NewMinimaxCodeExecutor(providerID string) *MinimaxCodeExecutor {
	if providerID == "" {
		providerID = "minimax-code"
	}
	m := &MinimaxCodeExecutor{DefaultExecutor: NewDefaultExecutor(providerID)}
	m.Base.Hooks.WrapResponse = func(resp *http.Response, req *Request) (*http.Response, string, error) {
		out, err := normalizeMinimaxQuotaResponse(resp)
		return out, "", err
	}
	// NOTE: the JS routes refresh through a dedicated single-use-token
	// handler (services/tokenRefresh refreshMiniMaxCodeToken, deduped by
	// token value) — token-refresh service territory; the generic grant
	// hook from DefaultExecutor is intentionally NOT inherited here.
	m.Base.Hooks.Refresh = nil
	return m
}

// normalizeMinimaxQuotaResponse ports normalizeQuotaResponse.
func normalizeMinimaxQuotaResponse(resp *http.Response) (*http.Response, error) {
	if resp == nil || (resp.StatusCode != 402 && resp.StatusCode != 403 && resp.StatusCode != 429) {
		return resp, nil
	}
	status := resp.StatusCode
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	mkResp := func(status int, body []byte, contentType string) *http.Response {
		h := resp.Header.Clone()
		h.Del("Content-Length")
		h.Del("Content-Encoding")
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		return &http.Response{
			StatusCode: status, Status: resp.Status, Header: h,
			Body: io.NopCloser(strings.NewReader(string(body))),
		}
	}
	text := string(raw)
	// A 429 is already the right signal; 402/403 not naming the balance
	// are auth failures — both pass through as-is.
	if status == 429 || !minimaxQuotaRe.MatchString(text) {
		return mkResp(status, raw, ""), nil
	}
	msg := strings.TrimSpace(text)
	var parsed map[string]any
	if unmarshalJSON(raw, &parsed) == nil && parsed != nil {
		if e, ok := parsed["error"].(map[string]any); ok && getStr(e, "message") != "" {
			msg = getStr(e, "message")
		} else if getStr(parsed, "message") != "" {
			msg = getStr(parsed, "message")
		} else if getStr(parsed, "msg") != "" {
			msg = getStr(parsed, "msg")
		} else if br, ok := parsed["base_resp"].(map[string]any); ok && getStr(br, "status_msg") != "" {
			msg = getStr(br, "status_msg")
		}
	}
	body, _ := marshalJSON(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    "rate_limit_error",
			"message": "usage limit reached: " + msg,
		},
	})
	out := mkResp(429, body, "application/json")
	out.Status = "429 Too Many Requests"
	return out, nil
}

// --- xiaomi-tokenplan (executors/xiaomi-tokenplan.js) ---

// XiaomiTokenplanExecutor: region-specific base URL; Claude-format
// transports route to /anthropic/v1/messages, others /chat/completions.
// The region base comes from the connection (Specific["tokenplanBaseUrl"])
// or the registry base (config resolveXiaomiTokenplanBaseUrl equivalent
// subset — the JS resolves per-region hosts from the connection's region).
type XiaomiTokenplanExecutor struct{ *DefaultExecutor }

func NewXiaomiTokenplanExecutor() *XiaomiTokenplanExecutor {
	x := &XiaomiTokenplanExecutor{DefaultExecutor: NewDefaultExecutor("xiaomi-tokenplan")}
	x.Base.Hooks.BuildURL = func(b *Base, req *Request, urlIndex int) (string, error) {
		base := req.Cred.SpecificString("tokenplanBaseUrl")
		if base == "" {
			base = req.Provider.BaseURL
		}
		base = strings.TrimSuffix(base, "/")
		if req.Cred.RuntimeTransport != nil && req.Cred.RuntimeTransport.Format == "claude" {
			// JS: baseUrl.replace(/\/v1\/?$/, "") — base already had its
			// trailing slash trimmed above.
			return strings.TrimSuffix(base, "/v1") + "/anthropic/v1/messages", nil
		}
		return base + "/chat/completions", nil
	}
	return x
}
