package chatcore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// core ports open-sse/handlers/chatCore.js handleChatCore: detect source
// format → resolve target format/transport → translate request → dispatch
// via the executor → 401/403 token-refresh retry → upstream error mapping
// → response translation / streaming passthrough.
//
// Not ported in this phase (documented in the Team D report): request
// logging/usage persistence (usageDb), RTK beyond the TokenSaver hook,
// headroom/caveman/ponytail/pxpipe savers, native-passthrough client-tool
// special cases, tool-name cloaking maps, modality stripping / image
// prefetch. Translation itself is Team A's (the Translator interface);
// when it reports no translation is needed the body passes through.
func (s *Service) core(ctx context.Context, req ChatRequest, info ProviderInfo, model string, cred Credential) outcome {
	provider := info.ID
	body := req.Body
	settings := s.settings()

	// --- Source format (endpoint override beats body detection) ---
	sourceFormat := DetectFormatByEndpoint(req.Endpoint, body)
	if sourceFormat == "" {
		sourceFormat = DetectFormat(body)
	}

	// --- Target format + runtime transport (chatCore.js) ---
	var meta ModelMeta
	if s.Providers != nil {
		meta = s.Providers.ModelMeta(provider, model)
	}
	var targetFormat string
	if s.Providers != nil {
		runtimeTransport := s.Providers.TransportFor(provider, sourceFormat)
		modelTargetTransport := (*TransportOption)(nil)
		if meta.TargetFormat != "" {
			modelTargetTransport = s.Providers.TransportFor(provider, meta.TargetFormat)
		}
		// Per-model guard: when a model declares supportedFormats, only use
		// the sourceFormat-matched transport if that format is declared;
		// otherwise fall back to the model's targetFormat transport so the
		// URL always matches the translated body (chatCore.js comment).
		var useTransport *TransportOption
		if meta.SupportedFormats == nil || containsStr(meta.SupportedFormats, sourceFormat) {
			useTransport = runtimeTransport
		} else {
			useTransport = modelTargetTransport
		}
		if useTransport != nil {
			targetFormat = useTransport.Format
			rt := *useTransport
			cred.RuntimeTransport = &rt
		}
	}
	if targetFormat == "" {
		targetFormat = meta.TargetFormat
	}
	if targetFormat == "" && s.Providers != nil {
		targetFormat = s.Providers.TargetFormat(provider, cred)
	}
	if targetFormat == "" {
		targetFormat = info.Format
	}
	if targetFormat == "" {
		targetFormat = FormatOpenAI
	}
	upstreamModel := meta.UpstreamID
	if upstreamModel == "" {
		upstreamModel = model
	}

	// --- Provider thinking override (only when the client hasn't set it) ---
	workBody := cloneBody(body)
	if tc, ok := settings.ProviderThinking[provider]; ok && tc.Mode != "" && tc.Mode != "auto" {
		switch {
		case tc.Mode == "on" && workBody["thinking"] == nil:
			workBody["thinking"] = map[string]any{"type": "enabled", "budget_tokens": 10000}
		case tc.Mode == "off" && workBody["thinking"] == nil:
			workBody["thinking"] = map[string]any{"type": "disabled"}
		case workBody["reasoning_effort"] == nil:
			workBody["reasoning_effort"] = tc.Mode
		}
	}

	// --- Stream decision (chatCore.js) ---
	clientRequestedStreaming := workBody["stream"] == true ||
		sourceFormat == FormatAntigravity || sourceFormat == FormatGemini || sourceFormat == FormatGeminiCLI
	providerRequiresStreaming := info.ForceStream
	stream := providerRequiresStreaming || workBody["stream"] != false
	if meta.Type == "imageGen" && (provider == "antigravity" || provider == "gemini-cli") {
		stream = false // image models require non-streaming (chatCore.js)
	}
	accept := req.Headers["accept"]
	clientPrefersJSON := strings.Contains(accept, "application/json")
	clientPrefersSSE := strings.Contains(accept, "text/event-stream")
	if clientPrefersJSON && !clientPrefersSSE && workBody["stream"] != true && !providerRequiresStreaming {
		stream = false
	}

	// Expose raw client headers to translators/executors (session ids).
	cred.RawHeaders = req.Headers
	// Per-provider user overrides (custom headers) from settings.
	if ov, ok := settings.ProviderOverrides[provider]; ok && len(ov.Headers) > 0 {
		cred.OverrideHeaders = ov.Headers
	}

	// --- Translate request ---
	workBody["model"] = upstreamModel
	var translated map[string]any
	if s.Translator != nil && s.Translator.NeedsTranslation(sourceFormat, targetFormat) {
		t, err := s.Translator.TranslateRequest(sourceFormat, targetFormat, cloneBody(workBody))
		if err != nil || t == nil {
			return outcome{
				success:   false,
				status:    StatusBadRequest,
				errorText: "Failed to translate request for " + sourceFormat + " → " + targetFormat,
				response:  ErrorResponse(StatusBadRequest, "Failed to translate request for "+sourceFormat+" → "+targetFormat, nil),
			}
		}
		translated = t
	} else if s.Translator != nil && (sourceFormat != targetFormat) {
		// Translator present but pair unregistered: JS translateRequest
		// returns null for unknown pairs → same 400.
		if s.Translator.NeedsTranslation(sourceFormat, targetFormat) {
			// unreachable; kept for clarity
		}
		translated = cloneBody(workBody)
	} else {
		translated = cloneBody(workBody)
	}
	delete(translated, "_toolNameMap")
	delete(translated, "_customToolNames")
	translated["model"] = StripThinkingSuffix(upstreamModel)
	stripContinuityFields(translated)

	// TTS models don't support tool messages/function calling.
	if meta.Type == "tts" {
		if msgs, ok := translated["messages"].([]any); ok {
			var kept []any
			for _, raw := range msgs {
				if m, ok := raw.(map[string]any); ok && m["role"] == "tool" {
					continue
				}
				kept = append(kept, raw)
			}
			translated["messages"] = kept
		}
		delete(translated, "tools")
	}

	// RTK token saver (fail-open hook; cursor's pre-translate pass is a JS
	// special case — the hook receives the translated body here).
	if s.TokenSaver != nil {
		tokenSaverEnabled := !strings.EqualFold(req.Headers["x-proxygo-token-saver"], "off")
		s.TokenSaver.Compress(translated, targetFormat, tokenSaverEnabled && settings.RTKEnabled)
	}

	// PII redaction (fail-open hook, Feature Pack F6 — opt-in via the
	// piiRedactionEnabled setting; nil guard = body untouched).
	if s.BodyGuard != nil {
		if n := s.BodyGuard.Process(translated, targetFormat, settings.PIIRedactionEnabled); n > 0 {
			s.log().Info("PII", "redacted "+strconv.Itoa(n)+" item(s) from request body")
		}
	}

	// --- Dispatch ---
	execBody, err := json.Marshal(translated)
	if err != nil {
		return outcome{success: false, status: StatusBadGateway,
			errorText: FormatProviderError(err, provider, model, StatusBadGateway),
			response:  ErrorResponse(StatusBadGateway, FormatProviderError(err, provider, model, StatusBadGateway), nil)}
	}
	result, err := s.Executor.Execute(ctx, provider, info, cred, execBody)
	if err != nil {
		if ctx.Err() != nil {
			return outcome{success: false, status: StatusClientClosedRequest,
				errorText: "Request aborted",
				response:  ErrorResponse(StatusClientClosedRequest, "Request aborted", nil)}
		}
		errMsg := FormatProviderError(err, provider, model, StatusBadGateway)
		return outcome{success: false, status: StatusBadGateway, errorText: errMsg,
			response: ErrorResponse(StatusBadGateway, errMsg, nil)}
	}
	resp := result.Response
	responseFormat := result.ResponseFormat
	if responseFormat == "" {
		responseFormat = targetFormat
	}

	// --- 401/403: token refresh + one retry (chatCore.js) ---
	if !info.NoAuth && !cred.NoAuth && s.Refresher != nil &&
		(resp.StatusCode == StatusUnauthorized || resp.StatusCode == StatusForbidden) {
		if newCred := s.refreshWithRetry(ctx, provider, cred); newCred != nil {
			s.log().Info("TOKEN", "TOKEN REFRESHED · "+provider+"/"+model)
			if s.Accounts != nil {
				_ = s.Accounts.PersistRefreshed(cred, *newCred)
			}
			merged := cred
			if newCred.AccessToken != "" {
				merged.AccessToken = newCred.AccessToken
			}
			if newCred.RefreshToken != "" {
				merged.RefreshToken = newCred.RefreshToken
			}
			if newCred.CopilotToken != "" {
				merged.CopilotToken = newCred.CopilotToken
			}
			if retryResult, rerr := s.Executor.Execute(ctx, provider, info, merged, execBody); rerr == nil && retryResult != nil && retryResult.Response != nil {
				if retryResult.Response.StatusCode >= 200 && retryResult.Response.StatusCode < 300 {
					drainBody(resp)
					resp = retryResult.Response
					if retryResult.ResponseFormat != "" {
						responseFormat = retryResult.ResponseFormat
					}
				} else {
					drainBody(retryResult.Response)
				}
			}
		} else {
			s.log().Warn("TOKEN", strings.ToUpper(provider)+" | refresh failed")
		}
	}

	// --- Upstream error ---
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw := cloneResponseBody(resp)
		var parseFn func(int, string) *ParsedErrorLike
		if ep, ok := s.Executor.(ExecutorErrorParser); ok {
			parseFn = func(status int, text string) *ParsedErrorLike {
				return ep.ParseError(provider, status, text)
			}
		}
		statusCode, message, resetsAt := ParseUpstreamError(resp.StatusCode, string(raw), parseFn)
		errMsg := FormatProviderError(errFromMessage(message), provider, model, statusCode)
		return outcome{
			success:   false,
			status:    statusCode,
			errorText: errMsg,
			resetsAt:  resetsAt,
			response:  ErrorResponse(statusCode, errMsg, passthroughHeaders(resp.Header)),
		}
	}

	// --- Success: client didn't ask for streaming but the provider forced
	// it (or the wire is Responses, which always streams upstream): collect
	// the SSE into JSON (chatCore.js handleForcedSSEToJson gate). ---
	if !clientRequestedStreaming && (providerRequiresStreaming || responseFormat == FormatOpenAIResponses) {
		ct0 := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct0, "text/event-stream") {
			if out, ok := s.collectForcedSSE(resp, responseFormat, sourceFormat); ok {
				return out
			}
		}
	}

	// --- Success: streaming ---
	if stream {
		// Upstream answered 2xx with an HTML/text page (e.g. Cloudflare
		// error page): piping it through the SSE transform crashes the
		// pipeline in the JS; return a clean JSON error instead
		// (streamingHandler.js blocked-pipe guard).
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if ct != "" && !strings.Contains(ct, "text/event-stream") && !strings.Contains(ct, "application/json") {
			raw := cloneResponseBody(resp)
			shortMsg := sanitiseHTMLTitle(string(raw), ct)
			status := resp.StatusCode
			return outcome{
				success:   false,
				status:    status,
				errorText: shortMsg,
				response:  ErrorResponse(status, "["+itoa(status)+"]: "+shortMsg, nil),
			}
		}
		if s.Translator != nil && s.Translator.NeedsTranslation(responseFormat, sourceFormat) {
			resp.Body = io.NopCloser(s.Translator.WrapStream(resp.Body, responseFormat, sourceFormat))
			resp.Header.Set("Content-Type", "text/event-stream")
			resp.Header.Del("Content-Length")
		}
		return outcome{success: true, status: resp.StatusCode, response: resp}
	}

	// --- Success: non-streaming, but upstream forced SSE (or Responses
	// wire): collect the SSE stream into a JSON completion
	// (chatCore.js handleForcedSSEToJson gate). ---
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	looksSSE := strings.Contains(ct, "text/event-stream")
	if providerRequiresStreaming || responseFormat == FormatOpenAIResponses || looksSSE {
		if out, ok := s.collectForcedSSE(resp, responseFormat, sourceFormat); ok {
			return out
		}
		// Not SSE after all: collectForcedSSE restored the raw body.
		return outcome{success: true, status: resp.StatusCode, response: resp}
	}

	// --- Success: plain non-streaming JSON ---
	if s.Translator != nil && s.Translator.NeedsTranslation(responseFormat, sourceFormat) {
		raw := cloneResponseBody(resp)
		var parsed map[string]any
		if json.Unmarshal(raw, &parsed) == nil && parsed != nil {
			if translatedResp, terr := s.Translator.TranslateResponseBody(responseFormat, sourceFormat, parsed); terr == nil && translatedResp != nil {
				out, _ := json.Marshal(translatedResp)
				return outcome{success: true, status: resp.StatusCode, response: jsonResponse(resp, out)}
			}
		}
		resp.Body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return outcome{success: true, status: resp.StatusCode, response: resp}
}

// collectForcedSSE reads an SSE upstream body and merges it into a JSON
// completion (translating to the client format when needed). ok=false
// means the body was not SSE; the raw body is restored onto resp so the
// caller can continue with it (JS handleForcedSSEToJson returns null in
// that case).
func (s *Service) collectForcedSSE(resp *http.Response, responseFormat, sourceFormat string) (outcome, bool) {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	resp.Body.Close()
	completion, ok := collectSSEToJSON(raw, responseFormat)
	if !ok {
		resp.Body = io.NopCloser(strings.NewReader(string(raw)))
		return outcome{}, false
	}
	if s.Translator != nil && s.Translator.NeedsTranslation(responseFormat, sourceFormat) {
		if translatedResp, terr := s.Translator.TranslateResponseBody(responseFormat, sourceFormat, completion); terr == nil && translatedResp != nil {
			completion = translatedResp
		}
	}
	out, _ := json.Marshal(completion)
	return outcome{success: true, status: resp.StatusCode, response: jsonResponse(resp, out)}, true
}

// refreshWithRetry ports services/tokenRefresh.js refreshWithRetry:
// up to 3 attempts, delay attempt*1s, first non-nil result wins. Rotating
// refresh tokens are adopted between attempts (chatCore.js comment: xAI/
// grok-cli issue a new RT on every refresh; reusing the consumed one
// yields invalid_grant).
func (s *Service) refreshWithRetry(ctx context.Context, provider string, cred Credential) *Credential {
	current := cred
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, time.Duration(attempt)*time.Second); err != nil {
				return nil
			}
		}
		res, err := s.Refresher.Refresh(ctx, provider, current)
		if err != nil || res == nil {
			continue
		}
		if res.RefreshToken != "" && res.RefreshToken != current.RefreshToken {
			current.AccessToken = res.AccessToken
			current.RefreshToken = res.RefreshToken
		}
		if res.AccessToken != "" || res.CopilotToken != "" {
			out := current
			if res.AccessToken != "" {
				out.AccessToken = res.AccessToken
			}
			if res.RefreshToken != "" {
				out.RefreshToken = res.RefreshToken
			}
			if res.CopilotToken != "" {
				out.CopilotToken = res.CopilotToken
			}
			return &out
		}
	}
	return nil
}

// stripContinuityFields ports chatCore.js stripContinuityFields: the
// Responses→Chat translator's encrypted_content stash must never reach an
// upstream provider.
func stripContinuityFields(body map[string]any) {
	msgs, ok := body["messages"].([]any)
	if !ok {
		return
	}
	for _, raw := range msgs {
		if m, ok := raw.(map[string]any); ok {
			delete(m, "encrypted_content")
			delete(m, "reasoning_encrypted_content")
		}
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

type msgError struct{ msg string }

func (e *msgError) Error() string { return e.msg }

func errFromMessage(msg string) error { return &msgError{msg: msg} }

func jsonResponse(orig *http.Response, body []byte) *http.Response {
	h := orig.Header.Clone()
	h.Set("Content-Type", "application/json")
	h.Del("Content-Length")
	return &http.Response{
		StatusCode: orig.StatusCode,
		Status:     orig.Status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}

var htmlTitleRe = regexp.MustCompile(`(?is)<title>([^<]+)</title>`)
var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

// sanitiseHTMLTitle ports streamingHandler.js's blocked-pipe message
// extraction: <title> text, tags stripped, whitespace collapsed, ≤160
// chars — untrusted upstream text never reaches the client verbatim.
func sanitiseHTMLTitle(bodyText, contentType string) string {
	title := ""
	if m := htmlTitleRe.FindStringSubmatch(bodyText); m != nil {
		title = m[1]
	}
	title = htmlTagRe.ReplaceAllString(title, "")
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 160 {
		title = title[:160]
	}
	if title != "" {
		return title
	}
	if len(bodyText) < 200 {
		plain := strings.TrimSpace(htmlTagRe.ReplaceAllString(bodyText, ""))
		if len(plain) > 160 {
			plain = plain[:160]
		}
		if plain != "" {
			return plain
		}
	}
	return "Upstream returned non-SSE response (" + contentType + ")"
}

// collectSSEToJSON ports the core of chatCore/sseToJsonHandler.js: merge
// OpenAI-shaped SSE chunks into one chat.completion object. Returns
// ok=false when the body carries no SSE data frames.
func collectSSEToJSON(raw []byte, format string) (map[string]any, bool) {
	var completion map[string]any
	var content, reasoning strings.Builder
	toolCalls := map[int]map[string]any{}
	var toolOrder []int
	var finishReason any
	var usage map[string]any
	found := false

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var chunk map[string]any
		if json.Unmarshal([]byte(payload), &chunk) != nil || chunk == nil {
			continue
		}
		found = true
		if completion == nil {
			completion = map[string]any{
				"id":      chunk["id"],
				"object":  "chat.completion",
				"created": chunk["created"],
				"model":   chunk["model"],
			}
		}
		if u, ok := chunk["usage"].(map[string]any); ok && u != nil {
			usage = u
		}
		choices, _ := chunk["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		choice, _ := choices[0].(map[string]any)
		if choice == nil {
			continue
		}
		if fr := choice["finish_reason"]; fr != nil {
			finishReason = fr
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			delta, _ = choice["message"].(map[string]any)
		}
		if delta == nil {
			continue
		}
		if c, ok := delta["content"].(string); ok {
			content.WriteString(c)
		}
		if r, ok := delta["reasoning_content"].(string); ok {
			reasoning.WriteString(r)
		}
		if tcs, ok := delta["tool_calls"].([]any); ok {
			for _, rawTC := range tcs {
				tc, _ := rawTC.(map[string]any)
				if tc == nil {
					continue
				}
				idx := 0
				if f, ok := tc["index"].(float64); ok {
					idx = int(f)
				} else if n, ok := tc["index"].(json.Number); ok {
					v, _ := n.Int64()
					idx = int(v)
				}
				acc := toolCalls[idx]
				if acc == nil {
					acc = map[string]any{"id": "", "type": "function", "function": map[string]any{"name": "", "arguments": ""}}
					toolCalls[idx] = acc
					toolOrder = append(toolOrder, idx)
				}
				if id, ok := tc["id"].(string); ok && id != "" {
					acc["id"] = id
				}
				if fn, ok := tc["function"].(map[string]any); ok {
					accFn := acc["function"].(map[string]any)
					if name, ok := fn["name"].(string); ok && name != "" {
						accFn["name"] = name
					}
					if args, ok := fn["arguments"].(string); ok {
						accFn["arguments"] = accFn["arguments"].(string) + args
					}
				}
			}
		}
	}
	if !found || completion == nil {
		return nil, false
	}
	message := map[string]any{"role": "assistant", "content": content.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolOrder) > 0 {
		var tcs []any
		for _, idx := range toolOrder {
			tcs = append(tcs, toolCalls[idx])
		}
		message["tool_calls"] = tcs
	}
	if finishReason == nil {
		finishReason = "stop"
	}
	completion["choices"] = []any{map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}}
	if usage != nil {
		completion["usage"] = usage
	}
	return completion, true
}
