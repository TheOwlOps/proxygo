package executors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default retry config by status code — config/runtimeConfig.js
// DEFAULT_RETRY_CONFIG + RETRY_CONFIG.delayMs (legacy bare-number delay).
var defaultRetryConfig = map[int]RetryEntry{
	429: {Attempts: 0, DelayMs: 0},
	502: {Attempts: 3, DelayMs: 3000},
	503: {Attempts: 3, DelayMs: 2000},
	504: {Attempts: 2, DelayMs: 3000},
}

const legacyRetryDelayMs = 2000 // RETRY_CONFIG.delayMs

// resolveRetryEntry mirrors resolveRetryEntry() in runtimeConfig.js.
func resolveRetryEntry(e *RetryEntry, present bool) RetryEntry {
	if !present || e == nil {
		return RetryEntry{Attempts: 0, DelayMs: legacyRetryDelayMs}
	}
	return *e
}

// retryConfigFor merges provider retry config over the defaults
// (base.js: { ...DEFAULT_RETRY_CONFIG, ...this.config.retry }).
func retryConfigFor(p *ProviderInfo) map[int]RetryEntry {
	out := make(map[int]RetryEntry, len(defaultRetryConfig))
	for k, v := range defaultRetryConfig {
		out[k] = v
	}
	if p != nil {
		for k, v := range p.Retry {
			out[k] = v
		}
	}
	return out
}

// SleepFunc is the retry-delay sleeper; replaceable in tests.
var SleepFunc = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// HTTPClient is the client used for upstream calls. No total timeout:
// streaming responses are long-lived; the connect timeout is applied per
// attempt (see doPost). Replaceable in tests.
var HTTPClient = &http.Client{}

// Hooks customise a Base executor per provider. Any nil hook uses the
// BaseExecutor behaviour from open-sse/executors/base.js.
type Hooks struct {
	BuildURL      func(b *Base, req *Request, urlIndex int) (string, error)
	BuildHeaders  func(b *Base, req *Request, url string) (map[string]string, error)
	TransformBody func(b *Base, req *Request) (map[string]any, error)
	// ShouldRetry: base.js default is (status==429 && more URLs remain).
	ShouldRetry func(status, urlIndex, fallbackCount int) bool
	ParseError  func(status int, bodyText string) *ParsedError
	// WrapResponse post-processes a successful (or any) response before it is
	// returned — binary decoders live here (kiro EventStream, bedrock
	// EventStream). It may also set the response format.
	WrapResponse func(resp *http.Response, req *Request) (*http.Response, string, error)
	Refresh      func(ctx context.Context, b *Base, p *ProviderInfo, cred Credential) (*Credential, error)
}

// Base is the Go port of BaseExecutor (open-sse/executors/base.js). One Base
// value per provider id; per-request state travels in *Request.
type Base struct {
	ProviderID string
	Hooks      Hooks
}

func (b *Base) fallbackCount(p *ProviderInfo) int {
	if n := len(p.BaseURLsList()); n > 0 {
		return n
	}
	return 1
}

// buildURL resolves the URL for one attempt.
func (b *Base) buildURL(req *Request, urlIndex int) (string, error) {
	if b.Hooks.BuildURL != nil {
		return b.Hooks.BuildURL(b, req, urlIndex)
	}
	// base.js buildUrl: openai-compatible / anthropic-compatible prefixes,
	// else config baseUrls[urlIndex].
	if strings.HasPrefix(b.ProviderID, "openai-compatible-") {
		base := req.Cred.BaseURL
		if base == "" {
			base = openAICompatBase
		}
		path := "/chat/completions"
		if resolveOpenAICompatibleAPIType(b.ProviderID, req.Cred) == "responses" {
			path = "/responses"
		}
		return strings.TrimSuffix(base, "/") + path, nil
	}
	if strings.HasPrefix(b.ProviderID, "anthropic-compatible-") {
		base := req.Cred.BaseURL
		if base == "" {
			base = anthropicCompatBase
		}
		return strings.TrimSuffix(base, "/") + "/messages", nil
	}
	urls := req.Provider.BaseURLsList()
	if urlIndex < len(urls) {
		return urls[urlIndex], nil
	}
	if len(urls) > 0 {
		return urls[0], nil
	}
	return req.Provider.BaseURL, nil
}

// buildHeaders resolves headers for one attempt.
func (b *Base) buildHeaders(req *Request, url string) (map[string]string, error) {
	if b.Hooks.BuildHeaders != nil {
		return b.Hooks.BuildHeaders(b, req, url)
	}
	return baseBuildHeaders(b.ProviderID, req), nil
}

// transformBody applies the TransformBody hook (identity by default).
func (b *Base) transformBody(req *Request) (map[string]any, error) {
	if b.Hooks.TransformBody != nil {
		return b.Hooks.TransformBody(b, req)
	}
	return req.Body, nil
}

func (b *Base) shouldRetry(status, urlIndex, fallbackCount int) bool {
	if b.Hooks.ShouldRetry != nil {
		return b.Hooks.ShouldRetry(status, urlIndex, fallbackCount)
	}
	// base.js shouldRetry: only 429 advances to the next base URL.
	return status == 429 && urlIndex+1 < fallbackCount
}

// ParseError implements ErrorParser: hook or the base.js default
// {status, message: bodyText || `HTTP ${status}`}.
func (b *Base) ParseError(status int, bodyText string) *ParsedError {
	if b.Hooks.ParseError != nil {
		if pe := b.Hooks.ParseError(status, bodyText); pe != nil {
			return pe
		}
	}
	msg := bodyText
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", status)
	}
	return &ParsedError{Status: status, Message: msg}
}

// RefreshCredentials implements Refresher via the Refresh hook; nil when the
// executor has no refresh path (base.js returns null).
func (b *Base) RefreshCredentials(ctx context.Context, p *ProviderInfo, cred Credential) (*Credential, error) {
	if b.Hooks.Refresh == nil {
		return nil, nil
	}
	return b.Hooks.Refresh(ctx, b, p, cred)
}

// Execute runs the base.js execute() loop: per base URL — build URL,
// transform body, build headers, POST with a connect timeout; per-status
// retry config retries the same URL in place; shouldRetry (429) and network
// errors advance to the next URL; caller aborts propagate.
func (b *Base) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: b.ProviderID}
	}
	bodyMap, isObj := decodeBody(body)
	req := &Request{
		Provider: p,
		Cred:     cred,
		Model:    ModelOf(bodyMap),
		RawBody:  body,
		State:    map[string]any{},
	}
	if isObj {
		req.Body = bodyMap
	}
	req.Stream = StreamRequested(bodyMap) || p.ForceStream

	fallbackCount := b.fallbackCount(p)
	retryCfg := retryConfigFor(p)
	attemptsByURL := map[int]int{}
	var lastErr error
	var lastStatus int

	for urlIndex := 0; urlIndex < fallbackCount; urlIndex++ {
		// Per-attempt request state: transforms run per URL in JS and may
		// mutate the body, so each attempt starts from a pristine clone.
		att := &Request{
			Provider: p, Cred: cred, Model: req.Model, Stream: req.Stream,
			RawBody: body, State: map[string]any{},
		}
		if isObj {
			att.Body = cloneMap(bodyMap)
		}

		url, err := b.buildURL(att, urlIndex)
		if err != nil {
			return nil, err
		}
		transformed, err := b.transformBody(att)
		if err != nil {
			return nil, err
		}
		payload := body
		if transformed != nil {
			payload, err = json.Marshal(transformed)
			if err != nil {
				return nil, err
			}
			// Transform may have flipped the stream flag (codex/commandcode
			// force stream:true upstream).
			att.Stream = StreamRequested(transformed) || p.ForceStream
		}
		headers, err := b.buildHeaders(att, url)
		if err != nil {
			return nil, err
		}
		// User per-provider override wins over registry headers
		// (base.js: Object.assign(headers, providerOverrides.headers)).
		for k, v := range cred.OverrideHeaders {
			headers[k] = v
		}

		resp, err := doPost(ctx, url, headers, payload, connectTimeout(p))
		if err != nil {
			// Caller abort (not our connect timeout) propagates — base.js:
			// `if (error.name === "AbortError" && !isConnectTimeout) throw`.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			// Network/fetch exceptions map to the 502 retry entry.
			entry := resolveRetryEntryPtr(retryCfg, 502)
			if entry.Attempts > 0 && attemptsByURL[urlIndex] < entry.Attempts {
				attemptsByURL[urlIndex]++
				if serr := SleepFunc(ctx, time.Duration(entry.DelayMs)*time.Millisecond); serr != nil {
					return nil, serr
				}
				urlIndex-- // retry same URL
				continue
			}
			if urlIndex+1 < fallbackCount {
				continue
			}
			return nil, err
		}

		// In-place retry for configured statuses (base.js tryRetry).
		entry := resolveRetryEntryPtr(retryCfg, resp.StatusCode)
		if entry.Attempts > 0 && attemptsByURL[urlIndex] < entry.Attempts {
			attemptsByURL[urlIndex]++
			drainClose(resp)
			if serr := SleepFunc(ctx, time.Duration(entry.DelayMs)*time.Millisecond); serr != nil {
				return nil, serr
			}
			urlIndex-- // retry same URL
			continue
		}

		if b.shouldRetry(resp.StatusCode, urlIndex, fallbackCount) {
			lastStatus = resp.StatusCode
			drainClose(resp)
			continue
		}

		result := &ExecResult{Response: resp, URL: url, Headers: headers, TransformedBody: payload}
		if b.Hooks.WrapResponse != nil {
			wrapped, format, werr := b.Hooks.WrapResponse(resp, att)
			if werr != nil {
				resp.Body.Close()
				return nil, werr
			}
			result.Response = wrapped
			result.ResponseFormat = format
		}
		return result, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all %d URLs failed with status %d", fallbackCount, lastStatus)
}

func resolveRetryEntryPtr(cfg map[int]RetryEntry, status int) RetryEntry {
	e, ok := cfg[status]
	return resolveRetryEntry(&e, ok)
}

func connectTimeout(p *ProviderInfo) time.Duration {
	if p != nil && p.TimeoutMs > 0 {
		return time.Duration(p.TimeoutMs) * time.Millisecond
	}
	return 60 * time.Second // FETCH_CONNECT_TIMEOUT_MS
}

// doPost POSTs payload and returns once response headers arrive. The connect
// timeout (base.js: abort if upstream doesn't return headers within
// FETCH_CONNECT_TIMEOUT_MS) is enforced with a timer that is disarmed as
// soon as headers land; the context is cancelled when the body is closed.
func doPost(ctx context.Context, url string, headers map[string]string, payload []byte, timeout time.Duration) (*http.Response, error) {
	reqCtx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(timeout, cancel)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		timer.Stop()
		cancel()
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		timer.Stop()
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Connect timeout surfaces as a retryable network error, not the
		// caller's AbortError (base.js converts it the same way).
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	timer.Stop()
	resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   bool
}

func (c *cancelOnCloseBody) Close() error {
	err := c.ReadCloser.Close()
	if !c.once {
		c.once = true
		c.cancel()
	}
	return err
}

func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}

var errAbort = errors.New("request aborted")

// resolveOpenAICompatibleAPIType mirrors services/provider.js
// resolveOpenAICompatibleApiType: stored providerSpecificData.apiType wins;
// legacy node ids embed the type ("openai-compatible-<chat|responses>-<uuid>").
func resolveOpenAICompatibleAPIType(provider string, cred Credential) string {
	if t := cred.SpecificString("apiType"); t == "chat" || t == "responses" {
		return t
	}
	if strings.Contains(provider, "responses") {
		return "responses"
	}
	return "chat"
}

// jsonDecoder decodes with UseNumber so re-marshalling preserves numeric
// literals as written instead of reformatting floats.
func jsonDecoder(b []byte) *json.Decoder {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d
}
