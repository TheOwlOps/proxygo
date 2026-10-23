// Package chatcore is the Go port of the chat request flow:
// src/sse/handlers/chat.js (combo expansion + account-selection loop) on
// top of open-sse/handlers/chatCore.js (detect format → translate →
// dispatch → refresh/retry → stream setup).
//
// The package is deliberately decoupled: providers, translation,
// execution and credential storage live behind the narrow interfaces in
// chatcore.go, implemented by fakes in tests and by adapters over
// internal/providers, internal/translator, internal/executors and
// internal/db in production (wired by the parent).
package chatcore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTP status codes used by the flow (config/runtimeConfig.js HTTP_STATUS).
const (
	StatusBadRequest          = 400
	StatusUnauthorized        = 401
	StatusPaymentRequired     = 402
	StatusForbidden           = 403
	StatusNotFound            = 404
	StatusNotAcceptable       = 406
	StatusRequestTimeout      = 408
	StatusRateLimited         = 429
	StatusServerError         = 500
	StatusBadGateway          = 502
	StatusServiceUnavailable  = 503
	StatusGatewayTimeout      = 504
	StatusClientClosedRequest = 499 // chatCore maps AbortError → 499
)

// errorTypes / defaultErrorMessages port config/errorConfig.js.
var errorTypes = map[int][2]string{
	400: {"invalid_request_error", "bad_request"},
	401: {"authentication_error", "invalid_api_key"},
	402: {"billing_error", "payment_required"},
	403: {"permission_error", "insufficient_quota"},
	404: {"invalid_request_error", "model_not_found"},
	406: {"invalid_request_error", "model_not_supported"},
	429: {"rate_limit_error", "rate_limit_exceeded"},
	500: {"server_error", "internal_server_error"},
	502: {"server_error", "bad_gateway"},
	503: {"server_error", "service_unavailable"},
	504: {"server_error", "gateway_timeout"},
}

var defaultErrorMessages = map[int]string{
	400: "Bad request",
	401: "Invalid API key provided",
	402: "Payment required",
	403: "You exceeded your current quota",
	404: "Model not found",
	406: "Model not supported",
	429: "Rate limit exceeded",
	500: "Internal server error",
	502: "Bad gateway - upstream provider error",
	503: "Service temporarily unavailable",
	504: "Gateway timeout",
}

// BuildErrorBody ports utils/error.js buildErrorBody (OpenAI-compatible
// error envelope).
func BuildErrorBody(statusCode int, message string) map[string]any {
	typ, code := "invalid_request_error", ""
	if statusCode >= 500 {
		typ = "server_error"
		code = "internal_server_error"
	}
	if et, ok := errorTypes[statusCode]; ok {
		typ, code = et[0], et[1]
	}
	if message == "" {
		message = defaultErrorMessages[statusCode]
	}
	if message == "" {
		message = "An error occurred"
	}
	return map[string]any{
		"error": map[string]any{"message": message, "type": typ, "code": code},
	}
}

// ErrorResponse builds the JSON error HTTP response (utils/error.js
// errorResponse, with CORS header like the JS).
func ErrorResponse(statusCode int, message string, extraHeaders http.Header) *http.Response {
	raw, _ := json.Marshal(BuildErrorBody(statusCode, message))
	h := http.Header{
		"Content-Type":                []string{"application/json"},
		"Access-Control-Allow-Origin": []string{"*"},
	}
	for k, vs := range extraHeaders {
		h[k] = vs
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(string(raw))),
	}
}

// Result mirrors the JS chatCore result object: {success, status, error,
// response, resetsAtMs}. HandleChat returns the *http.Response directly on
// success; failures inside the account/combo loops use Result semantics
// internally (see outcome in chatcore.go).
type Result struct {
	Success  bool
	Status   int
	Error    string
	Response *http.Response
	ResetsAt time.Time // provider-reported quota reset (codex/antigravity)
}

// ErrorResult ports utils/error.js createErrorResult.
func ErrorResult(statusCode int, message string, resetsAt time.Time, extraHeaders http.Header) *Result {
	return &Result{
		Success:  false,
		Status:   statusCode,
		Error:    message,
		Response: ErrorResponse(statusCode, message, extraHeaders),
		ResetsAt: resetsAt,
	}
}

// FormatProviderError ports utils/error.js formatProviderError:
// "[<code>]: <message>".
func FormatProviderError(err error, provider, model string, statusCode int) string {
	code := "FETCH_FAILED"
	if statusCode != 0 {
		code = fmt.Sprint(statusCode)
	}
	msg := "Unknown error"
	if err != nil && err.Error() != "" {
		msg = err.Error()
	}
	return fmt.Sprintf("[%s]: %s", code, msg)
}

// ParseUpstreamError ports utils/error.js parseUpstreamError: an
// executor-specific parser (when the executor implements ParseErrorFunc)
// wins; otherwise error.message / message / error from the JSON body, else
// the raw text, else the default message for the status.
func ParseUpstreamError(status int, bodyText string, parseFn func(status int, bodyText string) *ParsedErrorLike) (int, string, time.Time) {
	if parseFn != nil {
		if parsed := parseFn(status, bodyText); parsed != nil {
			msg := parsed.Message
			if msg == "" {
				msg = defaultErrorMessages[status]
			}
			if msg == "" {
				msg = fmt.Sprintf("Upstream error: %d", status)
			}
			st := parsed.Status
			if st == 0 {
				st = status
			}
			return st, msg, parsed.ResetsAt
		}
	}
	message := ""
	var parsed map[string]any
	if json.Unmarshal([]byte(bodyText), &parsed) == nil && parsed != nil {
		if e, ok := parsed["error"].(map[string]any); ok {
			if m, ok := e["message"].(string); ok {
				message = m
			}
		}
		if message == "" {
			if m, ok := parsed["message"].(string); ok {
				message = m
			}
		}
		if message == "" {
			switch e := parsed["error"].(type) {
			case string:
				message = e
			case map[string]any:
				raw, _ := json.Marshal(e)
				message = string(raw)
			}
		}
	} else {
		message = bodyText
	}
	if message == "" {
		message = defaultErrorMessages[status]
	}
	if message == "" {
		message = fmt.Sprintf("Upstream error: %d", status)
	}
	return status, message, time.Time{}
}

// ParsedErrorLike is the minimal shape chatcore needs from an executor's
// parseError result (executors.ParsedError satisfies it via the parent's
// adapter — chatcore does not import internal/executors).
type ParsedErrorLike struct {
	Status   int
	Message  string
	ResetsAt time.Time
}

// --- Account fallback classification (services/accountFallback.js +
// config/errorConfig.js ERROR_RULES) ---

const (
	cooldownLongMs         = 2 * 60 * 1000
	cooldownShortMs        = 5 * 1000
	transientCooldownMs    = 30 * 1000
	maxRateLimitCooldownMs = 30 * 60 * 1000
	backoffBaseMs          = 2000
	backoffMaxMs           = 5 * 60 * 1000
	backoffMaxLevel        = 15
)

type errorRule struct {
	provider   string
	text       string
	status     int
	cooldownMs int
	backoff    bool
}

// errorRules ports ERROR_RULES verbatim (order = priority; text rules
// first, then status rules).
var errorRules = []errorRule{
	{provider: "codex", text: "model is not supported when using codex with a chatgpt account", cooldownMs: maxRateLimitCooldownMs},
	{text: "no credentials", cooldownMs: cooldownLongMs},
	{text: "request not allowed", cooldownMs: cooldownShortMs},
	{text: "improperly formed request", cooldownMs: cooldownLongMs},
	{text: "rate limit", backoff: true},
	{text: "too many requests", backoff: true},
	{text: "quota exceeded", backoff: true},
	{text: "capacity", backoff: true},
	{text: "overloaded", backoff: true},
	{status: 401, cooldownMs: cooldownLongMs},
	{status: 402, cooldownMs: cooldownLongMs},
	{status: 403, cooldownMs: cooldownLongMs},
	{status: 404, cooldownMs: cooldownLongMs},
	{status: 429, backoff: true},
}

// QuotaCooldown ports getQuotaCooldown: exponential backoff 2s,4s,8s…
// capped at 5 minutes.
func QuotaCooldown(backoffLevel int) int {
	level := backoffLevel - 1
	if level < 0 {
		level = 0
	}
	cooldown := backoffBaseMs << level
	if cooldown > backoffMaxMs {
		cooldown = backoffMaxMs
	}
	return cooldown
}

// FallbackDecision is checkFallbackError's result.
type FallbackDecision struct {
	ShouldFallback  bool
	CooldownMs      int
	NewBackoffLevel int // -1 when the rule carries no backoff level
}

// CheckFallbackError ports services/accountFallback.js checkFallbackError:
// rules match top-to-bottom (a rule matches on text OR status, provider-
// scoped rules only for that provider); unmatched 4xx (except the
// account-scoped 401/402/403/429) do NOT fall back — a request-scoped 400
// says nothing about the credential (see the long comment in the JS);
// anything else unmatched gets the transient cooldown + fallback.
func CheckFallbackError(status int, errorText string, backoffLevel int, provider string) FallbackDecision {
	lower := strings.ToLower(errorText)
	for _, rule := range errorRules {
		if rule.provider != "" && rule.provider != provider {
			continue
		}
		if rule.text != "" && lower != "" && strings.Contains(lower, rule.text) {
			if rule.backoff {
				newLevel := backoffLevel + 1
				if newLevel > backoffMaxLevel {
					newLevel = backoffMaxLevel
				}
				return FallbackDecision{ShouldFallback: true, CooldownMs: QuotaCooldown(newLevel), NewBackoffLevel: newLevel}
			}
			return FallbackDecision{ShouldFallback: true, CooldownMs: rule.cooldownMs, NewBackoffLevel: -1}
		}
		if rule.status != 0 && rule.status == status {
			if rule.backoff {
				newLevel := backoffLevel + 1
				if newLevel > backoffMaxLevel {
					newLevel = backoffMaxLevel
				}
				return FallbackDecision{ShouldFallback: true, CooldownMs: QuotaCooldown(newLevel), NewBackoffLevel: newLevel}
			}
			return FallbackDecision{ShouldFallback: true, CooldownMs: rule.cooldownMs, NewBackoffLevel: -1}
		}
	}
	if status >= 400 && status < 500 && status != 401 && status != 402 && status != 403 && status != 429 {
		return FallbackDecision{ShouldFallback: false, CooldownMs: 0, NewBackoffLevel: -1}
	}
	return FallbackDecision{ShouldFallback: true, CooldownMs: transientCooldownMs, NewBackoffLevel: -1}
}

// FormatRetryAfter ports formatRetryAfter ("reset after 2m 30s").
func FormatRetryAfter(until time.Time) string {
	diff := time.Until(until)
	if diff <= 0 {
		return "reset after 0s"
	}
	totalSec := int((diff + time.Second - 1) / time.Second)
	h := totalSec / 3600
	m := (totalSec % 3600) / 60
	s := totalSec % 60
	var parts []string
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	if s > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", s))
	}
	return "reset after " + strings.Join(parts, " ")
}

// UnavailableResponse ports utils/error.js unavailableResponse: the
// all-accounts-rate-limited response with a Retry-After header (seconds
// until the earliest account resets).
func UnavailableResponse(statusCode int, message string, retryAfter time.Time, retryAfterHuman string, extraHeaders http.Header) *http.Response {
	retryAfterSec := int(time.Until(retryAfter) / time.Second)
	if retryAfterSec < 1 {
		retryAfterSec = 1
	}
	msg := fmt.Sprintf("%s (%s)", message, retryAfterHuman)
	raw, _ := json.Marshal(map[string]any{"error": map[string]any{"message": msg}})
	h := http.Header{"Content-Type": []string{"application/json"}, "Retry-After": []string{fmt.Sprint(retryAfterSec)}}
	for k, vs := range extraHeaders {
		h[k] = vs
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(string(raw))),
	}
}
