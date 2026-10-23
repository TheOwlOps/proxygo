package chatcore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Combo handling — port of open-sse/services/combo.js handleComboChat +
// rotation. (The fusion strategy — panel fan-out + judge synthesis — is
// NOT ported in this phase; Service.HandleChat treats a "fusion" combo
// strategy as fallback. See the Team D report TODO list.)

// comboRotationState tracks round-robin position per combo name
// (combo.js comboRotationState).
type comboRotationState struct {
	mu    sync.Mutex
	state map[string]*rotationEntry
}

type rotationEntry struct {
	index               int
	consecutiveUseCount int
}

func newComboRotationState() *comboRotationState {
	return &comboRotationState{state: map[string]*rotationEntry{}}
}

func normalizeStickyLimit(v int) int {
	if v > 0 {
		return v
	}
	return 1
}

// rotated ports getRotatedModels: only "round-robin" rotates; the sticky
// limit keeps one model for N consecutive requests before advancing.
func (c *comboRotationState) rotated(models []string, comboName, strategy string, stickyLimit int) []string {
	if len(models) <= 1 || strategy != "round-robin" {
		return models
	}
	limit := normalizeStickyLimit(stickyLimit)
	key := comboName
	if key == "" {
		key = "__default__"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.state[key]
	if entry == nil {
		entry = &rotationEntry{}
		c.state[key] = entry
	}
	currentIndex := entry.index % len(models)
	rotated := make([]string, 0, len(models))
	rotated = append(rotated, models[currentIndex:]...)
	rotated = append(rotated, models[:currentIndex]...)
	nextUse := entry.consecutiveUseCount + 1
	if nextUse >= limit {
		entry.index = (currentIndex + 1) % len(models)
		entry.consecutiveUseCount = 0
	} else {
		entry.index = currentIndex
		entry.consecutiveUseCount = nextUse
	}
	return rotated
}

// reset clears rotation state (combo.js resetComboRotation).
func (c *comboRotationState) reset(comboName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if comboName != "" {
		delete(c.state, comboName)
	} else {
		c.state = map[string]*rotationEntry{}
	}
}

// ResetComboRotation clears the round-robin rotation state for one combo
// (combo.js resetComboRotation(comboName)). The rotation state is keyed
// by combo NAME in both the JS and this port — callers pass the combo's
// name (the combos route resets the previous name and, on rename, the new
// name too). An empty name clears ALL combos, exactly like the JS
// no-argument call. Safe on a zero-value Service.
func (s *Service) ResetComboRotation(comboName string) {
	if s == nil || s.rotation == nil {
		return
	}
	s.rotation.reset(comboName)
}

// ResetAllComboRotation clears rotation state for every combo
// (combo.js resetComboRotation() with no argument — the settings route
// calls it when comboStrategy / comboStickyRoundRobinLimit /
// comboStrategies change).
func (s *Service) ResetAllComboRotation() {
	s.ResetComboRotation("")
}

// IsZeroContentResponse ports combo.js isZeroContentResponse: a 2xx JSON
// body with zero usable content (empty choices / empty Claude content
// without a normal stop reason) counts as a failure for combo fallback.
func IsZeroContentResponse(data map[string]any) bool {
	if data == nil {
		return false
	}
	if choices, ok := data["choices"].([]any); ok {
		if len(choices) == 0 {
			return true
		}
		choice, _ := choices[0].(map[string]any)
		if choice == nil {
			return true
		}
		msg, _ := choice["message"].(map[string]any)
		if msg == nil {
			msg, _ = choice["delta"].(map[string]any)
		}
		hasContent := false
		switch content := msg["content"].(type) {
		case string:
			hasContent = strings.TrimSpace(content) != ""
		case []any:
			hasContent = len(content) > 0
		}
		hasToolCalls := false
		if tc, ok := msg["tool_calls"].([]any); ok && len(tc) > 0 {
			hasToolCalls = true
		}
		if _, ok := msg["function_call"]; ok {
			hasToolCalls = true
		}
		hasReasoning := false
		if rc, ok := msg["reasoning_content"].(string); ok && strings.TrimSpace(rc) != "" {
			hasReasoning = true
		}
		finish, _ := choice["finish_reason"].(string)
		isNormalFinish := finish == "stop" || finish == "length" || finish == "tool_calls" || finish == "function_call"
		if !hasContent && !hasToolCalls && !hasReasoning && (!isNormalFinish || finish == "in_progress" || finish == "incomplete") {
			return true
		}
	}
	if content, ok := data["content"].([]any); ok {
		hasContent := false
		for _, raw := range content {
			block, _ := raw.(map[string]any)
			if block == nil {
				continue
			}
			if block["type"] == "text" {
				if t, ok := block["text"].(string); ok && strings.TrimSpace(t) != "" {
					hasContent = true
				}
			}
			if block["type"] == "tool_use" {
				hasContent = true
			}
		}
		stopReason, _ := data["stop_reason"].(string)
		if !hasContent && (stopReason == "" || stopReason == "in_progress" || stopReason == "incomplete") {
			return true
		}
	}
	return false
}

// comboOutcome is one model's attempt result in a combo: either an HTTP
// response (success or failure) — the loop reads error bodies by cloning.
type comboAttempt struct {
	resp *http.Response
	err  error
}

// HandleCombo runs the combo fallback loop (combo.js handleComboChat):
// models are tried in (possibly rotated) order; a 2xx returns immediately
// — except a non-final model whose JSON body has zero usable content,
// which falls through; a failure falls through only when
// CheckFallbackError says so; transient 502/503/504 with a short cooldown
// wait before the next model. When everything fails: 503 with the last
// error (or the earliest Retry-After when models reported one).
//
// tryOne performs a single-model attempt for a (possibly rewritten) body.
func (s *Service) HandleCombo(ctx context.Context, req ChatRequest, models []string, comboName, strategy string, stickyLimit int, tryOne func(ctx context.Context, req ChatRequest, modelStr string) *http.Response) *http.Response {
	rotated := s.rotation.rotated(models, comboName, strategy, stickyLimit)
	var lastError string
	var lastStatus int
	var earliestRetryAfter time.Time

	for i, modelStr := range rotated {
		resp := tryOne(ctx, req, modelStr)
		if resp == nil {
			lastError = "no response"
			if lastStatus == 0 {
				lastStatus = StatusServerError
			}
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			isLast := i == len(rotated)-1
			if !isLast && strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
				peeked, isZero := peekZeroContent(resp)
				resp = peeked
				if isZero {
					lastError = "Zero usable content"
					lastStatus = 200
					continue
				}
			}
			return resp
		}

		// Extract error info from a clone of the body (the original is
		// returned untouched when no fallback applies).
		errorText := resp.Status
		var retryAfter time.Time
		if cloned := cloneResponseBody(resp); cloned != nil {
			var errBody map[string]any
			if json.Unmarshal(cloned, &errBody) == nil && errBody != nil {
				if e, ok := errBody["error"].(map[string]any); ok {
					if m, ok := e["message"].(string); ok {
						errorText = m
					}
				}
				if errorText == resp.Status {
					if m, ok := errBody["message"].(string); ok {
						errorText = m
					}
				}
				if ra, ok := errBody["retryAfter"].(string); ok {
					if t, err := time.Parse(time.RFC3339, ra); err == nil {
						retryAfter = t
					}
				}
			}
		}
		if !retryAfter.IsZero() && (earliestRetryAfter.IsZero() || retryAfter.Before(earliestRetryAfter)) {
			earliestRetryAfter = retryAfter
		}

		decision := CheckFallbackError(resp.StatusCode, errorText, 0, "")
		if !decision.ShouldFallback {
			drainBody(resp)
			return resp
		}
		// Transient errors: wait out a short cooldown (≤5s) before the
		// next model so a briefly-overloaded provider can recover.
		if decision.CooldownMs > 0 && decision.CooldownMs <= 5000 &&
			(resp.StatusCode == 503 || resp.StatusCode == 502 || resp.StatusCode == 504) {
			if err := sleepCtx(ctx, time.Duration(decision.CooldownMs)*time.Millisecond); err != nil {
				drainBody(resp)
				return ErrorResponse(StatusClientClosedRequest, "Request aborted", nil)
			}
		}
		lastError = errorText
		if lastStatus == 0 {
			lastStatus = resp.StatusCode
		}
		drainBody(resp)
	}

	// All models failed — 503 (not 406: the request isn't invalid, the
	// providers are unavailable; combo.js comment).
	status := lastStatus
	if strings.Contains(strings.ToLower(lastError), "no credentials") {
		status = StatusServiceUnavailable
	}
	if status == 0 {
		status = StatusServiceUnavailable
	}
	msg := lastError
	if msg == "" {
		msg = "All combo models unavailable"
	}
	if !earliestRetryAfter.IsZero() {
		return UnavailableResponse(status, msg, earliestRetryAfter, FormatRetryAfter(earliestRetryAfter), nil)
	}
	return ErrorResponse(status, msg, nil)
}

// peekZeroContent reads a 2xx JSON body and reports zero-content, leaving
// the response readable afterwards.
func peekZeroContent(resp *http.Response) (*http.Response, bool) {
	if resp.Body == nil {
		return resp, false
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(strings.NewReader(""))
		return resp, false
	}
	resp.Body = io.NopCloser(bytesReader(raw))
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return resp, false
	}
	return resp, IsZeroContentResponse(data)
}
