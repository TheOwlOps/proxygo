package chatcore

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// UsageEvent describes one finished chat attempt for the usage sink.
// It mirrors the JS saveUsageStats / buildRequestDetail inputs
// (open-sse/handlers/chatCore/requestDetail.js): the app layer turns it
// into a usageHistory row plus a request-detail record. Status uses
// the JS detail vocabulary: "success" | "error".
type UsageEvent struct {
	Timestamp        time.Time
	Provider         string
	Model            string
	ConnectionID     string
	APIKey           string
	Endpoint         string
	PromptTokens     int64
	CompletionTokens int64
	Status           string
	TTFTMs           int64
	TotalMs          int64
	RequestBody      map[string]any
	ResponseBody     any // parsed JSON for buffered replies, raw SSE text for streams
}

// usageTap wraps a response body and, as the client consumes it,
// extracts token usage (and captures the payload for the request
// detail) without altering a single byte. The sink fires exactly
// once, at EOF or Close, whichever comes first. It is fail-open by
// construction: parse problems simply yield zero tokens.
type usageTap struct {
	rc      io.ReadCloser
	stream  bool
	started time.Time
	firstAt time.Time
	fired   bool
	onDone  func(p, c int64, ttftMs, totalMs int64, payload any)
	lineBuf []byte
	rawBuf  bytes.Buffer
	rawCap  int
	prompt  int64
	comple  int64
	haveUse bool
}

const (
	usageJSONCap = 8 << 20   // buffered (non-stream) payload capture cap
	usageSSECap  = 256 << 10 // stream payload capture cap (usage scan is unbounded)
)

func newUsageTap(rc io.ReadCloser, stream bool, started time.Time, onDone func(p, c int64, ttftMs, totalMs int64, payload any)) *usageTap {
	cap := usageJSONCap
	if stream {
		cap = usageSSECap
	}
	return &usageTap{rc: rc, stream: stream, started: started, rawCap: cap, onDone: onDone}
}

func (t *usageTap) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		if t.firstAt.IsZero() {
			t.firstAt = time.Now()
		}
		chunk := p[:n]
		if t.rawBuf.Len() < t.rawCap {
			room := t.rawCap - t.rawBuf.Len()
			if len(chunk) > room {
				t.rawBuf.Write(chunk[:room])
			} else {
				t.rawBuf.Write(chunk)
			}
		}
		if t.stream {
			t.scanSSE(chunk)
		}
	}
	if err == io.EOF {
		t.finish()
	}
	return n, err
}

func (t *usageTap) Close() error {
	err := t.rc.Close()
	t.finish()
	return err
}

// Unwrap lets http infrastructure (Flusher detection etc.) reach the
// underlying body if it needs to.
func (t *usageTap) Unwrap() io.ReadCloser { return t.rc }

func (t *usageTap) scanSSE(chunk []byte) {
	t.lineBuf = append(t.lineBuf, chunk...)
	for {
		i := bytes.IndexByte(t.lineBuf, '\n')
		if i < 0 {
			return
		}
		line := strings.TrimRight(string(t.lineBuf[:i]), "\r")
		t.lineBuf = t.lineBuf[i+1:]
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(data), &m) == nil {
			if p, c, ok := usageFromMap(m); ok {
				t.prompt, t.comple, t.haveUse = p, c, true
			}
		}
	}
}

func (t *usageTap) finish() {
	if t.fired || t.onDone == nil {
		return
	}
	t.fired = true
	now := time.Now()
	var ttft int64
	if !t.firstAt.IsZero() {
		ttft = t.firstAt.Sub(t.started).Milliseconds()
	}
	total := now.Sub(t.started).Milliseconds()
	var payload any
	if t.stream {
		if t.rawBuf.Len() > 0 {
			payload = t.rawBuf.String()
		}
	} else {
		raw := t.rawBuf.Bytes()
		if len(raw) > 0 {
			var m map[string]any
			if json.Unmarshal(raw, &m) == nil {
				payload = m
				if p, c, ok := usageFromMap(m); ok {
					t.prompt, t.comple, t.haveUse = p, c, true
				}
			} else {
				payload = string(raw)
			}
		}
	}
	t.onDone(t.prompt, t.comple, ttft, total, payload)
}

// usageFromMap extracts (prompt, completion) tokens from any of the
// client-facing usage shapes: OpenAI usage{}, Claude usage{}
// (input/output), Gemini usageMetadata{}, OpenAI Responses
// response{usage{}}, Claude message_start message{usage{}}.
func usageFromMap(m map[string]any) (int64, int64, bool) {
	if m == nil {
		return 0, 0, false
	}
	if u, ok := m["usage"].(map[string]any); ok {
		p := tokVal(u, "prompt_tokens", "input_tokens")
		c := tokVal(u, "completion_tokens", "output_tokens")
		return p, c, true
	}
	if u, ok := m["usageMetadata"].(map[string]any); ok {
		p := tokVal(u, "promptTokenCount")
		c := tokVal(u, "candidatesTokenCount")
		return p, c, true
	}
	if r, ok := m["response"].(map[string]any); ok {
		if p, c, ok2 := usageFromMap(r); ok2 {
			return p, c, true
		}
	}
	if msg, ok := m["message"].(map[string]any); ok {
		if p, c, ok2 := usageFromMap(msg); ok2 {
			return p, c, true
		}
	}
	return 0, 0, false
}

func tokVal(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int64(v)
		case json.Number:
			if n, err := v.Int64(); err == nil {
				return n
			}
		}
	}
	return 0
}

// recordUsageTap attaches the tap to a successful response and wires
// its completion into the sink. No-op when no sink is configured.
func (s *Service) recordUsageTap(req ChatRequest, provider, model, connID string, respBody io.ReadCloser, contentType string, started time.Time) io.ReadCloser {
	if s.UsageSink == nil || respBody == nil {
		return respBody
	}
	stream := strings.Contains(contentType, "text/event-stream")
	base := UsageEvent{
		Timestamp:    started,
		Provider:     provider,
		Model:        model,
		ConnectionID: connID,
		APIKey:       req.APIKey,
		Endpoint:     req.Endpoint,
		Status:       "success",
		RequestBody:  req.Body,
	}
	sink := s.UsageSink
	return newUsageTap(respBody, stream, started, func(p, c, ttft, total int64, payload any) {
		ev := base
		ev.PromptTokens = p
		ev.CompletionTokens = c
		ev.TTFTMs = ttft
		ev.TotalMs = total
		ev.ResponseBody = payload
		safeUsageSink(sink, ev)
	})
}

// recordUsageError reports a terminally failed attempt immediately
// (error bodies carry no usage in any client format).
func (s *Service) recordUsageError(req ChatRequest, provider, model, connID string, started time.Time) {
	if s.UsageSink == nil {
		return
	}
	safeUsageSink(s.UsageSink, UsageEvent{
		Timestamp:    started,
		Provider:     provider,
		Model:        model,
		ConnectionID: connID,
		APIKey:       req.APIKey,
		Endpoint:     req.Endpoint,
		Status:       "error",
		TotalMs:      time.Since(started).Milliseconds(),
		RequestBody:  req.Body,
	})
}

// safeUsageSink isolates the chat path from sink panics (fail-open,
// same contract as the RTK token saver and the PII guard).
func safeUsageSink(sink func(UsageEvent), ev UsageEvent) {
	defer func() { _ = recover() }()
	sink(ev)
}
