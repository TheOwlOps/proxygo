package app

import (
	"time"

	"9router-go/internal/breaker"
	"9router-go/internal/chatcore"
)

// breakerAdapter exposes internal/breaker to chatcore: Allow/OnResult
// delegate directly, and Snapshot() any satisfies the optional stats
// interface chatcore.Service.BreakerSnapshot looks for.
type breakerAdapter struct{ b *breaker.Breaker }

func (a breakerAdapter) Allow(provider, connID string) bool { return a.b.Allow(provider, connID) }

func (a breakerAdapter) OnResult(provider, connID string, success bool) {
	a.b.OnResult(provider, connID, success)
}

// Snapshot returns []breaker.KeyStats (as any, for BreakerSnapshot).
func (a breakerAdapter) Snapshot() any { return a.b.Snapshot() }

// Compile-time checks: the adapter is a chatcore.CircuitBreaker.
var _ chatcore.CircuitBreaker = breakerAdapter{}

// NewBreakerFromSettings builds the chatcore circuit breaker from the
// dashboard settings map (the settings(id=1) JSON document, e.g. a
// db.Record from Store.GetSettings). It returns nil when the feature
// is off (`circuitBreakerEnabled` not true) — the parent assigns the
// result to Service.Breaker unconditionally; nil keeps chatcore's
// behavior byte-identical to before the feature.
//
// Threshold and open duration are read HERE, at wire time (contract:
// live re-reads on every call would be overkill); changing them in
// the dashboard takes effect when the parent re-wires (server start).
func NewBreakerFromSettings(settings map[string]any) chatcore.CircuitBreaker {
	if settings == nil {
		return nil
	}
	if enabled, _ := settings["circuitBreakerEnabled"].(bool); !enabled {
		return nil
	}
	threshold := settingNumber(settings, "circuitBreakerFailureThreshold", breaker.DefaultThreshold)
	openSeconds := settingNumber(settings, "circuitBreakerOpenSeconds", int(breaker.DefaultOpenDuration/time.Second))
	return breakerAdapter{b: breaker.New(threshold, time.Duration(openSeconds)*time.Second)}
}

// WireBreaker constructs the breaker from settings and assigns it to
// the service. Returns true when a breaker was wired (feature on).
func WireBreaker(s *chatcore.Service, settings map[string]any) bool {
	if s == nil {
		return false
	}
	cb := NewBreakerFromSettings(settings)
	if cb == nil {
		return false
	}
	s.Breaker = cb
	return true
}

// settingNumber reads a numeric setting (settings JSON numbers decode
// as float64; plain ints are accepted too), falling back to def.
func settingNumber(settings map[string]any, key string, def int) int {
	switch v := settings[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	case int64:
		if v > 0 {
			return int(v)
		}
	}
	return def
}
