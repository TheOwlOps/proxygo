package app

import (
	"testing"

	"proxygo/internal/breaker"
	"proxygo/internal/chatcore"
)

func TestNewBreakerFromSettingsDisabled(t *testing.T) {
	if cb := NewBreakerFromSettings(nil); cb != nil {
		t.Fatal("nil settings must yield nil breaker")
	}
	if cb := NewBreakerFromSettings(map[string]any{}); cb != nil {
		t.Fatal("missing circuitBreakerEnabled must yield nil breaker")
	}
	if cb := NewBreakerFromSettings(map[string]any{"circuitBreakerEnabled": false}); cb != nil {
		t.Fatal("circuitBreakerEnabled:false must yield nil breaker")
	}
}

func TestNewBreakerFromSettingsEnabled(t *testing.T) {
	cb := NewBreakerFromSettings(map[string]any{
		"circuitBreakerEnabled":          true,
		"circuitBreakerFailureThreshold": float64(2),
		"circuitBreakerOpenSeconds":      float64(60),
	})
	if cb == nil {
		t.Fatal("enabled settings must yield a breaker")
	}
	// Threshold 2: two failures open the circuit.
	if !cb.Allow("openai", "c1") {
		t.Fatal("fresh circuit must allow")
	}
	cb.OnResult("openai", "c1", false)
	if !cb.Allow("openai", "c1") {
		t.Fatal("one failure below threshold 2 must allow")
	}
	cb.OnResult("openai", "c1", false)
	if cb.Allow("openai", "c1") {
		t.Fatal("threshold 2 reached: circuit must be open")
	}
}

func TestBreakerAdapterSnapshot(t *testing.T) {
	cb := NewBreakerFromSettings(map[string]any{"circuitBreakerEnabled": true})
	svc := chatcore.NewService(chatcore.Service{})
	svc.Breaker = cb
	cb.OnResult("openai", "c1", false)
	snap, ok := svc.BreakerSnapshot().([]breaker.KeyStats)
	if !ok {
		t.Fatalf("snapshot type = %T, want []breaker.KeyStats", svc.BreakerSnapshot())
	}
	if len(snap) != 1 || snap[0].Provider != "openai" || snap[0].TotalFailures != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestWireBreaker(t *testing.T) {
	svc := chatcore.NewService(chatcore.Service{})
	if WireBreaker(svc, map[string]any{}) {
		t.Fatal("WireBreaker must report false when the feature is off")
	}
	if svc.Breaker != nil {
		t.Fatal("WireBreaker must leave Breaker nil when the feature is off")
	}
	if !WireBreaker(svc, map[string]any{"circuitBreakerEnabled": true}) {
		t.Fatal("WireBreaker must report true when the feature is on")
	}
	if svc.Breaker == nil {
		t.Fatal("WireBreaker must assign the breaker when the feature is on")
	}
	if WireBreaker(nil, map[string]any{"circuitBreakerEnabled": true}) {
		t.Fatal("WireBreaker must be nil-service safe")
	}
}
