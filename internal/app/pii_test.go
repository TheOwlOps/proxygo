package app

import (
	"testing"

	"9router-go/internal/chatcore"
)

func piiTestBody() map[string]any {
	return map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "mail alice@example.com, cccd 001234567890"},
		},
	}
}

func TestPIIGuardDisabledReturnsZero(t *testing.T) {
	body := piiTestBody()
	if n := PIIGuardImpl().Process(body, "openai", false); n != 0 {
		t.Fatalf("disabled guard returned %d, want 0", n)
	}
	msg := body["messages"].([]any)[0].(map[string]any)
	if msg["content"] != "mail alice@example.com, cccd 001234567890" {
		t.Fatalf("disabled guard mutated body: %v", msg["content"])
	}
}

func TestPIIGuardDefaultKeepsNationalID(t *testing.T) {
	body := piiTestBody()
	if n := PIIGuardImpl().Process(body, "openai", true); n != 1 {
		t.Fatalf("default guard returned %d, want 1 (email only)", n)
	}
	msg := body["messages"].([]any)[0].(map[string]any)
	if msg["content"] != "mail [EMAIL], cccd 001234567890" {
		t.Fatalf("content = %v", msg["content"])
	}
}

func TestPIIGuardNationalIDOptIn(t *testing.T) {
	body := piiTestBody()
	if n := NewPIIGuard(true).Process(body, "openai", true); n != 2 {
		t.Fatalf("national-id guard returned %d, want 2", n)
	}
	msg := body["messages"].([]any)[0].(map[string]any)
	if msg["content"] != "mail [EMAIL], cccd [NATIONAL_ID]" {
		t.Fatalf("content = %v", msg["content"])
	}
}

func TestWirePIIGuard(t *testing.T) {
	svc := &chatcore.Service{}
	WirePIIGuard(svc)
	if svc.BodyGuard == nil {
		t.Fatal("WirePIIGuard left BodyGuard nil")
	}
	svc2 := &chatcore.Service{}
	WirePIIGuardWith(svc2, true)
	if svc2.BodyGuard == nil {
		t.Fatal("WirePIIGuardWith left BodyGuard nil")
	}
	WirePIIGuard(nil) // must not panic
	WirePIIGuardWith(nil, true)
}
