package app

import (
	"testing"

	"9router-go/internal/chatcore"
	"9router-go/internal/db"
)

func TestWireKeyLimiter(t *testing.T) {
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	defer store.Close()

	svc := chatcore.NewService(chatcore.Service{})
	if svc.KeyLimiter != nil {
		t.Fatal("KeyLimiter set before wiring")
	}
	WireKeyLimiter(svc, store)
	if svc.KeyLimiter == nil {
		t.Fatal("KeyLimiter not assigned by WireKeyLimiter")
	}
	// Keys without records/limits are never rejected (fail-open).
	if rej := svc.KeyLimiter.Check("sk-unrecorded"); rej != nil {
		t.Fatalf("unexpected rejection: %+v", rej)
	}
	if KeyLimiterImpl(store) == nil {
		t.Fatal("KeyLimiterImpl returned nil")
	}
	// Nil-service wiring is a no-op, not a panic.
	WireKeyLimiter(nil, store)
}
