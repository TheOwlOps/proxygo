package app

import (
	"strings"
	"testing"

	"9router-go/internal/chatcore"
	"9router-go/internal/db"
)

// TestTokenSaverWiring proves NewService attaches the RTK TokenSaver and
// that it actually compresses tool_result content through the
// chatcore.TokenSaver interface (fail-open).
func TestTokenSaverWiring(t *testing.T) {
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	defer func() { _ = store.Close() }()

	svc := NewService(store)
	if svc.TokenSaver == nil {
		t.Fatal("NewService must set the RTK TokenSaver")
	}

	payload := strings.Repeat("2024-01-01 INFO worker heartbeat ok status nominal\n", 20)
	body := map[string]any{"messages": []any{
		map[string]any{"role": "tool", "content": payload},
	}}
	svc.TokenSaver.Compress(body, "openai", true)
	got := body["messages"].([]any)[0].(map[string]any)["content"].(string)
	if got == payload || !strings.Contains(got, "duplicate lines") {
		t.Fatalf("TokenSaver did not compress: %.120q", got)
	}

	// Disabled → untouched.
	body2 := map[string]any{"messages": []any{
		map[string]any{"role": "tool", "content": payload},
	}}
	svc.TokenSaver.Compress(body2, "openai", false)
	if body2["messages"].([]any)[0].(map[string]any)["content"] != payload {
		t.Fatal("disabled TokenSaver must not touch the body")
	}

	// The standalone helper works on a bare Service too.
	bare := &chatcore.Service{}
	WireTokenSaver(bare)
	if bare.TokenSaver == nil {
		t.Fatal("WireTokenSaver must set the field")
	}
	WireTokenSaver(nil) // must not panic
}
