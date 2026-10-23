package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxygo/internal/server"
)

// The playground is a self-contained page: the handler must return it
// verbatim with an HTML content type, and the page must carry the
// markers the client-side behavior depends on (title, compare-mode
// toggle, the /v1 endpoints it calls, localStorage key persistence).
func TestPlaygroundHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/playground", nil)
	server.PlaygroundHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want HTML", ct)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	page := string(body)
	for _, marker := range []string{
		"ProxyGo Playground",    // page title
		"Compare mode",          // compare mode toggle
		`id="mode-compare-btn"`, // compare toggle element
		`id="model-a"`,          // compare picker A
		`id="model-b"`,          // compare picker B
		"/v1/chat/completions",  // chat endpoint the page calls
		"/v1/models",            // model list endpoint
		`type="password"`,       // API key input
		"localStorage",          // key persistence
		"proxygo-playground-api-key",
		"temperature",
		"max_tokens",
	} {
		if !strings.Contains(page, marker) {
			t.Errorf("playground page missing marker %q", marker)
		}
	}
	// Single-file page: no external assets may be referenced.
	for _, external := range []string{"src=\"http", "href=\"http", "<link"} {
		if strings.Contains(page, external) {
			t.Errorf("playground page references an external asset (%q)", external)
		}
	}
}
