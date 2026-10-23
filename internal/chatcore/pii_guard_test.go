package chatcore

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// --- F6 BodyGuard test doubles (pii-prefixed to avoid collisions) ---

type piiSettingsSource struct{ s Settings }

func (p piiSettingsSource) Settings() Settings { return p.s }

// piiRecordingGuard mimics a real redactor: it records how it was
// invoked and, only when enabled, scrubs the marker address from the
// first message's string content.
type piiRecordingGuard struct {
	calls   int
	enabled []bool
}

func (g *piiRecordingGuard) Process(body map[string]any, format string, enabled bool) int {
	g.calls++
	g.enabled = append(g.enabled, enabled)
	if !enabled {
		return 0
	}
	msgs, _ := body["messages"].([]any)
	if len(msgs) == 0 {
		return 0
	}
	msg, _ := msgs[0].(map[string]any)
	content, _ := msg["content"].(string)
	if strings.Contains(content, "secret@example.com") {
		msg["content"] = strings.Replace(content, "secret@example.com", "[EMAIL]", 1)
		return 1
	}
	return 0
}

type piiRecordingLogger struct{ infos []string }

func (l *piiRecordingLogger) Debug(string, string) {}
func (l *piiRecordingLogger) Info(tag, msg string) {
	l.infos = append(l.infos, tag+":"+msg)
}
func (l *piiRecordingLogger) Warn(string, string)  {}
func (l *piiRecordingLogger) Error(string, string) {}

func piiGuardSvc(guard BodyGuard, enabled bool, logger Logger, seen *string) *Service {
	accounts := &fakeAccounts{creds: []Credential{{ConnectionID: "c1", AccessToken: "tok"}}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		msgs, _ := body["messages"].([]any)
		if len(msgs) > 0 {
			msg, _ := msgs[0].(map[string]any)
			*seen, _ = msg["content"].(string)
		}
		return jsonResp(200, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}}
	return NewService(Service{
		Providers: &fakeProviders{},
		Accounts:  accounts,
		Executor:  exec,
		BodyGuard: guard,
		Settings:  piiSettingsSource{s: Settings{PIIRedactionEnabled: enabled}},
		Logger:    logger,
	})
}

func piiGuardBody() map[string]any {
	return map[string]any{
		"model":    "openai/gpt-x",
		"messages": []any{map[string]any{"role": "user", "content": "mail secret@example.com please"}},
	}
}

func TestBodyGuardEnabledRedactsAndLogs(t *testing.T) {
	guard := &piiRecordingGuard{}
	logger := &piiRecordingLogger{}
	var seen string
	svc := piiGuardSvc(guard, true, logger, &seen)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body: piiGuardBody(), Endpoint: "/v1/chat/completions", Headers: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if guard.calls != 1 || len(guard.enabled) != 1 || !guard.enabled[0] {
		t.Fatalf("guard calls=%d enabled=%v, want 1 call with enabled=true", guard.calls, guard.enabled)
	}
	if seen != "mail [EMAIL] please" {
		t.Fatalf("executor saw content %q, want redacted", seen)
	}
	foundLog := false
	for _, entry := range logger.infos {
		if strings.HasPrefix(entry, "PII:") && strings.Contains(entry, "1") {
			foundLog = true
		}
	}
	if !foundLog {
		t.Fatalf("expected a PII log line with the count, got %v", logger.infos)
	}
}

func TestBodyGuardDisabledIsNoOp(t *testing.T) {
	guard := &piiRecordingGuard{}
	var seen string
	svc := piiGuardSvc(guard, false, nil, &seen)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body: piiGuardBody(), Endpoint: "/v1/chat/completions", Headers: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if guard.calls != 1 || len(guard.enabled) != 1 || guard.enabled[0] {
		t.Fatalf("guard calls=%d enabled=%v, want 1 call with enabled=false", guard.calls, guard.enabled)
	}
	if seen != "mail secret@example.com please" {
		t.Fatalf("executor saw content %q, want untouched", seen)
	}
}

func TestBodyGuardNilIsNoOp(t *testing.T) {
	var seen string
	svc := piiGuardSvc(nil, true, nil, &seen)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body: piiGuardBody(), Endpoint: "/v1/chat/completions", Headers: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if seen != "mail secret@example.com please" {
		t.Fatalf("executor saw content %q, want untouched", seen)
	}
}
