package chatcore

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// recordingLimiter is a fake KeyLimiter for the F3 hook tests.
type recordingLimiter struct {
	rej   *LimitRejection
	calls []string
}

func (f *recordingLimiter) Check(keyID string) *LimitRejection {
	f.calls = append(f.calls, keyID)
	return f.rej
}

func keyLimitSvc(t *testing.T, lim KeyLimiter, execCalls *int) *Service {
	t.Helper()
	accounts := &fakeAccounts{creds: []Credential{{ConnectionID: "c1", AccessToken: "tok"}}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		*execCalls++
		return sseResp("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}}
	svc := newSvc(accounts, exec, nil)
	svc.KeyLimiter = lim
	return svc
}

func TestHandleChatNilKeyLimiterNoOp(t *testing.T) {
	execCalls := 0
	svc := keyLimitSvc(t, nil, &execCalls)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", true),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
		APIKey:   "sk-anything",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || execCalls != 1 {
		t.Fatalf("status=%d execCalls=%d, want 200/1", resp.StatusCode, execCalls)
	}
}

func TestHandleChatKeyLimiterRejection(t *testing.T) {
	execCalls := 0
	lim := &recordingLimiter{rej: &LimitRejection{
		Status:  StatusRateLimited,
		Type:    "budget_exceeded",
		Message: "API key daily token budget exceeded",
	}}
	svc := keyLimitSvc(t, lim, &execCalls)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", true),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
		APIKey:   "sk-limited",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 429 {
		t.Fatalf("status=%d body=%q, want 429", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"budget_exceeded"`) || !strings.Contains(body, "budget exceeded") {
		t.Fatalf("body=%q, want budget_exceeded error shape", body)
	}
	if execCalls != 0 {
		t.Fatalf("executor ran %d times despite rejection", execCalls)
	}
	if len(lim.calls) != 1 || lim.calls[0] != "sk-limited" {
		t.Fatalf("limiter calls = %v, want [sk-limited]", lim.calls)
	}
}

func TestHandleChatKeyLimiterSkippedWithoutKey(t *testing.T) {
	execCalls := 0
	lim := &recordingLimiter{rej: &LimitRejection{
		Status: StatusRateLimited, Type: "rate_limit_exceeded", Message: "slow down",
	}}
	svc := keyLimitSvc(t, lim, &execCalls)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", true),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
		// no APIKey presented
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || execCalls != 1 {
		t.Fatalf("status=%d execCalls=%d, want 200/1", resp.StatusCode, execCalls)
	}
	if len(lim.calls) != 0 {
		t.Fatalf("limiter consulted without a key: %v", lim.calls)
	}
}
