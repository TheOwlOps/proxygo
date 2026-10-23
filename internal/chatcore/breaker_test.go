package chatcore

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

// fakeBreaker is a chatcore-level CircuitBreaker stub: it blocks the
// connection IDs in `blocked` and records every OnResult call.
type fakeBreaker struct {
	mu      sync.Mutex
	blocked map[string]bool
	results []breakerResult
}

type breakerResult struct {
	provider string
	connID   string
	success  bool
}

func (f *fakeBreaker) Allow(provider, connID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.blocked[connID]
}

func (f *fakeBreaker) OnResult(provider, connID string, success bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, breakerResult{provider, connID, success})
}

func (f *fakeBreaker) Snapshot() any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{"recorded": len(f.results)}
}

func TestBreakerOpenSkipsCredential(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{
		{ConnectionID: "c1", ConnectionName: "first", AccessToken: "t1"},
		{ConnectionID: "c2", ConnectionName: "second", AccessToken: "t2"},
	}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		return jsonResp(200, `{"id":"ok","choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}]}`)
	}}
	br := &fakeBreaker{blocked: map[string]bool{"c1": true}}
	svc := newSvc(accounts, exec, nil)
	svc.Breaker = br

	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if len(exec.calls) != 1 || exec.calls[0].connectionID != "c2" {
		t.Fatalf("executor calls = %+v, want only c2 (c1 circuit open)", exec.calls)
	}
	if len(accounts.marked) != 0 {
		t.Fatalf("breaker skip must not mark the account unavailable: %v", accounts.marked)
	}
	if len(br.results) != 1 || br.results[0].connID != "c2" || !br.results[0].success {
		t.Fatalf("OnResult calls = %+v, want one success for c2", br.results)
	}
}

func TestBreakerOnResultClassification(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{
		{ConnectionID: "c1", ConnectionName: "first", AccessToken: "t1"},
		{ConnectionID: "c2", ConnectionName: "second", AccessToken: "t2"},
		{ConnectionID: "c3", ConnectionName: "third", AccessToken: "t3"},
	}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		switch cred.ConnectionID {
		case "c1":
			return jsonResp(503, `{"error":{"message":"Service unavailable"}}`)
		case "c2":
			return jsonResp(429, `{"error":{"message":"Rate limit exceeded"}}`)
		default:
			return jsonResp(200, `{"id":"ok","choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}]}`)
		}
	}}
	br := &fakeBreaker{}
	svc := newSvc(accounts, exec, nil)
	svc.Breaker = br

	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want fallback chain to reach c3", resp.StatusCode)
	}
	want := []breakerResult{
		{"openai", "c1", false}, // 5xx = breaker failure
		{"openai", "c2", true},  // 429 is NOT a breaker failure
		{"openai", "c3", true},  // 2xx success
	}
	if len(br.results) != len(want) {
		t.Fatalf("OnResult calls = %+v, want %+v", br.results, want)
	}
	for i := range want {
		if br.results[i] != want[i] {
			t.Fatalf("OnResult[%d] = %+v, want %+v", i, br.results[i], want[i])
		}
	}
}

func TestNilBreakerChangesNothing(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{
		{ConnectionID: "c1", ConnectionName: "first", AccessToken: "t1"},
		{ConnectionID: "c2", ConnectionName: "second", AccessToken: "t2"},
	}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		if cred.ConnectionID == "c1" {
			return jsonResp(503, `{"error":{"message":"Service unavailable"}}`)
		}
		return jsonResp(200, `{"id":"ok","choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}]}`)
	}}
	svc := newSvc(accounts, exec, nil) // Breaker left nil

	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if len(exec.calls) != 2 || exec.calls[0].connectionID != "c1" || exec.calls[1].connectionID != "c2" {
		t.Fatalf("executor calls = %+v, want the pre-feature c1→c2 fallback", exec.calls)
	}
	if svc.BreakerSnapshot() != nil {
		t.Fatal("BreakerSnapshot must be nil when no breaker is wired")
	}
}

func TestBreakerSnapshotDelegates(t *testing.T) {
	svc := newSvc(&fakeAccounts{}, &fakeExecutor{}, nil)
	if svc.BreakerSnapshot() != nil {
		t.Fatal("snapshot must be nil before wiring")
	}
	svc.Breaker = &fakeBreaker{}
	snap, ok := svc.BreakerSnapshot().(map[string]any)
	if !ok || snap["recorded"] != 0 {
		t.Fatalf("snapshot = %#v, want the fake breaker's map", svc.BreakerSnapshot())
	}
}
