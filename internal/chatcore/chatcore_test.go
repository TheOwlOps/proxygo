package chatcore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func decodeJSON(b []byte) (map[string]any, bool) {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

func init() {
	SleepFunc = func(ctx context.Context, d time.Duration) error { return nil }
}

// --- Fakes ---

type fakeProviders struct {
	combos map[string][]string
}

func (f *fakeProviders) Provider(id string) (ProviderInfo, bool) {
	return ProviderInfo{ID: id, Format: FormatOpenAI}, true
}
func (f *fakeProviders) ResolveProviderAlias(a string) string { return a }
func (f *fakeProviders) ResolveModelAlias(a string) (string, string, bool) {
	return "", "", false
}
func (f *fakeProviders) ModelMeta(p, m string) ModelMeta { return ModelMeta{} }
func (f *fakeProviders) TargetFormat(p string, c Credential) string {
	return FormatOpenAI
}
func (f *fakeProviders) TransportFor(p, format string) *TransportOption { return nil }
func (f *fakeProviders) Combo(name string) ([]string, bool) {
	m, ok := f.combos[name]
	return m, ok
}

type fakeAccounts struct {
	mu           sync.Mutex
	creds        []Credential
	marked       []int
	cleared      []string
	persisted    []Credential
	refreshCalls int
}

func (f *fakeAccounts) Next(provider string, exclude map[string]bool, model, requested string) (Credential, *AllRateLimited, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.creds {
		if !exclude[c.ConnectionID] {
			return c, nil, nil
		}
	}
	return Credential{}, nil, nil
}
func (f *fakeAccounts) RefreshIfNeeded(ctx context.Context, provider string, cred Credential) (Credential, error) {
	f.refreshCalls++
	return cred, nil
}
func (f *fakeAccounts) MarkUnavailable(cred Credential, status int, errText, provider, model string, resetsAt time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marked = append(f.marked, status)
	return CheckFallbackError(status, errText, 0, provider).ShouldFallback
}
func (f *fakeAccounts) ClearError(cred Credential, model string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleared = append(f.cleared, cred.ConnectionID)
}
func (f *fakeAccounts) PersistRefreshed(cred Credential, refreshed Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.persisted = append(f.persisted, refreshed)
	return nil
}

type fakeExecutor struct {
	mu    sync.Mutex
	calls []execCall
	fn    func(cred Credential, body map[string]any) *http.Response
}

type execCall struct {
	connectionID string
	accessToken  string
	model        string
}

func (f *fakeExecutor) Execute(ctx context.Context, provider string, info ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	m := BodyOf(body)
	f.mu.Lock()
	f.calls = append(f.calls, execCall{connectionID: cred.ConnectionID, accessToken: cred.AccessToken, model: strOf(m["model"])})
	f.mu.Unlock()
	resp := f.fn(cred, m)
	return &ExecResult{Response: resp, URL: "http://upstream.test/v1/chat/completions", TransformedBody: body}, nil
}

func BodyOf(b []byte) map[string]any {
	m, _ := decodeJSON(b)
	return m
}

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func sseResp(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func chatBody(model string, stream bool) map[string]any {
	return map[string]any{
		"model":    model,
		"stream":   stream,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}
}

func newSvc(accounts *fakeAccounts, exec *fakeExecutor, combos map[string][]string) *Service {
	return NewService(Service{
		Providers: &fakeProviders{combos: combos},
		Accounts:  accounts,
		Executor:  exec,
	})
}

// --- Tests ---

func TestHandleChatSuccessPassthroughSSE(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{{ConnectionID: "c1", AccessToken: "tok"}}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		return sseResp("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}}
	svc := newSvc(accounts, exec, nil)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", true),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "[DONE]") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if len(accounts.cleared) != 1 || accounts.cleared[0] != "c1" {
		t.Fatalf("ClearError calls = %v", accounts.cleared)
	}
}

func TestHandleChatAccountFallbackOn429(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{
		{ConnectionID: "c1", ConnectionName: "first", AccessToken: "t1"},
		{ConnectionID: "c2", ConnectionName: "second", AccessToken: "t2"},
	}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		if cred.ConnectionID == "c1" {
			return jsonResp(429, `{"error":{"message":"Rate limit exceeded"}}`)
		}
		return jsonResp(200, `{"id":"ok","choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}]}`)
	}}
	svc := newSvc(accounts, exec, nil)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, `"done"`) {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if len(exec.calls) != 2 || exec.calls[0].connectionID != "c1" || exec.calls[1].connectionID != "c2" {
		t.Fatalf("executor calls = %+v", exec.calls)
	}
	if len(accounts.marked) != 1 || accounts.marked[0] != 429 {
		t.Fatalf("MarkUnavailable calls = %v", accounts.marked)
	}
}

func TestHandleChatComboFallbackOn5xx(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{{ConnectionID: "c1", AccessToken: "t"}}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		// The executor sees the upstream model id in the body.
		if strings.HasSuffix(strOf(body["model"]), "/a") || strOf(body["model"]) == "a" {
			return jsonResp(503, `{"error":{"message":"Service unavailable"}}`)
		}
		return jsonResp(200, `{"id":"b","choices":[{"message":{"role":"assistant","content":"from-b"},"finish_reason":"stop"}]}`)
	}}
	svc := newSvc(accounts, exec, map[string][]string{"mycombo": {"openai/a", "openai/b"}})
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("mycombo", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "from-b") {
		t.Fatalf("combo fallback failed: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestHandleChatComboZeroContentFallsBack(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{{ConnectionID: "c1", AccessToken: "t"}}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		if strOf(body["model"]) == "a" {
			return jsonResp(200, `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":null}]}`)
		}
		return jsonResp(200, `{"choices":[{"message":{"role":"assistant","content":"real"},"finish_reason":"stop"}]}`)
	}}
	svc := newSvc(accounts, exec, map[string][]string{"zc": {"openai/a", "openai/b"}})
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("zc", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "real") {
		t.Fatalf("zero-content combo fallback failed: %q", body)
	}
}

type fakeRefresher struct {
	calls int
	token string
}

func (f *fakeRefresher) Refresh(ctx context.Context, provider string, cred Credential) (*Credential, error) {
	f.calls++
	out := cred
	out.AccessToken = f.token
	out.RefreshToken = "rt-new"
	return &out, nil
}

func TestHandleChatRefreshHookOn401(t *testing.T) {
	accounts := &fakeAccounts{creds: []Credential{{ConnectionID: "c1", AccessToken: "old", RefreshToken: "rt-old"}}}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		if cred.AccessToken == "old" {
			return jsonResp(401, `{"error":{"message":"Unauthorized"}}`)
		}
		return jsonResp(200, `{"id":"ok","choices":[{"message":{"role":"assistant","content":"after-refresh"},"finish_reason":"stop"}]}`)
	}}
	refresher := &fakeRefresher{token: "new"}
	svc := newSvc(accounts, exec, nil)
	svc.Refresher = refresher

	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "after-refresh") {
		t.Fatalf("refresh flow failed: status=%d body=%q", resp.StatusCode, body)
	}
	if refresher.calls == 0 {
		t.Fatal("refresher was not invoked on 401")
	}
	if len(exec.calls) != 2 || exec.calls[1].accessToken != "new" {
		t.Fatalf("executor calls = %+v", exec.calls)
	}
	if len(accounts.persisted) != 1 || accounts.persisted[0].AccessToken != "new" {
		t.Fatalf("PersistRefreshed = %+v", accounts.persisted)
	}
	if len(accounts.marked) != 0 {
		t.Fatalf("successful refresh must not mark the account unavailable: %v", accounts.marked)
	}
}

func TestHandleChatNoCredentials(t *testing.T) {
	accounts := &fakeAccounts{}
	exec := &fakeExecutor{fn: func(cred Credential, body map[string]any) *http.Response {
		return jsonResp(200, `{}`)
	}}
	svc := newSvc(accounts, exec, nil)
	resp, err := svc.HandleChat(context.Background(), ChatRequest{
		Body:     chatBody("openai/gpt-x", false),
		Endpoint: "/v1/chat/completions",
		Headers:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404 (no active credentials)", resp.StatusCode)
	}
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"responses input", map[string]any{"input": []any{}}, FormatOpenAIResponses},
		{"gemini contents", map[string]any{"contents": []any{}}, FormatGemini},
		{"claude system", map[string]any{"messages": []any{}, "system": "x"}, FormatClaude},
		{"openai default", map[string]any{"messages": []any{map[string]any{"role": "user", "content": "hi"}}}, FormatOpenAI},
		{"openai indicator wins", map[string]any{"messages": []any{}, "response_format": map[string]any{}}, FormatOpenAI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectFormat(tc.body); got != tc.want {
				t.Fatalf("DetectFormat = %q, want %q", got, tc.want)
			}
		})
	}
	if got := DetectFormatByEndpoint("/v1/messages", map[string]any{}); got != FormatClaude {
		t.Fatalf("endpoint claude = %q", got)
	}
	if got := DetectFormatByEndpoint("/v1/responses", map[string]any{}); got != FormatOpenAIResponses {
		t.Fatalf("endpoint responses = %q", got)
	}
}

func TestCheckFallbackErrorRules(t *testing.T) {
	if d := CheckFallbackError(400, "context length exceeded", 0, "openai"); d.ShouldFallback {
		t.Fatal("request-scoped 400 must not fall back")
	}
	if d := CheckFallbackError(429, "Rate limit exceeded", 0, "openai"); !d.ShouldFallback || d.CooldownMs <= 0 {
		t.Fatalf("429 must fall back with backoff cooldown: %+v", d)
	}
	if d := CheckFallbackError(401, "unauthorized", 0, "openai"); !d.ShouldFallback {
		t.Fatal("401 must fall back")
	}
	if d := CheckFallbackError(503, "boom", 0, "openai"); !d.ShouldFallback || d.CooldownMs != transientCooldownMs {
		t.Fatalf("unmatched 503 must fall back with transient cooldown: %+v", d)
	}
	if d := CheckFallbackError(400, "rate limit", 0, "openai"); !d.ShouldFallback {
		t.Fatal("text rules win over the 4xx no-fallback rule")
	}
}

func TestParseModelString(t *testing.T) {
	info := ParseModelString("kr/claude-sonnet-4.5", func(a string) string {
		if a == "kr" {
			return "kiro"
		}
		return a
	})
	if info.Provider != "kiro" || info.Model != "claude-sonnet-4.5" {
		t.Fatalf("parsed = %+v", info)
	}
	bare := ParseModelString("gpt-5.6-terra", nil)
	if !bare.IsAlias {
		t.Fatalf("bare model must be alias form: %+v", bare)
	}
	if got := InferProviderFromModelName("gpt-5.6-terra"); got != "codex" {
		t.Fatalf("prefix inference = %q, want codex", got)
	}
	if got := InferProviderFromModelName("claude-sonnet-4.5"); got != "anthropic" {
		t.Fatalf("prefix inference = %q, want anthropic", got)
	}
	clean, marker := StripModelContextMarker("claude-sonnet-4.5[1m]")
	if clean != "claude-sonnet-4.5" || marker != "1m" {
		t.Fatalf("context marker strip = %q / %q", clean, marker)
	}
}
