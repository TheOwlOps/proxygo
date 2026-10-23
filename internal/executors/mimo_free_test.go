package executors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mimoFreeMakeJWT builds an unsigned JWT-shaped token with the given exp
// (seconds) — only the payload is parsed by the executor.
func mimoFreeMakeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadRaw, _ := json.Marshal(map[string]any{"exp": exp})
	payload := base64.RawURLEncoding.EncodeToString(payloadRaw)
	return header + "." + payload + ".sig"
}

func mimoFreeSetBootstrap(t *testing.T, url string) {
	t.Helper()
	old := mimoFreeBootstrapURL
	mimoFreeBootstrapURL = url
	mimoFreeResetJWTCache()
	t.Cleanup(func() {
		mimoFreeBootstrapURL = old
		mimoFreeResetJWTCache()
	})
}

func TestMimoFreeParseJWTExp(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	got := mimoFreeParseJWTExp(mimoFreeMakeJWT(exp))
	if got.Unix() != exp {
		t.Fatalf("exp = %v, want %v", got.Unix(), exp)
	}
	// Unparseable tokens fall back to the fixed TTL (~3000s out).
	fallback := mimoFreeParseJWTExp("not-a-jwt")
	if d := time.Until(fallback); d < 2900*time.Second || d > 3100*time.Second {
		t.Fatalf("fallback TTL = %v", d)
	}
}

func TestMimoFreeSessionIDAndFingerprint(t *testing.T) {
	re := regexp.MustCompile(`^ses_[a-z0-9]{24}$`)
	for i := 0; i < 8; i++ {
		if id := mimoFreeGenerateSessionID(); !re.MatchString(id) {
			t.Fatalf("session id = %q", id)
		}
	}
	fp1, fp2 := mimoFreeGenerateFingerprint(), mimoFreeGenerateFingerprint()
	if fp1 != fp2 || len(fp1) != 64 {
		t.Fatalf("fingerprint unstable/malformed: %q vs %q", fp1, fp2)
	}
}

func TestMimoFreeInjectSystemMarker(t *testing.T) {
	body := map[string]any{"model": "mimo-auto", "messages": []any{
		map[string]any{"role": "user", "content": "hi"},
	}}
	out := mimoFreeInjectSystemMarker(body)
	msgs := out["messages"].([]any)
	if len(msgs) != 2 || msgs[0].(map[string]any)["content"] != mimoFreeSystemMarker {
		t.Fatalf("marker not prepended: %v", msgs)
	}
	// Idempotent: a body already carrying the marker is returned unchanged.
	out2 := mimoFreeInjectSystemMarker(out)
	if len(out2["messages"].([]any)) != 2 {
		t.Fatalf("marker injected twice: %v", out2["messages"])
	}
	// No messages array → body untouched.
	plain := map[string]any{"model": "m"}
	if mimoFreeInjectSystemMarker(plain)["messages"] != nil {
		t.Fatal("marker must not invent messages")
	}
}

func TestMimoFreeExecuteBootstrapAndChat(t *testing.T) {
	jwt := mimoFreeMakeJWT(time.Now().Add(2 * time.Hour).Unix())
	var bootstrapCalls int64
	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&bootstrapCalls, 1)
		var reqBody map[string]any
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &reqBody); err != nil || getStr(reqBody, "client") == "" {
			t.Errorf("bootstrap body = %s", raw)
		}
		if len(getStr(reqBody, "client")) != 64 {
			t.Errorf("fingerprint length = %q", getStr(reqBody, "client"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jwt":"`+jwt+`"}`)
	}))
	defer bootstrap.Close()
	mimoFreeSetBootstrap(t, bootstrap.URL)

	var gotAuth, gotSource, gotAffinity, gotUA, gotAccept string
	var gotBody map[string]any
	chat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSource = r.Header.Get("X-Mimo-Source")
		gotAffinity = r.Header.Get("x-session-affinity")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer chat.Close()

	ex := NewMimoFreeExecutor()
	p := &ProviderInfo{ID: "mimo-free", BaseURL: chat.URL}
	res, err := ex.Execute(context.Background(), p, Credential{},
		[]byte(`{"model":"mimo-auto","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("chat body = %q", body)
	}
	if gotAuth != "Bearer "+jwt {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotSource != "mimocode-cli-free" || gotAffinity != ex.mimoSessionID {
		t.Fatalf("source/affinity = %q/%q", gotSource, gotAffinity)
	}
	uaOK := false
	for _, ua := range mimoFreeUserAgents {
		if gotUA == ua {
			uaOK = true
		}
	}
	if !uaOK {
		t.Fatalf("user-agent not from the Chrome list: %q", gotUA)
	}
	if gotAccept != "text/event-stream" {
		t.Fatalf("accept = %q", gotAccept)
	}
	msgs := gotBody["messages"].([]any)
	if msgs[0].(map[string]any)["role"] != "system" || msgs[0].(map[string]any)["content"] != mimoFreeSystemMarker {
		t.Fatalf("first message must be the marker: %v", msgs[0])
	}

	// Second call reuses the cached JWT (no second bootstrap).
	if _, err := ex.Execute(context.Background(), p, Credential{},
		[]byte(`{"model":"mimo-auto","messages":[{"role":"user","content":"again"}]}`)); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&bootstrapCalls); n != 1 {
		t.Fatalf("bootstrap calls = %d, want 1 (cache hit)", n)
	}
}

func TestMimoFreeExecuteRetriesOnceOn401(t *testing.T) {
	jwt := mimoFreeMakeJWT(time.Now().Add(2 * time.Hour).Unix())
	var bootstrapCalls, chatCalls int64
	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&bootstrapCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jwt":"`+jwt+`"}`)
	}))
	defer bootstrap.Close()
	mimoFreeSetBootstrap(t, bootstrap.URL)

	chat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&chatCalls, 1) == 1 {
			w.WriteHeader(401)
			io.WriteString(w, "expired")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"ok"}`)
	}))
	defer chat.Close()

	ex := NewMimoFreeExecutor()
	p := &ProviderInfo{ID: "mimo-free", BaseURL: chat.URL}
	res, err := ex.Execute(context.Background(), p, Credential{},
		[]byte(`{"model":"mimo-auto","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 || !strings.Contains(body, `"ok"`) {
		t.Fatalf("retry result = %d %q", res.Response.StatusCode, body)
	}
	if atomic.LoadInt64(&chatCalls) != 2 || atomic.LoadInt64(&bootstrapCalls) != 2 {
		t.Fatalf("chat/bootstrap calls = %d/%d, want 2/2 (cache reset + fresh JWT)",
			chatCalls, bootstrapCalls)
	}
}

func TestMimoFreeBootstrapFailurePropagates(t *testing.T) {
	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer bootstrap.Close()
	mimoFreeSetBootstrap(t, bootstrap.URL)

	ex := NewMimoFreeExecutor()
	_, err := ex.Execute(context.Background(), &ProviderInfo{ID: "mimo-free", BaseURL: "http://127.0.0.1:1/unused"}, Credential{},
		[]byte(`{"model":"mimo-auto","messages":[]}`))
	if err == nil || !strings.Contains(err.Error(), "MiMo bootstrap failed: 500") {
		t.Fatalf("err = %v", err)
	}
}
