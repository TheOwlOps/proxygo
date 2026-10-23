package executors

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestXmimoBareModelAndAccountRoute(t *testing.T) {
	if xmimoBareModel("xiaomi-mimo/mimo-v2.6-pro") != "mimo-v2.6-pro" || xmimoBareModel("mimo-v2.5") != "mimo-v2.5" {
		t.Fatal("bareModel mismatch")
	}
	withToken := Credential{Specific: map[string]any{"mimoPassToken": "pt"}}
	withCookie := Credential{Specific: map[string]any{xmimoCookieKey: "serviceToken=x"}}
	if !xmimoIsAccountRoute("mimo-v2.6-flash", withToken) {
		t.Fatal("v2.6 + passToken must be account route")
	}
	if !xmimoIsAccountRoute("xiaomi-mimo/mimo-v2.6-pro-ultraspeed", withCookie) {
		t.Fatal("prefixed v2.6 + cookie must be account route")
	}
	if xmimoIsAccountRoute("mimo-v2.6-pro", Credential{}) {
		t.Fatal("v2.6 without session credentials must stay cloud route")
	}
	if xmimoIsAccountRoute("mimo-v2.5", withToken) {
		t.Fatal("non-v2.6 model must stay cloud route even with passToken")
	}
}

func TestXmimoResolveServerBaseAndSID(t *testing.T) {
	if got := xmimoResolveMimoServerBase(map[string]any{"region": "cn"}); got != "https://mimo-server-cn.xiaomimimo.com" {
		t.Fatalf("cn base = %q", got)
	}
	if got := xmimoResolveMimoServerBase(map[string]any{"region": "AMS"}); got != "https://mimo-server-ams.xiaomimimo.com" {
		t.Fatalf("ams base = %q", got)
	}
	if got := xmimoResolveMimoServerBase(nil); got != xmimoDefaultAPIBase {
		t.Fatalf("default base = %q", got)
	}
	if xmimoSIDForRegion("cn") != "mimopc" || xmimoSIDForRegion("in") != "mimoin" || xmimoSIDForRegion("??") != "mimosgp" {
		t.Fatal("sid mapping mismatch")
	}
}

func TestXmimoSignatureClientSign(t *testing.T) {
	sum := sha1.Sum([]byte("nonce=12345&sec"))
	want := base64.StdEncoding.EncodeToString(sum[:])
	got, err := url.QueryUnescape(xmimoSignatureClientSign("12345", "sec"))
	if err != nil || got != want {
		t.Fatalf("clientSign = %q (decoded %q), want sha1 base64 %q", xmimoSignatureClientSign("12345", "sec"), got, want)
	}
	// Empty ssecurity → no & segment.
	sum2 := sha1.Sum([]byte("nonce=12345"))
	got2, _ := url.QueryUnescape(xmimoSignatureClientSign("12345", ""))
	if got2 != base64.StdEncoding.EncodeToString(sum2[:]) {
		t.Fatalf("clientSign without ssecurity = %q", got2)
	}
}

// xmimoStartSSO serves a fake two-phase serviceLogin handshake: phase 1
// returns a location pointing at /sts; phase 2 sets serviceToken=tok-<n>
// (n = handshake number, so tests can tell a fresh cookie from a cached
// one) plus one keep-listed (*_ph) and one dropped cookie. It returns the
// base URL, the phase-1 call counter, and the Cookie headers seen on each
// phase (phase 2 must carry none).
func xmimoStartSSO(t *testing.T) (base string, phase1Count *int64, phase1Cookie, phase2Cookie *string) {
	t.Helper()
	var p1, p2 int64
	var p1Cookie, p2Cookie string
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/pass/serviceLogin", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&p1, 1)
		p1Cookie = r.Header.Get("Cookie")
		if sid := r.URL.Query().Get("sid"); sid != "mimosgp" {
			t.Errorf("phase1 sid = %q, want mimosgp", sid)
		}
		if sign := r.URL.Query().Get("clientSign"); sign != "" {
			t.Errorf("phase1 must not carry clientSign")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code":0,"location":"`+srv.URL+`/sts","ssecurity":"sec","nonce":12345}`)
	})
	mux.HandleFunc("/sts", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&p2, 1)
		p2Cookie = r.Header.Get("Cookie")
		if r.URL.Query().Get("clientSign") == "" {
			t.Errorf("phase2 missing clientSign")
		}
		w.Header().Add("Set-Cookie", "serviceToken=tok-"+strconv.FormatInt(n, 10)+"; Path=/")
		w.Header().Add("Set-Cookie", "device_ph=zz; Path=/")
		w.Header().Add("Set-Cookie", "tracking=drop-me; Path=/")
		w.WriteHeader(200)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, &p1, &p1Cookie, &p2Cookie
}

func TestXmimoSSOHandshakeAndCache(t *testing.T) {
	base, p1Count, p1Cookie, p2Cookie := xmimoStartSSO(t)
	oldBase := xmimoAccountBase
	xmimoAccountBase = base
	defer func() { xmimoAccountBase = oldBase }()
	xmimoInvalidateAccountCookieCache()
	defer xmimoInvalidateAccountCookieCache()

	specific := map[string]any{"mimoPassToken": "pt-1", "mimoUserId": "u1", "region": "sgp"}
	cookie := xmimoGetAccountCookie(context.Background(), specific)
	if !strings.Contains(cookie, "serviceToken=tok-1") || !strings.Contains(cookie, "userId=u1") || !strings.Contains(cookie, "device_ph=zz") {
		t.Fatalf("cookie = %q", cookie)
	}
	if strings.Contains(cookie, "tracking") {
		t.Fatalf("non-allowlisted cookie must be dropped: %q", cookie)
	}
	if !strings.Contains(*p1Cookie, "passToken=pt-1") {
		t.Fatalf("phase1 cookie = %q", *p1Cookie)
	}
	if *p2Cookie != "" {
		t.Fatalf("phase2 must send NO Cookie header, got %q", *p2Cookie)
	}
	// Cached: second resolve does not re-run the handshake.
	if again := xmimoGetAccountCookie(context.Background(), specific); again != cookie {
		t.Fatalf("cached cookie = %q, want %q", again, cookie)
	}
	if n := atomic.LoadInt64(p1Count); n != 1 {
		t.Fatalf("phase1 calls = %d, want 1", n)
	}
	// No passToken → no cookie (desktop DB read is not ported).
	if got := xmimoGetAccountCookie(context.Background(), map[string]any{}); got != "" {
		t.Fatalf("no-passToken cookie = %q", got)
	}
}

func TestXmimoCloudRoutePassthrough(t *testing.T) {
	var gotAuth, gotCookie string
	chat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"cloud"}`)
	}))
	defer chat.Close()

	ex := NewXiaomiMimoExecutor()
	p := &ProviderInfo{
		ID: "xiaomi-mimo", BaseURL: chat.URL, Format: "openai",
		Auth: &AuthSpec{Combined: true, Header: "Authorization", Scheme: "bearer"},
	}
	// mimoPassToken present, but the model is not a v2.6 account model.
	cred := Credential{APIKey: "sk-cloud", Specific: map[string]any{"mimoPassToken": "pt"}}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"mimo-v2.5","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "cloud") || res.URL != chat.URL {
		t.Fatalf("cloud result url=%q body=%q", res.URL, body)
	}
	if gotAuth != "Bearer sk-cloud" || gotCookie != "" {
		t.Fatalf("cloud headers auth=%q cookie=%q", gotAuth, gotCookie)
	}
}

func TestXmimoAccountRouteSeededCookie(t *testing.T) {
	var gotPath, gotCookie, gotAuth string
	var gotBody map[string]any
	chat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"acct"}`)
	}))
	defer chat.Close()

	oldOverride := xmimoServerBaseOverride
	xmimoServerBaseOverride = chat.URL
	defer func() { xmimoServerBaseOverride = oldOverride }()
	xmimoInvalidateAccountCookieCache()
	defer xmimoInvalidateAccountCookieCache()

	specific := map[string]any{"mimoPassToken": "pt-9", "region": "sgp"}
	seeded := "serviceToken=tok-seed; userId=u9"
	key := xmimoCookieCacheKey(xmimoResolveMimoServerBase(specific), "pt-9")
	// resolve with override returns chat.URL, so recompute the key the
	// executor will use (override already applied above).
	xmimoCookieCacheMu.Lock()
	xmimoCookieCache[key] = xmimoCachedCookie{cookie: seeded, at: time.Now()}
	xmimoCookieCacheMu.Unlock()

	ex := NewXiaomiMimoExecutor()
	p := &ProviderInfo{ID: "xiaomi-mimo", BaseURL: "https://api.xiaomimimo.com/v1/chat/completions", Format: "openai"}
	cred := Credential{APIKey: "sk-cloud", Specific: specific}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"xiaomi-mimo/mimo-v2.6-pro","reasoning_effort":"xhigh","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if gotPath != "/api/route/chat/completions" {
		t.Fatalf("account path = %q", gotPath)
	}
	if gotCookie != seeded {
		t.Fatalf("account cookie header = %q, want %q", gotCookie, seeded)
	}
	if gotAuth != "" {
		t.Fatalf("account route must not send the API key, got %q", gotAuth)
	}
	if _, has := gotBody["reasoning_effort"]; has {
		t.Fatalf("reasoning_effort must be bridged away: %v", gotBody)
	}
	if oc, _ := gotBody["output_config"].(map[string]any); oc == nil || oc["effort"] != "high" {
		t.Fatalf("output_config = %v, want effort=high (xhigh normalised)", gotBody["output_config"])
	}
	if gotBody["temperature"] != 1.0 || gotBody["top_p"] != 0.95 {
		t.Fatalf("defaults temperature/top_p = %v/%v", gotBody["temperature"], gotBody["top_p"])
	}
}

func TestXmimoAccountTransformPreservesTemperature(t *testing.T) {
	ex := NewXiaomiMimoExecutor()
	body := map[string]any{
		"model":            "mimo-v2.6-flash",
		"messages":         []any{},
		"reasoning_effort": "LOW",
		"temperature":      json.Number("0.5"),
	}
	req := &Request{
		Provider: &ProviderInfo{ID: "xiaomi-mimo"},
		Cred:     Credential{Specific: map[string]any{xmimoCookieKey: "serviceToken=x"}},
		Model:    "mimo-v2.6-flash",
		Body:     body,
		State:    map[string]any{},
	}
	out, err := ex.Base.Hooks.TransformBody(ex.Base, req)
	if err != nil {
		t.Fatal(err)
	}
	if oc := out["output_config"].(map[string]any); oc["effort"] != "low" {
		t.Fatalf("effort = %v", oc)
	}
	if out["temperature"] != json.Number("0.5") {
		t.Fatalf("explicit temperature must be preserved, got %v", out["temperature"])
	}
	if out["top_p"] != 0.95 {
		t.Fatalf("top_p default = %v", out["top_p"])
	}
}

func TestXmimoAccount401RetriesWithFreshCookie(t *testing.T) {
	base, p1Count, _, _ := xmimoStartSSO(t)
	oldBase := xmimoAccountBase
	xmimoAccountBase = base
	defer func() { xmimoAccountBase = oldBase }()

	var chatCalls int64
	var cookies []string
	chat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies = append(cookies, r.Header.Get("Cookie"))
		if atomic.AddInt64(&chatCalls, 1) == 1 {
			w.WriteHeader(401)
			io.WriteString(w, "session expired")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"fresh"}`)
	}))
	defer chat.Close()
	oldOverride := xmimoServerBaseOverride
	xmimoServerBaseOverride = chat.URL
	defer func() { xmimoServerBaseOverride = oldOverride }()
	xmimoInvalidateAccountCookieCache()
	defer xmimoInvalidateAccountCookieCache()

	ex := NewXiaomiMimoExecutor()
	p := &ProviderInfo{ID: "xiaomi-mimo", BaseURL: "https://api.xiaomimimo.com/v1/chat/completions"}
	cred := Credential{APIKey: "sk-cloud", Specific: map[string]any{"mimoPassToken": "pt-7", "region": "sgp"}}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"mimo-v2.6-pro","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 || !strings.Contains(body, "fresh") {
		t.Fatalf("retry result = %d %q", res.Response.StatusCode, body)
	}
	if atomic.LoadInt64(&chatCalls) != 2 || atomic.LoadInt64(p1Count) != 2 {
		t.Fatalf("chat/phase1 calls = %d/%d, want 2/2", chatCalls, *p1Count)
	}
	if len(cookies) != 2 || !strings.Contains(cookies[0], "serviceToken=tok-1") || !strings.Contains(cookies[1], "serviceToken=tok-2") {
		t.Fatalf("cookies per attempt = %v, want tok-1 then fresh tok-2", cookies)
	}
}
