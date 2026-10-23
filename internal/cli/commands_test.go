package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMaskKey(t *testing.T) {
	if got := maskKey("short"); got != "****" {
		t.Errorf("short key masked as %q, want ****", got)
	}
	if got := maskKey("sk-1234567890abcdef"); got != "sk-123…cdef" {
		t.Errorf("maskKey=%q", got)
	}
}

func TestResolveToolsUnknown(t *testing.T) {
	if _, err := resolveTools([]string{"nope"}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("want unknown-tool error, got %v", err)
	}
	if _, err := resolveTools([]string{"factory"}); err != nil { // alias → droid
		t.Fatalf("alias factory should resolve: %v", err)
	}
}

func TestCodexRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	def, ok := toolByID("codex")
	if !ok {
		t.Fatal("codex missing")
	}
	ctx := toolCtx{BaseURL: "http://srv:20128", APIKey: "sk-codex-key-123456", Model: "oc/gpt-5.5"}
	if _, err := def.apply(ctx); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg, err := def.show()
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if cfg.BaseURL != "http://srv:20128/v1" || cfg.APIKey != "sk-codex-key-123456" {
		t.Fatalf("show cfg=%+v", cfg)
	}
	found := false
	for _, m := range cfg.Models {
		if m.Key == "main" && m.Value == "oc/gpt-5.5" {
			found = true
		}
	}
	if !found || cfg.Active == nil || !*cfg.Active {
		t.Fatalf("models=%v active=%v", cfg.Models, cfg.Active)
	}
	if _, err := def.reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	cfg, _ = def.show()
	if cfg.BaseURL != "" || cfg.APIKey != "" {
		t.Fatalf("after reset cfg=%+v", cfg)
	}
}

func TestOmpYAMLRoundTrip(t *testing.T) {
	text := "providers:\n  other:\n    apiKey: keepme\n"
	out := ompApply9Router(text, toolCtx{BaseURL: "http://h:20128", APIKey: "k-omp-123"})
	if !strings.Contains(out, "other:") || !strings.Contains(out, "keepme") {
		t.Fatalf("other provider lost:\n%s", out)
	}
	if !strings.Contains(out, "baseUrl: http://h:20128/v1") {
		t.Fatalf("9router block missing:\n%s", out)
	}
	got := ompRead9Router(out)
	if got["baseUrl"] != "http://h:20128/v1" || got["apiKey"] != "k-omp-123" || got["discovery.type"] != "proxy" {
		t.Fatalf("read=%v", got)
	}
	removed, changed := ompRemove9Router(out)
	if !changed || strings.Contains(removed, "9router") || !strings.Contains(removed, "keepme") {
		t.Fatalf("remove changed=%v:\n%s", changed, removed)
	}
	// Removing the only provider drops the providers: header too.
	only := ompApply9Router("", toolCtx{BaseURL: "http://h:20128", APIKey: "k"})
	removed, _ = ompRemove9Router(only)
	if strings.TrimSpace(removed) != "" {
		t.Fatalf("expected empty after removing sole provider, got %q", removed)
	}
}

// fake9Router is the minimal server surface `connect` talks to.
func fake9Router(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["password"] != "pw" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"wrong password"}`)
			return
		}
		w.Header().Set("Set-Cookie", "auth_token=tok123; Path=/; HttpOnly")
		fmt.Fprint(w, `{"success":true}`)
	})
	mux.HandleFunc("/api/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "auth_token=tok123" {
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
			fmt.Fprint(w, `{"key":"sk-test-1234567890abcdef"}`)
			return
		}
		fmt.Fprint(w, `{"keys":[]}`)
	})
	mux.HandleFunc("/api/cli-tools/claude-settings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"settings":{"env":{"ANTHROPIC_DEFAULT_SONNET_MODEL":"srv/sonnet-1"}}}`)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"srv/sonnet-1"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DATA_DIR", t.TempDir())
	srv := fake9Router(t)

	var out, errBuf bytes.Buffer
	code := run([]string{"connect", srv.URL, "--tools", "claude", "--password", "pw"}, &out, &errBuf, strings.NewReader(""))
	if code != 0 {
		t.Fatalf("connect code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}
	raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("settings not written: %v (out=%q)", err, out.String())
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != srv.URL+"/v1" {
		t.Errorf("base url=%v", env["ANTHROPIC_BASE_URL"])
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "sk-test-1234567890abcdef" {
		t.Errorf("token=%v", env["ANTHROPIC_AUTH_TOKEN"])
	}
	if env["ANTHROPIC_DEFAULT_SONNET_MODEL"] != "srv/sonnet-1" {
		t.Errorf("sonnet=%v (server model should win)", env["ANTHROPIC_DEFAULT_SONNET_MODEL"])
	}
	if settings["hasCompletedOnboarding"] != true {
		t.Errorf("onboarding flag missing: %v", settings)
	}
	if strings.Contains(out.String(), "sk-test-1234567890abcdef") {
		t.Error("connect printed the full API key")
	}

	// show sees the written config, key masked.
	out.Reset()
	code = run([]string{"show", "claude"}, &out, &errBuf, strings.NewReader(""))
	text := out.String()
	if code != 0 || !strings.Contains(text, "srv/sonnet-1") || !strings.Contains(text, "sk-tes…cdef") {
		t.Fatalf("show code=%d out=%q", code, text)
	}
	if strings.Contains(text, "sk-test-1234567890abcdef") {
		t.Error("show printed the full API key")
	}

	// --reset removes the 9router env keys again.
	out.Reset()
	code = run([]string{"connect", "--reset", "--tools", "claude"}, &out, &errBuf, strings.NewReader(""))
	if code != 0 {
		t.Fatalf("reset code=%d out=%q", code, out.String())
	}
	raw, _ = os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	settings = map[string]any{}
	_ = json.Unmarshal(raw, &settings)
	env, _ = settings["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != nil || env["ANTHROPIC_AUTH_TOKEN"] != nil {
		t.Fatalf("reset left env behind: %v", env)
	}
}

func TestShowUnknownToolFails(t *testing.T) {
	code, _, errOut := runCapture("show", "nope")
	if code != 1 || !strings.Contains(errOut, "unknown tool") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestUpdateCheckAgainstFakeRelease(t *testing.T) {
	oldURL, oldClient := updateReleaseURL, updateHTTPClient
	t.Cleanup(func() { updateReleaseURL, updateHTTPClient = oldURL, oldClient })
	updateHTTPClient = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.6.0"}`)
	}))
	defer srv.Close()
	updateReleaseURL = srv.URL
	if v, ok := newerVersionAvailable(); !ok || v != "0.6.0" {
		t.Fatalf("newer: v=%q ok=%v", v, ok)
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v`+Version+`"}`)
	}))
	defer srv2.Close()
	updateReleaseURL = srv2.URL
	if _, ok := newerVersionAvailable(); ok {
		t.Fatal("same version reported as newer")
	}

	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv3.Close()
	updateReleaseURL = srv3.URL
	if _, ok := newerVersionAvailable(); ok {
		t.Fatal("HTTP 500 must be silent (no update)")
	}
}

func TestXaiVideoFlow(t *testing.T) {
	var polls atomic.Int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/videos/generations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-9router-connection-id", "conn-1")
		fmt.Fprint(w, `{"request_id":"req-1"}`)
	})
	mux.HandleFunc("/v1/videos/req-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-connection-id") != "conn-1" {
			t.Errorf("poll missing x-connection-id: %q", r.Header.Get("x-connection-id"))
		}
		if polls.Add(1) < 2 {
			fmt.Fprint(w, `{"status":"in_progress"}`)
			return
		}
		fmt.Fprintf(w, `{"status":"done","result":{"video":{"url":%q}}}`, srv.URL+"/file.mp4")
	})
	mux.HandleFunc("/file.mp4", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "FAKEVIDEO")
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(t.TempDir(), "vid.mp4")
	var out, errBuf bytes.Buffer
	code := cmdXaiVideo([]string{"a cat riding a skateboard",
		"--host", u.Hostname(), "--port", u.Port(),
		"--output", outPath, "--poll-interval-ms", "10", "--api-key", "k-test",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("xai code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil || string(raw) != "FAKEVIDEO" {
		t.Fatalf("saved file: err=%v content=%q", err, raw)
	}
	if _, err := os.Stat(outPath + ".part"); !os.IsNotExist(err) {
		t.Fatal(".part file left behind")
	}
}

func TestXaiVideoFailedStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/videos/generations", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"request_id":"req-9"}`)
	})
	mux.HandleFunc("/v1/videos/req-9", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"failed","error":"render exploded"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var out, errBuf bytes.Buffer
	code := cmdXaiVideo([]string{"boom",
		"--host", u.Hostname(), "--port", u.Port(),
		"--output", filepath.Join(t.TempDir(), "v.mp4"), "--poll-interval-ms", "10",
	}, &out, &errBuf)
	if code != 1 || !strings.Contains(errBuf.String(), "render exploded") {
		t.Fatalf("code=%d err=%q", code, errBuf.String())
	}
}

func TestXaiVideoRequiresPrompt(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := cmdXaiVideo(nil, &out, &errBuf); code != 1 {
		t.Fatalf("empty prompt code=%d", code)
	}
}
