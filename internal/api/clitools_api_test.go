package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ctSetupHome isolates every cli-tools handler in a temp HOME with an
// empty PATH so `which <tool>` probes deterministically report "not
// installed" (file-based detection still works).
func ctSetupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	return home
}

func ctDo(h http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, rdr)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func ctJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("response is not a JSON object: %v\nbody: %s", err, rec.Body.String())
	}
	return v
}

func TestCLIToolsClaudeSettingsRoundTrip(t *testing.T) {
	home := ctSetupHome(t)
	deps := Deps{}

	// GET before anything exists → not installed.
	rec := ctDo(ctClaudeGET(deps), "GET", "/api/cli-tools/claude-settings", "")
	if rec.Code != 200 {
		t.Fatalf("GET status = %d", rec.Code)
	}
	if got := ctJSON(t, rec); got["installed"] != false {
		t.Fatalf("expected installed=false, got %v", got)
	}

	// POST applies env (base URL gains the /v1 suffix), onboarding flag on.
	rec = ctDo(ctClaudePOST(deps), "POST", "/api/cli-tools/claude-settings",
		`{"env":{"ANTHROPIC_BASE_URL":"http://localhost:20128","ANTHROPIC_AUTH_TOKEN":"sk-test"}}`)
	if rec.Code != 200 {
		t.Fatalf("POST status = %d, body %s", rec.Code, rec.Body.String())
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("settings.json invalid: %v", err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != "http://localhost:20128/v1" {
		t.Fatalf("ANTHROPIC_BASE_URL = %v, want /v1 suffix", env["ANTHROPIC_BASE_URL"])
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "sk-test" {
		t.Fatalf("ANTHROPIC_AUTH_TOKEN = %v", env["ANTHROPIC_AUTH_TOKEN"])
	}
	if settings["hasCompletedOnboarding"] != true {
		t.Fatalf("hasCompletedOnboarding = %v", settings["hasCompletedOnboarding"])
	}

	// GET now reports installed + 9Router wiring.
	rec = ctDo(ctClaudeGET(deps), "GET", "/api/cli-tools/claude-settings", "")
	got := ctJSON(t, rec)
	if got["installed"] != true || got["has9Router"] != true {
		t.Fatalf("GET after POST = %v", got)
	}

	// DELETE strips the managed env keys again.
	rec = ctDo(ctClaudeDELETE(deps), "DELETE", "/api/cli-tools/claude-settings", "")
	if rec.Code != 200 {
		t.Fatalf("DELETE status = %d", rec.Code)
	}
	raw, _ = os.ReadFile(settingsPath)
	settings = map[string]any{}
	_ = json.Unmarshal(raw, &settings)
	env, _ = settings["env"].(map[string]any)
	if _, ok := env["ANTHROPIC_BASE_URL"]; ok {
		t.Fatalf("DELETE left ANTHROPIC_BASE_URL in %s", raw)
	}
}

func TestCLIToolsCodexSettingsToml(t *testing.T) {
	home := ctSetupHome(t)
	deps := Deps{}
	rec := ctDo(ctCodexPOST(deps), "POST", "/api/cli-tools/codex-settings",
		`{"baseUrl":"http://localhost:20128","apiKey":"sk-codex","model":"openai/gpt-5"}`)
	if rec.Code != 200 {
		t.Fatalf("POST status = %d, body %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("config.toml not written: %v", err)
	}
	content := string(raw)
	for _, want := range []string{"[model_providers.9router]", `base_url = "http://localhost:20128/v1"`, `wire_api = "responses"`, `model_provider = "9router"`} {
		if !strings.Contains(content, want) {
			t.Fatalf("config.toml missing %q:\n%s", want, content)
		}
	}
	rec = ctDo(ctCodexGET(deps), "GET", "/api/cli-tools/codex-settings", "")
	if got := ctJSON(t, rec); got["has9Router"] != true {
		t.Fatalf("codex GET has9Router = %v", got["has9Router"])
	}
}

func TestCLIToolsHermesSettingsYaml(t *testing.T) {
	home := ctSetupHome(t)
	deps := Deps{}
	rec := ctDo(ctHermesPOST(deps), "POST", "/api/cli-tools/hermes-settings",
		`{"baseUrl":"http://localhost:20128","model":"openai/gpt-5","apiKey":"sk-hermes"}`)
	if rec.Code != 200 {
		t.Fatalf("POST status = %d, body %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(home, ".hermes", "config.yaml"))
	if err != nil {
		t.Fatalf("config.yaml not written: %v", err)
	}
	content := string(raw)
	for _, want := range []string{"model:", `default: "openai/gpt-5"`, `provider: "custom"`, `base_url: "http://localhost:20128/v1"`, "api_key: ${OPENAI_API_KEY}"} {
		if !strings.Contains(content, want) {
			t.Fatalf("config.yaml missing %q:\n%s", want, content)
		}
	}
	envRaw, err := os.ReadFile(filepath.Join(home, ".hermes", ".env"))
	if err != nil || !strings.Contains(string(envRaw), "OPENAI_API_KEY=sk-hermes") {
		t.Fatalf(".env missing key: %v %q", err, envRaw)
	}
	rec = ctDo(ctHermesGET(deps), "GET", "/api/cli-tools/hermes-settings", "")
	if got := ctJSON(t, rec); got["has9Router"] != true {
		t.Fatalf("hermes GET has9Router = %v (body %s)", got["has9Router"], rec.Body.String())
	}
}

func TestCLIToolsAllStatusesShape(t *testing.T) {
	ctSetupHome(t)
	deps := Deps{}
	rec := ctDo(ctAllStatusesGET(deps), "GET", "/api/cli-tools/all-statuses", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	got := ctJSON(t, rec)
	want := []string{"claude", "codex", "opencode", "droid", "openclaw", "hermes", "cowork",
		"cline", "kilo", "deepseek-tui", "jcode", "grok-build", "devin", "pi", "omp",
		"crush", "forge", "smelt", "codewhale"}
	if len(got) != len(want) {
		t.Fatalf("all-statuses returned %d keys, want %d: %v", len(got), len(want), got)
	}
	for _, k := range want {
		v, ok := got[k]
		if !ok {
			t.Fatalf("missing tool key %q", k)
		}
		if v != nil {
			if _, isObj := v.(map[string]any); !isObj {
				t.Fatalf("tool %q status is %T, want object or null", k, v)
			}
		}
	}
	// With an empty HOME every tool must report installed=false (object, not null).
	if claude, _ := got["claude"].(map[string]any); claude == nil || claude["installed"] != false {
		t.Fatalf("claude status = %v", got["claude"])
	}
}

func TestCLIToolsGrokBuildConfig(t *testing.T) {
	home := ctSetupHome(t)
	deps := Deps{}
	// Seed an existing config with a previous default to exercise markers.
	grokDir := filepath.Join(home, ".grok")
	if err := os.MkdirAll(grokDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := "[models]\ndefault = \"grok-build\"\n"
	if err := os.WriteFile(filepath.Join(grokDir, "config.toml"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := ctDo(ctGrokPOST(deps), "POST", "/api/cli-tools/grok-build-settings",
		`{"baseUrl":"http://localhost:20128","apiKey":"sk-grok","model":"openai/gpt-5"}`)
	if rec.Code != 200 {
		t.Fatalf("POST status = %d, body %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(grokDir, "config.toml"))
	content := string(raw)
	for _, want := range []string{"[model.9router]", `# 9router-prev-default = "grok-build"`, `default = "9router"`, "context_window = 200000"} {
		if !strings.Contains(content, want) {
			t.Fatalf("grok config missing %q:\n%s", want, content)
		}
	}
	// DELETE restores the previous default and drops the slot.
	rec = ctDo(ctGrokDELETE(deps), "DELETE", "/api/cli-tools/grok-build-settings", "")
	if rec.Code != 200 {
		t.Fatalf("DELETE status = %d", rec.Code)
	}
	raw, _ = os.ReadFile(filepath.Join(grokDir, "config.toml"))
	content = string(raw)
	if strings.Contains(content, "[model.9router]") || !strings.Contains(content, `default = "grok-build"`) {
		t.Fatalf("grok reset wrong:\n%s", content)
	}
}

// Compile-time guard: the registrar must exist with the contract shape.
var _ = RegisterCLITools
var _ = http.MethodGet
