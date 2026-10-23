package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"9router-go/internal/db"
)

type opTestEnv struct {
	mux   *http.ServeMux
	store *db.Store
	dir   string
}

func newOpTestEnv(t *testing.T) *opTestEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.UpdateSettings(db.Record{"requireLogin": false}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	mux := http.NewServeMux()
	RegisterOps(mux, Deps{Store: store})
	return &opTestEnv{mux: mux, store: store, dir: dir}
}

func (e *opTestEnv) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:4321"
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func opDecode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestOpUsageStatsValidation(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/usage/stats?period=bogus", "")
	if rec.Code != 400 {
		t.Fatalf("invalid period status = %d", rec.Code)
	}
	if got := opDecode(t, rec)["error"]; got != "Invalid period" {
		t.Fatalf("error = %v", got)
	}
	rec = env.do(t, "GET", "/api/usage/stats", "")
	if rec.Code != 200 {
		t.Fatalf("stats status = %d body %s", rec.Code, rec.Body.String())
	}
	rec = env.do(t, "GET", "/api/usage/chart?period=30d", "")
	if rec.Code != 200 {
		t.Fatalf("chart status = %d", rec.Code)
	}
	rec = env.do(t, "GET", "/api/usage/history", "")
	if rec.Code != 200 {
		t.Fatalf("history status = %d", rec.Code)
	}
	rec = env.do(t, "GET", "/api/usage/logs", "")
	if rec.Code != 200 {
		t.Fatalf("logs status = %d", rec.Code)
	}
}

func TestOpUsageRequestDetailsRedaction(t *testing.T) {
	env := newOpTestEnv(t)
	// Request details are only recorded with observability on
	// (settings default is false, same as the JS).
	if _, err := env.store.UpdateSettings(db.Record{"enableObservability": true}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	err := env.store.SaveRequestDetail(db.Record{
		"id":        "det-1",
		"provider":  "openai",
		"model":     "gpt-4o",
		"status":    "success",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"request":   db.Record{"messages": []any{db.Record{"role": "user", "content": "secret prompt"}}},
		"response":  db.Record{"choices": []any{}},
	})
	if err != nil {
		t.Fatalf("save detail: %v", err)
	}
	rec := env.do(t, "GET", "/api/usage/request-details?page=0", "")
	if rec.Code != 400 {
		t.Fatalf("page<1 status = %d", rec.Code)
	}
	rec = env.do(t, "GET", "/api/usage/request-details?pageSize=101", "")
	if rec.Code != 400 {
		t.Fatalf("pageSize>100 status = %d", rec.Code)
	}
	rec = env.do(t, "GET", "/api/usage/request-details", "")
	if rec.Code != 200 {
		t.Fatalf("details status = %d body %s", rec.Code, rec.Body.String())
	}
	out := opDecode(t, rec)
	details, _ := out["details"].([]any)
	if len(details) != 1 {
		t.Fatalf("details len = %d (%v)", len(details), out)
	}
	d0, _ := details[0].(map[string]any)
	reqField, _ := d0["request"].(map[string]any)
	if reqField["redacted"] != true {
		t.Fatalf("request not redacted: %v", d0["request"])
	}
	if strings.Contains(rec.Body.String(), "secret prompt") {
		t.Fatal("prompt leaked through redaction")
	}
	if d0["provider"] != "openai" {
		t.Fatalf("provider = %v", d0["provider"])
	}
	// providers endpoint reflects the distinct provider
	rec = env.do(t, "GET", "/api/usage/providers", "")
	out = opDecode(t, rec)
	provs, _ := out["providers"].([]any)
	if len(provs) != 1 || provs[0].(map[string]any)["id"] != "openai" {
		t.Fatalf("providers = %v", out)
	}
	if provs[0].(map[string]any)["name"] != "OpenAI" {
		t.Fatalf("provider display name = %v", provs[0])
	}
}

func TestOpUsageConnectionGuards(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/usage/nope", "")
	if rec.Code != 404 {
		t.Fatalf("missing connection status = %d", rec.Code)
	}
	conn, err := env.store.CreateProviderConnection(db.Record{
		"id": "c1", "provider": "openai", "authType": "apikey",
		"apiKey": "sk-test", "isActive": true,
	})
	if err != nil {
		t.Fatalf("create conn: %v", err)
	}
	connID, _ := conn["id"].(string)
	if connID == "" {
		connID = "c1"
	}
	rec = env.do(t, "GET", "/api/usage/"+connID, "")
	if rec.Code != 200 {
		t.Fatalf("apikey non-eligible status = %d", rec.Code)
	}
	if got := opDecode(t, rec)["message"]; got != "Usage not available for this connection" {
		t.Fatalf("message = %v", got)
	}
	// codex guards
	rec = env.do(t, "GET", "/api/usage/"+connID+"/codex-reset-credits", "")
	if rec.Code != 400 {
		t.Fatalf("codex guard status = %d body %s", rec.Code, rec.Body.String())
	}
	rec = env.do(t, "POST", "/api/usage/"+connID+"/claude-reset", `{"grantId":"abc"}`)
	if rec.Code != 400 {
		t.Fatalf("claude reset guard status = %d", rec.Code)
	}
}

func TestOpTranslatorLoadSave(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/translator/load", "")
	if rec.Code != 400 {
		t.Fatalf("missing file param status = %d", rec.Code)
	}
	rec = env.do(t, "GET", "/api/translator/load?file=evil.json", "")
	if rec.Code != 400 || opDecode(t, rec)["error"] != "Invalid file name" {
		t.Fatalf("invalid file status = %d body %s", rec.Code, rec.Body.String())
	}
	rec = env.do(t, "GET", "/api/translator/load?file=1_req_client.json", "")
	if rec.Code != 404 {
		t.Fatalf("not found status = %d", rec.Code)
	}
	rec = env.do(t, "POST", "/api/translator/save", `{"file":"1_req_client.json","content":"{\"model\":\"gpt-4o\"}"}`)
	if rec.Code != 200 || opDecode(t, rec)["success"] != true {
		t.Fatalf("save status = %d body %s", rec.Code, rec.Body.String())
	}
	// saved under DATA_DIR/logs/translator
	if _, err := os.Stat(filepath.Join(env.dir, "logs", "translator", "1_req_client.json")); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}
	rec = env.do(t, "GET", "/api/translator/load?file=1_req_client.json", "")
	out := opDecode(t, rec)
	if out["success"] != true || out["content"] != `{"model":"gpt-4o"}` {
		t.Fatalf("load = %v", out)
	}
}

func TestOpTranslatorTranslateSteps(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "POST", "/api/translator/translate", `{"step":1,"body":{"model":"openai/gpt-4o","messages":[{"role":"user","content":"hi"}]}}`)
	if rec.Code != 200 {
		t.Fatalf("step1 status = %d body %s", rec.Code, rec.Body.String())
	}
	out := opDecode(t, rec)
	result, _ := out["result"].(map[string]any)
	if result["provider"] != "openai" || result["model"] != "gpt-4o" {
		t.Fatalf("step1 result = %v", result)
	}
	if result["sourceFormat"] != "openai" || result["targetFormat"] != "openai" {
		t.Fatalf("step1 formats = %v", result)
	}
	rec = env.do(t, "POST", "/api/translator/translate", `{"step":9,"body":{}}`)
	if rec.Code != 400 {
		t.Fatalf("invalid step status = %d", rec.Code)
	}
	rec = env.do(t, "POST", "/api/translator/translate", `{"step":3,"body":{"provider":"openai","model":"gpt-4o","messages":[]}}`)
	if rec.Code != 400 || opDecode(t, rec)["error"] != "No active connection for provider: openai" {
		t.Fatalf("step3 no-conn status = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestOpTranslatorConsoleLogs(t *testing.T) {
	env := newOpTestEnv(t)
	AddConsoleLog("hello console")
	rec := env.do(t, "GET", "/api/translator/console-logs", "")
	out := opDecode(t, rec)
	logs, _ := out["logs"].([]any)
	found := false
	for _, l := range logs {
		if l == "hello console" {
			found = true
		}
	}
	if !found {
		t.Fatalf("logs = %v", out)
	}
	rec = env.do(t, "DELETE", "/api/translator/console-logs", "")
	if rec.Code != 200 {
		t.Fatalf("delete status = %d", rec.Code)
	}
	rec = env.do(t, "GET", "/api/translator/console-logs", "")
	logs, _ = opDecode(t, rec)["logs"].([]any)
	if len(logs) != 0 {
		t.Fatalf("logs after clear = %v", logs)
	}
}

func TestOpTunnelStatusShape(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/tunnel/status", "")
	if rec.Code != 200 {
		t.Fatalf("tunnel status = %d body %s", rec.Code, rec.Body.String())
	}
	out := opDecode(t, rec)
	tun, _ := out["tunnel"].(map[string]any)
	if tun == nil || tun["enabled"] != false || tun["running"] != false {
		t.Fatalf("tunnel = %v", out["tunnel"])
	}
	ts, _ := out["tailscale"].(map[string]any)
	if ts == nil || ts["enabled"] != false {
		t.Fatalf("tailscale = %v", out["tailscale"])
	}
	dl, _ := out["download"].(map[string]any)
	if dl == nil || dl["downloading"] != false {
		t.Fatalf("download = %v", out["download"])
	}
	rec = env.do(t, "GET", "/api/tunnel/tailscale-check", "")
	out = opDecode(t, rec)
	if out["installed"] == nil || out["platform"] == nil || out["hasCachedPassword"] != false {
		t.Fatalf("tailscale-check = %v", out)
	}
}

func TestOpHeadroomStatusShape(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/headroom/status", "")
	if rec.Code != 200 {
		t.Fatalf("headroom status = %d body %s", rec.Code, rec.Body.String())
	}
	out := opDecode(t, rec)
	if out["url"] != "http://localhost:8787" {
		t.Fatalf("url = %v", out["url"])
	}
	if _, ok := out["installed"]; !ok {
		t.Fatalf("missing installed: %v", out)
	}
	if out["localUrl"] != true {
		t.Fatalf("localUrl = %v", out["localUrl"])
	}
	rec = env.do(t, "POST", "/api/headroom/stop", "")
	if rec.Code != 409 {
		t.Fatalf("stop not-running status = %d body %s", rec.Code, rec.Body.String())
	}
	rec = env.do(t, "GET", "/api/headroom/extras", "")
	if rec.Code != 200 {
		t.Fatalf("extras status = %d", rec.Code)
	}
}

func TestOpPxpipeStatusAndStats(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/pxpipe/status", "")
	if rec.Code != 200 {
		t.Fatalf("pxpipe status = %d body %s", rec.Code, rec.Body.String())
	}
	out := opDecode(t, rec)
	if out["installed"] != false || out["mode"] != "library" || out["running"] != false {
		t.Fatalf("status = %v", out)
	}
	rec = env.do(t, "GET", "/api/pxpipe/health", "")
	out = opDecode(t, rec)
	if out["healthy"] != false || out["error"] != "pxpipe not installed" {
		t.Fatalf("health = %v", out)
	}
	// pxpipeAutoInstall defaults to true; disable it to see the 409.
	if _, err := env.store.UpdateSettings(db.Record{"pxpipeAutoInstall": false}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	rec = env.do(t, "POST", "/api/pxpipe/start", "")
	if rec.Code != 409 {
		t.Fatalf("start not-installed status = %d body %s", rec.Code, rec.Body.String())
	}
	// seed an events file and check stats aggregation
	pxDir := filepath.Join(env.dir, "pxpipe")
	if err := os.MkdirAll(pxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	lines := ""
	for _, ev := range []map[string]any{
		{"ts": now, "applied": true, "tokensBeforeEst": 1000, "tokensAfterEst": 400, "tokensSavedEst": 600, "durationMs": 50, "imageCount": 1},
		{"ts": now, "applied": false, "reason": "too_small"},
		{"ts": now, "applied": false, "reason": "timeout"},
	} {
		raw, _ := json.Marshal(ev)
		lines += string(raw) + "\n"
	}
	if err := os.WriteFile(filepath.Join(pxDir, "events.jsonl"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = env.do(t, "GET", "/api/pxpipe/stats", "")
	out = opDecode(t, rec)
	windows, _ := out["windows"].(map[string]any)
	all, _ := windows["all"].(map[string]any)
	if all["requests"] != float64(3) || all["compressed"] != float64(1) || all["bypassed"] != float64(1) || all["errors"] != float64(1) {
		t.Fatalf("windows.all = %v", all)
	}
	if all["savedPct"] != float64(60) {
		t.Fatalf("savedPct = %v", all["savedPct"])
	}
	recent, _ := out["recent"].([]any)
	if len(recent) != 3 {
		t.Fatalf("recent len = %d", len(recent))
	}
	rec = env.do(t, "GET", "/api/pxpipe/logs", "")
	out = opDecode(t, rec)
	events, _ := out["events"].([]any)
	if len(events) != 3 {
		t.Fatalf("logs events = %v", out)
	}
}

func TestOpMcpUnknownPlugin(t *testing.T) {
	env := newOpTestEnv(t)
	rec := env.do(t, "GET", "/api/mcp/nope/sse", "")
	if rec.Code != 404 {
		t.Fatalf("sse unknown status = %d", rec.Code)
	}
	rec = env.do(t, "POST", "/api/mcp/nope/message", `{}`)
	if rec.Code != 404 {
		t.Fatalf("message unknown status = %d", rec.Code)
	}
	rec = env.do(t, "POST", "/api/mcp/browsermcp/message", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if rec.Code != 500 || opDecode(t, rec)["error"] != "Bridge not running: browsermcp" {
		t.Fatalf("message no-bridge status = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestOpUsageHelpers(t *testing.T) {
	// parseResetTime: seconds vs ms vs ISO
	if got := opParseResetTime(float64(1700000000)); got != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("reset seconds = %v", got)
	}
	if got := opParseResetTime("1700000000000"); got != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("reset ms string = %v", got)
	}
	if got := opParseResetTime(nil); got != nil {
		t.Fatalf("reset nil = %v", got)
	}
	// groq duration parsing
	if got := opGroqResetAt(""); got != nil {
		t.Fatalf("groq empty = %v", got)
	}
	if got := opGroqResetAt("garbage"); got != nil {
		t.Fatalf("groq garbage = %v", got)
	}
	before := time.Now()
	got := opGroqResetAt("2m0s")
	parsed, err := time.Parse(time.RFC3339, got.(string))
	if err != nil || parsed.Before(before.Add(110*time.Second)) || parsed.After(before.Add(130*time.Second)) {
		t.Fatalf("groq 2m = %v err %v", got, err)
	}
	// claude reset grants
	grants := opParseClaudeResetGrants(map[string]any{
		"eligible": true, "next_grant_id": "g1",
		"grants": []any{
			map[string]any{"id": "g1", "resets_left": float64(2), "ends_at": "2026-01-01", "clears": []any{"weekly"}},
			map[string]any{"id": "g2", "resets_left": float64(1), "paused": true},
		},
	})
	gm, _ := grants.(map[string]any)
	if gm == nil || gm["availableCount"] != float64(2) || gm["nextGrantId"] != "g1" {
		t.Fatalf("grants = %v", grants)
	}
	if got := opParseClaudeResetGrants(map[string]any{"eligible": false}); got != nil {
		t.Fatalf("ineligible grants = %v", got)
	}
	// MCP filter: short text untouched, sibling collapse for long text
	long := strings.Repeat("- link \"x\"\n", 40) + strings.Repeat("padding line to reach two thousand chars total in this snapshot text block. ", 40)
	filtered := opMcpSmartFilterText(long)
	if !strings.Contains(filtered, "items omitted by 9router bridge") {
		t.Fatalf("collapse missing: %.200s", filtered)
	}
	// codex window clamp
	win := opCodexWindow(map[string]any{"used_percent": float64(140)})
	if win["used"] != float64(100) || win["remaining"] != float64(0) {
		t.Fatalf("codex window = %v", win)
	}
}
