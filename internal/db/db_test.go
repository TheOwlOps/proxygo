package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAppliesSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenInDir(dir)
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	defer s.Close()

	// data file at <DATA_DIR>/db/data.sqlite like paths.js
	want := filepath.Join(dir, "db", "data.sqlite")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected db file at %s: %v", want, err)
	}

	var tables int
	if err := s.SQL().QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
		 ('_meta','settings','providerConnections','providerNodes','proxyPools','apiKeys','combos','kv','usageHistory','usageDaily','requestDetails')`,
	).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 11 {
		t.Fatalf("expected 11 tables, got %d", tables)
	}
	var idx int
	if err := s.SQL().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if idx != 17 {
		t.Fatalf("expected 17 idx_* indexes, got %d", idx)
	}
	v, err := s.GetMeta("schemaVersion", "")
	if err != nil || v != "1" {
		t.Fatalf("schemaVersion meta = %q, err=%v; want \"1\"", v, err)
	}
	// Reopen: schema application must be idempotent.
	s2, err := OpenInDir(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
}

func TestDataDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	if got := DataDir(); got != dir {
		t.Fatalf("DataDir() = %q, want %q", got, dir)
	}
	if got := DataFile(); got != filepath.Join(dir, "db", "data.sqlite") {
		t.Fatalf("DataFile() = %q", got)
	}
}

func TestSettingsCRUD(t *testing.T) {
	s := openTestStore(t)

	got, err := s.Settings().GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got["comboStrategy"] != "fallback" || got["rtkEnabled"] != true || got["requireLogin"] != true {
		t.Fatalf("defaults wrong: %v", got["comboStrategy"])
	}
	updated, err := s.UpdateSettings(Record{"comboStrategy": "round-robin", "customFlag": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if updated["comboStrategy"] != "round-robin" || updated["customFlag"] != "x" {
		t.Fatalf("update not merged: %v", updated)
	}
	// merge semantics: second update keeps first
	updated2, err := s.UpdateSettings(Record{"tunnelEnabled": true})
	if err != nil {
		t.Fatal(err)
	}
	if updated2["comboStrategy"] != "round-robin" || updated2["tunnelEnabled"] != true {
		t.Fatalf("merge lost keys: %v", updated2)
	}
	raw, err := s.ExportSettings()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["comboStrategy"]; !ok {
		t.Fatal("exportSettings should return raw stored doc")
	}
	if cloud, _ := s.IsCloudEnabled(); cloud {
		t.Fatal("cloud should be disabled by default")
	}
}

func TestConnectionsCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.Connections()

	c1, err := repo.CreateProviderConnection(Record{
		"provider": "openai", "authType": "apikey", "name": "Key 1", "apiKey": "sk-aaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c1["id"] == "" || c1["priority"] != float64(1) || c1["apiKey"] != "sk-aaa" {
		t.Fatalf("created conn wrong: %v", c1)
	}
	c2, err := repo.CreateProviderConnection(Record{
		"provider": "openai", "authType": "apikey", "name": "Key 2", "apiKey": "sk-bbb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c2["priority"] != float64(2) {
		t.Fatalf("second priority = %v, want 2", c2["priority"])
	}
	// apikey dedupe by name: same name updates in place
	c1b, err := repo.CreateProviderConnection(Record{
		"provider": "openai", "authType": "apikey", "name": "Key 1", "apiKey": "sk-ccc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c1b["id"] != c1["id"] || c1b["apiKey"] != "sk-ccc" {
		t.Fatalf("dedupe failed: %v vs %v", c1b, c1)
	}
	// allowOverwrite=false refuses
	_, err = repo.CreateProviderConnection(Record{
		"provider": "openai", "authType": "apikey", "name": "Key 1", "apiKey": "sk-ddd", "allowOverwrite": false,
	})
	if err == nil {
		t.Fatal("expected NameConflictError")
	}
	if nce, ok := err.(*NameConflictError); !ok || nce.Code() != "PROVIDER_NAME_CONFLICT" || nce.ExistingID != c1["id"] {
		t.Fatalf("wrong conflict error: %#v", err)
	}

	// oauth dedupe by email
	o1, err := repo.CreateProviderConnection(Record{
		"provider": "claude", "authType": "oauth", "email": "a@x.com", "accessToken": "t1",
	})
	if err != nil {
		t.Fatal(err)
	}
	o2, err := repo.CreateProviderConnection(Record{
		"provider": "claude", "authType": "oauth", "email": "a@x.com", "accessToken": "t2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o1["id"] != o2["id"] || o2["accessToken"] != "t2" {
		t.Fatalf("oauth dedupe failed: %v / %v", o1, o2)
	}

	all, err := repo.GetProviderConnections(ConnectionFilter{Provider: "openai"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 openai conns, got %d", len(all))
	}
	byID, err := repo.GetProviderConnectionByID(strVal(c2, "id"))
	if err != nil || byID == nil || byID["apiKey"] != "sk-bbb" {
		t.Fatalf("byId: %v err=%v", byID, err)
	}

	upd, err := repo.UpdateProviderConnection(strVal(c2, "id"), Record{"testStatus": "error", "lastError": "boom"})
	if err != nil || upd["testStatus"] != "error" {
		t.Fatalf("update: %v err=%v", upd, err)
	}
	// activation resets health state
	upd2, err := repo.UpdateProviderConnection(strVal(c2, "id"), Record{"testStatus": "active"})
	if err != nil {
		t.Fatal(err)
	}
	if upd2["errorCode"] != nil || upd2["rateLimitedUntil"] != nil {
		t.Fatalf("health reset failed: %v", upd2)
	}

	ok, err := repo.DeleteProviderConnection(strVal(c1, "id"))
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	// priorities renormalized to 1..N after delete
	rest, _ := repo.GetProviderConnections(ConnectionFilter{Provider: "openai"})
	if len(rest) != 1 || rest[0]["priority"] != float64(1) {
		t.Fatalf("reorder after delete failed: %v", rest)
	}
	n, err := repo.DeleteProviderConnectionsByProvider("claude")
	if err != nil || n != 1 {
		t.Fatalf("deleteByProvider: n=%d err=%v", n, err)
	}
}

func TestNodesCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.Nodes()
	node, err := repo.CreateProviderNode(Record{
		"type": "openai-compatible", "name": "My Node", "prefix": "mn", "apiType": "chat", "baseUrl": "http://localhost:9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node["baseUrl"] != "http://localhost:9" || node["prefix"] != "mn" {
		t.Fatalf("node extras lost: %v", node)
	}
	list, err := repo.GetProviderNodes(NodeFilter{Type: "openai-compatible"})
	if err != nil || len(list) != 1 {
		t.Fatalf("list by type: %v err=%v", list, err)
	}
	upd, err := repo.UpdateProviderNode(strVal(node, "id"), Record{"name": "Renamed"})
	if err != nil || upd["name"] != "Renamed" || upd["baseUrl"] != "http://localhost:9" {
		t.Fatalf("update node: %v err=%v", upd, err)
	}
	removed, err := repo.DeleteProviderNode(strVal(node, "id"))
	if err != nil || removed == nil {
		t.Fatalf("delete node: %v err=%v", removed, err)
	}
	gone, _ := repo.GetProviderNodeByID(strVal(node, "id"))
	if gone != nil {
		t.Fatalf("node should be gone: %v", gone)
	}
}

func TestProxyPoolsCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.ProxyPools()
	pool, err := repo.CreateProxyPool(Record{"name": "P1", "proxyUrl": "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if pool["type"] != "http" || pool["testStatus"] != "unknown" || pool["isActive"] != true {
		t.Fatalf("pool defaults wrong: %v", pool)
	}
	upd, err := repo.UpdateProxyPool(strVal(pool, "id"), Record{"testStatus": "ok"})
	if err != nil || upd["testStatus"] != "ok" || upd["proxyUrl"] != "http://127.0.0.1:8080" {
		t.Fatalf("update pool: %v err=%v", upd, err)
	}
	tru := true
	list, err := repo.GetProxyPools(ProxyPoolFilter{IsActive: &tru})
	if err != nil || len(list) != 1 {
		t.Fatalf("filter pools: %v err=%v", list, err)
	}
	removed, err := repo.DeleteProxyPool(strVal(pool, "id"))
	if err != nil || removed == nil || removed["name"] != "P1" {
		t.Fatalf("delete pool: %v err=%v", removed, err)
	}
}

func TestAPIKeysCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.APIKeys()

	if _, err := repo.CreateAPIKey("bad", ""); err == nil {
		t.Fatal("machineId required")
	}
	k, err := repo.CreateAPIKey("My Key", "machine123456789")
	if err != nil {
		t.Fatal(err)
	}
	key := strVal(k, "key")
	if !strings.HasPrefix(key, "sk-machine123456789-") {
		t.Fatalf("key format: %s", key)
	}
	parts := strings.Split(key, "-")
	if len(parts) != 4 || len(parts[3]) != 8 {
		t.Fatalf("key parts: %v", parts)
	}
	valid, err := repo.ValidateAPIKey(key)
	if err != nil || !valid {
		t.Fatalf("validate: %v err=%v", valid, err)
	}
	byKey, err := repo.GetAPIKeyByKey(key)
	if err != nil || byKey == nil || byKey["name"] != "My Key" {
		t.Fatalf("byKey: %v err=%v", byKey, err)
	}
	if acc, ok := byKey["access"].(KeyAccess); !ok || acc.Restricted {
		t.Fatalf("default access should be unrestricted: %v", byKey["access"])
	}
	upd, err := repo.UpdateAPIKey(strVal(k, "id"), Record{
		"access": Record{"restricted": true, "allow": []any{"gpt-5", " GPT-5 ", "claude-sonnet-5"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := upd["access"].(KeyAccess)
	if !acc.Restricted || len(acc.Allow) != 2 {
		t.Fatalf("access update/dedupe wrong: %+v", acc)
	}
	upd2, err := repo.UpdateAPIKey(strVal(k, "id"), Record{"isActive": false})
	if err != nil {
		t.Fatal(err)
	}
	_ = upd2
	valid, _ = repo.ValidateAPIKey(key)
	if valid {
		t.Fatal("inactive key must not validate")
	}
	ok, err := repo.DeleteAPIKey(strVal(k, "id"))
	if err != nil || !ok {
		t.Fatalf("delete key: %v %v", ok, err)
	}
}

func TestCombosCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.Combos()
	c, err := repo.CreateCombo(Record{"name": "my-combo", "kind": "fallback", "models": []any{"openai/gpt-5", "claude/sonnet"}})
	if err != nil {
		t.Fatal(err)
	}
	byName, err := repo.GetComboByName("my-combo")
	if err != nil || byName == nil {
		t.Fatalf("byName: %v err=%v", byName, err)
	}
	models := toSlice(byName["models"])
	if len(models) != 2 || models[0] != "openai/gpt-5" {
		t.Fatalf("models round-trip: %v", byName["models"])
	}
	upd, err := repo.UpdateCombo(strVal(c, "id"), Record{"models": []any{"openai/gpt-5"}})
	if err != nil || len(toSlice(upd["models"])) != 1 {
		t.Fatalf("update combo: %v err=%v", upd, err)
	}
	ok, err := repo.DeleteCombo(strVal(c, "id"))
	if err != nil || !ok {
		t.Fatalf("delete combo: %v %v", ok, err)
	}
	list, _ := repo.GetCombos()
	if len(list) != 0 {
		t.Fatalf("combos should be empty: %v", list)
	}
}

func TestAliasesCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.Aliases()

	if err := repo.SetModelAlias("fast", "openai/gpt-5-mini"); err != nil {
		t.Fatal(err)
	}
	aliases, err := repo.GetModelAliases()
	if err != nil || aliases["fast"] != "openai/gpt-5-mini" {
		t.Fatalf("aliases: %v err=%v", aliases, err)
	}
	if err := repo.DeleteModelAlias("fast"); err != nil {
		t.Fatal(err)
	}
	aliases, _ = repo.GetModelAliases()
	if _, ok := aliases["fast"]; ok {
		t.Fatal("alias not deleted")
	}

	added, err := repo.AddCustomModel(Record{"providerAlias": "mn", "id": "m1", "name": "Model 1"})
	if err != nil || !added {
		t.Fatalf("addCustomModel: added=%v err=%v", added, err)
	}
	added, err = repo.AddCustomModel(Record{"providerAlias": "mn", "id": "m1", "name": "Model 1b"})
	if err != nil || added {
		t.Fatalf("re-add should update, added=%v err=%v", added, err)
	}
	models, err := repo.GetCustomModels()
	if err != nil || len(models) != 1 || models[0]["name"] != "Model 1b" || models[0]["type"] != "llm" {
		t.Fatalf("custom models: %v err=%v", models, err)
	}
	if err := repo.DeleteCustomModel("mn", "m1", "llm"); err != nil {
		t.Fatal(err)
	}
	models, _ = repo.GetCustomModels()
	if len(models) != 0 {
		t.Fatalf("custom models should be empty: %v", models)
	}

	if err := repo.SetMitmAliasAll("claude-code", Record{"sonnet": "openai/gpt-5"}); err != nil {
		t.Fatal(err)
	}
	mitm, err := repo.GetMitmAlias("claude-code")
	if err != nil || toMap(mitm)["sonnet"] != "openai/gpt-5" {
		t.Fatalf("mitm alias: %v err=%v", mitm, err)
	}
	all, err := repo.GetMitmAlias("")
	if err != nil || all["claude-code"] == nil {
		t.Fatalf("mitm all: %v err=%v", all, err)
	}
}

func TestPricingCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.Pricing()

	user, err := repo.UpdatePricing(Record{
		"openai": Record{"gpt-x": Record{"input": 1.5, "output": 3.0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if toMap(toMap(user["openai"])["gpt-x"])["input"] != 1.5 {
		t.Fatalf("updatePricing: %v", user)
	}
	p, err := repo.GetPricingForModel("openai", "gpt-x")
	if err != nil || p == nil || p["output"] != 3.0 {
		t.Fatalf("getPricingForModel: %v err=%v", p, err)
	}
	all, err := repo.GetPricing()
	if err != nil || all["openai"] == nil {
		t.Fatalf("getPricing: %v err=%v", all, err)
	}
	if _, err := repo.ResetPricing("openai", "gpt-x"); err != nil {
		t.Fatal(err)
	}
	p, _ = repo.GetPricingForModel("openai", "gpt-x")
	if p != nil {
		t.Fatalf("pricing should be reset: %v", p)
	}
	if _, err := repo.UpdatePricing(Record{"claude": Record{"m": Record{"input": 1.0}}}); err != nil {
		t.Fatal(err)
	}
	empty, err := repo.ResetAllPricing()
	if err != nil || len(empty) != 0 {
		t.Fatalf("resetAll: %v err=%v", empty, err)
	}

	// cost math (open-sse calculateCostFromTokens): 1M prompt (200k cached)
	// + 500k output at input=2, cached=0.5, output=10 → 0.8*2 + 0.2*0.5 + 0.5*10
	cost := CalculateCostFromTokens(
		Record{"prompt_tokens": 1000000.0, "cached_tokens": 200000.0, "completion_tokens": 500000.0},
		Record{"input": 2.0, "output": 10.0, "cached": 0.5},
	)
	if cost != 1.6+0.1+5.0 {
		t.Fatalf("cost = %v, want 6.7", cost)
	}
}

func TestDisabledModelsCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.DisabledModels()

	if err := repo.DisableModels("openai", []any{"gpt-a", "gpt-b"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.DisableModels("openai", []any{"gpt-b", "gpt-c"}); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.GetDisabledByProvider("openai")
	if err != nil || len(ids) != 3 {
		t.Fatalf("disabled ids: %v err=%v", ids, err)
	}
	all, err := repo.GetDisabledModels()
	if err != nil || all["openai"] == nil {
		t.Fatalf("disabled all: %v err=%v", all, err)
	}
	if err := repo.EnableModels("openai", []any{"gpt-a"}); err != nil {
		t.Fatal(err)
	}
	ids, _ = repo.GetDisabledByProvider("openai")
	if len(ids) != 2 {
		t.Fatalf("after enable: %v", ids)
	}
	if err := repo.EnableModels("openai", nil); err != nil {
		t.Fatal(err)
	}
	ids, _ = repo.GetDisabledByProvider("openai")
	if len(ids) != 0 {
		t.Fatalf("enable-all should clear: %v", ids)
	}
}

func TestUsageCRUD(t *testing.T) {
	s := openTestStore(t)
	repo := s.Usage()

	entry := Record{
		"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"provider":  "openai", "model": "gpt-x", "connectionId": "conn-1",
		"endpoint": "/v1/chat/completions", "status": "ok",
		"tokens": Record{"prompt_tokens": 100.0, "completion_tokens": 50.0},
	}
	if err := repo.SaveRequestUsage(entry); err != nil {
		t.Fatal(err)
	}
	// JS dedupe: identical entry does not double-count
	if err := repo.SaveRequestUsage(cloneMap(entry)); err != nil {
		t.Fatal(err)
	}
	hist, err := repo.GetUsageHistory(UsageFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("history should have 1 row after dedupe, got %d", len(hist))
	}
	hist2, err := repo.GetUsageHistory(UsageFilter{Provider: "openai"})
	if err != nil || len(hist2) != 1 {
		t.Fatalf("history filter: %v err=%v", hist2, err)
	}

	stats, err := repo.GetUsageStats("all")
	if err != nil {
		t.Fatal(err)
	}
	if numVal(stats["totalRequests"]) != 1 || numVal(stats["totalPromptTokens"]) != 100 || numVal(stats["totalCompletionTokens"]) != 50 {
		t.Fatalf("stats totals: %v %v %v", stats["totalRequests"], stats["totalPromptTokens"], stats["totalCompletionTokens"])
	}
	if toMap(stats["byProvider"])["openai"] == nil {
		t.Fatalf("byProvider missing: %v", stats["byProvider"])
	}
	stats24, err := repo.GetUsageStats("24h")
	if err != nil || numVal(stats24["totalRequests"]) != 1 {
		t.Fatalf("stats24: %v err=%v", stats24, err)
	}

	chart, err := repo.GetChartData("7d")
	if err != nil || len(chart) != 7 {
		t.Fatalf("chart 7d: len=%d err=%v", len(chart), err)
	}
	todayChart, err := repo.GetChartData("today")
	if err != nil || len(todayChart) != 24 {
		t.Fatalf("chart today: len=%d err=%v", len(todayChart), err)
	}

	logs, err := repo.GetRecentLogs(10)
	if err != nil || len(logs) != 1 || !strings.Contains(logs[0], "GPT-X") && !strings.Contains(logs[0], "gpt-x") {
		t.Fatalf("logs: %v err=%v", logs, err)
	}
	lifetime, err := s.GetMeta("totalRequestsLifetime", "0")
	if err != nil || lifetime != "1" {
		t.Fatalf("lifetime = %q err=%v", lifetime, err)
	}

	// pending tracking
	repo.TrackPendingRequest("gpt-x", "openai", "conn-1", true, false)
	active, err := repo.GetActiveRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(active["activeRequests"].([]Record)) != 1 {
		t.Fatalf("active requests: %v", active)
	}
	repo.TrackPendingRequest("gpt-x", "openai", "conn-1", false, false)
	active, _ = repo.GetActiveRequests()
	if len(active["activeRequests"].([]Record)) != 0 {
		t.Fatalf("active after finish: %v", active)
	}
}

func TestRequestDetailsCRUD(t *testing.T) {
	t.Setenv("ENABLE_REQUEST_LOGS", "true")
	s := openTestStore(t)
	repo := s.RequestDetails()

	detail := Record{
		"provider": "openai", "model": "gpt-x", "connectionId": "conn-1", "status": "ok",
		"request": Record{
			"headers": Record{"Authorization": "Bearer secret", "X-Custom": "keep"},
			"body":    "hello",
		},
		"response": Record{"body": "world"},
	}
	if err := repo.SaveRequestDetail(detail); err != nil {
		t.Fatal(err)
	}
	page, err := repo.GetRequestDetails(RequestDetailsFilter{Provider: "openai"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Details) != 1 {
		t.Fatalf("details: %v", page.Details)
	}
	saved := page.Details[0]
	headers := toMap(toMap(saved["request"])["headers"])
	if _, leaked := headers["Authorization"]; leaked {
		t.Fatal("Authorization header must be sanitized")
	}
	if headers["X-Custom"] != "keep" {
		t.Fatalf("non-sensitive header lost: %v", headers)
	}
	byID, err := repo.GetRequestDetailByID(strVal(saved, "id"))
	if err != nil || byID == nil {
		t.Fatalf("byId: %v err=%v", byID, err)
	}
	providers, err := repo.GetDistinctProviders()
	if err != nil || len(providers) != 1 || providers[0] != "openai" {
		t.Fatalf("providers: %v err=%v", providers, err)
	}
	if page.Pagination["totalItems"] != 1 {
		t.Fatalf("pagination: %v", page.Pagination)
	}
}

func TestRequestDetailsDisabledByDefault(t *testing.T) {
	s := openTestStore(t)
	// Default settings: enableObservability=false, env unset → disabled
	// (env fallback is OBSERVABILITY_ENABLED != "false", but the settings
	// boolean wins in JS when present — default settings carry it false).
	// OBSERVABILITY_ENABLED is unset here; JS settings.enableObservability
	// default false means disabled.
	if err := s.SaveRequestDetail(Record{"provider": "openai", "model": "m"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.SQL().QueryRow(`SELECT COUNT(*) FROM requestDetails`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	// NOTE: JS default DEFAULT_SETTINGS has enableObservability: false, so
	// nothing is written.
	if n != 0 {
		t.Fatalf("expected 0 details when disabled, got %d", n)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.CreateProviderConnection(Record{"provider": "openai", "authType": "apikey", "name": "K", "apiKey": "sk-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCombo(Record{"name": "cb", "models": []any{"a/b"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetModelAlias("fast", "a/b"); err != nil {
		t.Fatal(err)
	}
	exp, err := s.ExportDB()
	if err != nil {
		t.Fatal(err)
	}

	s2 := openTestStore(t)
	restored, err := s2.ImportDB(exp)
	if err != nil {
		t.Fatal(err)
	}
	conns, _ := s2.GetProviderConnections(ConnectionFilter{})
	if len(conns) != 1 || conns[0]["apiKey"] != "sk-1" {
		t.Fatalf("imported conns: %v", conns)
	}
	combos, _ := s2.GetCombos()
	if len(combos) != 1 || combos[0]["name"] != "cb" {
		t.Fatalf("imported combos: %v", combos)
	}
	aliases, _ := s2.GetModelAliases()
	if aliases["fast"] != "a/b" {
		t.Fatalf("imported aliases: %v", aliases)
	}
	if restored == nil {
		t.Fatal("import should return exported db")
	}
}

func TestKVStore(t *testing.T) {
	s := openTestStore(t)
	kv := s.KV().Scoped("testScope")
	if err := kv.Set("a", Record{"x": 1.0}); err != nil {
		t.Fatal(err)
	}
	v, err := kv.Get("a", nil)
	if err != nil || toMap(v)["x"] != 1.0 {
		t.Fatalf("kv get: %v err=%v", v, err)
	}
	if err := kv.SetMany(Record{"b": "two", "c": "three"}); err != nil {
		t.Fatal(err)
	}
	all, err := kv.GetAll()
	if err != nil || len(all) != 3 {
		t.Fatalf("kv getAll: %v err=%v", all, err)
	}
	if err := kv.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if err := kv.Clear(); err != nil {
		t.Fatal(err)
	}
	all, _ = kv.GetAll()
	if len(all) != 0 {
		t.Fatalf("kv clear: %v", all)
	}
	if err := s.SetMeta("k1", "v1"); err != nil {
		t.Fatal(err)
	}
	mv, err := s.GetMeta("k1", "")
	if err != nil || mv != "v1" {
		t.Fatalf("meta: %q err=%v", mv, err)
	}
}
