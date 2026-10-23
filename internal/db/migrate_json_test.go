package db

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func legacyFixtureMain() Record {
	return Record{
		"settings": Record{"theme": "dark", "requireApiKey": false, "customFlag": "yes"},
		"providerConnections": []any{
			Record{"id": "c1", "provider": "openai", "authType": "apikey", "name": "Main key",
				"email": "a@example.com", "priority": float64(1), "isActive": true,
				"apiKey": "sk-legacy-1", "providerSpecificData": Record{"baseUrl": "http://localhost:9999/v1"},
				"createdAt": "2024-01-01T00:00:00.000Z", "updatedAt": "2024-01-02T00:00:00.000Z"},
			Record{"id": "c2", "provider": "claude", "name": "OAuth conn",
				"accessToken": "tok-123", "refreshToken": "ref-456", "isActive": false},
		},
		"providerNodes": []any{
			Record{"id": "n1", "type": "openai-compatible", "name": "Local node", "baseUrl": "http://127.0.0.1:8080/v1"},
		},
		"proxyPools": []any{
			Record{"id": "p1", "proxyUrl": "http://127.0.0.1:3128"},
		},
		"apiKeys": []any{
			Record{"id": "k1", "key": "sk-app-key-1", "name": "App key", "machineId": "m-1", "isActive": true},
		},
		"combos": []any{
			Record{"id": "cb1", "name": "my-combo", "kind": "fallback", "models": []any{"openai/gpt-4o", "claude/claude-sonnet-4-5"}},
		},
		"modelAliases": Record{"fast": "openai/gpt-4o-mini"},
		"customModels": []any{
			Record{"providerAlias": "openai", "id": "my-model", "type": "llm", "name": "My Model"},
		},
		"mitmAlias": Record{"claude": Record{"a": "b"}},
		"pricing":   Record{"openai": Record{"gpt-4o": Record{"input": 1.0}}},
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.sql.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestImportLegacyJSONOnce(t *testing.T) {
	dir := t.TempDir()
	writeJSONFile(t, filepath.Join(dir, "db.json"), legacyFixtureMain())
	writeJSONFile(t, filepath.Join(dir, "usage.json"), Record{
		"history": []any{
			Record{"timestamp": "2024-03-01T00:00:00.000Z", "provider": "openai", "model": "gpt-4o",
				"tokens": Record{"prompt_tokens": float64(10), "completion_tokens": float64(5)}, "cost": 0.5, "status": "ok"},
			Record{"timestamp": "2024-03-01T01:00:00.000Z", "provider": "claude", "model": "claude-sonnet-4-5",
				"tokens": Record{"input_tokens": float64(50), "output_tokens": float64(7)}},
		},
		"dailySummary":          Record{"2024-03-01": Record{"requests": float64(2)}},
		"totalRequestsLifetime": float64(1234),
	})
	writeJSONFile(t, filepath.Join(dir, "disabledModels.json"), Record{
		"disabled": Record{"openai": []any{"gpt-3.5-turbo"}},
	})
	writeJSONFile(t, filepath.Join(dir, "request-details.json"), Record{
		"records": []any{
			Record{"id": "r1", "timestamp": "2024-03-01T00:00:00.000Z", "provider": "openai", "model": "gpt-4o", "status": "200"},
		},
	})

	s, err := OpenInDir(dir)
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	defer func() { _ = s.Close() }()

	imported, err := s.ImportLegacyJSONOnce()
	if err != nil {
		t.Fatalf("ImportLegacyJSONOnce: %v", err)
	}
	if !imported {
		t.Fatal("expected imported=true")
	}

	// Main collections landed.
	if n := countRows(t, s, "providerConnections"); n != 2 {
		t.Fatalf("providerConnections = %d, want 2", n)
	}
	if n := countRows(t, s, "providerNodes"); n != 1 {
		t.Fatalf("providerNodes = %d, want 1", n)
	}
	if n := countRows(t, s, "proxyPools"); n != 1 {
		t.Fatalf("proxyPools = %d, want 1", n)
	}
	if n := countRows(t, s, "apiKeys"); n != 1 {
		t.Fatalf("apiKeys = %d, want 1", n)
	}
	if n := countRows(t, s, "combos"); n != 1 {
		t.Fatalf("combos = %d, want 1", n)
	}

	// Repo-level views work on the imported rows.
	settings, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["theme"] != "dark" || settings["customFlag"] != "yes" {
		t.Fatalf("settings not imported: %v", settings)
	}
	conn, err := s.GetProviderConnectionByID("c1")
	if err != nil || conn == nil {
		t.Fatalf("GetProviderConnectionByID c1: %v %v", conn, err)
	}
	if conn["apiKey"] != "sk-legacy-1" || conn["provider"] != "openai" || conn["authType"] != "apikey" {
		t.Fatalf("connection c1 fields wrong: %v", conn)
	}
	conn2, err := s.GetProviderConnectionByID("c2")
	if err != nil || conn2 == nil {
		t.Fatalf("GetProviderConnectionByID c2: %v %v", conn2, err)
	}
	if conn2["authType"] != "oauth" { // JS default when missing
		t.Fatalf("connection c2 authType = %v, want oauth (JS default)", conn2["authType"])
	}
	combo, err := s.GetComboByName("my-combo")
	if err != nil || combo == nil {
		t.Fatalf("GetComboByName: %v %v", combo, err)
	}
	if models := toSlice(combo["models"]); len(models) != 2 {
		t.Fatalf("combo models = %v", combo["models"])
	}
	aliases, err := s.GetModelAliases()
	if err != nil || aliases["fast"] != "openai/gpt-4o-mini" {
		t.Fatalf("modelAliases = %v err=%v", aliases, err)
	}
	disabled, err := s.GetDisabledModels()
	if err != nil {
		t.Fatalf("GetDisabledModels: %v", err)
	}
	if ids := toSlice(disabled["openai"]); len(ids) != 1 || ids[0] != "gpt-3.5-turbo" {
		t.Fatalf("disabledModels = %v", disabled)
	}

	// Usage import: prompt/completion fallback semantics (input_tokens
	// used when prompt_tokens is absent).
	if n := countRows(t, s, "usageHistory"); n != 2 {
		t.Fatalf("usageHistory = %d, want 2", n)
	}
	if n := countRows(t, s, "usageDaily"); n != 1 {
		t.Fatalf("usageDaily = %d, want 1", n)
	}
	if n := countRows(t, s, "requestDetails"); n != 1 {
		t.Fatalf("requestDetails = %d, want 1", n)
	}
	var prompt int
	if err := s.sql.QueryRow(`SELECT promptTokens FROM usageHistory WHERE provider='claude'`).Scan(&prompt); err != nil {
		t.Fatalf("usage promptTokens: %v", err)
	}
	if prompt != 50 {
		t.Fatalf("claude promptTokens = %d, want 50 (input_tokens fallback)", prompt)
	}
	lifetime, err := s.GetMeta("totalRequestsLifetime", "")
	if err != nil || lifetime != "1234" {
		t.Fatalf("totalRequestsLifetime meta = %q err=%v", lifetime, err)
	}

	// Marker written; second run is a no-op.
	if _, err := os.Stat(filepath.Join(dir, "db", ".migrated-from-json")); err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	again, err := s.ImportLegacyJSONOnce()
	if err != nil || again {
		t.Fatalf("second import = %v err=%v, want no-op", again, err)
	}
	if n := countRows(t, s, "providerConnections"); n != 2 {
		t.Fatalf("after second import providerConnections = %d, want 2", n)
	}
}

func TestImportLegacyJSONSkipsNonEmptyStore(t *testing.T) {
	dir := t.TempDir()
	writeJSONFile(t, filepath.Join(dir, "db.json"), legacyFixtureMain())

	s, err := OpenInDir(dir)
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	defer func() { _ = s.Close() }()

	if _, err := s.CreateProviderConnection(Record{
		"provider": "openai", "authType": "apikey", "name": "existing", "apiKey": "sk-existing",
	}); err != nil {
		t.Fatalf("CreateProviderConnection: %v", err)
	}

	imported, err := s.ImportLegacyJSONOnce()
	if err != nil {
		t.Fatalf("ImportLegacyJSONOnce: %v", err)
	}
	if imported {
		t.Fatal("import must not run on a non-empty store")
	}
	if n := countRows(t, s, "providerConnections"); n != 1 {
		t.Fatalf("providerConnections = %d, want 1 (only the pre-existing one)", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "db", ".migrated-from-json")); !os.IsNotExist(err) {
		t.Fatal("marker must not be written when nothing was imported")
	}
}

func TestImportLegacyJSONNoLegacyFiles(t *testing.T) {
	s := openTestStore(t)
	imported, err := s.ImportLegacyJSONOnce()
	if err != nil || imported {
		t.Fatalf("no legacy files: imported=%v err=%v, want false/nil", imported, err)
	}
}
