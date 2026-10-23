package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Port of the legacy-JSON import half of src/lib/db/migrate.js
// (importLegacyMain / importLegacyUsage / importLegacyDisabled /
// importLegacyDetails, driven by runMigrationOnce). The versioned
// schema migrations and additive schema sync from migrate.js are NOT
// here — schema.sql already carries the full current schema (see db.go).
//
// Wiring: the parent calls (*Store).ImportLegacyJSONOnce once, right
// after Open()/OpenInDir(), mirroring runMigrationOnce at adapter
// creation. It is a no-op unless ALL of these hold:
//   - the marker file <dataDir>/db/.migrated-from-json does not exist
//     (JS: prevents re-importing when the user wipes data.sqlite);
//   - at least one legacy file exists (db.json, usage.json,
//     disabledModels.json, request-details.json in the data dir);
//   - the store is fresh — every target table is still empty, so
//     existing SQLite data is never overwritten.
//
// On a row-count assertion mismatch (same rule as the JS
// importWithAssertion) the whole import transaction rolls back, the
// legacy files stay untouched, no marker is written, and an error is
// returned so the next boot can retry.

const legacyMarkerName = ".migrated-from-json"

// legacyFiles mirrors LEGACY_FILES in src/lib/db/paths.js.
type legacyFiles struct {
	main, usage, disabled, details string
}

func legacyPaths(dataDir string) legacyFiles {
	return legacyFiles{
		main:     filepath.Join(dataDir, "db.json"),
		usage:    filepath.Join(dataDir, "usage.json"),
		disabled: filepath.Join(dataDir, "disabledModels.json"),
		details:  filepath.Join(dataDir, "request-details.json"),
	}
}

// readJSONSafe mirrors readJsonSafe: missing or unparseable → nil.
func readJSONSafe(file string) Record {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var out Record
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// storeIsFreshForLegacyImport reports whether every table the legacy
// import writes to is empty (the Go analogue of the JS isFreshDb check,
// widened to the target tables because Open() stamps _meta rows).
func (s *Store) storeIsFreshForLegacyImport() (bool, error) {
	for _, table := range []string{
		"settings", "providerConnections", "providerNodes", "proxyPools",
		"apiKeys", "combos", "kv", "usageHistory", "usageDaily", "requestDetails",
	} {
		var n int
		if err := s.sql.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// ImportLegacyJSONOnce runs the one-time legacy JSON → SQLite import.
// It returns true when an import actually happened.
func (s *Store) ImportLegacyJSONOnce() (bool, error) {
	marker := filepath.Join(s.dataDir, "db", legacyMarkerName)
	if _, err := os.Stat(marker); err == nil {
		return false, nil // already imported once (JS marker semantics)
	}

	files := legacyPaths(s.dataDir)
	main := readJSONSafe(files.main)
	usage := readJSONSafe(files.usage)
	disabled := readJSONSafe(files.disabled)
	details := readJSONSafe(files.details)
	if main == nil && usage == nil && disabled == nil && details == nil {
		return false, nil // no legacy data
	}

	fresh, err := s.storeIsFreshForLegacyImport()
	if err != nil {
		return false, err
	}
	if !fresh {
		return false, nil // never overwrite existing SQLite data
	}

	// Back up the legacy files like the JS does (best-effort).
	backupDir := filepath.Join(s.dataDir, "db", "backups", "migrate-from-json")
	if err := os.MkdirAll(backupDir, 0o755); err == nil {
		for _, f := range []string{files.main, files.usage, files.disabled, files.details} {
			if raw, err := os.ReadFile(f); err == nil {
				_ = os.WriteFile(filepath.Join(backupDir, filepath.Base(f)), raw, 0o644)
			}
		}
	}

	tx, err := s.sql.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := importLegacyMain(tx, main); err != nil {
		return false, err
	}
	if err := importLegacyUsage(tx, usage); err != nil {
		return false, err
	}
	if err := importLegacyDisabled(tx, disabled); err != nil {
		return false, err
	}
	if err := importLegacyDetails(tx, details); err != nil {
		return false, err
	}
	if _, err := tx.Exec(
		`INSERT INTO _meta(key, value) VALUES('migratedAt', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		nowISO()); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}

	_ = os.WriteFile(marker, []byte(nowISO()), 0o644)
	return true, nil
}

// importWithAssertion mirrors the JS helper: insert rows one by one,
// then assert COUNT(*) equals the input length; any mismatch aborts
// the import (the caller rolls back).
func importWithAssertion(tx *sql.Tx, table string, rows []any, insert func(Record) error) error {
	for _, raw := range rows {
		row := toMap(raw)
		if row == nil {
			row = Record{}
		}
		_ = insert(row) // failures are caught by the count assertion, as in JS
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		return err
	}
	if n != len(rows) {
		return fmt.Errorf("db: legacy import %s row-count mismatch: expected %d, got %d", table, len(rows), n)
	}
	return nil
}

// restOf returns the record minus the given column keys (JS destructuring
// `...rest`, which lands in the JSON data column).
func restOf(row Record, cols ...string) Record {
	rest := cloneMap(row)
	for _, c := range cols {
		delete(rest, c)
	}
	return rest
}

// anyStrOrNil mirrors `value || null` for string columns (named to
// avoid colliding with connections.go's *string-based strOrNil).
func anyStrOrNil(v any) any {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return nil
}

// numOrNil passes a JSON number through, else nil (priority columns).
func numOrNil(v any) any {
	if f, ok := v.(float64); ok {
		return f
	}
	return nil
}

// activeOrDefault mirrors `isActive === false ? 0 : 1`.
func activeOrDefault(row Record) int {
	if b, ok := row["isActive"].(bool); ok && !b {
		return 0
	}
	return 1
}

func importLegacyMain(tx *sql.Tx, data Record) error {
	if data == nil {
		return nil
	}

	if settings, ok := data["settings"]; ok && settings != nil {
		if _, err := tx.Exec(
			`INSERT INTO settings(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
			stringifyJSON(settings)); err != nil {
			return err
		}
	}

	if err := importWithAssertion(tx, "providerConnections", toSlice(data["providerConnections"]), func(c Record) error {
		rest := restOf(c, "id", "provider", "authType", "name", "email", "priority", "isActive", "createdAt", "updatedAt")
		authType := strVal(c, "authType")
		if authType == "" {
			authType = "oauth"
		}
		created := strVal(c, "createdAt")
		if created == "" {
			created = nowISO()
		}
		updated := strVal(c, "updatedAt")
		if updated == "" {
			updated = nowISO()
		}
		_, err := tx.Exec(
			`INSERT OR REPLACE INTO providerConnections(id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c["id"], c["provider"], authType, anyStrOrNil(c["name"]), anyStrOrNil(c["email"]),
			numOrNil(c["priority"]), activeOrDefault(c), stringifyJSON(rest), created, updated)
		return err
	}); err != nil {
		return err
	}

	if err := importWithAssertion(tx, "providerNodes", toSlice(data["providerNodes"]), func(n Record) error {
		rest := restOf(n, "id", "type", "name", "createdAt", "updatedAt")
		created := strVal(n, "createdAt")
		if created == "" {
			created = nowISO()
		}
		updated := strVal(n, "updatedAt")
		if updated == "" {
			updated = nowISO()
		}
		_, err := tx.Exec(
			`INSERT OR REPLACE INTO providerNodes(id, type, name, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
			n["id"], anyStrOrNil(n["type"]), anyStrOrNil(n["name"]), stringifyJSON(rest), created, updated)
		return err
	}); err != nil {
		return err
	}

	if err := importWithAssertion(tx, "proxyPools", toSlice(data["proxyPools"]), func(p Record) error {
		rest := restOf(p, "id", "isActive", "testStatus", "createdAt", "updatedAt")
		testStatus := strVal(p, "testStatus")
		if testStatus == "" {
			testStatus = "unknown"
		}
		created := strVal(p, "createdAt")
		if created == "" {
			created = nowISO()
		}
		updated := strVal(p, "updatedAt")
		if updated == "" {
			updated = nowISO()
		}
		_, err := tx.Exec(
			`INSERT OR REPLACE INTO proxyPools(id, isActive, testStatus, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
			p["id"], activeOrDefault(p), testStatus, stringifyJSON(rest), created, updated)
		return err
	}); err != nil {
		return err
	}

	if err := importWithAssertion(tx, "apiKeys", toSlice(data["apiKeys"]), func(k Record) error {
		created := strVal(k, "createdAt")
		if created == "" {
			created = nowISO()
		}
		_, err := tx.Exec(
			`INSERT OR REPLACE INTO apiKeys(id, key, name, machineId, isActive, createdAt) VALUES(?, ?, ?, ?, ?, ?)`,
			k["id"], k["key"], anyStrOrNil(k["name"]), anyStrOrNil(k["machineId"]), activeOrDefault(k), created)
		return err
	}); err != nil {
		return err
	}

	if err := importWithAssertion(tx, "combos", toSlice(data["combos"]), func(c Record) error {
		models := c["models"]
		if models == nil {
			models = []any{}
		}
		created := strVal(c, "createdAt")
		if created == "" {
			created = nowISO()
		}
		updated := strVal(c, "updatedAt")
		if updated == "" {
			updated = nowISO()
		}
		_, err := tx.Exec(
			`INSERT OR REPLACE INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
			c["id"], c["name"], anyStrOrNil(c["kind"]), stringifyJSON(models), created, updated)
		return err
	}); err != nil {
		return err
	}

	// KV-scoped collections (INSERT OR REPLACE, no assertion — as in JS).
	kvInsert := func(scope, key string, value any) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO kv(scope, key, value) VALUES(?, ?, ?)`,
			scope, key, stringifyJSON(value))
		return err
	}
	for alias, model := range toMap(data["modelAliases"]) {
		if err := kvInsert("modelAliases", alias, model); err != nil {
			return err
		}
	}
	for _, raw := range toSlice(data["customModels"]) {
		m := toMap(raw)
		if m == nil {
			continue
		}
		typ := strVal(m, "type")
		if typ == "" {
			typ = "llm"
		}
		key := fmt.Sprintf("%s|%s|%s", strVal(m, "providerAlias"), strVal(m, "id"), typ)
		if err := kvInsert("customModels", key, m); err != nil {
			return err
		}
	}
	for tool, mappings := range toMap(data["mitmAlias"]) {
		if mappings == nil {
			mappings = Record{}
		}
		if err := kvInsert("mitmAlias", tool, mappings); err != nil {
			return err
		}
	}
	for provider, models := range toMap(data["pricing"]) {
		if models == nil {
			models = Record{}
		}
		if err := kvInsert("pricing", provider, models); err != nil {
			return err
		}
	}
	return nil
}

// jsNum mirrors JS `a || b || 0` numeric fallback: zero falls through.
func jsNum(vals ...any) float64 {
	for _, v := range vals {
		if f, ok := v.(float64); ok && f != 0 {
			return f
		}
	}
	return 0
}

func importLegacyUsage(tx *sql.Tx, data Record) error {
	if data == nil {
		return nil
	}
	for _, raw := range toSlice(data["history"]) {
		e := toMap(raw)
		if e == nil {
			continue
		}
		tokens := toMap(e["tokens"])
		if tokens == nil {
			tokens = Record{}
		}
		ts := strVal(e, "timestamp")
		if ts == "" {
			ts = nowISO()
		}
		status := strVal(e, "status")
		if status == "" {
			status = "ok"
		}
		if _, err := tx.Exec(
			`INSERT INTO usageHistory(timestamp, provider, model, connectionId, apiKey, endpoint, promptTokens, completionTokens, cost, status, tokens, meta) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ts, anyStrOrNil(e["provider"]), anyStrOrNil(e["model"]), anyStrOrNil(e["connectionId"]),
			anyStrOrNil(e["apiKey"]), anyStrOrNil(e["endpoint"]),
			jsNum(tokens["prompt_tokens"], tokens["input_tokens"]),
			jsNum(tokens["completion_tokens"], tokens["output_tokens"]),
			jsNum(e["cost"]), status, stringifyJSON(tokens), stringifyJSON(Record{})); err != nil {
			return err
		}
	}
	for dateKey, day := range toMap(data["dailySummary"]) {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO usageDaily(dateKey, data) VALUES(?, ?)`,
			dateKey, stringifyJSON(day)); err != nil {
			return err
		}
	}
	if n, ok := data["totalRequestsLifetime"].(float64); ok {
		if _, err := tx.Exec(
			`INSERT INTO _meta(key, value) VALUES('totalRequestsLifetime', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			fmt.Sprintf("%v", n)); err != nil {
			return err
		}
	}
	return nil
}

func importLegacyDisabled(tx *sql.Tx, data Record) error {
	if data == nil {
		return nil
	}
	disabled := toMap(data["disabled"])
	for provider, ids := range disabled {
		if ids == nil {
			ids = []any{}
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO kv(scope, key, value) VALUES('disabledModels', ?, ?)`,
			provider, stringifyJSON(ids)); err != nil {
			return err
		}
	}
	return nil
}

func importLegacyDetails(tx *sql.Tx, data Record) error {
	if data == nil {
		return nil
	}
	for _, raw := range toSlice(data["records"]) {
		r := toMap(raw)
		if r == nil {
			continue
		}
		ts := strVal(r, "timestamp")
		if ts == "" {
			ts = nowISO()
		}
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO requestDetails(id, timestamp, provider, model, connectionId, status, data) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			r["id"], ts, anyStrOrNil(r["provider"]), anyStrOrNil(r["model"]),
			anyStrOrNil(r["connectionId"]), anyStrOrNil(r["status"]), stringifyJSON(r)); err != nil {
			return err
		}
	}
	return nil
}
