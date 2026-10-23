// Package db is the Go port of src/lib/db/ (9Router v0.5.104).
//
// Storage is real SQLite via modernc.org/sqlite (pure Go, no cgo),
// replacing the JS driver fallback chain (bun:sqlite → better-sqlite3 →
// node:sqlite → sql.js) with a single driver. The on-disk layout matches
// src/lib/db/paths.js: <DATA_DIR>/db/data.sqlite, where DATA_DIR comes
// from the DATA_DIR env var, else ~/.9router/ (APPDATA/9router on Windows,
// mirroring src/lib/dataDir.js).
package db

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// SchemaVersion mirrors SCHEMA_VERSION in src/lib/db/schema.js.
const SchemaVersion = 2

// MigrationVersion is the highest versioned migration applied
// (migrations/001-initial.js).
const MigrationVersion = 1

// pragmaSQL mirrors PRAGMA_SQL in src/lib/db/schema.js.
var pragmaStmts = []string{
	"PRAGMA journal_mode = WAL",
	"PRAGMA synchronous = NORMAL",
	"PRAGMA temp_store = MEMORY",
	"PRAGMA mmap_size = 30000000",
	"PRAGMA cache_size = -64000",
	"PRAGMA foreign_keys = ON",
	"PRAGMA busy_timeout = 5000",
}

// Record is a dynamic JS-style object. Unknown fields are preserved
// end-to-end (JSON columns hold everything that is not a real column).
type Record = map[string]any

// Store is the opened database plus all repos (it implements every repo
// interface; the accessor methods exist for readability at call sites).
type Store struct {
	sql     *sql.DB
	dataDir string
	dbFile  string

	usage *usageState
	rd    *requestDetailsState
}

// DataDir resolves the data directory exactly like src/lib/dataDir.js:
// $DATA_DIR if set (created if needed), else the platform default.
func DataDir() string {
	if configured := os.Getenv("DATA_DIR"); configured != "" {
		// On Windows, ignore Unix-style absolute paths (JS behaviour).
		if runtime.GOOS == "windows" && len(configured) > 0 && configured[0] == '/' {
			return defaultDataDir()
		}
		if err := os.MkdirAll(configured, 0o755); err == nil {
			return configured
		} else if !os.IsPermission(err) {
			// JS throws on non-permission errors; mirror that loosely by
			// still returning the configured dir so Open() surfaces it.
			return configured
		}
		return defaultDataDir()
	}
	return defaultDataDir()
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "9router")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".9router"
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "9router")
	}
	return filepath.Join(home, ".9router")
}

// DBDir is <DATA_DIR>/db (paths.js DB_DIR).
func DBDir() string { return filepath.Join(DataDir(), "db") }

// DataFile is <DATA_DIR>/db/data.sqlite (paths.js DATA_FILE).
func DataFile() string { return filepath.Join(DBDir(), "data.sqlite") }

// Dir returns the data dir this store was opened on.
func (s *Store) Dir() string { return s.dataDir }

// File returns the sqlite file path for this store.
func (s *Store) File() string { return s.dbFile }

// SQL exposes the underlying handle for integration code that needs it
// (export/import). Repo code inside this package uses it directly.
func (s *Store) SQL() *sql.DB { return s.sql }

// Open opens (creating if needed) the store at the resolved DATA_DIR and
// applies the schema — the equivalent of driver.getAdapter() +
// runMigrationOnce() for migration 001. Additive schema sync from
// migrate.js is unnecessary: schema.sql already carries the full current
// TABLES definition (including the additive apiKeys access columns).
func Open() (*Store, error) {
	return OpenInDir(DataDir())
}

// OpenInDir opens a store rooted at an explicit data dir
// (<dir>/db/data.sqlite). Used by tests with t.TempDir().
func OpenInDir(dataDir string) (*Store, error) {
	dbDir := filepath.Join(dataDir, "db")
	for _, d := range []string{dataDir, dbDir, filepath.Join(dbDir, "backups")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("db: mkdir %s: %w", d, err)
		}
	}
	return OpenFile(filepath.Join(dbDir, "data.sqlite"), dataDir)
}

// OpenFile opens a store on an explicit sqlite file path.
func OpenFile(dbFile, dataDir string) (*Store, error) {
	dsn := "file:" + filepath.ToSlash(dbFile) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	// Single connection: serializes writes like the synchronous JS
	// drivers and avoids SQLITE_BUSY between pooled connections.
	sqlDB.SetMaxOpenConns(1)
	s := &Store{sql: sqlDB, dataDir: dataDir, dbFile: dbFile, usage: newUsageState(), rd: newRequestDetailsState()}
	if err := s.migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	for _, p := range pragmaStmts {
		if _, err := s.sql.Exec(p); err != nil {
			return fmt.Errorf("db: %s: %w", p, err)
		}
	}
	if _, err := s.sql.Exec(schemaSQL); err != nil {
		return fmt.Errorf("db: apply schema.sql: %w", err)
	}
	// Stamp versions like runVersionedMigrations/setMetaSync do.
	if _, err := s.sql.Exec(
		`INSERT INTO _meta(key, value) VALUES('schemaVersion', ?) ON CONFLICT(key) DO NOTHING`,
		fmt.Sprint(MigrationVersion)); err != nil {
		return fmt.Errorf("db: stamp schemaVersion: %w", err)
	}
	if _, err := s.sql.Exec(
		`INSERT INTO _meta(key, value) VALUES('backupSchemaVersion', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		fmt.Sprint(SchemaVersion)); err != nil {
		return fmt.Errorf("db: stamp backupSchemaVersion: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s.rd != nil {
		s.rd.stop()
	}
	return s.sql.Close()
}

// --- repo accessors (each returns the store, which implements them) ---

func (s *Store) Settings() SettingsRepo             { return s }
func (s *Store) Connections() ConnectionsRepo       { return s }
func (s *Store) Nodes() NodesRepo                   { return s }
func (s *Store) ProxyPools() ProxyPoolsRepo         { return s }
func (s *Store) APIKeys() APIKeysRepo               { return s }
func (s *Store) Combos() CombosRepo                 { return s }
func (s *Store) Aliases() AliasesRepo               { return s }
func (s *Store) Pricing() PricingRepo               { return s }
func (s *Store) DisabledModels() DisabledModelsRepo { return s }
func (s *Store) Usage() UsageRepo                   { return s }
func (s *Store) RequestDetails() RequestDetailsRepo { return s }
func (s *Store) KV() KVStore                        { return &kvStore{s: s, scope: ""} }

// --- shared helpers (ports of helpers/jsonCol.js etc.) ---

// stringifyJSON mirrors stringifyJson: JSON.stringify(value ?? null).
func stringifyJSON(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// parseJSON mirrors parseJson(str, fallback).
func parseJSON(s string, fallback any) any {
	if s == "" {
		return fallback
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return fallback
	}
	return v
}

// parseMap parses a JSON column into a Record ({} fallback, like
// parseJson(row.data, {})).
func parseMap(s string) Record {
	v := parseJSON(s, nil)
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return Record{}
}

func parseMapFallback(s string, fallback Record) Record {
	v := parseJSON(s, nil)
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if fallback != nil {
		return fallback
	}
	return Record{}
}

func toMap(v any) Record {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return Record{}
}

func toSlice(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	// Accept any other slice type (e.g. []Record) via reflection so
	// in-memory Export→Import round-trips work like JSON ones.
	rv := reflect.ValueOf(v)
	if rv.IsValid() && rv.Kind() == reflect.Slice {
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = rv.Index(i).Interface()
		}
		return out
	}
	return nil
}

func cloneMap(m Record) Record {
	out := make(Record, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mergeMaps returns {...a, ...b} (b wins), like JS object spread.
func mergeMaps(a, b Record) Record {
	out := cloneMap(a)
	for k, v := range b {
		out[k] = v
	}
	return out
}

func strVal(m Record, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func strPtr(m Record, key string) *string {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(string); ok {
		vv := v
		return &vv
	}
	return nil
}

func boolVal(m Record, key string, def bool) bool {
	if m == nil {
		return def
	}
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}

func hasKey(m Record, key string) bool {
	_, ok := m[key]
	return ok
}

func numVal(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func numPtr(m Record, key string) *float64 {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok && v != nil {
		f := numVal(v)
		return &f
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nowISO mirrors new Date().toISOString() (UTC, millisecond precision).
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func isoOf(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// newUUID is a crypto/rand UUID v4 (the JS repos use the uuid package).
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is vanishingly rare; fall back to time-based.
		n := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(n >> (8 * i))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// tx runs fn inside a transaction, like the adapters' db.transaction().
type txRunner interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func (s *Store) tx(fn func(tx *sql.Tx) error) error {
	tx, err := s.sql.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// nullStr converts an empty string to NULL for nullable TEXT columns
// where the JS passes `value || null` / `value ?? null`.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullStrPtr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func scanNullString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}
