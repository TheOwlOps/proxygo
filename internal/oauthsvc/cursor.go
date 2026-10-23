package oauthsvc

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Port of src/lib/oauth/services/cursor.js (CursorService) — checksum
// generation, import-token validation, and the state.vscdb reader the
// auto-import route uses.

// CursorChecksum ports generateChecksum (the jyh hash Cursor expects in
// its x-cursor-checksum header): XOR the timestamp string's bytes with a
// rolling key seeded at 165, base64 the result, append "," + machineId.
func CursorChecksum(machineID string) string {
	timestamp := itoa(int(time.Now().UnixMilli() / 1000))
	return cursorChecksumFor(machineID, timestamp)
}

func cursorChecksumFor(machineID, timestamp string) string {
	orig := []byte(timestamp)
	out := make([]byte, len(orig))
	key := 165
	for i, b := range orig {
		v := (int(b) ^ key) & 0xff
		out[i] = byte(v)
		key = (v + int(b)) & 0xff
	}
	return base64.StdEncoding.EncodeToString(out) + "," + machineID
}

// CursorValidateImportToken ports validateImportToken (format checks only —
// Cursor's API can't be probed without its protobuf protocol).
func CursorValidateImportToken(accessToken, machineID string) (map[string]any, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, errf("Access token is required")
	}
	if strings.TrimSpace(machineID) == "" {
		return nil, errf("Machine ID is required")
	}
	if len(accessToken) < 50 {
		return nil, errf("Invalid token format. Token appears too short.")
	}
	stripped := strings.ReplaceAll(machineID, "-", "")
	if !regexp.MustCompile(`^[a-f0-9]{32,}$`).MatchString(strings.ToLower(stripped)) {
		return nil, errf("Invalid machine ID format. Expected UUID format.")
	}
	return map[string]any{
		"accessToken": accessToken,
		"machineId":   machineID,
		"expiresIn":   float64(86400),
		"authMethod":  "imported",
	}, nil
}

// CursorExtractUserInfo ports extractUserInfo (JWT payload peek).
func CursorExtractUserInfo(accessToken string) (email, userID string, ok bool) {
	payload := DecodeJWTPayload(accessToken)
	if payload == nil {
		return "", "", false
	}
	email = firstStr(strOf(payload, "email"), strOf(payload, "sub"))
	userID = firstStr(strOf(payload, "sub"), strOf(payload, "user_id"))
	return email, userID, email != "" || userID != ""
}

// CursorTokenStoragePaths mirrors CursorService.config.tokenStoragePaths.
func CursorTokenStoragePaths() map[string]string {
	home, _ := os.UserHomeDir()
	return map[string]string{
		"linux":   filepath.Join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"),
		"darwin":  filepath.Join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "state.vscdb"),
		"windows": filepath.Join(os.Getenv("APPDATA"), "Cursor", "User", "globalStorage", "state.vscdb"),
	}
}

// CursorCandidateDBPaths lists the state.vscdb locations the auto-import
// route probes (current platform first).
func CursorCandidateDBPaths() []string {
	paths := CursorTokenStoragePaths()
	ordered := []string{}
	switch runtime.GOOS {
	case "darwin":
		ordered = append(ordered, paths["darwin"])
	case "windows":
		ordered = append(ordered, paths["windows"])
	default:
		ordered = append(ordered, paths["linux"])
	}
	ordered = append(ordered, paths["linux"], paths["darwin"], paths["windows"])
	seen := map[string]bool{}
	out := []string{}
	for _, p := range ordered {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// ReadSQLiteItemTable reads key/value pairs from an itemTable-style SQLite
// DB (state.vscdb, Zed kv_store uses a different table — see
// ReadSQLiteKVStore). Values that are JSON strings are unwrapped like the
// JS reader does.
func ReadSQLiteItemTable(dbPath, table string, keys []string) (map[string]string, error) {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	out := map[string]string{}
	for _, key := range keys {
		var value string
		row := db.QueryRow("SELECT value FROM "+table+" WHERE key = ? LIMIT 1", key)
		if err := row.Scan(&value); err != nil {
			continue
		}
		out[key] = unwrapDBValue(value)
	}
	return out, nil
}

// ReadSQLiteKVStore reads one key from a kv_store table (Zed db.sqlite).
func ReadSQLiteKVStore(dbPath, key string) (string, error) {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var value string
	err = db.QueryRow("SELECT value FROM kv_store WHERE key = ? LIMIT 1", key).Scan(&value)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(unwrapDBValue(value)), nil
}

func unwrapDBValue(v string) string {
	trimmed := strings.TrimSpace(v)
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if json.Unmarshal([]byte(trimmed), &s) == nil {
			return s
		}
	}
	return v
}

// CursorReadTokensFromDB ports the auto-import DB read: access token +
// machine id from a state.vscdb path.
func CursorReadTokensFromDB(dbPath string) (accessToken, machineID string, err error) {
	values, err := ReadSQLiteItemTable(dbPath, "itemTable", []string{
		"cursorAuth/accessToken", "cursorAuth/token",
		"storage.serviceMachineId", "storage.machineId", "telemetry.machineId",
	})
	if err != nil {
		return "", "", err
	}
	accessToken = firstStr(values["cursorAuth/accessToken"], values["cursorAuth/token"])
	machineID = firstStr(values["storage.serviceMachineId"], values["storage.machineId"], values["telemetry.machineId"])
	return accessToken, machineID, nil
}

// CursorInstalled reports whether a Cursor install is present (Linux check
// used by the auto-import route).
func CursorInstalled() bool {
	for _, p := range CursorCandidateDBPaths() {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if runtime.GOOS == "linux" {
		for _, dir := range []string{"/usr/share/cursor", "/opt/cursor", "/usr/bin/cursor"} {
			if _, err := os.Stat(dir); err == nil {
				return true
			}
		}
	}
	return false
}
