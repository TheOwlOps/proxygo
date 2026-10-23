package db

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// Port of repos/apiKeysRepo.js (apiKeys table) plus the key generation
// from src/shared/utils/apiKey.js and access columns from
// src/shared/utils/keyAccess.js.

// keyAccessFromColumns mirrors keyAccessFromColumns (fails closed).
func keyAccessFromColumns(restricted int, allowCol *string) KeyAccess {
	if restricted != 1 {
		return KeyAccess{Restricted: false, Allow: []string{}}
	}
	var parsed []string
	if allowCol != nil && *allowCol != "" {
		v := parseJSON(*allowCol, nil)
		for _, e := range toSlice(v) {
			if s, ok := e.(string); ok {
				parsed = append(parsed, s)
			}
		}
	}
	return KeyAccess{Restricted: true, Allow: normalizeAllowList(parsed)}
}

// normalizeAllowList mirrors the JS helper (strings only, trimmed,
// deduped case-insensitively, order preserved).
func normalizeAllowList(list []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range list {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}
		k := strings.ToLower(entry)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, entry)
	}
	return out
}

func keyAccessToColumns(a KeyAccess) (int, string) {
	allow := []string{}
	if a.Restricted {
		allow = normalizeAllowList(a.Allow)
	}
	return boolToInt(a.Restricted), stringifyJSON(allow)
}

// ValidateKeyAccessInput mirrors validateKeyAccessInput.
func ValidateKeyAccessInput(input Record) (KeyAccess, error) {
	if input == nil {
		return KeyAccess{}, errors.New("access must be an object { restricted, allow }")
	}
	for k := range input {
		if k != "restricted" && k != "allow" {
			return KeyAccess{}, errors.New("access: unexpected field(s) " + k)
		}
	}
	restricted, ok := input["restricted"].(bool)
	if !ok {
		return KeyAccess{}, errors.New("access.restricted must be a boolean")
	}
	var allow []string
	if v, present := input["allow"]; present && v != nil {
		arr, isArr := v.([]any)
		if !isArr {
			return KeyAccess{}, errors.New("access.allow must be an array of strings")
		}
		for _, e := range arr {
			s, isStr := e.(string)
			if !isStr {
				return KeyAccess{}, errors.New("access.allow must be an array of strings")
			}
			allow = append(allow, s)
		}
	}
	if len(allow) > 200 {
		return KeyAccess{}, errors.New("access.allow has more than 200 entries")
	}
	for _, e := range allow {
		if len(strings.TrimSpace(e)) > 256 {
			return KeyAccess{}, errors.New("access.allow entries must be at most 256 characters")
		}
	}
	return KeyAccess{Restricted: restricted, Allow: normalizeAllowList(allow)}, nil
}

func accessOf(m Record) KeyAccess {
	if v, ok := m["access"]; ok {
		if am, ok := v.(map[string]any); ok {
			var allow []string
			for _, e := range toSlice(am["allow"]) {
				if s, ok := e.(string); ok {
					allow = append(allow, s)
				}
			}
			return KeyAccess{Restricted: am["restricted"] == true, Allow: allow}
		}
	}
	return KeyAccess{Restricted: false, Allow: []string{}}
}

func rowToAPIKey(id, key string, name, machineID *string, isActive int, createdAt string, accessRestricted int, accessAllow *string) Record {
	return Record{
		"id":        id,
		"key":       key,
		"name":      strOrNil(name),
		"machineId": strOrNil(machineID),
		"isActive":  isActive == 1,
		"createdAt": createdAt,
		"access":    keyAccessFromColumns(accessRestricted, accessAllow),
	}
}

func queryAPIKeys(q txRunner, where string, args ...any) ([]Record, error) {
	rows, err := q.Query(`SELECT id, key, name, machineId, isActive, createdAt, accessRestricted, accessAllow FROM apiKeys`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var id, key, createdAt string
		var name, machineID, accessAllow sql.NullString
		var isActive, accessRestricted int
		if err := rows.Scan(&id, &key, &name, &machineID, &isActive, &createdAt, &accessRestricted, &accessAllow); err != nil {
			return nil, err
		}
		out = append(out, rowToAPIKey(id, key, scanNullString(name), scanNullString(machineID), isActive, createdAt, accessRestricted, scanNullString(accessAllow)))
	}
	return out, rows.Err()
}

func getAPIKeyQ(q txRunner, where string, arg any) (Record, error) {
	recs, err := queryAPIKeys(q, where, arg)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return recs[0], nil
}

func (s *Store) GetAPIKeys() ([]Record, error) {
	out, err := queryAPIKeys(s.sql, ` ORDER BY createdAt ASC`)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Record{}
	}
	return out, nil
}

func (s *Store) GetAPIKeyByID(id string) (Record, error) {
	return getAPIKeyQ(s.sql, ` WHERE id = ?`, id)
}

// GetAPIKeyByKey is used by the /v1 handlers to read a presented key's
// access settings.
func (s *Store) GetAPIKeyByKey(key string) (Record, error) {
	if key == "" {
		return nil, nil
	}
	return getAPIKeyQ(s.sql, ` WHERE key = ?`, key)
}

// apiKeySecret is the HMAC secret for generated keys (env API_KEY_SECRET,
// as in src/shared/utils/apiKey.js / .env.example).
func apiKeySecret() string {
	if v := os.Getenv("API_KEY_SECRET"); v != "" {
		return v
	}
	// The JS source ships a built-in default; deployments are expected to
	// set API_KEY_SECRET. See README.md.
	return "9router-default-secret"
}

const keyIDChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func generateKeyID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "000000"
	}
	out := make([]byte, 6)
	for i, v := range b {
		out[i] = keyIDChars[int(v)%len(keyIDChars)]
	}
	return string(out)
}

// GenerateAPIKeyWithMachine mirrors generateApiKeyWithMachine:
// sk-{machineId}-{keyId}-{crc8}, crc = HMAC-SHA256(secret, machineId+keyId)[:8] hex.
func GenerateAPIKeyWithMachine(machineID string) string {
	keyID := generateKeyID()
	mac := hmac.New(sha256.New, []byte(apiKeySecret()))
	mac.Write([]byte(machineID + keyID))
	crc := hex.EncodeToString(mac.Sum(nil))[:8]
	return "sk-" + machineID + "-" + keyID + "-" + crc
}

func (s *Store) CreateAPIKey(name, machineID string) (Record, error) {
	if machineID == "" {
		return nil, errors.New("machineId is required")
	}
	return s.CreateAPIKeyWithKey(name, machineID, GenerateAPIKeyWithMachine(machineID))
}

// CreateAPIKeyWithKey inserts a key with a caller-provided key string
// (JS createApiKey always generates; this variant exists so API routes
// that accept/import explicit keys share the same insert path).
func (s *Store) CreateAPIKeyWithKey(name, machineID, key string) (Record, error) {
	if machineID == "" {
		return nil, errors.New("machineId is required")
	}
	rec := Record{
		"id":        newUUID(),
		"name":      name,
		"key":       key,
		"machineId": machineID,
		"isActive":  true,
		"createdAt": nowISO(),
		"access":    KeyAccess{Restricted: false, Allow: []string{}},
	}
	restricted, allow := keyAccessToColumns(KeyAccess{})
	_, err := s.sql.Exec(
		`INSERT INTO apiKeys(id, key, name, machineId, isActive, createdAt, accessRestricted, accessAllow) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		rec["id"], key, name, machineID, 1, rec["createdAt"], restricted, allow)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *Store) UpdateAPIKey(id string, data Record) (Record, error) {
	var result Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getAPIKeyQ(tx, ` WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if existing == nil {
			return nil
		}
		merged := mergeMaps(existing, data)
		access := accessOf(merged)
		restricted, allow := keyAccessToColumns(access)
		if _, err := tx.Exec(
			`UPDATE apiKeys SET key = ?, name = ?, machineId = ?, isActive = ?, accessRestricted = ?, accessAllow = ? WHERE id = ?`,
			strVal(merged, "key"), nullStr(strVal(merged, "name")), nullStr(strVal(merged, "machineId")),
			boolToInt(boolVal(merged, "isActive", true)), restricted, allow, id); err != nil {
			return err
		}
		result, err = getAPIKeyQ(tx, ` WHERE id = ?`, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) DeleteAPIKey(id string) (bool, error) {
	res, err := s.sql.Exec(`DELETE FROM apiKeys WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ValidateAPIKey(key string) (bool, error) {
	var isActive int
	err := s.sql.QueryRow(`SELECT isActive FROM apiKeys WHERE key = ?`, key).Scan(&isActive)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return isActive == 1, nil
}
