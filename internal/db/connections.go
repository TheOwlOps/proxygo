package db

import (
	"database/sql"
	"sort"
	"strings"
)

// Port of repos/connectionsRepo.js (providerConnections table).
// Column fields: id, provider, authType, name, email, priority, isActive,
// createdAt, updatedAt — everything else lives in the `data` JSON column
// and is merged back on read (rowToConn).

var connectionOptionalFields = []string{
	"displayName", "email", "globalPriority", "defaultModel",
	"accessToken", "refreshToken", "expiresAt", "tokenType",
	"scope", "projectId", "apiKey", "testStatus",
	"lastTested", "lastError", "lastErrorAt", "rateLimitedUntil", "expiresIn", "errorCode",
	"consecutiveUseCount", "idToken", "lastRefreshAt",
}

const modelLockPrefix = "modelLock_"

// resetHealthStateOnActivation mirrors the JS helper of the same name.
func resetHealthStateOnActivation(existing, patch Record) Record {
	if strVal(patch, "testStatus") != "active" {
		return patch
	}
	normalized := cloneMap(patch)
	normalized["testStatus"] = "active"
	if !hasKey(patch, "lastError") {
		normalized["lastError"] = nil
	}
	if !hasKey(patch, "lastErrorAt") {
		normalized["lastErrorAt"] = nil
	}
	normalized["errorCode"] = nil
	normalized["rateLimitedUntil"] = nil
	normalized["backoffLevel"] = 0
	for k := range existing {
		if strings.HasPrefix(k, modelLockPrefix) {
			normalized[k] = nil
		}
	}
	return normalized
}

type connRow struct {
	id        string
	provider  string
	authType  string
	name      *string
	email     *string
	priority  *float64
	isActive  int
	data      string
	createdAt string
	updatedAt string
}

func (r *connRow) toRecord() Record {
	rec := parseMap(r.data)
	rec["id"] = r.id
	rec["provider"] = r.provider
	rec["authType"] = r.authType
	rec["name"] = strOrNil(r.name)
	rec["email"] = strOrNil(r.email)
	if r.priority != nil {
		rec["priority"] = *r.priority
	} else {
		rec["priority"] = nil
	}
	rec["isActive"] = r.isActive == 1
	rec["createdAt"] = r.createdAt
	rec["updatedAt"] = r.updatedAt
	return rec
}

func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func scanConnRow(rows *sql.Rows) (*connRow, error) {
	var r connRow
	var name, email sql.NullString
	var priority sql.NullFloat64
	if err := rows.Scan(&r.id, &r.provider, &r.authType, &name, &email, &priority, &r.isActive, &r.data, &r.createdAt, &r.updatedAt); err != nil {
		return nil, err
	}
	r.name = scanNullString(name)
	r.email = scanNullString(email)
	if priority.Valid {
		f := priority.Float64
		r.priority = &f
	}
	return &r, nil
}

const connCols = `id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt`

func queryConns(q txRunner, where string, args ...any) ([]Record, error) {
	rows, err := q.Query(`SELECT `+connCols+` FROM providerConnections`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanConnRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r.toRecord())
	}
	return out, rows.Err()
}

func getConnQ(q txRunner, id string) (Record, error) {
	recs, err := queryConns(q, ` WHERE id = ?`, id)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return recs[0], nil
}

// connToRow splits a record into column values + rest-JSON (JS connToRow).
func connToRow(c Record) connRow {
	rest := cloneMap(c)
	for _, k := range []string{"id", "provider", "authType", "name", "email", "priority", "isActive", "createdAt", "updatedAt"} {
		delete(rest, k)
	}
	r := connRow{
		id:        strVal(c, "id"),
		provider:  strVal(c, "provider"),
		authType:  strVal(c, "authType"),
		name:      strPtr(c, "name"),
		email:     strPtr(c, "email"),
		priority:  numPtr(c, "priority"),
		isActive:  boolToInt(boolVal(c, "isActive", true)),
		data:      stringifyJSON(rest),
		createdAt: strVal(c, "createdAt"),
		updatedAt: strVal(c, "updatedAt"),
	}
	return r
}

func upsertConn(q txRunner, c Record) error {
	r := connToRow(c)
	var prio any
	if r.priority != nil {
		prio = *r.priority
	}
	_, err := q.Exec(
		`INSERT INTO providerConnections(id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   provider=excluded.provider, authType=excluded.authType, name=excluded.name,
		   email=excluded.email, priority=excluded.priority, isActive=excluded.isActive,
		   data=excluded.data, updatedAt=excluded.updatedAt`,
		r.id, r.provider, r.authType, nullStrPtr(r.name), nullStrPtr(r.email), prio, r.isActive, r.data, r.createdAt, r.updatedAt)
	return err
}

func deriveConnectionName(data Record, fallback string) string {
	if strVal(data, "provider") == "github" {
		psd := toMap(data["providerSpecificData"])
		for _, k := range []string{"githubLogin", "githubEmail"} {
			if v := strVal(psd, k); v != "" {
				return v
			}
		}
		if v := strVal(data, "email"); v != "" {
			return v
		}
		if v := strVal(psd, "githubName"); v != "" {
			return v
		}
	}
	return fallback
}

func (s *Store) GetProviderConnections(filter ConnectionFilter) ([]Record, error) {
	where := ""
	var args []any
	var conds []string
	if filter.Provider != "" {
		conds = append(conds, "provider = ?")
		args = append(args, filter.Provider)
	}
	if filter.IsActive != nil {
		conds = append(conds, "isActive = ?")
		args = append(args, boolToInt(*filter.IsActive))
	}
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	list, err := queryConns(s.sql, where, args...)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(list, func(i, j int) bool {
		pi, pj := 999.0, 999.0
		if v := list[i]["priority"]; v != nil {
			pi = numVal(v)
		}
		if v := list[j]["priority"]; v != nil {
			pj = numVal(v)
		}
		return pi < pj
	})
	if list == nil {
		list = []Record{}
	}
	return list, nil
}

func (s *Store) GetProviderConnectionByID(id string) (Record, error) {
	return getConnQ(s.sql, id)
}

// reorderInTx normalizes priorities to 1..N (JS reorderInTx; call inside tx).
func reorderInTx(q txRunner, providerID string) error {
	list, err := queryConns(q, ` WHERE provider = ?`, providerID)
	if err != nil {
		return err
	}
	// JS: priority asc (missing = 0), ties broken by updatedAt DESC.
	sort.SliceStable(list, func(i, j int) bool {
		pi, pj := numVal(list[i]["priority"]), numVal(list[j]["priority"])
		if pi != pj {
			return pi < pj
		}
		return strVal(list[i], "updatedAt") > strVal(list[j], "updatedAt")
	})
	for i, c := range list {
		want := float64(i + 1)
		if numVal(c["priority"]) != want {
			if _, err := q.Exec(`UPDATE providerConnections SET priority = ? WHERE id = ?`, want, strVal(c, "id")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) CreateProviderConnection(data Record) (Record, error) {
	var result Record
	var conflict *NameConflictError
	err := s.tx(func(tx *sql.Tx) error {
		now := nowISO()
		provider := strVal(data, "provider")
		isAPIKey := strVal(data, "authType") == "apikey" && strVal(data, "name") != ""

		var all []Record
		var poolSize int
		if isAPIKey {
			var err error
			all, err = queryConns(tx, ` WHERE provider = ? AND authType = ? AND name = ?`, provider, "apikey", strVal(data, "name"))
			if err != nil {
				return err
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM providerConnections WHERE provider = ?`, provider).Scan(&n); err != nil {
				return err
			}
			poolSize = n
		} else {
			var err error
			all, err = queryConns(tx, ` WHERE provider = ?`, provider)
			if err != nil {
				return err
			}
			poolSize = len(all)
		}

		var existing Record
		if strVal(data, "authType") == "oauth" && strVal(data, "email") != "" {
			incoming := toMap(data["providerSpecificData"])
			incomingUsername := strVal(incoming, "username")
			incomingWs := strVal(incoming, "chatgptAccountId")
			for _, c := range all {
				if strVal(c, "authType") != "oauth" || strVal(c, "email") != strVal(data, "email") {
					continue
				}
				existingWs := strVal(toMap(c["providerSpecificData"]), "chatgptAccountId")
				if provider == "codex" {
					if incomingWs != "" && existingWs != "" && incomingWs == existingWs {
						existing = c
						break
					}
					continue
				}
				if incomingWs != "" && existingWs != "" {
					if incomingWs == existingWs {
						existing = c
						break
					}
					continue
				}
				if incomingWs != "" && existingWs == "" {
					continue
				}
				if incomingWs == "" && existingWs != "" {
					continue
				}
				existingUsername := strVal(toMap(c["providerSpecificData"]), "username")
				if incomingUsername != "" && existingUsername != "" {
					if incomingUsername == existingUsername {
						existing = c
						break
					}
					continue
				}
				if incomingUsername != "" || existingUsername != "" {
					continue
				}
				existing = c
				break
			}
		} else if isAPIKey {
			for _, c := range all {
				if strVal(c, "authType") == "apikey" && strVal(c, "name") == strVal(data, "name") {
					existing = c
					break
				}
			}
		}

		if existing != nil {
			// JS: only an explicit allowOverwrite === false is refused.
			if v, ok := data["allowOverwrite"]; ok && v == false {
				conflict = &NameConflictError{
					ExistingID:   strVal(existing, "id"),
					ExistingName: strVal(existing, "name"),
					Provider:     provider,
				}
				return conflict
			}
			normalized := resetHealthStateOnActivation(existing, data)
			merged := mergeMaps(existing, normalized)
			merged["updatedAt"] = now
			if err := upsertConn(tx, merged); err != nil {
				return err
			}
			result = merged
			return nil
		}

		connName := strPtr(data, "name")
		if connName == nil && (strVal(data, "authType") == "oauth" || strVal(data, "authType") == "access_token") {
			fallback := strVal(data, "email")
			if fallback == "" {
				fallback = "Account " + itoa(poolSize+1)
			}
			n := deriveConnectionName(data, fallback)
			connName = &n
		}
		var prio *float64
		if p := numPtr(data, "priority"); p != nil && *p != 0 {
			prio = p
		} else {
			var maxP sql.NullFloat64
			if err := tx.QueryRow(`SELECT MAX(priority) FROM providerConnections WHERE provider = ?`, provider).Scan(&maxP); err != nil {
				return err
			}
			f := maxP.Float64 + 1
			prio = &f
		}

		conn := Record{
			"id":        newUUID(),
			"provider":  provider,
			"authType":  firstNonEmpty(strVal(data, "authType"), "oauth"),
			"priority":  *prio,
			"isActive":  boolVal(data, "isActive", true),
			"createdAt": now,
			"updatedAt": now,
		}
		if connName != nil {
			conn["name"] = *connName
		} else {
			conn["name"] = nil
		}
		for _, f := range connectionOptionalFields {
			if v, ok := data[f]; ok && v != nil {
				conn[f] = v
			}
		}
		if psd := toMap(data["providerSpecificData"]); len(psd) > 0 {
			conn["providerSpecificData"] = psd
		}
		if _, ok := data["email"]; ok {
			conn["email"] = data["email"]
		}
		if err := upsertConn(tx, conn); err != nil {
			return err
		}
		result = conn
		return nil
	})
	if conflict != nil {
		return nil, conflict
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) UpdateProviderConnection(id string, data Record) (Record, error) {
	var result Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getConnQ(tx, id)
		if err != nil {
			return err
		}
		if existing == nil {
			result = nil
			return nil
		}
		normalized := resetHealthStateOnActivation(existing, data)
		merged := mergeMaps(existing, normalized)
		merged["updatedAt"] = nowISO()
		if err := upsertConn(tx, merged); err != nil {
			return err
		}
		if _, ok := data["priority"]; ok {
			if err := reorderInTx(tx, strVal(existing, "provider")); err != nil {
				return err
			}
		}
		result = merged
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) DeleteProviderConnection(id string) (bool, error) {
	ok := false
	err := s.tx(func(tx *sql.Tx) error {
		var provider string
		err := tx.QueryRow(`SELECT provider FROM providerConnections WHERE id = ?`, id).Scan(&provider)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM providerConnections WHERE id = ?`, id); err != nil {
			return err
		}
		if err := reorderInTx(tx, provider); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return ok, err
}

func (s *Store) DeleteProviderConnectionsByProvider(providerID string) (int64, error) {
	var n int64
	if err := s.sql.QueryRow(`SELECT COUNT(*) FROM providerConnections WHERE provider = ?`, providerID).Scan(&n); err != nil {
		return 0, err
	}
	if _, err := s.sql.Exec(`DELETE FROM providerConnections WHERE provider = ?`, providerID); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) ReorderProviderConnections(providerID string) error {
	return s.tx(func(tx *sql.Tx) error { return reorderInTx(tx, providerID) })
}

func (s *Store) CleanupProviderConnections() (int, error) {
	fields := []string{
		"displayName", "email", "globalPriority", "defaultModel",
		"accessToken", "refreshToken", "expiresAt", "tokenType",
		"scope", "projectId", "apiKey", "testStatus",
		"lastTested", "lastError", "lastErrorAt", "rateLimitedUntil", "expiresIn",
		"consecutiveUseCount",
	}
	cleaned := 0
	err := s.tx(func(tx *sql.Tx) error {
		all, err := queryConns(tx, "")
		if err != nil {
			return err
		}
		for _, conn := range all {
			dirty := false
			for _, f := range fields {
				if v, ok := conn[f]; ok && v == nil {
					delete(conn, f)
					cleaned++
					dirty = true
				}
			}
			if psd, ok := conn["providerSpecificData"]; ok {
				if m := toMap(psd); len(m) == 0 {
					delete(conn, "providerSpecificData")
					cleaned++
					dirty = true
				}
			}
			if dirty {
				if err := upsertConn(tx, conn); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return cleaned, err
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
