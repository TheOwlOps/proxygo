package db

import (
	"database/sql"
	"sort"
	"strings"
)

// Port of repos/proxyPoolsRepo.js (proxyPools table).

func queryPools(q txRunner, where string, args ...any) ([]Record, error) {
	rows, err := q.Query(`SELECT id, isActive, testStatus, data, createdAt, updatedAt FROM proxyPools`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var id, data, createdAt, updatedAt string
		var isActive int
		var testStatus sql.NullString
		if err := rows.Scan(&id, &isActive, &testStatus, &data, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		rec := parseMap(data)
		rec["id"] = id
		rec["isActive"] = isActive == 1
		rec["testStatus"] = strOrNil(scanNullString(testStatus))
		rec["createdAt"] = createdAt
		rec["updatedAt"] = updatedAt
		out = append(out, rec)
	}
	return out, rows.Err()
}

func getPoolQ(q txRunner, id string) (Record, error) {
	recs, err := queryPools(q, ` WHERE id = ?`, id)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return recs[0], nil
}

func upsertPool(q txRunner, p Record) error {
	rest := cloneMap(p)
	for _, k := range []string{"id", "isActive", "testStatus", "createdAt", "updatedAt"} {
		delete(rest, k)
	}
	_, err := q.Exec(
		`INSERT INTO proxyPools(id, isActive, testStatus, data, createdAt, updatedAt)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   isActive=excluded.isActive, testStatus=excluded.testStatus,
		   data=excluded.data, updatedAt=excluded.updatedAt`,
		strVal(p, "id"), boolToInt(boolVal(p, "isActive", true)), nullStr(strVal(p, "testStatus")),
		stringifyJSON(rest), strVal(p, "createdAt"), strVal(p, "updatedAt"))
	return err
}

func (s *Store) GetProxyPools(filter ProxyPoolFilter) ([]Record, error) {
	var conds []string
	var args []any
	if filter.IsActive != nil {
		conds = append(conds, "isActive = ?")
		args = append(args, boolToInt(*filter.IsActive))
	}
	if filter.TestStatus != "" {
		conds = append(conds, "testStatus = ?")
		args = append(args, filter.TestStatus)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	list, err := queryPools(s.sql, where, args...)
	if err != nil {
		return nil, err
	}
	// JS sorts by updatedAt DESC in memory.
	sort.SliceStable(list, func(i, j int) bool {
		return strVal(list[i], "updatedAt") > strVal(list[j], "updatedAt")
	})
	if list == nil {
		list = []Record{}
	}
	return list, nil
}

func (s *Store) GetProxyPoolByID(id string) (Record, error) {
	return getPoolQ(s.sql, id)
}

func (s *Store) CreateProxyPool(data Record) (Record, error) {
	now := nowISO()
	id := strVal(data, "id")
	if id == "" {
		id = newUUID()
	}
	pool := Record{
		"id":           id,
		"name":         data["name"],
		"proxyUrl":     data["proxyUrl"],
		"noProxy":      firstNonEmpty(strVal(data, "noProxy"), ""),
		"type":         firstNonEmpty(strVal(data, "type"), "http"),
		"isActive":     boolVal(data, "isActive", true),
		"strictProxy":  data["strictProxy"] == true,
		"testStatus":   firstNonEmpty(strVal(data, "testStatus"), "unknown"),
		"lastTestedAt": data["lastTestedAt"],
		"lastError":    data["lastError"],
		"createdAt":    now,
		"updatedAt":    now,
	}
	if err := upsertPool(s.sql, pool); err != nil {
		return nil, err
	}
	return pool, nil
}

func (s *Store) UpdateProxyPool(id string, data Record) (Record, error) {
	var result Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getPoolQ(tx, id)
		if err != nil {
			return err
		}
		if existing == nil {
			return nil
		}
		merged := mergeMaps(existing, data)
		merged["updatedAt"] = nowISO()
		if err := upsertPool(tx, merged); err != nil {
			return err
		}
		result = merged
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) DeleteProxyPool(id string) (Record, error) {
	var removed Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getPoolQ(tx, id)
		if err != nil {
			return err
		}
		if existing == nil {
			return nil
		}
		removed = existing
		_, err = tx.Exec(`DELETE FROM proxyPools WHERE id = ?`, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}
