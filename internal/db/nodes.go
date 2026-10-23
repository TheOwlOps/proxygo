package db

import (
	"database/sql"
)

// Port of repos/nodesRepo.js (providerNodes table).

type nodeRow struct {
	id        string
	typ       *string
	name      *string
	data      string
	createdAt string
	updatedAt string
}

func (r *nodeRow) toRecord() Record {
	rec := parseMap(r.data)
	rec["id"] = r.id
	rec["type"] = strOrNil(r.typ)
	rec["name"] = strOrNil(r.name)
	rec["createdAt"] = r.createdAt
	rec["updatedAt"] = r.updatedAt
	return rec
}

func queryNodes(q txRunner, where string, args ...any) ([]Record, error) {
	rows, err := q.Query(`SELECT id, type, name, data, createdAt, updatedAt FROM providerNodes`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r nodeRow
		var typ, name sql.NullString
		if err := rows.Scan(&r.id, &typ, &name, &r.data, &r.createdAt, &r.updatedAt); err != nil {
			return nil, err
		}
		r.typ = scanNullString(typ)
		r.name = scanNullString(name)
		out = append(out, r.toRecord())
	}
	return out, rows.Err()
}

func getNodeQ(q txRunner, id string) (Record, error) {
	recs, err := queryNodes(q, ` WHERE id = ?`, id)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return recs[0], nil
}

func upsertNode(q txRunner, n Record) error {
	rest := cloneMap(n)
	for _, k := range []string{"id", "type", "name", "createdAt", "updatedAt"} {
		delete(rest, k)
	}
	_, err := q.Exec(
		`INSERT INTO providerNodes(id, type, name, data, createdAt, updatedAt)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   type=excluded.type, name=excluded.name, data=excluded.data, updatedAt=excluded.updatedAt`,
		strVal(n, "id"), nullStr(strVal(n, "type")), nullStr(strVal(n, "name")),
		stringifyJSON(rest), strVal(n, "createdAt"), strVal(n, "updatedAt"))
	return err
}

func (s *Store) GetProviderNodes(filter NodeFilter) ([]Record, error) {
	where := ""
	var args []any
	if filter.Type != "" {
		where = " WHERE type = ?"
		args = append(args, filter.Type)
	}
	out, err := queryNodes(s.sql, where, args...)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Record{}
	}
	return out, nil
}

func (s *Store) GetProviderNodeByID(id string) (Record, error) {
	return getNodeQ(s.sql, id)
}

func (s *Store) CreateProviderNode(data Record) (Record, error) {
	now := nowISO()
	id := strVal(data, "id")
	if id == "" {
		id = newUUID()
	}
	node := Record{"id": id, "createdAt": now, "updatedAt": now}
	// JS builds the node from exactly these fields (undefined ones are
	// dropped by JSON serialization, so we simply omit missing keys).
	for _, k := range []string{"type", "name", "prefix", "apiType", "baseUrl"} {
		if v, ok := data[k]; ok && v != nil {
			node[k] = v
		}
	}
	if err := upsertNode(s.sql, node); err != nil {
		return nil, err
	}
	return node, nil
}

func (s *Store) UpdateProviderNode(id string, data Record) (Record, error) {
	var result Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getNodeQ(tx, id)
		if err != nil {
			return err
		}
		if existing == nil {
			return nil
		}
		merged := mergeMaps(existing, data)
		merged["updatedAt"] = nowISO()
		if err := upsertNode(tx, merged); err != nil {
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

func (s *Store) DeleteProviderNode(id string) (Record, error) {
	var removed Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getNodeQ(tx, id)
		if err != nil {
			return err
		}
		if existing == nil {
			return nil
		}
		removed = existing
		if _, err := tx.Exec(`DELETE FROM providerNodes WHERE id = ?`, id); err != nil {
			return err
		}
		// JS also removes this node's custom models (kv keys "<id>|...").
		_, err = tx.Exec(`DELETE FROM kv WHERE scope = 'customModels' AND key LIKE ?`, id+"|%")
		return err
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}
