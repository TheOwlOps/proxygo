package db

import "database/sql"

// Port of repos/combosRepo.js (combos table). models is a JSON column.

func queryCombos(q txRunner, where string, args ...any) ([]Record, error) {
	rows, err := q.Query(`SELECT id, name, kind, models, createdAt, updatedAt FROM combos`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var id, name, models, createdAt, updatedAt string
		var kind sql.NullString
		if err := rows.Scan(&id, &name, &kind, &models, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		out = append(out, Record{
			"id":        id,
			"name":      name,
			"kind":      strOrNil(scanNullString(kind)),
			"models":    parseJSON(models, []any{}),
			"createdAt": createdAt,
			"updatedAt": updatedAt,
		})
	}
	return out, rows.Err()
}

func getComboQ(q txRunner, where string, arg any) (Record, error) {
	recs, err := queryCombos(q, where, arg)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return recs[0], nil
}

func (s *Store) GetCombos() ([]Record, error) {
	out, err := queryCombos(s.sql, ` ORDER BY createdAt ASC`)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Record{}
	}
	return out, nil
}

func (s *Store) GetComboByID(id string) (Record, error) {
	return getComboQ(s.sql, ` WHERE id = ?`, id)
}

func (s *Store) GetComboByName(name string) (Record, error) {
	return getComboQ(s.sql, ` WHERE name = ?`, name)
}

func (s *Store) CreateCombo(data Record) (Record, error) {
	now := nowISO()
	models := data["models"]
	if models == nil {
		models = []any{}
	}
	combo := Record{
		"id":        newUUID(),
		"name":      data["name"],
		"kind":      data["kind"],
		"models":    models,
		"createdAt": now,
		"updatedAt": now,
	}
	_, err := s.sql.Exec(
		`INSERT INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
		combo["id"], combo["name"], nullStr(strVal(data, "kind")), stringifyJSON(models), now, now)
	if err != nil {
		return nil, err
	}
	return combo, nil
}

func (s *Store) UpdateCombo(id string, data Record) (Record, error) {
	var result Record
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := getComboQ(tx, ` WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if existing == nil {
			return nil
		}
		merged := mergeMaps(existing, data)
		merged["updatedAt"] = nowISO()
		models := merged["models"]
		if models == nil {
			models = []any{}
		}
		if _, err := tx.Exec(
			`UPDATE combos SET name = ?, kind = ?, models = ?, updatedAt = ? WHERE id = ?`,
			merged["name"], nullStr(strVal(merged, "kind")), stringifyJSON(models), merged["updatedAt"], id); err != nil {
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

func (s *Store) DeleteCombo(id string) (bool, error) {
	res, err := s.sql.Exec(`DELETE FROM combos WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
