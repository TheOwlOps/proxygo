package db

import "database/sql"

// Port of repos/disabledModelsRepo.js (kv scope "disabledModels":
// key=providerAlias, value=JSON array of model ids).

const disabledScope = "disabledModels"

func (s *Store) GetDisabledModels() (Record, error) {
	rows, err := s.sql.Query(`SELECT key, value FROM kv WHERE scope = ?`, disabledScope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := Record{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		parsed := parseJSON(v, []any{})
		if arr, ok := parsed.([]any); ok {
			out[k] = arr
		} else {
			out[k] = []any{}
		}
	}
	return out, rows.Err()
}

func (s *Store) GetDisabledByProvider(providerAlias string) ([]any, error) {
	raw, found, err := kvGetQ(s.sql, disabledScope, providerAlias)
	if err != nil {
		return nil, err
	}
	if !found {
		return []any{}, nil
	}
	if arr, ok := parseJSON(raw, []any{}).([]any); ok {
		return arr, nil
	}
	return []any{}, nil
}

func (s *Store) DisableModels(providerAlias string, ids []any) error {
	if providerAlias == "" || ids == nil {
		return nil
	}
	return s.tx(func(tx *sql.Tx) error {
		raw, found, err := kvGetQ(tx, disabledScope, providerAlias)
		if err != nil {
			return err
		}
		var current []any
		if found {
			current, _ = parseJSON(raw, []any{}).([]any)
		}
		seen := map[string]bool{}
		merged := []any{}
		for _, v := range append(append([]any{}, current...), ids...) {
			k := stringifyJSON(v)
			if !seen[k] {
				seen[k] = true
				merged = append(merged, v)
			}
		}
		return kvSetQ(tx, disabledScope, providerAlias, merged)
	})
}

func (s *Store) EnableModels(providerAlias string, ids []any) error {
	if providerAlias == "" {
		return nil
	}
	return s.tx(func(tx *sql.Tx) error {
		if len(ids) == 0 {
			_, err := tx.Exec(`DELETE FROM kv WHERE scope = ? AND key = ?`, disabledScope, providerAlias)
			return err
		}
		raw, found, err := kvGetQ(tx, disabledScope, providerAlias)
		if err != nil {
			return err
		}
		var current []any
		if found {
			current, _ = parseJSON(raw, []any{}).([]any)
		}
		remove := map[string]bool{}
		for _, v := range ids {
			remove[stringifyJSON(v)] = true
		}
		next := []any{}
		for _, v := range current {
			if !remove[stringifyJSON(v)] {
				next = append(next, v)
			}
		}
		if len(next) == 0 {
			_, err := tx.Exec(`DELETE FROM kv WHERE scope = ? AND key = ?`, disabledScope, providerAlias)
			return err
		}
		return kvSetQ(tx, disabledScope, providerAlias, next)
	})
}
