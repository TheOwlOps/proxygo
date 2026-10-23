package db

import "database/sql"

// Port of helpers/kvStore.js (makeKv) and helpers/metaStore.js.

type kvStore struct {
	s     *Store
	scope string
}

// Scoped returns a KVScope bound to a kv scope. Calling Scoped on the
// store-level KVStore (scope "") is the normal entry point.
func (k *kvStore) Scoped(scope string) KVScope {
	return &kvStore{s: k.s, scope: scope}
}

func (k *kvStore) GetMeta(key string, fallback string) (string, error) {
	return k.s.getMeta(key, fallback)
}

func (k *kvStore) SetMeta(key, value string) error {
	return k.s.setMeta(key, value)
}

func (s *Store) getMeta(key string, fallback string) (string, error) {
	var v string
	err := s.sql.QueryRow(`SELECT value FROM _meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return fallback, nil
	}
	if err != nil {
		return fallback, err
	}
	return v, nil
}

func (s *Store) setMeta(key, value string) error {
	_, err := s.sql.Exec(
		`INSERT INTO _meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// GetMeta exposes metaStore.getMeta on the store itself.
func (s *Store) GetMeta(key string, fallback string) (string, error) {
	return s.getMeta(key, fallback)
}

// SetMeta exposes metaStore.setMeta on the store itself.
func (s *Store) SetMeta(key string, value string) error { return s.setMeta(key, value) }

// --- KVScope ---

func (k *kvStore) Get(key string, fallback any) (any, error) {
	var v string
	err := k.s.sql.QueryRow(`SELECT value FROM kv WHERE scope = ? AND key = ?`, k.scope, key).Scan(&v)
	if err == sql.ErrNoRows {
		return fallback, nil
	}
	if err != nil {
		return fallback, err
	}
	return parseJSON(v, fallback), nil
}

func (k *kvStore) GetAll() (Record, error) {
	rows, err := k.s.sql.Query(`SELECT key, value FROM kv WHERE scope = ?`, k.scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := Record{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = parseJSON(value, nil)
	}
	return out, rows.Err()
}

func kvSetQ(q txRunner, scope, key string, value any) error {
	_, err := q.Exec(
		`INSERT INTO kv(scope, key, value) VALUES(?, ?, ?) ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value`,
		scope, key, stringifyJSON(value))
	return err
}

func (k *kvStore) Set(key string, value any) error {
	return kvSetQ(k.s.sql, k.scope, key, value)
}

func (k *kvStore) SetMany(obj Record) error {
	return k.s.tx(func(tx *sql.Tx) error {
		for key, v := range obj {
			if err := kvSetQ(tx, k.scope, key, v); err != nil {
				return err
			}
		}
		return nil
	})
}

func (k *kvStore) Remove(key string) error {
	_, err := k.s.sql.Exec(`DELETE FROM kv WHERE scope = ? AND key = ?`, k.scope, key)
	return err
}

func (k *kvStore) Clear() error {
	_, err := k.s.sql.Exec(`DELETE FROM kv WHERE scope = ?`, k.scope)
	return err
}

// kvGetQ reads one kv value inside any runner (used inside transactions).
func kvGetQ(q txRunner, scope, key string) (string, bool, error) {
	var v string
	err := q.QueryRow(`SELECT value FROM kv WHERE scope = ? AND key = ?`, scope, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}
