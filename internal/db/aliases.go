package db

import "database/sql"

// Port of repos/aliasRepo.js — all three collections live in the kv table
// under scopes "modelAliases", "customModels", "mitmAlias".

func (s *Store) aliasKV() KVScope  { return &kvStore{s: s, scope: "modelAliases"} }
func (s *Store) customKV() KVScope { return &kvStore{s: s, scope: "customModels"} }
func (s *Store) mitmKV() KVScope   { return &kvStore{s: s, scope: "mitmAlias"} }

// --- modelAliases: key=alias, value=modelString ---

func (s *Store) GetModelAliases() (Record, error) { return s.aliasKV().GetAll() }

func (s *Store) SetModelAlias(alias, model string) error { return s.aliasKV().Set(alias, model) }

func (s *Store) DeleteModelAlias(alias string) error { return s.aliasKV().Remove(alias) }

// --- customModels: key=`${providerAlias}|${id}|${type}`, value=model object ---

func customModelKey(providerAlias, id, typ string) string {
	return providerAlias + "|" + id + "|" + typ
}

func (s *Store) GetCustomModels() ([]Record, error) {
	all, err := s.customKV().GetAll()
	if err != nil {
		return nil, err
	}
	out := []Record{}
	for _, v := range all {
		out = append(out, toMap(v))
	}
	return out, nil
}

// AddCustomModel mirrors addCustomModel: atomic upsert; re-adding an
// existing model updates name/caps/transport without resetting omitted
// fields. Returns true when a new model was added.
func (s *Store) AddCustomModel(m Record) (bool, error) {
	providerAlias := strVal(m, "providerAlias")
	id := strVal(m, "id")
	typ := strVal(m, "type")
	if typ == "" {
		typ = "llm"
	}
	k := customModelKey(providerAlias, id, typ)
	added := false
	err := s.tx(func(tx *sql.Tx) error {
		raw, found, err := kvGetQ(tx, "customModels", k)
		if err != nil {
			return err
		}
		if found {
			next := parseMap(raw)
			if v, ok := m["name"]; ok && v != nil {
				next["name"] = v
			}
			if v, ok := m["caps"]; ok && v != nil {
				next["caps"] = v
			}
			if v, ok := m["transport"]; ok && v != nil {
				next["transport"] = v
			}
			_, err := tx.Exec(`UPDATE kv SET value = ? WHERE scope = 'customModels' AND key = ?`, stringifyJSON(next), k)
			return err
		}
		value := Record{
			"providerAlias": providerAlias,
			"id":            id,
			"type":          typ,
			"name":          firstNonEmpty(strVal(m, "name"), id),
		}
		if v, ok := m["caps"]; ok && v != nil {
			value["caps"] = v
		}
		if v, ok := m["transport"]; ok && v != nil {
			value["transport"] = v
		}
		if err := kvSetQ(tx, "customModels", k, value); err != nil {
			return err
		}
		added = true
		return nil
	})
	return added, err
}

func (s *Store) DeleteCustomModel(providerAlias, id, typ string) error {
	if typ == "" {
		typ = "llm"
	}
	return s.customKV().Remove(customModelKey(providerAlias, id, typ))
}

// --- mitmAlias: key=toolName, value=mappings object ---

// GetMitmAlias returns the mappings for one tool, or all tools when
// toolName is "" (JS getMitmAlias() with no argument).
func (s *Store) GetMitmAlias(toolName string) (Record, error) {
	if toolName != "" {
		v, err := s.mitmKV().Get(toolName, nil)
		if err != nil {
			return nil, err
		}
		return toMap(v), nil
	}
	return s.mitmKV().GetAll()
}

func (s *Store) SetMitmAliasAll(toolName string, mappings Record) error {
	if mappings == nil {
		mappings = Record{}
	}
	return s.mitmKV().Set(toolName, mappings)
}
