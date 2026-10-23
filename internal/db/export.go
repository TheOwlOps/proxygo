package db

import (
	"database/sql"
	"errors"
)

// Port of exportDb()/importDb() from src/lib/db/index.js.
// Export shape matches the JS object exactly (used for backup/restore).

func (s *Store) ExportDB() (Record, error) {
	settings, err := s.ExportSettings()
	if err != nil {
		return nil, err
	}
	out := Record{"settings": settings}

	conns, err := queryConns(s.sql, "")
	if err != nil {
		return nil, err
	}
	out["providerConnections"] = conns

	nodes, err := queryNodes(s.sql, "")
	if err != nil {
		return nil, err
	}
	out["providerNodes"] = nodes

	pools, err := queryPools(s.sql, "")
	if err != nil {
		return nil, err
	}
	out["proxyPools"] = pools

	keys, err := s.GetAPIKeys()
	if err != nil {
		return nil, err
	}
	// JS export keeps only these fields per key.
	keyList := []Record{}
	for _, k := range keys {
		keyList = append(keyList, Record{
			"id": k["id"], "key": k["key"], "name": k["name"], "machineId": k["machineId"],
			"isActive": k["isActive"], "createdAt": k["createdAt"], "access": k["access"],
		})
	}
	out["apiKeys"] = keyList

	combos, err := s.GetCombos()
	if err != nil {
		return nil, err
	}
	out["combos"] = combos

	aliases, err := (&kvStore{s: s, scope: "modelAliases"}).GetAll()
	if err != nil {
		return nil, err
	}
	out["modelAliases"] = aliases

	custom, err := (&kvStore{s: s, scope: "customModels"}).GetAll()
	if err != nil {
		return nil, err
	}
	customList := []any{}
	for _, v := range custom {
		customList = append(customList, v)
	}
	out["customModels"] = customList

	mitm, err := (&kvStore{s: s, scope: "mitmAlias"}).GetAll()
	if err != nil {
		return nil, err
	}
	out["mitmAlias"] = mitm

	pricing, err := (&kvStore{s: s, scope: "pricing"}).GetAll()
	if err != nil {
		return nil, err
	}
	out["pricing"] = pricing

	return out, nil
}

func (s *Store) ImportDB(payload Record) (Record, error) {
	if payload == nil {
		return nil, errors.New("Invalid database payload")
	}
	err := s.tx(func(tx *sql.Tx) error {
		for _, stmt := range []string{
			`DELETE FROM settings`,
			`DELETE FROM providerConnections`,
			`DELETE FROM providerNodes`,
			`DELETE FROM proxyPools`,
			`DELETE FROM apiKeys`,
			`DELETE FROM combos`,
			`DELETE FROM kv WHERE scope IN ('modelAliases', 'customModels', 'mitmAlias', 'pricing')`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return err
			}
		}

		if payload["settings"] != nil {
			if _, err := tx.Exec(
				`INSERT INTO settings(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
				stringifyJSON(payload["settings"])); err != nil {
				return err
			}
		}

		for _, cAny := range toSlice(payload["providerConnections"]) {
			c := toMap(cAny)
			rest := cloneMap(c)
			for _, k := range []string{"id", "provider", "authType", "name", "email", "priority", "isActive", "createdAt", "updatedAt"} {
				delete(rest, k)
			}
			authType := strVal(c, "authType")
			if authType == "" {
				authType = "oauth"
			}
			created := strVal(c, "createdAt")
			if created == "" {
				created = nowISO()
			}
			updated := strVal(c, "updatedAt")
			if updated == "" {
				updated = nowISO()
			}
			var prio any
			if p := numPtr(c, "priority"); p != nil {
				prio = *p
			}
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO providerConnections(id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				strVal(c, "id"), strVal(c, "provider"), authType, nullStr(strVal(c, "name")), nullStr(strVal(c, "email")),
				prio, boolToInt(boolVal(c, "isActive", true)), stringifyJSON(rest), created, updated); err != nil {
				return err
			}
		}
		for _, nAny := range toSlice(payload["providerNodes"]) {
			n := toMap(nAny)
			rest := cloneMap(n)
			for _, k := range []string{"id", "type", "name", "createdAt", "updatedAt"} {
				delete(rest, k)
			}
			created := strVal(n, "createdAt")
			if created == "" {
				created = nowISO()
			}
			updated := strVal(n, "updatedAt")
			if updated == "" {
				updated = nowISO()
			}
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO providerNodes(id, type, name, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
				strVal(n, "id"), nullStr(strVal(n, "type")), nullStr(strVal(n, "name")), stringifyJSON(rest), created, updated); err != nil {
				return err
			}
		}
		for _, pAny := range toSlice(payload["proxyPools"]) {
			p := toMap(pAny)
			rest := cloneMap(p)
			for _, k := range []string{"id", "isActive", "testStatus", "createdAt", "updatedAt"} {
				delete(rest, k)
			}
			ts := strVal(p, "testStatus")
			if ts == "" {
				ts = "unknown"
			}
			created := strVal(p, "createdAt")
			if created == "" {
				created = nowISO()
			}
			updated := strVal(p, "updatedAt")
			if updated == "" {
				updated = nowISO()
			}
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO proxyPools(id, isActive, testStatus, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
				strVal(p, "id"), boolToInt(boolVal(p, "isActive", true)), ts, stringifyJSON(rest), created, updated); err != nil {
				return err
			}
		}
		for _, kAny := range toSlice(payload["apiKeys"]) {
			k := toMap(kAny)
			access := KeyAccess{Restricted: false, Allow: []string{}}
			if rawAccess, present := k["access"]; present && rawAccess != nil {
				checked, err := ValidateKeyAccessInput(toMap(rawAccess))
				if err != nil {
					return errors.New("apiKeys " + strVal(k, "id") + ": " + err.Error())
				}
				access = checked
			}
			restricted, allow := keyAccessToColumns(access)
			created := strVal(k, "createdAt")
			if created == "" {
				created = nowISO()
			}
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO apiKeys(id, key, name, machineId, isActive, createdAt, accessRestricted, accessAllow) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
				strVal(k, "id"), strVal(k, "key"), nullStr(strVal(k, "name")), nullStr(strVal(k, "machineId")),
				boolToInt(boolVal(k, "isActive", true)), created, restricted, allow); err != nil {
				return err
			}
		}
		for _, cAny := range toSlice(payload["combos"]) {
			c := toMap(cAny)
			created := strVal(c, "createdAt")
			if created == "" {
				created = nowISO()
			}
			updated := strVal(c, "updatedAt")
			if updated == "" {
				updated = nowISO()
			}
			models := c["models"]
			if models == nil {
				models = []any{}
			}
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)`,
				strVal(c, "id"), strVal(c, "name"), nullStr(strVal(c, "kind")), stringifyJSON(models), created, updated); err != nil {
				return err
			}
		}
		for alias, m := range toMap(payload["modelAliases"]) {
			if err := kvSetQ(tx, "modelAliases", alias, m); err != nil {
				return err
			}
		}
		for _, mAny := range toSlice(payload["customModels"]) {
			m := toMap(mAny)
			typ := strVal(m, "type")
			if typ == "" {
				typ = "llm"
			}
			k := strVal(m, "providerAlias") + "|" + strVal(m, "id") + "|" + typ
			if err := kvSetQ(tx, "customModels", k, m); err != nil {
				return err
			}
		}
		for tool, mappings := range toMap(payload["mitmAlias"]) {
			if mappings == nil {
				mappings = Record{}
			}
			if err := kvSetQ(tx, "mitmAlias", tool, mappings); err != nil {
				return err
			}
		}
		for provider, models := range toMap(payload["pricing"]) {
			if models == nil {
				models = Record{}
			}
			if err := kvSetQ(tx, "pricing", provider, models); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.ExportDB()
}
