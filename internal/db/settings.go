package db

import (
	"database/sql"
	"os"
	"strings"
)

// Port of repos/settingsRepo.js. Settings live as one JSON document in
// settings(id=1).data; DEFAULT_SETTINGS is ported verbatim.

func defaultHeadroomURL() string {
	if v := os.Getenv("HEADROOM_URL"); v != "" {
		return v
	}
	return "http://localhost:8787"
}

// DefaultSettings mirrors DEFAULT_SETTINGS in settingsRepo.js.
func DefaultSettings() Record {
	return Record{
		"cloudEnabled":               false,
		"tunnelEnabled":              false,
		"tunnelUrl":                  "",
		"tunnelProvider":             "cloudflare",
		"tailscaleEnabled":           false,
		"tailscaleUrl":               "",
		"stickyRoundRobinLimit":      3,
		"providerStrategies":         Record{},
		"quotaVisibility":            Record{},
		"comboStrategy":              "fallback",
		"comboStickyRoundRobinLimit": 1,
		"comboStrategies":            Record{},
		"capacityAdapter": Record{
			"vision":     Record{"enabled": true, "roundRobin": false, "models": []any{}},
			"pdf":        Record{"enabled": false, "roundRobin": false, "models": []any{}},
			"audioInput": Record{"enabled": true, "roundRobin": false, "models": []any{}},
			"videoInput": Record{"enabled": false, "roundRobin": false, "models": []any{}},
		},
		"requireLogin":  true,
		"requireApiKey": true,
		// Feature Pack 1+3 (Go-only additions, all opt-in/off by default).
		"responseCacheEnabled":           false,
		"responseCacheTTLSeconds":        300,
		"responseCacheMaxEntries":        500,
		"circuitBreakerEnabled":          false,
		"circuitBreakerFailureThreshold": 5,
		"circuitBreakerOpenSeconds":      30,
		"piiRedactionEnabled":            false,
		"piiRedactNationalId":            false,
		"tunnelDashboardAccess":          true,
		"authMode":                       "password",
		"ssoType":                        "oidc",
		"oidcIssuerUrl":                  "",
		"oidcClientId":                   "",
		"oidcClientSecret":               "",
		"oidcScopes":                     "openid profile email",
		"oidcLoginLabel":                 "Sign in with OIDC",
		"samlEntryPoint":                 "",
		"samlIssuer":                     "urn:9router:sp",
		"samlCert":                       "",
		"samlLoginLabel":                 "Sign in with SAML SSO",
		"samlAttributeEmail":             "email",
		"samlAttributeName":              "name",
		"enableObservability":            false,
		"observabilityMaxRecords":        1000,
		"observabilityBatchSize":         20,
		"observabilityFlushIntervalMs":   5000,
		"observabilityMaxJsonSize":       5,
		"outboundProxyEnabled":           false,
		"outboundProxyUrl":               "",
		"outboundNoProxy":                "",
		"mitmRouterBaseUrl":              "http://localhost:20128",
		"dnsToolEnabled":                 Record{},
		"rtkEnabled":                     true,
		"headroomEnabled":                false,
		"headroomUrl":                    defaultHeadroomURL(),
		"headroomCompressUserMessages":   false,
		"headroomTimeoutMs":              3000,
		"cavemanEnabled":                 false,
		"cavemanLevel":                   "full",
		"ponytailEnabled":                false,
		"ponytailLevel":                  "full",
		"pxpipeEnabled":                  false,
		"pxpipeAutoInstall":              true,
		"pxpipeMinChars":                 25000,
		"pxpipeTimeoutMs":                15000,
		"providerOverrides":              Record{},
	}
}

// MergeWithDefaults mirrors mergeWithDefaults(raw), including the
// outboundProxyEnabled legacy derivation and the capacityAdapter
// mimo model rename fix-up.
func MergeWithDefaults(raw Record) Record {
	defaults := DefaultSettings()
	merged := cloneMap(defaults)
	for k, v := range raw {
		merged[k] = v
	}
	// JS: a key explicitly present but undefined falls back to the default
	// (with outboundProxyEnabled derivable from a non-empty proxy URL).
	// In JSON storage undefined cannot occur, but keep the semantics for
	// in-memory callers passing nil values.
	for key, defVal := range defaults {
		if v, ok := raw[key]; ok && v == nil {
			if key == "outboundProxyEnabled" {
				if u, ok := merged["outboundProxyUrl"].(string); ok && strings.TrimSpace(u) != "" {
					merged[key] = true
					continue
				}
			}
			merged[key] = defVal
		}
	}
	if ca, ok := merged["capacityAdapter"].(map[string]any); ok {
		for _, entry := range ca {
			em := toMap(entry)
			if models, ok := em["models"].([]any); ok {
				for i, m := range models {
					if s, ok := m.(string); ok && s == "oc/mimo-v2.5-free" {
						models[i] = "oc/mimo-v2.6-flash-free"
					}
				}
			}
		}
	}
	return merged
}

func (s *Store) readRawSettingsQ(q txRunner) (Record, error) {
	var data string
	err := q.QueryRow(`SELECT data FROM settings WHERE id = 1`).Scan(&data)
	if err == sql.ErrNoRows {
		return Record{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseMap(data), nil
}

func (s *Store) GetSettings() (Record, error) {
	raw, err := s.readRawSettingsQ(s.sql)
	if err != nil {
		return nil, err
	}
	return MergeWithDefaults(raw), nil
}

// UpdateSettings is the JS atomic read-merge-write inside a transaction.
func (s *Store) UpdateSettings(updates Record) (Record, error) {
	var next Record
	err := s.tx(func(tx *sql.Tx) error {
		current, err := s.readRawSettingsQ(tx)
		if err != nil {
			return err
		}
		next = mergeMaps(current, updates)
		_, err = tx.Exec(
			`INSERT INTO settings(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
			stringifyJSON(next))
		return err
	})
	if err != nil {
		return nil, err
	}
	return MergeWithDefaults(next), nil
}

func (s *Store) IsCloudEnabled() (bool, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return false, err
	}
	return settings["cloudEnabled"] == true, nil
}

func (s *Store) GetCloudURL() (string, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return "", err
	}
	if v := strVal(settings, "cloudUrl"); v != "" {
		return v, nil
	}
	if v := os.Getenv("CLOUD_URL"); v != "" {
		return v, nil
	}
	return os.Getenv("NEXT_PUBLIC_CLOUD_URL"), nil
}

// ExportSettings returns the RAW stored settings (no defaults merged),
// like exportSettings().
func (s *Store) ExportSettings() (Record, error) {
	return s.readRawSettingsQ(s.sql)
}
