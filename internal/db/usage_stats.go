package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Port of getUsageStats / getChartData / getRecentLogs from
// repos/usageRepo.js.

type dayRow struct {
	dateKey string
	data    Record
}

func (s *Store) loadDaysInRange(maxDays *int) ([]dayRow, error) {
	var rows *sql.Rows
	var err error
	if maxDays == nil {
		rows, err = s.sql.Query(`SELECT dateKey, data FROM usageDaily ORDER BY dateKey ASC`)
	} else {
		today := time.Now()
		cutoff := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location()).AddDate(0, 0, -*maxDays+1)
		cutoffKey := cutoff.Format("2006-01-02")
		rows, err = s.sql.Query(`SELECT dateKey, data FROM usageDaily WHERE dateKey >= ? ORDER BY dateKey ASC`, cutoffKey)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dayRow
	for rows.Next() {
		var dk, data string
		if err := rows.Scan(&dk, &data); err != nil {
			return nil, err
		}
		out = append(out, dayRow{dateKey: dk, data: parseMap(data)})
	}
	return out, rows.Err()
}

func statsCounter() Record {
	return Record{"requests": float64(0), "promptTokens": float64(0), "completionTokens": float64(0), "cachedTokens": float64(0), "cost": float64(0)}
}

func mergeCounter(dst Record, src Record) {
	dst["requests"] = numVal(dst["requests"]) + numVal(src["requests"])
	dst["promptTokens"] = numVal(dst["promptTokens"]) + numVal(src["promptTokens"])
	dst["completionTokens"] = numVal(dst["completionTokens"]) + numVal(src["completionTokens"])
	dst["cachedTokens"] = numVal(dst["cachedTokens"]) + numVal(src["cachedTokens"])
	dst["cost"] = numVal(dst["cost"]) + numVal(src["cost"])
}

func bumpCounter(dst Record, prompt, completion, cached, cost float64) {
	dst["requests"] = numVal(dst["requests"]) + 1
	dst["promptTokens"] = numVal(dst["promptTokens"]) + prompt
	dst["completionTokens"] = numVal(dst["completionTokens"]) + completion
	dst["cachedTokens"] = numVal(dst["cachedTokens"]) + cached
	dst["cost"] = numVal(dst["cost"]) + cost
}

// GetUsageStats ports getUsageStats(period): "all" (default), "7d",
// "30d", "60d" aggregate from usageDaily; "24h"/"today" aggregate live
// from usageHistory. Returned shape matches the JS object.
func (s *Store) GetUsageStats(period string) (Record, error) {
	if period == "" {
		period = "all"
	}
	// connection / node / api-key lookup maps (JS loads all three repos)
	connMap := map[string]string{}
	if conns, err := s.GetProviderConnections(ConnectionFilter{}); err == nil {
		for _, c := range conns {
			name := strVal(c, "name")
			if name == "" {
				name = strVal(c, "email")
			}
			if name == "" {
				name = strVal(c, "id")
			}
			connMap[strVal(c, "id")] = name
		}
	}
	nodeName := map[string]string{}
	if nodes, err := s.GetProviderNodes(NodeFilter{}); err == nil {
		for _, n := range nodes {
			if strVal(n, "id") != "" && strVal(n, "name") != "" {
				nodeName[strVal(n, "id")] = strVal(n, "name")
			}
		}
	}
	type keyInfo struct{ name, id, createdAt string }
	apiKeyMap := map[string]keyInfo{}
	if keys, err := s.GetAPIKeys(); err == nil {
		for _, k := range keys {
			if key := strings.TrimSpace(strVal(k, "key")); key != "" {
				var nm any = k["name"]
				name, _ := nm.(string)
				apiKeyMap[key] = keyInfo{name: name, id: strVal(k, "id"), createdAt: strVal(k, "createdAt")}
			}
		}
	}
	displayProvider := func(p string) string {
		if n, ok := nodeName[p]; ok {
			return n
		}
		return p
	}

	// recentRequests from live history (last 100)
	recentRows, err := s.sql.Query(`SELECT timestamp, provider, model, tokens, status FROM usageHistory ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	var recentRaw []Record
	for recentRows.Next() {
		var ts string
		var provider, model, status sql.NullString
		var tokens sql.NullString
		if err := recentRows.Scan(&ts, &provider, &model, &tokens, &status); err != nil {
			recentRows.Close()
			return nil, err
		}
		recentRaw = append(recentRaw, Record{
			"timestamp": ts, "provider": provider.String, "model": model.String,
			"status": status.String, "tokens": parseJSON(tokens.String, Record{}),
		})
	}
	recentRows.Close()
	if err := recentRows.Err(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	recentRequests := []Record{}
	for _, r := range recentRaw {
		t := toMap(r["tokens"])
		status := strVal(r, "status")
		if status == "" {
			status = "ok"
		}
		rec := Record{
			"timestamp":        r["timestamp"],
			"model":            r["model"],
			"provider":         strVal(r, "provider"),
			"promptTokens":     tokNum(t, "prompt_tokens", "input_tokens"),
			"completionTokens": tokNum(t, "completion_tokens", "output_tokens"),
			"cachedTokens":     tokNum(t, "cached_tokens", "cache_read_input_tokens"),
			"status":           status,
		}
		pt := numVal(rec["promptTokens"])
		ct := numVal(rec["completionTokens"])
		if pt == 0 && ct == 0 {
			continue
		}
		minute := ""
		if ts := strVal(r, "timestamp"); len(ts) >= 16 {
			minute = ts[:16]
		}
		key := strVal(r, "model") + "|" + strVal(r, "provider") + "|" + ftoa(pt) + "|" + ftoa(ct) + "|" + minute
		if seen[key] {
			continue
		}
		seen[key] = true
		recentRequests = append(recentRequests, rec)
		if len(recentRequests) >= 20 {
			break
		}
	}

	u := s.usage
	u.mu.Lock()
	lastErr := ""
	if time.Since(u.lastErrTs) < 10*time.Second {
		lastErr = u.lastErr
	}
	pendingSnapshot := Record{"byModel": Record{}, "byAccount": Record{}}
	for k, v := range u.byModel {
		pendingSnapshot["byModel"].(map[string]any)[k] = v
	}
	for k, v := range u.byAccount {
		inner := Record{}
		for kk, vv := range v {
			inner[kk] = vv
		}
		pendingSnapshot["byAccount"].(map[string]any)[k] = inner
	}
	u.mu.Unlock()

	stats := Record{
		"totalRequests":         float64(0),
		"totalPromptTokens":     float64(0),
		"totalCompletionTokens": float64(0),
		"totalCachedTokens":     float64(0),
		"totalCost":             float64(0),
		"byProvider":            Record{},
		"byModel":               Record{},
		"byAccount":             Record{},
		"byApiKey":              Record{},
		"byEndpoint":            Record{},
		"last10Minutes":         []Record{},
		"pending":               pendingSnapshot,
		"activeRequests":        []Record{},
		"recentRequests":        recentRequests,
		"errorProvider":         lastErr,
	}
	byProvider := stats["byProvider"].(map[string]any)
	byModel := stats["byModel"].(map[string]any)
	byAccount := stats["byAccount"].(map[string]any)
	byApiKey := stats["byApiKey"].(map[string]any)
	byEndpoint := stats["byEndpoint"].(map[string]any)

	// active requests from pending state
	for connID, modelsAny := range pendingSnapshot["byAccount"].(map[string]any) {
		for mk, countAny := range toMap(modelsAny) {
			count := numVal(countAny)
			if count <= 0 {
				// counts are ints in the snapshot; numVal handles them
				if iv, ok := countAny.(int); ok {
					count = float64(iv)
				}
			}
			if count > 0 {
				accountName, ok := connMap[connID]
				if !ok || accountName == "" {
					short := connID
					if len(short) > 8 {
						short = short[:8]
					}
					accountName = "Account " + short + "..."
				}
				model, provider := splitModelKey(mk)
				stats["activeRequests"] = append(stats["activeRequests"].([]Record), Record{
					"model": model, "provider": provider, "account": accountName, "count": int(count),
				})
			}
		}
	}

	// last10Minutes buckets
	now := time.Now()
	currentMinuteStart := time.Unix(now.Unix()/60*60, 0)
	tenMinutesAgo := currentMinuteStart.Add(-9 * time.Minute)
	bucketIdx := map[int64]int{}
	last10 := []Record{}
	for i := 0; i < 10; i++ {
		ts := currentMinuteStart.Add(-time.Duration(9-i) * time.Minute)
		bucketIdx[ts.Unix()] = i
		last10 = append(last10, Record{"requests": float64(0), "promptTokens": float64(0), "completionTokens": float64(0), "cost": float64(0)})
	}
	stats["last10Minutes"] = last10
	rows10, err := s.sql.Query(
		`SELECT timestamp, promptTokens, completionTokens, cost FROM usageHistory WHERE timestamp >= ? AND timestamp <= ?`,
		isoOf(tenMinutesAgo), isoOf(now))
	if err != nil {
		return nil, err
	}
	for rows10.Next() {
		var ts string
		var pt, ct sql.NullFloat64
		var cost float64
		if err := rows10.Scan(&ts, &pt, &ct, &cost); err != nil {
			rows10.Close()
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			minuteStart := t.Unix() / 60 * 60
			if idx, ok := bucketIdx[minuteStart]; ok {
				b := last10[idx]
				b["requests"] = numVal(b["requests"]) + 1
				b["promptTokens"] = numVal(b["promptTokens"]) + pt.Float64
				b["completionTokens"] = numVal(b["completionTokens"]) + ct.Float64
				b["cost"] = numVal(b["cost"]) + cost
			}
		}
	}
	rows10.Close()
	if err := rows10.Err(); err != nil {
		return nil, err
	}

	useDaily := period != "24h" && period != "today"
	if useDaily {
		periodDays := map[string]int{"7d": 7, "30d": 30, "60d": 60}
		var maxDays *int
		if d, ok := periodDays[period]; ok {
			maxDays = &d
		}
		dayRows, err := s.loadDaysInRange(maxDays)
		if err != nil {
			return nil, err
		}
		for _, dr := range dayRows {
			day := dr.data
			stats["totalPromptTokens"] = numVal(stats["totalPromptTokens"]) + numVal(day["promptTokens"])
			stats["totalCompletionTokens"] = numVal(stats["totalCompletionTokens"]) + numVal(day["completionTokens"])
			stats["totalCachedTokens"] = numVal(stats["totalCachedTokens"]) + numVal(day["cachedTokens"])
			stats["totalCost"] = numVal(stats["totalCost"]) + numVal(day["cost"])

			for prov, pAny := range toMap(day["byProvider"]) {
				p := toMap(pAny)
				dst, ok := byProvider[prov].(map[string]any)
				if !ok {
					dst = statsCounter()
					byProvider[prov] = dst
				}
				mergeCounter(dst, p)
			}
			for mk, mAny := range toMap(day["byModel"]) {
				m := toMap(mAny)
				rawModel := strVal(m, "rawModel")
				if rawModel == "" {
					rawModel = strings.SplitN(mk, "|", 2)[0]
				}
				provider := strVal(m, "provider")
				if provider == "" {
					parts := strings.SplitN(mk, "|", 2)
					if len(parts) == 2 {
						provider = parts[1]
					}
				}
				statsKey := rawModel
				if provider != "" {
					statsKey = rawModel + " (" + provider + ")"
				}
				dst, ok := byModel[statsKey].(map[string]any)
				if !ok {
					dst = statsCounter()
					dst["rawModel"] = rawModel
					dst["provider"] = displayProvider(provider)
					dst["lastUsed"] = dr.dateKey
					byModel[statsKey] = dst
				}
				mergeCounter(dst, m)
				if dr.dateKey > strVal(dst, "lastUsed") {
					dst["lastUsed"] = dr.dateKey
				}
			}
			for connID, aAny := range toMap(day["byAccount"]) {
				a := toMap(aAny)
				accountName, ok := connMap[connID]
				if !ok || accountName == "" {
					short := connID
					if len(short) > 8 {
						short = short[:8]
					}
					accountName = "Account " + short + "..."
				}
				rawModel := strVal(a, "rawModel")
				provider := strVal(a, "provider")
				accountKey := rawModel + " (" + provider + " - " + accountName + ")"
				dst, ok := byAccount[accountKey].(map[string]any)
				if !ok {
					dst = statsCounter()
					dst["rawModel"] = rawModel
					dst["provider"] = displayProvider(provider)
					dst["connectionId"] = connID
					dst["accountName"] = accountName
					dst["lastUsed"] = dr.dateKey
					byAccount[accountKey] = dst
				}
				mergeCounter(dst, a)
				if dr.dateKey > strVal(dst, "lastUsed") {
					dst["lastUsed"] = dr.dateKey
				}
			}
			for akKey, akAny := range toMap(day["byApiKey"]) {
				ak := toMap(akAny)
				rawModel := strVal(ak, "rawModel")
				provider := strVal(ak, "provider")
				var apiKeyVal *string
				if v, ok := ak["apiKey"].(string); ok && v != "" {
					t := strings.TrimSpace(v)
					apiKeyVal = &t
				}
				var keyInfoPtr *keyInfo
				if apiKeyVal != nil {
					if ki, ok := apiKeyMap[*apiKeyVal]; ok {
						keyInfoPtr = &ki
					}
				}
				var masked any
				if apiKeyVal != nil {
					masked = MaskAPIKey(*apiKeyVal)
				}
				keyName := ""
				if keyInfoPtr != nil && keyInfoPtr.name != "" {
					keyName = keyInfoPtr.name
				} else if apiKeyVal != nil {
					if m, ok := masked.(string); ok && m != "" {
						keyName = m
					} else if len(*apiKeyVal) >= 8 {
						keyName = (*apiKeyVal)[:8] + "..."
					} else {
						keyName = *apiKeyVal
					}
				} else {
					keyName = "Local (No API Key)"
				}
				apiKeyKey := "local-no-key"
				if m, ok := masked.(string); ok && m != "" {
					apiKeyKey = m
				}
				dst, ok := byApiKey[akKey].(map[string]any)
				if !ok {
					dst = statsCounter()
					dst["rawModel"] = rawModel
					dst["provider"] = displayProvider(provider)
					dst["apiKeyMasked"] = masked
					dst["keyName"] = keyName
					dst["apiKeyKey"] = apiKeyKey
					dst["lastUsed"] = dr.dateKey
					byApiKey[akKey] = dst
				}
				mergeCounter(dst, ak)
				if dr.dateKey > strVal(dst, "lastUsed") {
					dst["lastUsed"] = dr.dateKey
				}
			}
			for epKey, epAny := range toMap(day["byEndpoint"]) {
				ep := toMap(epAny)
				endpoint := strVal(ep, "endpoint")
				if endpoint == "" {
					endpoint = strings.SplitN(epKey, "|", 2)[0]
				}
				if endpoint == "" {
					endpoint = "Unknown"
				}
				rawModel := strVal(ep, "rawModel")
				provider := strVal(ep, "provider")
				dst, ok := byEndpoint[epKey].(map[string]any)
				if !ok {
					dst = statsCounter()
					dst["endpoint"] = endpoint
					dst["rawModel"] = rawModel
					dst["provider"] = displayProvider(provider)
					dst["lastUsed"] = dr.dateKey
					byEndpoint[epKey] = dst
				}
				mergeCounter(dst, ep)
				if dr.dateKey > strVal(dst, "lastUsed") {
					dst["lastUsed"] = dr.dateKey
				}
			}
		}

		// Overlay precise lastUsed from recent history (JS overlay step).
		var overlayCutoff int64 = 0
		if maxDays != nil {
			overlayCutoff = time.Now().UnixMilli() - int64(*maxDays)*86400000
		}
		twoDaysAgo := time.Now().UnixMilli() - 2*86400000
		if twoDaysAgo > overlayCutoff {
			overlayCutoff = twoDaysAgo
		}
		// JS: max(maxDaysCutoff, now-2d) where maxDaysCutoff is 0 when no maxDays.
		if maxDays == nil {
			overlayCutoff = twoDaysAgo
		}
		histRows, err := s.sql.Query(
			`SELECT timestamp, provider, model, connectionId, apiKey, endpoint FROM usageHistory WHERE timestamp >= ?`,
			isoOf(time.UnixMilli(overlayCutoff)))
		if err != nil {
			return nil, err
		}
		for histRows.Next() {
			var ts string
			var provider, model, connID, apiKey, endpoint sql.NullString
			if err := histRows.Scan(&ts, &provider, &model, &connID, &apiKey, &endpoint); err != nil {
				histRows.Close()
				return nil, err
			}
			mk := model.String
			if provider.String != "" {
				mk = model.String + " (" + provider.String + ")"
			}
			if dst, ok := byModel[mk].(map[string]any); ok && ts > strVal(dst, "lastUsed") {
				dst["lastUsed"] = ts
			}
			if connID.Valid && connID.String != "" {
				accountName, ok := connMap[connID.String]
				if !ok || accountName == "" {
					short := connID.String
					if len(short) > 8 {
						short = short[:8]
					}
					accountName = "Account " + short + "..."
				}
				accountKey := model.String + " (" + provider.String + " - " + accountName + ")"
				if dst, ok := byAccount[accountKey].(map[string]any); ok && ts > strVal(dst, "lastUsed") {
					dst["lastUsed"] = ts
				}
			}
			apiKeyKey := "local-no-key"
			if apiKey.Valid && apiKey.String != "" {
				apiKeyKey = apiKey.String + "|" + model.String + "|" + firstNonEmpty(provider.String, "unknown")
			}
			if dst, ok := byApiKey[apiKeyKey].(map[string]any); ok && ts > strVal(dst, "lastUsed") {
				dst["lastUsed"] = ts
			}
			ep := endpoint.String
			if ep == "" {
				ep = "Unknown"
			}
			endpointKey := ep + "|" + model.String + "|" + firstNonEmpty(provider.String, "unknown")
			if dst, ok := byEndpoint[endpointKey].(map[string]any); ok && ts > strVal(dst, "lastUsed") {
				dst["lastUsed"] = ts
			}
		}
		histRows.Close()
		if err := histRows.Err(); err != nil {
			return nil, err
		}
	} else {
		// 24h / today: live history
		var cutoff string
		if period == "today" {
			start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
			cutoff = isoOf(start)
		} else {
			cutoff = isoOf(now.Add(-24 * time.Hour))
		}
		rows, err := s.sql.Query(
			`SELECT timestamp, provider, model, connectionId, apiKey, endpoint, promptTokens, completionTokens, cost, tokens FROM usageHistory WHERE timestamp >= ?`, cutoff)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ts string
			var provider, model, connID, apiKey, endpoint sql.NullString
			var tokens sql.NullString
			var ptCol, ctCol sql.NullFloat64
			var cost float64
			if err := rows.Scan(&ts, &provider, &model, &connID, &apiKey, &endpoint, &ptCol, &ctCol, &cost, &tokens); err != nil {
				rows.Close()
				return nil, err
			}
			toks := parseMapFallback(tokens.String, Record{})
			prompt := tokNum(toks, "prompt_tokens", "input_tokens")
			if prompt == 0 {
				prompt = ptCol.Float64
			}
			completion := tokNum(toks, "completion_tokens", "output_tokens")
			if completion == 0 {
				completion = ctCol.Float64
			}
			cached := tokNum(toks, "cached_tokens", "cache_read_input_tokens")
			prov := provider.String
			mod := model.String

			stats["totalPromptTokens"] = numVal(stats["totalPromptTokens"]) + prompt
			stats["totalCompletionTokens"] = numVal(stats["totalCompletionTokens"]) + completion
			stats["totalCachedTokens"] = numVal(stats["totalCachedTokens"]) + cached
			stats["totalCost"] = numVal(stats["totalCost"]) + cost

			dst, ok := byProvider[prov].(map[string]any)
			if !ok {
				dst = statsCounter()
				byProvider[prov] = dst
			}
			bumpCounter(dst, prompt, completion, cached, cost)

			mk := mod
			if prov != "" {
				mk = mod + " (" + prov + ")"
			}
			mdst, ok := byModel[mk].(map[string]any)
			if !ok {
				mdst = statsCounter()
				mdst["rawModel"] = mod
				mdst["provider"] = displayProvider(prov)
				mdst["lastUsed"] = ts
				byModel[mk] = mdst
			}
			bumpCounter(mdst, prompt, completion, cached, cost)
			if ts > strVal(mdst, "lastUsed") {
				mdst["lastUsed"] = ts
			}

			if connID.Valid && connID.String != "" {
				accountName, ok2 := connMap[connID.String]
				if !ok2 || accountName == "" {
					short := connID.String
					if len(short) > 8 {
						short = short[:8]
					}
					accountName = "Account " + short + "..."
				}
				accountKey := mod + " (" + prov + " - " + accountName + ")"
				adst, ok := byAccount[accountKey].(map[string]any)
				if !ok {
					adst = statsCounter()
					adst["rawModel"] = mod
					adst["provider"] = displayProvider(prov)
					adst["connectionId"] = connID.String
					adst["accountName"] = accountName
					adst["lastUsed"] = ts
					byAccount[accountKey] = adst
				}
				bumpCounter(adst, prompt, completion, cached, cost)
				if ts > strVal(adst, "lastUsed") {
					adst["lastUsed"] = ts
				}
			}

			if apiKey.Valid && apiKey.String != "" {
				apiKeyVal := strings.TrimSpace(apiKey.String)
				var keyName string
				if ki, ok := apiKeyMap[apiKeyVal]; ok && ki.name != "" {
					keyName = ki.name
				} else if m := MaskAPIKey(apiKey.String); m != nil {
					keyName, _ = m.(string)
				}
				if keyName == "" {
					if len(apiKey.String) >= 8 {
						keyName = apiKey.String[:8] + "..."
					} else {
						keyName = apiKey.String
					}
				}
				akKey := apiKey.String + "|" + mod + "|" + firstNonEmpty(prov, "unknown")
				kdst, ok := byApiKey[akKey].(map[string]any)
				if !ok {
					kdst = statsCounter()
					kdst["rawModel"] = mod
					kdst["provider"] = displayProvider(prov)
					kdst["apiKeyMasked"] = MaskAPIKey(apiKey.String)
					kdst["keyName"] = keyName
					kdst["apiKeyKey"] = MaskAPIKey(apiKey.String)
					kdst["lastUsed"] = ts
					byApiKey[akKey] = kdst
				}
				bumpCounter(kdst, prompt, completion, cached, cost)
				if ts > strVal(kdst, "lastUsed") {
					kdst["lastUsed"] = ts
				}
			} else {
				kdst, ok := byApiKey["local-no-key"].(map[string]any)
				if !ok {
					kdst = statsCounter()
					kdst["rawModel"] = mod
					kdst["provider"] = displayProvider(prov)
					kdst["apiKeyMasked"] = nil
					kdst["keyName"] = "Local (No API Key)"
					kdst["apiKeyKey"] = "local-no-key"
					kdst["lastUsed"] = ts
					byApiKey["local-no-key"] = kdst
				}
				bumpCounter(kdst, prompt, completion, cached, cost)
				if ts > strVal(kdst, "lastUsed") {
					kdst["lastUsed"] = ts
				}
			}

			ep := endpoint.String
			if ep == "" {
				ep = "Unknown"
			}
			epKey := ep + "|" + mod + "|" + firstNonEmpty(prov, "unknown")
			edst, ok := byEndpoint[epKey].(map[string]any)
			if !ok {
				edst = statsCounter()
				edst["endpoint"] = ep
				edst["rawModel"] = mod
				edst["provider"] = displayProvider(prov)
				edst["lastUsed"] = ts
				byEndpoint[epKey] = edst
			}
			bumpCounter(edst, prompt, completion, cached, cost)
			if ts > strVal(edst, "lastUsed") {
				edst["lastUsed"] = ts
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	total := 0.0
	for _, pAny := range byProvider {
		total += numVal(toMap(pAny)["requests"])
	}
	stats["totalRequests"] = total
	return stats, nil
}

// GetChartData ports getChartData(period): hourly buckets for
// "today"/"24h", daily buckets otherwise ("7d" default, "30d", "60d",
// "all"). Labels use en-US formatting like the JS toLocale* calls.
func (s *Store) GetChartData(period string) ([]Record, error) {
	if period == "" {
		period = "7d"
	}
	now := time.Now()

	hourLabel := func(t time.Time) string { return t.Format("15:04") }
	dayLabel := func(t time.Time) string { return t.Format("Jan 2") }

	if period == "today" || period == "24h" {
		const bucketCount = 24
		const bucketMs = int64(3600000)
		var startTime time.Time
		if period == "today" {
			startTime = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		} else {
			startTime = now.Add(-bucketCount * time.Hour)
		}
		buckets := make([]Record, bucketCount)
		for i := range buckets {
			buckets[i] = Record{
				"label":    hourLabel(startTime.Add(time.Duration(i) * time.Hour)),
				"tokens":   float64(0),
				"cost":     float64(0),
				"requests": float64(0),
			}
		}
		rows, err := s.sql.Query(
			`SELECT timestamp, promptTokens, completionTokens, cost FROM usageHistory WHERE timestamp >= ?`,
			isoOf(startTime))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		endTime := startTime.Add(bucketCount * time.Hour)
		for rows.Next() {
			var ts string
			var pt, ct sql.NullFloat64
			var cost float64
			if err := rows.Scan(&ts, &pt, &ct, &cost); err != nil {
				return nil, err
			}
			t, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				continue
			}
			if period == "today" {
				if t.Before(startTime) || !t.Before(endTime) {
					continue
				}
			} else {
				if t.Before(startTime) || t.After(now) {
					continue
				}
			}
			idx := int((t.UnixMilli() - startTime.UnixMilli()) / bucketMs)
			if period == "24h" && idx >= bucketCount {
				idx = bucketCount - 1
			}
			if idx >= 0 && idx < bucketCount {
				b := buckets[idx]
				b["tokens"] = numVal(b["tokens"]) + pt.Float64 + ct.Float64
				b["cost"] = numVal(b["cost"]) + cost
				b["requests"] = numVal(b["requests"]) + 1
			}
		}
		return buckets, rows.Err()
	}

	if period == "all" {
		dayRows, err := s.loadDaysInRange(nil)
		if err != nil {
			return nil, err
		}
		if len(dayRows) == 0 {
			return []Record{}, nil
		}
		dayMap := map[string]Record{}
		for _, r := range dayRows {
			dayMap[r.dateKey] = r.data
		}
		earliest, err := time.ParseInLocation("2006-01-02", dayRows[0].dateKey, time.Local)
		if err != nil {
			return []Record{}, nil
		}
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		diffDays := int(today.Sub(earliest).Hours()/24) + 1
		if diffDays < 1 {
			diffDays = 1
		}
		out := make([]Record, 0, diffDays)
		for i := 0; i < diffDays; i++ {
			d := earliest.AddDate(0, 0, i)
			dayData := dayMap[d.Format("2006-01-02")]
			rec := Record{"label": dayLabel(d), "tokens": float64(0), "cost": float64(0), "requests": float64(0)}
			if dayData != nil {
				rec["tokens"] = numVal(dayData["promptTokens"]) + numVal(dayData["completionTokens"])
				rec["cost"] = numVal(dayData["cost"])
				rec["requests"] = numVal(dayData["requests"])
			}
			out = append(out, rec)
		}
		return out, nil
	}

	bucketCount := 7
	if period == "30d" {
		bucketCount = 30
	} else if period == "60d" {
		bucketCount = 60
	}
	dayRows, err := s.loadDaysInRange(&bucketCount)
	if err != nil {
		return nil, err
	}
	dayMap := map[string]Record{}
	for _, r := range dayRows {
		dayMap[r.dateKey] = r.data
	}
	out := make([]Record, 0, bucketCount)
	for i := 0; i < bucketCount; i++ {
		d := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -(bucketCount - 1 - i))
		dayData := dayMap[d.Format("2006-01-02")]
		rec := Record{"label": dayLabel(d), "tokens": float64(0), "cost": float64(0), "requests": float64(0)}
		if dayData != nil {
			rec["tokens"] = numVal(dayData["promptTokens"]) + numVal(dayData["completionTokens"])
			rec["cost"] = numVal(dayData["cost"])
			rec["requests"] = numVal(dayData["requests"])
		}
		out = append(out, rec)
	}
	return out, nil
}

// AppendRequestLog is a no-op, exactly like the JS (request logs are
// derived from usageHistory on read).
func (s *Store) AppendRequestLog() error { return nil }

func formatLogDate(t time.Time) string {
	return t.Local().Format("02-01-2006 15:04:05")
}

// GetRecentLogs ports getRecentLogs: formatted lines derived from
// usageHistory, newest first.
func (s *Store) GetRecentLogs(limit int) ([]string, error) {
	if limit == 0 {
		limit = 200
	}
	rows, err := s.sql.Query(
		`SELECT timestamp, provider, model, connectionId, promptTokens, completionTokens, status, tokens FROM usageHistory ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return []string{}, nil // JS catches and returns []
	}
	defer rows.Close()

	type logRow struct {
		ts, provider, model, connID, status string
		pt, ct                              sql.NullFloat64
		tokens                              string
	}
	var raw []logRow
	for rows.Next() {
		var r logRow
		var provider, model, connID, status sql.NullString
		var tokens sql.NullString
		if err := rows.Scan(&r.ts, &provider, &model, &connID, &r.pt, &r.ct, &status, &tokens); err != nil {
			return []string{}, nil
		}
		r.provider, r.model, r.connID, r.status = provider.String, model.String, connID.String, status.String
		r.tokens = tokens.String
		raw = append(raw, r)
	}
	if len(raw) == 0 {
		return []string{}, nil
	}
	connMap := map[string]string{}
	if conns, err := s.GetProviderConnections(ConnectionFilter{}); err == nil {
		for _, c := range conns {
			name := strVal(c, "name")
			if name == "" {
				name = strVal(c, "email")
			}
			connMap[strVal(c, "id")] = name
		}
	}
	out := []string{}
	for _, r := range raw {
		ts := r.ts
		if t, err := time.Parse(time.RFC3339, r.ts); err == nil {
			ts = formatLogDate(t)
		}
		p := strings.ToUpper(r.provider)
		if p == "" {
			p = "-"
		}
		m := r.model
		if m == "" {
			m = "-"
		}
		account := connMap[r.connID]
		if account == "" {
			if r.connID != "" {
				short := r.connID
				if len(short) > 8 {
					short = short[:8]
				}
				account = short
			} else {
				account = "-"
			}
		}
		tk := parseMap(r.tokens)
		sent := "-"
		if r.pt.Valid {
			sent = ftoa(r.pt.Float64)
		} else if v, ok := tk["prompt_tokens"]; ok {
			sent = ftoa(numVal(v))
		}
		received := "-"
		if r.ct.Valid {
			received = ftoa(r.ct.Float64)
		} else if v, ok := tk["completion_tokens"]; ok {
			received = ftoa(numVal(v))
		}
		status := r.status
		if status == "" {
			status = "-"
		}
		out = append(out, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s", ts, m, p, account, sent, received, status))
	}
	return out, nil
}
