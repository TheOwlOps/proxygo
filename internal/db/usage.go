package db

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Port of repos/usageRepo.js (usageHistory + usageDaily + _meta
// totalRequestsLifetime; in-memory pending/ring state mirrors the JS
// globals). Stats event emission (statsEmitter) has no Go equivalent
// here — consumers poll GetUsageStats/GetActiveRequests instead.

const (
	pendingTimeout = 60 * time.Second
	ringCap        = 50
	connCacheTTL   = 30 * time.Second
)

var periodMs = map[string]int64{
	"24h": 86400000, "7d": 604800000, "30d": 2592000000, "60d": 5184000000,
}

// MaskAPIKey ports maskApiKey.
func MaskAPIKey(key string) any {
	if key == "" {
		return nil
	}
	trimmed := strings.TrimSpace(key)
	if len(trimmed) <= 12 {
		if trimmed == "" {
			return nil
		}
		return trimmed[:1] + "***"
	}
	return trimmed[:8] + "***" + trimmed[len(trimmed)-4:]
}

type usageState struct {
	mu         sync.Mutex
	byModel    map[string]int
	byAccount  map[string]map[string]int
	timers     map[string]*time.Timer
	lastErr    string
	lastErrTs  time.Time
	ring       []Record
	ringInit   bool
	connCache  map[string]string
	connCacheT time.Time
}

func newUsageState() *usageState {
	return &usageState{
		byModel:   map[string]int{},
		byAccount: map[string]map[string]int{},
		timers:    map[string]*time.Timer{},
		connCache: map[string]string{},
	}
}

func modelKeyOf(model, provider string) string {
	if provider != "" {
		return model + " (" + provider + ")"
	}
	return model
}

// TrackPendingRequest mirrors trackPendingRequest (in-memory counters
// with a 60s auto-reset timer per connection|model).
func (s *Store) TrackPendingRequest(model, provider, connectionID string, started, isErr bool) {
	u := s.usage
	mk := modelKeyOf(model, provider)
	timerKey := connectionID + "|" + mk

	u.mu.Lock()
	defer u.mu.Unlock()

	delta := -1
	if started {
		delta = 1
	}
	u.byModel[mk] += delta
	if u.byModel[mk] < 0 {
		u.byModel[mk] = 0
	}
	if u.byModel[mk] == 0 {
		delete(u.byModel, mk)
	}
	if connectionID != "" {
		if u.byAccount[connectionID] == nil {
			u.byAccount[connectionID] = map[string]int{}
		}
		u.byAccount[connectionID][mk] += delta
		if u.byAccount[connectionID][mk] < 0 {
			u.byAccount[connectionID][mk] = 0
		}
		if u.byAccount[connectionID][mk] == 0 {
			delete(u.byAccount[connectionID], mk)
			if len(u.byAccount[connectionID]) == 0 {
				delete(u.byAccount, connectionID)
			}
		}
	}

	if t, ok := u.timers[timerKey]; ok {
		t.Stop()
		delete(u.timers, timerKey)
	}
	if started {
		u.timers[timerKey] = time.AfterFunc(pendingTimeout, func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			delete(u.timers, timerKey)
			if u.byModel[mk] > 0 {
				u.byModel[mk] = 0
			}
			if connectionID != "" && u.byAccount[connectionID] != nil && u.byAccount[connectionID][mk] > 0 {
				u.byAccount[connectionID][mk] = 0
			}
		})
	}

	if !started && isErr && provider != "" {
		u.lastErr = strings.ToLower(provider)
		u.lastErrTs = time.Now()
	}
}

func (s *Store) connectionMapCached() map[string]string {
	u := s.usage
	u.mu.Lock()
	if time.Since(u.connCacheT) < connCacheTTL && u.connCache != nil {
		m := u.connCache
		u.mu.Unlock()
		return m
	}
	u.mu.Unlock()

	m := map[string]string{}
	if conns, err := s.GetProviderConnections(ConnectionFilter{}); err == nil {
		for _, c := range conns {
			name := strVal(c, "name")
			if name == "" {
				name = strVal(c, "email")
			}
			if name == "" {
				name = strVal(c, "id")
			}
			m[strVal(c, "id")] = name
		}
	}
	u.mu.Lock()
	u.connCache = m
	u.connCacheT = time.Now()
	u.mu.Unlock()
	return m
}

func (s *Store) ensureRingInit() {
	u := s.usage
	u.mu.Lock()
	if u.ringInit {
		u.mu.Unlock()
		return
	}
	u.ringInit = true
	u.mu.Unlock()

	rows, err := s.sql.Query(
		`SELECT timestamp, provider, model, connectionId, apiKey, endpoint, cost, status, tokens FROM usageHistory ORDER BY id DESC LIMIT ?`, ringCap)
	if err != nil {
		return
	}
	defer rows.Close()
	var items []Record
	for rows.Next() {
		var ts string
		var provider, model, connID, apiKey, endpoint, status sql.NullString
		var tokens sql.NullString
		var cost float64
		if err := rows.Scan(&ts, &provider, &model, &connID, &apiKey, &endpoint, &cost, &status, &tokens); err != nil {
			return
		}
		items = append(items, Record{
			"timestamp":    ts,
			"provider":     strOrNil(scanNullString(provider)),
			"model":        strOrNil(scanNullString(model)),
			"connectionId": strOrNil(scanNullString(connID)),
			"apiKey":       strOrNil(scanNullString(apiKey)),
			"endpoint":     strOrNil(scanNullString(endpoint)),
			"cost":         cost,
			"status":       strOrNil(scanNullString(status)),
			"tokens":       parseJSON(tokens.String, Record{}),
		})
	}
	// reverse (JS rows.reverse())
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	u.mu.Lock()
	u.ring = items
	u.mu.Unlock()
}

func (s *Store) pushToRing(entry Record) {
	u := s.usage
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ring = append(u.ring, entry)
	if len(u.ring) > ringCap {
		u.ring = u.ring[len(u.ring)-ringCap:]
	}
}

// recentFromRing builds the deduped recentRequests list (shared by
// getActiveRequests/getUsageStats shape in JS).
func recentFromRing(items []Record) []Record {
	sortedItems := append([]Record{}, items...)
	sort.SliceStable(sortedItems, func(i, j int) bool {
		return strVal(sortedItems[i], "timestamp") > strVal(sortedItems[j], "timestamp")
	})
	seen := map[string]bool{}
	out := []Record{}
	for _, e := range sortedItems {
		t := toMap(e["tokens"])
		pt := tokNum(t, "prompt_tokens", "input_tokens")
		ct := tokNum(t, "completion_tokens", "output_tokens")
		status := strVal(e, "status")
		if status == "" {
			status = "ok"
		}
		rec := Record{
			"timestamp":        e["timestamp"],
			"model":            e["model"],
			"provider":         firstNonEmpty(strVal(e, "provider"), ""),
			"promptTokens":     pt,
			"completionTokens": ct,
			"status":           status,
		}
		if pt == 0 && ct == 0 {
			continue
		}
		minute := ""
		if ts := strVal(e, "timestamp"); len(ts) >= 16 {
			minute = ts[:16]
		}
		key := strVal(e, "model") + "|" + strVal(e, "provider") + "|" + ftoa(pt) + "|" + ftoa(ct) + "|" + minute
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rec)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func ftoa(f float64) string {
	if f == float64(int64(f)) {
		return itoa(int(f))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", f), "0"), ".")
}

// GetActiveRequests mirrors getActiveRequests.
func (s *Store) GetActiveRequests() (Record, error) {
	connMap := s.connectionMapCached()
	u := s.usage

	active := []Record{}
	u.mu.Lock()
	for connID, models := range u.byAccount {
		for mk, count := range models {
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
				active = append(active, Record{
					"model":    model,
					"provider": provider,
					"account":  accountName,
					"count":    count,
				})
			}
		}
	}
	lastErr := ""
	if time.Since(u.lastErrTs) < 10*time.Second {
		lastErr = u.lastErr
	}
	u.mu.Unlock()

	s.ensureRingInit()
	u.mu.Lock()
	ringCopy := append([]Record{}, u.ring...)
	u.mu.Unlock()

	return Record{
		"activeRequests": active,
		"recentRequests": recentFromRing(ringCopy),
		"errorProvider":  lastErr,
	}, nil
}

func splitModelKey(mk string) (model, provider string) {
	// JS: /^(.*) \((.*)\)$/
	if strings.HasSuffix(mk, ")") {
		if idx := strings.LastIndex(mk, " ("); idx >= 0 {
			return mk[:idx], mk[idx+2 : len(mk)-1]
		}
	}
	return mk, "unknown"
}

// localDateKey mirrors getLocalDateKey (local timezone).
func localDateKey(ts string) string {
	t := time.Now()
	if ts != "" {
		if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			t = parsed
		}
	}
	lt := t.Local()
	return lt.Format("2006-01-02")
}

func counterRecord() Record {
	return Record{"requests": float64(0), "promptTokens": float64(0), "completionTokens": float64(0), "cachedTokens": float64(0), "cost": float64(0)}
}

func addToCounter(target Record, key string, prompt, completion, cached, cost float64, meta Record) {
	c, ok := target[key].(map[string]any)
	if !ok {
		c = counterRecord()
		c["requests"] = float64(0)
		target[key] = c
	}
	req := numVal(c["requests"])
	c["requests"] = req + 1
	c["promptTokens"] = numVal(c["promptTokens"]) + prompt
	c["completionTokens"] = numVal(c["completionTokens"]) + completion
	c["cachedTokens"] = numVal(c["cachedTokens"]) + cached
	c["cost"] = numVal(c["cost"]) + cost
	for k, v := range meta {
		c[k] = v
	}
}

// aggregateEntryToDay ports aggregateEntryToDay.
func aggregateEntryToDay(day, entry Record) {
	tokens := toMap(entry["tokens"])
	prompt := tokNum(tokens, "prompt_tokens", "input_tokens")
	completion := tokNum(tokens, "completion_tokens", "output_tokens")
	cached := tokNum(tokens, "cached_tokens", "cache_read_input_tokens")
	cost := numVal(entry["cost"])

	day["requests"] = numVal(day["requests"]) + 1
	day["promptTokens"] = numVal(day["promptTokens"]) + prompt
	day["completionTokens"] = numVal(day["completionTokens"]) + completion
	day["cachedTokens"] = numVal(day["cachedTokens"]) + cached
	day["cost"] = numVal(day["cost"]) + cost

	for _, k := range []string{"byProvider", "byModel", "byAccount", "byApiKey", "byEndpoint"} {
		if _, ok := day[k].(map[string]any); !ok {
			day[k] = Record{}
		}
	}
	byProvider := day["byProvider"].(map[string]any)
	byModel := day["byModel"].(map[string]any)
	byAccount := day["byAccount"].(map[string]any)
	byApiKey := day["byApiKey"].(map[string]any)
	byEndpoint := day["byEndpoint"].(map[string]any)

	provider := strVal(entry, "provider")
	model := strVal(entry, "model")

	if provider != "" {
		addToCounter(byProvider, provider, prompt, completion, cached, cost, nil)
	}
	modelKey := model
	if provider != "" {
		modelKey = model + "|" + provider
	}
	addToCounter(byModel, modelKey, prompt, completion, cached, cost, Record{"rawModel": model, "provider": provider})

	if connID := strVal(entry, "connectionId"); connID != "" {
		addToCounter(byAccount, connID, prompt, completion, cached, cost, Record{"rawModel": model, "provider": provider})
	}

	apiKeyVal := "local-no-key"
	if k := strVal(entry, "apiKey"); k != "" {
		apiKeyVal = k
	}
	akModelKey := apiKeyVal + "|" + model + "|" + firstNonEmpty(provider, "unknown")
	var akRaw any
	if v, ok := entry["apiKey"]; ok {
		akRaw = v
	}
	addToCounter(byApiKey, akModelKey, prompt, completion, cached, cost, Record{"rawModel": model, "provider": provider, "apiKey": akRaw})

	endpoint := strVal(entry, "endpoint")
	if endpoint == "" {
		endpoint = "Unknown"
	}
	epKey := endpoint + "|" + model + "|" + firstNonEmpty(provider, "unknown")
	addToCounter(byEndpoint, epKey, prompt, completion, cached, cost, Record{"endpoint": endpoint, "rawModel": model, "provider": provider})
}

// SaveRequestUsage ports saveRequestUsage: dedupe on
// (timestamp, provider, model, connectionId, apiKey, prompt, completion),
// then history insert + daily rollup + lifetime counter in ONE tx.
// Cost is computed via PricingResolver (wired by the parent) exactly as
// JS computes it via pricingRepo + calculateCostFromTokens.
func (s *Store) SaveRequestUsage(entry Record) error {
	e := cloneMap(entry)
	if strVal(e, "timestamp") == "" {
		e["timestamp"] = nowISO()
	}
	tokens := toMap(e["tokens"])
	if e["tokens"] == nil {
		tokens = Record{}
		e["tokens"] = tokens
	}
	pricing, _ := s.GetPricingForModel(strVal(e, "provider"), strVal(e, "model"))
	e["cost"] = CalculateCostFromTokens(tokens, pricing)

	prompt := tokNum(tokens, "prompt_tokens", "input_tokens")
	completion := tokNum(tokens, "completion_tokens", "output_tokens")

	inserted := false
	err := s.tx(func(tx *sql.Tx) error {
		var existingID sql.NullInt64
		var existingEndpoint sql.NullString
		row := tx.QueryRow(
			`SELECT id, endpoint FROM usageHistory
			 WHERE timestamp = ?
			   AND COALESCE(provider, '') = COALESCE(?, '')
			   AND COALESCE(model, '') = COALESCE(?, '')
			   AND COALESCE(connectionId, '') = COALESCE(?, '')
			   AND COALESCE(apiKey, '') = COALESCE(?, '')
			   AND promptTokens = ?
			   AND completionTokens = ?
			 ORDER BY id DESC LIMIT 1`,
			e["timestamp"], nullStr(strVal(e, "provider")), nullStr(strVal(e, "model")),
			nullStr(strVal(e, "connectionId")), nullStr(strVal(e, "apiKey")), prompt, completion)
		scanErr := row.Scan(&existingID, &existingEndpoint)
		if scanErr == nil && existingID.Valid {
			if !existingEndpoint.Valid || existingEndpoint.String == "" {
				if ep := strVal(e, "endpoint"); ep != "" {
					_, err := tx.Exec(`UPDATE usageHistory SET endpoint = ? WHERE id = ?`, ep, existingID.Int64)
					return err
				}
			}
			return nil
		}
		if scanErr != nil && scanErr != sql.ErrNoRows {
			return scanErr
		}

		status := strVal(e, "status")
		if status == "" {
			status = "ok"
		}
		if _, err := tx.Exec(
			`INSERT INTO usageHistory(timestamp, provider, model, connectionId, apiKey, endpoint, promptTokens, completionTokens, cost, status, tokens, meta) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e["timestamp"], nullStr(strVal(e, "provider")), nullStr(strVal(e, "model")),
			nullStr(strVal(e, "connectionId")), nullStr(strVal(e, "apiKey")), nullStr(strVal(e, "endpoint")),
			prompt, completion, numVal(e["cost"]), status, stringifyJSON(tokens), stringifyJSON(Record{})); err != nil {
			return err
		}

		dateKey := localDateKey(strVal(e, "timestamp"))
		var dayData string
		day := Record{
			"requests": float64(0), "promptTokens": float64(0), "completionTokens": float64(0), "cost": float64(0),
			"byProvider": Record{}, "byModel": Record{}, "byAccount": Record{}, "byApiKey": Record{}, "byEndpoint": Record{},
		}
		if err := tx.QueryRow(`SELECT data FROM usageDaily WHERE dateKey = ?`, dateKey).Scan(&dayData); err == nil {
			day = parseMap(dayData)
		} else if err != sql.ErrNoRows {
			return err
		}
		aggregateEntryToDay(day, e)
		if _, err := tx.Exec(
			`INSERT INTO usageDaily(dateKey, data) VALUES(?, ?) ON CONFLICT(dateKey) DO UPDATE SET data = excluded.data`,
			dateKey, stringifyJSON(day)); err != nil {
			return err
		}

		var curStr string
		cur := 0
		if err := tx.QueryRow(`SELECT value FROM _meta WHERE key = 'totalRequestsLifetime'`).Scan(&curStr); err == nil {
			cur, _ = atoiSafe(curStr)
		} else if err != sql.ErrNoRows {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO _meta(key, value) VALUES('totalRequestsLifetime', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			itoa(cur+1)); err != nil {
			return err
		}
		inserted = true
		return nil
	})
	if err != nil {
		return err
	}
	if inserted {
		s.pushToRing(e)
	}
	return nil
}

func atoiSafe(s string) (int, error) {
	n := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, sql.ErrNoRows
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

// GetUsageHistory ports getUsageHistory (apiKey is masked, never raw).
func (s *Store) GetUsageHistory(filter UsageFilter) ([]Record, error) {
	var conds []string
	var params []any
	if filter.Provider != "" {
		conds = append(conds, "provider = ?")
		params = append(params, filter.Provider)
	}
	if filter.Model != "" {
		conds = append(conds, "model = ?")
		params = append(params, filter.Model)
	}
	if filter.StartDate != "" {
		if t, err := time.Parse(time.RFC3339, filter.StartDate); err == nil {
			conds = append(conds, "timestamp >= ?")
			params = append(params, isoOf(t))
		}
	}
	if filter.EndDate != "" {
		if t, err := time.Parse(time.RFC3339, filter.EndDate); err == nil {
			conds = append(conds, "timestamp <= ?")
			params = append(params, isoOf(t))
		}
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	rows, err := s.sql.Query(
		`SELECT timestamp, provider, model, connectionId, apiKey, endpoint, cost, status, tokens FROM usageHistory`+where+` ORDER BY id ASC`, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var ts string
		var provider, model, connID, apiKey, endpoint, status sql.NullString
		var tokens sql.NullString
		var cost float64
		if err := rows.Scan(&ts, &provider, &model, &connID, &apiKey, &endpoint, &cost, &status, &tokens); err != nil {
			return nil, err
		}
		out = append(out, Record{
			"timestamp":    ts,
			"provider":     strOrNil(scanNullString(provider)),
			"model":        strOrNil(scanNullString(model)),
			"connectionId": strOrNil(scanNullString(connID)),
			"apiKeyMasked": MaskAPIKey(apiKey.String),
			"endpoint":     strOrNil(scanNullString(endpoint)),
			"cost":         cost,
			"status":       strOrNil(scanNullString(status)),
			"tokens":       parseJSON(tokens.String, Record{}),
		})
	}
	return out, rows.Err()
}
