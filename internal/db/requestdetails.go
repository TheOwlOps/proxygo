package db

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port of repos/requestDetailsRepo.js (requestDetails table).
//
// Divergence (documented in README.md): the JS repo buffers records and
// flushes asynchronously (batchSize / flushIntervalMs, plus a shutdown
// hook). The Go port writes synchronously inside SaveRequestDetail —
// same config gating, sanitization, truncation and retention pruning,
// no data loss on crash, no background goroutine to drain.

const (
	defaultObsMaxRecords  = 200
	defaultObsBatchSize   = 20
	defaultObsFlushMs     = 5000
	defaultObsMaxJSONSize = 5 * 1024
	obsConfigCacheTTL     = 5000 * time.Millisecond
)

type obsConfig struct {
	enabled         bool
	maxRecords      int
	batchSize       int
	flushIntervalMs int
	maxJSONSize     int
}

type requestDetailsState struct {
	mu       sync.Mutex
	cached   *obsConfig
	cachedTs time.Time
}

func newRequestDetailsState() *requestDetailsState { return &requestDetailsState{} }

// stop exists for symmetry with Close(); there is no background work.
func (st *requestDetailsState) stop() {}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func (s *Store) observabilityConfig() obsConfig {
	st := s.rd
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.cached != nil && time.Since(st.cachedTs) < obsConfigCacheTTL {
		return *st.cached
	}
	cfg := obsConfig{
		enabled:         false,
		maxRecords:      defaultObsMaxRecords,
		batchSize:       defaultObsBatchSize,
		flushIntervalMs: defaultObsFlushMs,
		maxJSONSize:     defaultObsMaxJSONSize,
	}
	settings, err := s.GetSettings()
	if err == nil {
		maxRecords := int(numVal(settings["observabilityMaxRecords"]))
		if maxRecords == 0 {
			maxRecords = envInt("OBSERVABILITY_MAX_RECORDS", defaultObsMaxRecords)
		}
		batchSize := int(numVal(settings["observabilityBatchSize"]))
		if batchSize == 0 {
			batchSize = envInt("OBSERVABILITY_BATCH_SIZE", defaultObsBatchSize)
		}
		flushMs := int(numVal(settings["observabilityFlushIntervalMs"]))
		if flushMs == 0 {
			flushMs = envInt("OBSERVABILITY_FLUSH_INTERVAL_MS", defaultObsFlushMs)
		}
		maxJSONKB := int(numVal(settings["observabilityMaxJsonSize"]))
		if maxJSONKB == 0 {
			maxJSONKB = envInt("OBSERVABILITY_MAX_JSON_SIZE", 5)
		}

		if v, present := os.LookupEnv("ENABLE_REQUEST_LOGS"); present {
			cfg = obsConfig{
				enabled:         strings.ToLower(v) == "true",
				maxRecords:      maxRecords,
				batchSize:       batchSize,
				flushIntervalMs: flushMs,
				maxJSONSize:     maxJSONKB * 1024,
			}
		} else {
			envFallback := os.Getenv("OBSERVABILITY_ENABLED") != "false"
			enabled := envFallback
			if b, ok := settings["enableObservability"].(bool); ok {
				enabled = b
			}
			cfg = obsConfig{
				enabled:         enabled,
				maxRecords:      maxRecords,
				batchSize:       batchSize,
				flushIntervalMs: flushMs,
				maxJSONSize:     maxJSONKB * 1024,
			}
		}
	}
	st.cached = &cfg
	st.cachedTs = time.Now()
	return cfg
}

// SanitizeHeaders ports sanitizeHeaders: drops keys containing
// authorization / x-api-key / cookie / token / api-key (case-insensitive).
func SanitizeHeaders(headers Record) Record {
	if headers == nil {
		return Record{}
	}
	sensitive := []string{"authorization", "x-api-key", "cookie", "token", "api-key"}
	out := cloneMap(headers)
	for k := range out {
		lk := strings.ToLower(k)
		for _, s := range sensitive {
			if strings.Contains(lk, s) {
				delete(out, k)
				break
			}
		}
	}
	return out
}

var detailRandChars = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

func generateDetailID(model string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	rnd := make([]byte, 6)
	for i, v := range b {
		rnd[i] = detailRandChars[int(v)%len(detailRandChars)]
	}
	modelPart := "unknown"
	if model != "" {
		modelPart = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				return r
			}
			return '-'
		}, model)
	}
	return fmt.Sprintf("%s-%s-%s", nowISO(), string(rnd), modelPart)
}

func truncateField(obj any, maxSize int) any {
	if obj == nil {
		return Record{}
	}
	str := stringifyJSON(obj)
	if len(str) > maxSize {
		preview := str
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return Record{"_truncated": true, "_originalSize": len(str), "_preview": preview}
	}
	return obj
}

// SaveRequestDetail persists one detail record immediately (see the
// divergence note above), applying the same config gate as JS.
func (s *Store) SaveRequestDetail(detail Record) error {
	cfg := s.observabilityConfig()
	if !cfg.enabled {
		return nil
	}
	item := cloneMap(detail)
	if strVal(item, "id") == "" {
		item["id"] = generateDetailID(strVal(item, "model"))
	}
	if strVal(item, "timestamp") == "" {
		item["timestamp"] = nowISO()
	}
	if req, ok := item["request"].(map[string]any); ok {
		if headers, ok := req["headers"].(map[string]any); ok {
			reqCopy := cloneMap(req)
			reqCopy["headers"] = SanitizeHeaders(headers)
			item["request"] = reqCopy
		}
	}

	record := Record{
		"id":           item["id"],
		"provider":     nil,
		"model":        nil,
		"connectionId": nil,
		"timestamp":    item["timestamp"],
		"status":       nil,
	}
	if v := item["provider"]; v != nil {
		record["provider"] = v
	}
	if v := item["model"]; v != nil {
		record["model"] = v
	}
	if v := item["connectionId"]; v != nil {
		record["connectionId"] = v
	}
	if v := item["status"]; v != nil {
		record["status"] = v
	}
	if v, ok := item["latency"]; ok && v != nil {
		record["latency"] = v
	} else {
		record["latency"] = Record{}
	}
	if v, ok := item["tokens"]; ok && v != nil {
		record["tokens"] = v
	} else {
		record["tokens"] = Record{}
	}
	record["request"] = truncateField(item["request"], cfg.maxJSONSize)
	record["providerRequest"] = truncateField(item["providerRequest"], cfg.maxJSONSize)
	record["providerResponse"] = truncateField(item["providerResponse"], cfg.maxJSONSize)
	record["response"] = truncateField(item["response"], cfg.maxJSONSize)
	if v, ok := item["pxpipe"]; ok {
		record["pxpipe"] = v
	}

	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`INSERT INTO requestDetails(id, timestamp, provider, model, connectionId, status, data) VALUES(?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET timestamp = excluded.timestamp, provider = excluded.provider, model = excluded.model, connectionId = excluded.connectionId, status = excluded.status, data = excluded.data`,
			record["id"], record["timestamp"], nullStr(strVal(record, "provider")), nullStr(strVal(record, "model")),
			nullStr(strVal(record, "connectionId")), nullStr(strVal(record, "status")), stringifyJSON(record)); err != nil {
			return err
		}
		var cnt int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM requestDetails`).Scan(&cnt); err != nil {
			return err
		}
		if cnt > cfg.maxRecords {
			_, err := tx.Exec(
				`DELETE FROM requestDetails WHERE id IN (SELECT id FROM requestDetails ORDER BY timestamp ASC LIMIT ?)`,
				cnt-cfg.maxRecords)
			return err
		}
		return nil
	})
}

func (s *Store) GetRequestDetails(filter RequestDetailsFilter) (*RequestDetailsPage, error) {
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
	if filter.ConnectionID != "" {
		conds = append(conds, "connectionId = ?")
		params = append(params, filter.ConnectionID)
	}
	if filter.Status != "" {
		conds = append(conds, "status = ?")
		params = append(params, filter.Status)
	}
	if filter.StartDate != "" {
		if t, err := time.Parse(time.RFC3339, filter.StartDate); err == nil {
			conds = append(conds, "timestamp >= ?")
			params = append(params, isoOf(t))
		} else if t2, err2 := time.Parse("2006-01-02", filter.StartDate); err2 == nil {
			conds = append(conds, "timestamp >= ?")
			params = append(params, isoOf(t2))
		}
	}
	if filter.EndDate != "" {
		if t, err := time.Parse(time.RFC3339, filter.EndDate); err == nil {
			conds = append(conds, "timestamp <= ?")
			params = append(params, isoOf(t))
		} else if t2, err2 := time.Parse("2006-01-02", filter.EndDate); err2 == nil {
			conds = append(conds, "timestamp <= ?")
			params = append(params, isoOf(t2))
		}
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var totalItems int
	if err := s.sql.QueryRow(`SELECT COUNT(*) FROM requestDetails`+where, params...).Scan(&totalItems); err != nil {
		return nil, err
	}
	page := filter.Page
	if page == 0 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize == 0 {
		pageSize = 50
	}
	totalPages := 0
	if pageSize > 0 {
		totalPages = (totalItems + pageSize - 1) / pageSize
	}
	offset := (page - 1) * pageSize

	rows, err := s.sql.Query(
		`SELECT data FROM requestDetails`+where+` ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		append(append([]any{}, params...), pageSize, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	details := []Record{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		details = append(details, parseMap(data))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &RequestDetailsPage{
		Details: details,
		Pagination: Record{
			"page":       page,
			"pageSize":   pageSize,
			"totalItems": totalItems,
			"totalPages": totalPages,
			"hasNext":    page < totalPages,
			"hasPrev":    page > 1,
		},
	}, nil
}

func (s *Store) GetDistinctProviders() ([]string, error) {
	rows, err := s.sql.Query(`SELECT DISTINCT provider FROM requestDetails WHERE provider IS NOT NULL ORDER BY provider ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetRequestDetailByID(id string) (Record, error) {
	var data string
	err := s.sql.QueryRow(`SELECT data FROM requestDetails WHERE id = ?`, id).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseMap(data), nil
}
