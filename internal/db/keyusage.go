package db

import "time"

// Per-API-key usage aggregation for Feature Pack F3 (per-key budgets).
// usageHistory.apiKey stores the presented client API key string (the
// same value usage_stats.go resolves back to a key record), so totals
// are aggregated by that string. Windows are the caller's job: pass the
// window start (local midnight / local month start) as `since`;
// timestamps are fixed-width UTC ISO strings, so the >= comparison is
// exact.

// KeyUsageTotals is one window of usage for a single API key.
type KeyUsageTotals struct {
	Requests         int64
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64 // prompt + completion
	CostUSD          float64
}

// GetKeyUsageTotals sums usageHistory rows for apiKey at or after since.
func (s *Store) GetKeyUsageTotals(apiKey string, since time.Time) (KeyUsageTotals, error) {
	var out KeyUsageTotals
	if apiKey == "" {
		return out, nil
	}
	row := s.sql.QueryRow(
		`SELECT COUNT(*),
		        COALESCE(SUM(promptTokens), 0),
		        COALESCE(SUM(completionTokens), 0),
		        COALESCE(SUM(cost), 0)
		   FROM usageHistory
		  WHERE apiKey = ? AND timestamp >= ?`,
		apiKey, isoOf(since))
	if err := row.Scan(&out.Requests, &out.PromptTokens, &out.CompletionTokens, &out.CostUSD); err != nil {
		return KeyUsageTotals{}, err
	}
	out.TotalTokens = out.PromptTokens + out.CompletionTokens
	return out, nil
}
