// Package keylimit implements Feature Pack F3: per-API-key request
// rate limits (RPM, in-memory sliding window) and token/cost budgets
// (daily + monthly, derived from the DB usage accounting in
// usageHistory). Limits are opt-in per key: a key with no stored limits
// (or all-zero limits) is never rejected, so behavior is unchanged
// until an operator sets limits via /api/keys/{id}/limits.
//
// Storage: the limits document lives in the DB KV store (scope "")
// under `keylimit:<apiKeyRecordID>` as JSON
// {rpm, dailyTokens, monthlyTokens, dailyCostUSD, monthlyCostUSD};
// 0/absent = unlimited.
//
// Identity: Check receives the presented client API key string (what
// chatcore has). It is resolved to the key record via
// Store.GetAPIKeyByKey; budget totals aggregate usageHistory rows by
// that same key string (the value usage accounting stores).
package keylimit

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"9router-go/internal/chatcore"
	"9router-go/internal/db"
)

// Limits is the per-key limits document (KV `keylimit:<id>`).
type Limits struct {
	RPM            int64   `json:"rpm"`
	DailyTokens    int64   `json:"dailyTokens"`
	MonthlyTokens  int64   `json:"monthlyTokens"`
	DailyCostUSD   float64 `json:"dailyCostUSD"`
	MonthlyCostUSD float64 `json:"monthlyCostUSD"`
}

// Any reports whether any limit is set.
func (l Limits) Any() bool {
	return l.RPM > 0 || l.DailyTokens > 0 || l.MonthlyTokens > 0 ||
		l.DailyCostUSD > 0 || l.MonthlyCostUSD > 0
}

const kvPrefix = "keylimit:"

func kvScope(store *db.Store) db.KVScope { return store.KV().Scoped("") }

// GetLimits reads the limits for an API key record id (zero Limits when
// none are stored).
func GetLimits(store *db.Store, keyID string) (Limits, error) {
	v, err := kvScope(store).Get(kvPrefix+keyID, nil)
	if err != nil || v == nil {
		return Limits{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Limits{}, err
	}
	var lim Limits
	if err := json.Unmarshal(raw, &lim); err != nil {
		return Limits{}, err
	}
	return lim, nil
}

// SetLimits stores the limits document for an API key record id.
func SetLimits(store *db.Store, keyID string, lim Limits) error {
	raw, err := json.Marshal(lim)
	if err != nil {
		return err
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return err
	}
	return kvScope(store).Set(kvPrefix+keyID, asMap)
}

// DeleteLimits removes the limits document for an API key record id.
func DeleteLimits(store *db.Store, keyID string) error {
	return kvScope(store).Remove(kvPrefix + keyID)
}

// StartOfDay returns local midnight at the start of t's day (the
// daily-budget window start; usage daily rollups are local-day too).
func StartOfDay(t time.Time) time.Time {
	lt := t.Local()
	return time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, lt.Location())
}

// StartOfMonth returns local midnight on the 1st of t's month.
func StartOfMonth(t time.Time) time.Time {
	lt := t.Local()
	return time.Date(lt.Year(), lt.Month(), 1, 0, 0, 0, 0, lt.Location())
}

const rpmWindow = time.Minute

// Limiter enforces per-key limits against a Store. Goroutine-safe.
type Limiter struct {
	store *db.Store
	now   func() time.Time

	mu   sync.Mutex
	hits map[string][]time.Time // key record id → request times in window
}

// New builds a Limiter over the store. It satisfies chatcore.KeyLimiter.
func New(store *db.Store) *Limiter {
	return &Limiter{store: store, now: time.Now, hits: map[string][]time.Time{}}
}

var _ chatcore.KeyLimiter = (*Limiter)(nil)

// Check implements chatcore.KeyLimiter. keyID is the presented client
// API key string; it is resolved to the key record for the limits
// lookup. Returns nil when the request is allowed (consuming one RPM
// slot when an RPM limit applies), or a 429 LimitRejection. Unknown
// keys, keys without limits and store errors are fail-open (nil) —
// limits must never take the gateway down.
func (l *Limiter) Check(keyID string) *chatcore.LimitRejection {
	if l == nil || l.store == nil || keyID == "" {
		return nil
	}
	rec, err := l.store.GetAPIKeyByKey(keyID)
	if err != nil || rec == nil {
		return nil
	}
	id, _ := rec["id"].(string)
	if id == "" {
		return nil
	}
	lim, err := GetLimits(l.store, id)
	if err != nil || !lim.Any() {
		return nil
	}

	now := l.now()
	if lim.DailyTokens > 0 || lim.DailyCostUSD > 0 {
		if rej := l.checkBudget(keyID, lim.DailyTokens, lim.DailyCostUSD, StartOfDay(now), "daily"); rej != nil {
			return rej
		}
	}
	if lim.MonthlyTokens > 0 || lim.MonthlyCostUSD > 0 {
		if rej := l.checkBudget(keyID, lim.MonthlyTokens, lim.MonthlyCostUSD, StartOfMonth(now), "monthly"); rej != nil {
			return rej
		}
	}
	if lim.RPM > 0 && !l.consume(id, now, lim.RPM) {
		return &chatcore.LimitRejection{
			Status:  chatcore.StatusRateLimited,
			Type:    "rate_limit_exceeded",
			Message: fmt.Sprintf("Rate limit exceeded for this API key (%d requests per minute)", lim.RPM),
		}
	}
	return nil
}

func (l *Limiter) checkBudget(key string, tokenCap int64, costCap float64, since time.Time, period string) *chatcore.LimitRejection {
	totals, err := l.store.GetKeyUsageTotals(key, since)
	if err != nil {
		return nil // fail-open, like Check
	}
	if tokenCap > 0 && totals.TotalTokens >= tokenCap {
		return &chatcore.LimitRejection{
			Status:  chatcore.StatusRateLimited,
			Type:    "budget_exceeded",
			Message: fmt.Sprintf("API key %s token budget exceeded (%d of %d tokens used)", period, totals.TotalTokens, tokenCap),
		}
	}
	if costCap > 0 && totals.CostUSD >= costCap {
		return &chatcore.LimitRejection{
			Status:  chatcore.StatusRateLimited,
			Type:    "budget_exceeded",
			Message: fmt.Sprintf("API key %s cost budget exceeded ($%.2f of $%.2f used)", period, totals.CostUSD, costCap),
		}
	}
	return nil
}

// consume records one request for id at now when the sliding window
// (last 60s) still has room under rpm; reports whether it recorded.
func (l *Limiter) consume(id string, now time.Time, rpm int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-rpmWindow)
	kept := l.hits[id][:0]
	for _, ts := range l.hits[id] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if int64(len(kept)) >= rpm {
		l.hits[id] = kept
		return false
	}
	l.hits[id] = append(kept, now)
	return true
}
