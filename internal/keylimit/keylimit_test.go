package keylimit

import (
	"testing"
	"time"

	"proxygo/internal/chatcore"
	"proxygo/internal/db"
)

const testKey = "sk-test-keylimit-0001"

func openStore(t *testing.T) *db.Store {
	t.Helper()
	s, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("OpenInDir: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// createKey inserts a key record and returns its record id.
func createKey(t *testing.T, s *db.Store) string {
	t.Helper()
	rec, err := s.CreateAPIKeyWithKey("test", "machine-1", testKey)
	if err != nil {
		t.Fatalf("CreateAPIKeyWithKey: %v", err)
	}
	id, _ := rec["id"].(string)
	if id == "" {
		t.Fatal("key record has no id")
	}
	return id
}

func seedUsage(t *testing.T, s *db.Store, ts time.Time, key string, prompt, completion int, cost float64) {
	t.Helper()
	_, err := s.SQL().Exec(
		`INSERT INTO usageHistory(timestamp, provider, model, connectionId, apiKey, endpoint, promptTokens, completionTokens, cost, status, tokens, meta)
		 VALUES(?, 'openai', 'gpt-x', 'c1', ?, '/v1/chat/completions', ?, ?, ?, 'ok', '{}', '{}')`,
		ts.UTC().Format("2006-01-02T15:04:05.000Z"), key, prompt, completion, cost)
	if err != nil {
		t.Fatalf("seed usage: %v", err)
	}
}

func TestRPMSlidingWindow(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	if err := SetLimits(s, id, Limits{RPM: 3}); err != nil {
		t.Fatal(err)
	}
	l := New(s)
	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.Local)
	cur := t0
	l.now = func() time.Time { return cur }

	for i, at := range []time.Duration{0, 10 * time.Second, 20 * time.Second} {
		cur = t0.Add(at)
		if rej := l.Check(testKey); rej != nil {
			t.Fatalf("request %d at +%v rejected: %+v", i+1, at, rej)
		}
	}
	cur = t0.Add(30 * time.Second)
	rej := l.Check(testKey)
	if rej == nil {
		t.Fatal("4th request inside the minute was allowed")
	}
	if rej.Status != chatcore.StatusRateLimited || rej.Type != "rate_limit_exceeded" {
		t.Fatalf("rejection = %+v, want 429 rate_limit_exceeded", rej)
	}
	// Window slides: at +61s the +0s hit has expired, one slot frees up.
	cur = t0.Add(61 * time.Second)
	if rej := l.Check(testKey); rej != nil {
		t.Fatalf("request after window slide rejected: %+v", rej)
	}
	// ...and the window is full again right after.
	cur = t0.Add(62 * time.Second)
	if rej := l.Check(testKey); rej == nil || rej.Type != "rate_limit_exceeded" {
		t.Fatalf("expected rate_limit_exceeded after refill, got %+v", rej)
	}
}

func TestDailyTokenBudget(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	if err := SetLimits(s, id, Limits{DailyTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	l := New(s)
	dayStart := StartOfDay(time.Now())
	// Yesterday's usage must not count toward today's budget.
	seedUsage(t, s, dayStart.Add(-time.Hour), testKey, 4000, 1000, 0)
	// Today: 900 of 1000 tokens → still allowed.
	seedUsage(t, s, dayStart.Add(time.Hour), testKey, 600, 300, 0)
	if rej := l.Check(testKey); rej != nil {
		t.Fatalf("under-budget request rejected: %+v", rej)
	}
	// Today reaches 1100 ≥ 1000 → budget_exceeded.
	seedUsage(t, s, dayStart.Add(2*time.Hour), testKey, 200, 0, 0)
	rej := l.Check(testKey)
	if rej == nil || rej.Type != "budget_exceeded" || rej.Status != chatcore.StatusRateLimited {
		t.Fatalf("rejection = %+v, want 429 budget_exceeded", rej)
	}
}

func TestDailyCostBudget(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	if err := SetLimits(s, id, Limits{DailyCostUSD: 5}); err != nil {
		t.Fatal(err)
	}
	l := New(s)
	dayStart := StartOfDay(time.Now())
	seedUsage(t, s, dayStart.Add(time.Hour), testKey, 10, 10, 3.50)
	if rej := l.Check(testKey); rej != nil {
		t.Fatalf("under-budget request rejected: %+v", rej)
	}
	seedUsage(t, s, dayStart.Add(2*time.Hour), testKey, 10, 10, 2.00)
	if rej := l.Check(testKey); rej == nil || rej.Type != "budget_exceeded" {
		t.Fatalf("rejection = %+v, want budget_exceeded", rej)
	}
}

func TestMonthlyTokenBudget(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	if err := SetLimits(s, id, Limits{MonthlyTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	l := New(s)
	// A row anywhere inside the current month counts (month start + 1h).
	seedUsage(t, s, StartOfMonth(time.Now()).Add(time.Hour), testKey, 1200, 300, 0)
	if rej := l.Check(testKey); rej == nil || rej.Type != "budget_exceeded" {
		t.Fatalf("rejection = %+v, want budget_exceeded", rej)
	}
}

func TestNoLimitsAndUnknownKeysPass(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	l := New(s)
	for i := 0; i < 5; i++ {
		if rej := l.Check(testKey); rej != nil {
			t.Fatalf("key without limits rejected: %+v", rej)
		}
	}
	// Explicitly stored all-zero limits are also unlimited.
	if err := SetLimits(s, id, Limits{}); err != nil {
		t.Fatal(err)
	}
	if rej := l.Check(testKey); rej != nil {
		t.Fatalf("key with zero limits rejected: %+v", rej)
	}
	if rej := l.Check("sk-does-not-exist"); rej != nil {
		t.Fatalf("unknown key rejected: %+v", rej)
	}
	if rej := l.Check(""); rej != nil {
		t.Fatalf("empty key rejected: %+v", rej)
	}
}

func TestBudgetRejectionDoesNotConsumeRPM(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	if err := SetLimits(s, id, Limits{RPM: 1, DailyTokens: 10}); err != nil {
		t.Fatal(err)
	}
	l := New(s)
	seedUsage(t, s, StartOfDay(time.Now()).Add(time.Hour), testKey, 100, 0, 0)
	if rej := l.Check(testKey); rej == nil || rej.Type != "budget_exceeded" {
		t.Fatalf("rejection = %+v, want budget_exceeded", rej)
	}
	// Lift the budget: the single RPM slot must still be free, proving
	// the budget-rejected request never consumed it.
	if err := SetLimits(s, id, Limits{RPM: 1}); err != nil {
		t.Fatal(err)
	}
	if rej := l.Check(testKey); rej != nil {
		t.Fatalf("first RPM request rejected: %+v", rej)
	}
	if rej := l.Check(testKey); rej == nil || rej.Type != "rate_limit_exceeded" {
		t.Fatalf("rejection = %+v, want rate_limit_exceeded", rej)
	}
}

func TestLimitsCRUD(t *testing.T) {
	s := openStore(t)
	id := createKey(t, s)
	got, err := GetLimits(s, id)
	if err != nil || got != (Limits{}) {
		t.Fatalf("initial limits = %+v, %v", got, err)
	}
	want := Limits{RPM: 60, DailyTokens: 100000, MonthlyTokens: 2000000, DailyCostUSD: 12.5, MonthlyCostUSD: 250}
	if err := SetLimits(s, id, want); err != nil {
		t.Fatal(err)
	}
	got, err = GetLimits(s, id)
	if err != nil || got != want {
		t.Fatalf("limits = %+v, %v; want %+v", got, err, want)
	}
	if err := DeleteLimits(s, id); err != nil {
		t.Fatal(err)
	}
	got, err = GetLimits(s, id)
	if err != nil || got != (Limits{}) {
		t.Fatalf("limits after delete = %+v, %v", got, err)
	}
}
