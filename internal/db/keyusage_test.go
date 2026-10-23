package db

import (
	"testing"
	"time"
)

func seedUsageRow(t *testing.T, s *Store, ts time.Time, apiKey string, prompt, completion int, cost float64) {
	t.Helper()
	_, err := s.SQL().Exec(
		`INSERT INTO usageHistory(timestamp, provider, model, connectionId, apiKey, endpoint, promptTokens, completionTokens, cost, status, tokens, meta)
		 VALUES(?, 'openai', 'gpt-x', 'c1', ?, '/v1/chat/completions', ?, ?, ?, 'ok', '{}', '{}')`,
		isoOf(ts), apiKey, prompt, completion, cost)
	if err != nil {
		t.Fatalf("seed usage row: %v", err)
	}
}

func TestGetKeyUsageTotals(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	since := now.Add(-time.Hour)

	seedUsageRow(t, s, now.Add(-30*time.Minute), "sk-aaa", 100, 50, 1.25)
	seedUsageRow(t, s, now.Add(-10*time.Minute), "sk-aaa", 200, 100, 2.75)
	seedUsageRow(t, s, now.Add(-2*time.Hour), "sk-aaa", 999, 999, 99) // before window
	seedUsageRow(t, s, now.Add(-5*time.Minute), "sk-bbb", 7, 3, 0.5)  // other key

	got, err := s.GetKeyUsageTotals("sk-aaa", since)
	if err != nil {
		t.Fatal(err)
	}
	if got.Requests != 2 || got.PromptTokens != 300 || got.CompletionTokens != 150 ||
		got.TotalTokens != 450 || got.CostUSD != 4.0 {
		t.Fatalf("totals = %+v, want {2 300 150 450 4}", got)
	}

	empty, err := s.GetKeyUsageTotals("", since)
	if err != nil || empty != (KeyUsageTotals{}) {
		t.Fatalf("empty key totals = %+v, %v", empty, err)
	}
	none, err := s.GetKeyUsageTotals("sk-missing", since)
	if err != nil || none != (KeyUsageTotals{}) {
		t.Fatalf("missing key totals = %+v, %v", none, err)
	}
}
