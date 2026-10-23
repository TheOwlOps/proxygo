package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxygo/internal/chatcore"
	"proxygo/internal/db"
)

// ---------- schedule (quotaPingSchedule.js) ----------

func TestNormalizePingSchedule(t *testing.T) {
	if normalizePingSchedule(nil) != nil {
		t.Error("nil raw should give nil schedule")
	}
	if normalizePingSchedule(map[string]any{"enabled": false}) != nil {
		t.Error("disabled schedule should be nil")
	}
	s := normalizePingSchedule(map[string]any{"enabled": true})
	if s == nil {
		t.Fatal("enabled schedule should normalize")
	}
	if s.anchor != "09:30" || s.windowHours != 5 || s.slotsPerDay != 3 {
		t.Errorf("defaults = anchor %q window %v slots %d, want 09:30/5/3", s.anchor, s.windowHours, s.slotsPerDay)
	}
	// slotsPerDay clamps to floor(24/windowHours): window 5 -> max 4.
	s = normalizePingSchedule(map[string]any{"enabled": true, "windowHours": 5.0, "slotsPerDay": 9.0})
	if s.slotsPerDay != 4 {
		t.Errorf("slotsPerDay = %d, want clamped 4", s.slotsPerDay)
	}
	// Invalid anchor falls back to the default anchor.
	s = normalizePingSchedule(map[string]any{"enabled": true, "anchor": "25:99"})
	if s.anchor != "09:30" {
		t.Errorf("anchor = %q, want fallback 09:30", s.anchor)
	}
	// Invalid timezone falls back to local.
	s = normalizePingSchedule(map[string]any{"enabled": true, "timezone": "Not/AZone"})
	if s == nil || s.loc == nil {
		t.Error("invalid timezone should fall back to local, not nil")
	}
}

func TestDuePingSlot(t *testing.T) {
	now := time.Now()
	anchorNow := now.Format("15:04")
	s := normalizePingSchedule(map[string]any{
		"enabled": true, "anchor": anchorNow, "windowHours": 5.0, "slotsPerDay": 1.0,
	})
	if s == nil {
		t.Fatal("schedule should normalize")
	}
	due := duePingSlot(s, now)
	if due == nil {
		t.Fatal("slot anchored at the current minute should be due")
	}
	if due.index != 0 || !strings.HasSuffix(due.key, "#0") {
		t.Errorf("due slot = %+v", due)
	}
	if !strings.HasPrefix(due.key, now.Format("2006-01-02")) {
		t.Errorf("slot key %q should start with today's date", due.key)
	}

	// A slot 3h ago is outside the 30min grace window.
	old := normalizePingSchedule(map[string]any{
		"enabled": true, "anchor": now.Add(-3 * time.Hour).Format("15:04"), "windowHours": 5.0, "slotsPerDay": 1.0,
	})
	if due := duePingSlot(old, now); due != nil {
		t.Errorf("stale slot should not be due, got %+v", due)
	}
}

// ---------- ping decision logic (quotaAutoPing.js pingConnection) ----------

type fakeAutoPing struct {
	usageRecord db.Record
	usageErr    error
	pings       int
	updates     []db.Record
}

func (f *fakeAutoPing) deps() autoPingDeps {
	return autoPingDeps{
		refresh: func(ctx context.Context, conn db.Record) (db.Record, error) { return conn, nil },
		usage: func(ctx context.Context, conn db.Record) (db.Record, error) {
			return f.usageRecord, f.usageErr
		},
		sendPing: func(ctx context.Context, conn db.Record, cfg autoPingProviderCfg) bool {
			f.pings++
			return true
		},
		update: func(id string, fields db.Record) error {
			f.updates = append(f.updates, fields)
			return nil
		},
	}
}

func claudeCfg() autoPingProviderCfg { return autoPingProviders[0] }
func codexCfg() autoPingProviderCfg  { return autoPingProviders[1] }

func TestPingConnectionClaudeReactiveReset(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	f := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session (5h)": db.Record{"used": 10.0, "total": 100.0, "remaining": 90.0, "resetAt": apISO(past)},
	}}}
	state := newAutoPingState()
	conn := db.Record{"id": "c1", "provider": "claude", "authType": "oauth", "accessToken": "tok"}
	if err := pingConnection(context.Background(), f.deps(), state, conn, claudeCfg(), nil, true); err != nil {
		t.Fatalf("pingConnection: %v", err)
	}
	if f.pings != 1 {
		t.Fatalf("pings = %d, want 1 (reset just passed)", f.pings)
	}
	if len(f.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(f.updates))
	}
	wantKey := apNormalizeResetKey(apISO(past))
	if f.updates[0]["lastPingedResetKey"] != wantKey {
		t.Errorf("lastPingedResetKey = %v, want %v", f.updates[0]["lastPingedResetKey"], wantKey)
	}
	if f.updates[0]["lastPingAt"] == nil || f.updates[0]["lastPingAt"] == "" {
		t.Error("lastPingAt not recorded")
	}

	// Same reset again (connection now carries lastPingedResetKey): no ping.
	conn["lastPingedResetKey"] = wantKey
	if err := pingConnection(context.Background(), f.deps(), state, conn, claudeCfg(), nil, true); err != nil {
		t.Fatalf("pingConnection 2: %v", err)
	}
	if f.pings != 1 {
		t.Errorf("pings = %d, want still 1 for already-pinged reset", f.pings)
	}
}

func TestPingConnectionClaudeFutureResetAndExhausted(t *testing.T) {
	future := apISO(time.Now().Add(2 * time.Hour))
	f := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session (5h)": db.Record{"used": 10.0, "total": 100.0, "remaining": 90.0, "resetAt": future},
	}}}
	conn := db.Record{"id": "c1", "provider": "claude", "authType": "oauth", "accessToken": "tok"}
	if err := pingConnection(context.Background(), f.deps(), newAutoPingState(), conn, claudeCfg(), nil, true); err != nil {
		t.Fatal(err)
	}
	if f.pings != 0 {
		t.Errorf("pings = %d, want 0 (reset 2h away)", f.pings)
	}

	f2 := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session (5h)": db.Record{"used": 100.0, "total": 100.0, "remaining": 0.0, "resetAt": apISO(time.Now().Add(-time.Minute))},
	}}}
	if err := pingConnection(context.Background(), f2.deps(), newAutoPingState(), conn, claudeCfg(), nil, true); err != nil {
		t.Fatal(err)
	}
	if f2.pings != 0 {
		t.Errorf("pings = %d, want 0 (quota exhausted)", f2.pings)
	}
}

func TestPingConnectionCodexResetSlides(t *testing.T) {
	base := time.Now().Add(-time.Hour)
	conn := db.Record{"id": "c2", "provider": "codex", "authType": "oauth", "accessToken": "tok"}

	// Drift >= 30s against the cached reset -> ping.
	f := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session": db.Record{"used": 1.0, "total": 100.0, "remaining": 99.0, "resetAt": apISO(base.Add(31 * time.Second))},
	}}}
	state := newAutoPingState()
	state.setReset("codex:c2", apISO(base))
	if err := pingConnection(context.Background(), f.deps(), state, conn, codexCfg(), nil, true); err != nil {
		t.Fatal(err)
	}
	if f.pings != 1 {
		t.Errorf("pings = %d, want 1 (reset slid 31s)", f.pings)
	}

	// Drift < 30s -> no ping.
	f2 := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session": db.Record{"used": 1.0, "total": 100.0, "remaining": 99.0, "resetAt": apISO(base.Add(10 * time.Second))},
	}}}
	state2 := newAutoPingState()
	state2.setReset("codex:c2", apISO(base))
	if err := pingConnection(context.Background(), f2.deps(), state2, conn, codexCfg(), nil, true); err != nil {
		t.Fatal(err)
	}
	if f2.pings != 0 {
		t.Errorf("pings = %d, want 0 (drift only 10s)", f2.pings)
	}

	// A blocking (non-session) quota exhausted -> skip even with drift.
	f3 := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session": db.Record{"used": 1.0, "total": 100.0, "remaining": 99.0, "resetAt": apISO(base.Add(31 * time.Second))},
		"weekly":  db.Record{"used": 100.0, "total": 100.0, "remaining": 0.0},
	}}}
	state3 := newAutoPingState()
	state3.setReset("codex:c2", apISO(base))
	if err := pingConnection(context.Background(), f3.deps(), state3, conn, codexCfg(), nil, true); err != nil {
		t.Fatal(err)
	}
	if f3.pings != 0 {
		t.Errorf("pings = %d, want 0 (blocking quota exhausted)", f3.pings)
	}
}

func TestPingConnectionScheduleSlot(t *testing.T) {
	now := time.Now()
	schedule := normalizePingSchedule(map[string]any{
		"enabled": true, "anchor": now.Format("15:04"), "windowHours": 5.0, "slotsPerDay": 1.0,
	})
	f := &fakeAutoPing{usageRecord: db.Record{"quotas": db.Record{
		"session (5h)": db.Record{"used": 10.0, "total": 100.0, "remaining": 90.0, "resetAt": apISO(now.Add(2 * time.Hour))},
	}}}
	conn := db.Record{"id": "c1", "provider": "claude", "authType": "oauth", "accessToken": "tok"}
	// Reactive off, but the anchored slot is due -> schedule path pings.
	if err := pingConnection(context.Background(), f.deps(), newAutoPingState(), conn, claudeCfg(), schedule, false); err != nil {
		t.Fatal(err)
	}
	if f.pings != 1 {
		t.Fatalf("pings = %d, want 1 (due slot)", f.pings)
	}
	if len(f.updates) != 1 || f.updates[0]["lastPingedSlotKey"] == nil || f.updates[0]["lastPingedSlotKey"] == "" {
		t.Fatalf("update should record lastPingedSlotKey, got %v", f.updates)
	}
	// Second run with the slot already pinged: no ping.
	conn["lastPingedSlotKey"] = f.updates[0]["lastPingedSlotKey"]
	if err := pingConnection(context.Background(), f.deps(), newAutoPingState(), conn, claudeCfg(), schedule, false); err != nil {
		t.Fatal(err)
	}
	if f.pings != 1 {
		t.Errorf("pings = %d, want still 1 (slot already pinged)", f.pings)
	}
}

// ---------- configure / scheduler lifecycle ----------

func TestConfigureQuotaAutoPingStartStop(t *testing.T) {
	e := newTestEnv(t)
	defer stopQuotaAutoPing()
	deps := Deps{Store: e.store}

	if hasAnyAutoPingEnabled(map[string]any{}) {
		t.Error("empty settings should not enable AutoPing")
	}
	ghost := map[string]any{"claudeAutoPing": map[string]any{
		"connections": map[string]any{"ghost-conn": true},
	}}
	if !hasAnyAutoPingEnabled(ghost) {
		t.Fatal("opted-in connection should enable AutoPing")
	}
	configureQuotaAutoPing(deps, ghost)
	if !autoPingSchedulerRunning() {
		t.Error("scheduler should be running after configure with opt-in")
	}
	configureQuotaAutoPing(deps, map[string]any{})
	if autoPingSchedulerRunning() {
		t.Error("scheduler should stop after configure with nothing enabled")
	}
	// A lone enabled schedule also starts it.
	withSchedule := map[string]any{"codexAutoPing": map[string]any{
		"schedules": map[string]any{"c9": map[string]any{"enabled": true}},
	}}
	configureQuotaAutoPing(deps, withSchedule)
	if !autoPingSchedulerRunning() {
		t.Error("scheduler should run for a lone enabled schedule")
	}
	configureQuotaAutoPing(deps, map[string]any{})
	if autoPingSchedulerRunning() {
		t.Error("scheduler should stop again")
	}
}

// ---------- settings PATCH side effects (wiring) ----------

func comboHead(t *testing.T, svc *chatcore.Service, models []string, name string) string {
	t.Helper()
	first := ""
	resp := svc.HandleCombo(context.Background(), chatcore.ChatRequest{}, models, name, "round-robin", 1,
		func(ctx context.Context, req chatcore.ChatRequest, modelStr string) *http.Response {
			if first == "" {
				first = modelStr
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}
		})
	if resp == nil {
		t.Fatal("HandleCombo returned nil")
	}
	return first
}

func TestSettingsPatchSideEffects(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	t.Setenv("INITIAL_PASSWORD", "")
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	svc := chatcore.NewService(chatcore.Service{})
	mux := http.NewServeMux()
	RegisterAuth(mux, Deps{Store: store, Chat: svc})
	defer stopQuotaAutoPing()

	do := func(method, path, body, cookie string) *httptest.ResponseRecorder {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:4321"
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	// Login (default password).
	lrec := do("POST", "/api/auth/login", `{"password":"123456"}`, "")
	if lrec.Code != 200 {
		t.Fatalf("login %d: %s", lrec.Code, lrec.Body.String())
	}
	cookie := ""
	for _, c := range lrec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, "auth_token=") {
			cookie = strings.Split(c, ";")[0]
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie")
	}

	models := []string{"a/m1", "b/m2", "c/m3"}
	if got := comboHead(t, svc, models, "combo-x"); got != "a/m1" {
		t.Fatalf("head 1 = %q, want a/m1", got)
	}
	// Unrelated PATCH: rotation must NOT reset.
	if rec := do("PATCH", "/api/settings", `{"someUnrelatedKey":true}`, cookie); rec.Code != 200 {
		t.Fatalf("patch unrelated %d: %s", rec.Code, rec.Body.String())
	}
	if got := comboHead(t, svc, models, "combo-x"); got != "b/m2" {
		t.Fatalf("head 2 = %q, want b/m2 (no reset on unrelated key)", got)
	}
	// comboStrategy PATCH: rotation resets (all combos).
	if rec := do("PATCH", "/api/settings", `{"comboStrategy":"round-robin"}`, cookie); rec.Code != 200 {
		t.Fatalf("patch comboStrategy %d: %s", rec.Code, rec.Body.String())
	}
	if got := comboHead(t, svc, models, "combo-x"); got != "a/m1" {
		t.Fatalf("head 3 = %q, want a/m1 (rotation reset by settings)", got)
	}
	// comboStickyRoundRobinLimit also resets.
	_ = comboHead(t, svc, models, "combo-x") // advance to b/m2 next
	if rec := do("PATCH", "/api/settings", `{"comboStickyRoundRobinLimit":3}`, cookie); rec.Code != 200 {
		t.Fatalf("patch sticky %d: %s", rec.Code, rec.Body.String())
	}
	if got := comboHead(t, svc, models, "combo-x"); got != "a/m1" {
		t.Fatalf("head after sticky patch = %q, want a/m1", got)
	}

	// AutoPing reconfigure via PATCH: opt-in starts, clearing stops.
	if rec := do("PATCH", "/api/settings", `{"claudeAutoPing":{"connections":{"ghost":true}}}`, cookie); rec.Code != 200 {
		t.Fatalf("patch autoping %d: %s", rec.Code, rec.Body.String())
	}
	if !autoPingSchedulerRunning() {
		t.Error("scheduler should start after claudeAutoPing PATCH")
	}
	if rec := do("PATCH", "/api/settings", `{"claudeAutoPing":{"connections":{}}}`, cookie); rec.Code != 200 {
		t.Fatalf("patch autoping clear %d: %s", rec.Code, rec.Body.String())
	}
	if autoPingSchedulerRunning() {
		t.Error("scheduler should stop after claudeAutoPing cleared")
	}
}
