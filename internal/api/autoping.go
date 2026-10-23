package api

// Quota AutoPing scheduler — port of src/shared/services/quotaAutoPing.js
// + src/shared/services/quotaPingSchedule.js.
//
// Warms providers' 5h quota windows by sending a tiny opt-in request
// right after a window reset (reactive path) or at fixed wall-clock
// slots (anchored schedules). Settings contract (unchanged from the JS):
// settings.claudeAutoPing / settings.codexAutoPing =
// { connections: {connId: true}, schedules: {connId: schedule} }.
//
// The JS service is a process-wide singleton fed by configure/start
// calls from the settings route and app init; mirrored here: RegisterAuth
// configures from persisted settings, PATCH /api/settings reconfigures
// when claudeAutoPing/codexAutoPing keys are present.
//
// Deliberate divergences from the JS (infrastructure the Go port lacks):
//   - Per-connection proxy options (connectionProxy/vercel relay) are NOT
//     applied to usage/ping calls — the default HTTP transport (env
//     proxy) is used, the same limitation the usage fetchers document.
//   - The Codex ping goes straight to the Codex responses endpoint with
//     the registry's CLI headers instead of through the executor graph
//     (the api layer has no executor handle); the wire request matches
//     what the JS executor sends, including the full stream drain —
//     Codex only starts the 5h window once the stream completes.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"9router-go/internal/db"
	"9router-go/internal/providers"
)

// QUOTA_AUTOPING_CONFIG (src/shared/constants/config.js).
const (
	autoPingTickInterval  = 60 * time.Second  // tickIntervalMs
	autoPingLead          = 5 * time.Second   // pingLeadMs
	autoPingRefreshAhead  = 300 * time.Second // refreshAheadMs
	autoPingFailureCool   = 900 * time.Second // failureCooldownMs
	autoPingSlotGrace     = 30 * time.Minute  // SLOT_GRACE_MS
	autoPingClaudePingURL = "https://api.anthropic.com/v1/messages?beta=true"
	autoPingCodexPingURL  = "https://chatgpt.com/backend-api/codex/responses"
)

type autoPingProviderCfg struct {
	provider                     string
	settingsKey                  string
	quotaKey                     string
	pingModel                    string
	pingText                     string
	pingMaxTokens                int
	pingWhenResetAtSlides        bool
	resetAtDriftMs               int64
	minPingIntervalMs            int64
	skipWhenBlockingQuotaExhaust bool
	pingInstructions             string
	pingReasoningEffort          string
}

var autoPingProviders = []autoPingProviderCfg{
	{
		provider: "claude", settingsKey: "claudeAutoPing", quotaKey: "session (5h)",
		pingModel: "claude-haiku-4-5-20251001", pingText: "hi", pingMaxTokens: 1,
	},
	{
		provider: "codex", settingsKey: "codexAutoPing", quotaKey: "session",
		pingModel: "gpt-5.6-terra", pingText: "hi",
		pingWhenResetAtSlides: true, resetAtDriftMs: 30000, minPingIntervalMs: 600000,
		skipWhenBlockingQuotaExhaust: true,
		pingInstructions:             "Reply with OK.", pingReasoningEffort: "none",
	},
}

// ---------- small value helpers (JS toFiniteNumber / field access) ----------

func apChild(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func apStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func apNum(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		if strings.TrimSpace(n) != "" {
			if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

func apParseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func apISO(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// normalizeResetKey ports quotaAutoPing.js normalizeResetKey: floor to
// the minute, JS-ISO format; unparseable input passes through unchanged.
func apNormalizeResetKey(resetAt string) string {
	t, ok := apParseTime(resetAt)
	if !ok {
		return resetAt
	}
	return apISO(t.Truncate(time.Minute))
}

func apResetDriftMs(prev, next string) int64 {
	p, ok1 := apParseTime(prev)
	n, ok2 := apParseTime(next)
	if !ok1 || !ok2 {
		return 0
	}
	return n.Sub(p).Milliseconds()
}

// isQuotaExhausted ports the JS helper over the Go usage-record shape
// ({used, total, remaining, unlimited}).
func apIsQuotaExhausted(quota map[string]any) bool {
	if quota == nil {
		return false
	}
	if u, _ := quota["unlimited"].(bool); u {
		return false
	}
	if rem, ok := apNum(quota["remaining"]); ok {
		return rem <= 0
	}
	used, okU := apNum(quota["used"])
	total, okT := apNum(quota["total"])
	return okT && total > 0 && okU && used >= total
}

func apIsBlockingQuotaName(name, sessionKey string) bool {
	if name == sessionKey {
		return false
	}
	return !strings.Contains(strings.ToLower(name), "session")
}

func apHasExhaustedBlockingQuota(quotas map[string]any, sessionKey string) bool {
	for name, raw := range quotas {
		if apIsBlockingQuotaName(name, sessionKey) && apIsQuotaExhausted(apChild(quotas, name)) {
			_ = raw
			return true
		}
	}
	return false
}

func apWasPingedRecently(conn map[string]any, intervalMs int64, now time.Time) bool {
	if intervalMs == 0 {
		return false
	}
	last, ok := apParseTime(apStr(conn, "lastPingAt"))
	return ok && now.Sub(last) < time.Duration(intervalMs)*time.Millisecond
}

func apShouldPingForReset(cfg autoPingProviderCfg, cachedReset, resetAt string, now time.Time) bool {
	if cfg.pingWhenResetAtSlides {
		return cachedReset != "" && apResetDriftMs(cachedReset, resetAt) >= cfg.resetAtDriftMs
	}
	rt, ok := apParseTime(resetAt)
	return ok && !now.Before(rt.Add(-autoPingLead))
}

// ---------- anchored ping schedule (quotaPingSchedule.js) ----------

type pingSchedule struct {
	anchor      string // "HH:MM"
	timezone    string
	loc         *time.Location
	windowHours float64
	slotsPerDay int
}

type pingSlot struct {
	key   string
	index int
	at    time.Time
}

var apAnchorRe = regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)

func apParseAnchor(s string) (int, int, bool) {
	m := apAnchorRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, false
	}
	h, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	if h > 23 || min > 59 {
		return 0, 0, false
	}
	return h, min, true
}

func apClampNum(v any, fallback, min, max float64) float64 {
	n, ok := apNum(v)
	if !ok {
		n = fallback
	}
	return math.Min(max, math.Max(min, n))
}

// normalizePingSchedule ports normalizePingSchedule: a fully-defaulted
// schedule, or nil when absent/disabled/invalid.
func normalizePingSchedule(raw any) *pingSchedule {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	if en, _ := m["enabled"].(bool); !en {
		return nil
	}
	ah, am, ok := apParseAnchor(apStr(m, "anchor"))
	if !ok {
		ah, am, _ = apParseAnchor("09:30")
	}
	loc := time.Local
	tzName := apStr(m, "timezone")
	if tzName != "" {
		if l, err := time.LoadLocation(tzName); err == nil {
			loc = l
		} else {
			tzName = ""
		}
	}
	if tzName == "" {
		tzName = loc.String()
	}
	windowHours := apClampNum(m["windowHours"], 5, 0.5, 24)
	maxSlots := int(math.Max(1, math.Floor(24/windowHours)))
	slots := int(math.Round(apClampNum(m["slotsPerDay"], 3, 1, float64(maxSlots))))
	return &pingSchedule{
		anchor:      fmt.Sprintf("%02d:%02d", ah, am),
		timezone:    tzName,
		loc:         loc,
		windowHours: windowHours,
		slotsPerDay: slots,
	}
}

func (s *pingSchedule) slotsForAnchorDay(instant time.Time) []pingSlot {
	ah, am, _ := apParseAnchor(s.anchor)
	p := instant.In(s.loc)
	first := time.Date(p.Year(), p.Month(), p.Day(), ah, am, 0, 0, s.loc)
	date := first.Format("2006-01-02")
	out := make([]pingSlot, 0, s.slotsPerDay)
	for i := 0; i < s.slotsPerDay; i++ {
		at := first.Add(time.Duration(float64(i) * s.windowHours * float64(time.Hour)))
		out = append(out, pingSlot{key: date + "#" + strconv.Itoa(i), index: i, at: at})
	}
	return out
}

// scheduleSlots ports getScheduleSlots (yesterday + today + tomorrow).
func scheduleSlots(s *pingSchedule, now time.Time) []pingSlot {
	out := []pingSlot{}
	out = append(out, s.slotsForAnchorDay(now.Add(-24*time.Hour))...)
	out = append(out, s.slotsForAnchorDay(now)...)
	out = append(out, s.slotsForAnchorDay(now.Add(24*time.Hour))...)
	sort.Slice(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

// duePingSlot ports getDuePingSlot: the most recent slot that is due and
// still inside the grace window, or nil.
func duePingSlot(s *pingSchedule, now time.Time) *pingSlot {
	var due *pingSlot
	for _, slot := range scheduleSlots(s, now) {
		slot := slot
		if !slot.at.After(now) && now.Sub(slot.at) <= autoPingSlotGrace {
			due = &slot
		}
	}
	return due
}

// ---------- scheduler state + injectable deps (JS createDefaultDeps) ----------

type autoPingState struct {
	mu           sync.Mutex
	running      bool
	resetCache   map[string]string
	failureCache map[string]time.Time
}

func newAutoPingState() *autoPingState {
	return &autoPingState{resetCache: map[string]string{}, failureCache: map[string]time.Time{}}
}

func (s *autoPingState) cachedReset(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resetCache[key]
}

func (s *autoPingState) setReset(key, resetAt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetCache[key] = resetAt
}

func (s *autoPingState) failedRecently(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	failedAt, ok := s.failureCache[key]
	return ok && now.Sub(failedAt) < autoPingFailureCool
}

func (s *autoPingState) setFailure(key string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failureCache[key] = at
}

func (s *autoPingState) clearFailure(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failureCache, key)
}

type autoPingDeps struct {
	settings    func() (map[string]any, error)
	connections func(provider string) ([]db.Record, error)
	refresh     func(ctx context.Context, conn db.Record) (db.Record, error)
	usage       func(ctx context.Context, conn db.Record) (db.Record, error)
	sendPing    func(ctx context.Context, conn db.Record, cfg autoPingProviderCfg) bool
	update      func(id string, fields db.Record) error
}

func realAutoPingDeps(deps Deps) autoPingDeps {
	return autoPingDeps{
		settings: func() (map[string]any, error) {
			s, err := deps.Store.GetSettings()
			if err != nil {
				return nil, err
			}
			return map[string]any(s), nil
		},
		connections: func(provider string) ([]db.Record, error) {
			active := true
			return deps.Store.GetProviderConnections(db.ConnectionFilter{Provider: provider, IsActive: &active})
		},
		refresh: func(ctx context.Context, conn db.Record) (db.Record, error) {
			return opRefreshConnection(ctx, deps, conn, false)
		},
		usage: func(ctx context.Context, conn db.Record) (db.Record, error) {
			return opFetchUsageForProvider(ctx, conn, false)
		},
		sendPing: func(ctx context.Context, conn db.Record, cfg autoPingProviderCfg) bool {
			switch cfg.provider {
			case "claude":
				return autoPingSendClaude(ctx, conn, cfg)
			case "codex":
				return autoPingSendCodex(ctx, conn, cfg)
			}
			return false
		},
		update: func(id string, fields db.Record) error {
			_, err := deps.Store.UpdateProviderConnection(id, fields)
			return err
		},
	}
}

// pingConnection ports quotaAutoPing.js pingConnection for one
// connection. Errors from the usage fetch propagate (the tick records a
// failure, like the JS per-connection catch).
func pingConnection(ctx context.Context, d autoPingDeps, state *autoPingState, conn db.Record, cfg autoPingProviderCfg, schedule *pingSchedule, reactive bool) error {
	key := cfg.provider + ":" + apStr(conn, "id")

	// resetAt is stable for time-based windows; Codex polls every tick
	// because inactive windows slide forward.
	cachedReset := state.cachedReset(key)
	if schedule == nil && !cfg.pingWhenResetAtSlides && cachedReset != "" {
		if rt, ok := apParseTime(cachedReset); ok && time.Now().Before(rt.Add(-autoPingRefreshAhead)) {
			return nil
		}
	}

	// Avoid hammering provider auth/quota endpoints after a recent failure.
	if state.failedRecently(key, time.Now()) {
		return nil
	}

	connection := conn
	refreshed, err := d.refresh(ctx, connection)
	if err != nil {
		state.setFailure(key, time.Now())
		log.Printf("[AutoPing] %s: refresh failed: %v", key, err)
		return nil
	}
	connection = refreshed

	usage, err := d.usage(ctx, connection)
	if err != nil {
		return err
	}
	quotas := apChild(usage, "quotas")
	quota := apChild(quotas, cfg.quotaKey)
	resetAt := apStr(quota, "resetAt")
	if resetAt != "" {
		state.setReset(key, resetAt)
	}

	if cfg.skipWhenBlockingQuotaExhaust && apHasExhaustedBlockingQuota(quotas, cfg.quotaKey) {
		return nil
	}
	if apIsQuotaExhausted(quota) {
		return nil
	}

	now := time.Now()
	resetKey := ""
	if resetAt != "" {
		resetKey = apNormalizeResetKey(resetAt)
	}

	// Anchored schedule runs alongside the reactive path.
	var due *pingSlot
	if schedule != nil {
		due = duePingSlot(schedule, now)
	}
	slotPending := due != nil && apStr(connection, "lastPingedSlotKey") != due.key

	if slotPending {
		if apWasPingedRecently(connection, cfg.minPingIntervalMs, now) {
			return nil
		}
	} else {
		if !reactive || resetAt == "" {
			return nil
		}
		lastPingedResetKey := apStr(connection, "lastPingedResetKey")
		if lastPingedResetKey == "" {
			if lp := apStr(connection, "lastPingedResetAt"); lp != "" {
				lastPingedResetKey = apNormalizeResetKey(lp)
			}
		}
		if !apShouldPingForReset(cfg, cachedReset, resetAt, now) {
			return nil
		}
		if apWasPingedRecently(connection, cfg.minPingIntervalMs, now) {
			return nil
		}
		if lastPingedResetKey != "" && lastPingedResetKey == resetKey {
			return nil
		}
	}

	if !d.sendPing(ctx, connection, cfg) {
		// Do not mark reset/slot as pinged unless upstream accepted.
		state.setFailure(key, time.Now())
		log.Printf("[AutoPing] %s: ping failed", key)
		return nil
	}

	state.clearFailure(key)
	pingedAt := apISO(now)
	fields := db.Record{"lastPingAt": pingedAt, "updatedAt": pingedAt}
	if resetAt != "" {
		fields["lastPingedResetAt"] = resetAt
		fields["lastPingedResetKey"] = resetKey
	}
	if slotPending {
		fields["lastPingedSlotKey"] = due.key
	}
	_ = d.update(apStr(connection, "id"), fields)
	log.Printf("[AutoPing] %s: ping sent", key)
	return nil
}

// runAutoPingTick ports runQuotaAutoPingTick.
func runAutoPingTick(ctx context.Context, d autoPingDeps, state *autoPingState) {
	state.mu.Lock()
	if state.running {
		state.mu.Unlock()
		return
	}
	state.running = true
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.running = false
		state.mu.Unlock()
	}()

	settings, err := d.settings()
	if err != nil {
		log.Printf("[AutoPing] tick error: %v", err)
		return
	}
	for _, cfg := range autoPingProviders {
		section := apChild(settings, cfg.settingsKey)
		enabledMap := apChild(section, "connections")
		scheduleMap := apChild(section, "schedules")
		if len(enabledMap) == 0 && len(scheduleMap) == 0 {
			continue
		}
		conns, err := d.connections(cfg.provider)
		if err != nil {
			continue
		}
		for _, conn := range conns {
			if apStr(conn, "authType") != "oauth" {
				continue
			}
			id := apStr(conn, "id")
			var schedule *pingSchedule
			if raw, ok := scheduleMap[id]; ok {
				schedule = normalizePingSchedule(raw)
			}
			reactive := false
			if v, ok := enabledMap[id].(bool); ok && v {
				reactive = true
			}
			if !reactive && schedule == nil {
				continue
			}
			if err := pingConnection(ctx, d, state, conn, cfg, schedule, reactive); err != nil {
				state.setFailure(cfg.provider+":"+id, time.Now())
				log.Printf("[AutoPing] %s:%s: %v", cfg.provider, id, err)
			}
		}
	}
}

// ---------- process-wide scheduler (JS global.__quotaAutoPing) ----------

var autoPingSched = struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	state  *autoPingState
}{state: newAutoPingState()}

// hasAnyAutoPingEnabled ports hasAnyAutoPingEnabled: an opted-in account
// or a single enabled schedule is enough to need the scheduler.
func hasAnyAutoPingEnabled(settings map[string]any) bool {
	for _, cfg := range autoPingProviders {
		section := apChild(settings, cfg.settingsKey)
		for _, v := range apChild(section, "connections") {
			if b, ok := v.(bool); ok && b {
				return true
			}
		}
		for _, raw := range apChild(section, "schedules") {
			if normalizePingSchedule(raw) != nil {
				return true
			}
		}
	}
	return false
}

func startQuotaAutoPing(deps Deps) {
	autoPingSched.mu.Lock()
	if autoPingSched.cancel != nil {
		autoPingSched.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	autoPingSched.cancel = cancel
	state := autoPingSched.state
	autoPingSched.mu.Unlock()

	log.Printf("[AutoPing] scheduler started")
	d := realAutoPingDeps(deps)
	go func() {
		runAutoPingTick(ctx, d, state)
		ticker := time.NewTicker(autoPingTickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAutoPingTick(ctx, d, state)
			}
		}
	}()
}

func stopQuotaAutoPing() {
	autoPingSched.mu.Lock()
	cancel := autoPingSched.cancel
	autoPingSched.cancel = nil
	autoPingSched.mu.Unlock()
	if cancel != nil {
		cancel()
		log.Printf("[AutoPing] scheduler stopped")
	}
}

func autoPingSchedulerRunning() bool {
	autoPingSched.mu.Lock()
	defer autoPingSched.mu.Unlock()
	return autoPingSched.cancel != nil
}

// configureQuotaAutoPing ports configureQuotaAutoPing: start the
// scheduler when any account opted in (or has a schedule), else stop it.
func configureQuotaAutoPing(deps Deps, settings map[string]any) {
	if hasAnyAutoPingEnabled(settings) {
		startQuotaAutoPing(deps)
	} else {
		stopQuotaAutoPing()
	}
}

// ---------- ping senders ----------

// autoPingHTTPDo is the transport seam (JS proxyAwareFetch — see the
// proxy divergence note at the top of this file).
var autoPingHTTPDo = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

func apStainlessArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	}
	return runtime.GOARCH
}

func apStainlessOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "MacOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return runtime.GOOS
}

// claudeSpoofHeaders mirrors CLAUDE_CLI_SPOOF_HEADERS
// (open-sse/providers/shared.js; version constants match the JS:
// ANTHROPIC_API_VERSION 2023-06-01, CLAUDE_CLI_VERSION 2.1.280).
func claudeSpoofHeaders() map[string]string {
	return map[string]string{
		"Anthropic-Version":                         opAnthropicAPIVersion,
		"Anthropic-Beta":                            "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20,effort-2025-11-24,structured-outputs-2025-12-15,fast-mode-2026-02-01,redact-thinking-2026-02-12,token-efficient-tools-2026-03-28",
		"Anthropic-Dangerous-Direct-Browser-Access": "true",
		"User-Agent":                                "claude-cli/2.1.280 (external, sdk-cli)",
		"X-App":                                     "cli",
		"X-Stainless-Helper-Method":                 "stream",
		"X-Stainless-Retry-Count":                   "0",
		"X-Stainless-Runtime-Version":               "v24.14.0",
		"X-Stainless-Package-Version":               "0.80.0",
		"X-Stainless-Runtime":                       "node",
		"X-Stainless-Lang":                          "js",
		"X-Stainless-Arch":                          apStainlessArch(),
		"X-Stainless-Os":                            apStainlessOS(),
		"X-Stainless-Timeout":                       "600",
	}
}

func autoPingSendClaude(ctx context.Context, conn db.Record, cfg autoPingProviderCfg) bool {
	body, _ := json.Marshal(map[string]any{
		"model":      cfg.pingModel,
		"max_tokens": cfg.pingMaxTokens,
		"messages":   []any{map[string]any{"role": "user", "content": cfg.pingText}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, autoPingClaudePingURL, strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	for k, v := range claudeSpoofHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+apStr(conn, "accessToken"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := autoPingHTTPDo(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func autoPingSendCodex(ctx context.Context, conn db.Record, cfg autoPingProviderCfg) bool {
	input := []any{map[string]any{
		"type":    "message",
		"role":    "user",
		"content": []any{map[string]any{"type": "input_text", "text": cfg.pingText}},
	}}
	payload := map[string]any{
		"model":  cfg.pingModel,
		"input":  input,
		"store":  false,
		"stream": true,
	}
	if cfg.pingInstructions != "" {
		payload["instructions"] = cfg.pingInstructions
	}
	if cfg.pingReasoningEffort != "" {
		payload["reasoning"] = map[string]any{"effort": cfg.pingReasoningEffort, "summary": "auto"}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, autoPingCodexPingURL, strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	// Registry CLI identity headers (transport.headers of the codex
	// registry entry — the same source the JS executor builds from).
	ua := "codex_cli_rs/0.159.0"
	if p, ok := providers.Get("codex"); ok && p != nil {
		if headers := apChild(p.Raw, "transport"); headers != nil {
			if h := apChild(headers, "headers"); h != nil {
				if v := apStr(h, "User-Agent"); v != "" {
					ua = v
				}
			}
		}
	}
	req.Header.Set("Authorization", "Bearer "+apStr(conn, "accessToken"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("User-Agent", ua)
	if acct := opCodexAccountID(apChild(conn, "providerSpecificData")); acct != "" {
		req.Header.Set("ChatGPT-Account-Id", acct)
	}
	resp, err := autoPingHTTPDo(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Codex only starts the 5h window after the streaming response
	// completes — drain it fully before reporting success.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
