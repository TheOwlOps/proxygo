# Feature Pack 1+3 — Contract (2026-10-23, user-approved "gói 1 3")

New features for the Go port. These are ADDITIVE features (not JS parity):
when a feature's toggle is off, behavior must be byte-identical to today.

## Global rules

- Go toolchain: `export PATH=$HOME/tools/go/bin:$PATH`. Module `9router-go`.
- ALL features are opt-in via settings (single JSON doc in `settings(id=1)`),
  default OFF / no-op. Settings keys:
  - `responseCacheEnabled` (bool), `responseCacheTTLSeconds` (number, def 300),
    `responseCacheMaxEntries` (number, def 500)
  - `circuitBreakerEnabled` (bool), `circuitBreakerFailureThreshold`
    (number, def 5), `circuitBreakerOpenSeconds` (number, def 30)
  - `piiRedactionEnabled` (bool), `piiRedactNationalId` (bool, def false)
  - Key limits live in the KV store (`internal/db/kv.go`), key
    `keylimit:<apiKeyId>` — NOT in settings.
- chatcore.Service extension pattern (same as TokenSaver): add an interface
  field to `chatcore.Service`; nil = disabled. Parent wires concrete
  implementations in `internal/app` and route registrations in
  `internal/server/server.go` / `api.RegisterAll`. Teams deliver exported
  constructors/registration funcs; parent adds the one-line calls.
- No new go.mod dependencies, EXCEPT Team F7 which may promote
  `golang.org/x/sys` to a direct dependency at the version already in the
  module graph (no version bump).
- Every team: unit tests for the new package + the touched package's full
  test suite green. Report real-tree vs scratch verification honestly.
- Errors on the /v1 surface keep the existing OpenAI-style error shape.

## F1 — Response cache (internal/respcache + internal/server + internal/api)

- `internal/respcache`: in-memory LRU + per-entry TTL, goroutine-safe.
  Key = sha256 over canonical JSON of {path, model, canonical body} +
  api-key fingerprint (first 8 chars of sha256 of the key; empty when no
  key). Canonical body = the raw request JSON with `stream` removed
  (stream and non-stream share an entry ONLY via byte replay — see below)
  and keys sorted (parse to any, re-marshal with encoding/json which
  sorts map keys).
- Server middleware (new file `internal/server/cache_mw.go`): wraps the
  three chat POST routes. On enabled + cacheable request (POST chat
  endpoints; skip when header `x-9router-no-cache: 1`): lookup → on hit,
  replay stored status/headers/body bytes verbatim with header
  `x-9router-cache: hit`. On miss: capture the response (tee) and store
  ONLY status-200 responses, after completion; works for SSE too
  (store the raw byte stream; replay verbatim). Cap stored body at 4MB.
- Export `func CacheMiddleware(next http.Handler) http.Handler` +
  package-level stats (hits, misses, stores, evictions, entries) +
  `Clear()`. Settings read through an injected
  `Configure(func() (enabled bool, ttlSeconds, maxEntries int))`;
  parent calls Configure with a settings-backed getter.
- API (new file `internal/api/cache_api.go`):
  `RegisterCacheAPI(mux, deps)` → `GET /api/cache/stats`,
  `POST /api/cache/clear` (dashboard-session guarded like other /api).

## F2 — Circuit breaker (internal/breaker + chatcore + internal/app)

- `internal/breaker`: per (provider, connectionID) state machine:
  closed → open after N consecutive failures → half-open after open
  duration (1 probe) → closed on probe success, open again on failure.
  Failure = transport error or upstream 5xx. 429 is NOT a breaker
  failure (cooldown already handles rate limits). Goroutine-safe,
  injectable clock for tests. Snapshot() for stats.
- chatcore: field `Breaker` interface
  `{ Allow(provider, connID string) bool; OnResult(provider, connID string, success bool) }`.
  Call sites in the attempt loop of `handleSingleModel` ONLY: skip
  credentials Allow() rejects (like an exclusion), call OnResult after
  each Execute attempt. Nil = no-op. Also `func (s *Service)
  BreakerSnapshot() any` returning nil when unset.
- Adapter `internal/app/breaker.go`: builds breaker from settings
  (threshold/openSeconds read live from the Service's Settings source
  at call time is overkill — read at wire time; note it).
- API (new file `internal/api/breaker_api.go`): `RegisterBreakerAPI`
  → `GET /api/breaker/stats` from `deps.Chat.BreakerSnapshot()`.

## F3 — Per-key rate limit + budgets (internal/keylimit + chatcore + internal/api)

- Limits per API key (KV `keylimit:<id>`):
  `{rpm, dailyTokens, monthlyTokens, dailyCostUSD, monthlyCostUSD}`
  (0/absent = unlimited).
- `internal/keylimit`: RPM sliding window (in-memory, per key);
  budget check derives today's / this month's token + cost totals from
  the DB usage accounting (inspect `internal/db/usage*.go` and
  request-details; use what exists — if per-key aggregation is missing,
  add a Store method in a NEW file `internal/db/keyusage.go`).
- chatcore: field `KeyLimiter` interface
  `{ Check(keyID string) *LimitRejection }` where LimitRejection
  carries HTTP 429 + type `rate_limit_exceeded` | `budget_exceeded` +
  message. Call site: in `HandleChat` ONLY, right after the API key is
  validated/identified (find where Keys/KeyAccess run). Nil = no-op.
  RPM consumption happens in Check (count the request when allowed).
- API (new file `internal/api/keylimits_api.go`): `RegisterKeyLimitsAPI`
  → `GET /api/keys/{id}/limits`, `PUT /api/keys/{id}/limits`,
  `DELETE /api/keys/{id}/limits`, `GET /api/keys/{id}/usage-summary`.
- Adapter/wiring support in `internal/app/keylimit.go`: construct the
  limiter with the Store and assign `svc.KeyLimiter`.

## F4 — Playground (internal/server/playground.go only)

- Embedded single-file HTML/CSS/JS (no build step), served by an
  exported `PlaygroundHandler() http.Handler` (parent adds the mux
  line `GET /playground`). Flat design consistent with the dashboard
  (white/gray, system sans).
- Behavior (all client-side against existing endpoints): API-key input
  (persisted to localStorage), model dropdown from `GET /v1/models`,
  chat with streaming rendering via `POST /v1/chat/completions`,
  temperature/max-tokens inputs, and COMPARE mode: two model pickers,
  one prompt → both panels stream side by side, each showing latency
  and usage (tokens) from the stream's usage chunk / final JSON.
  Clear, friendly error display when the key is missing/invalid.
- Tests: handler returns 200 + HTML markers; no backend changes.

## F5 — Self-update (internal/selfupdate + api/auth.go + internal/cli)

- `internal/selfupdate`: `Check(ctx) (Info, error)` reads a GitHub
  Releases feed: API base overridable via env `NINEROUTER_UPDATE_API`
  (default `https://api.github.com`), repo via `NINEROUTER_UPDATE_REPO`
  (default `decolua/9router`). Finds asset
  `9router-go-<GOOS>-<GOARCH>[.exe]` in the latest release; reports
  `Compatible:false` when absent (today's upstream releases ship no Go
  assets — the mechanism activates when a release does). Version
  compare: own semver compare (do not import internal/cli).
  `Apply(ctx, info)`: download asset (optional `checksums.txt`
  sha256 verification when present in the release), write to temp file
  beside the target, chmod 0755 (unix), swap: unix = rename over;
  windows = rename running exe to `<exe>.old`, move new into place.
  Target = `os.Executable()` unless overridden.
- `internal/api/auth.go` `versionUpdate` ONLY: when production and a
  compatible update exists → Apply, then the existing scheduleExit()
  (document: process supervisor/CLI relaunches the new binary). When
  no compatible asset → keep current response shape + a clear
  `selfUpdate: "no-compatible-asset"` field. Do not break Team E's
  existing tests.
- CLI: `9router-cli update` command in `internal/cli/update.go`
  (check + apply against the resolved SERVER binary path chain), plus
  one dispatch case + help line in `cli.go` (minimal, additive).
- Tests: httptest fake GitHub API + asset + checksums; Apply against a
  temp file (unix path); windows swap logic compile-guarded.

## F6 — PII redaction (internal/pii + chatcore + internal/app)

- `internal/pii`: `RedactBody(body map[string]any, opts) int` walks the
  request body like RTK does (message content strings in
  OpenAI/Claude/Gemini shapes, incl. tool results) and replaces:
  emails → `[EMAIL]`; phone numbers (VN `0` + 9 digits with optional
  spaces/dots, `+84` forms, generic intl) → `[PHONE]`; credit cards
  (13–19 digits, Luhn-valid, optional separators) → `[CARD]`;
  API-key-like tokens (`sk-…`, `ghp_…`, `AKIA…`, `xox…`, JWTs,
  `Bearer …`) → `[API_KEY]`; national ID (12-digit VN CCCD) →
  `[NATIONAL_ID]` ONLY when `piiRedactNationalId` is on (default off —
  false-positive risk). Conservative regexes: when in doubt, don't
  redact. Returns replacement count.
- chatcore: field `BodyGuard` interface
  `{ Process(body map[string]any, format string, enabled bool) int }`,
  invoked at the same site as TokenSaver (its own region of
  chatcore.go), gated by settings `piiRedactionEnabled`; log the count
  via Logger when > 0. Nil = no-op.
- Adapter `internal/app/pii.go` (mirrors rtk.go).

## F7 — Windows tray (internal/cli)

- `internal/cli/tray_windows.go` (`//go:build windows`): real tray via
  `Shell_NotifyIconW` + a hidden message window + `TrackPopupMenu`
  menu: **Open Dashboard**, **Start Server**, **Stop Server**,
  separator, **Quit**. Double-click icon → Open Dashboard. Start/Stop
  reuse the CLI's existing pid-file process functions (read
  server.go/process_*.go first). Icon: embedded ICO bytes — build the
  ICO in code from a stdlib-PNG-encoded 32×32 image (simple flat
  rounded-square + dot motif is fine for v1; document it).
  Message loop with GetMessageW; remove icon on quit.
  May promote `golang.org/x/sys` to direct at the in-graph version.
- `internal/cli/tray_other.go` (`//go:build !windows`): keeps today's
  behavior (detached start + explanatory note).
- `cli.go`: route `tray` command and `-t/--tray` to `runTray()` —
  minimal additive edits in the tray region ONLY (Team F5 edits the
  update region).
- Verification bar: `GOOS=windows go build ./...` + linux build/test
  green. It cannot be run on a real Windows desktop here — say so.

## File-ownership map (avoid collisions)

- chatcore.go editors: F2 (attempt loop in handleSingleModel),
  F3 (HandleChat key-check region), F6 (TokenSaver call region).
  Three distinct regions — keep hunks small and exact.
- cli.go editors: F5 (update dispatch/help), F7 (tray dispatch).
- Everyone else: new files only (+ your own package).
- Parent wires: server.go (cache middleware wrap, /playground line),
  api.RegisterAll calls, internal/app/app.go hook assignments,
  db DefaultSettings keys.
