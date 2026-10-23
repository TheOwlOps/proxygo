# 9Router — Go port

Backend rewritten in Go (module `9router-go`, Go 1.23, single binary);
the React dashboard is unchanged and served as static files by the Go
server (`WEB_DIR`). Port plan: `docs/CONVERSION_PLAN.md`; binding package
contract: `docs/GO_CONTRACT.md`.

## Run

```bash
# Linux/macOS
export PATH=$HOME/tools/go/bin:$PATH   # if Go is installed under ~/tools
go build -o 9router ./cmd/9router
PORT=20128 ./9router
```

```powershell
# Windows (PowerShell)
go build -o 9router.exe ./cmd/9router
$env:PORT=20128; .\9router.exe
```

First-run shortcut (seeds an `openai` connection when the DB is empty):

```bash
UPSTREAM_API_KEY=sk-... ./9router
```

Endpoints: `GET /health`, `GET /v1/models`,
`POST /v1/chat/completions` · `/v1/messages` · `/v1/responses`.
Data lives in SQLite at `$DATA_DIR/db/data.sqlite` (default `~/.9router/`),
schema-compatible with the original `src/lib/db`.

Custom endpoints work exactly like the original: create a provider
connection for `openai-compatible-<name>` / `anthropic-compatible-<name>`
with `providerSpecificData.baseUrl` pointing at your endpoint.

## Status (2026-10-23)

Phase 1 + Phase 2 + the gap-closing round + Feature Pack 1+3
complete and verified (`go vet ./...` clean, `go test ./...` — all
20 packages PASS, `GOOS=windows go build ./...` green, live binary
smoke-tested: health, 1,133 models, login flow, keys CRUD, OAuth
authorize URL, usage stats, a real per-provider usage fetch, pxpipe
status/health, and every Feature Pack behavior above). ~85,600
lines of Go + ~16,600 lines of tests across 219 Go files.

- `internal/providers` — 137/137 registries extracted (1,133 models)
- `internal/modelcatalog` — 1,155 model entries / 112 providers +
  pricing (127 canonical + 112 overrides + 51 patterns), wired live
- `internal/translator` — OpenAI↔Claude/Gemini/Responses + Kiro (all
  directions) + Cursor request, request+body+stream
- `internal/db` — real SQLite (modernc, no cgo), 11 tables, 11 repos,
  legacy `db.json` → SQLite one-time import
- `internal/executors` + `internal/chatcore` — default + special
  executors (Kiro EventStream, Bedrock SigV4, CommandCode NDJSON,
  Cursor HTTP/2 + hand-rolled protobuf…), account/combo fallback,
  token refresh, SSE, RTK token saver
- `internal/api` — the full dashboard API surface: auth/settings/keys/
  pricing/version, providers/nodes/combos/models/tags/proxy-pools
  (incl. Cloudflare/Deno/Netlify/Vercel deploys), OAuth + OIDC/SAML
  SSO, cli-tools config writers for ~19 tools, usage/translator/
  media/MCP/headroom/pxpipe/tunnel ops
- `internal/oauthsvc` — OAuth engine for 28 providers (auth-code,
  device-code, refresh), callback proxy, auto-import readers
- `internal/tunnel` — Cloudflare quick tunnels + Tailscale
- `internal/mitm` — root CA, hosts/DNS management, TLS intercept
  server on :443
- `internal/cli` + `cmd/9router-cli` — launcher (start/stop/status/
  open/version/reset-password/connect/show/xai video; tray stubbed)
- `internal/app` + `internal/server` — wiring, HTTP surface, static UI

SAML SSO login is fully ported including XMLDSig signature
verification (goxmldsig; assertion- or response-signed, tamper /
wrong-cert / unsigned responses rejected — covered by tests; not yet
live-verified against a real IdP).

Feature Pack 1+3 (2026-10-23, Go-only additions — all opt-in via
settings, default off, no behavior change when off): response cache
(byte-level replay incl. SSE, LRU + TTL, `GET /api/cache/stats`,
`POST /api/cache/clear`); per-connection circuit breaker
(`GET /api/breaker/stats`); per-API-key RPM + daily/monthly
token/cost budgets (`/api/keys/{id}/limits`, fail-open); embedded
playground at `/playground` with a two-model compare mode; real
self-update from GitHub Releases (checksum-verified binary swap,
dashboard action + `9router-cli update` — activates when a release
publishes `9router-go-<os>-<arch>` assets); PII redaction of outbound
prompts (email/phone/Luhn-checked cards/API keys, national ID
opt-in separately); a hand-rolled Windows system tray
(Shell_NotifyIcon; compile-verified, not yet run on a real Windows
desktop). Live-smoke verified against a mock upstream: cache hit
replay, redacted upstream body, 429 on the 3rd over-RPM request,
breaker circuit open in stats. See `docs/FEATURE_PACK_13.md`.

Gap-closing round (2026-10-23): all previously documented functional
gaps are closed — per-provider usage fetchers 29/29; MITM Kiro
intercept fully ported (incl. the x-request-source anti-loop rule);
all 14 bespoke web/session executors ported (`executors.NotPorted`
is empty); pxpipe runs for real as a child process (the npm package
ships a standalone proxy server on :47821 — `internal/pxpipe`);
CLI `connect`/`show`/`xai video` ported and the update check reads
GitHub Releases; provider test-path OAuth refresh, all 9 live model
resolvers, the Bedrock SigV4 credential probe, the Vercel-relay URL
rewrite and the models.dev catalog-sync engine are wired; settings
PATCH side effects (combo-rotation reset, quota AutoPing) and
OIDC/SAML session-claims parity are in.

Remaining residuals (documented in each package):
- The Windows tray is implemented but has never run on a real
  Windows desktop (no GUI environment here) — smoke-test pending.
- CLI tray on non-Windows platforms remains the detached-start note.
- The dashboard "update now" action cannot self-update a standalone
  binary the way the JS spawns an npm updater; it exits so an
  external supervisor/CLI can swap the binary (check is real).
- pxpipe's transform is not routed through the Go chat pipeline;
  the proxy runs standalone, as its own dashboard expects.
- Per-connection proxy options are not applied inside the usage
  fetchers / AutoPing (they use the default transport).
- Desktop credential extraction that has no Go equivalent:
  Xiaomi MiMo passToken from the desktop cookie DB, Zed Windows
  Credential Manager, Bedrock profile-mode credentials (AWS SDK
  profile chain) — static keys work everywhere.
- The 14 web executors, Cursor and SAML are verified against
  protocol fixtures generated from the original JS, not against
  live provider accounts / a real IdP.
