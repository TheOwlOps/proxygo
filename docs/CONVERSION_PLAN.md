# 9Router → Go — Conversion Plan (surveyed 2026-10-23)

Source: https://github.com/decolua/9router @ 87a74e1 (v0.5.104)
Local clone: `~/workspace/9router` — 1,797 files

## Measured size of the original (JS, no TypeScript)

| Part | Files | LOC | What it is |
|---|---|---|---|
| `open-sse/` | 418 | 60,200 | Routing/translation engine: 138 provider registry files, 33 executors, translator OpenAI↔Claude↔Gemini↔Kiro↔Cursor…, RTK token saver, token-refresh, usage |
| `src/app/api/` | 179 | 18,617 | Next.js API routes: auth (incl. SAML/OIDC), providers, combos, keys, oauth, models, proxy-pools, tunnel, usage… |
| `src/lib/` | 133 | 17,580 | SQLite layer (driver fallback chain + repos + migrations), OAuth services, tunnel (Cloudflare/Tailscale), updater, MITM helpers |
| `src/sse/` | 16 | 3,434 | App-side chat handler glue (combo expansion, account selection) |
| `src/mitm/` | 17 | 3,399 | MITM proxy (certs, DNS, handlers) |
| Dashboard UI (`src/app` pages, `src/shared`, `src/store`) | ~200+ | ~40,000+ | React 19 + Next.js dashboard (JSX) — **not portable to Go literally** |
| `cli/` | 37 | 8,165 | npm CLI launcher + tray |
| `tests/` | 394 | 55,681 | Vitest suite (~938 pass / ~64 known-fail upstream) |
| **Production total** | **~1,018** | **~159,000** | excl. tests |

## The one real decision

React/Next dashboard cannot be "converted to Go" 1:1. Three honest routes:

1. **Go backend + keep React UI (recommended)** — Port `open-sse/` + API routes +
   `src/lib` to Go (net/http, modernc/sqlite or mattn/go-sqlite3).
   Go serves the pre-built dashboard as static files, exactly like
   `custom-server.js` serves the Next standalone build today.
   Result: single Go binary, UI identical, all logic in Go.
2. **Full Go incl. UI rewrite (Go templates / htmx)** — Everything in Go,
   but the dashboard is rebuilt, not converted. Loses React features
   (Monaco editor, xyflow, recharts, dnd-kit) or needs JS islands anyway.
   Longest path, UI will differ.
3. **Core gateway only first** — Port `open-sse/` engine + `/v1/*` +
   `/health` to Go (providers, translators, fallback, RTK), defer the
   ~179 dashboard management APIs. Fastest usable Go binary; dashboard
   APIs phased in afterwards.

## Go architecture (all routes)

```
cmd/proxygo/            main, config from env (.env.example contract kept)
internal/
  server/               net/http mux — /v1/*, /api/*, /health, static UI
  translator/           OpenAI pivot; direct routes for fragile pairs
                        (claude:kiro etc.), port of open-sse/translator
  providers/registry/   one .go file per provider, generated index
                        (port of scripts/migrate-registry.mjs)
  executors/            default = any OpenAI-compatible upstream;
                        special: kiro, cursor, codex, vertex, bedrock…
  chatcore/             detect format → translate → dispatch → retry/refresh → SSE
  combo/                combo expansion + multi-account fallback loop
  rtk/                  tool_result compressors — fail-open, port of open-sse/rtk
  db/                   SQLite (single driver, no fallback chain needed in Go),
                        repos + migrations ported from src/lib/db
  auth/                 JWT (golang-jwt), password, API keys; SAML/OIDC = phase 2
  oauth/                provider token refresh services
  usage/                usage/quota tracking (~/.proxygo, DATA_DIR rules kept)
  tunnel/, mitm/, updater/   later phases
```

Env contract, port (20128), data dir (`~/.proxygo/` / `DATA_DIR`), and the
OpenAI-compatible surface stay identical so existing CLI tools
(Claude Code, Codex, Cursor, Cline…) keep working unchanged.

## Phases (route 1)

1. Core: config, server, `/v1/chat/completions` + `/v1/models`, default
   executor, SSE streaming, OpenAI↔Claude + OpenAI↔Gemini translators.
2. Registry: generate Go registry from the 138 JS registry files
   (script-assisted, model catalogs become data, not hand-typed code).
3. Accounts: SQLite repos, combos, multi-account fallback, token refresh, RTK.
4. Dashboard APIs: providers/keys/combos/settings/usage/oauth routes (~179).
5. Special executors: kiro (EventStream), cursor (protobuf), commandcode
   (NDJSON), vertex, bedrock — binary formats stay inside their executor.
6. Extras: tunnel, proxy pools, MITM, updater, CLI launcher in Go.
7. Verification: port key Vitest suites to Go tests; run original and Go
   side-by-side on the same requests and diff the SSE output.

## Scaffold status

`cmd/proxygo/main.go` — minimal proof-of-route: `/health`,
`/v1/models`, `/v1/chat/completions` with streaming passthrough to an
OpenAI-compatible upstream (`UPSTREAM_BASE_URL` / `UPSTREAM_API_KEY`).
Builds and runs with Go 1.23 — verified locally before this plan was filed.
