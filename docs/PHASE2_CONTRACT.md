# Phase 2 Contract — dashboard APIs, OAuth, RTK, catalog, Cursor/Kiro, CLI

Phase 1 is done (see README). Phase 2 ports everything else.
Parent already added deps: `golang.org/x/crypto` (bcrypt),
`golang.org/x/net` (http2). **No team edits `go.mod`/`go.sum` again** —
if you need another dep, report it instead.

## Shared API framework (parent-owned, `internal/api/api.go`)

```go
package api
type Deps struct { Store *db.Store; Chat *chatcore.Service }
func RegisterAll(mux *http.ServeMux, deps Deps) // calls the five team registrars
// helpers you MUST use:
WriteJSON(w, status, v)          // NextResponse.json equivalent
ReadBodyJSON(r) (map[string]any, error)
Err(w, status, msg)              // {"error": msg} — match each JS route's own shape when it differs
RequireAuth(deps, h) http.HandlerFunc   // dashboardGuard port (below)
SessionToken(r) string           // auth_token cookie or Bearer
CreateSession(w, r, claims)      // sets auth_token cookie (HS256 JWT, 24h)
ClearSession(w)
VerifyPassword(pw string) bool   // bcrypt settings.password, else INITIAL_PASSWORD||"123456"
```

Auth model (from `src/lib/auth/dashboardSession.js` + `src/dashboardGuard.js`):
cookie `auth_token`, HS256 JWT, secret = `JWT_SECRET` env else
`$DATA_DIR/jwt-secret` file (0600, generated once). Public paths:
`/api/health`, `/api/init`, `/api/locale`, `/api/auth/login|logout|status`,
`/api/auth/oidc`, `/api/auth/saml`, `/api/version`,
`/api/settings/require-login`. Protected prefixes (`/api/settings`,
`/api/keys`, `/api/providers`, `/api/provider-nodes`, `/api/proxy-pools`,
`/api/combos`, `/api/models`, `/api/usage`, `/api/oauth`, `/api/media-providers`,
`/api/pricing`, `/api/tags`, `/api/cli-tools`, `/api/mcp`, `/api/translator`,
`/api/tunnel`) require a session **when `requireLogin` setting is on**;
`/api/shutdown`, `/api/settings/database`, `/api/version/shutdown|update`
always require one. Port the guard faithfully in `RequireAuth`.

Route patterns: Go mux style — `"POST /api/keys"`, `"GET /api/keys/{id}"`
(Next `[id]` → `{id}`, `[...path]` → `{path...}`).

## Team registrars (one file each in `internal/api/`, replace the stub)

- `RegisterAuth(mux, deps)` — Team E: `auth.go`
- `RegisterProviders(mux, deps)` — Team F: `providers.go`
- `RegisterOAuth(mux, deps)` — Team G: `oauth.go`
- `RegisterOps(mux, deps)` — Team H: `ops.go`
- `RegisterCLITools(mux, deps)` — Team I: `clitools.go`

Each registrar file is owned by exactly one team. Port each JS route's
methods, request/response JSON shapes and status codes faithfully; where a
JS route depends on something not yet ported, return the JS shape with a
documented TODO in your report — never invent a different API.

## Other teams

- Team J: `internal/rtk/` + TokenSaver wiring in `internal/app` (new file
  `rtk.go` there, do not rewrite app.go) + `internal/db/migrate_json.go`.
- Team K: `tools/extract_provider_models.mjs` + `internal/modelcatalog/` +
  wiring in `internal/app` (new file `catalog.go`: ModelMeta enrichment +
  db pricing hooks — coordinate via that file only, do not rewrite app.go).
- Team L: rewrite `internal/executors/cursor.go` (+ new files in that dir)
  and the cursor stubs in `internal/translator/stubs.go`.
- Team M: replace kiro stubs in `internal/translator/` with the real port.
- Team N: `cmd/proxygo-cli/` + `internal/cli/`.

## Verification (every team)

`go vet ./<your dirs>/... && go test ./<your dirs>/...` must pass, plus
`go build ./...` for the whole repo where your change touches shared code.
Report: routes/features ported count vs assigned, exact TODO list, tests.
