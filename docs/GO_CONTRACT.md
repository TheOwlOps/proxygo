# Go Port — Package Contract (binding for all teams)

Source of truth: `~/workspace/9router` (JS, v0.5.104 @ 87a74e1).
Target: `~/workspace/proxygo`, module `proxygo`, Go 1.23.
Toolchain: `~/tools/go/bin/go` (not on PATH — export PATH=$HOME/tools/go/bin:$PATH).
First build on this VM is slow (~80s, high load) — scope builds to your package.

## Rules for every team

- **Stdlib only**, except Team C (db) which may try `modernc.org/sqlite`.
- Work ONLY inside your assigned directory. Do not edit `go.mod`, `cmd/`,
  `internal/server/`, or another team's directory.
- Port behaviour, not comments. Where JS is dynamic, use `map[string]any`
  and preserve unknown fields (never drop keys you don't recognise).
- Every package must compile and pass its own tests:
  `go vet ./internal/<pkg>/... && go test ./internal/<pkg>/...`
- Fail-open where the JS fails open (RTK, translators' fix-ups).

## Team A — `internal/translator/`

Port of `open-sse/translator/`. Pivot format is OpenAI.

```go
package translator
type Body = map[string]any
func Register(from, to string, req ReqFn, res ResFn)
func TranslateRequest(from, to string, body Body) (Body, error)   // direct route if registered, else pivot via openai
func TranslateResponse(from, to string, body Body) (Body, error)
func TranslateStreamChunk(from, to string, chunk Body, state *StreamState) ([]Body, error)
```

Phase-1 pairs (request + response + streaming chunks):
openai↔claude, openai↔gemini, claude→openai, gemini→openai,
openai→openai-responses, openai↔kiro & openai↔cursor may be stub-registered
with a clear TODO if their concerns (protobuf/EventStream) block a pure port —
report exactly what was stubbed. Include schema constants (roles, finish
reasons) from `translator/schema/`. Tests: table-driven round-trips using
fixtures distilled from `tests/` in the source repo where practical.

## Team B — `internal/providers/` + `tools/extract_registry.mjs`

Registry files in `open-sse/providers/registry/*.js` are
`export default {…}` literals (some import shared constants).
Write a Node script that dynamic-imports each file and dumps the default
export to JSON; record per-file failures in the report (do not hand-edit
the generated data). Output: `internal/providers/registry.json` (embedded).

```go
package providers
type Model struct { ID, Name, Kind string }
type Display struct { Name, Icon, Color, TextIcon, Website string }
type Transport struct {
    BaseURL, Format, URLSuffix string
    Headers map[string]string
    ForceStream bool
}
type Provider struct {
    ID string; Priority int; Alias, Category string
    Display Display; Transport Transport; Models []Model
    Raw map[string]any // everything else, preserved
}
func All() []*Provider            // sorted by priority then id
func Get(idOrAlias string) (*Provider, bool)
func Models() []ModelEntry        // flattened provider/model pairs for /v1/models
```

Tests: count matches the number of successfully extracted JS registries,
spot-check openai + claude fields (baseUrl, format, a known model id).

## Team C — `internal/db/`

Port of `src/lib/db/`: read `migrations/001-initial.js` for the real schema,
`repos/*.js` for the 11 repos (aliases, apiKeys, combos, connections,
disabledModels, nodes, pricing, proxyPools, requestDetails, settings, usage).

- Keep the SQL schema in `internal/db/schema.sql` (embedded, applied on open).
- Repo layer behind interfaces named after the JS repos.
- Driver: first try `go get modernc.org/sqlite` (pure Go, no cgo).
  If the download fails on this VM, fall back to a JSON-file store with the
  SAME interfaces and say so in `internal/db/README.md` — do not fake SQLite.
- Data dir rules from `src/lib/db/paths.js`: `DATA_DIR` env, else `~/.proxygo/`.
- Tests: open a temp store, run migrations, CRUD round-trip per repo.

## Team D — `internal/executors/` + `internal/chatcore/`

Port of `open-sse/executors/` + `open-sse/handlers/chatCore.js` +
`src/sse/handlers/chat.js` flow (combo expansion + account-selection loop
belong to chatcore; credential storage itself is Team C's connections repo —
chatcore receives credentials through its own interface).

```go
package executors
type Credential struct { APIKey, AccessToken, BaseURL string; Headers map[string]string }
type Executor interface {
    Execute(ctx context.Context, p *providers.Provider, cred Credential,
        body []byte) (*http.Response, error)
}
// DefaultExecutor: any OpenAI-compatible upstream (auth header/scheme from
// registry transport.auth), plus per-provider files for special upstreams.

package chatcore
// Define narrow interfaces (ProviderSource, Translator, Executor, Accounts)
// so this package compiles and tests with fakes; parent wires real adapters.
func (s *Service) HandleChat(ctx context.Context, req ChatRequest) (*http.Response, error)
```

Behaviour to preserve: detect source format → translate request → dispatch →
on 401/429/5xx apply retry + token-refresh hook + next-account fallback →
combo fallback (next model in combo) → stream setup (SSE passthrough).
Binary upstreams (kiro EventStream, cursor protobuf, commandcode NDJSON)
stay inside their executor; if one cannot be fully ported, implement its
HTTP path and mark the binary decoder TODO in the report.

## Parent (integration) — `cmd/proxygo/`, `internal/server/`, `internal/config/`

net/http server: `/health`, `/v1/models`, `/v1/chat/completions`,
`/v1/messages`, `/v1/responses`, dashboard management APIs under `/api/*`
(phase 2), and the React dashboard served as static files from
`WEB_DIR` (built Next export) — logic in Go, UI unchanged.
Env contract identical to `.env.example` (PORT 20128 default, JWT_SECRET,
INITIAL_PASSWORD, DATA_DIR…).
