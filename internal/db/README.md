# internal/db — Go port of `src/lib/db/`

## Driver outcome: REAL SQLite ✅

`go get modernc.org/sqlite` (v1.34.4) **succeeded** on this VM
(downloaded through the proxy in ~2m10s), so this package uses real
SQLite via `modernc.org/sqlite` (pure Go, no cgo) — **no JSON-file
fallback was needed or implemented**. It replaces the JS fallback chain
(bun:sqlite → better-sqlite3 → node:sqlite → sql.js) with one driver.
Note: the package only compiles once the module cache is warm; the
first build of modernc.org/sqlite on this VM took ~2.5 minutes.

I ran `go get` as Team C (allowed for this team only): `go.mod`/`go.sum`
gained modernc.org/sqlite and its transitive deps.

## Layout / data dir

Same as `src/lib/db/paths.js` + `src/lib/dataDir.js`:

- `DATA_DIR` env if set, else `~/.proxygo/` (Windows: `%APPDATA%/proxygo`)
- DB file: `<DATA_DIR>/db/data.sqlite`, backups dir `<DATA_DIR>/db/backups/`
- `Open()` resolves the env; `OpenInDir(dir)` is the explicit form (tests).

## Schema

`schema.sql` (embedded, applied on open) is a faithful port of the
`TABLES` definition in `src/lib/db/schema.js` (SCHEMA_VERSION = 2) —
which is exactly what `migrations/001-initial.js` creates on a fresh DB:

- **11 tables**: `_meta`, `settings`, `providerConnections`,
  `providerNodes`, `proxyPools`, `apiKeys`, `combos`, `kv`,
  `usageHistory`, `usageDaily`, `requestDetails`
- **17 indexes** (`idx_*`), same names/SQL as the JS source
- PRAGMAs from `PRAGMA_SQL` applied in `Open()`; `_meta.schemaVersion`
  stamped `1`, `backupSchemaVersion` stamped `2`.
- The migrate.js additive auto-sync is unnecessary: schema.sql already
  carries the full current definition (incl. the additive
  `apiKeys.accessRestricted/accessAllow` columns). Legacy JSON import
  from `migrate.js` (db.json → SQLite) is **not** ported — a JS-era
  `~/.proxygo/db.json` will not be auto-imported by the Go binary.

## Repos (11, named after `repos/*.js`)

Interfaces in `types.go`; records are `map[string]any` (`Record`) with
column fields materialised and all other keys preserved in the JSON
`data`/`value` columns — no unknown field is dropped.

| Go interface | JS file | Storage |
|---|---|---|
| SettingsRepo | settingsRepo.js | settings row id=1 (defaults ported verbatim) |
| ConnectionsRepo | connectionsRepo.js | providerConnections (+dedupe/health-reset/reorder logic) |
| NodesRepo | nodesRepo.js | providerNodes |
| ProxyPoolsRepo | proxyPoolsRepo.js | proxyPools |
| APIKeysRepo | apiKeysRepo.js | apiKeys (+keyAccess columns, HMAC key generation) |
| CombosRepo | combosRepo.js | combos |
| AliasesRepo | aliasRepo.js | kv scopes modelAliases/customModels/mitmAlias |
| PricingRepo | pricingRepo.js | kv scope pricing |
| DisabledModelsRepo | disabledModelsRepo.js | kv scope disabledModels |
| UsageRepo | usageRepo.js | usageHistory + usageDaily + _meta counter |
| RequestDetailsRepo | requestDetailsRepo.js | requestDetails |

Plus `KVStore`/`KVScope` (helpers/kvStore.js `makeKv`, metaStore) and
`ExportDB()`/`ImportDB()` (index.js), with key-access validation on
import exactly as in JS.

## Integration hooks the parent must wire

- **Pricing catalogue**: `open-sse/providers/pricing.js`
  (`PROVIDER_PRICING`, `getPricingForModel`, `calculateCostFromTokens`)
  belongs to the providers package. Set `db.DefaultProviderPricing`
  and/or `db.PricingResolver` at startup; until then GetPricing returns
  user overrides only and usage cost computes as 0.
  `CalculateCostFromTokens` itself is ported here.
- **API key secret**: generated keys are `sk-{machineId}-{keyId}-{crc8}`
  with crc = HMAC-SHA256(`API_KEY_SECRET`, machineId+keyId)[:8] hex,
  mirroring `src/shared/utils/apiKey.js`. If the env var is unset, the
  fallback constant `"9router-default-secret"` is used — set
  `API_KEY_SECRET` to match any existing deployment.

## Known divergences (honest)

1. **RequestDetails writes are synchronous.** JS buffers and flushes
   async (batchSize/flushInterval + shutdown hook). Go inserts inside
   `SaveRequestDetail` with the same config gating, header sanitizing,
   truncation and retention pruning. Resulting rows are identical; a
   crash loses nothing. The observability config is still read with
   the JS 5s cache.
2. **Usage statsEmitter** (Node EventEmitter) is not ported; poll
   `GetUsageStats` / `GetActiveRequests`.
3. **SaveRequestUsage** returns errors to the caller; JS swallows them
   after console.error.
4. **CreateAPIKeyWithKey** is an extra helper (JS createApiKey always
   generates); shared insert path for API routes that import keys.
5. JS `getUsageStats` quirks are preserved as-is (e.g. totalRequests is
   derived from byProvider sums; the lastUsed overlay uses the
   `"local-no-key"` key exactly like JS).
6. **Settings defaults**: `headroomUrl` honours `HEADROOM_URL` env like
   JS; `mitmRouterBaseUrl` default is the literal `http://localhost:20128`
   from the JS source.

## Verify

```bash
export PATH=$HOME/tools/go/bin:$PATH
cd ~/workspace/proxygo
go vet ./internal/db/...   # OK
go test ./internal/db/...  # 16 tests, all PASS
```
