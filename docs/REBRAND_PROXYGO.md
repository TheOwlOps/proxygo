# Rebrand contract: 9Router → ProxyGo (2026-10-23)

The product is renamed **ProxyGo** and its brand color changes from
coral/orange to **indigo → blue** (matching the Hugging Face front
matter already in README.md: colorFrom indigo, colorTo blue).
Parent already did the structural Go rename (module `proxygo`,
`cmd/proxygo`, `cmd/proxygo-cli`, import paths, Dockerfile). Your
job is the string/color pass in your assigned slice ONLY.

## Name map (apply in this order)

| From | To |
|---|---|
| `9Router Proxy` | `ProxyGo` |
| `9Router` | `ProxyGo` |
| `9ROUTER` | `PROXYGO` |
| `9router-go` | `proxygo` |
| `9router-cli` | `proxygo-cli` |
| `9router` | `proxygo` |
| `NINEROUTER` | `PROXYGO` |
| `ninerouter` | `proxygo` |
| `NineRouter` | `ProxyGo` |
| `.9router` (home/data dir) | `.proxygo` |
| `x-9router-` (headers) | `x-proxygo-` |
| `9router-` (localStorage keys, misc prefixes) | `proxygo-` |
| self-update default repo `decolua/9router` (ONLY in selfupdate defaults + CLI update check) | `TheOwlOps/proxygo` |
| JS `package.json` name `9router-app` | `proxygo-app` |

Watch for glued forms the table misses (e.g. `9router_` ,
`9RouterAI`, URLs like `9router.` in help text) and normalize them
to the ProxyGo equivalent with the same casing pattern.

## KEEP — never rename

- Provider IDs, model IDs, combo/connection semantics
  (`openai-compatible-*` etc. are untouched anyway).
- DB table/column names and settings KEYS that are data, not brand
  (e.g. `jwt-secret` file name stays; `auth_token` cookie stays).
- `internal/providers/registry.json` and
  `internal/modelcatalog` DATA files — extracted upstream data,
  skip entirely.
- Third-party names and brand colors (GitHub, Claude, OpenAI,
  provider logos/colors in the registry and UI provider cards).
- Semantic colors: success green, danger red, warning amber,
  info blue status tokens.
- The version string `0.5.104`.
- Factual attribution: links to the upstream project
  (github.com/decolua/9router) in docs/README may stay as
  attribution; product self-references become ProxyGo.
- `pxpipe`, `mitm` etc. product-neutral terms stay.

## Color map (dashboard, `src/app/globals.css` + stray hardcodes)

Brand scale (both `:root` and `.dark` blocks):

| Token | Old | New |
|---|---|---|
| brand-50 | #fdf1ed | #eef2ff |
| brand-100 | #fadccf | #e0e7ff |
| brand-200 | #f4b59c | #c7d2fe |
| brand-300 | #ee8d6a | #a5b4fc |
| brand-400 | #ea7855 | #818cf8 |
| brand-500 | #E56A4A | #6366F1 |
| brand-600 | #cc5236 | #4F46E5 |
| brand-700 | #a64027 | #4338CA |
| brand-800 | #7a2f1d | #3730A3 |
| brand-900 | #4d1e12 | #1E1B4B |

Surfaces (light): `--color-bg` #FDFAF6 → #F7F8FC;
`--color-bg-alt` #F7F3EE → #EEF0F8;
`--color-sidebar` rgba(244,241,236,0.85) → rgba(237,239,247,0.85).
Shadows: `rgba(229, 106, 74, α)` → `rgba(99, 102, 241, α)` (same α);
`--shadow-elevated` light tint rgba(60,50,45,0.06) → rgba(30,27,75,0.06);
`--shadow-focus` follows the RGBA rule.
Dark block: brand scale as above; surfaces stay neutral;
warm shadows follow the RGBA rule.

Elsewhere (JS + Go): any literal `#E56A4A` / `#e56a4a` /
`rgba(229,106,74,…)` / `rgb(229,106,74)` → the indigo equivalents
(#6366F1 / rgba(99,102,241,…)). Tailwind `orange-*` classes used as
BRAND accents (logo, highlights, active states) → `indigo-*`;
`orange-*`/`amber-*` used as WARNING/status or provider colors
STAY. The logo mark (SVG/component) takes brand-500.

Go playground (`internal/server/playground.go`): title/brand text
→ ProxyGo; primary button/accent colors → #4F46E5 / #6366F1 if
they currently use a coral/orange or the old brand tone (its slate
neutrals stay). Tray ICO: already an indigo square — leave art,
rename text only.

## Verification (every worker, for its own files)

1. `grep -n "9router\|9Router\|9ROUTER\|NINEROUTER" <files>` →
   zero hits outside the KEEP list (report any kept hit + why).
2. `grep -n "E56A4A\|229, 106, 74\|229,106,74" <files>` → zero.
3. Files must still parse: Go → `gofmt -l` clean on your files;
   JS → no syntax breakage (balanced braces; the parent rebuild
   will catch the rest).
4. Do NOT edit go.mod/go.sum, registry.json, catalog data, or
   another slice's files. Do NOT run builds of the whole tree
   (siblings are mid-flight); file-local checks only.
