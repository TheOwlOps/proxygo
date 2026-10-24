# ProxyGo — Rotation checklist (one page)

Context: supply-chain hardening pass, 2026-10-24. Go deps are checksum-pinned
(go.sum); Docker base images are digest-pinned. Rotate the human-managed
secrets below on the stated cadence, or immediately after any exposure.

## Deploy keys (SSH, per repo — repo Settings → Deploy keys)
- `github-9routergo` (TheOwlOps/proxygo) — rotation: 6 months / after any
  token paste in chat that touched the machine. Revoke old key only after
  the new one pushes cleanly (`git ls-remote github-9routergo`).

## Hugging Face Space (proxygo)
- `UPSTREAM_API_KEY` Space secret (seed connection at boot) — rotate 90 days.
- Space **persistent storage is OFF**: every restart wipes /app/data
  (admin password, connections, keys). If you enable paid persistent storage,
  treat the data dir as secret-bearing and back it up before upgrades.
- Default dashboard password is `123456` — change on first boot; it lives in
  the data dir, so it resets with the Space.

## Runtime secrets (environment, never committed)
- Admin password / API keys / OAuth client secrets: set only via env vars or
  the dashboard; never in `docs/`, `web/`, or chat. The PII redaction pass
  (feature pack F6) masks `sk-…`, `ghp_…`, `AKIA…`, `xox…`, JWTs in logs.
- After any accidental paste: rotate the exposed secret, then
  `git log -S '<secret>'` to confirm it never landed in history.

## Dependencies (verify, don't just trust)
- Go: `go mod verify` — all modules must print OK. `go.sum` is the lockfile;
  never hand-edit it, regenerate with `go mod tidy`.
- Dockerfile bases are digest-pinned (`golang:1.23-alpine@sha256:3833…`,
  `alpine@sha256:be26…`). Re-resolve digests quarterly and rebuild to pick up
  security patches — a pinned digest never moves on its own.
- Release uploads: publish `proxygo-<os>-<arch>` + `checksums.txt` together;
  the self-updater only matches that exact asset-name pattern.

## If a dependency is compromised (LiteLLM-style)
1. `git log -- go.sum` — find when the dep entered.
2. `go mod download <module>@<last-good-version>` + `go mod verify`.
3. Rebuild, republish release assets, rotate any secret that shared the build
   machine.
