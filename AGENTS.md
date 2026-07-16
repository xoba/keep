# AGENTS.md

Guidance for coding agents (and humans) working in this repository.

## What this is

`xoba.com/keep` — the public Go SDK and CLI for keep, the passive
custodian for a small fleet of services (keepcentral.com). This module is
the deployment side only: status reports, leased secrets, SQLite backups,
and the one deploy-time write (own-service desired revision). Admin
operations live in the private server project and are out of scope here —
permanently.

**docs/design.md is authoritative** (decision record S1–S10);
**API.md is the normative wire contract** with the server. The two
projects share no code and never import each other (S1).

## Layout

```
client.go        low-level Client: status, leases, backups, set-desired
renew.go         renewable leases (refresh/backoff/stale policy)
sdk.go           SDK: the recommended high-level interface
identity.go      Ed25519 keygen, fingerprints, mTLS cert loading
cmd/keep/        the CLI — installs as `keep`
keep_test.go     fake server implementing API.md verbatim + contract tests
```

## Commands

```bash
make build   # go build ./...   (CGO required: mattn/go-sqlite3)
make vet
make test
make scan    # gitleaks + trufflehog over full history — before any push
```

## Conventions

- **This repository is public-by-design: treat every commit as already
  published.** Never commit content containing account IDs, cloud
  resource IDs/ARNs, IP addresses, email addresses, key material or key
  fingerprints, or hostnames of private machines — the private git host
  is only ever "the private origin."
- The only endpoint that may appear anywhere is the built-in one,
  `api.keepcentral.com` (S9). No server flag, env var, or config file for
  it; `Client.BaseURL` is a test seam, not a knob.
- Commit messages: lowercase, concise subject; body only when it earns
  its place. **No AI co-authorship trailers.**
- The go directive stays on a stable Go release, never an RC (S6).
- Wire-contract changes are additive-only (S4) and must land in API.md,
  the fake server, and the server project together.
- Tests must never send traffic to the production endpoint: anything that
  performs I/O gets wired to the fake server first (see TestSDK).
