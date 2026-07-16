# keep SDK — design

**Status:** design record (pre-implementation)
**Module:** `xoba.com/keep`
**Provenance:** extracted by design (2026-07-16) from the keep server project's
`client` package. The server project is private and its module
(`keepcentral.com`) is unpublished; this project is the public face of keep's
client side. §9 records every decision with rationale.

---

## 1. Purpose & positioning

Keep is a passive custodian for a small fleet of services: registry, secret
custody, SQLite backups. Its server exposes a small mTLS HTTP API to the
services it watches over. Until now the Go SDK lived inside the server's
module, so every consumer had to resolve a private module through `replace`
directives or `go.work` — friction that grows with every consumer.

This project extracts the **deployment-side SDK** into an independent,
publishable module:

- **`xoba.com/keep`** — this module. Public. What services import.
- **`keepcentral.com`** — the server. Private, unpublished. Keeps its own
  admin client internally.

**Honest scope (S9): this SDK exists for the author's own services, working
in tandem with the keepcentral.com deployment.** It is published to remove
private-module friction, not (yet) to serve other operators: the endpoint
`https://api.keepcentral.com` is hardcoded — no configurability — and the
server's key registry only ever contains the author's own deployments.
Generalizing to other operators' servers is a possible future, deliberately
not designed now.

The trust boundary (S10): client projects get the runtime basics (status,
leases, backups) plus exactly one deploy-time write — recording the desired
revision of **their own service**. Every other administrative function
(registry, keys, secret writes, backup download, reports, audit) stays in
the server project's admin CLI, in the operator's hands.

The two modules are **completely independent: no import dependency in either
direction, ever** (S1). Their only coupling is the wire contract (§5). Once
this SDK is published, the server project deletes its `client` package and
the extraction is complete (§8).

Publication target: a public GitHub repository, with the module path served
as a vanity import from `https://xoba.com/keep?go-get=1`.

## 2. Scope

**In scope** — everything a *deployment* (a service under keep's care) needs:

- Identity: keygen (Ed25519 keypair + self-signed cert), loading, fingerprints.
- Low-level client: status reports, one-shot secret leases, secret listing,
  database backup upload.
- Renewable leases: in-process auto-renewal with the documented timing policy.
- High-level SDK: the recommended interface (lease-and-forget secrets,
  keep-alives, health hook).
- Deploy-time: setting the desired revision of the deployment's **own**
  service (S10).
- A small CLI for non-Go services, deploy scripts, and scheduler-driven
  jobs: `keygen`, `status`, `lease`, `exec`, `secrets`, `backup`,
  `set-desired`.

**Out of scope** — stays private in the server project:

- Admin operations (`/v1/admin/*`): service/deployment registry, key
  registration, secret writes, backup download, reports, audit, and
  setting desired revisions for *arbitrary* services (deployments may set
  only their own — S10). The server project moves these to an internal
  package with its own small mTLS client (deliberate duplication, S1).
- The server, dashboard, and recovery tools.
- Server-side provisioning and operations.

## 3. Module identity, layout & publishing

### Layout (S2, S3)

```
xoba.com/keep              package keep — the SDK (CGO: mattn/go-sqlite3, for backups)
xoba.com/keep/cmd/keep     the CLI — installs as `keep`
```

- **Root package `keep`** (S2): consumers write `import "xoba.com/keep"` and
  call `keep.NewSDK(...)`. The parent project's own integration guide aliased
  its package to `keep` in every example — evidence that this is the natural
  name. (The alternative — a `client` subpackage preserving today's
  `xoba.com/keep/client` import paths — was rejected: it stutters, and the
  three first-party consumers must edit their `go.mod` anyway.)
- **Single package, CGO accepted** (S3): `BackupDatabase` needs a SQLite
  driver (`VACUUM INTO`), today `mattn/go-sqlite3`, which requires CGO.
  It stays in the root package for exact parity with the parent — every
  consumer build therefore needs `CGO_ENABLED=1` and a C toolchain, a cost
  accepted deliberately (the parent's integration guide carried the same
  note: any project already using SQLite has it).
- **Go directive** (S6): the lowest *stable* Go release the code compiles
  with — never a release candidate. (The server pins an RC deliberately; a
  published module must not force toolchain upgrades on consumers.)

### Publishing (S7, S8)

- Development happens on the private origin. The repository history is
  public-by-design from birth (fresh history, hygiene rules in §7).
- The vanity-import binding is **already live**: xoba.com serves, at
  `https://xoba.com/keep?go-get=1`,

  ```html
  <meta name="go-import" content="xoba.com/keep git https://github.com/xoba/keep">
  ```

  so the module path is bound to `github.com/xoba/keep` today (choose a
  different repository only by changing the meta first; repository name and
  module path are otherwise independent).
- **Publication is the moment `github.com/xoba/keep` exists and is public.**
  From that instant the module is fetchable by anyone — and every version
  fetched through proxy.golang.org, *including pseudo-versions of arbitrary
  commits*, is recorded permanently in sum.golang.org. There is no partial
  publication: push nothing to GitHub until the history is meant to be
  public.
- **Tag only after the API settles and the module path is final.** A
  mis-tagged release cannot be re-tagged. Start at `v0.x`; cut `v1.0.0`
  when the extraction completes (§8 phase 4) and the contract has survived
  real fleet use.
- Pre-publication resolution: consumers need a
  `replace xoba.com/keep => <local checkout>` in their own `go.mod` —
  this is the only mechanism that satisfies builds *and* `go mod tidy`
  (tidy ignores `go.work`, and `GOPRIVATE` merely routes fetches direct,
  which cannot resolve an unpublished module). A `go.work` `use` entry
  additionally works for day-to-day builds. After publication, drop the
  `replace` directives; `GOPRIVATE=xoba.com` on developer machines may
  stay (direct fetch works for public repos) or be narrowed to the
  still-private `xoba.com/*` modules.

## 4. API surface (v0)

Semantics are ported from the parent implementation — exactly, except where
a decision below says otherwise (S5); the names below are the extraction
mapping.

**Identity**

```go
keep.GenerateIdentity(dir, name string) (keyid, pubB64 string, err error)
keep.Fingerprint(pub ed25519.PublicKey) string        // sha256 of raw key, hex
```

Writes/reads an identity directory (`cert.pem` + `key.pem`; conventionally
`~/.keep/<name>`). The certificate is a self-signed carrier for the Ed25519
key — its subject conveys no authority (§5).

**Low-level client**

```go
keep.New(identityDir string) (*keep.Client, error)   // talks to api.keepcentral.com (S9)

(c *Client) PutStatus(st Status) error
(c *Client) LeaseSecret(name string) (*Lease, error)
(c *Client) ListSelfSecrets() ([]SecretInfo, error)
(c *Client) BackupDatabase(dbName, srcPath string) (*BackupResult, error)
(c *Client) SetDesiredRevision(revision string) error   // own service only (S10)
(c *Client) LeaseRenewed(ctx, name string, onNew func(*Lease)) (*Renewed, error)

(r *Renewed) Value() (payload []byte, version int64, stale bool)
(r *Renewed) Stop()

keep.DefaultStatus(health string) Status   // revision + client version from build info,
                                           // hostname from the OS, start time from the clock
```

Types: `Status`, `Lease` (+ `PayloadBytes()`), `SecretInfo`, `BackupResult` —
JSON shapes fixed by the wire contract (§5).

The base URL is a hardcoded constant, `https://api.keepcentral.com` (S9);
`New` and `NewSDK` take only the identity directory. `Client.BaseURL`
remains an exported field so the test suite can point at a fake server —
a test seam, not a configuration knob.

**Renewable-lease policy** (unchanged): initial lease synchronous (caller
decides cold-start behavior); refresh at the server's `refresh_after` (~12 h)
plus jitter; exponential backoff from 1 s to 15 min on failure; past
`soft_lease_until` (~24 h) the value is marked stale but **still served** —
`Value` never blocks and the upstream credential does not expire with the
lease; `onNew` fires on version change.

**High-level SDK**: `NewSDK` starts keep-alives immediately (every 5 min
± 1 min jitter; the operator's dashboard shows a deployment offline after 15
silent minutes); `SetHealth` installs a real health claim; `FetchSecret`
leases on first use, then reads from memory; `ListSecrets` names the secrets
available to the deployment's service; `Backup` snapshots and uploads a
SQLite database (stateless; run it periodically — uploads are idempotent);
`Raw` exposes the low-level client; `Close` stops everything. All state is
in memory — a restart re-leases on first use.

**Backup** (`BackupDatabase` / `SDK.Backup`, unchanged): snapshot via
`VACUUM INTO`, validate the SQLite magic, gzip, SHA-256 of the compressed
bytes as idempotency key, upload. All format validation is client-side, as
in the parent.

**CLI** (`keep` — S5): the parent's `keep client …` subcommands promoted to
the top level, plus keygen and the deploy-time write: `keep keygen`, `keep
status`, `keep lease <secret>`, `keep exec <secret> -- <command> [args...]`
(one-shot environment injection — an env var cannot be refreshed after
process start), `keep secrets`, `keep backup <db-name> <sqlite-path>`, and
`keep set-desired <revision>` (for deploy scripts, typically
`keep set-desired $(git rev-parse HEAD)`). There is no server flag and no
`KEEP_SERVER`: the endpoint is built in (S9) — the parent CLI's entire
server-URL resolution (flags, env, operator-database fallback) is not
ported because there is nothing to resolve. Identity dir from `--identity`,
else `KEEP_IDENTITY`, else `~/.keep/client`.
`go install xoba.com/keep/cmd/keep@latest` installs it under the right name
with no extra machinery.

## 5. Wire contract

This section (expanded into `API.md` alongside the implementation) is the
**normative coupling** between the two projects. Nothing else is shared.

**Transport & authentication**

- All requests go to the built-in base URL `https://api.keepcentral.com`
  (S9).
- HTTPS. The server presents a certificate from a public CA, verified
  normally by the client.
- The client presents a self-signed certificate carrying an Ed25519 key.
  The server authorizes by the **SHA-256 fingerprint of the raw public
  key**, registered out-of-band by an administrator. Certificate subject
  and issuer carry no meaning.
- Identity directory layout: `cert.pem`, `key.pem` (PEM, Ed25519).

**Endpoints used by this SDK** (all under mTLS):

| Method & path | Body → Response |
|---|---|
| `PUT /v1/self/status` | `Status` → — |
| `GET /v1/self/secrets` | — → `{"secrets": [SecretInfo…]}` |
| `POST /v1/self/secrets/{name}/lease` | — → `Lease` |
| `POST /v1/self/databases/{name}/backups?uncompressed_size=&created_at=` | gzipped SQLite snapshot → `BackupResult` |
| `POST /v1/self/desired-revision` | `{"revision": "<git-sha>"}` → — |

`POST /v1/self/desired-revision` is **new in this design** (S10): the
parent server adds it as an additive `/v1` change (S4). Like every
`/v1/self/` route, the caller's mTLS identity determines the service — the
request body names no service and can never touch another one. It is the
self-scoped mirror of the admin set-desired operation, and it is
service-scoped: any registered deployment of a service may set that
service's desired revision.

Backup upload headers: `Content-Type: application/vnd.sqlite3+gzip`,
`Content-Digest: sha-256=:<base64>:`, `Idempotency-Key: sha256:<hex>` —
retrying identical content can never duplicate a backup. **A positive
declared `Content-Length` is required**: the server enforces its size cap
before reading and answers `411 Length Required` for chunked bodies, and
rejects uploads whose actual byte count differs from the declared length.
This is why the client gzips to a temp file (digest and length must be
known) before uploading.

Error envelope: non-2xx with `{"error": "message"}`. The client caps
response reads at 8 MiB on the JSON endpoints and 1 MiB on the
backup-upload response.

`Lease` timing fields (`issued_at`, `refresh_after`, `soft_lease_until`,
RFC 3339) drive the renewal policy in §4. The payload travels in two
fields, both exported on `Lease`: `payload_base64` — always present,
authoritative, decoding to the exact stored secret bytes (by convention a
small flat JSON document) — and `payload`, a raw-JSON convenience echo the
server includes when the secret parses as JSON. The SDK reads only
`payload_base64`.

**Stability rules (S4)**

- `/v1` is frozen **additive-only**: the server may add fields and
  endpoints; it never removes, renames, or changes the semantics of
  anything this contract names.
- The SDK must tolerate unknown response fields (Go's default JSON
  behavior — preserve it).
- A breaking change means `/v2` on the server and a new major version of
  this module. Expected approximately never, in keeping with keep's
  append-only ethos.

## 6. Testing & conformance

- **Unit/contract tests**: an `httptest` fake server implementing §5
  verbatim lives in this repository and doubles as an executable statement
  of the contract; tests point `Client.BaseURL` at it (the one sanctioned
  use of that field). mTLS paths get real self-signed certs in
  `t.TempDir()`.
- **Integration smoke test** (env-gated, skipped by default): when
  `KEEP_TEST_IDENTITY` names a registered identity directory, a
  deliberately read-mostly smoke test (status report + secret listing)
  runs against the real deployment at the built-in endpoint. No
  identities are ever committed.
- No cross-module test imports either (S1): the server project maintains
  its side of the contract with its own tests. Drift between the two is
  caught by the integration suite and by the fleet itself.

## 7. Publication hygiene

This repository is public-by-design from its first commit; treat every
commit as already published.

- **Never commit content containing**: account IDs, cloud resource
  IDs/ARNs, IP addresses, email addresses, key material or key
  fingerprints, or hostnames of private machines — the private git host is
  referred to only as "the private origin." Git author/committer metadata
  is the one place an identity necessarily rides along with history:
  choose the author identity for this repository deliberately (a public
  or noreply address if preferred) *before* anything reaches GitHub.
- The only endpoint that may appear anywhere is the built-in one:
  `api.keepcentral.com` (S9), plus keepcentral.com as the project's
  homepage and the name of the private server module this SDK was
  extracted from. No other operator hostnames, ever. xoba.com appears
  only as this module's vanity-import host.
- `make scan` (gitleaks + trufflehog over full history) before any push —
  same gate as the server project.
- The default status report includes the machine's hostname
  (`HostMetadata`); that flows only to the consumer's own keep server at
  runtime and never into this repository.

## 8. Migration plan

Phased; each phase leaves both projects working.

- **Phase 0 — design** (this document). Agree the decisions in §9.
  **Done 2026-07-16.**
- **Phase 1 — implement**: port `client.go`, `renew.go`, `sdk.go`, the
  identity functions, and the client CLI subcommands into this module per
  §3–§4. Write `API.md` and the fake-server test suite. Add `AGENTS.md`
  (hygiene rules of §7, layout, commands) and `Makefile` (`build`, `vet`,
  `test`, `scan`). Private origin only. In tandem, the parent server adds
  the one new route this design introduces — `POST
  /v1/self/desired-revision` (additive per S4, scoped per S10).
  **Done 2026-07-16**: SDK + CLI implemented with contract tests; the
  server route shipped and was verified live (401 without a client cert;
  end-to-end write with a deployment identity).
- **Phase 2 — first-party consumers**: the three existing consumers import
  `xoba.com/keep/client` and require `xoba.com/keep`, resolved by
  `replace`/`go.work` to the server checkout — which no longer declares
  that path (the server module was renamed), so their builds are broken
  until this phase. Per consumer: change imports to `xoba.com/keep` (root
  package — call sites are otherwise untouched), keep
  the `require xoba.com/keep` line, point the `replace` directive (in
  `go.mod` — required for `go mod tidy` even where a `go.work` exists) at
  this checkout, `go mod tidy`, rebuild, verify against the live fleet.
  Deploy scripts may then adopt `keep set-desired` per project, at leisure.
  **Done 2026-07-16**: all three consumers switched, rebuilt, and verified
  against the live fleet (running = desired everywhere, all healthy);
  their deploy flows now publish desired revisions with their own
  deployment identities via the self-scoped route — none uses the admin
  identity anymore.
- **Phase 3 — publish**: create `github.com/xoba/keep` (the vanity meta
  already points there — §3), push, tag `v0.1.0`. Publication happens the
  moment the repository is public; there is no partial state. Consumers
  drop their `replace` directives and fetch normally.
  **Done 2026-07-16**: published (created private, inspected, flipped
  public) and tagged `v0.1.0`; verified from scratch modules via
  `GOPROXY=direct`, via proxy.golang.org with sum.golang.org
  verification, and via `go install` of the CLI. All three consumers
  dropped their `replace` directives, pinned `v0.1.0`, and were rebuilt
  and verified against the live fleet.
- **Phase 4 — extract from the server project**: delete `client/` and the
  client CLI subcommands from `keepcentral.com`; move the admin operations
  to an internal package with its own minimal mTLS client; rewire the admin
  CLI and dashboard; update its docs (integration guide points here; design
  decision record amended; the server binary becomes server + admin +
  dashboard + recovery only). The two modules never import each other.
  **Done 2026-07-16**: `client/` and the client subcommands deleted, admin
  operations moved to an internal package (server decision D24), docs
  rewired, and the server deployed. The extraction is complete; `v1.0.0`
  (S8) is unblocked and waits only on fleet soak.

Rollback at any phase is trivial: the parent keeps its `client` package
until phase 4, and consumers can re-point a `replace` directive in one line.

## 9. Decision record

| # | Decision | Rationale |
|---|---|---|
| S1 | **Full independence**: no import dependency between `xoba.com/keep` and `keepcentral.com`, in either direction, ever. The wire contract (§5) is the only coupling. | A public module importing a private one is unresolvable for consumers; the reverse couples the server's release cadence to a public API. Cost: ~200 lines of deliberately duplicated identity + HTTP plumbing on the server side. Cheap, and it keeps both sides free. |
| S2 | Root package `keep` (`import "xoba.com/keep"`), not a `client` subpackage. | The parent's own docs aliased `client` to `keep` in every example. Consumers edit `go.mod` regardless; path stutter (`keep/client`) serves no one. |
| S3 | **REVISED:** single package — backup (and its `mattn/go-sqlite3` / CGO dependency) stays in the root package; the SDK keeps its `Backup` method verbatim. A subpackage split isolating CGO was designed and deliberately rejected. | Exact parity with the proven fleet behavior, and an API identical to the parent's, beat dependency purity: the operator accepts the CGO requirement for all importers (services doing backups use SQLite already). A pure-Go driver (`modernc.org/sqlite`) remains a future option that would lift the CGO requirement without any API change. |
| S4 | `/v1` contract is additive-only; breaking change ⇒ server `/v2` + SDK major version. | Two independent modules need a stability promise, not shared types. Matches keep's append-only migration ethos. |
| S5 | **RESOLVED:** the CLI is named `keep` (`xoba.com/keep/cmd/keep`), carrying the parent's `client` subcommands at the top level plus `keygen`. | On a service machine, `keep` is the natural name and the client CLI is the only keep binary present. Known cost: on machines that also carry the *server* binary (operator workstation, the instance), the names collide — those hosts keep the server binary and don't install this CLI, or install it outside `PATH` precedence. From this project's view, `keep` *is* the client. |
| S6 | Go directive pinned to a stable release, never an RC. | The directive is a floor imposed on every consumer's toolchain. The server's RC pin is its own deliberate, private choice. |
| S7 | Public-by-design hygiene (§7): fresh history, forbidden-identifier rules, `make scan` gate; the built-in endpoint is the only hostname that ever appears. | Retroactive scrubbing of a published git history is somewhere between painful and impossible; far cheaper to never commit anything that couldn't be public. |
| S8 | Version `v0.x` until phase 4 completes; `v1.0.0` afterward. Tags only after the module path and API are final. | sum.golang.org records the first fetch of each version permanently. |
| S9 | The endpoint is hardcoded: `https://api.keepcentral.com`. No server flag, no env var, no config file; the exported `Client.BaseURL` field is a test seam, not a knob. | Honesty about purpose: this SDK serves the author's fleet against the keepcentral.com deployment, and a configuration surface would advertise a generality the project doesn't (yet) promise. Adding configurability later is additive and non-breaking; the reverse is not. Supersedes the parent's "no endpoint defaults in code" convention *for this repo* — that rule protected a server meant for many operators; this SDK client is explicitly for one. |
| S10 | Deployments may set the desired revision of **their own service** via the new self-scoped `POST /v1/self/desired-revision`; every other admin function stays exclusively in the server project's admin CLI. | Client projects deploy themselves and should record "what should be running" at deploy time without borrowing admin credentials; the mTLS identity scopes the write to the caller's own service (it is service-wide: any deployment of the service may set it). Accepted trade-off: a compromised deployment key could rewrite its own service's desired revision and mask drift on the dashboard — acceptable for a personal fleet, revisit if drift ever becomes a security control rather than an operational signal. |

## Open questions

1. **RESOLVED 2026-07-16:** `v0.1.0` shipped at phase 3, the same day
   phase 2 put the fleet on the SDK — the soak was hours, accepted
   deliberately: v0.x signals instability, and the consumers are all
   first-party.
