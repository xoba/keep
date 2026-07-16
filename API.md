# keep wire contract (v1)

This document is the **normative coupling** between this SDK
(`xoba.com/keep`) and the keep server. The two projects share no code; an
implementation on either side is correct iff it conforms to this contract.
The fake server in `keep_test.go` implements it verbatim.

Base URL: `https://api.keepcentral.com` (built in; design S9).

## Transport & authentication

- HTTPS. The server presents a certificate from a public CA, verified
  normally by the client.
- The client presents a **self-signed certificate carrying an Ed25519
  key**. The server authorizes by the SHA-256 fingerprint (lowercase hex)
  of the raw 32-byte public key, registered out-of-band by an
  administrator. Certificate subject and issuer carry no meaning.
- Identity directory layout: `cert.pem`, `key.pem` (PEM; PKCS#8 Ed25519
  key), as written by `keep keygen`, mode 0600.
- Failed auth: `401` (no/unknown/disabled key, non-Ed25519 key) or `403`
  (key registered but of the wrong principal type for the route).

## Error envelope

Every non-2xx response carries `{"error": "<message>"}`. The client caps
response reads at 8 MiB on the JSON endpoints and 1 MiB on the
backup-upload response.

## Endpoints

All under mTLS; the caller's identity determines the service and
deployment — no request names them.

### `PUT /v1/self/status`

Body (JSON, ≤64 KiB):

```json
{
  "health": "healthy",
  "running_revision": "<git sha, optional>",
  "started_at": "<RFC3339, optional>",
  "client_version": "<module version, optional>",
  "host_metadata": {"hostname": "..."}
}
```

Any valid JSON is accepted (the shape above is the convention, not a
requirement); an invalid body gets `400`, and a body over 64 KiB gets
`413`. The server stores only the latest status per deployment. Cadence:
the SDK reports immediately, then every 5 minutes ± 1 minute of jitter;
after 15 silent minutes the deployment shows offline.

### `GET /v1/self/secrets`

Response:

```json
{"secrets": [{"service": "...", "name": "...", "version": 1,
              "media_type": null, "updated_at": "<RFC3339>"}]}
```

Metadata only, never values.

### `POST /v1/self/secrets/{name}/lease`

Response:

```json
{
  "name": "...",
  "version": 1,
  "media_type": null,
  "issued_at": "<RFC3339>",
  "refresh_after": "<RFC3339, ~12h out>",
  "soft_lease_until": "<RFC3339, ~24h out>",
  "payload_base64": "<base64 of the exact secret bytes>",
  "payload": {"present": "only when the secret parses as JSON"}
}
```

`payload_base64` is authoritative and always present; `payload` is a
raw-JSON convenience echo. The SDK reads only `payload_base64`. Unknown
secret: `404`.

Client renewal policy: refresh at `refresh_after` plus jitter (up to
10 min); exponential backoff from 1 s to 15 min on failure; past
`soft_lease_until` the value is marked stale but still served — the
upstream credential does not expire with the lease.

### `POST /v1/self/databases/{name}/backups?uncompressed_size=N&created_at=<RFC3339>`

Body: a gzipped SQLite database snapshot. Required:

- **A positive declared `Content-Length`** — chunked bodies get
  `411 Length Required`; a body whose byte count differs from the declared
  length is rejected.
- `Content-Type: application/vnd.sqlite3+gzip`
- `Content-Digest: sha-256=:<base64 of the raw sha-256 of the compressed
  body>:`  — mismatch is rejected.
- `Idempotency-Key` (≤128 bytes; the client uses `sha256:<hex>` of the
  compressed body) — retrying identical content can never duplicate a
  backup; a retry of a completed upload returns the original record.
- `uncompressed_size` query parameter (positive).

Response:

```json
{"id": "...", "service": "...", "database_name": "...",
 "state": "available", "size_bytes": 123, "uncompressed_size_bytes": 456,
 "sha256": "<hex of compressed body>", "received_at": "<RFC3339>"}
```

Other responses: `404` for an unregistered database name; `413` when the
declared length exceeds the server's backup size limit (default 2 GiB,
server-configurable); `409` when an upload with the same idempotency key
is still in progress (retry later — only a *completed* retry returns the
original record).

### `POST /v1/self/desired-revision`

Body: `{"revision": "<git sha or other revision string>"}` (required,
non-empty). **The request body is strict**: unknown fields are rejected
with `400`. Records the desired revision of the **caller's own service**
(design S10) — the self-scoped mirror of the admin operation. Any
registered deployment of a service may set it. Response:

```json
{"service": "...", "desired_revision": "..."}
```

## Stability rules (design S4)

- `/v1` is frozen **additive-only**: the server may add fields and
  endpoints; it never removes, renames, or changes the semantics of
  anything this contract names.
- Clients must tolerate unknown response fields.
- A breaking change means `/v2` on the server and a new major version of
  this module. Expected approximately never.
