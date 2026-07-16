# keep SDK

The Go SDK and CLI for [keep](https://keepcentral.com), a passive custodian
for a small fleet of services: deployment status keep-alives, leased
secrets, and SQLite database backups, over mTLS with pinned Ed25519 client
keys. Keep records, stores, and provides — it never causes another service
to act.

This module is the deployment-side client of the author's own fleet: the
endpoint (`https://api.keepcentral.com`) is built in, and that server's key
registry only ever contains the author's deployments. It is published to
make consuming projects easy to build — not (yet) as a general-purpose
client for other operators. `docs/design.md` is the design record;
`API.md` is the wire contract.

## SDK

```go
import keep "xoba.com/keep"

sdk, err := keep.NewSDK(os.ExpandEnv("$HOME/.keep/myapp-prod-macbook"))
if err != nil {
    log.Fatal(err)
}
defer sdk.Close() // stops keep-alives and renewals

sdk.SetHealth(func() string { return "healthy" }) // consulted at each keep-alive
v, err := sdk.FetchSecret("db-creds")             // leased once, auto-renewed (~12 h)
_, err = sdk.Backup("main", "myapp.db")           // VACUUM INTO, gzip, upload; idempotent
```

Construction immediately starts status keep-alives every 5 minutes; leases
and keep-alive state live in memory only, so a restart simply re-leases on
first use. Building needs CGO (`mattn/go-sqlite3`, for backups).

## CLI

```bash
go install xoba.com/keep/cmd/keep@latest

keep keygen                             # create an identity; register the printed public key
keep status                             # report deployment status
keep secrets                            # list available secret names
keep lease <name> --stdout              # one-shot lease
keep exec <name> -- <command> [args]    # env injection at process start
keep backup <db-name> <sqlite-path>     # snapshot + upload
keep set-desired "$(git rev-parse HEAD)"  # deploy-time: publish the desired revision
```

The identity directory comes from `--identity`, else `$KEEP_IDENTITY`, else
`~/.keep/client`. There is no server flag: the endpoint is built in.

## License

MIT — see [LICENSE](LICENSE).
