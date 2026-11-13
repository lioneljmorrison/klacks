# klacks

A self-hosted, embeddable messaging core in Go with Signal-protocol
end-to-end encryption. The server only ever stores and relays ciphertext.

## Quick start

Needs Go (version in `go.mod`), Docker with Compose, and `make`.

```sh
make env          # create .env from .env.example (edit ports/DSNs if needed)
make up           # start PostgreSQL + ScyllaDB, wait until healthy
make migrate-up   # apply migrations to both stores
make run          # build and run the server
curl localhost:8080/readyz
```

`make` on its own lists every target.

## Everyday targets

| Target | What it does |
|---|---|
| `make build` / `make run` | Build `bin/klacks` / build and serve |
| `make check` | `go vet` + golangci-lint + unit tests (what CI runs) |
| `make test` | Unit tests only, no Docker needed |
| `make test-integration` | Unit + integration tests against the local stack |
| `make up` / `down` / `nuke` | Start / stop / stop and delete data |
| `make logs SERVICE=scylla` | Follow one service's logs |
| `make psql` / `make cqlsh` | Shells into the local stores |
| `make migrate-create STORE=postgres NAME=add_rooms` | New empty up/down pair |
| `make migrate-up` / `migrate-version` | Apply / show versions (both stores) |
| `make migrate-down STORE=scylla N=1` | Roll back one store |
| `make migrate-force STORE=… TO=N` | Clear a dirty store after a manual fix |

## Configuration

Defaults, then an optional JSON file (`-config` or `KLACKS_CONFIG`), then
`KLACKS_*` environment variables. See [.env.example](.env.example) for the
variables, and run `make config` to print the effective configuration with
secrets redacted.

The Compose stack publishes Postgres on `127.0.0.1:55432` (clear of a local
Postgres on 5432) and ScyllaDB on `127.0.0.1:9042`. Override them with
`KLACKS_DEV_POSTGRES_PORT` and `KLACKS_DEV_SCYLLA_PORT`.

## Layout

```
cmd/klacks           the server binary (serve, migrate, config)
internal/config      configuration loading and validation
internal/logging     slog setup (text in dev, JSON in prod)
internal/api         transports (HTTP now; WebSocket and gRPC later)
internal/core        rooms, sequencing, fan-out, resume
internal/store       PostgreSQL + ScyllaDB access, migrations
migrations/          embedded schema migrations for both stores
pkg/chat             the public, importable ChatService
```

## Endpoints

- `GET /healthz`: liveness. Always 200 while the process is serving.
- `GET /readyz`: readiness. 200 when PostgreSQL and ScyllaDB both answer,
  503 otherwise. On shutdown it reports `draining` for `KLACKS_HTTP_DRAIN_DELAY`
  (default 0) before the listener closes, so load balancers can stop routing
  traffic. In-flight requests then get `KLACKS_HTTP_SHUTDOWN_TIMEOUT` to finish.
