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
| `make proto` | Lint the protos and regenerate `api/gen` |
| `make test-web` | Regenerate the dev UI's interop vectors and run its Node tests |

## Test clients

Two test clients exist for exercising a running dev server end to end
(rooms, resume, backpressure, E2EE interop). Both need `env=dev`, whose
authenticator trusts any claimed identity. Neither requires a UUID: rooms,
users and devices accept plain human names, which resolve deterministically
to UUIDs (see [Names](#names)).

- **`cmd/testchat`** — a Go CLI built on the reference client
  (`client/`). Room management goes through the server's dev room API;
  messaging speaks E2EE over REST + WebSocket:
  `go run ./cmd/testchat -user alice` (add `-base` when the server is not
  on `:8090`). Then `/create standup`, `/invite standup bob`,
  `/join standup`, `/send standup hello`. `/drop` simulates an outage,
  `/dial` reconnects, `/resume` replays, `/members` refreshes the member
  list, `/status` reports the session.
  The device's keys and ratchet sessions persist in `~/.klacks-testchat`,
  so the same `-user` is the same device with the same sessions on every
  run: messages peers seal while the CLI is down, or sent over its
  sessions before a restart, decrypt after it (`-fresh` starts over with
  new keys and no sessions). After a `make nuke`, start each CLI device
  with `-fresh`: room seqs restart at 1, and saved sessions remember the
  seqs their peers' initiations arrived at, so they would refuse a peer's
  new session as a replay of an old one. Sessions are saved before every publish and after every
  delivery, so a crash can't make the CLI reuse a message key. `/send`
  watches a room live; `/join` or `/resume` replay its history.
- **The dev UI** — a browser client with full E2EE (X3DH + Double Ratchet
  in WebCrypto plus its own ChaCha20-Poly1305), served by the dev server
  itself at `GET /devui` (same origin, because `/ws` rejects cross-origin
  upgrades). Three steps, no UUIDs and no jargon: type your name and hit
  Start (keys, bundle registration and connecting are automatic), type a
  room name and hit Open (creates it if it doesn't exist, joins if it
  does), chat. Invite people by name from the chat; a reload offers
  "Continue as …" with the same keys and sessions, and reopening a room
  resumes after the last message this browser processed. The member list
  is refreshed from the server before every send. Sender-key group
  broadcasts are reported, not decrypted.

The browser client's crypto is kept byte-compatible with the Go reference
by test vectors (`client/jsvectors_test.go` generates them from pinned
keys; `node --test internal/api/devui/interop/` replays them through the
JavaScript) — `make test-web` runs both halves, including the name
mappings.

## Names

Test-client names resolve to UUIDs with UUIDv5 (SHA-1) under one fixed
namespace (`internal/names`, mirrored by `internal/api/devui/web/js/names.mjs`):

- user `alice` → `v5(ns, "user/alice")`
- device `phone` of user alice → `v5(ns, "device/<alice's user UUID>/phone")`
- room `standup` → `v5(ns, "room/standup")`

No server state, no shared storage: every client resolves the same name to
the same UUID offline. A canonical UUID is accepted anywhere a name is and
takes precedence, so nothing blocks explicit identities.

## Dev-only endpoints (env=dev)

Alongside `/ws` and the prekey API, a dev server also serves:

- `GET /devui` — the browser test client above.
- `POST /v1/dev/rooms` — create a room (optional caller-chosen
  `room_id`, `kind` dm/group/space, `members` to invite). The
  authenticated user becomes its owner.
- `POST /v1/dev/rooms/{room}/members` — invite one user
  (`user`, optional `role`).
- `DELETE /v1/dev/rooms/{room}/members/{user}` — remove a member.
- `GET /v1/dev/rooms/{room}/members` — list members.

These shim `pkg/chat`'s room management over REST for testing only; none
of it exists outside env=dev.

## Configuration

Defaults, then an optional JSON file (`-config` or `KLACKS_CONFIG`), then
`KLACKS_*` environment variables. See [.env.example](.env.example) for the
variables, and run `make config` to print the effective configuration with
secrets redacted.

The Compose stack publishes Postgres on `127.0.0.1:55432` (clear of a local
Postgres on 5432) and ScyllaDB on `127.0.0.1:9042`. Override them with
`KLACKS_DEV_POSTGRES_PORT` and `KLACKS_DEV_SCYLLA_PORT`.

## Embedding

`pkg/chat` is importable: open a `ChatService` on both migrated stores,
create rooms, add members, post, and subscribe. [examples/meetings](examples/meetings)
is a toy meeting scheduler that shows the whole flow — a meeting's room is
created when the meeting is, its attendees join, and its messages arrive
live:

```sh
make up migrate-up
go run ./examples/meetings
```

Encryption happens entirely in client apps: the server never sees plaintext
and treats all crypto as opaque bytes, so any client library that speaks the
wire format interoperates. See [docs/protocol.md](docs/protocol.md)
(§ Encryption) for the wire format, the Go reference implementation, and the
licensing note on libsignal.

## Layout

See [docs/architecture.md](docs/architecture.md) for a diagram of how the
packages, transports and stores connect.

```
cmd/klacks           the server binary (serve, migrate, config)
cmd/testchat         the Go CLI test client (rooms + E2EE messaging)
api/proto            protobuf definitions; api/gen holds generated code
examples/meetings    the toy meeting scheduler, an embedding example
internal/config      configuration loading and validation
internal/logging     slog setup (text in dev, JSON in prod)
internal/api         transports (HTTP now; WebSocket and gRPC later)
internal/api/devui   the browser test client, served at /devui in dev
internal/api/grpcapi the gRPC adapter over pkg/chat (not served yet)
internal/core        rooms, sequencing, fan-out, resume
internal/names       human name → UUID mapping (test clients)
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
