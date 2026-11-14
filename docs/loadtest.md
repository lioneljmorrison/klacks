# Load test (S-34)

Goal (plan Phase 5, G-8): **10k connections, sustained 1k msg/s fan-out,
p99 delivery < 200 ms**, plus p99 ScyllaDB insert and resume-read latency,
room lock hold time and Postgres pool use.

## Tool

`cmd/klacksload` speaks the wire protocol directly against a dev server
(dev auth, `/v1/dev/rooms`), with opaque payloads; the server never
decrypts, so E2EE adds nothing to its load. Each payload carries its send
time; generator and server share the host clock.

```sh
# server: env=dev, metrics on, a pool sized for the load (see Results)
KLACKS_METRICS_ADDR=127.0.0.1:9090 \
KLACKS_POSTGRES_DSN='postgres://…?sslmode=disable&pool_max_conns=60' klacks serve

go run ./cmd/klacksload -base http://127.0.0.1:8080 -metrics http://127.0.0.1:9090 \
    -rooms 1000 -members 10 -rate 1000 -duration 60s -warmup 10s -run-id <uuid>

# restart the server (empties the in-memory replay buffer), then measure
# cold resumes, which are ScyllaDB range reads:
go run ./cmd/klacksload -phase resume -rooms 1000 -members 10 -run-id <same uuid> \
    -base … -metrics …
```

- `rooms × members` connections, one user each; rooms created through the
  dev API.
- Publishes are spread round-robin over rooms (and members within a room)
  at `-rate` per second; every other member receives each one, so
  deliveries/s = rate × (members − 1).
- Latency = receive time − send time, at every receiver, for messages sent
  in the measured window. Receivers also check each room's seqs are
  gap-free.
- Server-side p99s come from `/metrics` histograms (upper bound of the
  bucket that reaches 99%, so coarse: buckets double from 0.5 ms).

## Results (2026-11-14)

Single host: 24 cores, WSL2, Docker Compose PostgreSQL 18 and ScyllaDB
2026.3 (one node each), server and generator on the same machine.
1,000 rooms × 10 members = **10,000 connections**, **1,000 publishes/s**
(9,000 deliveries/s), 60 s measured after 10 s warmup, 256-byte payloads.

| Postgres pool | Delivery p50 | p95 | p99 | max | Gaps / errors |
|---|---|---|---|---|---|
| 24 (pgx default: max(4, CPUs)) | 11.8 ms | 266 ms | **719 ms** ✗ | 911 ms | 0 / 0 |
| 60 (`pool_max_conns=60`) | 10.2 ms | 29.4 ms | **51.8 ms** ✓ | 125 ms | 0 / 0 |

Both runs: every expected delivery arrived (counts are within ~100 of
540,009; the excess is messages published at the warmup boundary), no
slow-consumer disconnects, connecting 10k clients took under 1 s.

Server side (pool 60): room lock held p50 ≤ 8 ms, p99 ≤ 64 ms; ScyllaDB
insert p50 ≤ 1 ms, p99 ≤ 4 ms; pool **saturated** (60 of 60 at peak
samples). Cold resume after a restart (996 rooms, ~70 messages each, all
read from ScyllaDB): range read p50 ≤ 4 ms, **p99 ≤ 64 ms**.

**G-8 passes with the pool sized for the load; it fails with the
default pool.**

## Findings

- **The hotspot is the PostgreSQL transaction inside the room lock, not
  ScyllaDB.** A publish holds a pool connection and the room's row lock
  for ~8 ms at p50, of which the ScyllaDB insert is ~1 ms; the rest is
  ~7 round trips (BEGIN, SET LOCAL timeouts, SELECT … FOR UPDATE, role
  check, nextval, UPDATE, COMMIT) and the commit's WAL flush. At 1k
  publishes/s that keeps ~8 connections busy on average and far more in
  bursts, so the default pool (24 here) queues publishes and the tail
  explodes. Sizing the pool fixes it here; fewer round trips per publish
  would raise the ceiling (proposed as a follow-up story).
- **Pool sizing rule of thumb** (in `docs/operations.md`):
  `pool_max_conns` ≥ peak publishes/s × p99 lock hold, with headroom, and
  within PostgreSQL's `max_connections` across all klacks nodes (the
  default `max_connections = 100` refused a 100-connection pool on this
  shared instance).
- Lock hold p99 (≤ 64 ms) is far above p50: commit latency spikes on this
  WSL/Docker volume. Production PostgreSQL on real disks should do better;
  watch `klacks_room_lock_held_seconds`.
- Not covered: multiple server nodes, a remote database, rate limits (S-32
  limits are off on this branch's base).

## Performance gate (S-53)

`make perf` turns the load test into a pass/fail check. It builds
`klacks` and `klacksload`, then `scripts/perf.sh`:

1. applies migrations to the running stack (`make up` first);
2. starts a dev server on `127.0.0.1:18080` (metrics `:19090`) with
   `pool_max_conns=60` appended to `KLACKS_POSTGRES_DSN`;
3. runs the G-8 profile with `-max-p99 200ms`;
4. stops the server whatever the result, and exits with klacksload's
   status. The report and server log go to `bin/perf/`.

A run **fails** on any of: delivery p99 over the limit, a seq gap, an
error frame, a publish write error, a slow-consumer disconnect, more than
0.1% of expected deliveries missing (the drain window can cut off a few
in flight; real loss also shows as a gap or a short resume), or a room
that doesn't finish the resume phase.

It runs locally, not in CI (GitHub's 4-vCPU runners can't carry 10k
connections), and must pass before a `dev`→`main` PR merges. Every knob
is an environment variable: `PERF_ROOMS`, `PERF_MEMBERS`, `PERF_RATE`,
`PERF_DURATION`, `PERF_WARMUP`, `PERF_MAX_P99`, `PERF_POOL`,
`PERF_HTTP_PORT`, `PERF_METRICS_PORT`, `PERF_OUT`. With prebuilt
binaries, run `KLACKS=… KLACKSLOAD=… scripts/perf.sh` directly.

### Gate runs (2026-11-14)

Each machine runs the server, generator, PostgreSQL 18 and ScyllaDB
2026.3 (`--smp 1 --memory 750M`, as in `compose.yaml`) together, alongside
its usual services.

| Machine | Hardware | Profile | Delivery p99 | Lock hold p50 / p99 | Pool peak | Result |
|---|---|---|---|---|---|---|
| M4 | Apple M4, 10 cores, 16 GB; databases in a colima VM (4 CPU, 4 GB) | G-8: 10k conns, 1k msg/s | 6.2 ms | ≤ 2 ms / ≤ 8 ms | 50 / 60 | **pass** |
| lab-hermes | Intel i3-6100T, 4 threads, 7 GB, Debian 13 | G-8 | 8.63 s | ≤ 64 ms / ≤ 128 ms | 60 / 60 | fail: p99, 39,019 of 540,009 still in flight |
| lab-hermes | same | 1k conns, 100 msg/s, 30 s | 22 ms | ≤ 8 ms / ≤ 64 ms | 4 / 60 | **pass** |
| nas | AMD A10-5700, 4 cores, 30 GB, Debian 13 | — | — | — | — | not run: ScyllaDB exits with SIGILL (illegal instruction) on this CPU, which has AVX but not AVX2; the exact instruction was not identified |

On lab-hermes the full profile saturates the pool and the room lock
(p50 64 ms), so publishes queue and delivery falls seconds behind; no
seq gaps, no error frames, and every room resumed, so nothing was lost.
On macOS, klacksload dials 100 at a time: at 200, a local server reset
connections (`kern.ipc.somaxconn` is 128 there).
