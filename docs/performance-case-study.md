# Performance case study: three small machines (S-54)

How klacks performs on three ordinary machines, what limits each one, and
which tuning moves the limit. All the numbers come from 150 load runs on
2026-11-14 using the performance gate (`make perf`, [loadtest.md](loadtest.md)).
The raw data is in `perf-data/` (one JSON line per run). `perf-data/summary.md`
is the full table.

## Summary

| Machine | Sustainable rate, stock settings | Bottleneck | Best tuning measured | Rate sustained with it |
|---|---|---|---|---|
| M4 (Apple M4, databases in a 4-CPU colima VM) | **4,000 msg/s** (36k deliveries/s) | PostgreSQL time per publish inside the room lock | S-48 + `synchronous_commit=off` | **≥ 5,000 msg/s** (p99 66 ms) |
| WSL (Ryzen 9 9900X, 24 threads) | **2,000 msg/s** | Commit flush (WAL fsync) on WSL's virtual disk | `synchronous_commit=off` | **≥ 4,000 msg/s** (p99 31 ms; 22 ms with S-48) |
| lab-hermes (i3-6100T, 4 threads, 7 GB) | **~500 msg/s** | CPU: four threads shared by server, both databases and the generator | S-48 | 600 msg/s, still near the limit |

*Sustainable* means every repeat passed the gate at 10,000 connections
(1,000 rooms × 10 members): p99 delivery under 200 ms, no seq gaps, no error
frames and no lost deliveries. The plan's G-8 target (1,000 msg/s) passes on
M4 and WSL with stock settings, but not on lab-hermes.

What the data says, in short:

- **Past the limit, nothing degrades gracefully.** Each machine goes from
  tens of milliseconds to seconds within one rate step, because publishes
  queue for the room lock and pool faster than they drain.
- **Overload shows up as latency, never as loss.** Across all 150 runs
  there were zero seq gaps, error frames, publish errors and slow-consumer
  disconnects, and every room finished its resume. Missing deliveries
  appear only in overloaded runs, and they are backlog still draining when
  the measurement ended.
- **The cost is PostgreSQL, not ScyllaDB.** ScyllaDB insert p50 was ≤ 2 ms
  on every passing run on every machine. The room lock hold (seven Postgres
  round trips plus a commit) is what grows.
- **Which fix helps depends on the machine.** On a fast CPU with a slow disk
  flush (WSL), `synchronous_commit=off` doubled capacity and S-48 did nothing.
  On a fast CPU with a fast disk (M4), S-48 cut p99 at 4,000/s from 96 ms to
  28 ms. On a slow CPU (lab-hermes), neither moved it much.
- **Pool size matters only near the limit, and 60 is about right.** 30
  collapsed M4 and WSL at their working rates. 90 bought a little on M4 and
  made WSL worse.

## Method

**Workload.** `cmd/klacksload` against a dev server on the same machine:
1,000 rooms × 10 members, so 10,000 WebSocket connections. 256-byte
payloads; every publish is delivered to the 9 other members. Only the
publish rate varies, so one variable changes at a time. Each run is 10 s of
warmup plus 30 s measured. Latency is receive time minus send time, taken at
every receiver on one clock, so it is exact. Server figures come from
`/metrics` histograms whose buckets double from 0.5 ms, so they are upper
bounds: "≤ 16" means somewhere in 8–16 ms, and a one-bucket difference isn't
a finding.

**Runs.** `scripts/perf-sweep.sh` runs `scripts/perf.sh` (the gate) once per
plan line and appends each run to the dataset, pass or fail. Each run starts
a fresh server. The databases persist across a machine's whole sweep.

- **At least 3 repeats per point.** Tables show the **median with the
  min–max range**, never the best run.
- **Repeats interleave.** Rate sweeps go up, down, then up again. A/B
  comparisons run A, B, C, A, B, C…, never AAA BBB, so drift and other
  load on the host spread across all the variants.
- **Drift checks.** Each sweep re-ran an early point at the end. M4 was
  identical (1,000/s: p99 6.0 ms at 17:24 and at 18:03). lab-hermes was no
  worse (300/s: 74 → 24 ms). WSL was not stable: see Limitations.

**Passes.**
1. A rate sweep on each machine.
2. Finer rates around each machine's limit, then tuning (pool 30/60/90,
   `synchronous_commit` on/off, S-48 vs base) at a rate just below the limit.
3. The tuning combinations at a rate just above the stock limit, to see
   whether the limit moves.

Then one cold-resume measurement per machine.

**Variants.**

| Variant | What it is |
|---|---|
| `base` | This branch's server: 7 PostgreSQL round trips per publish. |
| `s48` | The server built from `s48-fewer-roundtrips` (PR #25): 5 round trips (BEGIN and its `SET LOCAL`s in one message; the role check and `nextval` in one statement). Same schema. |
| `SYNC=off` | PostgreSQL `synchronous_commit = off` (`ALTER SYSTEM` + reload, reset afterwards). |
| pool | `pool_max_conns` on the server's DSN. |

### Machines

| | M4 | WSL | lab-hermes |
|---|---|---|---|
| CPU | Apple M4: 4 performance + 6 efficiency cores | AMD Ryzen 9 9900X: 12 cores / 24 threads | Intel i3-6100T: 2 cores / 4 threads |
| RAM | 16 GB | 61 GB | 7 GB, ~2 GB free with its usual services |
| Disk | Apple SSD (AP0256Z) | WSL2 virtual disk | SanDisk SATA SSD, 128 GB, 94% full |
| OS | macOS 27.0.1 | WSL2, Linux 6.18 | Debian 13.6 |
| Databases | Docker in colima (4 CPU, 4 GB VM) | Docker | Docker |
| klacks + generator | native, same machine | same | same |

Databases: PostgreSQL 18.7 and ScyllaDB 2026.3.5 with `compose.yaml`'s
settings (`--smp 1 --memory 750M`), and PostgreSQL defaults otherwise.
Server and generator are Go 1.27.4.

## Rate sweeps (stock: pool 60, `synchronous_commit=on`, base)

Delivery latency in ms, median (min–max) over the repeats. *Lock* is the
room-lock hold time, as a bucket bound. *Pool* is the peak number of
PostgreSQL connections in use, out of 60.

### M4

| msg/s | Pass | p50 | p95 | p99 | max | Lock p50 / p99 | Pool |
|---|---|---|---|---|---|---|---|
| 500 | 3/3 | 2.3 | 3.3 (3.1–3.5) | 5.3 (5.1–5.3) | 19 | ≤ 2 / ≤ 8 | 6 |
| 1,000 | 4/4 | 2.2 | 4.0 (3.8–4.0) | 6.0 (6.0–6.1) | 22 | ≤ 2 / ≤ 8 | 48 |
| 2,000 | 3/3 | 4.9 | 7.3 | 13.4 (12.4–13.9) | 33 | ≤ 4 / ≤ 16 | 48 |
| 3,000 | 3/3 | 8.0 | 12.4 | 26.4 (25.1–27.4) | 36 | ≤ 8 / ≤ 16 | 60 |
| 4,000 | 6/6 | 20.8 (16.6–67.3) | 80.1 (36.9–124) | 95.8 (43.7–156) | 111 | ≤ 16 / ≤ 16 | 60 |
| 5,000 | 0/6 | *overloaded* | | 8,513 | | ≤ 16 / ≤ 32 | 60 |
| 6,000 | 0/3 | *overloaded* | | 14,684 | | | 60 |
| 8,000 | 0/3 | *overloaded* | | 21,946 | | | 60 |

### WSL

| msg/s | Pass | p50 | p95 | p99 | max | Lock p50 / p99 | Pool |
|---|---|---|---|---|---|---|---|
| 250 | 3/3 | 7.1 | 10.1 (8.0–45.4) | 33.3 (10.6–103) | 78 | ≤ 8 / ≤ 32 | 19 |
| 500 | 3/3 | 8.1 | 29.5 (11.7–31.5) | 40.6 (24.5–42.0) | 78 | ≤ 8 / ≤ 64 | 30 |
| 1,000 | 2/4 | 9.8 | 138 (13–1,386) | 399 (22.6–1,896) | 538 | ≤ 8–16 / ≤ 64–512 | 60 |
| 1,500 | 2/3 | 9.1 | 22.8 (13.9–48.4) | 86.2 (60.9–259) | 153 | ≤ 8 / ≤ 64 | 60 |
| 2,000 | 3/3 | 10.2 | 16.3 (15.9–27.3) | 67.5 (24.4–121) | 158 | ≤ 8 / ≤ 32 | 60 |
| 2,500 | 0/3 | *overloaded* | | 4,078 (1,616–7,420) | | ≤ 16 / ≤ 128 | 60 |
| 3,000 | 0/3 | 16.8 | 296 | 415 (275–1,515) | 445 | ≤ 16 / ≤ 64 | 60 |

WSL's failures at 1,000 and 1,500 msg/s weren't repeatable. Each had a
passing repeat at a far lower p99, and 2,000/s passed every time. The
worst of them (1,000/s, p99 1.9 s) also had the longest lock-hold tail in
the WSL data (≤ 512 ms), which fits a stalled commit flush; the others'
lock tails looked like the passing runs'. 2,000/s is the highest rate that
passed every repeat.

### lab-hermes

| msg/s | Pass | p50 | p95 | p99 | max | Lock p50 / p99 | Pool |
|---|---|---|---|---|---|---|---|
| 100 | 1/3 | 8.2 | 24.3 (19.5–48.0) | 231 (34.6–374) | 512 | ≤ 32 / ≤ 128 | 41 |
| 200 | 6/6 | 6.0 | 14.3 (11.3–25.2) | 24.0 (19.4–118) | 57 | ≤ 16 / ≤ 64–128 | 35 |
| 300 | 4/4 | 6.0 | 24.8 (13.6–29.0) | 64.2 (23.7–73.6) | 157 | ≤ 16 / ≤ 64 | 45 |
| 400 | 2/3 | 7.7 | 34.8 (31.6–68.2) | 69.7 (52.8–240) | 206 | ≤ 16 / ≤ 64 | 48 |
| 500 | 5/6 | 8.8 | 60.5 (33.8–98.9) | 105 (68.9–395) | 203 | ≤ 16 / ≤ 128 | 59 |
| 600 | 3/6 | 10.0 | 76.6 (63.4–92.3) | 193 (100–200) | 286 | ≤ 16 / ≤ 128 | 60 |
| 700 | 0/3 | 34.2 | 218 (178–256) | 328 (265–378) | 400 | ≤ 32 / ≤ 128 | 60 |
| 1,000 | 0/3 | *overloaded* | | 5,687 | | ≤ 64 / ≤ 128 | 60 |

lab-hermes's limit is soft. Its p99 climbs steadily from 300/s, and the
200 ms line falls at about 600/s. The 100/s failures are its first run
(cold caches) and one later run with a single latency spike. Every rate
from 200 to 500 has runs with a p99 well under 100 ms. Its lock-hold p99
is ≤ 64–128 ms at *every* rate, a sign that the box stalls now and then
regardless of load, which is why its tail is noisy.

## Why the limits are where they are

A publish holds its room's lock and one pooled PostgreSQL connection for
the whole transaction: BEGIN, `SET LOCAL` timeouts, `SELECT … FOR UPDATE`,
the role check, `nextval`, the ScyllaDB insert, `UPDATE`, `COMMIT` (S-34's
findings). Two numbers decide whether publishes queue:

- **Connections busy ≈ publish rate × hold time** (Little's law). On M4 at
  4,000/s, with a lock hold of 8–16 ms, that is 32–64 connections busy. The
  pool's 60 is at the edge, the pool peaked at 60, and 5,000/s tipped it
  over. On WSL, commit flushes are slower and spikier, so the same pool
  fills at a lower rate. lab-hermes's hold is 8–16 ms at 500/s, but the CPU
  that has to run those transactions is also busy with 10k sockets, two
  databases and the generator.
- **Once the arrival rate exceeds what the pool drains, the queue grows
  without bound.** That is why overloaded runs show p50s of seconds and,
  past the limit, p99 that just measures how long the run lasted (60 s of
  overload would show roughly twice the 30 s figure). It is also why those
  rows deliver less than 100%: the backlog was still draining when the
  measurement ended. The few rows above 100% are the same backlog seen from
  the other side, warmup messages delivered inside the measured window.

ScyllaDB was never the constraint. On passing runs, insert p50 was ≤ 2 ms
everywhere and insert p99 ≤ 8 ms on M4 and WSL (≤ 32 ms on lab-hermes).
Insert latency rose (p50 ≤ 4–8 ms) only in lab-hermes's overloaded runs,
where the whole box is saturated.

## Tuning experiments

All at 10,000 connections, 3 interleaved repeats each, delivery latency
in ms.

### Near the stock limit

| Machine @ rate | Setting | Pass | p50 | p95 | p99 | Lock p50 |
|---|---|---|---|---|---|---|
| M4 @ 4,000 | base, pool 60 | 6/6 | 20.8 | 80.1 | 95.8 (43.7–156) | ≤ 16 |
| | **S-48** | 3/3 | 7.5 | 14.5 | **27.7 (27.6–28.6)** | ≤ 8 |
| | `synchronous_commit=off` | 3/3 | 12.1 | 35.9 | 67.0 (57.4–85.4) | ≤ 8 |
| | pool 90 | 3/3 | 17.1 | 35.3 | 66.6 (65.4–71.9) | ≤ 16 |
| | pool 30 | 0/3 | *overloaded* | | 5,896 | ≤ 8 |
| WSL @ 2,500 | base, pool 60 | 0/3 | *overloaded* | | 4,078 (1,616–7,420) | ≤ 16 |
| | **`synchronous_commit=off`** | 3/3 | 6.0 | 9.9 | **16.5 (16.2–16.9)** | ≤ 4 |
| | S-48 | 0/3 | *overloaded* | | 5,094 | ≤ 16 |
| | pool 90 | 0/3 | 18.3 | 487 | 884 (352–1,639) | ≤ 16 |
| | pool 30 | 0/3 | *overloaded* | | 7,196 | ≤ 16 |
| lab-hermes @ 500 | base, pool 60 | 5/6 | 8.8 | 60.5 | 105 (68.9–395) | ≤ 16 |
| | S-48 | 3/3 | 5.7 | 42.7 | 81.5 (49.5–104) | ≤ 8–16 |
| | `synchronous_commit=off` | 3/3 | 4.4 | 35.4 | 120 (76.4–145) | ≤ 8 |
| | pool 90 | 2/3 | 6.7 | 47.9 | 72.3 (43.3–287) | ≤ 16 |
| | pool 30 | 2/3 | 7.3 | 40.5 | 149 (61.6–234) | ≤ 8–16 |
| lab-hermes @ 200 | base | 6/6 | 6.0 | 14.3 | 24.0 (19.4–118) | ≤ 16 |
| | `synchronous_commit=off` | 3/3 | 4.3 | 9.9 | 15.6 (14.9–20.7) | ≤ 8 |

### Does the limit move?

| Machine @ rate | Setting | Pass | p50 | p95 | p99 |
|---|---|---|---|---|---|
| M4 @ 5,000 | base | 0/6 | *overloaded* | | 8,513 |
| | `synchronous_commit=off` | 0/3 | *overloaded* | | 6,894 |
| | S-48 | 0/3 | 410 | 834 | 857 (276–956) |
| | **S-48 + `synchronous_commit=off`** | **3/3** | 12.5 | 54.0 | **66.0 (65.7–89.3)** |
| WSL @ 3,000 | base | 0/3 | 16.8 | 296 | 415 (275–1,515) |
| | **`synchronous_commit=off`** | **3/3** | 7.7 | 15.2 | **30.0 (19.6–30.5)** |
| WSL @ 4,000 | `synchronous_commit=off` | 3/3 | 9.7 | 18.5 | 31.5 (27.4–36.8) |
| | S-48 + `synchronous_commit=off` | 3/3 | 6.3 | 11.9 | 21.6 (20.0–26.6) |
| lab-hermes @ 600 | base | 3/6 | 10.0 | 76.6 | 193 (100–200) |
| | S-48 | 3/3 | 6.8 | 52.1 | 121 (67.7–197) |
| | S-48 + `synchronous_commit=off` | 3/3 | 5.0 | 46.9 | 115 (82.8–128) |

### Reading the results

- **S-48 (5 round trips instead of 7)** is a clear win on M4. At 4,000/s
  its p99 range (27.6–28.6 ms) sits entirely below base's (43.7–156 ms), and
  the lock hold drops a bucket. S-48's own PR, on a single noisy host,
  couldn't establish a load-level improvement; interleaved repeats on a
  quiet machine can. On WSL at 2,500/s it does nothing, because the
  commit flush dominates there. With the flush removed (sync off, 4,000/s)
  it helps again: 21.6 vs 31.5 ms, ranges just apart. On lab-hermes it
  turns 600/s from 3/6 into 3/3, but the p99 ranges overlap, so the effect
  there is small and uncertain. **Recommendation: merge S-48.** It never
  hurt, and where round trips dominate it buys a lot.
- **`synchronous_commit=off`** removes the wait for the WAL flush at
  COMMIT. On WSL that flush is the bottleneck. Turning it off doubled the
  sustainable rate and cut p99 at 2,500/s from seconds to 16.5 ms. On M4
  it helps alone (p99 96 → 67 ms at 4,000/s), and combined with S-48 it is
  what carries 5,000/s. On lab-hermes it helps at low rates (p99 24 → 16 ms
  at 200/s) but not at 500/s, where the CPU is the limit. **This is a
  durability trade-off, not a free speed-up.** See below.
- **Pool size** only matters near saturation. 30 connections were too few
  for M4 at 4,000/s and WSL at 2,500/s, and both collapsed. 90 helped M4 a
  little (p99 96 → 67 ms) but made WSL worse (884 ms vs overloaded at 60:
  more concurrent commits contending for the same slow flush). On
  lab-hermes neither 30 nor 90 was distinguishable from 60. The sizing rule
  in [operations.md](operations.md) (`pool_max_conns` ≥ peak publishes/s ×
  p99 lock hold, with headroom) holds, but a bigger pool can't fix a slow
  disk.

### What `synchronous_commit=off` risks

The PostgreSQL documentation ([Asynchronous Commit](https://www.postgresql.org/docs/18/wal-async-commit.html))
says asynchronous commit "introduces the risk of data loss": if the server
crashes before the WAL is flushed, "changes made during that transaction
*will* be lost". The window is at most three times `wal_writer_delay`. It
is "data loss, not data corruption": PostgreSQL recovers to a consistent
earlier state.

For klacks, losing the last few PostgreSQL commits while ScyllaDB keeps the
messages is the same situation as restoring PostgreSQL to an earlier point
(`internal/store/reconcile.go`). Rooms' `next_seq` and `message_write_ts` go
backwards. A new publish can then reuse a seq that clients have already
seen, and the new message is silently lost. **After any PostgreSQL crash
with `synchronous_commit=off`, stop the servers and run `klacks reconcile`
before restarting**, as after a restore
([operations.md](operations.md#after-any-postgresql-restore-klacks-reconcile)).
A clean shutdown loses nothing. Weigh that procedure against the capacity
it buys; on hardware like M4's, S-48 alone already gives most of the
latency gain.

## Cold resume

After a restart the replay buffer is empty, so resuming a room reads its
history from ScyllaDB. Each machine loaded 1,000 rooms of history, restarted
the server, and resumed every room from seq 0 (`perf-data/cold-resume.txt`):

| Machine | Messages replayed | Range read p50 / p99 |
|---|---|---|
| M4 | 40,001 | ≤ 8 ms / ≤ 16 ms |
| WSL | 40,001 | ≤ 2 ms / ≤ 32 ms |
| lab-hermes | 12,001 | ≤ 4 ms / ≤ 32 ms |

Every room replayed completely. Resume isn't a bottleneck on any of these
machines.

## Sizing guidance

- **Budget by publishes per second, not connections.** 10,000 idle-ish
  connections cost little; every machine connected them in seconds. The
  limit is publishes per second through PostgreSQL.
- **Rough capacities (one node, everything on one box):**
  - **Laptop-class modern CPU with a fast SSD (M4):** about 4,000 msg/s
    stock; over 5,000 with S-48 and async commit.
  - **Desktop CPU on a slow-flush disk (WSL here):** about 2,000 msg/s
    stock; about 4,000 with async commit.
  - **Old 2-core box:** a few hundred msg/s, plenty for a small community.
- **Check the disk's flush latency before tuning anything else.** If the
  lock hold is high while the CPU is idle, the commit flush is the
  bottleneck. Faster storage, or `synchronous_commit=off` with its
  reconcile procedure, is the lever; a bigger pool is not.
- **Keep the pool near 60 for a few thousand msg/s.** Too small collapses
  the server at load, and much bigger can hurt on slow disks. Watch
  `klacks_pg_pool_acquired_conns`: pinned at the maximum means you're at
  the limit.
- **Watch for the limit, not just p99.** Past it, latency goes from
  milliseconds to seconds within one step. Alert on pool saturation and
  rising `klacks_room_lock_held_seconds` before users see delays.

## Limitations

- **Everything shares one machine.** The generator's 10,000 connections and
  up to 45,000 measured deliveries per second compete with the server and databases for
  CPU. That matters most on lab-hermes. Real deployments with clients
  elsewhere would do better.
- **Shared hosts.** lab-hermes runs n8n and other services. WSL shares its
  host with other development work, and its run-to-run variance at
  1,000–1,500/s (p99 22 ms to 1.9 s for the same point) is larger than any
  tuning effect there. Only differences with non-overlapping ranges are
  claimed as effects.
- **Load average isn't a usable interference signal.** The sweep records
  the 1-minute load before each run, but it mostly reflects the previous
  run's load, so runs weren't filtered on it.
- **M4's databases run in a 4-CPU, 4 GB colima VM** on a 10-core machine.
  Native databases, or a bigger VM, would likely raise M4's numbers.
- **One node, single-node databases**, PostgreSQL defaults and
  `compose.yaml`'s small ScyllaDB (`--smp 1 --memory 750M`). There are no
  multi-node or remote-database results.
- **Runs are 30 s plus 10 s warmup,** shorter than the gate's 60 s. This
  matters only past the limit, where p99 grows with run length.
- **nas** (AMD A10-5700) is excluded: ScyllaDB 2026.3.5 exits with SIGILL
  on it.
- **Server quantiles are coarse** (bucket bounds), and rate limits (S-32)
  are off on this branch's base.

## Reproduce

```sh
make up                      # or any stack; set KLACKS_POSTGRES_DSN / KLACKS_SCYLLA_HOSTS
make build && go build -o bin/klacksload ./cmd/klacksload
# optional variant binary: bin/klacks-s48 built from s48-fewer-roundtrips
MACHINE=mybox OUT=perf-data/mybox.jsonl scripts/perf-sweep.sh < perf-data/plans/sweep1-m4.txt
scripts/perf-summary.py perf-data/*.jsonl
```

`perf-data/plans/` has the exact plans used (sweep1 = rate sweep,
sweep2 = limits and tuning, sweep3 = moving the limit). Each run's record
carries its labels (`machine`, `seq`, `VARIANT`, `SYNC`, `PERF_POOL`,
`commit`) and the full result.
