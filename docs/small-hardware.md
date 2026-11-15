# Running klacks on small machines

Status: decision recorded, cloud test pending (S-56, 2026-11-14).

Cheap cloud servers, such as Linode, Hostinger and similar entry plans,
have little memory and shared vCPUs. This note records what the load tests
say about such machines, the decision to keep ScyllaDB, a provisional
minimum hardware spec, and the plan for testing on a real cloud instance.

## Target

A self-hosted install is unlikely to see more than a few hundred messages
per second. **300 msg/s at 10,000 connections, delivery p99 under 200 ms**
is the small-machine target. G-8 (1,000 msg/s) stays the target for
release machines (`make perf`, [loadtest.md](loadtest.md)).

## What we know

From the [performance case study](performance-case-study.md) (S-54):

- **lab-hermes**, an Intel i3-6100T (2 cores / 4 threads), 7 GB with about
  2 GB free, SATA SSD, with server, generator, PostgreSQL and ScyllaDB on
  the one box:
  - passes 300 msg/s every time;
  - passes 200–500 msg/s mostly, with a soft limit near 500;
  - is overloaded at 1,000 msg/s: p50 3.6 s, and about 6% of messages
    still in flight when the run ends.
- **Per-room contention is not the limit.** The load is 1,000 rooms at
  about 1 msg/s each. On lab-hermes, a publish holds its room lock for
  8–16 ms at 500 msg/s, yet the 60-connection pool still fills.
- **The likely limit is the box itself:** four threads carrying 10k
  sockets, two databases and the generator. CPU and memory weren't
  recorded, so this isn't confirmed. The cloud test records them.
- **ScyllaDB was never the constraint on passing runs.** Insert p50 was
  ≤ 2 ms everywhere, and p99 ≤ 32 ms on lab-hermes.
- **ScyllaDB failed to start on nas** (AMD A10-5700) with SIGILL. Its
  documentation lists AMD Bulldozer and newer as supported, and requires
  SSE4.2. The A10-5700 is a Bulldozer-family CPU with SSE4.2 but no AVX2.
  The instruction it hit wasn't identified.

## Decision: keep ScyllaDB

A PostgreSQL-only message store was considered for small installs and
rejected. ScyllaDB lets message storage scale out across nodes, while
PostgreSQL is a single primary that scales only up. Small installs
therefore carry ScyllaDB's footprint and are tuned within the current
architecture.

What a PostgreSQL-only store would have offered, for the record:

- **Less memory:** one database process instead of two.
- **More hardware:** it would run on CPUs like nas's.
- **One transaction per publish:** no lock held across a network write.
- **No cross-store reconcile:** two stores could no longer disagree.

What it would have cost:

- **Scale-out:** message storage would be tied to one primary.
- **Retention:** a growing message table would need partitioning or a
  retention policy.
- **Two code paths:** two message stores to keep and test.

### What ScyllaDB needs

ScyllaDB's
[system requirements](https://docs.scylladb.com/manual/stable/getting-started/system-requirements.html)
give these minimums, the higher figure applying:

| | Memory minimum |
|---|---|
| Production | 4 GB, or 0.5 GB per logical core |
| Test | 1 GB, or 256 MiB per logical core |

`compose.yaml` runs it at `--smp 1 --memory 750M --overprovisioned 1
--developer-mode 1`, below even the test minimum. lab-hermes's results
come from that setting.

Per
[ScyllaDB in a shared environment](https://docs.scylladb.com/manual/branch-2025.1/getting-started/scylla-in-a-shared-environment.html):

- by default ScyllaDB claims all of a machine's memory; `--memory` caps
  it, and `--smp` limits its cores;
- `--overprovisioned` stops it pinning threads and memory, and reduces
  its polling. It's the right setting for a box shared with other
  processes.

So a 4 GB VPS can only run ScyllaDB at test-environment sizing. A
production-sized ScyllaDB plus everything else needs a larger machine.

## Why I-2 doesn't help small machines

I-2 (a dedicated sequence service, storage proposal §3.3c Option B) moves
per-room seq assignment out of PostgreSQL, for example to Redis `INCR`.

- **It targets a hot room:** one room sustaining hundreds of msg/s. That
  isn't what limits lab-hermes, where load is spread across rooms and
  locks are short.
- **Seqs are a gap-free promise** ([protocol.md](protocol.md)), and
  clients treat a gap as tampering or loss. A seq taken from a counter,
  followed by a crash before the message is stored, leaves a gap.
  Avoiding that needs a durable write per increment, which moves the
  commit cost rather than removing it.
- **It adds a process,** competing for the same small memory.

I-2 stays an idea, for when per-room contention is measured.

## Levers within the current architecture

In rough order of cost, using the case study's data:

1. **S-48** (five PostgreSQL round trips per publish instead of seven) is
   merged. On lab-hermes it lowered p50 at 500–600 msg/s and turned
   600 msg/s from 2/3 into 3/3 passes.
2. **Check the disk's flush latency first.** Each publish waits for one
   WAL flush at COMMIT. Run `pg_test_fsync` (shipped in the PostgreSQL
   image) on the instance before tuning anything else; the test plan
   below includes it.
3. **PostgreSQL group commit:** `commit_delay` and `commit_siblings` let
   concurrent commits share a flush. It's a configuration change with no
   code, and it is **untested** here.
4. **`synchronous_commit=off`.** Measured: it doubled WSL's passing rate.
   It risks losing the last few commits on a PostgreSQL crash, after which
   `klacks reconcile` must run before restarting (see the case study).
   It's a trade-off, not a default.
5. **Pool size:** 60 was right on every machine tested. On lab-hermes,
   30 and 90 were indistinguishable from 60.
6. **ScyllaDB flags:** keep `--overprovisioned` on shared boxes. The
   cloud test's optional second pass tries `--memory 1G`, the documented
   test minimum.

## Provisional minimum hardware

lab-hermes is the only small machine measured. That makes it a known-good
point, not a measured minimum.

| | Provisional baseline |
|---|---|
| CPU | 2 cores / 4 threads, x86-64 that ScyllaDB starts on, or ARM64 (Graviton, Ampere, Apple M) |
| Memory | 4 GB or more, with about 2 GB free for klacks and both databases (lab-hermes) |
| Disk | SSD |
| Expected capacity | about 300 msg/s reliably, at 10,000 connections |

**Caveat: shared vCPUs.** lab-hermes's cores are physical and its own. A
VPS's vCPUs are shared with other tenants, so the same nominal spec can
perform worse. The cloud test decides whether "2 vCPU / 4 GB" meets the
target or the baseline must be larger.

## Cloud test plan

Goal: decide whether a typical 2 vCPU / 4 GB VPS meets the
small-machine target, and record what limits it.

### Instance

- 2 vCPU, 4 GB, SSD, Debian or Ubuntu, in the cheapest tier that offers
  it.
- Note the provider, plan name, price, and whether its vCPUs are shared
  or dedicated.
- Optional, for comparison: the next tier up (4 vCPU / 8 GB).

### 1. Pre-flight (about 5 minutes)

```sh
lscpu | grep -E 'Model name|^CPU\(s\)|Thread'
grep -o -w -E 'sse4_2|avx2' /proc/cpuinfo | sort -u   # sse4_2 is required; avx2 missing is the nas case
free -h; df -h /
ulimit -Hn          # needs well over 10,000. Go raises the soft limit to this at startup.
```

Install Docker and Go 1.27.x. Alternatively, cross-compile on another
machine and copy over `bin/`:

```sh
GOOS=linux GOARCH=amd64 go build -trimpath -o bin/klacks ./cmd/klacks
GOOS=linux GOARCH=amd64 go build -trimpath -o bin/klacksload ./cmd/klacksload
```

### 2. Stack and disk check

```sh
git clone <repo> klacks && cd klacks
make env && make up
docker exec klacks-postgres-1 sh -c 'cd /var/lib/postgresql && pg_test_fsync -s 2' | head -12
```

Record the `fdatasync` ops/sec. A low figure means the WAL flush will be
the limit.

### 3. Rate sweep, same box (about 30 minutes)

This uses stock settings, as lab-hermes did, so the two compare directly.
`vmstat` and `docker stats` record CPU, steal time and memory alongside.

```sh
make build && go build -o bin/klacksload ./cmd/klacksload
mkdir -p bin/perf
vmstat -t 5 > bin/perf/vmstat.log &
while sleep 5; do docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}'; done > bin/perf/docker-stats.log &
set -a; . ./.env; set +a
MACHINE=<provider-plan> OUT=perf-data/<provider-plan>.jsonl PG_CONTAINER=klacks-postgres-1 \
  scripts/perf-sweep.sh < perf-data/plans/small-vps.txt
kill %1 %2
scripts/perf-summary.py perf-data/<provider-plan>.jsonl
```

If port 18080 or 19090 is taken, add `PERF_HTTP_PORT=… PERF_METRICS_PORT=…`
to the environment. `perf-data/plans/small-vps.txt` sweeps 100–500 msg/s at 10,000
connections, three interleaved passes.

**Watch:**
- the `st` (steal) column in `vmstat`: CPU time taken by other tenants;
- `free` memory, and any swap use;
- each container's memory against the instance's total.

### 4. Optional passes

- **ScyllaDB at 1 GB.** Change `--memory 750M` to `--memory 1G` in a
  compose override, `make down && make up`, then repeat the 300 and
  500 msg/s lines.
- **Generator on another machine.** This isolates klacks from the load
  generator.
  - Start the server by hand with `KLACKS_HTTP_ADDR=0.0.0.0:8080`, then
    point `bin/klacksload -base http://<vps>:8080` at it from the other
    machine.
  - The dev stack trusts any claimed identity, so first firewall port
    8080 to the generator's IP only, and stop the server afterwards.

### Pass criteria

- **Meets the baseline:** 300 msg/s passes 3/3 at p99 < 200 ms.
- **Fails:** record where the limit is (the highest rate passing 3/3) and
  what was saturated: CPU, steal time, memory or swap, or flush latency.

Results go into `perf-data/`, a new machine section in the case study,
and the baseline table above.

## Open questions

- Is 2 vCPU / 4 GB enough on shared CPUs, or does the baseline need
  4 vCPU / 8 GB?
- How much memory do the klacks server and generator use at 10,000
  connections? Not yet recorded.
- Does `commit_delay` help on a slow-flush disk?
- Should `make perf` gain a small-machine profile (300 msg/s) for
  checking an install's hardware?
