# klacks operations runbook

How to watch, back up, restore and reason about failures of a klacks
deployment's two stores: **PostgreSQL** (rooms, members, room counters,
devices and prekeys, the audit log, the write-timestamp sequence) and
**ScyllaDB** (the message stream). Commands come from the vendor docs for
the versions in `compose.yaml` (PostgreSQL 18, ScyllaDB 2026.3, ScyllaDB
Manager 3.13); links are given per section.

## The invariant

Everything below follows from one rule (plan §3.3c):

> For every room, ScyllaDB holds every message with `seq ≤ hi`, where
> `hi = room_seq.next_seq - 1` in PostgreSQL.

A publish holds the room's `room_seq` row lock, writes the message to
ScyllaDB, and only then advances `next_seq` and commits. So `hi` is the
durable watermark: resume reads `(lastSeenSeq, hi]` and never sees a gap.
ScyllaDB may hold rows *above* `hi` (a publish whose commit failed), which
are never served and which the next publish overwrites, because its write
timestamp (from the PostgreSQL sequence `message_write_ts`) is higher.

Both halves of that last sentence break if PostgreSQL goes back in time
while ScyllaDB does not. That is what [`klacks reconcile`](#after-any-postgresql-restore-klacks-reconcile)
fixes.

## Health and metrics

| Endpoint | Listener | Meaning |
|---|---|---|
| `GET /healthz` | client (`KLACKS_HTTP_ADDR`) | The process is up. Use for liveness. |
| `GET /readyz` | client | Both stores answer within `KLACKS_HTTP_READY_TIMEOUT`. `503` with JSON naming the failing store, e.g. `{"status":"unavailable","checks":{"postgres":"ok","scylla":"unavailable"}}`. Also `503` while draining at shutdown. Use for readiness/load-balancer routing. |
| `GET /metrics` | metrics (`KLACKS_METRICS_ADDR`, off when empty) | Prometheus. Never on the client listener. |

Metrics (plus the standard `go_*` and `process_*` collectors):

| Metric | What to watch |
|---|---|
| `klacks_room_lock_held_seconds` (histogram) | How long each publish or membership change held its room's lock, ScyllaDB write and commit included. This is a room's serialization cost: one room can do at most ~1/p50 publishes per second. Alert on p99 rising toward `KLACKS_SCYLLA_TIMEOUT`. |
| `klacks_scylla_insert_seconds` (histogram) | Message insert latency at QUORUM. The main contributor to lock hold time. |
| `klacks_scylla_range_seconds` (histogram) | Resume read latency at LOCAL_QUORUM, store time only. |
| `klacks_pg_pool_{acquired,idle,total,max}_conns` (gauges) | Every in-flight publish holds a pool connection across its ScyllaDB write. `acquired` near `max` means publishes queue for connections; raise the pool size (`pool_max_conns` in the DSN) or find the slow ScyllaDB. |
| `klacks_ws_connections` (gauge) | Open client connections on this node. |
| `klacks_ws_slow_disconnects_total` (counter) | Clients dropped because they could not keep up (backpressure). A rising rate means slow clients or an overloaded node. |

## Backups

Back up both stores. ScyllaDB is the message history; PostgreSQL is
everything that makes it addressable (rooms, membership, counters) plus
device keys and the audit log.

**Ordering rule.** When both have to be restored, the PostgreSQL restore
point must be **no later than** the ScyllaDB backup point. Otherwise
PostgreSQL's counters claim seqs ScyllaDB lacks: those messages are gone,
and resume reads hit holes the protocol promises never exist. The other way
round (ScyllaDB newer) is repairable with `klacks reconcile`. In practice:
take ScyllaDB snapshots on a schedule, and run PostgreSQL with continuous
WAL archiving so it can be recovered to any time at or before the newest
snapshot.

### PostgreSQL

Recommended: continuous archiving + base backups, for point-in-time
recovery ([PostgreSQL 18 docs, §25.3](https://www.postgresql.org/docs/18/continuous-archiving.html)).

1. In `postgresql.conf` (needs a restart for `archive_mode`):
   ```
   wal_level = replica
   archive_mode = on
   archive_command = 'test ! -f /mnt/server/archivedir/%f && cp %p /mnt/server/archivedir/%f'
   archive_timeout = 60
   ```
   `archive_command` must exit 0 only on success. Use durable, off-host
   storage in place of the example directory.
2. Take base backups regularly with
   [`pg_basebackup`](https://www.postgresql.org/docs/18/app-pgbasebackup.html),
   e.g. `pg_basebackup -D /backups/base-$(date +%F) -Ft -z -X stream -P -c fast`
   (role with `REPLICATION`, `pg_hba.conf` allowing the replication
   connection). Keep all WAL from the oldest base backup you keep.

A logical dump is fine for small deployments and for copies:
`pg_dump -Fc -f klacks.dump <db>` ([docs](https://www.postgresql.org/docs/18/app-pgdump.html)).
It is consistent and includes sequence values (`message_write_ts`), but
only restores to the moment it was taken.

### ScyllaDB

Per-node snapshots ([ScyllaDB 2026.3 backup](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/backup-restore/backup.html)):

1. Schema (superuser): `cqlsh -e "DESC SCHEMA WITH INTERNALS AND PASSWORDS" > schema.cql`
2. On **every node**: `nodetool snapshot -t <tag> <keyspace>` (keyspace:
   `KLACKS_SCYLLA_KEYSPACE`, default `klacks`). Files land under
   `/var/lib/scylla/data/<keyspace>/messages-<uuid>/snapshots/<tag>` as
   hard links; copy them off the node.
3. Old snapshots are not deleted automatically: `nodetool clearsnapshot <keyspace>`
   once they are copied off.

Snapshots are per node and not one cluster-wide instant. Treat the
**earliest** node's snapshot time as the ScyllaDB backup point for the
ordering rule. For a cluster, ScyllaDB recommends ScyllaDB Manager, which
orchestrates snapshot and upload across nodes:
`sctool backup --cluster <name> --location s3:<bucket> --keyspace <keyspace>`
([Manager 3.13](https://manager.docs.scylladb.com/stable/sctool/backup.html)).

## Restore

1. **Stop every klacks server** (and any embedder using `pkg/chat`). Nothing
   may publish until step 5.
2. **ScyllaDB** (if it was lost): recreate the schema
   (`cqlsh -e "SOURCE 'schema.cql'"`), then load the snapshot. Either
   ScyllaDB Manager (`sctool restore … --restore-schema`, then
   `--restore-tables`), or copy each snapshot's SSTables into the
   `messages` table's `upload/` directory on any node, `chown -R
   scylla:scylla` them, and run `nodetool refresh <keyspace> messages
   --load-and-stream`. Then run a repair
   ([restore docs](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/backup-restore/restore.html)).
3. **PostgreSQL**: restore the base backup into an empty data directory,
   empty `pg_wal/`, set `restore_command` and a `recovery_target_time` **no
   later than the ScyllaDB backup point** (or the latest time, if ScyllaDB
   was not restored), create `recovery.signal`, start it
   ([§25.3.5](https://www.postgresql.org/docs/18/continuous-archiving.html)).
   `recovery_target_action` defaults to `pause`: check the data, then
   promote.
4. **`klacks migrate up`**: a no-op for a current backup; applies anything
   newer than the backup's schema.
5. **`klacks reconcile`** — always, after any PostgreSQL restore. Then start
   the servers.

### After any PostgreSQL restore: `klacks reconcile`

A PostgreSQL restore rewinds `room_seq.next_seq` and `message_write_ts`,
while ScyllaDB still holds the messages committed after the restore point,
and clients have already seen them. Left alone, the next publish to such a
room reuses one of those seqs: the sender is told it succeeded, but
ScyllaDB keeps the old row (higher or equal write timestamp; ties are
broken per cell by value), so the new message is silently lost, and every
client that saw the old message at that seq rejects the stream. This is
reproduced by `TestReconcileAfterPostgresRewind`.

`klacks reconcile`, with all servers stopped:

- for each room, under its lock, reads ScyllaDB above the watermark and
  moves `next_seq` past the unbroken run of rows it finds, so those messages
  are committed again, as clients already believe (a row above a missing
  seq is never included);
- moves `message_write_ts` to at least the current time in microseconds
  (its seeding unit), past every timestamp issued so far.

It prints each room it moved and is safe to run again (`advanced 0`).
The run can include one message whose publish had failed after its
ScyllaDB write (its sender saw an error and may have retried): it is then
served like any other.

### What a PostgreSQL restore loses

Everything PostgreSQL recorded after the restore point:

- **Rooms created** after it: gone, their ScyllaDB rows unreachable
  (harmless; they are never read).
- **Membership changes**: members removed after the restore point are
  members again, and can read and post. Re-apply membership changes from
  the embedder's source of truth before serving.
- **Audit events** after the point.
- **Devices and prekeys**: bundles registered after the point are gone
  (those devices must register again), and one-time prekeys consumed after
  it are served again — their owners already deleted the private halves, so
  sessions initiated with them fail and must be retried.

## Failure modes

The ScyllaDB and partitioned-PostgreSQL rows were verified against a live
server by pausing each store's container (S-37); a paused container is a
network blackhole, the harsher case. The refused-connection row is the
expected behavior, not drilled.

| Store down | Publish | Resume / subscribe | `/readyz` |
|---|---|---|---|
| ScyllaDB | Fails with an error frame, code `unavailable` (S-46); the transaction rolls back, `next_seq` does not move, nothing is delivered. | Error frame. | `503`, `scylla: unavailable` |
| PostgreSQL refusing connections | Fails with an error frame, code `unavailable`; nothing committed. | Error frame, `unavailable`. | `503`, `postgres: unavailable` |
| PostgreSQL partitioned (no answer) | Fails with an error frame, code `unavailable`, after at most the room lock timeout plus `KLACKS_SCYLLA_TIMEOUT` (15 s by default, S-47); nothing commits unless the deadline hit during `COMMIT`. | Error frame, `unavailable`, after at most the room lock timeout (10 s) per store call. | `503` within `KLACKS_HTTP_READY_TIMEOUT` |

Recovery is automatic: once the store answers, `/readyz` returns `200` and
clients that resume from their last seq get exactly what they missed. No
reconcile is needed after an outage — only after a restore.

A publish that times out *after* its ScyllaDB write but before `COMMIT`
returns may or may not have committed; a sender that retries can post a
duplicate (plan §3.3c, known limitation).

## Production guidance

- **ScyllaDB**: a managed ScyllaDB Cloud cluster, or one well-sized
  self-managed cluster, replication factor 3 in one DC. klacks writes at
  QUORUM and resumes at LOCAL_QUORUM, which overlap only within a DC.
  Set `KLACKS_SCYLLA_REPLICATION_FACTOR` before `klacks migrate up` creates
  the keyspace.
- **PostgreSQL**: a primary with a synchronous or promptly promoted
  standby, and WAL archiving as above. The room lock is a row lock, so one
  primary serves every klacks node.
- **Room lock timeout** (10 s, `roomLockTimeout`) must exceed
  `KLACKS_SCYLLA_TIMEOUT`, since a publish holds the lock across its
  ScyllaDB write.
- Run `klacks migrate up` before rolling out a new version; migrations are
  idempotent.
