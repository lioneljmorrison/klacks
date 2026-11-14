# Secure Messaging Core — Implementation Plan

## 1. Goal & Scope

Build a **self-hosted, embeddable messaging core in Go** that:

- Runs standalone (desktop / web / mobile clients over WebSocket + REST).
- Embeds into a larger Go ecosystem as an importable package or gRPC service (e.g. `chat.CreateRoom(meetingID)` for meeting rooms, "Spaces" in a bigger product).
- Provides **end-to-end encryption** using the Signal Protocol (X3DH + Double Ratchet), with AEAD (AES-GCM or ChaCha20-Poly1305) as the message-level primitive.
- Guarantees **no message loss** across brief disconnections via a resume-from-`last_seen_message_id` mechanism, backed by persistent storage.

**Out of scope for v1**: federation, voice/video, bots framework, server-side search over E2EE content, multi-region replication.

---

## 2. Architecture Overview

Three layers, cleanly separated so the messaging core can be dropped into a larger system:

```
┌─────────────────────────────────────────────────┐
│  Integration API (Go package + gRPC)            │  ← your ecosystem imports this
├─────────────────────────────────────────────────┤
│  Messaging Core (Go server)                     │
│  ├─ Connection Manager (WebSocket)              │
│  ├─ Channel/Room Service                        │
│  ├─ Storage (PostgreSQL + ScyllaDB)             │
│  └─ Resume / Replay Logic                       │
├─────────────────────────────────────────────────┤
│  Security Layer (E2EE, client-side)             │
│  ├─ X3DH key agreement                          │
│  ├─ Double Ratchet per session                  │
│  └─ AEAD message encryption                     │
└─────────────────────────────────────────────────┘
```

**Key principle**: the server **never sees plaintext**. It stores and relays opaque ciphertext blobs plus routing metadata (room ID, sender ID, sequence number, timestamp).

---

## 3. Component Breakdown

### 3.1 Connection Manager

- WebSocket endpoint (`/ws`) accepting authenticated connections.
- Per-connection state: `userID`, `sessionID`, `lastAckedSeq`, subscribed rooms.
- Heartbeat / ping-pong to detect dead connections.
- Backpressure handling: bounded send queue per connection; slow consumers get disconnected and must resume.

### 3.2 Channel / Room Service

- `Room` is a logical container: DM, group, or ecosystem-created "Space".
- Membership table (`room_id`, `user_id`, `role`, `joined_at`).
- Publish path: validate sender is a member → assign monotonic `seq` per room → persist → fan out to online subscribers.
- Expose room lifecycle as first-class API so your larger ecosystem can create/manage rooms programmatically.

### 3.3 Storage (PostgreSQL + ScyllaDB)

Polyglot persistence: each store does what it's best at.

- **PostgreSQL** — relational, transactional data (`rooms`, `room_members`, `devices`, permissions, the per-room `seq` counter).
- **ScyllaDB** — high-volume, append-only message streams (`messages`).

Message storage sits behind a Go `MessageStore` interface, so the physical backend can change (e.g. a Postgres-backed implementation for small embedded deployments) without touching the core.

#### 3.3a PostgreSQL (relational layer)

```
rooms(id, kind, created_at, metadata jsonb)
room_members(room_id, user_id, role, joined_at)
devices(user_id, device_id, identity_key, signed_prekey, one_time_prekeys jsonb, last_seen_at)
room_seq(room_id, next_seq)
SEQUENCE message_write_ts   -- monotonic ScyllaDB write timestamps (see 3.3c)
```

- `devices` stays here: prekey bundles are small, per-user, transactional, and consumed exactly once (one-time prekey deletion needs a transaction).
- `room_members` stays here: membership changes must be strongly consistent and drive Sender Key rotation events.
- Migrations via `golang-migrate`.

#### 3.3b ScyllaDB (message stream layer)

```sql
CREATE TABLE messages (
    room_id      uuid,
    bucket       bigint,        -- seq / N, N fixed forever (see below)
    seq          bigint,
    message_id   uuid,
    sender_id    uuid,
    device_id    uuid,
    ciphertext   blob,
    header       blob,          -- X3DH / ratchet header, opaque to server
    created_at   timestamp,
    PRIMARY KEY ((room_id, bucket), seq)
) WITH CLUSTERING ORDER BY (seq ASC);
```

- **Partition key** `(room_id, bucket)` with **seq-range buckets**: `bucket = seq / N`. Decided over Discord-style time buckets because `seq` carries no time (unlike Snowflake IDs), so time buckets cannot be computed from `lastSeenSeq`; seq buckets are trivially computable, never empty in the middle (seq is gap-free), and immune to clock skew.
- **N is fixed forever** (a constant, or stored per room at creation and never changed) — it is baked into the partition key, so changing it would remap every stored message. Partition size is bounded only if payload size is: worst case is N × max ciphertext size. A maximum payload size is enforced on publish, and N is chosen against ScyllaDB's large-partition thresholds (`compaction_large_partition_warning_threshold_mb`, `compaction_rows_count_warning_threshold`). Starting point to validate: max ciphertext 64 KiB, N = 1000.
- **Clustering key** `seq` — monotonic per room, assigned by the server (not the DB). Preserves the resume cursor semantics.
- **Read path for resume**: with `hi` = the room's committed `next_seq − 1` (3.3c), read buckets `(lastSeenSeq+1)/N … hi/N` in order, `seq > lastSeenSeq AND seq <= hi`, and stream the results. Rows above `hi` are ignored (they are uncommitted orphans, see 3.3c). A `seq ≤ hi` that comes back missing is retried, never skipped.
- **Write path**: server assigns `seq` (3.3c), computes `bucket`, then inserts. Append-only from the server's perspective.
- **No secondary indexes.** All queries are partition-routed by design.
- **Consistency**: writes at `QUORUM`; resume reads at `LOCAL_QUORUM` (must overlap the write quorum — fine in a single DC). `ONE` is **never** used on the resume path: it can miss a committed `seq ≤ hi`, which is exactly a gap. It is acceptable only for non-authoritative hot-tail reads.

#### 3.3c Sequence assignment

- **Do not** use ScyllaDB `now()` / `TIMEUUID` as the ordering key — resume needs gap-free, per-room monotonic integers.
- **Later, only if contention is measured**: a dedicated sequence service (e.g. Redis `INCR` or a small Go service).

**v1 publish path — the counter is held locked across the ScyllaDB write, and committed only after it succeeds:**

1. `BEGIN`; `SELECT next_seq FROM room_seq WHERE room_id = $1 FOR UPDATE` (serializes publishes per room, across all server nodes); check membership; `N = next_seq`.
2. `ts = nextval('message_write_ts')` — taken *after* acquiring the lock.
3. Write message N to ScyllaDB at `QUORUM` with `USING TIMESTAMP ts`.
4. On success: `UPDATE room_seq SET next_seq = N + 1`; `COMMIT`; then fan out. On failure or timeout: `ROLLBACK` and return an error to the sender.

Why this is gap-free:
- **The committed counter is the durable watermark.** `next_seq` only advances after message N is in ScyllaDB, so every `seq ≤ hi` (= `next_seq − 1`) exists. Resume and fan-out never serve anything above `hi`.
- **No reordering.** The row lock means N+1 cannot commit before N.
- **Crashes leave invisible orphans, not holes.** A crash or rollback after step 3 leaves a ScyllaDB row at N above `hi`; nobody reads it, and the next successful publish reuses N and overwrites it (same primary key).
- **The overwrite always wins.** ScyllaDB resolves same-key writes by timestamp. `message_write_ts` is a Postgres sequence: values are never rolled back and only increase, and each attempt takes one after the room lock, so a later attempt always has a higher timestamp than any orphan. A Postgres *clock* is not used — a rolled-back attempt persists nothing, so a clock step backwards could let the orphan win. The sequence uses `CACHE 1` (the default; larger caches break cross-session ordering) and is seeded at the current epoch in microseconds.

Operational constraints of holding the lock:
- The ScyllaDB write timeout must be shorter than Postgres `lock_timeout` / `statement_timeout`.
- Set `idle_in_transaction_session_timeout` so a hung process releases the room's lock.
- Every in-flight publish holds a pool connection for the duration of the ScyllaDB write; size the pool accordingly and measure lock hold time under load.
- Per-room throughput is bounded by `1 / (lock hold time)` — fine for human chat speed; revisit with the sequence-service option if measured contention says so.

**Known limitation:** if the ScyllaDB write succeeds and `COMMIT` then returns an error, the commit may or may not have happened. A sender who retries could post a duplicate. The eventual fix is idempotent publish keyed by a client-generated `message_id`.

Request coalescing for hot reads (e.g. a room-wide announcement) is a later optimization, not v1.

### 3.4 Resume / Replay

- Client reconnects with `{roomID, lastSeenSeq}`.
- Server streams all messages with `seq > lastSeenSeq` from the store, then resumes live push.
- Short-window in-memory replay buffer (e.g. last N minutes) for fast resume before hitting the DB.
- Ack protocol: client acks `seq`; server advances `lastAckedSeq` and can prune the replay buffer.

### 3.5 Security Layer (Client-Side)

**Device registration (X3DH prekey bundle upload):**
- Identity key (Ed25519), signed prekey (X25519, signed by identity key), batch of one-time prekeys (X25519).
- Server stores the public bundle per `(userID, deviceID)`.

**Session establishment (X3DH):**
- Sender fetches recipient's prekey bundle, performs X3DH, derives shared secret, sends initial message with ephemeral key + used one-time prekey ID.
- Server deletes consumed one-time prekey.

**Message encryption (Double Ratchet + AEAD):**
- Each message: derive message key via symmetric ratchet → encrypt with AEAD.
- **Associated data** must bind: `room_id || sender_id || device_id || seq`. Any tampering with routing metadata → AEAD verification fails.
- Unique nonce per message, derived from the message key (never reuse `(key, nonce)`).

**Group messaging (Sender Keys):**
- Signal Protocol does not define group messaging natively.
- Each member generates a Sender Key, distributes it pairwise (via existing Double Ratchet sessions) to all other members.
- Messages encrypted once with the Sender Key (AEAD), broadcast as a single ciphertext.
- Key rotation on member removal — handled by server as a membership event, clients react.

### 3.6 Integration API

**Go package interface** (importable by your ecosystem):

```go
type ChatService interface {
    CreateRoom(ctx context.Context, spec RoomSpec) (RoomID, error)
    AddMember(ctx context.Context, room RoomID, user UserID, role Role) error
    PostMessage(ctx context.Context, room RoomID, sender UserID, payload EncryptedPayload) (Seq, error)
    Subscribe(ctx context.Context, room RoomID, fromSeq Seq) (<-chan Message, error)
    RemoveMember(ctx context.Context, room RoomID, user UserID) error
}
```

The interface carries no acting user: the embedder acts through one
configured service identity (`pkg/chat`'s `Config.Actor`). CreateRoom makes
the actor the room's owner; AddMember and RemoveMember act as that actor;
Subscribe authorizes the actor as the reader. PostMessage keeps its explicit
sender, who must be a member. A member leaving as an end user is not part of
the embedded API.

**gRPC mirror** of the same interface for cross-language / cross-process integration.

**HTTP + WebSocket** for the standalone clients. The standalone app and the embedded use case share the same core; only the transport differs.

---

## 4. Implementation Phases

### Phase 0 — Foundations (1 week)
- Repo layout: `cmd/`, `internal/core`, `internal/store`, `internal/api`, `pkg/chat` (public interface).
- Config, logging.
- Local dev stack in Docker Compose: `postgres` + `scylla`.
- Migration tooling for both stores: `golang-migrate` for Postgres; CQL migrations (`cqlsh`-driven or a `gocql` helper) for ScyllaDB.
- Health endpoint (checks both stores), graceful shutdown.

### Phase 1 — Rooms & Messages, No Crypto (1–2 weeks)
- PostgreSQL schema + migrations (rooms, members, devices, `room_seq`).
- ScyllaDB `messages` table, `MessageStore` interface, insert and partition-routed read.
- `CreateRoom`, `AddMember`, `PostMessage` (plaintext payload, treated as opaque bytes); `room_seq` counter increment in Postgres, then ScyllaDB write.
- Room membership authorization checks.
- Unit + integration tests, including: post message → read back by `(room_id, seq > lastSeen)` → verify ordering.

### Phase 2 — Real-Time Delivery & Resume (2 weeks)
- WebSocket connection manager.
- Fan-out on publish, per-room `seq` assignment.
- Resume protocol, in this order: subscribe to live → read `hi` (committed `next_seq − 1`) from Postgres → replay `(lastSeenSeq, hi]` from the ScyllaDB buckets `(lastSeenSeq+1)/N … hi/N` → drain the live buffer, dropping anything `≤ hi`. (Reading `hi` before subscribing would miss a commit landing in between.)
- Ack handling, replay buffer, slow-consumer handling.
- Integration test: kill connection mid-stream, reconnect, verify no gaps or duplicates — **including across bucket boundaries** (the critical new test introduced by bucketing), concurrent posts, and failure injection after the ScyllaDB write but before `COMMIT` (orphan is never served and is overwritten by the next publish).

### Phase 3 — Integration API (1 week)
- Public Go package (`pkg/chat`) wrapping the core.
- gRPC service mirroring the interface.
- Example embedder: a toy "meeting scheduler" that creates a room on meeting creation.

### Phase 4 — E2EE (3–4 weeks)
- Build the Go reference implementation (X3DH + Double Ratchet on `x/crypto`) — it is the executable definition of the wire format and the test oracle. There is no library choice for klacks to make: crypto happens entirely in client apps, so each client project chooses its own library (real clients will likely be TS/Kotlin/Swift wrapping `libsignal`). Document that recommendation, including libsignal's AGPL-3.0 license (a distributed client built on it must be released under AGPL-3.0), and keep `docs/protocol.md` buildable-against for third-party and closed-source clients.
- Implement X3DH prekey bundle registration + consumption on the server (store keys, delete one-time prekeys on use).
- Implement Sender Key distribution as opaque server-relayed blobs.
- **Server-side crypto stays at "opaque blob" level** — no server-side decryption path exists, by design.
- End-to-end test: two clients exchange messages through the server; assert server DB contains only ciphertext.
- Associated data binding test: tamper with `seq` in ScyllaDB, assert client rejects.

### Phase 5 — Hardening (ongoing)
- Rate limiting per user/room.
- Auth: JWT or mTLS for client connections; service tokens for gRPC.
- Audit log of membership changes (not message content).
- Load test: 10k concurrent connections, 1k msg/s fan-out; measure p99 ScyllaDB insert and resume-read latency, per-room lock hold time and pool usage.
- Bucket-boundary correctness test in CI (messages spanning two buckets, resume from before the boundary); fuzz the bucket-range computation (property: the buckets returned cover exactly `(lastSeenSeq, hi]`).
- Fuzz AEAD envelope parsing.
- Operations: backup, monitoring and documented failure modes for both stores; production on managed ScyllaDB Cloud or a single well-sized cluster.

---

## 5. Key Design Decisions (Lock These Early)

| Decision | Choice | Rationale |
|---|---|---|
| Server sees plaintext? | **No** | E2EE mandatory; server is a relay + store of ciphertext. |
| Group crypto | **Sender Keys** | Signal's own approach; server treats distribution as opaque blobs. |
| AEAD algorithm | **ChaCha20-Poly1305** (or AES-GCM on hardware-AES hosts) | Go `x/crypto` support; no AES-future-risk dependency if preferred. |
| Nonce strategy | Derived from message key, unique per message | Prevents catastrophic (key, nonce) reuse. |
| Resume cursor | `(room_id, seq)` monotonic per room | Simple, gap-free, idempotent; maps to a partition-routed read. |
| Transport | WebSocket (clients) + gRPC (ecosystem) | One core, two transports. |
| Message storage | **ScyllaDB** | Append-heavy, partition-routed range reads, linear write scaling. |
| Relational storage | **PostgreSQL** | ACID for rooms/members/prekeys; transactional one-time-prekey consumption. |
| Sequence assignment | **Postgres `room_seq` counter (v1)** | Correctness first; decouple only if contention appears. |
| Partition key (messages) | `(room_id, bucket)`, `bucket = seq / N`, N fixed forever | Computable from `lastSeenSeq`; no empty mid-range buckets; no clock skew. Size bounded by N × max payload. |
| Publish ordering | Postgres `room_seq` row lock held across the ScyllaDB write; commit after | Committed counter = durable watermark; gap-free with no reordering; orphans overwritten (write timestamp from a Postgres sequence). |
| Clustering key (messages) | `seq` | Preserves resume semantics. |
| Secondary indexes | **None on messages** | ScyllaDB constraint; queries are partition-routed by design. |
| Consistency (messages) | `QUORUM` write / `LOCAL_QUORUM` read | Balance durability and latency; tune later. |
| Identity | Per-device keys | Matches Signal model; supports multi-device. |
| Client crypto library | **None chosen by klacks** | Crypto lives in client apps; each project picks its own (libsignal recommended; AGPL-3.0 caveat documented). Klacks ships a Go reference implementation on `x/crypto` as the wire-format spec and test oracle. |

---

## 6. Risks & Mitigations

- **E2EE group key management complexity** — biggest risk. Mitigation: ship 1:1 first (Phase 4a), then groups (Phase 4b); Sender Key rotation on membership change is the hard part — test exhaustively.
- **Nonce reuse** — catastrophic. Mitigation: derive nonce from message key; fuzz test; code review gate.
- **Resume correctness under concurrent writes** — mitigate with strict `(room_id, seq)` uniqueness and integration tests that interleave publishes with reconnects.
- **`libsignal-go` licensing (AGPL)** — resolved: klacks never touches crypto (the server relays opaque ciphertext only), so the AGPL exposure lands entirely on shipped client apps, which choose their own library. libsignal stays the documented recommendation for real clients, with the AGPL-3.0 consequence (a distributed client built on it must be released under AGPL-3.0) written into the docs; the Go reference implementation on `x/crypto` defines the wire format and carries no license constraint.
- **Backpressure / slow consumers** — disconnect + resume is simpler and safer than unbounded buffering.
- **Operational complexity (two datastores)** — two systems to run, back up and monitor. Mitigation: Docker Compose locally; managed ScyllaDB Cloud or one well-sized cluster in production; documented failure modes for each store.
- **Bucket-boundary bugs** — resume across bucket boundaries is the most likely correctness regression. Mitigation: seq-range buckets (3.3b) make the range a pure function of `(lastSeenSeq, hi, N)`; dedicated integration tests in Phases 2 and 5; fuzz the bucket-range computation.
- **Sequence counter contention** — publishes serialize per room on the `room_seq` row lock, now held across the ScyllaDB write. Fine for v1 (one room's rate is bounded by human chat speed); measure lock hold time in the load test and revisit only if a single room sustains hundreds of msgs/sec.
- **Two-system consistency** — a naive Postgres-commit-then-ScyllaDB-write leaves permanent `seq` holes after a crash and exposes N+1 before N under concurrent posts. Mitigation: the 3.3c publish path (lock across the write, commit after, serve only up to the committed counter, sequence-based write timestamps). Document this ordering explicitly in the code. Residual: an ambiguous `COMMIT` failure can cause a duplicate on sender retry until idempotent publish by `message_id` lands.

---

## 7. Definition of Done (Core v1)

- [ ] Two clients can create a DM, exchange E2EE messages via the server, with the server DB containing only ciphertext.
- [ ] A client disconnects mid-conversation, reconnects, receives exactly the missed messages (no gaps, no duplicates) via `lastSeenSeq`.
- [ ] Resume across a bucket boundary returns exactly the missed messages.
- [ ] A larger Go service can import `pkg/chat`, create a room, add members, and post a message without touching WebSocket internals.
- [ ] Tampering with `seq` or `sender_id` in the DB causes client-side AEAD verification to fail.
- [ ] Group message with 3+ members works, and removing a member rotates the Sender Key.
- [ ] Load test passes: 10k connections, sustained 1k msg/s fan-out, p99 delivery < 200ms.