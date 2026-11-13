-- Relational layer, plan §3.3a. Messages live in ScyllaDB, not here.

CREATE TABLE rooms (
    id         uuid        PRIMARY KEY,
    kind       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    metadata   jsonb       NOT NULL DEFAULT '{}'
);

CREATE TABLE room_members (
    room_id   uuid        NOT NULL REFERENCES rooms (id),
    user_id   uuid        NOT NULL,
    role      text        NOT NULL,
    joined_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (room_id, user_id)
);

-- Rooms a user belongs to.
CREATE INDEX room_members_user_id ON room_members (user_id);

-- Prekey bundles. One-time prekeys (and any further bundle fields) are added
-- by S-22, which defines the bundle format.
CREATE TABLE devices (
    user_id       uuid        NOT NULL,
    device_id     uuid        NOT NULL,
    identity_key  bytea       NOT NULL,
    signed_prekey bytea       NOT NULL,
    last_seen_at  timestamptz,
    PRIMARY KEY (user_id, device_id)
);

-- Per-room sequence counter and publish lock (plan §3.3c). PostMessage holds
-- this row FOR UPDATE across the ScyllaDB write and advances next_seq only
-- after it succeeds, so the committed next_seq - 1 is the durable watermark
-- (hi). seq starts at 1: an empty room has hi = 0.
CREATE TABLE room_seq (
    room_id  uuid   PRIMARY KEY REFERENCES rooms (id),
    next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq >= 1)
);

-- Monotonic ScyllaDB write timestamps (plan §3.3c). A sequence, not a clock:
-- values never roll back, so a retried publish always outranks an orphan.
-- CACHE 1 (the default) keeps values ordered across sessions; a larger cache
-- breaks that. Seeded at the current epoch in microseconds, the unit of CQL
-- write timestamps.
CREATE SEQUENCE message_write_ts AS bigint CACHE 1;
SELECT setval('message_write_ts', (extract(epoch FROM clock_timestamp()) * 1000000)::bigint);
