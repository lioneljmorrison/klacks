-- Membership audit log (S-33). One row per committed membership change,
-- written in the change's own transaction, so a change and its event commit
-- or roll back together. Never message content.
--
-- No foreign key to rooms: the log is a record, and must outlive anything
-- it names.
CREATE TABLE audit_events (
    id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    room_id   uuid        NOT NULL,
    action    text        NOT NULL CHECK (action IN ('room_created', 'member_added', 'member_removed')),
    actor_id  uuid        NOT NULL,
    target_id uuid        NOT NULL,
    -- The role granted (room_created, member_added) or held when removed.
    role      text        NOT NULL,
    at        timestamptz NOT NULL DEFAULT now()
);

-- A room's events in order, for paging by id.
CREATE INDEX audit_events_room_id ON audit_events (room_id, id);

-- Append-only: updates, deletes and truncation are refused. An operator who
-- must prune (retention) drops these triggers deliberately first.
CREATE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
