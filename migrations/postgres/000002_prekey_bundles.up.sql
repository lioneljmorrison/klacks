-- Prekey bundle storage, S-22 (plan §3.5). Bundle format and the client-side
-- X3DH use are defined by the reference implementation, client/bundle.go.

-- The identity's X25519 (Montgomery) form, which X3DH's DHs use; the signed
-- prekey's id (an initial message names which one it used); and the identity
-- key's Ed25519 signature over the bundle's X25519 keys. Columns default so
-- devices rows written before S-22 remain valid; new uploads are validated
-- to fill them.
ALTER TABLE devices
    ADD COLUMN identity_dh_key   bytea  NOT NULL DEFAULT '',
    ADD COLUMN signed_prekey_id  bigint NOT NULL DEFAULT 0,
    ADD COLUMN signed_prekey_sig bytea  NOT NULL DEFAULT '';

-- One-time prekeys, one row per uploaded key, in upload order by id. Bundle
-- fetch consumes one with a delete-returning (S-23), so a key is handed out
-- at most once. Cascades on the device: removing a device removes its keys.
CREATE TABLE one_time_prekeys (
    user_id   uuid        NOT NULL,
    device_id uuid        NOT NULL,
    prekey_id bigint      NOT NULL CHECK (prekey_id >= 1),
    prekey    bytea       NOT NULL,
    PRIMARY KEY (user_id, device_id, prekey_id),
    FOREIGN KEY (user_id, device_id)
        REFERENCES devices (user_id, device_id) ON DELETE CASCADE
);
