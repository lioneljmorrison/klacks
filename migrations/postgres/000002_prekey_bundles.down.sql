DROP TABLE one_time_prekeys;

ALTER TABLE devices
    DROP COLUMN signed_prekey_sig,
    DROP COLUMN signed_prekey_id,
    DROP COLUMN identity_dh_key;
