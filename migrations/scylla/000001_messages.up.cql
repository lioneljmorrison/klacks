-- Message stream layer, plan §3.3b. Partition (room_id, bucket) with
-- bucket = seq / N (store.BucketSize, fixed forever), clustered by seq.
-- No secondary indexes: every query is partition-routed.
CREATE TABLE messages (
    room_id      uuid,
    bucket       bigint,
    seq          bigint,
    message_id   uuid,
    sender_id    uuid,
    device_id    uuid,
    ciphertext   blob,
    header       blob,
    created_at   timestamp,
    PRIMARY KEY ((room_id, bucket), seq)
) WITH CLUSTERING ORDER BY (seq ASC);
