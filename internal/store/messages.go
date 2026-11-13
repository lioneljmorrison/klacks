package store

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// BucketSize is N in plan §3.3b: message seq is stored in partition
// (room_id, seq / BucketSize). It is baked into every partition key, so it
// must never change: a new value would remap every stored message.
//
// Budget: a partition holds at most BucketSize rows, so its size is bounded
// by BucketSize × the largest message (ciphertext + header), which publish
// must cap. At 64 KiB per message, 1000 rows is about 64 MiB and 1000 rows,
// against these ScyllaDB 2026.3.5 defaults (read from system.config on the
// dev node; check them on a production cluster):
// compaction_large_partition_warning_threshold_mb = 1000,
// compaction_rows_count_warning_threshold = 100000,
// compaction_large_row_warning_threshold_mb = 10,
// compaction_large_cell_warning_threshold_mb = 1.
const BucketSize int64 = 1000

// UUID is a 16-byte identifier. It is a plain array, not a named type, so the
// ScyllaDB and PostgreSQL drivers both accept it as is.
type UUID = [16]byte

// Message is one stored message. The server never sees plaintext:
// Ciphertext and Header are opaque.
type Message struct {
	RoomID     UUID
	Seq        int64 // per-room, gap-free, from 1; assigned by PostMessage
	MessageID  UUID
	SenderID   UUID
	DeviceID   UUID
	Ciphertext []byte
	Header     []byte    // X3DH / ratchet header
	CreatedAt  time.Time // stored at millisecond precision
}

// MessageStore is the message stream layer (plan §3.3).
type MessageStore interface {
	// Insert writes m with the explicit write timestamp writeTS (from the
	// Postgres message_write_ts sequence). For the same (room, seq) the write
	// with the higher timestamp wins, so a retried publish overwrites an
	// orphan left by a failed one.
	Insert(ctx context.Context, m Message, writeTS int64) error
	// Range yields the room's messages with after < seq <= hi in seq order.
	// hi must be the committed watermark (room_seq.next_seq - 1): rows above
	// it are uncommitted orphans. Range does not detect gaps; the resume path
	// owns retrying a missing seq.
	Range(ctx context.Context, room UUID, after, hi int64) iter.Seq2[Message, error]
}

// ScyllaMessages is the ScyllaDB MessageStore. Writes go at QUORUM and reads
// at LOCAL_QUORUM, which overlap in a single DC; never read the resume path
// at ONE, which can miss a committed row.
type ScyllaMessages struct {
	s *gocql.Session
}

var _ MessageStore = (*ScyllaMessages)(nil)

// NewScyllaMessages returns a MessageStore on s, a session bound to the
// migrated keyspace.
func NewScyllaMessages(s *gocql.Session) *ScyllaMessages { return &ScyllaMessages{s: s} }

func (m *ScyllaMessages) Insert(ctx context.Context, msg Message, writeTS int64) error {
	if msg.Seq < 1 {
		return fmt.Errorf("messages: insert: seq %d < 1", msg.Seq)
	}
	if writeTS < 1 {
		return fmt.Errorf("messages: insert: write timestamp %d < 1", writeTS)
	}
	err := m.s.Query(`INSERT INTO messages
		(room_id, bucket, seq, message_id, sender_id, device_id, ciphertext, header, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?`,
		msg.RoomID, bucket(msg.Seq), msg.Seq, msg.MessageID, msg.SenderID, msg.DeviceID,
		msg.Ciphertext, msg.Header, msg.CreatedAt, writeTS,
	).Consistency(gocql.Quorum).ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("messages: insert room %x seq %d: %w", msg.RoomID, msg.Seq, err)
	}
	return nil
}

func (m *ScyllaMessages) Range(ctx context.Context, room UUID, after, hi int64) iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		if after < 0 {
			yield(Message{}, errors.New("messages: range: negative cursor"))
			return
		}
		first, last, ok := bucketRange(after, hi, BucketSize)
		if !ok {
			return
		}
		for b := first; b <= last; b++ {
			it := m.s.Query(`SELECT seq, message_id, sender_id, device_id, ciphertext, header, created_at
				FROM messages WHERE room_id = ? AND bucket = ? AND seq > ? AND seq <= ?`,
				room, b, after, hi,
			).Consistency(gocql.LocalQuorum).IterContext(ctx)
			msg := Message{RoomID: room}
			for it.Scan(&msg.Seq, &msg.MessageID, &msg.SenderID, &msg.DeviceID, &msg.Ciphertext, &msg.Header, &msg.CreatedAt) {
				if !yield(msg, nil) {
					_ = it.Close()
					return
				}
				msg = Message{RoomID: room}
			}
			if err := it.Close(); err != nil {
				yield(Message{}, fmt.Errorf("messages: range room %x bucket %d: %w", room, b, err))
				return
			}
		}
	}
}

// bucket is the partition bucket holding seq.
func bucket(seq int64) int64 { return seq / BucketSize }

// bucketRange returns the first and last buckets holding seqs in (after, hi]
// for bucket size n: (after+1)/n … hi/n. ok is false when the range is empty.
func bucketRange(after, hi, n int64) (first, last int64, ok bool) {
	if hi <= after {
		return 0, 0, false
	}
	return (after + 1) / n, hi / n, true
}
