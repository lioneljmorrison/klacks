package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// MaxPayloadSize caps a message's ciphertext and header together.
// store.BucketSize is chosen against it: a ScyllaDB partition holds at most
// BucketSize × MaxPayloadSize bytes of payload. Do not raise it without
// revisiting BucketSize.
const MaxPayloadSize = 64 << 10

var ErrPayloadTooLarge = errors.New("payload too large")

// Payload is a message as the sender submits it. The server never sees
// plaintext: Ciphertext and Header are opaque. The client generates
// MessageID. DeviceID is the sender's device; it is not checked yet.
type Payload struct {
	MessageID  store.UUID
	DeviceID   store.UUID
	Ciphertext []byte
	Header     []byte
}

// PostMessage publishes p to room as sender and returns its seq. Seqs are
// per room, gap-free and start at 1.
//
// The ordering (plan §3.3c) is what makes seq gap-free:
//
//  1. Lock the room's room_seq row (store.Rooms.Locked) and check that the
//     sender is a member, all in one transaction. N = next_seq.
//  2. Take a write timestamp from message_write_ts after the lock.
//  3. Write message N to ScyllaDB with that timestamp.
//  4. Only after that succeeds, advance next_seq to N+1 and commit. On any
//     failure the transaction rolls back and the error is returned.
//
// The committed next_seq - 1 is the durable watermark: every seq at or below
// it exists in ScyllaDB. A failure after step 3 leaves an orphan at N, above
// the watermark, that is never served. The next publish reuses N with a
// higher timestamp and overwrites it.
//
// Known limitation: if COMMIT fails after the ScyllaDB write, the commit may
// still have happened, and a sender that retries can post a duplicate. The
// eventual fix is idempotent publish by MessageID.
func (s *Service) PostMessage(ctx context.Context, room, sender store.UUID, p Payload) (int64, error) {
	if n := len(p.Ciphertext) + len(p.Header); n > MaxPayloadSize {
		return 0, fmt.Errorf("post message: %d bytes > %d: %w", n, MaxPayloadSize, ErrPayloadTooLarge)
	}
	var seq int64
	var committed store.Message
	err := s.rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		role, err := memberRole(ctx, l, sender)
		if err != nil {
			return err
		}
		if err := authorize(request{actor: role, action: actPost}); err != nil {
			return fmt.Errorf("post message: %w", err)
		}
		ts, err := l.WriteTS(ctx)
		if err != nil {
			return err
		}
		seq = l.NextSeq()
		committed = store.Message{
			RoomID:     room,
			Seq:        seq,
			MessageID:  p.MessageID,
			SenderID:   sender,
			DeviceID:   p.DeviceID,
			Ciphertext: p.Ciphertext,
			Header:     p.Header,
			CreatedAt:  time.Now().UTC().Truncate(time.Millisecond),
		}
		err = s.messages.Insert(ctx, committed, ts)
		if err != nil {
			return fmt.Errorf("post message: %w", err)
		}
		return l.AdvanceSeq(ctx)
	})
	if err != nil {
		return 0, err
	}
	// Fan-out to online subscribers (S-13), after the commit: the message is
	// durable, so live delivery never shows a seq above the watermark. In
	// publish order, because the next publish cannot reach this point until
	// its room lock, freed by the commit above.
	if s.onPosted != nil {
		s.onPosted(ctx, committed)
	}
	return seq, nil
}
