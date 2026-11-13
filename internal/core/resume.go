package core

import (
	"context"
	"fmt"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// maxReplayAttempts bounds the retries of a seq <= hi that a read fails to
// return, and replayRetryDelay is the pause between attempts. The committed
// watermark promises every seq <= hi exists, so a read that skips one is a
// transient store failure (a LOCAL_QUORUM read that missed a replica).
const (
	maxReplayAttempts = 4
	replayRetryDelay  = 25 * time.Millisecond
)

// AuthorizeRead checks that user may read room (S-14): the member role is
// read outside the room lock and passed to the central authorizer. It
// returns ErrNotMember, ErrForbidden or ErrRoomNotFound.
func (s *Service) AuthorizeRead(ctx context.Context, room, user store.UUID) error {
	role, _, err := s.rooms.Role(ctx, room, user)
	if err != nil {
		return fmt.Errorf("read room %x: %w", room, err)
	}
	if err := authorize(request{actor: Role(role), action: actRead}); err != nil {
		return fmt.Errorf("read room %x: %w", room, err)
	}
	return nil
}

// Resume is the server half of the resume protocol (S-14). It authorizes
// user to read room, reads the committed watermark hi (room_seq.next_seq - 1)
// with a plain SELECT, no room lock, and streams the room's committed
// messages in (lastSeenSeq, hi] to deliver in seq order. It returns hi.
//
// The caller must have started buffering live delivery before calling: it
// drops what it buffered at or below hi afterwards, so a commit landing
// between the watermark read and the replay is delivered once. A seq <= hi
// that a read fails to return is retried, never skipped. deliver may stop
// the stream early by returning an error, which Resume returns as is.
func (s *Service) Resume(ctx context.Context, room, user store.UUID, lastSeenSeq int64, deliver func(store.Message) error) (int64, error) {
	if lastSeenSeq < 0 {
		return 0, fmt.Errorf("resume: %w: last_seen_seq %d < 0", ErrInvalidArgument, lastSeenSeq)
	}
	if err := s.AuthorizeRead(ctx, room, user); err != nil {
		return 0, fmt.Errorf("resume: %w", err)
	}
	hi, err := s.rooms.Watermark(ctx, room)
	if err != nil {
		return 0, fmt.Errorf("resume: %w", err)
	}
	if err := s.replay(ctx, room, lastSeenSeq, hi, deliver); err != nil {
		return hi, err
	}
	return hi, nil
}

// Hi returns the room's committed watermark hi: room_seq.next_seq - 1, read
// with a plain SELECT, without the room lock (S-14). Every seq <= hi is in
// the message store; rows above it may be uncommitted orphans and must never
// be served. It returns ErrRoomNotFound for a room that does not exist.
func (s *Service) Hi(ctx context.Context, room store.UUID) (int64, error) {
	hi, err := s.rooms.Watermark(ctx, room)
	if err != nil {
		return 0, fmt.Errorf("watermark: %w", err)
	}
	return hi, nil
}

// replay streams (after, hi] in seq order to deliver. Range scans the
// buckets (after+1)/N … hi/N at LOCAL_QUORUM and yields what it finds; a seq
// <= hi that comes back missing is retried from that seq, never skipped. A
// gap ends the scan early and retries: everything the scan did yield stays
// delivered, and the retry re-reads from the gap. deliver's error stops the
// stream and is returned unwrapped.
func (s *Service) replay(ctx context.Context, room store.UUID, after, hi int64, deliver func(store.Message) error) error {
	next := after + 1
	for attempts := 0; next <= hi; {
		progressed := false
		for msg, err := range s.messages.Range(ctx, room, next-1, hi) {
			if err != nil {
				return fmt.Errorf("replay room %x: %w", room, err)
			}
			if msg.Seq < next {
				continue // below the cursor already served
			}
			if msg.Seq > next {
				break // gap at next: retry from there
			}
			if err := deliver(msg); err != nil {
				return err
			}
			next++
			progressed = true
		}
		if next > hi {
			return nil
		}
		if !progressed {
			attempts++
			if attempts >= maxReplayAttempts {
				return fmt.Errorf("replay room %x: seq %d missing after %d attempts", room, next, attempts)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(replayRetryDelay):
			}
		}
	}
	return nil
}
