// The subscription hub: Subscribe's resume flow and the fan-out the core
// calls after each commit.
//
// All hub state lives behind Service.hubMu, and every send to a
// subscription's channel happens while it is held, so a close can never race
// a send. Deliver, the core's post-commit fan-out entry point, is cheap and
// non-blocking: it takes the lock briefly and never waits — a consumer that
// cannot keep up has its subscription closed instead.
//
// Ordering: the core calls Deliver once per committed message, in commit
// order per room, but concurrent calls can reach this hub slightly out of
// seq order. Each subscription therefore sequences its own stream: it
// delivers seq lastSeq+1, holds anything ahead of that until its
// predecessors land, and skips anything behind (already served). Every
// subscription is anchored before it receives live fan-out — its registration
// sets buffering, the resume's drain re-anchors at the watermark its replay
// ended at — so held messages always have predecessors that arrive, and no
// subscription is ever stuck waiting.
package chat

import (
	"context"
	"errors"
	"fmt"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// subscription is one Subscribe call's stream: a queue the embedder reads,
// fed by replay and live fan-out, all sequenced through lastSeq/pending.
// Every field is guarded by the owning Service's hubMu.
type subscription struct {
	room store.UUID
	ch   chan Message

	// lastSeq is the last seq delivered, live or replayed. Fan-out delivers
	// lastSeq+1, holds what is ahead of it in pending until its predecessors
	// land, and skips what is behind.
	lastSeq int64
	pending map[int64]store.Message

	// buffering is true from registration until the resume's drain: fan-out
	// buffers into live instead of delivering, and the drain drops what is
	// at or below the watermark the replay read.
	buffering bool
	live      []store.Message

	// closed is set once; ch is closed at the same time and no send happens
	// after it. cancel stops the resume pump's context (Close).
	closed bool
	cancel context.CancelFunc
}

// Subscribe returns a channel streaming the room's messages with
// seq > fromSeq, exactly once each and in seq order: every committed message
// above fromSeq replayed, then live fan-out. The channel closes when ctx is
// cancelled, the service is closed, a store error ends the replay, or the
// consumer falls behind (Config.SendQueue); the consumer resubscribes from
// the last seq it received. fromSeq 0 replays the whole room.
//
// The subscription is anchored before it can miss anything: it is registered
// buffering before the watermark is read, so a commit landing during the
// replay is delivered once, by replay or live fan-out, never twice or not at
// all.
func (s *Service) Subscribe(ctx context.Context, room RoomID, fromSeq Seq) (<-chan Message, error) {
	if fromSeq < 0 {
		return nil, fmt.Errorf("subscribe: %w: from_seq %d < 0", ErrInvalidArgument, fromSeq)
	}
	s.hubMu.Lock()
	stopping := s.stopping
	s.hubMu.Unlock()
	if stopping {
		return nil, fmt.Errorf("subscribe: %w", ErrClosed)
	}
	// The same read authorization as the WebSocket resume path: the actor's
	// role, read outside the room lock, through the central authorizer.
	if err := s.core.AuthorizeRead(ctx, store.UUID(room), store.UUID(s.cfg.Actor)); err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}

	pctx, cancel := context.WithCancel(ctx)
	s.hubMu.Lock()
	if s.stopping { // Close won the race with the authorization above
		s.hubMu.Unlock()
		cancel()
		return nil, fmt.Errorf("subscribe: %w", ErrClosed)
	}
	sub := &subscription{
		room:      store.UUID(room),
		ch:        make(chan Message, s.queueSize()),
		lastSeq:   int64(fromSeq),
		buffering: true, // until the drain: fan-out buffers instead of delivering
		cancel:    cancel,
	}
	subs := s.hub[sub.room]
	if subs == nil {
		subs = make(map[*subscription]struct{})
		s.hub[sub.room] = subs
	}
	subs[sub] = struct{}{}
	s.wg.Add(1)
	s.hubMu.Unlock()

	go s.runSubscription(pctx, sub, int64(fromSeq))
	return sub.ch, nil
}

// runSubscription is one subscription's resume pump: it replays (fromSeq,
// hi] through the core's Resume — the WebSocket resume path — drains the
// live buffer at the watermark, then leaves the stream to fan-out until ctx
// is done. Its deferred cleanup closes the channel and forgets the
// subscription whatever ended it.
func (s *Service) runSubscription(ctx context.Context, sub *subscription, fromSeq int64) {
	defer s.wg.Done()
	defer func() {
		s.hubMu.Lock()
		defer s.hubMu.Unlock()
		s.closeSubLocked(sub)
	}()
	hi, err := s.core.Resume(ctx, sub.room, store.UUID(s.cfg.Actor), fromSeq, func(msg store.Message) error {
		return s.replayDeliver(sub, msg)
	})
	if err != nil {
		return // the deferred cleanup closes the channel: resubscribe from the last seq
	}
	s.drain(sub, hi)
	<-ctx.Done()
}

// replayDeliver delivers one replayed message. A full queue closes the
// subscription and aborts the replay: the consumer is not keeping up.
func (s *Service) replayDeliver(sub *subscription, msg store.Message) error {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	if sub.closed {
		return errSubClosed
	}
	select {
	case sub.ch <- toChatMessage(msg):
		return nil
	default:
		s.closeSlowLocked(sub, msg)
		return errSubClosed
	}
}

// Deliver fans a committed message out to the room's subscriptions. The
// core calls it after each publish commits, in publish order; it is safe
// from any goroutine and never blocks. With no subscribers there is nothing
// to do.
func (s *Service) Deliver(_ context.Context, msg store.Message) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	for sub := range s.hub[msg.RoomID] {
		s.feedLocked(sub, msg)
	}
}

// feedLocked runs one fan-out message through a subscription's sequencer.
// Called with hubMu held.
func (s *Service) feedLocked(sub *subscription, msg store.Message) {
	if sub.closed {
		return
	}
	if sub.buffering {
		sub.live = append(sub.live, msg)
		return
	}
	if msg.Seq <= sub.lastSeq {
		return // behind the stream: already served
	}
	if msg.Seq > sub.lastSeq+1 {
		if sub.pending == nil {
			sub.pending = make(map[int64]store.Message)
		}
		sub.pending[msg.Seq] = msg
		return
	}
	// A stale pending entry for this seq (a drain can leave one just above
	// the watermark) must not be delivered again on top of this fan-out.
	delete(sub.pending, msg.Seq)
	s.deliverLocked(sub, msg)
	s.drainPendingLocked(sub)
}

// drainPendingLocked delivers whatever the subscription's chain has become
// contiguous with. Called with hubMu held.
func (s *Service) drainPendingLocked(sub *subscription) {
	for !sub.closed {
		p, ok := sub.pending[sub.lastSeq+1]
		if !ok {
			return
		}
		delete(sub.pending, sub.lastSeq+1)
		s.deliverLocked(sub, p)
	}
}

// deliverLocked delivers one fan-out message and advances the subscription.
// Called with hubMu held. A full queue closes the subscription: the embedder
// is not keeping up.
func (s *Service) deliverLocked(sub *subscription, msg store.Message) {
	select {
	case sub.ch <- toChatMessage(msg):
		sub.lastSeq = msg.Seq
	default:
		s.closeSlowLocked(sub, msg)
	}
}

// closeSlowLocked closes a subscription whose consumer fell behind and
// forgets it. Called with hubMu held; closeSlowLocked is the one place that
// both closes and unregisters outside of teardown.
func (s *Service) closeSlowLocked(sub *subscription, msg store.Message) {
	s.log.Warn("chat: slow consumer: closing subscription (resubscribe from the last seq received)",
		"room", store.FormatUUID(sub.room), "stalled_at_seq", msg.Seq)
	if sub.cancel != nil {
		sub.cancel()
	}
	s.closeSubLocked(sub)
}

// closeSubLocked marks a subscription closed and closes its channel;
// whatever is queued stays readable, then the receive ends. Called with
// hubMu held.
func (s *Service) closeSubLocked(sub *subscription) {
	if sub.closed {
		return
	}
	sub.closed = true
	close(sub.ch)
	if subs := s.hub[sub.room]; subs != nil {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(s.hub, sub.room)
		}
	}
}

// drain ends a subscription's resume: the subscription is anchored at the
// watermark hi the replay ended at, and the live buffer accumulated while
// the replay ran is fed through the sequencer — everything at or below hi is
// skipped (the replay covered it; skipping keeps the stream free of
// duplicates), the rest is delivered in order.
func (s *Service) drain(sub *subscription, hi int64) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	if sub.closed {
		return
	}
	sub.buffering = false
	live := sub.live
	sub.live = nil
	if hi > sub.lastSeq {
		sub.lastSeq = hi
	}
	for seq := range sub.pending {
		if seq <= hi {
			delete(sub.pending, seq)
		}
	}
	for _, msg := range live {
		s.feedLocked(sub, msg)
	}
}

// errSubClosed aborts a replay whose subscription ended meanwhile.
var errSubClosed = errors.New("subscription closed")

// toChatMessage converts a stored message to the public type.
func toChatMessage(m store.Message) Message {
	return Message{
		RoomID:     RoomID(m.RoomID),
		Seq:        Seq(m.Seq),
		MessageID:  m.MessageID,
		SenderID:   UserID(m.SenderID),
		DeviceID:   m.DeviceID,
		Ciphertext: m.Ciphertext,
		Header:     m.Header,
		CreatedAt:  m.CreatedAt,
	}
}
