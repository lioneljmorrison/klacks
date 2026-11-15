// The chat half of the endpoint: the in-process hub that clients subscribe
// to (S-13), the resume flow (S-14), the per-room replay buffer with ack
// handling (S-15) and the backpressure that disconnects slow consumers
// (S-16).
//
// All hub state lives behind Manager.hubMu. Deliver, the fan-out entry point
// the core calls after each commit, is cheap and non-blocking: it takes the
// lock briefly and enqueues without waiting, so a publish is never held up
// by a slow consumer — the slow one is disconnected instead.
//
// Ordering: the core calls Deliver once per committed message, in commit
// order per room, but concurrent calls can reach this hub slightly out of
// seq order. Each subscription therefore sequences its own stream: it
// delivers seq lastSeq+1, holds anything ahead of that until its
// predecessors land, and skips anything behind (already served). Every
// subscription is anchored before it receives live fan-out — a resume at the
// watermark its replay ended at, a fresh subscribe at the watermark read
// when it subscribed — so the held messages always have predecessors that
// arrive, and no subscription is ever stuck waiting.
package ws

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// Chat is the slice of the chat core the endpoint serves; *core.Service
// implements it. The interface keeps the endpoint testable without stores.
type Chat interface {
	// PostMessage publishes p to room as sender and returns its seq.
	PostMessage(ctx context.Context, room, sender store.UUID, p core.Payload) (int64, error)
	// AuthorizeRead checks that user may read room.
	AuthorizeRead(ctx context.Context, room, user store.UUID) error
	// Hi returns the room's committed watermark hi (next_seq - 1).
	Hi(ctx context.Context, room store.UUID) (int64, error)
	// Resume authorizes user, reads the committed watermark hi and streams
	// the committed messages in (lastSeenSeq, hi] to deliver in seq order.
	// The caller must be buffering live delivery before calling, and drops
	// what it buffered at or below hi afterwards.
	Resume(ctx context.Context, room, user store.UUID, lastSeenSeq int64, deliver func(store.Message) error) (int64, error)
	// Members returns the room's member user ids: the resume flow leads
	// with the list, so a returning client reconciles membership changes
	// it was offline for (S-29).
	Members(ctx context.Context, room store.UUID) ([]store.UUID, error)
}

var _ Chat = (*core.Service)(nil)

// subscription is one connection's subscription to one room.
type subscription struct {
	conn *Conn
	room store.UUID

	// lastSeq is the last seq delivered to the connection, live or
	// replayed. Fan-out delivers lastSeq+1, holds what is ahead of it in
	// pending until its predecessors land, and skips what is behind.
	lastSeq int64
	pending map[int64]store.Message

	// acked is the seq the client has confirmed consuming (S-15): the
	// highest seq of an ack frame for this room.
	acked int64

	// buffering is true while a resume is replaying into the connection:
	// fan-out buffers into live instead of delivering, and the resume's
	// drain drops what is at or below the watermark it read. gen is bumped
	// on each resume start, so a superseded resume's drain is a no-op.
	buffering bool
	gen       int
	live      []store.Message
}

// roomState is the hub's state for one room with at least one subscriber.
type roomState struct {
	subs map[*Conn]*subscription

	// buffer is the in-memory replay buffer (S-15): recent committed
	// messages by seq, pruned from the low end by acks, age and size, so
	// the present seqs form the contiguous run bufMin..bufMax. bufMin == 0
	// means empty (seqs start at 1, so 0 is never a seq).
	buffer map[int64]store.Message
	bufMin int64
	bufMax int64
}

// Deliver fans a committed message out to the room's online subscribers.
// core.Service calls it after each publish commits (S-13); it is safe from
// any goroutine. With no subscribers there is nothing to do.
func (m *Manager) Deliver(_ context.Context, msg store.Message) {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	st := m.rooms[msg.RoomID]
	if st == nil {
		return
	}
	m.bufferAdd(st, msg)
	for _, sub := range st.subs {
		m.feedLocked(sub, msg)
	}
}

// feedLocked runs one fan-out message through a subscription's sequencer.
// Called with hubMu held.
func (m *Manager) feedLocked(sub *subscription, msg store.Message) {
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
	m.enqueueDeliver(sub, msg)
	m.drainPendingLocked(sub)
}

// drainPendingLocked delivers whatever buffered messages the subscription's
// chain has become contiguous with. Called with hubMu held.
func (m *Manager) drainPendingLocked(sub *subscription) {
	for {
		p, ok := sub.pending[sub.lastSeq+1]
		if !ok {
			return
		}
		delete(sub.pending, sub.lastSeq+1)
		m.enqueueDeliver(sub, p)
	}
}

// enqueueDeliver delivers one stored message to a subscriber and advances
// its lastSeq. Called with hubMu held; the enqueue itself is non-blocking.
func (m *Manager) enqueueDeliver(sub *subscription, msg store.Message) {
	m.enqueue(sub.conn, deliverFrame(msg))
	sub.lastSeq = msg.Seq
}

// deliverFrame converts a stored message to its wire frame.
func deliverFrame(msg store.Message) *protocol.Deliver {
	return &protocol.Deliver{
		RoomID:     protocol.UUID(msg.RoomID),
		Seq:        msg.Seq,
		MessageID:  protocol.UUID(msg.MessageID),
		SenderID:   protocol.UUID(msg.SenderID),
		DeviceID:   protocol.UUID(msg.DeviceID),
		Header:     msg.Header,
		Ciphertext: msg.Ciphertext,
	}
}

// bufferAdd puts msg in the room's replay buffer, then prunes it back within
// its bounds: entry count from the low end, and entries older than the
// window. Called with hubMu held.
func (m *Manager) bufferAdd(st *roomState, msg store.Message) {
	if st.bufMin != 0 && msg.Seq < st.bufMin {
		return // already pruned: resume falls back to the database for it
	}
	if st.buffer == nil {
		st.buffer = make(map[int64]store.Message)
	}
	st.buffer[msg.Seq] = msg
	if msg.Seq > st.bufMax {
		st.bufMax = msg.Seq
	}
	if st.bufMin == 0 || msg.Seq < st.bufMin {
		st.bufMin = msg.Seq
	}
	for st.bufMax-st.bufMin+1 > int64(m.ReplayEntries) {
		delete(st.buffer, st.bufMin)
		st.bufMin++
	}
	m.pruneBufferLocked(st)
}

// pruneBufferLocked drops buffered entries at or below the lowest acked seq
// of any subscriber (everyone connected has them; a later resume falls back
// to the database) and entries older than the replay window. Called with
// hubMu held.
func (m *Manager) pruneBufferLocked(st *roomState) {
	if len(st.buffer) == 0 {
		st.bufMin, st.bufMax = 0, 0
		return
	}
	minAck := int64(-1)
	for _, sub := range st.subs {
		if minAck < 0 || sub.acked < minAck {
			minAck = sub.acked
		}
	}
	if minAck > st.bufMin {
		for s := st.bufMin; s <= minAck && s <= st.bufMax; s++ {
			delete(st.buffer, s)
		}
		st.bufMin = minAck + 1
	}
	now := time.Now()
	for st.bufMin <= st.bufMax {
		oldest, ok := st.buffer[st.bufMin]
		if !ok || now.Sub(oldest.CreatedAt) <= m.ReplayWindow {
			break
		}
		delete(st.buffer, st.bufMin)
		st.bufMin++
	}
	if st.bufMin > st.bufMax {
		st.bufMin, st.bufMax = 0, 0
	}
}

// bufferTake returns copies of the room's messages in (lastSeen, hi] when
// the buffer covers the whole range: the fast resume path before the
// database (S-15). Called with hubMu held.
func bufferTake(st *roomState, lastSeen, hi int64) ([]store.Message, bool) {
	if hi <= lastSeen {
		return nil, true
	}
	if st.bufMin == 0 || st.bufMin > lastSeen+1 || st.bufMax < hi {
		return nil, false
	}
	out := make([]store.Message, 0, hi-lastSeen)
	for s := lastSeen + 1; s <= hi; s++ {
		msg, ok := st.buffer[s]
		if !ok {
			return nil, false
		}
		out = append(out, msg)
	}
	return out, true
}

// join subscribes c to room, idempotently, and returns the subscription.
func (m *Manager) join(c *Conn, room store.UUID) *subscription {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	return m.joinLocked(c, room)
}

func (m *Manager) joinLocked(c *Conn, room store.UUID) *subscription {
	st := m.rooms[room]
	if st == nil {
		st = &roomState{subs: make(map[*Conn]*subscription)}
		m.rooms[room] = st
	}
	if sub, ok := st.subs[c]; ok {
		return sub
	}
	sub := &subscription{conn: c, room: room}
	st.subs[c] = sub
	return sub
}

// detach removes c from every room it subscribed to; a room left without
// subscribers drops its whole state, replay buffer included. Resume falls
// back to the database until someone subscribes again.
func (m *Manager) detach(c *Conn) {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	for room, st := range m.rooms {
		if _, ok := st.subs[c]; ok {
			delete(st.subs, c)
			if len(st.subs) == 0 {
				delete(m.rooms, room)
			}
		}
	}
}

// drop removes c's subscription to room; a failed resume must not leave a
// half-served subscription behind. The client reconnects and retries.
func (m *Manager) drop(c *Conn, room store.UUID) {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	st := m.rooms[room]
	if st == nil {
		return
	}
	if _, ok := st.subs[c]; ok {
		delete(st.subs, c)
		if len(st.subs) == 0 {
			delete(m.rooms, room)
		}
	}
}

// doSubscribe authorizes the reader, then subscribes the connection to the
// room's live fan-out (S-13). The subscription is anchored at the room's
// committed watermark: everything at or below it was committed before the
// subscription and is skipped, everything after it is delivered live.
// Re-subscribing a subscribed connection is a no-op. There is no
// confirmation frame in v1; delivery itself is the confirmation.
//
// Live-only subscribe is best-effort: a message that commits while the
// subscription is being set up may be missed. Clients that must not miss
// anything resume instead, from their own last seen seq.
func (m *Manager) doSubscribe(ctx context.Context, c *Conn, f *protocol.Subscribe, log *slog.Logger) {
	room := store.UUID(f.RoomID)
	if err := m.Chat.AuthorizeRead(ctx, room, c.id.UserID); err != nil {
		m.replyError(c, err, f, log)
		return
	}
	hi, err := m.Chat.Hi(ctx, room)
	if err != nil {
		m.replyError(c, err, f, log)
		return
	}
	m.hubMu.Lock()
	sub := m.joinLocked(c, room)
	if !sub.buffering && sub.lastSeq == 0 && hi > sub.lastSeq {
		// A fresh subscription: anchor at the watermark just read. An
		// existing one keeps its place in the stream.
		sub.lastSeq = hi
	}
	m.hubMu.Unlock()
}

// doResume runs the resume flow (S-14), in the order the plan fixes:
// authorize; subscribe to live and buffer; read hi and replay (lastSeenSeq,
// hi] — from the replay buffer when it covers the range (S-15), otherwise
// from the database with missing-seq retry; drain the live buffer, dropping
// anything <= hi, then continue live. Duplicate resume requests are
// idempotent: the subscription is keyed by connection and room, and the flow
// re-runs from the client's lastSeenSeq.
func (m *Manager) doResume(ctx context.Context, c *Conn, f *protocol.Resume, log *slog.Logger) {
	room := store.UUID(f.RoomID)
	if err := m.Chat.AuthorizeRead(ctx, room, c.id.UserID); err != nil {
		m.replyError(c, err, f, log)
		return
	}
	// The resume flow leads with the room's current member list (S-29):
	// the client reconciles membership it missed while offline before the
	// replayed messages arrive.
	members, err := m.Chat.Members(ctx, room)
	if err != nil {
		m.replyError(c, err, f, log)
		return
	}
	m.enqueue(c, &protocol.Members{RoomID: f.RoomID, Members: memberIDs(members)})
	sub := m.join(c, room)
	gen := m.startReplay(sub)
	hi, err := m.replayRoom(ctx, room, c.id.UserID, f.LastSeenSeq, func(msg store.Message) error {
		return m.enqueueMsg(c, msg)
	})
	if err != nil {
		m.drop(c, room)
		m.replyError(c, err, f, log)
		return
	}
	m.drain(sub, gen, hi)
}

// memberIDs converts the core's member list for the wire.
func memberIDs(members []store.UUID) []protocol.UUID {
	out := make([]protocol.UUID, len(members))
	for i, u := range members {
		out[i] = protocol.UUID(u)
	}
	return out
}

// MemberRemoved fans a committed membership change out to the room's
// subscribers (S-29): the core calls it synchronously after the removal
// commits, and every subscriber gets a member_removed frame. It is safe
// from any goroutine and, like Deliver, never blocks a caller. The event
// is live-only — not replayed by resume; the members frame carries the
// authoritative list there instead. The removed member, still subscribed
// until its connection ends, receives the event too; its client clears
// its state for the room.
func (m *Manager) MemberRemoved(_ context.Context, ev core.MemberRemoved) {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	st := m.rooms[ev.Room]
	if st == nil {
		return
	}
	f := &protocol.MemberRemoved{
		RoomID: protocol.UUID(ev.Room),
		User:   protocol.UUID(ev.User),
		Actor:  protocol.UUID(ev.Actor),
	}
	for _, sub := range st.subs {
		m.enqueue(sub.conn, f)
	}
}

// replayRoom streams (lastSeenSeq, hi] to deliver, trying the room's
// in-memory replay buffer first (S-15): the committed watermark is read from
// the core, and when the buffer covers the whole range the database is not
// touched. Otherwise Chat.Resume does the replay from the database, with its
// own watermark read and missing-seq retry. Both paths end at a committed
// watermark, which drain needs.
func (m *Manager) replayRoom(ctx context.Context, room, user store.UUID, lastSeenSeq int64, deliver func(store.Message) error) (int64, error) {
	hi, err := m.Chat.Hi(ctx, room)
	if err != nil {
		return 0, err
	}
	m.hubMu.Lock()
	var buffered []store.Message
	if st := m.rooms[room]; st != nil {
		buffered, _ = bufferTake(st, lastSeenSeq, hi)
	}
	m.hubMu.Unlock()
	if buffered != nil || hi <= lastSeenSeq {
		for _, msg := range buffered {
			if err := deliver(msg); err != nil {
				return hi, err
			}
		}
		return hi, nil
	}
	return m.Chat.Resume(ctx, room, user, lastSeenSeq, deliver)
}

// startReplay marks the subscription as buffering live delivery for this
// resume, superseding any earlier one, and returns the generation.
func (m *Manager) startReplay(sub *subscription) int {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	sub.gen++
	sub.buffering = true
	sub.live = nil
	return sub.gen
}

// drain ends a resume: the subscription is anchored at the watermark hi the
// replay ended at, and the live buffer accumulated while the replay ran is
// fed through the sequencer — everything at or below hi is skipped (the
// replay covered it; skipping keeps the stream free of duplicates), the rest
// is delivered in order. A superseded resume does nothing.
func (m *Manager) drain(sub *subscription, gen int, hi int64) {
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	if sub.gen != gen {
		return
	}
	sub.buffering = false
	live := sub.live
	sub.live = nil
	if hi > sub.lastSeq {
		sub.lastSeq = hi
	}
	for s := range sub.pending {
		if s <= hi {
			delete(sub.pending, s)
		}
	}
	for _, msg := range live {
		m.feedLocked(sub, msg)
	}
}

// enqueueMsg delivers one replayed message; it fails when the connection
// cannot take it (closed, or disconnected as a slow consumer), which aborts
// the replay.
func (m *Manager) enqueueMsg(c *Conn, msg store.Message) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errConnClosed
	}
	m.enqueue(c, deliverFrame(msg))
	return nil
}

var errConnClosed = errors.New("connection closed")

// ack records the client's consumption progress (S-15) and prunes the room's
// replay buffer. Acking a room the connection is not subscribed to is
// accepted and ignored: there is nothing to advance. It runs inline in the
// read loop: no database, only hub state.
func (m *Manager) ack(c *Conn, f *protocol.Ack) {
	room := store.UUID(f.RoomID)
	m.hubMu.Lock()
	defer m.hubMu.Unlock()
	st := m.rooms[room]
	if st == nil {
		return
	}
	sub, ok := st.subs[c]
	if !ok || f.Seq <= sub.acked {
		return
	}
	sub.acked = f.Seq
	m.pruneBufferLocked(st)
}

// doPublish posts the frame's payload through the core (S-13). Success has
// no per-sender confirmation frame in v1: the message comes back as live or
// resumed delivery like everyone else's. On failure the sender gets an error
// frame naming its room and message.
func (m *Manager) doPublish(ctx context.Context, c *Conn, f *protocol.Publish, log *slog.Logger) {
	p := core.Payload{
		MessageID:  store.UUID(f.MessageID),
		DeviceID:   store.UUID(f.DeviceID),
		Ciphertext: f.Ciphertext,
		Header:     f.Header,
	}
	if m.PublishTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.PublishTimeout)
		defer cancel()
	}
	if _, err := m.Chat.PostMessage(ctx, store.UUID(f.RoomID), c.id.UserID, p); err != nil {
		m.replyError(c, err, f, log)
	}
}

// replyError sends an error frame for a failed request, naming it.
func (m *Manager) replyError(c *Conn, err error, f protocol.Frame, log *slog.Logger) {
	e := protocol.ErrorFor(err)
	setRefs(e, f)
	m.enqueue(c, e)
	// The client gets no detail for these two, so the log must carry it.
	switch e.Code {
	case protocol.CodeInternal:
		log.Error("ws request failed", "code", e.Code, "err", err)
	case protocol.CodeUnavailable:
		log.Warn("ws request failed: store unavailable", "code", e.Code, "err", err)
	default:
		log.Debug("ws request failed", "code", e.Code, "err", err)
	}
}
