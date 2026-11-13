package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// fakeChat is a Chat whose answers the test sets per case.
type fakeChat struct {
	mu       sync.Mutex
	authzErr error
	hi       int64
	hiErr    error

	posts   []core.Payload
	postSeq int64
	postErr error

	resumes    int
	resumeHi   int64
	resumeMsgs []store.Message
	resumeErr  error
	before     func() // runs at the start of Resume, e.g. to fan out a live frame
}

func (f *fakeChat) PostMessage(_ context.Context, room, sender store.UUID, p core.Payload) (int64, error) {
	f.mu.Lock()
	f.posts = append(f.posts, p)
	if f.postErr != nil {
		err := f.postErr
		f.mu.Unlock()
		return 0, err
	}
	f.postSeq++
	seq := f.postSeq
	f.mu.Unlock()
	return seq, nil
}

func (f *fakeChat) AuthorizeRead(_ context.Context, _, _ store.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authzErr
}

func (f *fakeChat) Hi(_ context.Context, _ store.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hi, f.hiErr
}

func (f *fakeChat) Resume(_ context.Context, _, _ store.UUID, lastSeen int64, deliver func(store.Message) error) (int64, error) {
	f.mu.Lock()
	f.resumes++
	before := f.before
	msgs := append([]store.Message(nil), f.resumeMsgs...)
	hi, err := f.resumeHi, f.resumeErr
	f.mu.Unlock()
	if before != nil {
		before()
	}
	for _, msg := range msgs {
		if msg.Seq <= lastSeen {
			continue
		}
		if err := deliver(msg); err != nil {
			return hi, err
		}
	}
	return hi, err
}

func (f *fakeChat) postCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.posts)
}

func (f *fakeChat) resumeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resumes
}

// newChatTestServer returns a Manager with chat as its core.
func newChatTestServer(t *testing.T, chat Chat, sendQueue int) (*Manager, *httptest.Server) {
	t.Helper()
	m := NewManager(auth.Dev{}, discard)
	m.PingInterval, m.PingTimeout = time.Minute, time.Minute
	if sendQueue != 0 {
		m.SendQueue = sendQueue
	}
	m.Chat = chat
	srv := httptest.NewServer(m)
	t.Cleanup(func() {
		m.Close()
		srv.Close()
	})
	return m, srv
}

// serverFrame parses one server-to-client frame. protocol.Decode only reads
// client-to-server frames.
func serverFrame(b []byte) (protocol.Frame, error) {
	var env protocol.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	switch env.Type {
	case protocol.TypeDeliver:
		d := new(protocol.Deliver)
		return d, json.Unmarshal(b, d)
	case protocol.TypeError:
		e := new(protocol.Error)
		return e, json.Unmarshal(b, e)
	}
	return nil, fmt.Errorf("unexpected server frame type %q", env.Type)
}

// readFrames reads the connection until it closes; each value is a
// protocol.Frame or the error that ended the connection.
func readFrames(c *websocket.Conn) <-chan any {
	out := make(chan any, 256)
	go func() {
		defer close(out)
		for {
			typ, b, err := c.Read(context.Background())
			if err != nil {
				out <- err
				return
			}
			if typ != websocket.MessageText {
				out <- errors.New("binary frame")
				return
			}
			f, err := serverFrame(b)
			if err != nil {
				out <- err
				return
			}
			out <- f
		}
	}()
	return out
}

// next returns the next frame or close, failing the test after d.
func next(t *testing.T, ch <-chan any, d time.Duration) any {
	t.Helper()
	select {
	case v, ok := <-ch:
		if !ok {
			t.Fatal("reader ended without a close")
		}
		return v
	case <-time.After(d):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

// wantNothing fails the test if a frame or close arrives within d.
func wantNothing(t *testing.T, ch <-chan any, d time.Duration) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("unexpected frame or close: %v", v)
	case <-time.After(d):
	}
}

// deliverOf asserts v is a deliver frame and returns it.
func deliverOf(t *testing.T, v any) *protocol.Deliver {
	t.Helper()
	d, ok := v.(*protocol.Deliver)
	if !ok {
		t.Fatalf("got %T (%v); want a deliver frame", v, v)
	}
	return d
}

// errorOf asserts v is an error frame and returns it.
func errorOf(t *testing.T, v any) *protocol.Error {
	t.Helper()
	e, ok := v.(*protocol.Error)
	if !ok {
		t.Fatalf("got %T (%v); want an error frame", v, v)
	}
	return e
}

func testRoom(t *testing.T) store.UUID {
	t.Helper()
	return store.UUID(mustID(t, roomStr))
}

// storedMsg builds a message as the core would deliver it.
func storedMsg(t *testing.T, room store.UUID, seq int64) store.Message {
	t.Helper()
	return store.Message{
		RoomID: room,
		Seq:    seq,
		MessageID: store.UUID{
			0: 0x0f, 14: byte(seq >> 8), 15: byte(seq),
		},
		SenderID:   store.UUID(mustID(t, userStr)),
		DeviceID:   store.UUID(mustID(t, deviceStr)),
		Ciphertext: []byte{byte(seq), 0x2b},
		Header:     []byte("hdr"),
		CreatedAt:  time.Now().UTC().Truncate(time.Millisecond),
	}
}

// waitSubs waits until room has n subscribers.
func waitSubs(t *testing.T, m *Manager, room store.UUID, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.hubMu.Lock()
		st := m.rooms[room]
		got := 0
		if st != nil {
			got = len(st.subs)
		}
		m.hubMu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("room has %d subscribers; want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sendFrame(t *testing.T, c *websocket.Conn, f protocol.Frame) {
	t.Helper()
	b, err := protocol.Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func TestSubscribeRegistersAndReceives(t *testing.T) {
	chat := &fakeChat{}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)
	room := testRoom(t)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	waitSubs(t, m, room, 1)

	m.Deliver(context.Background(), storedMsg(t, room, 1))
	d := deliverOf(t, next(t, frames, 5*time.Second))
	if d.RoomID != mustID(t, roomStr) || d.Seq != 1 {
		t.Errorf("deliver = room %v seq %d; want room %v seq 1", d.RoomID, d.Seq, mustID(t, roomStr))
	}
	if !bytes.Equal(d.Ciphertext, storedMsg(t, room, 1).Ciphertext) {
		t.Errorf("ciphertext = %x; want the stored payload", d.Ciphertext)
	}
}

func TestSubscribeRejectsNonMember(t *testing.T) {
	chat := &fakeChat{authzErr: core.ErrNotMember}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	e := errorOf(t, next(t, frames, 5*time.Second))
	if e.Code != protocol.CodeNotMember || e.RoomID != mustID(t, roomStr) {
		t.Errorf("error = %+v; want not_member naming the room", e)
	}
	waitSubs(t, m, testRoom(t), 0)
}

func TestSubscribeRoomMissing(t *testing.T) {
	chat := &fakeChat{hiErr: core.ErrRoomNotFound, authzErr: nil}
	// Authorization succeeds but the watermark read fails with
	// room_not_found, as it does for a room that does not exist.
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	e := errorOf(t, next(t, frames, 5*time.Second))
	if e.Code != protocol.CodeRoomNotFound || e.RoomID != mustID(t, roomStr) {
		t.Errorf("error = %+v; want room_not_found naming the room", e)
	}
	waitSubs(t, m, testRoom(t), 0)
}

func TestPublishForwardsPayload(t *testing.T) {
	chat := &fakeChat{}
	_, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Publish{
		RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr),
		Header: []byte("hdr"), Ciphertext: []byte("ct"),
	})
	deadline := time.Now().Add(5 * time.Second)
	for chat.postCount() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("publish never reached the core")
		}
		time.Sleep(5 * time.Millisecond)
	}
	posts := chat.posts
	if len(posts) != 1 || string(posts[0].Ciphertext) != "ct" || string(posts[0].Header) != "hdr" {
		t.Errorf("posts = %+v; want the frame's payload", posts)
	}
	if got := posts[0].MessageID; got != store.UUID(mustID(t, msgStr)) {
		t.Errorf("message id = %x; want %x", got, mustID(t, msgStr))
	}
	wantNothing(t, frames, 100*time.Millisecond) // no confirmation frame in v1
}

func TestPublishErrorNamesRequest(t *testing.T) {
	chat := &fakeChat{postErr: core.ErrNotMember}
	_, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Publish{
		RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr),
		Ciphertext: []byte("ct"),
	})
	e := errorOf(t, next(t, frames, 5*time.Second))
	if e.Code != protocol.CodeNotMember || e.RoomID != mustID(t, roomStr) || e.MessageID != mustID(t, msgStr) {
		t.Errorf("error = %+v; want not_member naming the room and message", e)
	}
}

// Fan-out holds a seq that arrived ahead of its predecessors and delivers it
// once they land, in order.
func TestFanoutHeldUntilPredecessor(t *testing.T) {
	chat := &fakeChat{}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)
	room := testRoom(t)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	waitSubs(t, m, room, 1)

	ctx := context.Background()
	m.Deliver(ctx, storedMsg(t, room, 1))
	m.Deliver(ctx, storedMsg(t, room, 3)) // ahead: held
	m.Deliver(ctx, storedMsg(t, room, 2)) // completes the chain: 2 then 3

	for seq := int64(1); seq <= 3; seq++ {
		if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != seq {
			t.Fatalf("deliver seq = %d; want %d (stream out of order)", d.Seq, seq)
		}
	}
	// A repeated fan-out of a served seq is skipped.
	m.Deliver(ctx, storedMsg(t, room, 1))
	m.Deliver(ctx, storedMsg(t, room, 4))
	if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != 4 {
		t.Fatalf("deliver seq = %d; want 4", d.Seq)
	}
	wantNothing(t, frames, 100*time.Millisecond)
}

// Fan-out goes only to the room's subscribers.
func TestFanoutOnlyToSubscribers(t *testing.T) {
	chat := &fakeChat{}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)
	roomA := store.UUID(mustID(t, roomStr))
	roomB := store.UUID(mustID(t, msgStr))

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	waitSubs(t, m, roomA, 1)

	m.Deliver(context.Background(), storedMsg(t, roomB, 1)) // other room
	wantNothing(t, frames, 100*time.Millisecond)
	m.Deliver(context.Background(), storedMsg(t, roomA, 1))
	deliverOf(t, next(t, frames, 5*time.Second))
}

// A fresh subscribe is anchored at the watermark read when it subscribed:
// fan-out at or below it is skipped.
func TestSubscribeAnchoredAtWatermark(t *testing.T) {
	chat := &fakeChat{hi: 5}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)
	room := testRoom(t)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	waitSubs(t, m, room, 1)

	ctx := context.Background()
	m.Deliver(ctx, storedMsg(t, room, 5)) // at the watermark: skipped
	m.Deliver(ctx, storedMsg(t, room, 6)) // the first live message
	m.Deliver(ctx, storedMsg(t, room, 7))
	if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != 6 {
		t.Fatalf("deliver seq = %d; want 6", d.Seq)
	}
	if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != 7 {
		t.Fatalf("deliver seq = %d; want 7", d.Seq)
	}
	wantNothing(t, frames, 100*time.Millisecond)
}

// Resume replays through the core and anchors the subscription at the
// watermark, so live fan-out continues without a gap or a duplicate.
func TestResumeReplayThenLive(t *testing.T) {
	room := testRoom(t)
	msgs := []store.Message{storedMsg(t, room, 1), storedMsg(t, room, 2), storedMsg(t, room, 3)}
	chat := &fakeChat{resumeHi: 3, hi: 3, resumeMsgs: msgs}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Resume{RoomID: mustID(t, roomStr), LastSeenSeq: 0})
	for seq := int64(1); seq <= 3; seq++ {
		if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != seq {
			t.Fatalf("deliver seq = %d; want %d", d.Seq, seq)
		}
	}
	// The subscription is anchored at 3: live fan-out continues at 4,
	// and a late replay-range duplicate is skipped.
	m.Deliver(context.Background(), storedMsg(t, room, 2))
	m.Deliver(context.Background(), storedMsg(t, room, 4))
	if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != 4 {
		t.Fatalf("deliver seq = %d; want 4", d.Seq)
	}
	wantNothing(t, frames, 100*time.Millisecond)
}

// Live fan-out that lands while the resume is replaying is buffered and
// drained: below the watermark it is dropped (the replay covered it), above
// it the buffer is delivered after the replay.
func TestResumeBuffersLiveDuringReplay(t *testing.T) {
	room := testRoom(t)
	msgs := []store.Message{storedMsg(t, room, 1), storedMsg(t, room, 2)}
	chat := &fakeChat{resumeHi: 2, hi: 2, resumeMsgs: msgs}
	m, srv := newChatTestServer(t, chat, 0)
	chat.mu.Lock()
	chat.before = func() {
		// Fan-out racing the replay: 2 is at or below the watermark, 3
		// is above it. Out of order, as concurrent publishes arrive.
		ctx := context.Background()
		m.Deliver(ctx, storedMsg(t, room, 3))
		m.Deliver(ctx, storedMsg(t, room, 2))
	}
	chat.mu.Unlock()
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Resume{RoomID: mustID(t, roomStr), LastSeenSeq: 0})
	for seq := int64(1); seq <= 3; seq++ {
		if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != seq {
			t.Fatalf("deliver seq = %d; want %d", d.Seq, seq)
		}
	}
	wantNothing(t, frames, 100*time.Millisecond) // no duplicate of 2, nothing else
}

// Ack advances the subscription and prunes the replay buffer, so a resume
// the buffer no longer covers falls back to the database.
func TestAckPrunesReplayBuffer(t *testing.T) {
	room := testRoom(t)
	chat := &fakeChat{}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	waitSubs(t, m, room, 1)

	ctx := context.Background()
	for seq := int64(1); seq <= 4; seq++ {
		m.Deliver(ctx, storedMsg(t, room, seq))
	}
	for seq := int64(1); seq <= 4; seq++ {
		if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != seq {
			t.Fatalf("deliver seq = %d; want %d", d.Seq, seq)
		}
	}
	sendFrame(t, c, &protocol.Ack{RoomID: mustID(t, roomStr), Seq: 2})

	// The buffer now starts at 3.
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.hubMu.Lock()
		bufMin := m.rooms[room].bufMin
		m.hubMu.Unlock()
		if bufMin == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replay buffer starts at %d; want 3", bufMin)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Resuming from 1 is no longer covered by the buffer: the core's
	// Resume is called.
	chat.mu.Lock()
	chat.resumeHi, chat.hi = 4, 4
	chat.mu.Unlock()
	sendFrame(t, c, &protocol.Resume{RoomID: mustID(t, roomStr), LastSeenSeq: 1})
	deadline = time.Now().Add(5 * time.Second)
	for chat.resumeCount() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("resume fell through to the core; buffer miss was not detected")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Anchored at 4: live continues at 5.
	m.Deliver(ctx, storedMsg(t, room, 5))
	if d := deliverOf(t, next(t, frames, 5*time.Second)); d.Seq != 5 {
		t.Fatalf("deliver seq = %d; want 5", d.Seq)
	}
}

// Acking a room without a subscription is accepted and ignored.
func TestAckWithoutSubscriptionIgnored(t *testing.T) {
	chat := &fakeChat{}
	_, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Ack{RoomID: mustID(t, roomStr), Seq: 2})
	wantNothing(t, frames, 100*time.Millisecond)
}

// A consumer that cannot keep up fills its bounded queue and is disconnected
// with the slow-consumer close code; it must reconnect and resume.
func TestSlowConsumerDisconnected(t *testing.T) {
	room := testRoom(t)
	chat := &fakeChat{}
	m, srv := newChatTestServer(t, chat, 2)
	c := dial(t, srv)

	sendFrame(t, c, &protocol.Subscribe{RoomID: mustID(t, roomStr)})
	waitSubs(t, m, room, 1)

	// The client reads, but slowly: the writer keeps draining into TCP
	// while the queue overflows.
	frames := readFrames(c)
	big := storedMsg(t, room, 1)
	big.Ciphertext = bytes.Repeat([]byte{0xff}, 32<<10)
	for i := range 3000 {
		big.Seq = int64(i + 1)
		big.MessageID = store.UUID{0: 0x0f, 14: byte(i >> 8), 15: byte(i)}
		m.Deliver(context.Background(), big)
		if m.SlowDisconnects() == 1 {
			break
		}
	}
	if n := m.SlowDisconnects(); n != 1 {
		t.Fatalf("slow disconnects = %d; want 1", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("slow consumer was not disconnected")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The client sees the close code, not a plain drop: deliver frames
	// arrive first, then the close.
	for {
		v := next(t, frames, 5*time.Second)
		err, ok := v.(error)
		if !ok {
			continue // a queued deliver frame; keep draining
		}
		if got := websocket.CloseStatus(err); got != closeSlowConsumer {
			t.Errorf("close status = %v (%v); want %d", got, err, closeSlowConsumer)
		}
		break
	}
}

// Duplicate resume requests are idempotent: the subscription stays single
// and the flow re-runs.
func TestResumeIdempotent(t *testing.T) {
	room := testRoom(t)
	chat := &fakeChat{resumeHi: 2, hi: 2, resumeMsgs: []store.Message{storedMsg(t, room, 1), storedMsg(t, room, 2)}}
	m, srv := newChatTestServer(t, chat, 0)
	c := dial(t, srv)
	frames := readFrames(c)

	sendFrame(t, c, &protocol.Resume{RoomID: mustID(t, roomStr), LastSeenSeq: 0})
	for seq := int64(1); seq <= 2; seq++ {
		deliverOf(t, next(t, frames, 5*time.Second))
	}
	sendFrame(t, c, &protocol.Resume{RoomID: mustID(t, roomStr), LastSeenSeq: 0})
	for seq := int64(1); seq <= 2; seq++ { // re-run from the client's cursor
		deliverOf(t, next(t, frames, 5*time.Second))
	}

	m.hubMu.Lock()
	subs := len(m.rooms[room].subs)
	m.hubMu.Unlock()
	if subs != 1 {
		t.Errorf("room has %d subscriptions; want 1", subs)
	}
}
