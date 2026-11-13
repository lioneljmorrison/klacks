//go:build integration

// Resume correctness end to end (S-17): real stores, real core, real hub.
package ws

import (
	"context"
	"errors"
	"math/rand"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

var (
	userA = "a1000000-0000-0000-0000-000000000001"
	userB = "a1000000-0000-0000-0000-000000000002"
	userC = "a1000000-0000-0000-0000-000000000003"
	devID = "b2000000-0000-0000-0000-000000000001"
)

// stack is the full serve path on fresh stores: manager with the core wired
// in, fan-out included. wrap, if not nil, wraps the MessageStore the core
// uses.
type stack struct {
	m    *Manager
	srv  *httptest.Server
	svc  *core.Service
	pool *pgxpool.Pool
	msgs store.MessageStore
}

// newStack builds the stack.
func newStack(t *testing.T, wrap func(store.MessageStore) store.MessageStore) *stack {
	t.Helper()
	pool := dbtest.MigratedPostgres(t)
	var msgs store.MessageStore = store.NewScyllaMessages(dbtest.MigratedScylla(t))
	used := msgs
	if wrap != nil {
		used = wrap(msgs)
	}
	rooms := store.NewRooms(pool, 10*time.Second)
	m := NewManager(auth.Dev{}, discard)
	m.PingInterval, m.PingTimeout = time.Minute, time.Minute
	// A resume that replays more frames than the queue depth can overflow
	// it and disconnect the client (close 4000) mid-replay — that is the
	// designed backpressure. These tests assert replay correctness, not
	// backpressure, so the queue here holds a full replay.
	m.SendQueue = 4096
	svc := core.New(rooms, used, m.Deliver, nil)
	m.Chat = svc
	srv := httptest.NewServer(m)
	t.Cleanup(func() {
		m.Close()
		srv.Close()
	})
	return &stack{m: m, srv: srv, svc: svc, pool: pool, msgs: msgs}
}

// mustUser parses a UUID string that is known to be valid.
func mustUser(s string) store.UUID {
	var u protocol.UUID
	if err := u.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return store.UUID(u)
}

// dialAs dials as a specific dev identity.
func dialAs(t *testing.T, srv *httptest.Server, user string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?user=" + user + "&device=" + devID
	c, resp, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	c.SetReadLimit(-1)
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

// chatRoom creates a group room owned by userA with userB and userC as
// members.
func chatRoom(t *testing.T, s *stack) store.UUID {
	t.Helper()
	ctx := context.Background()
	room, err := s.svc.CreateRoom(ctx, core.KindGroup, mustUser(userA))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{userB, userC} {
		if err := s.svc.AddMember(ctx, room, mustUser(userA), mustUser(u), core.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	return room
}

// frameStream reads the connection until it closes; values are
// protocol.Frame or the ending error.
type frameStream struct {
	ch chan any
}

func stream(c *websocket.Conn) *frameStream {
	fs := &frameStream{ch: make(chan any, 1024)}
	go func() {
		defer close(fs.ch)
		for {
			typ, b, err := c.Read(context.Background())
			if err != nil {
				fs.ch <- err
				return
			}
			if typ != websocket.MessageText {
				fs.ch <- errors.New("binary frame")
				return
			}
			f, err := serverFrame(b)
			if err != nil {
				fs.ch <- err
				return
			}
			fs.ch <- f
		}
	}()
	return fs
}

func (fs *frameStream) next(t *testing.T, d time.Duration) any {
	t.Helper()
	select {
	case v, ok := <-fs.ch:
		if !ok {
			t.Fatal("stream ended without a close")
		}
		return v
	case <-time.After(d):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

func (fs *frameStream) deliver(t *testing.T, d time.Duration) *protocol.Deliver {
	t.Helper()
	for {
		select {
		case v, ok := <-fs.ch:
			if !ok {
				t.Fatal("stream ended without a close")
			}
			if df, ok := v.(*protocol.Deliver); ok {
				return df
			}
			continue // an error frame in between; keep waiting
		case <-time.After(d):
			t.Fatal("timed out waiting for a deliver frame")
			return nil
		}
	}
}

// wsPublish publishes p as user over the wire.
func wsPublish(t *testing.T, c *websocket.Conn, room store.UUID, p core.Payload) {
	t.Helper()
	b, err := protocol.Encode(&protocol.Publish{
		RoomID:     protocol.UUID(room),
		MessageID:  protocol.UUID(p.MessageID),
		DeviceID:   protocol.UUID(p.DeviceID),
		Header:     p.Header,
		Ciphertext: p.Ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func wsResume(t *testing.T, c *websocket.Conn, room store.UUID, lastSeen int64) {
	t.Helper()
	b, err := protocol.Encode(&protocol.Resume{RoomID: protocol.UUID(room), LastSeenSeq: lastSeen})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

// TestLiveFanoutEndToEnd: two subscribed members receive a member's publish
// live, in order and complete.
func TestLiveFanoutEndToEnd(t *testing.T) {
	s := newStack(t, nil)
	room := chatRoom(t, s)

	ca := dialAs(t, s.srv, userB)
	fa := stream(ca)
	cb := dialAs(t, s.srv, userC)
	fb := stream(cb)
	for _, c := range []*websocket.Conn{ca, cb} {
		b, _ := protocol.Encode(&protocol.Subscribe{RoomID: protocol.UUID(room)})
		if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	waitSubs(t, s.m, room, 2)

	cc := dialAs(t, s.srv, userA)
	wsPublish(t, cc, room, core.Payload{
		MessageID:  store.UUID{0: 0x0f, 15: 1},
		DeviceID:   mustUser(devID),
		Ciphertext: []byte("ciphertext 1"),
		Header:     []byte("header 1"),
	})
	for _, fs := range []*frameStream{fa, fb} {
		d := fs.deliver(t, 5*time.Second)
		if d.RoomID != protocol.UUID(room) || d.Seq != 1 ||
			d.MessageID != protocol.UUID(store.UUID{0: 0x0f, 15: 1}) ||
			d.SenderID != protocol.UUID(mustUser(userA)) {
			t.Fatalf("deliver = %+v; want the published message at seq 1", d)
		}
		if string(d.Ciphertext) != "ciphertext 1" || string(d.Header) != "header 1" {
			t.Fatalf("deliver payload = %x %x", d.Ciphertext, d.Header)
		}
	}
}

// TestResumeRandomizedNoGapsOrDuplicates: several publishers post
// concurrently while clients drop and resume at random points; every client
// ends with every seq exactly once.
func TestResumeRandomizedNoGapsOrDuplicates(t *testing.T) {
	s := newStack(t, nil)
	room := chatRoom(t, s)
	const (
		publishers = 4
		perPub     = 25
		total      = publishers * perPub
		clients    = 3
	)

	type watcher struct {
		mu   sync.Mutex
		got  map[int64]int
		last int64 // highest seq delivered contiguously; the resume cursor
		conn *websocket.Conn
		fs   *frameStream
	}
	ws := make([]*watcher, clients)
	for i := range ws {
		ws[i] = &watcher{got: make(map[int64]int)}
	}
	connect := func(w *watcher, lastSeen int64) {
		w.conn = dialAs(t, s.srv, userB)
		w.fs = stream(w.conn)
		wsResume(t, w.conn, room, lastSeen)
	}
	for _, w := range ws {
		connect(w, 0)
	}

	var wwg sync.WaitGroup
	for i, w := range ws {
		w := w
		wwg.Go(func() {
			// A private *rand.Rand is not thread-safe; each watcher
			// randomness lives in its own goroutine.
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(i)))
			for {
				w.mu.Lock()
				done := len(w.got) >= total
				w.mu.Unlock()
				if done {
					return
				}
				// Drop and resume at random points.
				if rng.Intn(4) == 0 {
					w.mu.Lock()
					c := w.conn
					w.mu.Unlock()
					_ = c.CloseNow() // abrupt: frames in flight are lost client-side
					time.Sleep(time.Duration(rng.Intn(20)) * time.Millisecond)
					connect(w, w.last)
				}
				v := w.fs.next(t, 10*time.Second)
				d, ok := v.(*protocol.Deliver)
				if !ok {
					t.Errorf("watcher got %T (%v); want a deliver frame", v, v)
					return
				}
				w.mu.Lock()
				if d.Seq == w.last+1 {
					w.last = d.Seq
				}
				w.got[d.Seq]++
				w.mu.Unlock()
			}
		})
	}

	var pwg sync.WaitGroup
	for p := range publishers {
		pwg.Go(func() {
			for j := range perPub {
				n := p*perPub + j
				p := core.Payload{
					MessageID:  store.UUID{0: 0x0f, 14: byte(n >> 8), 15: byte(n)},
					DeviceID:   mustUser(devID),
					Ciphertext: []byte{byte(n >> 8), byte(n)},
					Header:     []byte("hdr"),
				}
				if _, err := s.svc.PostMessage(context.Background(), room, mustUser(userA), p); err != nil {
					t.Errorf("publish %d: %v", n, err)
					return
				}
			}
		})
	}
	pwg.Wait()

	done := make(chan struct{})
	go func() {
		wwg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("watchers did not converge in time")
	}

	if hi, err := s.svc.Hi(context.Background(), room); err != nil || hi != total {
		t.Fatalf("hi = %d, err %v; want %d", hi, err, total)
	}
	for i, w := range ws {
		w.mu.Lock()
		defer w.mu.Unlock()
		if len(w.got) != total {
			t.Fatalf("watcher %d got %d distinct seqs; want %d", i, len(w.got), total)
		}
		seqs := make([]int64, 0, total)
		for seq := range w.got {
			seqs = append(seqs, seq)
		}
		slices.Sort(seqs)
		for j, seq := range seqs {
			if seq != int64(j+1) {
				t.Fatalf("watcher %d seqs = %v…; want 1..%d", i, seqs[:min(10, len(seqs))], total)
			}
			if w.got[seq] != 1 {
				t.Fatalf("watcher %d: seq %d delivered %d times; want exactly once", i, seq, w.got[seq])
			}
		}
	}
}

// TestResumeAcrossBucketBoundary: messages spanning two buckets, resumed
// from before and after the boundary, deliver exactly what is in range.
func TestResumeAcrossBucketBoundary(t *testing.T) {
	s := newStack(t, nil)
	room := chatRoom(t, s)
	const n = store.BucketSize + 1 // 1001: buckets 0 and 1

	base := time.Now().UTC().Truncate(time.Millisecond).UnixMicro()
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			seq := i + 1
			m := store.Message{
				RoomID:     room,
				Seq:        seq,
				MessageID:  store.UUID{0: 0x0f, 14: byte(seq >> 8), 15: byte(seq)},
				SenderID:   mustUser(userA),
				DeviceID:   mustUser(devID),
				Ciphertext: []byte{byte(seq >> 8), byte(seq)},
				Header:     []byte("hdr"),
				CreatedAt:  time.UnixMicro(base + seq),
			}
			if err := s.msgs.Insert(context.Background(), m, base+seq); err != nil {
				t.Errorf("insert seq %d: %v", seq, err)
			}
		})
	}
	wg.Wait()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE room_seq SET next_seq = $2 WHERE room_id = $1`, room, n+1); err != nil {
		t.Fatal(err)
	}
	if hi, err := s.svc.Hi(context.Background(), room); err != nil || hi != n {
		t.Fatalf("hi = %d, err %v; want %d", hi, err, n)
	}

	// Each watcher resumes from a different point relative to the bucket
	// boundary and reads exactly (lastSeen, hi].
	cursors := []int64{0, store.BucketSize - 1, store.BucketSize, n - 1, n}
	for _, lastSeen := range cursors {
		c := dialAs(t, s.srv, userB)
		fs := stream(c)
		wsResume(t, c, room, lastSeen)
		want := n - lastSeen
		for j := range want {
			d := fs.deliver(t, 10*time.Second)
			if want := lastSeen + 1 + j; d.Seq != want {
				t.Fatalf("resume from %d: deliver seq = %d; want %d", lastSeen, d.Seq, want)
			}
		}
		select {
		case v := <-fs.ch:
			t.Fatalf("resume from %d: unexpected extra frame %v", lastSeen, v)
		case <-time.After(150 * time.Millisecond):
		}
		_ = c.CloseNow()
	}

	// Live after a full replay: the next publish lands at the end.
	c := dialAs(t, s.srv, userC)
	fs := stream(c)
	wsResume(t, c, room, n)
	p := core.Payload{
		MessageID:  store.UUID{0: 0x1f, 15: 2},
		DeviceID:   mustUser(devID),
		Ciphertext: []byte("after boundary"),
	}
	seq, err := s.svc.PostMessage(context.Background(), room, mustUser(userA), p)
	if err != nil || seq != n+1 {
		t.Fatalf("post: seq %d, err %v; want %d", seq, err, n+1)
	}
	if d := fs.deliver(t, 5*time.Second); d.Seq != n+1 || string(d.Ciphertext) != "after boundary" {
		t.Fatalf("deliver = seq %d %x; want seq %d", d.Seq, d.Ciphertext, n+1)
	}
	select {
	case v := <-fs.ch:
		t.Fatalf("unexpected extra frame %v", v)
	case <-time.After(150 * time.Millisecond):
	}
}

var errInjected = errors.New("injected failure after the ScyllaDB write")

// failAfterInsert performs the real Insert, then fails once: the ScyllaDB
// row exists but the publish does not commit, leaving an orphan above the
// watermark.
type failAfterInsert struct {
	store.MessageStore
	fail bool
}

func (f *failAfterInsert) Insert(ctx context.Context, m store.Message, writeTS int64) error {
	if err := f.MessageStore.Insert(ctx, m, writeTS); err != nil {
		return err
	}
	if f.fail {
		f.fail = false
		return errInjected
	}
	return nil
}

// TestResumeOrphanNeverDelivered: a publish that fails after the ScyllaDB
// write and before the commit leaves an orphan that is never delivered; the
// retry's content wins at the same seq.
func TestResumeOrphanNeverDelivered(t *testing.T) {
	inject := &failAfterInsert{fail: true}
	s := newStack(t, func(ms store.MessageStore) store.MessageStore {
		inject.MessageStore = ms
		return inject
	})
	room := chatRoom(t, s)
	orphanPayload := core.Payload{
		MessageID:  store.UUID{0: 0x0f, 15: 1},
		DeviceID:   mustUser(devID),
		Ciphertext: []byte("orphan"),
	}
	if _, err := s.svc.PostMessage(context.Background(), room, mustUser(userA), orphanPayload); !errors.Is(err, errInjected) {
		t.Fatalf("err = %v; want the injected failure", err)
	}
	if hi, err := s.svc.Hi(context.Background(), room); err != nil || hi != 0 {
		t.Fatalf("hi = %d, err %v; want 0 after a failed publish", hi, err)
	}

	// A client resuming from nothing sees the empty room, then stays live.
	c := dialAs(t, s.srv, userB)
	fs := stream(c)
	wsResume(t, c, room, 0)
	select {
	case v := <-fs.ch:
		t.Fatalf("orphan delivered: %v", v)
	case <-time.After(150 * time.Millisecond):
	}

	// The retry commits with different content at the same seq; the live
	// client gets the new content.
	retryPayload := core.Payload{
		MessageID:  store.UUID{0: 0x0f, 15: 2},
		DeviceID:   mustUser(devID),
		Ciphertext: []byte("retry"),
	}
	seq, err := s.svc.PostMessage(context.Background(), room, mustUser(userA), retryPayload)
	if err != nil || seq != 1 {
		t.Fatalf("retry: seq %d, err %v; want 1", seq, err)
	}
	d := fs.deliver(t, 5*time.Second)
	if d.Seq != 1 || string(d.Ciphertext) != "retry" || d.MessageID != protocol.UUID(retryPayload.MessageID) {
		t.Fatalf("deliver = seq %d %x %x; want the retry content at seq 1", d.Seq, d.Ciphertext, d.MessageID)
	}

	// A fresh client resumes from the database: the orphan is not there.
	c2 := dialAs(t, s.srv, userC)
	fs2 := stream(c2)
	wsResume(t, c2, room, 0)
	d2 := fs2.deliver(t, 5*time.Second)
	if d2.Seq != 1 || string(d2.Ciphertext) != "retry" {
		t.Fatalf("replayed deliver = seq %d %x; want the retry content at seq 1", d2.Seq, d2.Ciphertext)
	}
	select {
	case v := <-fs2.ch:
		t.Fatalf("unexpected extra frame %v", v)
	case <-time.After(150 * time.Millisecond):
	}
}
