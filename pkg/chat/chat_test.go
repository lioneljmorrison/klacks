package chat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func testLog() *slog.Logger { return discard }

// validConfig satisfies every Config.validate rule.
func validConfig() Config {
	return Config{
		PostgresDSN:     "postgres://klacks:pw@localhost/klacks",
		ScyllaHosts:     []string{"localhost"},
		ScyllaKeyspace:  "klacks",
		ScyllaTimeout:   5 * time.Second,
		RoomLockTimeout: 10 * time.Second,
		Actor:           UserID{15: 0xa1},
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name  string
		tweak func(*Config)
		want  error
	}{
		{"valid", func(*Config) {}, nil},
		{"lock timeout 0 disables the timeouts", func(c *Config) { c.RoomLockTimeout = 0 }, nil},
		{"missing postgres dsn", func(c *Config) { c.PostgresDSN = "" }, ErrInvalidArgument},
		{"missing scylla hosts", func(c *Config) { c.ScyllaHosts = nil }, ErrInvalidArgument},
		{"bad keyspace", func(c *Config) { c.ScyllaKeyspace = "1bad" }, ErrInvalidArgument},
		{"zero scylla timeout", func(c *Config) { c.ScyllaTimeout = 0 }, ErrInvalidArgument},
		{"negative lock timeout", func(c *Config) { c.RoomLockTimeout = -time.Second }, ErrInvalidArgument},
		{"lock timeout at the scylla timeout", func(c *Config) { c.RoomLockTimeout = 5 * time.Second }, ErrInvalidArgument},
		{"lock timeout under the scylla timeout", func(c *Config) { c.RoomLockTimeout = 4 * time.Second }, ErrInvalidArgument},
		{"zero actor", func(c *Config) { c.Actor = UserID{} }, ErrInvalidArgument},
		{"negative max conns", func(c *Config) { c.PostgresMaxConns = -1 }, ErrInvalidArgument},
		{"negative send queue", func(c *Config) { c.SendQueue = -1 }, ErrInvalidArgument},
	}
	for _, tt := range tests {
		cfg := validConfig()
		tt.tweak(&cfg)
		err := cfg.validate()
		if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestQueueSize(t *testing.T) {
	var s Service // no config: picks the default
	if s.queueSize() != DefaultSendQueue {
		t.Errorf("queueSize = %d, want default %d", s.queueSize(), DefaultSendQueue)
	}
	s = Service{cfg: Config{SendQueue: 7}}
	if s.queueSize() != 7 {
		t.Errorf("queueSize = %d, want 7", s.queueSize())
	}
}

// newTestService returns a Service with only the hub wired: enough to
// exercise the fan-out paths without a core or stores.
func newTestService(queue int) *Service {
	return &Service{
		cfg:  Config{SendQueue: queue},
		log:  testLog(),
		hub:  make(map[store.UUID]map[*subscription]struct{}),
		pool: nil,
	}
}

// newTestSub registers a subscription the way Subscribe does after its
// authorization: anchored at lastSeq, buffering until a drain.
func newTestSub(s *Service, room store.UUID, lastSeq int64) *subscription {
	sub := &subscription{
		room:      room,
		ch:        make(chan Message, s.queueSize()),
		lastSeq:   lastSeq,
		buffering: true,
	}
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	subs := s.hub[sub.room]
	if subs == nil {
		subs = make(map[*subscription]struct{})
		s.hub[sub.room] = subs
	}
	subs[sub] = struct{}{}
	return sub
}

func msg(room store.UUID, seq int64) store.Message {
	return store.Message{
		RoomID:     room,
		Seq:        seq,
		MessageID:  store.UUID{15: byte(seq)},
		SenderID:   store.UUID{14: 0xbb},
		Ciphertext: []byte{byte(seq)},
		Header:     []byte("h"),
	}
}

func receive(t *testing.T, ch <-chan Message, d time.Duration) (Message, bool) {
	t.Helper()
	select {
	case m, ok := <-ch:
		return m, ok
	case <-time.After(d):
		t.Fatal("timed out waiting for a message")
		return Message{}, false
	}
}

// assertQuiet expects no message within d: nothing more is coming.
func assertQuiet(t *testing.T, ch <-chan Message, d time.Duration) {
	t.Helper()
	select {
	case m, ok := <-ch:
		t.Fatalf("unexpected message seq %v ok=%v", m.Seq, ok)
	case <-time.After(d):
	}
}

// assertClosed expects the channel to close after draining what is queued.
func assertClosed(t *testing.T, ch <-chan Message, d time.Duration) {
	t.Helper()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel was not closed")
		}
	case <-time.After(d):
		t.Fatal("timed out waiting for the channel to close")
	}
}

func TestFeedDeliversInOrder(t *testing.T) {
	s := newTestService(0)
	room := store.UUID{15: 1}
	sub := newTestSub(s, room, 0)
	sub.buffering = false
	ctx := context.Background()
	for seq := int64(1); seq <= 3; seq++ {
		s.Deliver(ctx, msg(room, seq))
	}
	for seq := int64(1); seq <= 3; seq++ {
		m, ok := receive(t, sub.ch, time.Second)
		if !ok || m.Seq != Seq(seq) {
			t.Fatalf("got seq %v ok=%v, want %d", m.Seq, ok, seq)
		}
	}
	assertQuiet(t, sub.ch, 50*time.Millisecond) // nothing more is coming
}

func TestFeedHoldsAndResumesGaps(t *testing.T) {
	s := newTestService(0)
	room := store.UUID{15: 2}
	sub := newTestSub(s, room, 0)
	sub.buffering = false
	ctx := context.Background()
	s.Deliver(ctx, msg(room, 3)) // ahead of lastSeq+1: held in pending
	assertQuiet(t, sub.ch, 50*time.Millisecond)
	s.Deliver(ctx, msg(room, 2)) // still a gap at 1
	assertQuiet(t, sub.ch, 50*time.Millisecond)
	s.Deliver(ctx, msg(room, 1)) // the chain completes: 1, 2, 3
	for seq := int64(1); seq <= 3; seq++ {
		m, ok := receive(t, sub.ch, time.Second)
		if !ok || m.Seq != Seq(seq) {
			t.Fatalf("got seq %v ok=%v, want %d", m.Seq, ok, seq)
		}
	}
	assertQuiet(t, sub.ch, 50*time.Millisecond)
}

func TestFeedSkipsBehind(t *testing.T) {
	s := newTestService(0)
	room := store.UUID{15: 3}
	sub := newTestSub(s, room, 1)
	sub.buffering = false
	s.Deliver(context.Background(), msg(room, 1)) // at or below lastSeq
	assertQuiet(t, sub.ch, 50*time.Millisecond)
}

func TestFeedBuffersWhileDraining(t *testing.T) {
	s := newTestService(0)
	room := store.UUID{15: 4}
	sub := newTestSub(s, room, 0) // buffering: true
	ctx := context.Background()
	s.Deliver(ctx, msg(room, 1))
	s.Deliver(ctx, msg(room, 2))
	assertQuiet(t, sub.ch, 50*time.Millisecond) // buffered, not delivered
	s.drain(sub, 1)                             // replay ended at hi = 1
	m, ok := receive(t, sub.ch, time.Second)
	if !ok || m.Seq != 2 {
		t.Fatalf("got seq %v ok=%v, want 2 (1 is at or below hi)", m.Seq, ok)
	}
	assertQuiet(t, sub.ch, 50*time.Millisecond)
}

func TestOverflowClosesSubscription(t *testing.T) {
	s := newTestService(2)
	room := store.UUID{15: 5}
	sub := newTestSub(s, room, 0)
	sub.buffering = false
	ctx := context.Background()
	s.Deliver(ctx, msg(room, 1))
	s.Deliver(ctx, msg(room, 2)) // queue full
	s.Deliver(ctx, msg(room, 3)) // overflow: the subscription closes
	s.hubMu.Lock()
	if _, live := s.hub[room][sub]; live {
		t.Error("overflow left the subscription registered")
	}
	s.hubMu.Unlock()
	if got, ok := receive(t, sub.ch, time.Second); !ok || got.Seq != 1 {
		t.Fatalf("got seq %v ok=%v, want 1", got.Seq, ok)
	}
	if got, ok := receive(t, sub.ch, time.Second); !ok || got.Seq != 2 {
		t.Fatalf("got seq %v ok=%v, want 2", got.Seq, ok)
	}
	assertClosed(t, sub.ch, time.Second)
}

func TestPendingDropsAtOrBelowHi(t *testing.T) {
	s := newTestService(0)
	room := store.UUID{15: 6}
	sub := newTestSub(s, room, 3)
	sub.buffering = false
	sub.pending = map[int64]store.Message{4: msg(room, 4), 5: msg(room, 5)}
	s.drain(sub, 4) // replay covered (3, 4]; 4 must not be delivered twice
	// Fan-out brings 5: the chain completes from lastSeq = 4.
	s.Deliver(context.Background(), msg(room, 5))
	m, ok := receive(t, sub.ch, time.Second)
	if !ok || m.Seq != 5 {
		t.Fatalf("got seq %v ok=%v, want 5", m.Seq, ok)
	}
	assertQuiet(t, sub.ch, 50*time.Millisecond)
}

func TestCloseClosesEverySubscription(t *testing.T) {
	s := newTestService(0)
	room := store.UUID{15: 7}
	a := newTestSub(s, room, 0)
	b := newTestSub(s, room, 0)
	other := newTestSub(s, store.UUID{15: 8}, 0)
	s.Close()
	for name, ch := range map[string]<-chan Message{"a": a.ch, "b": b.ch, "other": other.ch} {
		assertClosed(t, ch, time.Second)
		_ = name
	}
	s.hubMu.Lock()
	n := 0
	for range s.hub {
		n++
	}
	s.hubMu.Unlock()
	if n != 0 {
		t.Errorf("hub still holds %d rooms", n)
	}
	// A second Close is a no-op, and Deliver after Close does nothing.
	s.Close()
	s.Deliver(context.Background(), msg(room, 1))
}
