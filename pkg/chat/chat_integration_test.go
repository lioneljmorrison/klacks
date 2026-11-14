//go:build integration

package chat_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
	"github.com/lioneljmorrison/klacks/pkg/chat"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

var (
	actor = chat.UserID{15: 0xa1} // the service identity
	alice = chat.UserID{15: 0xb2}
)

// payload builds a distinct encrypted payload for seq n.
func payload(n int) chat.EncryptedPayload {
	return chat.EncryptedPayload{
		MessageID:  [16]byte{15: byte(n)},
		DeviceID:   [16]byte{14: 0xdd},
		Ciphertext: []byte{byte(n)},
		Header:     []byte("header"),
	}
}

// openChat opens a ChatService on a fresh migrated stack. mutate adjusts the
// config before Open.
func openChat(t *testing.T, mutate func(*chat.Config)) (*chat.Service, chat.Config) {
	t.Helper()
	cfg := chat.Config{
		PostgresDSN:     dbtest.MigratedPostgresDSN(t),
		ScyllaHosts:     nil, // filled below
		ScyllaTimeout:   10 * time.Second,
		RoomLockTimeout: 20 * time.Second,
		Actor:           actor,
		Log:             discard,
	}
	sc := dbtest.MigratedScyllaConfig(t)
	cfg.ScyllaHosts = sc.Hosts
	cfg.ScyllaKeyspace = sc.Keyspace
	cfg.ScyllaUsername = sc.Username
	cfg.ScyllaPassword = sc.Password
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := chat.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc, cfg
}

// setupRoom creates a room owned by the service actor with alice as a member.
func setupRoom(t *testing.T, svc *chat.Service) chat.RoomID {
	t.Helper()
	room, err := svc.CreateRoom(context.Background(), chat.RoomSpec{Kind: chat.KindGroup})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(context.Background(), room, alice, chat.RoleMember); err != nil {
		t.Fatal(err)
	}
	return room
}

// collect receives exactly n messages from ch; the channel closing early or
// a timeout fails the test.
func collect(t *testing.T, ch <-chan chat.Message, n int) []chat.Message {
	t.Helper()
	got := make([]chat.Message, 0, n)
	for len(got) < n {
		select {
		case m, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed after %d of %d messages", len(got), n)
			}
			got = append(got, m)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out after %d of %d messages", len(got), n)
		}
	}
	return got
}

// expectClose waits for the channel to close after draining what is queued.
func expectClose(t *testing.T, ch <-chan chat.Message) {
	t.Helper()
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for the channel to close")
		}
	}
}

func TestRoomLifecycle(t *testing.T) {
	svc, cfg := openChat(t, nil)
	ctx := context.Background()

	room, err := svc.CreateRoom(ctx, chat.RoomSpec{Kind: chat.KindGroup})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateRoom(ctx, chat.RoomSpec{Kind: "channel"}); !errors.Is(err, chat.ErrInvalidArgument) {
		t.Errorf("unknown kind: err = %v, want ErrInvalidArgument", err)
	}

	if err := svc.AddMember(ctx, room, alice, chat.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, room, alice, chat.RoleAdmin); !errors.Is(err, chat.ErrAlreadyMember) {
		t.Errorf("re-add: err = %v, want ErrAlreadyMember", err)
	}
	if err := svc.AddMember(ctx, room, alice, "superuser"); !errors.Is(err, chat.ErrInvalidArgument) {
		t.Errorf("unknown role: err = %v, want ErrInvalidArgument", err)
	}

	seq, err := svc.PostMessage(ctx, room, alice, payload(1))
	if err != nil || seq != 1 {
		t.Fatalf("post: seq = %d err = %v, want 1 nil", seq, err)
	}
	if _, err := svc.PostMessage(ctx, room, chat.UserID{15: 0xee}, payload(2)); !errors.Is(err, chat.ErrNotMember) {
		t.Errorf("outsider post: err = %v, want ErrNotMember", err)
	}
	big := chat.EncryptedPayload{Ciphertext: make([]byte, chat.MaxPayloadSize+1)}
	if _, err := svc.PostMessage(ctx, room, alice, big); !errors.Is(err, chat.ErrPayloadTooLarge) {
		t.Errorf("oversized payload: err = %v, want ErrPayloadTooLarge", err)
	}

	if err := svc.RemoveMember(ctx, room, alice); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveMember(ctx, room, alice); !errors.Is(err, chat.ErrMemberNotFound) {
		t.Errorf("remove twice: err = %v, want ErrMemberNotFound", err)
	}
	if err := svc.RemoveMember(ctx, chat.RoomID{15: 0xee}, alice); !errors.Is(err, chat.ErrRoomNotFound) {
		t.Errorf("missing room: err = %v, want ErrRoomNotFound", err)
	}

	// Room metadata is not settable yet (always '{}').
	conn, err := pgx.Connect(ctx, cfg.PostgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var metadata, kind string
	if err := conn.QueryRow(ctx, `SELECT metadata::text, kind FROM rooms WHERE id = $1`, room).Scan(&metadata, &kind); err != nil {
		t.Fatal(err)
	}
	if metadata != "{}" || kind != "group" {
		t.Errorf("room row: metadata = %s kind = %s, want {} group", metadata, kind)
	}
}

func TestSubscribeReplayAndLive(t *testing.T) {
	svc, _ := openChat(t, nil)
	room := setupRoom(t, svc)
	ctx := context.Background()

	for n := 1; n <= 3; n++ {
		if _, err := svc.PostMessage(ctx, room, alice, payload(n)); err != nil {
			t.Fatal(err)
		}
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := svc.Subscribe(sctx, room, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range collect(t, ch, 3) {
		want := payload(i + 1)
		if m.Seq != chat.Seq(i+1) || m.RoomID != room || m.SenderID != alice ||
			string(m.Ciphertext) != string(want.Ciphertext) || string(m.Header) != string(want.Header) {
			t.Errorf("message %d = %+v, want seq %d from alice with payload %d", i, m, i+1, i+1)
		}
	}
	// Live fan-out continues the stream.
	for n := 4; n <= 5; n++ {
		if _, err := svc.PostMessage(ctx, room, alice, payload(n)); err != nil {
			t.Fatal(err)
		}
	}
	for i, m := range collect(t, ch, 2) {
		if m.Seq != chat.Seq(i+4) {
			t.Errorf("live message %d = seq %d, want %d", i, m.Seq, i+4)
		}
	}
	cancel()
	expectClose(t, ch)

	// Resubscribing from the last seen seq replays exactly the gap.
	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	ch2, err := svc.Subscribe(rctx, room, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range collect(t, ch2, 2) {
		if m.Seq != chat.Seq(i+4) {
			t.Errorf("resumed message %d = seq %d, want %d", i, m.Seq, i+4)
		}
	}
	rcancel()
	expectClose(t, ch2)
}

func TestSubscribeFromMidStream(t *testing.T) {
	svc, _ := openChat(t, nil)
	room := setupRoom(t, svc)
	ctx := context.Background()
	for n := 1; n <= 5; n++ {
		if _, err := svc.PostMessage(ctx, room, alice, payload(n)); err != nil {
			t.Fatal(err)
		}
	}
	ch, err := svc.Subscribe(ctx, room, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range collect(t, ch, 3) {
		if m.Seq != chat.Seq(i+3) {
			t.Errorf("message %d = seq %d, want %d", i, m.Seq, i+3)
		}
	}
}

func TestSubscribeAuthorization(t *testing.T) {
	svc, _ := openChat(t, nil)
	ctx := context.Background()
	room, err := svc.CreateRoom(ctx, chat.RoomSpec{Kind: chat.KindDM})
	if err != nil {
		t.Fatal(err)
	}
	// The actor may always leave a room it is in.
	if err := svc.RemoveMember(ctx, room, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Subscribe(ctx, room, 0); !errors.Is(err, chat.ErrNotMember) {
		t.Errorf("non-member subscribe: err = %v, want ErrNotMember", err)
	}
	if _, err := svc.Subscribe(ctx, chat.RoomID{15: 0xee}, 0); !errors.Is(err, chat.ErrRoomNotFound) {
		t.Errorf("missing room: err = %v, want ErrRoomNotFound", err)
	}
	if _, err := svc.Subscribe(ctx, room, -1); !errors.Is(err, chat.ErrInvalidArgument) {
		t.Errorf("negative from_seq: err = %v, want ErrInvalidArgument", err)
	}
}

// TestConcurrentPostsOrdered publishes from several goroutines and checks
// that one subscriber sees every message exactly once, in seq order.
func TestConcurrentPostsOrdered(t *testing.T) {
	svc, _ := openChat(t, nil)
	room := setupRoom(t, svc)
	ctx := context.Background()

	ch, err := svc.Subscribe(ctx, room, 0)
	if err != nil {
		t.Fatal(err)
	}
	const posters, perPoster = 4, 25
	errs := make(chan error, posters)
	for p := 0; p < posters; p++ {
		go func(p int) {
			for n := 0; n < perPoster; n++ {
				if _, err := svc.PostMessage(ctx, room, alice, payload(p*perPoster+n+1)); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}(p)
	}
	got := collect(t, ch, posters*perPoster)
	for i := 0; i < posters; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for i, m := range got {
		if m.Seq != chat.Seq(i+1) {
			t.Fatalf("position %d = seq %d, want %d: stream out of order", i, m.Seq, i+1)
		}
	}
}

// TestSlowConsumerCloses checks that a consumer which stops reading has its
// channel closed rather than a publish blocked, and that what it did receive
// is an ordered prefix it can resume from.
func TestSlowConsumerCloses(t *testing.T) {
	svc, _ := openChat(t, func(c *chat.Config) { c.SendQueue = 1 })
	room := setupRoom(t, svc)
	ctx := context.Background()

	ch, err := svc.Subscribe(ctx, room, 0)
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 5; n++ {
		if _, err := svc.PostMessage(ctx, room, alice, payload(n)); err != nil {
			t.Fatal(err)
		}
	}
	var got []chat.Message
	for {
		m, ok := <-ch
		if !ok {
			break
		}
		got = append(got, m)
	}
	if len(got) < 1 || len(got) > 5 {
		t.Fatalf("received %d messages, want between 1 and 5", len(got))
	}
	for i, m := range got {
		if m.Seq != chat.Seq(i+1) {
			t.Fatalf("position %d = seq %d, want %d: stream out of order", i, m.Seq, i+1)
		}
	}
}

func TestCloseStopsSubscriptions(t *testing.T) {
	svc, _ := openChat(t, nil)
	room := setupRoom(t, svc)
	ctx := context.Background()
	if _, err := svc.PostMessage(ctx, room, alice, payload(1)); err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Subscribe(ctx, room, 0)
	if err != nil {
		t.Fatal(err)
	}
	if m := collect(t, ch, 1)[0]; m.Seq != 1 {
		t.Fatalf("got seq %d, want 1", m.Seq)
	}
	svc.Close()
	expectClose(t, ch)
	if _, err := svc.Subscribe(ctx, room, 0); !errors.Is(err, chat.ErrClosed) {
		t.Errorf("subscribe after close: err = %v, want ErrClosed", err)
	}
	svc.Close() // idempotent
}

// OnMemberRemoved receives every removal, in commit order (S-29), which is
// the hook an E2EE client's rotation logic hangs off.
func TestOnMemberRemoved(t *testing.T) {
	var mu sync.Mutex
	var got []chat.MemberRemoved
	svc, _ := openChat(t, func(c *chat.Config) {
		c.OnMemberRemoved = func(_ context.Context, ev chat.MemberRemoved) {
			mu.Lock()
			got = append(got, ev)
			mu.Unlock()
		}
	})
	ctx := context.Background()
	room, err := svc.CreateRoom(ctx, chat.RoomSpec{Kind: chat.KindGroup})
	if err != nil {
		t.Fatal(err)
	}
	bob := chat.UserID{15: 0xb0}
	if err := svc.AddMember(ctx, room, bob, chat.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveMember(ctx, room, bob); err != nil {
		t.Fatal(err)
	}
	// A failed removal emits nothing.
	if err := svc.RemoveMember(ctx, room, bob); !errors.Is(err, chat.ErrMemberNotFound) {
		t.Fatalf("second removal: err = %v, want ErrMemberNotFound", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("events = %+v, want one removal of bob", got)
	}
	if e := got[0]; e.Room != room || e.User != bob || e.Actor != actor {
		t.Fatalf("event = %+v, want bob removed by the actor from %v", e, room)
	}
}
