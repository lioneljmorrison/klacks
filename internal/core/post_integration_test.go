//go:build integration

package core_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

type env struct {
	svc  *core.Service
	pool *pgxpool.Pool
	msgs store.MessageStore // the real store, bypassing any wrapper
}

// newEnv returns a Service on fresh databases. wrap, if not nil, wraps the
// MessageStore the Service uses.
func newEnv(t *testing.T, wrap func(store.MessageStore) store.MessageStore) env {
	t.Helper()
	pool := dbtest.MigratedPostgres(t)
	var msgs store.MessageStore = store.NewScyllaMessages(dbtest.MigratedScylla(t))
	used := msgs
	if wrap != nil {
		used = wrap(msgs)
	}
	return env{svc: core.New(store.NewRooms(pool, 10*time.Second), used, nil, nil), pool: pool, msgs: msgs}
}

// hi returns the room's committed watermark, next_seq - 1.
func (e env) hi(t *testing.T, room store.UUID) int64 {
	t.Helper()
	var next int64
	if err := e.pool.QueryRow(context.Background(), `SELECT next_seq FROM room_seq WHERE room_id = $1`, room).Scan(&next); err != nil {
		t.Fatal(err)
	}
	return next - 1
}

// stored returns the committed messages of room, read up to the watermark.
func (e env) stored(t *testing.T, room store.UUID) []store.Message {
	t.Helper()
	var out []store.Message
	for m, err := range e.msgs.Range(context.Background(), room, 0, e.hi(t, room)) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func payload(n int) core.Payload {
	return core.Payload{
		MessageID:  store.UUID{0: 0x0f, 14: byte(n >> 8), 15: byte(n)},
		DeviceID:   id(0xd1),
		Ciphertext: []byte{byte(n >> 8), byte(n)},
		Header:     []byte("hdr"),
	}
}

func groupRoom(t *testing.T, svc *core.Service) store.UUID {
	t.Helper()
	room, err := svc.CreateRoom(context.Background(), core.KindGroup, owner)
	if err != nil {
		t.Fatal(err)
	}
	return room
}

func TestPostMessageRoundTrip(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	p := payload(1)
	before := time.Now().Truncate(time.Millisecond)
	seq, err := e.svc.PostMessage(ctx, room, owner, p)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("first seq = %d, want 1", seq)
	}
	got := e.stored(t, room)
	if len(got) != 1 {
		t.Fatalf("stored %d messages, want 1", len(got))
	}
	m := got[0]
	if m.RoomID != room || m.Seq != 1 || m.MessageID != p.MessageID || m.SenderID != owner ||
		m.DeviceID != p.DeviceID || !bytes.Equal(m.Ciphertext, p.Ciphertext) || !bytes.Equal(m.Header, p.Header) {
		t.Fatalf("stored %+v, want payload %+v from owner at seq 1", m, p)
	}
	if m.CreatedAt.Before(before) || m.CreatedAt.After(time.Now()) {
		t.Fatalf("created_at %v outside the publish window", m.CreatedAt)
	}
}

// TestPostMessageConcurrentSeq: N concurrent publishes to one room get seqs
// 1..N exactly once, and each stored seq holds the message it was given for.
func TestPostMessageConcurrentSeq(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	const n = 50

	seqs := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { seqs[i], errs[i] = e.svc.PostMessage(ctx, room, owner, payload(i)) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	sorted := slices.Sorted(slices.Values(seqs))
	for i, s := range sorted {
		if s != int64(i+1) {
			t.Fatalf("seqs = %v, want 1..%d exactly once", sorted, n)
		}
	}
	if hi := e.hi(t, room); hi != n {
		t.Fatalf("watermark = %d, want %d", hi, n)
	}
	got := e.stored(t, room)
	if len(got) != n {
		t.Fatalf("stored %d messages, want %d", len(got), n)
	}
	for i, seq := range seqs {
		if m := got[seq-1]; m.Seq != seq || m.MessageID != payload(i).MessageID {
			t.Fatalf("seq %d holds message %x, want %x", seq, m.MessageID, payload(i).MessageID)
		}
	}
}

var errInjected = errors.New("injected failure after the ScyllaDB write")

// failAfterInsert performs the real Insert, then fails once: the ScyllaDB row
// exists but the publish does not commit, leaving an orphan above hi.
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

func TestPostMessageOrphanOverwritten(t *testing.T) {
	inject := &failAfterInsert{fail: true}
	e := newEnv(t, func(ms store.MessageStore) store.MessageStore {
		inject.MessageStore = ms
		return inject
	})
	ctx := context.Background()
	room := groupRoom(t, e.svc)

	if _, err := e.svc.PostMessage(ctx, room, owner, payload(1)); !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the injected failure", err)
	}
	if hi := e.hi(t, room); hi != 0 {
		t.Fatalf("watermark advanced to %d after a failed publish", hi)
	}
	if got := e.stored(t, room); len(got) != 0 {
		t.Fatalf("orphan served: %+v", got)
	}
	// The orphan exists in ScyllaDB above the watermark: reading past hi
	// finds it.
	var orphans []store.Message
	for m, err := range e.msgs.Range(ctx, room, 0, 1) {
		if err != nil {
			t.Fatal(err)
		}
		orphans = append(orphans, m)
	}
	if len(orphans) != 1 || orphans[0].MessageID != payload(1).MessageID {
		t.Fatalf("rows above the watermark = %+v, want the orphan of message 1", orphans)
	}

	seq, err := e.svc.PostMessage(ctx, room, owner, payload(2))
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("retry got seq %d, want the orphan's seq 1", seq)
	}
	got := e.stored(t, room)
	if len(got) != 1 || got[0].MessageID != payload(2).MessageID {
		t.Fatalf("stored %+v, want only message 2 at seq 1", got)
	}
}

func TestPostMessageAuthorization(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	member, gone, outsider := id(0xc2), id(0xc3), id(0xc4)
	for _, u := range []store.UUID{member, gone} {
		if err := e.svc.AddMember(ctx, room, owner, u, core.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.RemoveMember(ctx, room, owner, gone); err != nil {
		t.Fatal(err)
	}

	for name, sender := range map[string]store.UUID{"outsider": outsider, "removed member": gone} {
		if _, err := e.svc.PostMessage(ctx, room, sender, payload(1)); !errors.Is(err, core.ErrNotMember) {
			t.Errorf("%s: err = %v, want ErrNotMember", name, err)
		}
	}
	if hi := e.hi(t, room); hi != 0 {
		t.Fatalf("watermark = %d after rejected publishes", hi)
	}
	if seq, err := e.svc.PostMessage(ctx, room, member, payload(1)); err != nil || seq != 1 {
		t.Fatalf("member publish: seq %d, err %v", seq, err)
	}
	if _, err := e.svc.PostMessage(ctx, id(0xee), owner, payload(1)); !errors.Is(err, core.ErrRoomNotFound) {
		t.Fatalf("missing room: err = %v, want ErrRoomNotFound", err)
	}
}

// TestPostMessageSizeCap: ciphertext and header together are capped at
// MaxPayloadSize, which store.BucketSize relies on.
func TestPostMessageSizeCap(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	const header = 100

	p := payload(1)
	p.Header = make([]byte, header)
	p.Ciphertext = make([]byte, core.MaxPayloadSize-header)
	if _, err := e.svc.PostMessage(ctx, room, owner, p); err != nil {
		t.Fatalf("payload at the cap: %v", err)
	}
	p.Ciphertext = make([]byte, core.MaxPayloadSize-header+1)
	if _, err := e.svc.PostMessage(ctx, room, owner, p); !errors.Is(err, core.ErrPayloadTooLarge) {
		t.Fatalf("payload over the cap: err = %v, want ErrPayloadTooLarge", err)
	}
	if hi := e.hi(t, room); hi != 1 {
		t.Fatalf("watermark = %d, want 1", hi)
	}
}

// TestPostMessageRoomRateLimit: the room limit (S-32) is charged only after
// the sender is authorized, so a non-member cannot spend a room's budget,
// and a refused publish leaves the watermark alone.
func TestPostMessageRoomRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	outsider := id(0xc4)
	budget := 2
	var charged []store.UUID
	e.svc.AllowRoomPost = func(r store.UUID) bool {
		charged = append(charged, r)
		budget--
		return budget >= 0
	}

	for range 5 {
		if _, err := e.svc.PostMessage(ctx, room, outsider, payload(1)); !errors.Is(err, core.ErrNotMember) {
			t.Fatalf("outsider: err = %v; want ErrNotMember", err)
		}
	}
	if len(charged) != 0 {
		t.Fatalf("non-member publishes charged the room %d times", len(charged))
	}
	for i := 1; i <= 2; i++ {
		if _, err := e.svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	if _, err := e.svc.PostMessage(ctx, room, owner, payload(3)); !errors.Is(err, core.ErrRateLimited) {
		t.Fatalf("over budget: err = %v; want ErrRateLimited", err)
	}
	if hi := e.hi(t, room); hi != 2 {
		t.Fatalf("watermark = %d; want 2", hi)
	}
}
