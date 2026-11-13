//go:build integration

package core_test

import (
	"context"
	"errors"
	"iter"
	"sync/atomic"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// collect resumes room as user from lastSeen, gathering the messages Resume
// delivers.
func collect(t *testing.T, svc *core.Service, room, user store.UUID, lastSeen int64) (msgs []store.Message, hi int64, err error) {
	t.Helper()
	hi, err = svc.Resume(context.Background(), room, user, lastSeen, func(m store.Message) error {
		msgs = append(msgs, m)
		return nil
	})
	return msgs, hi, err
}

func TestResumeRoundTrip(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	const n = 10
	for i := range n {
		if _, err := e.svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatal(err)
		}
	}

	msgs, hi, err := collect(t, e.svc, room, owner, 0)
	if err != nil {
		t.Fatal(err)
	}
	if hi != n {
		t.Fatalf("hi = %d; want %d", hi, n)
	}
	if len(msgs) != n {
		t.Fatalf("got %d messages; want %d", len(msgs), n)
	}
	for i, m := range msgs {
		if m.Seq != int64(i+1) {
			t.Fatalf("message %d has seq %d; want %d", i, m.Seq, i+1)
		}
		if m.MessageID != payload(i).MessageID {
			t.Fatalf("seq %d holds message %x; want %x", m.Seq, m.MessageID, payload(i).MessageID)
		}
	}

	// From a mid cursor: only what is after it.
	msgs, hi, err = collect(t, e.svc, room, owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	if hi != n || len(msgs) != n-4 {
		t.Fatalf("resume from 4: hi = %d, %d messages; want hi %d and %d", hi, len(msgs), n, n-4)
	}
	if msgs[0].Seq != 5 {
		t.Fatalf("first resumed seq = %d; want 5", msgs[0].Seq)
	}

	// From a cursor at or above the watermark: nothing, hi still returned.
	msgs, hi, err = collect(t, e.svc, room, owner, int64(n))
	if err != nil {
		t.Fatal(err)
	}
	if hi != n || len(msgs) != 0 {
		t.Fatalf("resume from hi: hi = %d, %d messages; want hi %d and none", hi, len(msgs), n)
	}
}

func TestResumeAuthorization(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	member := id(0xc2)
	if err := e.svc.AddMember(ctx, room, owner, member, core.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PostMessage(ctx, room, owner, payload(1)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := collect(t, e.svc, room, id(0xc4), 0); !errors.Is(err, core.ErrNotMember) {
		t.Errorf("outsider: err = %v; want ErrNotMember", err)
	}
	if _, _, err := collect(t, e.svc, room, member, 0); err != nil {
		t.Errorf("member: err = %v; want nil", err)
	}
	if _, _, err := collect(t, e.svc, id(0xee), member, 0); !errors.Is(err, core.ErrRoomNotFound) {
		t.Errorf("missing room: err = %v; want ErrRoomNotFound", err)
	}
	if _, _, err := collect(t, e.svc, room, id(0xc4), -1); !errors.Is(err, core.ErrInvalidArgument) {
		t.Errorf("negative cursor: err = %v; want ErrInvalidArgument", err)
	}
}

func TestAuthorizeRead(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	member := id(0xc2)
	if err := e.svc.AddMember(ctx, room, owner, member, core.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.AuthorizeRead(ctx, room, member); err != nil {
		t.Errorf("member: err = %v; want nil", err)
	}
	if err := e.svc.AuthorizeRead(ctx, room, id(0xc4)); !errors.Is(err, core.ErrNotMember) {
		t.Errorf("outsider: err = %v; want ErrNotMember", err)
	}
	if err := e.svc.AuthorizeRead(ctx, id(0xee), owner); !errors.Is(err, core.ErrRoomNotFound) {
		t.Errorf("missing room: err = %v; want ErrRoomNotFound", err)
	}
}

func TestHi(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room := groupRoom(t, e.svc)

	if hi, err := e.svc.Hi(ctx, room); err != nil || hi != 0 {
		t.Fatalf("hi = %d, err %v; want 0, nil", hi, err)
	}
	if _, err := e.svc.PostMessage(ctx, room, owner, payload(1)); err != nil {
		t.Fatal(err)
	}
	if hi, err := e.svc.Hi(ctx, room); err != nil || hi != 1 {
		t.Fatalf("hi = %d, err %v; want 1, nil", hi, err)
	}
	if _, err := e.svc.Hi(ctx, id(0xee)); !errors.Is(err, core.ErrRoomNotFound) {
		t.Fatalf("missing room: err = %v; want ErrRoomNotFound", err)
	}
}

// gapStore hides one seq from a single read: the committed watermark still
// promises it, so the replay must retry, not skip.
type gapStore struct {
	store.MessageStore
	hide   int64
	hidden atomic.Bool
}

func (g *gapStore) Range(ctx context.Context, room store.UUID, after, hi int64) iter.Seq2[store.Message, error] {
	inner := g.MessageStore.Range(ctx, room, after, hi)
	return func(yield func(store.Message, error) bool) {
		inner(func(m store.Message, err error) bool {
			if err == nil && m.Seq == g.hide && g.hidden.CompareAndSwap(false, true) {
				return true // swallowed once
			}
			return yield(m, err)
		})
	}
}

// TestResumeReplayRetriesMissingSeq: a seq <= hi that a read fails to return
// is retried and delivered; the client never sees a gap.
func TestResumeReplayRetriesMissingSeq(t *testing.T) {
	gap := &gapStore{hide: 3}
	e := newEnv(t, func(ms store.MessageStore) store.MessageStore {
		gap.MessageStore = ms
		return gap
	})
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	const n = 5
	for i := range n {
		if _, err := e.svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatal(err)
		}
	}

	msgs, hi, err := collect(t, e.svc, room, owner, 0)
	if err != nil {
		t.Fatalf("resume with a swallowed seq: %v", err)
	}
	if hi != n || len(msgs) != n {
		t.Fatalf("hi = %d, %d messages; want hi %d and %d", hi, len(msgs), n, n)
	}
	for i, m := range msgs {
		if m.Seq != int64(i+1) {
			t.Fatalf("message %d has seq %d; want %d (gap not filled)", i, m.Seq, i+1)
		}
	}
	if !gap.hidden.Load() {
		t.Error("the gap was never exercised")
	}
}

// TestResumeReplayGivesUpOnPersistentGap: a seq that never comes back is an
// error, never a silent skip.
func TestResumeReplayGivesUpOnPersistentGap(t *testing.T) {
	hole := &alwaysHiding{hide: 3}
	e := newEnv(t, func(ms store.MessageStore) store.MessageStore {
		hole.MessageStore = ms
		return hole
	})
	ctx := context.Background()
	room := groupRoom(t, e.svc)
	for i := range 5 {
		if _, err := e.svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := collect(t, e.svc, room, owner, 0)
	if err == nil {
		t.Fatal("resume succeeded despite a permanently missing seq")
	}
}

// alwaysHiding never yields its hide seq.
type alwaysHiding struct {
	store.MessageStore
	hide int64
}

func (h *alwaysHiding) Range(ctx context.Context, room store.UUID, after, hi int64) iter.Seq2[store.Message, error] {
	inner := h.MessageStore.Range(ctx, room, after, hi)
	return func(yield func(store.Message, error) bool) {
		inner(func(m store.Message, err error) bool {
			if err == nil && m.Seq == h.hide {
				return true
			}
			return yield(m, err)
		})
	}
}
