//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

// The membership audit log (S-33): every committed membership change, and
// only those, appends one event in the same transaction.
func TestAuditLog(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	rooms := store.NewRooms(pool, testLockTimeout)
	ctx := context.Background()
	owner, admin, user := id(0xa1), id(0xa2), id(0xa3)
	room, err := rooms.CreateRoom(ctx, "group", owner, "owner")
	if err != nil {
		t.Fatal(err)
	}
	other, err := rooms.CreateRoom(ctx, "group", owner, "owner")
	if err != nil {
		t.Fatal(err)
	}
	locked := func(fn func(ctx context.Context, l *store.LockedRoom) error) error {
		return rooms.Locked(ctx, room, fn)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, owner, admin, "admin") }))
	must(locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, admin, user, "member") }))
	// A change that rolls back leaves no event.
	boom := errors.New("boom")
	if err := locked(func(ctx context.Context, l *store.LockedRoom) error {
		if err := l.RemoveMember(ctx, owner, admin); err != nil {
			return err
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v; want boom", err)
	}
	// A refused change leaves no event either.
	if err := locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, owner, user, "member") }); !errors.Is(err, store.ErrAlreadyMember) {
		t.Fatalf("re-add: %v", err)
	}
	must(locked(func(ctx context.Context, l *store.LockedRoom) error { return l.RemoveMember(ctx, user, user) }))

	got, err := rooms.Audit(ctx, room, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []store.AuditEvent{
		{Room: room, Action: store.AuditRoomCreated, Actor: owner, Target: owner, Role: "owner"},
		{Room: room, Action: store.AuditMemberAdded, Actor: owner, Target: admin, Role: "admin"},
		{Room: room, Action: store.AuditMemberAdded, Actor: admin, Target: user, Role: "member"},
		{Room: room, Action: store.AuditMemberRemoved, Actor: user, Target: user, Role: "member"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events: %+v; want %d", len(got), got, len(want))
	}
	for i := range want {
		g := got[i]
		if g.ID == 0 || g.At.IsZero() {
			t.Errorf("event %d: missing id or time: %+v", i, g)
		}
		if i > 0 && g.ID <= got[i-1].ID {
			t.Errorf("event %d: id %d not after %d", i, g.ID, got[i-1].ID)
		}
		g.ID, g.At = 0, want[i].At
		if g != want[i] {
			t.Errorf("event %d = %+v; want %+v", i, g, want[i])
		}
	}

	// Paging: after an id, at most limit events.
	page, err := rooms.Audit(ctx, room, got[1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].ID != got[2].ID || page[1].ID != got[3].ID {
		t.Errorf("page after %d = %+v", got[1].ID, page)
	}
	// Rooms do not see each other's events.
	o, err := rooms.Audit(ctx, other, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(o) != 1 || o[0].Room != other || o[0].Action != store.AuditRoomCreated {
		t.Errorf("other room's events = %+v", o)
	}

	// Append-only: the table refuses updates and deletes.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET role = 'owner'`); err == nil {
		t.Error("UPDATE audit_events succeeded")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events`); err == nil {
		t.Error("DELETE FROM audit_events succeeded")
	}
}

func TestAuditCreateRoomWithID(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
	ctx := context.Background()
	room, owner := id(0xa9), id(0xa1)
	if err := rooms.CreateRoomWithID(ctx, room, "dm", owner, "owner"); err != nil {
		t.Fatal(err)
	}
	got, err := rooms.Audit(ctx, room, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Action != store.AuditRoomCreated || got[0].Actor != owner || got[0].Target != owner {
		t.Errorf("events = %+v", got)
	}
}
