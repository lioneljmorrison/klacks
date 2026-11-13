//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

// role reads user's role in room under the room lock.
func role(t *testing.T, rooms *store.Rooms, room, user store.UUID) (string, bool) {
	t.Helper()
	var r string
	var ok bool
	err := rooms.Locked(context.Background(), room, func(ctx context.Context, l *store.LockedRoom) error {
		var err error
		r, ok, err = l.Role(ctx, user)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, ok
}

func TestRoomsCreate(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	rooms := store.NewRooms(pool)
	ctx := context.Background()
	owner := id(0xb1)

	room, err := rooms.CreateRoom(ctx, "group", owner, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if room == (store.UUID{}) {
		t.Fatal("zero room id")
	}
	other, err := rooms.CreateRoom(ctx, "group", owner, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if other == room {
		t.Fatal("two rooms got the same id")
	}

	var kind string
	var next int64
	if err := pool.QueryRow(ctx, `SELECT r.kind, s.next_seq FROM rooms r JOIN room_seq s ON s.room_id = r.id WHERE r.id = $1`, room).Scan(&kind, &next); err != nil {
		t.Fatal(err)
	}
	if kind != "group" || next != 1 {
		t.Fatalf("kind=%q next_seq=%d, want group, 1", kind, next)
	}
	if r, ok := role(t, rooms, room, owner); !ok || r != "owner" {
		t.Fatalf("creator role = %q, %t; want owner", r, ok)
	}
}

func TestRoomsMembership(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t))
	ctx := context.Background()
	owner, user := id(0xb1), id(0xb2)
	room, err := rooms.CreateRoom(ctx, "group", owner, "owner")
	if err != nil {
		t.Fatal(err)
	}
	locked := func(fn func(ctx context.Context, l *store.LockedRoom) error) error {
		return rooms.Locked(ctx, room, fn)
	}

	if _, ok := role(t, rooms, room, user); ok {
		t.Fatal("non-member has a role")
	}
	if err := locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, user, "member") }); err != nil {
		t.Fatal(err)
	}
	if r, ok := role(t, rooms, room, user); !ok || r != "member" {
		t.Fatalf("role = %q, %t; want member", r, ok)
	}
	err = locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, user, "admin") })
	if !errors.Is(err, store.ErrAlreadyMember) {
		t.Fatalf("re-add: err = %v, want ErrAlreadyMember", err)
	}

	if err := locked(func(ctx context.Context, l *store.LockedRoom) error { return l.RemoveMember(ctx, user) }); err != nil {
		t.Fatal(err)
	}
	if _, ok := role(t, rooms, room, user); ok {
		t.Fatal("removed member still has a role")
	}
	err = locked(func(ctx context.Context, l *store.LockedRoom) error { return l.RemoveMember(ctx, user) })
	if !errors.Is(err, store.ErrNotMember) {
		t.Fatalf("remove non-member: err = %v, want ErrNotMember", err)
	}
}

func TestRoomsLockedMissingRoom(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t))
	called := false
	err := rooms.Locked(context.Background(), id(0xee), func(context.Context, *store.LockedRoom) error {
		called = true
		return nil
	})
	if !errors.Is(err, store.ErrRoomNotFound) || called {
		t.Fatalf("err = %v, fn called = %t; want ErrRoomNotFound, not called", err, called)
	}
}

// TestRoomsLockedRollsBack checks that an error from fn rolls back its writes.
func TestRoomsLockedRollsBack(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t))
	ctx := context.Background()
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err = rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		if err := l.AddMember(ctx, id(0xb2), "member"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if _, ok := role(t, rooms, room, id(0xb2)); ok {
		t.Fatal("write from a failed transaction was committed")
	}
}
