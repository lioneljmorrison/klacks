//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

const testLockTimeout = 10 * time.Second

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
	rooms := store.NewRooms(pool, testLockTimeout)
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
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
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
	if err := locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, owner, user, "member") }); err != nil {
		t.Fatal(err)
	}
	if r, ok := role(t, rooms, room, user); !ok || r != "member" {
		t.Fatalf("role = %q, %t; want member", r, ok)
	}
	err = locked(func(ctx context.Context, l *store.LockedRoom) error { return l.AddMember(ctx, owner, user, "admin") })
	if !errors.Is(err, store.ErrAlreadyMember) {
		t.Fatalf("re-add: err = %v, want ErrAlreadyMember", err)
	}

	if err := locked(func(ctx context.Context, l *store.LockedRoom) error { return l.RemoveMember(ctx, owner, user) }); err != nil {
		t.Fatal(err)
	}
	if _, ok := role(t, rooms, room, user); ok {
		t.Fatal("removed member still has a role")
	}
	err = locked(func(ctx context.Context, l *store.LockedRoom) error { return l.RemoveMember(ctx, owner, user) })
	if !errors.Is(err, store.ErrMemberNotFound) {
		t.Fatalf("remove non-member: err = %v, want ErrMemberNotFound", err)
	}
}

func TestRoomsLockedMissingRoom(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
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
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
	ctx := context.Background()
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err = rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		if err := l.AddMember(ctx, id(0xb1), id(0xb2), "member"); err != nil {
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

func TestRoomsSeq(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
	ctx := context.Background()
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}
	var prevTS int64
	for want := int64(1); want <= 3; want++ {
		err := rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
			if got := l.NextSeq(); got != want {
				t.Fatalf("NextSeq = %d, want %d", got, want)
			}
			ts, err := l.WriteTS(ctx)
			if err != nil {
				return err
			}
			if ts <= prevTS {
				t.Fatalf("WriteTS %d after %d: not increasing", ts, prevTS)
			}
			prevTS = ts
			return l.AdvanceSeq(ctx)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A rolled-back advance leaves the counter alone.
	_ = rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		if err := l.AdvanceSeq(ctx); err != nil {
			t.Fatal(err)
		}
		return errors.New("roll back")
	})
	_ = rooms.Locked(ctx, room, func(_ context.Context, l *store.LockedRoom) error {
		if got := l.NextSeq(); got != 4 {
			t.Fatalf("NextSeq after rollback = %d, want 4", got)
		}
		return nil
	})
}

// TestRoomsLockTimeouts checks that Locked bounds both waiting for the room
// lock and sitting idle while holding it (plan §3.3c operational constraints).
func TestRoomsLockTimeouts(t *testing.T) {
	const timeout = 300 * time.Millisecond
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), timeout)
	ctx := context.Background()
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("waiting for the lock", func(t *testing.T) {
		held, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
				close(held)
				// Stay busy, so the idle timeout does not end this transaction.
				for {
					select {
					case <-release:
						return nil
					case <-time.After(timeout / 4):
						if _, _, err := l.Role(ctx, id(0xb1)); err != nil {
							return err
						}
					}
				}
			})
		}()
		<-held
		start := time.Now()
		err := rooms.Locked(ctx, room, func(context.Context, *store.LockedRoom) error { return nil })
		waited := time.Since(start)
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("holder: %v", err)
		}
		var pgErr *pgconn.PgError
		// lock_timeout and statement_timeout are equal, so either may fire.
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" && pgErr.Code != "57014" {
			t.Fatalf("waiter err = %v, want lock_not_available or query_canceled", err)
		}
		if waited > 5*timeout {
			t.Fatalf("waiter gave up after %v, want about %v", waited, timeout)
		}
	})

	t.Run("idle while holding the lock", func(t *testing.T) {
		err := rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
			time.Sleep(3 * timeout)
			_, _, err := l.Role(ctx, id(0xb1))
			return err
		})
		if err == nil {
			t.Fatal("transaction idle past the timeout still succeeded")
		}
	})
}
