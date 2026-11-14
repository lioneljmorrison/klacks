//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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
			_, _, ts, err := l.RoleAndWriteTS(ctx, id(0xb1))
			if err != nil {
				return err
			}
			if ts <= prevTS {
				t.Fatalf("write ts %d after %d: not increasing", ts, prevTS)
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

// OnLockHeld (S-37) reports how long each Locked call held the room lock:
// from the FOR UPDATE row lock to the end of the transaction, commit
// included. A room that does not exist never held a lock.
func TestRoomsOnLockHeld(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
	ctx := context.Background()
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}
	var held []time.Duration
	rooms.OnLockHeld = func(d time.Duration) { held = append(held, d) }
	const work = 30 * time.Millisecond
	if err := rooms.Locked(ctx, room, func(context.Context, *store.LockedRoom) error {
		time.Sleep(work)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if err := rooms.Locked(ctx, room, func(context.Context, *store.LockedRoom) error { return boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	_ = rooms.Locked(ctx, id(0xee), func(context.Context, *store.LockedRoom) error { return nil })
	if len(held) != 2 {
		t.Fatalf("OnLockHeld called %d times; want 2 (commit and rollback, not the missing room)", len(held))
	}
	if held[0] < work {
		t.Errorf("held %v; want at least the %v of work inside", held[0], work)
	}
}

// S-48: the room lock's timeouts ride on BEGIN and stay transaction-local:
// the pooled connection is back at the server defaults afterwards.
func TestRoomsLockTimeoutsAreTransactionLocal(t *testing.T) {
	cfg, err := pgxpool.ParseConfig(dbtest.MigratedPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1 // every call below shares one connection
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	show := func() (lock, stmt, idle string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT current_setting('lock_timeout'), current_setting('statement_timeout'),
			current_setting('idle_in_transaction_session_timeout')`).Scan(&lock, &stmt, &idle); err != nil {
			t.Fatal(err)
		}
		return
	}
	l0, s0, i0 := show()
	rooms := store.NewRooms(pool, 1234*time.Millisecond)
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := rooms.Locked(ctx, room, func(context.Context, *store.LockedRoom) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if l, s, i := show(); l != l0 || s != s0 || i != i0 {
		t.Errorf("after Locked: %s %s %s; want the defaults %s %s %s", l, s, i, l0, s0, i0)
	}
}

// S-48: the role check and the write timestamp come back together, after the
// lock: a member gets its role, a non-member ok == false, and every call a
// fresh, increasing timestamp.
func TestRoomsRoleAndWriteTS(t *testing.T) {
	rooms := store.NewRooms(dbtest.MigratedPostgres(t), testLockTimeout)
	ctx := context.Background()
	room, err := rooms.CreateRoom(ctx, "group", id(0xb1), "owner")
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	for _, tc := range []struct {
		user store.UUID
		role string
		ok   bool
	}{{id(0xb1), "owner", true}, {id(0xb2), "", false}, {id(0xb1), "owner", true}} {
		err := rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
			role, ok, ts, err := l.RoleAndWriteTS(ctx, tc.user)
			if err != nil {
				return err
			}
			if role != tc.role || ok != tc.ok {
				t.Errorf("user %x: role %q ok %v; want %q %v", tc.user, role, ok, tc.role, tc.ok)
			}
			if ts <= last {
				t.Errorf("write ts %d not above %d", ts, last)
			}
			last = ts
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
