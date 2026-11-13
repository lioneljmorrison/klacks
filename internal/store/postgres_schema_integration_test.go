//go:build integration

package store_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/store/migrate"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
	"github.com/lioneljmorrison/klacks/migrations"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// migratedPostgres returns a pool on a fresh database with the embedded
// migrations applied.
func migratedPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	dsn := dbtest.Postgres(t)
	m, err := migrate.NewPostgres(ctx, dsn, migrations.Postgres(), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	pool, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

const (
	room1 = "00000000-0000-0000-0000-0000000000a1"
	user1 = "00000000-0000-0000-0000-0000000000b1"
	dev1  = "00000000-0000-0000-0000-0000000000c1"
)

func TestPostgresSchemaRooms(t *testing.T) {
	pool := migratedPostgres(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	if err := exec(`INSERT INTO rooms (id, kind) VALUES ($1, 'group')`, room1); err != nil {
		t.Fatal(err)
	}
	var metadata string
	var created time.Time
	if err := pool.QueryRow(ctx, `SELECT metadata::text, created_at FROM rooms WHERE id = $1`, room1).Scan(&metadata, &created); err != nil {
		t.Fatal(err)
	}
	if metadata != "{}" || created.IsZero() {
		t.Fatalf("defaults: metadata=%q created_at=%v", metadata, created)
	}

	if err := exec(`INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'member')`, room1, user1); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'member')`, room1, user1); err == nil {
		t.Fatal("duplicate membership accepted")
	}
	if err := exec(`INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'member')`, user1, user1); err == nil {
		t.Fatal("membership of a missing room accepted")
	}

	// room_seq starts at 1, so hi = next_seq - 1 = 0 for an empty room.
	if err := exec(`INSERT INTO room_seq (room_id) VALUES ($1)`, room1); err != nil {
		t.Fatal(err)
	}
	var next int64
	if err := pool.QueryRow(ctx, `SELECT next_seq FROM room_seq WHERE room_id = $1`, room1).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next != 1 {
		t.Fatalf("next_seq default = %d, want 1", next)
	}
	if err := exec(`INSERT INTO room_seq (room_id) VALUES ($1)`, user1); err == nil {
		t.Fatal("room_seq for a missing room accepted")
	}
	if err := exec(`UPDATE room_seq SET next_seq = 0 WHERE room_id = $1`, room1); err == nil {
		t.Fatal("next_seq below 1 accepted")
	}
}

func TestPostgresSchemaDevices(t *testing.T) {
	pool := migratedPostgres(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO devices (user_id, device_id, identity_key, signed_prekey)
		VALUES ($1, $2, $3, $4)`, user1, dev1, []byte{1, 2}, []byte{3, 4})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO devices (user_id, device_id, identity_key, signed_prekey)
		VALUES ($1, $2, $3, $4)`, user1, dev1, []byte{1}, []byte{1})
	if err == nil {
		t.Fatal("duplicate device accepted")
	}
	var last *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_seen_at FROM devices WHERE user_id = $1 AND device_id = $2`, user1, dev1).Scan(&last); err != nil {
		t.Fatal(err)
	}
}

// TestMessageWriteTS checks the properties plan §3.3c relies on: CACHE 1,
// seeded at the current epoch in microseconds, strictly increasing across
// sessions.
func TestMessageWriteTS(t *testing.T) {
	before := time.Now().UnixMicro()
	pool := migratedPostgres(t)
	ctx := context.Background()

	var cache int64
	if err := pool.QueryRow(ctx, `SELECT cache_size FROM pg_sequences WHERE sequencename = 'message_write_ts'`).Scan(&cache); err != nil {
		t.Fatal(err)
	}
	if cache != 1 {
		t.Fatalf("cache_size = %d, want 1", cache)
	}

	a, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()

	conns := []*pgx.Conn{a.Conn(), b.Conn()}
	var prev int64
	for i := range 20 {
		var v int64
		if err := conns[i%2].QueryRow(ctx, `SELECT nextval('message_write_ts')`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if v < before {
				t.Fatalf("first value %d is below the epoch µs %d taken before migrating", v, before)
			}
			if after := time.Now().UnixMicro(); v > after {
				t.Fatalf("first value %d is ahead of now %d", v, after)
			}
		} else if v <= prev {
			t.Fatalf("value %d after %d: not strictly increasing across sessions", v, prev)
		}
		prev = v
	}
}
