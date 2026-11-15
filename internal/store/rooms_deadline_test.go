package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/testutil/blackhole"
)

// S-47: with PostgreSQL partitioned (connections accepted, nothing ever
// answered), every unlocked room read gives up after the lock timeout
// with an error store.Unavailable recognizes, instead of hanging until the
// caller goes away.
func TestRoomReadsHaveDeadline(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@"+blackhole.Listen(t)+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	r := NewRooms(pool, 200*time.Millisecond)
	ctx := context.Background() // no deadline of its own, as in the ws handlers
	room, user := UUID{1}, UUID{2}

	for name, call := range map[string]func() error{
		"role":      func() error { _, _, err := r.Role(ctx, room, user); return err },
		"members":   func() error { _, err := r.Members(ctx, room); return err },
		"watermark": func() error { _, err := r.Watermark(ctx, room); return err },
		"create":    func() error { _, err := r.CreateRoom(ctx, "group", user, "owner"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- call() }()
			select {
			case err := <-done:
				if !Unavailable(err) {
					t.Errorf("err = %v; want an unavailable error", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("still hanging after 5s")
			}
		})
	}
}
