package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/testutil/blackhole"
)

// S-51: with PostgreSQL partitioned, every device call gives up after its
// timeout with an error Unavailable recognizes, instead of hanging until
// the caller goes away.
func TestDeviceCallsHaveDeadline(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@"+blackhole.Listen(t)+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	d := NewDevices(pool, 200*time.Millisecond)
	ctx := context.Background() // no deadline of its own, as in the REST handlers
	user, device := UUID{1}, UUID{2}
	b := Bundle{
		IdentityKey: make([]byte, IdentityKeySize), IdentityDHKey: make([]byte, DHKeySize),
		SignedPrekeyID: 1, SignedPrekey: make([]byte, DHKeySize), SignedPrekeySig: make([]byte, SignatureSize),
	}

	for name, call := range map[string]func() error{
		"upload":  func() error { return d.UploadBundle(ctx, user, device, b, nil) },
		"prekeys": func() error { return d.AddOneTimePrekeys(ctx, user, device, nil) },
		"bundle":  func() error { _, _, err := d.Bundle(ctx, user, device); return err },
		"list":    func() error { _, err := d.ListDevices(ctx, user); return err },
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
