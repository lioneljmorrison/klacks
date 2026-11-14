//go:build integration

package core_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

// queryCounter counts the statements sent on a pool, one per round trip.
type queryCounter struct{ n atomic.Int64 }

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.n.Add(1)
	return ctx
}

func (*queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// S-48: a publish holds its room lock and a pool connection across five
// PostgreSQL round trips: BEGIN with its SET LOCAL timeouts, the FOR UPDATE
// lock, the role check with the write timestamp, the next_seq UPDATE, and
// COMMIT. (It was seven: SET LOCAL and nextval went separately.)
func TestPostMessageRoundTrips(t *testing.T) {
	cfg, err := pgxpool.ParseConfig(dbtest.MigratedPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	counter := &queryCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	svc := core.New(store.NewRooms(pool, 10*time.Second), store.NewScyllaMessages(dbtest.MigratedScylla(t)), nil, nil)
	room := groupRoom(t, svc)

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		before := counter.n.Load()
		if _, err := svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatal(err)
		}
		if n := counter.n.Load() - before; n != 5 {
			t.Errorf("publish %d: %d round trips; want 5", i, n)
		}
	}
	// A non-member is still refused, without advancing anything.
	if _, err := svc.PostMessage(ctx, room, id(0x99), payload(9)); err == nil {
		t.Error("non-member publish succeeded")
	}
}
