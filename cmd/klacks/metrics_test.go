package main

import (
	"context"
	"io"
	"iter"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
)

type fakeMessages struct{}

func (fakeMessages) Insert(context.Context, store.Message, int64) error {
	time.Sleep(2 * time.Millisecond)
	return nil
}

func (fakeMessages) Range(context.Context, store.UUID, int64, int64) iter.Seq2[store.Message, error] {
	return func(yield func(store.Message, error) bool) {
		for i := int64(1); i <= 3; i++ {
			time.Sleep(time.Millisecond)
			if !yield(store.Message{Seq: i}, nil) {
				return
			}
		}
	}
}

// The metrics endpoint (S-37) exposes the operational signals the runbook
// watches, and the message store wrapper times inserts and whole range
// reads.
func TestMetrics(t *testing.T) {
	m := newMetrics(
		func() poolStats { return poolStats{Acquired: 2, Idle: 3, Total: 5, Max: 10} },
		func() int { return 7 },
		func() int64 { return 4 },
	)
	m.lockHeld(15 * time.Millisecond)
	msgs := m.timed(fakeMessages{})
	if err := msgs.Insert(context.Background(), store.Message{}, 1); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, err := range msgs.Range(context.Background(), store.UUID{}, 0, 3) {
		if err != nil {
			t.Fatal(err)
		}
		n++
		time.Sleep(50 * time.Millisecond) // the consumer's time is not the store's
	}
	if n != 3 {
		t.Fatalf("range yielded %d; want 3", n)
	}

	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	text := string(body)
	for _, want := range []string{
		"klacks_room_lock_held_seconds_count 1",
		"klacks_scylla_insert_seconds_count 1",
		"klacks_scylla_range_seconds_count 1",
		"klacks_pg_pool_acquired_conns 2",
		"klacks_pg_pool_idle_conns 3",
		"klacks_pg_pool_total_conns 5",
		"klacks_pg_pool_max_conns 10",
		"klacks_ws_connections 7",
		"klacks_ws_slow_disconnects_total 4",
		"go_goroutines",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	// A whole range read is timed (3 rows at 1ms: over 1ms), and the
	// consumer's 150ms is not (under 0.128s).
	if strings.Contains(text, `klacks_scylla_range_seconds_bucket{le="0.001"} 1`) {
		t.Error("range timed before it finished")
	}
	if !strings.Contains(text, `klacks_scylla_range_seconds_bucket{le="0.128"} 1`) {
		t.Error("range time includes the consumer's")
	}
}
