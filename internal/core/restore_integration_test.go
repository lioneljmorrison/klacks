//go:build integration

package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// After Postgres is restored to a point before the ScyllaDB data (S-37), the
// rooms' next_seq and message_write_ts are rewound while the messages
// committed after that point are still in ScyllaDB, and clients have seen
// them. Unreconciled, the next publish reuses a seq whose old row wins in
// ScyllaDB: the sender is told it succeeded and the message is lost.
// store.Reconcile moves each room's counter past what ScyllaDB holds and the
// timestamp sequence past the wall clock, so the old rows stand and new
// publishes land above them.
func TestReconcileAfterPostgresRewind(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	room, quiet := groupRoom(t, e.svc), groupRoom(t, e.svc)
	for i := 1; i <= 2; i++ {
		if _, err := e.svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.PostMessage(ctx, quiet, owner, payload(50)); err != nil {
		t.Fatal(err)
	}
	// The "backup": the counter and the write-timestamp sequence now.
	var backupTS int64
	if err := e.pool.QueryRow(ctx, `SELECT last_value FROM message_write_ts`).Scan(&backupTS); err != nil {
		t.Fatal(err)
	}
	for i := 3; i <= 5; i++ {
		if _, err := e.svc.PostMessage(ctx, room, owner, payload(i)); err != nil {
			t.Fatal(err)
		}
	}
	// The "restore".
	if _, err := e.pool.Exec(ctx, `UPDATE room_seq SET next_seq = 3 WHERE room_id = $1`, room); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `SELECT setval('message_write_ts', $1)`, backupTS); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	rooms := store.NewRooms(e.pool, 10*time.Second)
	rep, err := store.Reconcile(ctx, rooms, e.msgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Advanced) != 1 || rep.Advanced[0].Room != room || rep.Advanced[0].From != 3 || rep.Advanced[0].To != 6 {
		t.Fatalf("advanced = %+v; want room from next_seq 3 to 6", rep.Advanced)
	}
	if rep.Rooms != 2 {
		t.Errorf("checked %d rooms; want 2", rep.Rooms)
	}
	var ts int64
	if err := e.pool.QueryRow(ctx, `SELECT last_value FROM message_write_ts`).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if ts < before.UnixMicro() {
		t.Errorf("message_write_ts = %d; want at least the wall clock %d", ts, before.UnixMicro())
	}

	fresh := payload(0) // compares below the old rows, so a tie cannot hide a loss
	seq, err := e.svc.PostMessage(ctx, room, owner, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 6 {
		t.Fatalf("publish after reconcile got seq %d; want 6", seq)
	}
	got := e.stored(t, room)
	if len(got) != 6 {
		t.Fatalf("stored %d messages; want 6", len(got))
	}
	for i := 0; i < 5; i++ {
		if got[i].MessageID != payload(i+1).MessageID {
			t.Errorf("seq %d = %x; want the original %x", i+1, got[i].MessageID, payload(i+1).MessageID)
		}
	}
	if got[5].MessageID != fresh.MessageID {
		t.Errorf("seq 6 = %x; want the new publish", got[5].MessageID)
	}

	// Idempotent: nothing more to move.
	rep, err = store.Reconcile(ctx, rooms, e.msgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Advanced) != 0 {
		t.Errorf("second reconcile advanced %+v", rep.Advanced)
	}
}
