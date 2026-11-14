package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReconcileReport says what Reconcile checked and moved.
type ReconcileReport struct {
	Rooms    int           // rooms checked
	Advanced []RoomAdvance // rooms whose next_seq moved
	WriteTS  int64         // message_write_ts afterwards
}

// RoomAdvance is one room's next_seq moved from From to To.
type RoomAdvance struct {
	Room     UUID
	From, To int64
}

// Reconcile brings Postgres back in line with ScyllaDB after Postgres was
// restored to an earlier point than ScyllaDB holds (S-37). A restore
// rewinds two things that must never go back:
//
//   - each room's next_seq: the messages committed after the restore point
//     are still in ScyllaDB, and clients have seen them. A publish reusing
//     one of those seqs is told it succeeded, but the old row is what
//     ScyllaDB keeps, so the new message is lost.
//   - message_write_ts: a reused timestamp ties with an old row's, and
//     ScyllaDB breaks a tie per cell by value.
//
// For each room, under its lock, Reconcile reads ScyllaDB above the
// watermark and moves next_seq past the contiguous run it finds, so those
// rows become committed again, as clients already believe. A row above a
// missing seq is never part of the run. Then it moves message_write_ts to
// at least the wall clock in microseconds, its seeding unit, which is past
// every value issued so far unless publishes ever averaged more than one
// per microsecond. The run can include one publish that failed after its
// ScyllaDB write (its sender saw an error); it is then served like any
// other message.
//
// Run it with every klacks server stopped, before serving again. It is
// idempotent.
func Reconcile(ctx context.Context, rooms *Rooms, msgs MessageStore) (ReconcileReport, error) {
	var rep ReconcileReport
	rows, err := rooms.pool.Query(ctx, `SELECT room_id FROM room_seq ORDER BY room_id`)
	if err != nil {
		return rep, fmt.Errorf("reconcile: list rooms: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[UUID])
	if err != nil {
		return rep, fmt.Errorf("reconcile: list rooms: %w", err)
	}
	for _, room := range ids {
		err := rooms.Locked(ctx, room, func(ctx context.Context, l *LockedRoom) error {
			from := l.NextSeq()
			top, err := contiguousTop(ctx, msgs, room, from-1)
			if err != nil {
				return err
			}
			if top < from {
				return nil
			}
			if _, err := l.tx.Exec(ctx, `UPDATE room_seq SET next_seq = $2 WHERE room_id = $1`, room, top+1); err != nil {
				return fmt.Errorf("reconcile: advance %x: %w", room, err)
			}
			rep.Advanced = append(rep.Advanced, RoomAdvance{Room: room, From: from, To: top + 1})
			return nil
		})
		if err != nil {
			return rep, err
		}
		rep.Rooms++
	}
	if err := rooms.pool.QueryRow(ctx,
		`SELECT setval('message_write_ts', GREATEST((SELECT last_value FROM message_write_ts), $1))`,
		time.Now().UnixMicro()).Scan(&rep.WriteTS); err != nil {
		return rep, fmt.Errorf("reconcile: advance message_write_ts: %w", err)
	}
	return rep, nil
}

// contiguousTop returns the highest seq of the unbroken run of rows above
// after, or after itself when there is none. It reads a bucket's worth of
// seqs at a time, at the resume path's consistency.
func contiguousTop(ctx context.Context, msgs MessageStore, room UUID, after int64) (int64, error) {
	top := after
	for {
		n := int64(0)
		for m, err := range msgs.Range(ctx, room, top, top+BucketSize) {
			if err != nil {
				return 0, fmt.Errorf("reconcile: read %x: %w", room, err)
			}
			if m.Seq != top+1 {
				return top, nil // a gap: the run ends here
			}
			top = m.Seq
			n++
		}
		if n < BucketSize {
			return top, nil
		}
	}
}
