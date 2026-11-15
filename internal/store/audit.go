package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit actions (S-33).
const (
	AuditRoomCreated   = "room_created"
	AuditMemberAdded   = "member_added"
	AuditMemberRemoved = "member_removed"
)

// AuditEvent is one membership change. Role is the role granted
// (room_created, member_added) or the one held when removed. ID orders a
// room's events and is the paging cursor.
type AuditEvent struct {
	ID     int64
	Room   UUID
	Action string
	Actor  UUID
	Target UUID
	Role   string
	At     time.Time
}

// audit appends one event inside tx, so it commits or rolls back with the
// change it records.
func audit(ctx context.Context, tx pgx.Tx, room UUID, action string, actor, target UUID, role string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_events (room_id, action, actor_id, target_id, role) VALUES ($1, $2, $3, $4, $5)`,
		room, action, actor, target, role)
	if err != nil {
		return fmt.Errorf("rooms: audit %s: %w", action, err)
	}
	return nil
}

// Audit returns up to limit of room's events with an ID above after, oldest
// first. Pass the last ID seen as after to read the next page. A room that
// does not exist has no events; that is not an error.
func (r *Rooms) Audit(ctx context.Context, room UUID, after int64, limit int) ([]AuditEvent, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, room_id, action, actor_id, target_id, role, at
		FROM audit_events WHERE room_id = $1 AND id > $2 ORDER BY id LIMIT $3`, room, after, limit)
	if err != nil {
		return nil, fmt.Errorf("rooms: audit: %w", err)
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (AuditEvent, error) {
		var e AuditEvent
		err := row.Scan(&e.ID, &e.Room, &e.Action, &e.Actor, &e.Target, &e.Role, &e.At)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("rooms: audit: %w", err)
	}
	return events, nil
}
