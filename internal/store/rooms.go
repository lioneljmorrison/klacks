package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRoomNotFound   = errors.New("room not found")
	ErrAlreadyMember  = errors.New("already a member")
	ErrMemberNotFound = errors.New("member not found")
)

// uniqueViolation is the PostgreSQL SQLSTATE for a unique constraint failure.
const uniqueViolation = "23505"

// Rooms is the PostgreSQL store for rooms and membership (plan §3.3a).
type Rooms struct {
	pool *pgxpool.Pool
}

// NewRooms returns a Rooms on a pool whose database is migrated.
func NewRooms(pool *pgxpool.Pool) *Rooms { return &Rooms{pool: pool} }

// CreateRoom creates a room of the given kind with a generated ID, its
// room_seq counter, and owner as its first member with ownerRole, in one
// transaction.
func (r *Rooms) CreateRoom(ctx context.Context, kind string, owner UUID, ownerRole string) (UUID, error) {
	var room UUID
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO rooms (id, kind) VALUES (gen_random_uuid(), $1) RETURNING id`, kind).Scan(&room); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO room_seq (room_id) VALUES ($1)`, room); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, $3)`, room, owner, ownerRole)
		return err
	})
	if err != nil {
		return UUID{}, fmt.Errorf("rooms: create: %w", err)
	}
	return room, nil
}

// Locked runs fn in a transaction that holds the room's room_seq row
// FOR UPDATE. Publishes and membership changes all take this lock, so they
// are serialized per room across server nodes. The transaction commits if fn
// returns nil and rolls back otherwise. It returns ErrRoomNotFound, without
// calling fn, if the room does not exist.
func (r *Rooms) Locked(ctx context.Context, room UUID, fn func(context.Context, *LockedRoom) error) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		l := &LockedRoom{tx: tx, room: room}
		err := tx.QueryRow(ctx, `SELECT next_seq FROM room_seq WHERE room_id = $1 FOR UPDATE`, room).Scan(&l.nextSeq)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("rooms: %x: %w", room, ErrRoomNotFound)
		}
		if err != nil {
			return fmt.Errorf("rooms: lock %x: %w", room, err)
		}
		return fn(ctx, l)
	})
}

// LockedRoom is a room whose lock is held by the enclosing Locked call. It
// is valid only inside that call.
type LockedRoom struct {
	tx      pgx.Tx
	room    UUID
	nextSeq int64
}

// Role returns user's role in the room; ok is false if user is not a member.
func (l *LockedRoom) Role(ctx context.Context, user UUID) (role string, ok bool, err error) {
	err = l.tx.QueryRow(ctx, `SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2`, l.room, user).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("rooms: role: %w", err)
	}
	return role, true, nil
}

// AddMember adds user with role. It returns ErrAlreadyMember if user is a
// member already.
func (l *LockedRoom) AddMember(ctx context.Context, user UUID, role string) error {
	_, err := l.tx.Exec(ctx, `INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, $3)`, l.room, user, role)
	if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return fmt.Errorf("rooms: add member: %w", ErrAlreadyMember)
	}
	if err != nil {
		return fmt.Errorf("rooms: add member: %w", err)
	}
	return nil
}

// RemoveMember removes user. It returns ErrMemberNotFound if user is not a member.
func (l *LockedRoom) RemoveMember(ctx context.Context, user UUID) error {
	tag, err := l.tx.Exec(ctx, `DELETE FROM room_members WHERE room_id = $1 AND user_id = $2`, l.room, user)
	if err != nil {
		return fmt.Errorf("rooms: remove member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("rooms: remove member: %w", ErrMemberNotFound)
	}
	return nil
}
