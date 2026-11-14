package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

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

// Rooms is the PostgreSQL store for rooms, membership and the per-room seq
// counter (plan §3.3a, §3.3c).
type Rooms struct {
	pool        *pgxpool.Pool
	lockTimeout time.Duration

	// OnLockHeld, if not nil, is called after each Locked call that took
	// its room's lock, with how long it held it: from the FOR UPDATE row
	// lock to the end of the transaction, commit or rollback included
	// (S-37). Publishes hold it across their ScyllaDB write, so this is the
	// per-room serialization cost. Set it before use.
	OnLockHeld func(time.Duration)
}

// NewRooms returns a Rooms on a pool whose database is migrated.
//
// lockTimeout bounds every Locked transaction: it is the transaction's
// lock_timeout, statement_timeout and idle_in_transaction_session_timeout.
// It must be longer than the ScyllaDB write timeout. A publish holds the room
// lock across its ScyllaDB write, during which the Postgres session is idle in
// transaction; a shorter timeout would kill a live publish. The idle timeout
// also releases the lock if a process hangs while holding it.
func NewRooms(pool *pgxpool.Pool, lockTimeout time.Duration) *Rooms {
	return &Rooms{pool: pool, lockTimeout: lockTimeout}
}

// beginSQL opens a Locked transaction with its timeouts. The values are
// integer milliseconds, formatted here, never caller text.
func (r *Rooms) beginSQL() string {
	ms := strconv.FormatInt(r.lockTimeout.Milliseconds(), 10)
	return "BEGIN; SET LOCAL lock_timeout = " + ms +
		"; SET LOCAL statement_timeout = " + ms +
		"; SET LOCAL idle_in_transaction_session_timeout = " + ms
}

// CreateRoom creates a room of the given kind with a generated ID, its
// room_seq counter, and owner as its first member with ownerRole, in one
// transaction.
func (r *Rooms) CreateRoom(ctx context.Context, kind string, owner UUID, ownerRole string) (UUID, error) {
	var room UUID
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO rooms (id, kind) VALUES (gen_random_uuid(), $1) RETURNING id`, kind).Scan(&room); err != nil {
			return err
		}
		return createRoomSeqAndMember(ctx, tx, room, owner, ownerRole)
	})
	if err != nil {
		return UUID{}, fmt.Errorf("rooms: create: %w", err)
	}
	return room, nil
}

// CreateRoomWithID creates a room with the caller's chosen ID — the
// deterministic UUID a human-readable name resolves to. An ID that already
// exists fails with the driver's unique-violation error, which the caller
// surfaces as "already exists".
func (r *Rooms) CreateRoomWithID(ctx context.Context, room UUID, kind string, owner UUID, ownerRole string) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO rooms (id, kind) VALUES ($1, $2)`, room, kind); err != nil {
			return err
		}
		return createRoomSeqAndMember(ctx, tx, room, owner, ownerRole)
	})
}

// createRoomSeqAndMember is the room_seq and owner-member half of room
// creation, shared by both entry points. It runs inside the caller's
// transaction, after the rooms row exists.
func createRoomSeqAndMember(ctx context.Context, tx pgx.Tx, room UUID, owner UUID, ownerRole string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO room_seq (room_id) VALUES ($1)`, room); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, $3)`, room, owner, ownerRole)
	return err
}

// Locked runs fn in a transaction that holds the room's room_seq row
// FOR UPDATE. Publishes and membership changes all take this lock, so they
// are serialized per room across server nodes. The transaction commits if fn
// returns nil and rolls back otherwise. It returns ErrRoomNotFound, without
// calling fn, if the room does not exist.
func (r *Rooms) Locked(ctx context.Context, room UUID, fn func(context.Context, *LockedRoom) error) error {
	var locked time.Time
	// The timeouts ride on BEGIN, in the same round trip (S-48): pgx sends a
	// BeginQuery without arguments as one simple-protocol message, and SET
	// LOCAL lasts for this transaction. lock_timeout is in force before the
	// FOR UPDATE below waits for the row lock.
	err := pgx.BeginTxFunc(ctx, r.pool, pgx.TxOptions{BeginQuery: r.beginSQL()}, func(tx pgx.Tx) error {
		l := &LockedRoom{tx: tx, room: room}
		err := tx.QueryRow(ctx, `SELECT next_seq FROM room_seq WHERE room_id = $1 FOR UPDATE`, room).Scan(&l.nextSeq)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("rooms: %x: %w", room, ErrRoomNotFound)
		}
		if err != nil {
			return fmt.Errorf("rooms: lock %x: %w", room, err)
		}
		locked = time.Now()
		return fn(ctx, l)
	})
	// BeginFunc has committed or rolled back by now: the lock is released.
	if !locked.IsZero() && r.OnLockHeld != nil {
		r.OnLockHeld(time.Since(locked))
	}
	return err
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

// Role returns user's role in room without taking the room lock: a plain
// read, for the read authorization behind subscribe and resume. ok is false
// if user is not a member. It returns ErrRoomNotFound if the room does not
// exist.
func (r *Rooms) Role(ctx context.Context, room, user UUID) (role string, ok bool, err error) {
	err = r.pool.QueryRow(ctx, `SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2`, room, user).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		// No member row: either user is not a member or there is no room.
		// Distinguish for callers, which report the two differently.
		var exists bool
		if e := r.pool.QueryRow(ctx, `SELECT true FROM rooms WHERE id = $1`, room).Scan(&exists); errors.Is(e, pgx.ErrNoRows) {
			return "", false, fmt.Errorf("rooms: %x: %w", room, ErrRoomNotFound)
		} else if e != nil {
			return "", false, fmt.Errorf("rooms: exists: %w", e)
		}
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("rooms: role: %w", err)
	}
	return role, true, nil
}

// Members returns the room's member user ids, in no particular order. It
// returns ErrRoomNotFound if the room does not exist.
func (r *Rooms) Members(ctx context.Context, room UUID) ([]UUID, error) {
	rows, err := r.pool.Query(ctx, `SELECT user_id FROM room_members WHERE room_id = $1`, room)
	if err != nil {
		return nil, fmt.Errorf("rooms: members: %w", err)
	}
	defer rows.Close()
	var out []UUID
	for rows.Next() {
		var u UUID
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("rooms: members: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rooms: members: %w", err)
	}
	if out == nil {
		// No member rows: either the room is empty or there is no room.
		// Distinguish for callers, which report the two differently.
		var exists bool
		if e := r.pool.QueryRow(ctx, `SELECT true FROM rooms WHERE id = $1`, room).Scan(&exists); errors.Is(e, pgx.ErrNoRows) {
			return nil, fmt.Errorf("rooms: %x: %w", room, ErrRoomNotFound)
		} else if e != nil {
			return nil, fmt.Errorf("rooms: exists: %w", e)
		}
	}
	return out, nil
}

// Watermark returns the room's committed watermark hi: room_seq.next_seq - 1,
// read with a plain SELECT, without FOR UPDATE (it does not guard a publish,
// it only observes it). Every seq <= hi is in the message store; rows above
// hi may be uncommitted orphans and must never be served.
func (r *Rooms) Watermark(ctx context.Context, room UUID) (int64, error) {
	var next int64
	err := r.pool.QueryRow(ctx, `SELECT next_seq FROM room_seq WHERE room_id = $1`, room).Scan(&next)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("rooms: %x: %w", room, ErrRoomNotFound)
	}
	if err != nil {
		return 0, fmt.Errorf("rooms: watermark: %w", err)
	}
	return next - 1, nil
}

// RoleAndWriteTS returns user's role in the room (ok is false if user is
// not a member) and the next ScyllaDB write timestamp from the
// message_write_ts sequence, in one round trip (S-48). Both are read in a
// statement of their own after the FOR UPDATE, so after the lock is
// granted: the role sees any membership change that committed while this
// call waited for the lock, and the timestamp is higher than that of any
// earlier attempt at the same seq, so a retry overwrites an orphan (plan
// §3.3c). Neither may be folded into the FOR UPDATE query: under READ
// COMMITTED a command that waited for a row lock "does not see effects of
// those commands on other rows in the database", while later commands in
// the transaction do (PostgreSQL docs, Read Committed Isolation Level), so
// the role must come from a later statement; and nothing documents that a
// select-list nextval runs after the lock wait. A non-member still consumes
// a timestamp; the sequence only has to increase.
func (l *LockedRoom) RoleAndWriteTS(ctx context.Context, user UUID) (role string, ok bool, ts int64, err error) {
	var r *string
	err = l.tx.QueryRow(ctx, `SELECT (SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2),
		nextval('message_write_ts')`, l.room, user).Scan(&r, &ts)
	if err != nil {
		return "", false, 0, fmt.Errorf("rooms: role and write timestamp: %w", err)
	}
	if r == nil {
		return "", false, ts, nil
	}
	return *r, true, ts, nil
}

// NextSeq is the seq the next published message gets: the locked
// room_seq.next_seq. The committed watermark (hi) is NextSeq - 1.
func (l *LockedRoom) NextSeq() int64 { return l.nextSeq }

// AdvanceSeq sets next_seq to NextSeq + 1. It takes effect when the
// enclosing Locked call commits.
func (l *LockedRoom) AdvanceSeq(ctx context.Context) error {
	if _, err := l.tx.Exec(ctx, `UPDATE room_seq SET next_seq = $2 WHERE room_id = $1`, l.room, l.nextSeq+1); err != nil {
		return fmt.Errorf("rooms: advance seq: %w", err)
	}
	return nil
}
