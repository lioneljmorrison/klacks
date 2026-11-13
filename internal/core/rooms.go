package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/lioneljmorrison/klacks/internal/store"
)

var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrRoomNotFound    = store.ErrRoomNotFound
	ErrAlreadyMember   = store.ErrAlreadyMember
	ErrNotMember       = store.ErrNotMember
)

// Kind is a room kind (plan §3.2).
type Kind string

const (
	KindDM    Kind = "dm"
	KindGroup Kind = "group"
	KindSpace Kind = "space" // created by an embedding ecosystem
)

func (k Kind) valid() bool { return k == KindDM || k == KindGroup || k == KindSpace }

// Role is a member's role in a room.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

func (r Role) valid() bool { return r == RoleOwner || r == RoleAdmin || r == RoleMember }

// MemberRemoved is the membership-change event RemoveMember emits after its
// transaction commits. Sender Key rotation (S-29) and the audit log (S-33)
// consume it.
type MemberRemoved struct {
	Room store.UUID
	User store.UUID
}

// Service is the room and membership core.
type Service struct {
	rooms     *store.Rooms
	onRemoved func(context.Context, MemberRemoved)
}

// New returns a Service. onRemoved, if not nil, is called synchronously after
// each committed removal.
func New(rooms *store.Rooms, onRemoved func(context.Context, MemberRemoved)) *Service {
	return &Service{rooms: rooms, onRemoved: onRemoved}
}

// CreateRoom creates a room of kind with creator as its owner and returns
// the room's generated ID.
func (s *Service) CreateRoom(ctx context.Context, kind Kind, creator store.UUID) (store.UUID, error) {
	if !kind.valid() {
		return store.UUID{}, fmt.Errorf("create room: kind %q: %w", kind, ErrInvalidArgument)
	}
	return s.rooms.CreateRoom(ctx, string(kind), creator, string(RoleOwner))
}

// AddMember adds user to room with role.
func (s *Service) AddMember(ctx context.Context, room, user store.UUID, role Role) error {
	if !role.valid() {
		return fmt.Errorf("add member: role %q: %w", role, ErrInvalidArgument)
	}
	return s.rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		return l.AddMember(ctx, user, string(role))
	})
}

// RemoveMember removes user from room, then emits MemberRemoved.
func (s *Service) RemoveMember(ctx context.Context, room, user store.UUID) error {
	err := s.rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		return l.RemoveMember(ctx, user)
	})
	if err != nil {
		return err
	}
	if s.onRemoved != nil {
		s.onRemoved(ctx, MemberRemoved{Room: room, User: user})
	}
	return nil
}
