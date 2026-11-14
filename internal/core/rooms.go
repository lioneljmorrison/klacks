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
	ErrMemberNotFound  = store.ErrMemberNotFound
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
// consume it. Actor == User when a member leaves.
type MemberRemoved struct {
	Room  store.UUID
	User  store.UUID
	Actor store.UUID
}

// Service is the room, membership and publish core.
type Service struct {
	rooms     *store.Rooms
	messages  store.MessageStore
	onPosted  func(context.Context, store.Message)
	onRemoved func(context.Context, MemberRemoved)

	// AllowRoomPost, if not nil, is the per-room publish limit (S-32): it
	// is asked once per authorized publish, after the sender's membership
	// check, so a non-member's refused publishes never spend a room's
	// budget. False fails the publish with ErrRateLimited. It runs under
	// the room lock and must be fast. Set it before serving.
	AllowRoomPost func(room store.UUID) bool
}

// New returns a Service. onPosted, if not nil, is called with each committed
// message after its publish commits: live fan-out to online subscribers
// (S-13). The call happens in publish order, so the room's seqs arrive in
// order. onRemoved, if not nil, is called synchronously after each committed
// removal.
func New(rooms *store.Rooms, messages store.MessageStore, onPosted func(context.Context, store.Message), onRemoved func(context.Context, MemberRemoved)) *Service {
	return &Service{rooms: rooms, messages: messages, onPosted: onPosted, onRemoved: onRemoved}
}

// CreateRoom creates a room of kind with creator as its owner and returns
// the room's generated ID.
func (s *Service) CreateRoom(ctx context.Context, kind Kind, creator store.UUID) (store.UUID, error) {
	if !kind.valid() {
		return store.UUID{}, fmt.Errorf("create room: kind %q: %w", kind, ErrInvalidArgument)
	}
	return s.rooms.CreateRoom(ctx, string(kind), creator, string(RoleOwner))
}

// CreateRoomWithID creates a room with the caller's chosen ID — the UUID a
// human-readable name resolved to — with creator as its owner. The caller
// validates the ID is not the zero UUID; an ID that already exists fails
// with the driver's unique-violation error.
func (s *Service) CreateRoomWithID(ctx context.Context, room store.UUID, kind Kind, creator store.UUID) error {
	if !kind.valid() {
		return fmt.Errorf("create room: kind %q: %w", kind, ErrInvalidArgument)
	}
	if room == (store.UUID{}) {
		return fmt.Errorf("create room: room id is required: %w", ErrInvalidArgument)
	}
	return s.rooms.CreateRoomWithID(ctx, room, string(kind), creator, string(RoleOwner))
}

// AddMember adds user to room with role, if actor may grant it.
func (s *Service) AddMember(ctx context.Context, room, actor, user store.UUID, role Role) error {
	if !role.valid() {
		return fmt.Errorf("add member: role %q: %w", role, ErrInvalidArgument)
	}
	return s.rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		actorRole, err := memberRole(ctx, l, actor)
		if err != nil {
			return err
		}
		if err := authorize(request{actor: actorRole, action: actAdd, target: role}); err != nil {
			return fmt.Errorf("add member: %w", err)
		}
		return l.AddMember(ctx, user, string(role))
	})
}

// RemoveMember removes user from room, if actor may remove them, then emits
// MemberRemoved. A member may always remove themself (leave).
func (s *Service) RemoveMember(ctx context.Context, room, actor, user store.UUID) error {
	err := s.rooms.Locked(ctx, room, func(ctx context.Context, l *store.LockedRoom) error {
		actorRole, err := memberRole(ctx, l, actor)
		if err != nil {
			return err
		}
		if actorRole == "" {
			return fmt.Errorf("remove member: %w", ErrNotMember)
		}
		target, err := memberRole(ctx, l, user)
		if err != nil {
			return err
		}
		if target == "" {
			return fmt.Errorf("remove member: %w", ErrMemberNotFound)
		}
		if err := authorize(request{actor: actorRole, action: actRemove, target: target, self: actor == user}); err != nil {
			return fmt.Errorf("remove member: %w", err)
		}
		return l.RemoveMember(ctx, user)
	})
	if err != nil {
		return err
	}
	if s.onRemoved != nil {
		s.onRemoved(ctx, MemberRemoved{Room: room, User: user, Actor: actor})
	}
	return nil
}

// memberRole returns user's role in the locked room, or "" if user is not a
// member.
func memberRole(ctx context.Context, l *store.LockedRoom, user store.UUID) (Role, error) {
	r, ok, err := l.Role(ctx, user)
	if err != nil || !ok {
		return "", err
	}
	return Role(r), nil
}

// Members returns the room's member user ids. The resume flow carries the
// list to clients (S-29), so a returning member can reconcile membership
// changes it was offline for.
func (s *Service) Members(ctx context.Context, room store.UUID) ([]store.UUID, error) {
	return s.rooms.Members(ctx, room)
}
