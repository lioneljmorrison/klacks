package chat

import (
	"errors"
	"time"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// RoomID identifies a room; UserID a user. Both are 16-byte UUIDs.
type (
	RoomID [16]byte
	UserID [16]byte
)

// Seq is a message's position in its room's stream: per room, gap-free and
// starting at 1.
type Seq int64

// Kind is a room kind.
type Kind string

const (
	KindDM    Kind = "dm"
	KindGroup Kind = "group"
	KindSpace Kind = "space" // created by an embedding ecosystem
)

// Role is a member's role in a room.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// RoomSpec describes a room to create. Room metadata is not settable yet:
// every room is stored with '{}'.
type RoomSpec struct {
	Kind Kind
}

// EncryptedPayload is a message as the sender submits it. The server never
// sees plaintext: Ciphertext and Header are opaque. The client generates
// MessageID; DeviceID is the sending device and is not verified yet.
type EncryptedPayload struct {
	MessageID  [16]byte
	DeviceID   [16]byte
	Ciphertext []byte
	Header     []byte
}

// MaxPayloadSize caps one message's Ciphertext and Header together.
const MaxPayloadSize = core.MaxPayloadSize

// Message is one stored message as delivered to a subscriber. Ciphertext and
// Header are opaque to the server.
type Message struct {
	RoomID     RoomID
	Seq        Seq
	MessageID  [16]byte
	SenderID   UserID
	DeviceID   [16]byte
	Ciphertext []byte
	Header     []byte
	CreatedAt  time.Time
}

// AuditAction names a membership change in the audit log.
type AuditAction string

// Audit actions.
const (
	AuditRoomCreated   AuditAction = store.AuditRoomCreated   // the creator became owner
	AuditMemberAdded   AuditAction = store.AuditMemberAdded   // Target was added with Role
	AuditMemberRemoved AuditAction = store.AuditMemberRemoved // Target, holding Role, was removed (Actor == Target: left)
)

// AuditEvent is one committed membership change (S-33). It never carries
// message content. ID orders a room's events and is the paging cursor.
type AuditEvent struct {
	ID     int64
	Room   RoomID
	Action AuditAction
	Actor  UserID
	Target UserID
	Role   Role
	At     time.Time
}

// MemberRemoved is a membership-change event (S-29): User left Room,
// removed by Actor (Actor == User when they left). E2EE clients use it to
// rotate Sender Keys. For a durable record use AuditLog. The event fires
// synchronously after the removal commits, in commit order per room.
type MemberRemoved struct {
	Room  RoomID
	User  UserID
	Actor UserID
}

// Errors the service returns. They wrap the core's, so errors.Is matches
// across both.
var (
	// ErrInvalidArgument: a kind, role, seq or configuration is not usable.
	ErrInvalidArgument = core.ErrInvalidArgument
	// ErrRoomNotFound: the room does not exist.
	ErrRoomNotFound = core.ErrRoomNotFound
	// ErrAlreadyMember: the user is in the room already.
	ErrAlreadyMember = core.ErrAlreadyMember
	// ErrMemberNotFound: the user is not in the room.
	ErrMemberNotFound = core.ErrMemberNotFound
	// ErrNotMember: the acting user (the configured Actor, or PostMessage's
	// sender) is not a member of the room.
	ErrNotMember = core.ErrNotMember
	// ErrForbidden: the acting user's role does not allow the action.
	ErrForbidden = core.ErrForbidden
	// ErrPayloadTooLarge: the payload exceeds MaxPayloadSize.
	ErrPayloadTooLarge = core.ErrPayloadTooLarge
	// ErrDeviceNotFound: no registered device for the (user, device) pair.
	ErrDeviceNotFound = store.ErrDeviceNotFound
	// ErrInvalidBundle: the bundle or its keys are not usable. The server
	// validates shapes only.
	ErrInvalidBundle = store.ErrInvalidBundle
)

// ErrClosed: the service has been closed.
var ErrClosed = errors.New("chat service is closed")
