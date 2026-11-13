package chat

import (
	"errors"
	"time"

	"github.com/lioneljmorrison/klacks/internal/core"
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
)

// ErrClosed: the service has been closed.
var ErrClosed = errors.New("chat service is closed")
