package core

import "errors"

var (
	// ErrNotMember means the acting user is not a member of the room.
	ErrNotMember = errors.New("not a member of the room")
	// ErrForbidden means the acting user's role does not allow the action.
	ErrForbidden = errors.New("forbidden")
)

type action int

const (
	actPost action = iota
	actRead
	actAdd
	actRemove
)

// request is one authorization question.
type request struct {
	actor  Role // the acting user's role; "" if not a member
	action action
	target Role // add: the role granted; remove: the target's current role
	self   bool // remove: the actor removes themself (leaves)
}

// authorize is the central room authorizer. Every member may post and read.
// An owner may add or remove anyone. An admin may add or remove members only.
// Any member may leave.
func authorize(r request) error {
	if r.actor == "" {
		return ErrNotMember
	}
	switch r.action {
	case actPost, actRead:
		return nil
	case actRemove:
		if r.self {
			return nil
		}
		fallthrough
	case actAdd:
		if r.actor == RoleOwner || r.actor == RoleAdmin && r.target == RoleMember {
			return nil
		}
	}
	return ErrForbidden
}
