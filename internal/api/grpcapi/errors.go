package grpcapi

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// errorFor maps a pkg/chat error to its gRPC code, keeping the distinctions
// an embedder's clients care about: what to retry (Unavailable), what to fix
// in the request (InvalidArgument), what does not exist (NotFound), what
// conflicts (AlreadyExists), what they may not do (PermissionDenied and
// FailedPrecondition). Anything else is Internal: the chat service's own
// store errors are not for the client to interpret.
func errorFor(err error) codes.Code {
	switch {
	case errors.Is(err, chat.ErrInvalidArgument), errors.Is(err, chat.ErrPayloadTooLarge):
		return codes.InvalidArgument
	case errors.Is(err, chat.ErrRoomNotFound), errors.Is(err, chat.ErrMemberNotFound):
		return codes.NotFound
	case errors.Is(err, chat.ErrAlreadyMember):
		return codes.AlreadyExists
	case errors.Is(err, chat.ErrNotMember):
		return codes.FailedPrecondition
	case errors.Is(err, chat.ErrForbidden):
		return codes.PermissionDenied
	case errors.Is(err, chat.ErrClosed):
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

// wrap turns a chat error into a status error naming the operation, as
// pkg/chat itself names its errors ("add member: ...").
func wrap(op string, err error) error {
	return status.Error(errorFor(err), op+": "+err.Error())
}
