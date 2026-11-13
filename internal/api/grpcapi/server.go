// Package grpcapi serves the chat core as gRPC: klacks.chat.v1.ChatService
// mirrors pkg/chat.ChatService one to one, for embedders that reach the core
// from another language or another process. New wraps any ChatService —
// *chat.Service in production, anything else in tests. The identity and
// configuration are the server's, exactly as with the embedded API: the
// service actor creates rooms and acts on membership, and Subscribe reads as
// the actor.
//
// Errors cross as gRPC status codes (see errorFor); Subscribe is a server
// stream over the chat service's subscription channel, so a stream ends
// wherever that channel ends — client cancellation, service close, a store
// error during replay, or a consumer too slow for the server's send queue,
// which the client recovers from by resubscribing from its last seq.
package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	chatv1 "github.com/lioneljmorrison/klacks/api/gen/klacks/chat/v1"
	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// Server is the ChatService adapter over a chat.ChatService.
type Server struct {
	chatv1.UnimplementedChatServiceServer
	chat chat.ChatService
}

var _ chatv1.ChatServiceServer = (*Server)(nil)

// New returns a Server serving chat over gRPC.
func New(chat chat.ChatService) *Server {
	return &Server{chat: chat}
}

// CreateRoom creates a room of the request's kind with the service actor as
// its owner.
func (s *Server) CreateRoom(ctx context.Context, req *chatv1.CreateRoomRequest) (*chatv1.CreateRoomResponse, error) {
	id, err := s.chat.CreateRoom(ctx, chat.RoomSpec{Kind: chat.Kind(req.GetKind())})
	if err != nil {
		return nil, wrap("create room", err)
	}
	return &chatv1.CreateRoomResponse{RoomId: id[:]}, nil
}

// AddMember adds user_id to room_id with role, acting as the service actor.
func (s *Server) AddMember(ctx context.Context, req *chatv1.AddMemberRequest) (*chatv1.AddMemberResponse, error) {
	r, u, err := uuids("add member", req.GetRoomId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.chat.AddMember(ctx, chat.RoomID(r), chat.UserID(u), chat.Role(req.GetRole())); err != nil {
		return nil, wrap("add member", err)
	}
	return &chatv1.AddMemberResponse{}, nil
}

// RemoveMember removes user_id from room_id, acting as the service actor.
func (s *Server) RemoveMember(ctx context.Context, req *chatv1.RemoveMemberRequest) (*chatv1.RemoveMemberResponse, error) {
	r, u, err := uuids("remove member", req.GetRoomId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.chat.RemoveMember(ctx, chat.RoomID(r), chat.UserID(u)); err != nil {
		return nil, wrap("remove member", err)
	}
	return &chatv1.RemoveMemberResponse{}, nil
}

// PostMessage publishes payload to room_id as sender_id and returns its seq.
func (s *Server) PostMessage(ctx context.Context, req *chatv1.PostMessageRequest) (*chatv1.PostMessageResponse, error) {
	r, u, err := uuids("post message", req.GetRoomId(), req.GetSenderId())
	if err != nil {
		return nil, err
	}
	p := req.GetPayload()
	mid, err := uuid("post message", "message_id", p.GetMessageId())
	if err != nil {
		return nil, invalid(err)
	}
	did, err := uuid("post message", "device_id", p.GetDeviceId())
	if err != nil {
		return nil, invalid(err)
	}
	seq, err := s.chat.PostMessage(ctx, chat.RoomID(r), chat.UserID(u), chat.EncryptedPayload{
		MessageID:  mid,
		DeviceID:   did,
		Ciphertext: p.GetCiphertext(),
		Header:     p.GetHeader(),
	})
	if err != nil {
		return nil, wrap("post message", err)
	}
	return &chatv1.PostMessageResponse{Seq: int64(seq)}, nil
}

// Subscribe streams the room's messages above from_seq, in seq order, until
// the subscription ends. The stream's context is the subscription's, so a
// disconnecting client stops its server-side work. A send failure ends the
// stream with that error; the channel ending (slow consumer, service close,
// replay error) ends the stream cleanly, telling the client to resume from
// its last seq.
func (s *Server) Subscribe(req *chatv1.SubscribeRequest, stream grpc.ServerStreamingServer[chatv1.Message]) error {
	r, err := uuid("subscribe", "room_id", req.GetRoomId())
	if err != nil {
		return invalid(err)
	}
	msgs, err := s.chat.Subscribe(stream.Context(), chat.RoomID(r), chat.Seq(req.GetFromSeq()))
	if err != nil {
		return wrap("subscribe", err)
	}
	for m := range msgs {
		if err := stream.Send(toProto(m)); err != nil {
			return err
		}
	}
	return nil
}

// toProto converts a delivered chat message to its wire form.
func toProto(m chat.Message) *chatv1.Message {
	return &chatv1.Message{
		RoomId:     m.RoomID[:],
		Seq:        int64(m.Seq),
		MessageId:  m.MessageID[:],
		SenderId:   m.SenderID[:],
		DeviceId:   m.DeviceID[:],
		Ciphertext: m.Ciphertext,
		Header:     m.Header,
		CreatedAt:  timestamppb.New(m.CreatedAt),
	}
}

// uuid copies b as a 16-byte ID. The protos carry raw 16-byte UUIDs, so any
// other length is an InvalidArgument naming the field.
func uuid(op, field string, b []byte) ([16]byte, error) {
	var id [16]byte
	if len(b) != 16 {
		return id, fmt.Errorf("%s: %s is %d bytes, want 16", op, field, len(b))
	}
	copy(id[:], b)
	return id, nil
}

// uuids copies two 16-byte IDs, room and user, in one error.
func uuids(op string, room, user []byte) ([16]byte, [16]byte, error) {
	r, err := uuid(op, "room_id", room)
	if err != nil {
		return r, [16]byte{}, invalid(err)
	}
	u, err := uuid(op, "user_id", user)
	if err != nil {
		return r, u, invalid(err)
	}
	return r, u, nil
}

// invalid turns a field error into an InvalidArgument status.
func invalid(err error) error {
	return status.Error(codes.InvalidArgument, err.Error())
}
