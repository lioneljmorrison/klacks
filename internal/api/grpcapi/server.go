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

// Device registration and prekey bundles (S-22). RegisterDevice upserts the
// (user_id, device_id) bundle; DeviceBundle fetches it and consumes one of
// its one-time prekeys (S-23).

// RegisterDevice registers or replaces user_id's device bundle.
func (s *Server) RegisterDevice(ctx context.Context, req *chatv1.RegisterDeviceRequest) (*chatv1.RegisterDeviceResponse, error) {
	u, d, err := uuids("register device", req.GetUserId(), req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	bundle, prekeys, err := deviceArgs("register device", req.GetBundle(), req.GetOneTimePrekeys(), true)
	if err != nil {
		return nil, err
	}
	if err := s.chat.RegisterDevice(ctx, chat.UserID(u), chat.DeviceID(d), bundle, prekeys); err != nil {
		return nil, wrap("register device", err)
	}
	return &chatv1.RegisterDeviceResponse{}, nil
}

// AddDevicePrekeys replenishes user_id's device one-time prekeys.
func (s *Server) AddDevicePrekeys(ctx context.Context, req *chatv1.AddDevicePrekeysRequest) (*chatv1.AddDevicePrekeysResponse, error) {
	u, d, err := uuids("add device prekeys", req.GetUserId(), req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	_, prekeys, err := deviceArgs("add device prekeys", nil, req.GetOneTimePrekeys(), false)
	if err != nil {
		return nil, err
	}
	if err := s.chat.AddDevicePrekeys(ctx, chat.UserID(u), chat.DeviceID(d), prekeys); err != nil {
		return nil, wrap("add device prekeys", err)
	}
	return &chatv1.AddDevicePrekeysResponse{}, nil
}

// DeviceBundle fetches user_id's device bundle, consuming one of its
// one-time prekeys.
func (s *Server) DeviceBundle(ctx context.Context, req *chatv1.DeviceBundleRequest) (*chatv1.DeviceBundleResponse, error) {
	u, d, err := uuids("device bundle", req.GetUserId(), req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	b, taken, err := s.chat.DeviceBundle(ctx, chat.UserID(u), chat.DeviceID(d))
	if err != nil {
		return nil, wrap("device bundle", err)
	}
	resp := &chatv1.DeviceBundleResponse{
		Bundle: &chatv1.PrekeyBundle{
			IdentityKey:           b.IdentityKey,
			IdentityDhKey:         b.IdentityDHKey,
			SignedPrekeyId:        b.SignedPrekeyID,
			SignedPrekey:          b.SignedPrekey,
			SignedPrekeySignature: b.SignedPrekeySignature,
		},
		Remaining: int32(taken.Remaining),
	}
	if taken.ID != 0 {
		resp.OneTimePrekey = &chatv1.Prekey{Id: taken.ID, Key: taken.Key}
	}
	return resp, nil
}

// ListDevices lists user_id's registered devices.
func (s *Server) ListDevices(ctx context.Context, req *chatv1.ListDevicesRequest) (*chatv1.ListDevicesResponse, error) {
	u, err := uuid("list devices", "user_id", req.GetUserId())
	if err != nil {
		return nil, invalid(err)
	}
	devs, err := s.chat.ListDevices(ctx, chat.UserID(u))
	if err != nil {
		return nil, wrap("list devices", err)
	}
	out := make([]*chatv1.Device, 0, len(devs))
	for _, d := range devs {
		info := &chatv1.Device{DeviceId: d.DeviceID[:]}
		if d.LastSeen != nil {
			info.LastSeenAt = timestamppb.New(*d.LastSeen)
		}
		out = append(out, info)
	}
	return &chatv1.ListDevicesResponse{Devices: out}, nil
}

// deviceArgs converts proto bundle and prekeys to the chat API's shapes,
// validating the 32/64-byte key sizes via the service. withBundle validates
// the bundle too (registration, not replenishment).
func deviceArgs(op string, b *chatv1.PrekeyBundle, prekeys []*chatv1.Prekey, withBundle bool) (chat.PrekeyBundle, []chat.Prekey, error) {
	var bundle chat.PrekeyBundle
	if withBundle {
		if b == nil {
			return chat.PrekeyBundle{}, nil, invalid(fmt.Errorf("%s: bundle is required", op))
		}
		bundle = chat.PrekeyBundle{
			IdentityKey:           b.GetIdentityKey(),
			IdentityDHKey:         b.GetIdentityDhKey(),
			SignedPrekeyID:        b.GetSignedPrekeyId(),
			SignedPrekey:          b.GetSignedPrekey(),
			SignedPrekeySignature: b.GetSignedPrekeySignature(),
		}
	}
	out := make([]chat.Prekey, len(prekeys))
	for i, p := range prekeys {
		out[i] = chat.Prekey{ID: p.GetId(), Key: p.GetKey()}
	}
	return bundle, out, nil
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
