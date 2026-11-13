//go:build integration

package grpcapi_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	chatv1 "github.com/lioneljmorrison/klacks/api/gen/klacks/chat/v1"
	"github.com/lioneljmorrison/klacks/internal/api/grpcapi"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// The adapter against a real chat.Service on a fresh migrated stack, over an
// in-memory gRPC connection: the wire format, status codes and stream
// behavior a cross-process client would see.

var (
	actor = chat.UserID{15: 0xa1}
	alice = chat.UserID{15: 0xb2}
)

// gpayload builds a distinct encrypted payload for seq n.
func gpayload(n int) chat.EncryptedPayload {
	return chat.EncryptedPayload{
		MessageID:  [16]byte{15: byte(n)},
		DeviceID:   [16]byte{14: 0xdd},
		Ciphertext: []byte{byte(n)},
		Header:     []byte("header"),
	}
}

// setup serves a chat.Service over bufconn and returns a client for it.
func setup(t *testing.T) (chatv1.ChatServiceClient, *chat.Service) {
	t.Helper()
	cfg := chat.Config{
		PostgresDSN:     dbtest.MigratedPostgresDSN(t),
		ScyllaTimeout:   10 * time.Second,
		RoomLockTimeout: 20 * time.Second,
		Actor:           actor,
	}
	sc := dbtest.MigratedScyllaConfig(t)
	cfg.ScyllaHosts = sc.Hosts
	cfg.ScyllaKeyspace = sc.Keyspace
	cfg.ScyllaUsername = sc.Username
	cfg.ScyllaPassword = sc.Password
	svc, err := chat.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	chatv1.RegisterChatServiceServer(gs, grpcapi.New(svc))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return chatv1.NewChatServiceClient(conn), svc
}

// memberRoom creates a group room with alice as a member.
func memberRoom(t *testing.T, c chatv1.ChatServiceClient) []byte {
	t.Helper()
	ctx := context.Background()
	res, err := c.CreateRoom(ctx, &chatv1.CreateRoomRequest{Kind: "group"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: res.RoomId, UserId: alice[:], Role: "member"}); err != nil {
		t.Fatal(err)
	}
	return res.RoomId
}

// code reports the status code of a client error.
func stcode(err error) codes.Code { return status.Code(err) }

// post sends payload n as sender to room and returns its seq.
func post(t *testing.T, c chatv1.ChatServiceClient, room []byte, sender chat.UserID, n int) int64 {
	t.Helper()
	p := gpayload(n)
	res, err := c.PostMessage(context.Background(), &chatv1.PostMessageRequest{
		RoomId:   room,
		SenderId: sender[:],
		Payload: &chatv1.EncryptedPayload{
			MessageId:  p.MessageID[:],
			DeviceId:   p.DeviceID[:],
			Ciphertext: p.Ciphertext,
			Header:     p.Header,
		},
	})
	if err != nil {
		t.Fatalf("post %d: %v", n, err)
	}
	return res.Seq
}

// collect reads exactly n messages from the stream.
func collect(t *testing.T, stream chatv1.ChatService_SubscribeClient, n int) []*chatv1.Message {
	t.Helper()
	got := make([]*chatv1.Message, 0, n)
	for len(got) < n {
		m, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv after %d of %d messages: %v", len(got), n, err)
		}
		got = append(got, m)
	}
	return got
}

// TestClientLifecycle walks a room through the client the way an embedder
// would: create, member, posts (with the errors that come back as codes),
// removal.
func TestClientLifecycle(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()

	res, err := c.CreateRoom(ctx, &chatv1.CreateRoomRequest{Kind: "group"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RoomId) != 16 {
		t.Fatalf("room_id is %d bytes, want 16", len(res.RoomId))
	}
	room := res.RoomId
	if _, err := c.CreateRoom(ctx, &chatv1.CreateRoomRequest{Kind: "channel"}); stcode(err) != codes.InvalidArgument {
		t.Errorf("unknown kind: code = %s (%v), want InvalidArgument", stcode(err), err)
	}

	if _, err := c.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: room, UserId: alice[:], Role: "member"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: room, UserId: alice[:], Role: "admin"}); stcode(err) != codes.AlreadyExists {
		t.Errorf("re-add: code = %s (%v), want AlreadyExists", stcode(err), err)
	}
	if _, err := c.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: room, UserId: alice[:], Role: "boss"}); stcode(err) != codes.InvalidArgument {
		t.Errorf("unknown role: code = %s (%v), want InvalidArgument", stcode(err), err)
	}

	for n := 1; n <= 3; n++ {
		if seq := post(t, c, room, alice, n); seq != int64(n) {
			t.Fatalf("post %d: seq = %d, want %d", n, seq, n)
		}
	}
	out := gpayload(9)
	uid := chat.UserID{15: 0xee}
	if _, err := c.PostMessage(ctx, &chatv1.PostMessageRequest{RoomId: room, SenderId: uid[:], Payload: &chatv1.EncryptedPayload{MessageId: out.MessageID[:], DeviceId: out.DeviceID[:], Ciphertext: out.Ciphertext, Header: out.Header}}); stcode(err) != codes.FailedPrecondition {
		t.Errorf("outsider post: code = %s (%v), want FailedPrecondition", stcode(err), err)
	}
	big := &chatv1.EncryptedPayload{MessageId: b16(0x42), DeviceId: b16(0x43), Ciphertext: make([]byte, chat.MaxPayloadSize+1)}
	if _, err := c.PostMessage(ctx, &chatv1.PostMessageRequest{RoomId: room, SenderId: alice[:], Payload: big}); stcode(err) != codes.InvalidArgument {
		t.Errorf("oversized payload: code = %s (%v), want InvalidArgument", stcode(err), err)
	}

	if _, err := c.RemoveMember(ctx, &chatv1.RemoveMemberRequest{RoomId: room, UserId: alice[:]}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveMember(ctx, &chatv1.RemoveMemberRequest{RoomId: room, UserId: alice[:]}); stcode(err) != codes.NotFound {
		t.Errorf("remove twice: code = %s (%v), want NotFound", stcode(err), err)
	}
	if _, err := c.RemoveMember(ctx, &chatv1.RemoveMemberRequest{RoomId: b16(0xee), UserId: alice[:]}); stcode(err) != codes.NotFound {
		t.Errorf("missing room: code = %s (%v), want NotFound", stcode(err), err)
	}
}

// subErr subscribes and returns the first status code: at the call or on
// the first Recv, whichever carries it.
func subErr(t *testing.T, c chatv1.ChatServiceClient, ctx context.Context, req *chatv1.SubscribeRequest) codes.Code {
	t.Helper()
	stream, err := c.Subscribe(ctx, req)
	if err != nil {
		return stcode(err)
	}
	_, err = stream.Recv()
	return stcode(err)
}

// TestClientSubscribeStream checks the wire behavior of Subscribe: full
// replay, live continuation, clean end on cancel, resume from a seq, and the
// subscription errors as codes.
func TestClientSubscribeStream(t *testing.T) {
	c, _ := setup(t)
	ctx := context.Background()
	room := memberRoom(t, c)
	for n := 1; n <= 3; n++ {
		post(t, c, room, alice, n)
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.Subscribe(sctx, &chatv1.SubscribeRequest{RoomId: room})
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, stream, 3)
	for i, m := range got {
		p := gpayload(i + 1)
		if m.Seq != int64(i+1) || !bytes.Equal(m.RoomId, room) || !bytes.Equal(m.SenderId, alice[:]) ||
			!bytes.Equal(m.MessageId, p.MessageID[:]) || !bytes.Equal(m.DeviceId, p.DeviceID[:]) ||
			!bytes.Equal(m.Ciphertext, p.Ciphertext) || !bytes.Equal(m.Header, p.Header) ||
			m.CreatedAt == nil {
			t.Errorf("message %d = %+v, want seq %d from alice with payload %d", i, m, i+1, i+1)
		}
	}

	for n := 4; n <= 5; n++ {
		post(t, c, room, alice, n)
	}
	for i, m := range collect(t, stream, 2) {
		if m.Seq != int64(i+4) {
			t.Errorf("live message %d = seq %d, want %d", i, m.Seq, i+4)
		}
	}
	cancel()
	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) && stcode(err) != codes.Canceled {
		t.Errorf("recv after cancel: %v, want EOF or Canceled", err)
	}

	rstream, err := c.Subscribe(ctx, &chatv1.SubscribeRequest{RoomId: room, FromSeq: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range collect(t, rstream, 2) {
		if m.Seq != int64(i+4) {
			t.Errorf("resumed message %d = seq %d, want %d", i, m.Seq, i+4)
		}
	}

	// The actor is not a member of this room.
	dm, err := c.CreateRoom(ctx, &chatv1.CreateRoomRequest{Kind: "dm"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveMember(ctx, &chatv1.RemoveMemberRequest{RoomId: dm.RoomId, UserId: actor[:]}); err != nil {
		t.Fatal(err)
	}
	if got := subErr(t, c, ctx, &chatv1.SubscribeRequest{RoomId: dm.RoomId}); got != codes.FailedPrecondition {
		t.Errorf("non-member subscribe: code = %s, want FailedPrecondition", got)
	}
	if got := subErr(t, c, ctx, &chatv1.SubscribeRequest{RoomId: b16(0xee)}); got != codes.NotFound {
		t.Errorf("missing room: code = %s, want NotFound", got)
	}
	if got := subErr(t, c, ctx, &chatv1.SubscribeRequest{RoomId: room, FromSeq: -1}); got != codes.InvalidArgument {
		t.Errorf("negative from_seq: code = %s, want InvalidArgument", got)
	}
	if got := subErr(t, c, ctx, &chatv1.SubscribeRequest{RoomId: []byte("short")}); got != codes.InvalidArgument {
		t.Errorf("short room_id: code = %s, want InvalidArgument", got)
	}
}
