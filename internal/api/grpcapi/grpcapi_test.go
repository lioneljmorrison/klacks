package grpcapi_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	chatv1 "github.com/lioneljmorrison/klacks/api/gen/klacks/chat/v1"
	"github.com/lioneljmorrison/klacks/internal/api/grpcapi"
	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// The adapter over a fake chat.ChatService: request and response conversion,
// and pkg/chat's error distinctions carried into gRPC status codes.

var (
	room   = chat.RoomID{15: 0x01}
	user   = chat.UserID{15: 0x02}
	sender = chat.UserID{15: 0x03}
)

// fakeChat records what the adapter calls it with and answers from the
// fields the test sets.
type fakeChat struct {
	createSpec   chat.RoomSpec
	addRoom      chat.RoomID
	addUser      chat.UserID
	addRole      chat.Role
	removeRoom   chat.RoomID
	removeUser   chat.UserID
	postRoom     chat.RoomID
	postSender   chat.UserID
	postPayload  chat.EncryptedPayload
	subRoom      chat.RoomID
	subFromSeq   chat.Seq
	subCtxCancel bool

	createErr  error
	addErr     error
	removeErr  error
	postErr    error
	postSeq    chat.Seq
	subErr     error
	subCh      chan chat.Message
	subDiscard bool

	// Device registration and prekey bundles (S-22).
	regUser          chat.UserID
	regDevice        chat.DeviceID
	regBundle        chat.PrekeyBundle
	regPrekeys       []chat.Prekey
	regErr           error
	addPrekeysUser   chat.UserID
	addPrekeysDevice chat.DeviceID
	addPrekeys       []chat.Prekey
	bundleUser       chat.UserID
	bundleDevice     chat.DeviceID
	bundleOut        chat.PrekeyBundle
	takenOut         chat.ConsumedPrekey
	bundleErr        error
	listUser         chat.UserID
	listOut          []chat.DeviceInfo
	listErr          error
}

var _ chat.ChatService = (*fakeChat)(nil)

func (f *fakeChat) CreateRoom(_ context.Context, spec chat.RoomSpec) (chat.RoomID, error) {
	f.createSpec = spec
	if f.createErr != nil {
		return chat.RoomID{}, f.createErr
	}
	return room, nil
}

func (f *fakeChat) AddMember(_ context.Context, r chat.RoomID, u chat.UserID, role chat.Role) error {
	f.addRoom, f.addUser, f.addRole = r, u, role
	return f.addErr
}

func (f *fakeChat) RemoveMember(_ context.Context, r chat.RoomID, u chat.UserID) error {
	f.removeRoom, f.removeUser = r, u
	return f.removeErr
}

func (f *fakeChat) PostMessage(_ context.Context, r chat.RoomID, s chat.UserID, p chat.EncryptedPayload) (chat.Seq, error) {
	f.postRoom, f.postSender, f.postPayload = r, s, p
	if f.postErr != nil {
		return 0, f.postErr
	}
	return f.postSeq, nil
}

func (f *fakeChat) Subscribe(ctx context.Context, r chat.RoomID, from chat.Seq) (<-chan chat.Message, error) {
	f.subRoom, f.subFromSeq = r, from
	select {
	case <-ctx.Done():
		f.subCtxCancel = true
		return nil, f.subErr
	default:
	}
	if f.subErr != nil {
		return nil, f.subErr
	}
	if f.subDiscard {
		return nil, nil
	}
	return f.subCh, nil
}

// Device methods: the fake records calls and answers with the registered
// bundle, so the adapter tests can check conversion in both directions.

var (
	regDevice = chat.DeviceID{14: 0x22}
)

func (f *fakeChat) RegisterDevice(_ context.Context, u chat.UserID, d chat.DeviceID, b chat.PrekeyBundle, prekeys []chat.Prekey) error {
	f.regUser, f.regDevice, f.regBundle, f.regPrekeys = u, d, b, prekeys
	return f.regErr
}

func (f *fakeChat) DeviceBundle(_ context.Context, u chat.UserID, d chat.DeviceID) (chat.PrekeyBundle, chat.ConsumedPrekey, error) {
	f.bundleUser, f.bundleDevice = u, d
	if f.bundleErr != nil {
		return chat.PrekeyBundle{}, chat.ConsumedPrekey{}, f.bundleErr
	}
	return f.bundleOut, f.takenOut, nil
}

func (f *fakeChat) AddDevicePrekeys(_ context.Context, u chat.UserID, d chat.DeviceID, prekeys []chat.Prekey) error {
	f.addPrekeysUser, f.addPrekeysDevice, f.addPrekeys = u, d, prekeys
	return f.regErr
}

func (f *fakeChat) ListDevices(_ context.Context, u chat.UserID) ([]chat.DeviceInfo, error) {
	f.listUser = u
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listOut, nil
}

// fakeStream is the server stream Subscribe writes to. The embedded
// grpc.ServerStream is never used; Context and Send are overridden.
type fakeStream struct {
	grpc.ServerStream
	ctx     context.Context
	sent    []*chatv1.Message
	sendErr error
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func (f *fakeStream) Send(m *chatv1.Message) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, m)
	return nil
}

func b16(last byte) []byte { return append(make([]byte, 15), last) }

// dev is a 16-byte device ID with 0x22 at index 14.
func dev() []byte {
	b := make([]byte, 16)
	b[14] = 0x22
	return b
}

// happyChat is a fake with all errors unset and one message to stream.
func happyChat() (*fakeChat, func()) {
	f := &fakeChat{postSeq: 7, subCh: make(chan chat.Message, 2)}
	f.subCh <- chat.Message{
		RoomID:     room,
		Seq:        3,
		MessageID:  [16]byte{15: 0x11},
		SenderID:   sender,
		DeviceID:   [16]byte{14: 0x22},
		Ciphertext: []byte("cipher"),
		Header:     []byte("header"),
		CreatedAt:  time.Date(2026, 11, 13, 8, 30, 0, 0, time.UTC),
	}
	close(f.subCh)
	return f, func() {}
}

func code(t *testing.T, err error) codes.Code {
	t.Helper()
	return status.Code(err)
}

func TestCreateRoom(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	res, err := s.CreateRoom(context.Background(), &chatv1.CreateRoomRequest{Kind: "group"})
	if err != nil {
		t.Fatal(err)
	}
	if f.createSpec != (chat.RoomSpec{Kind: chat.KindGroup}) {
		t.Errorf("fake got spec %+v, want {group}", f.createSpec)
	}
	if string(res.RoomId) != string(b16(0x01)) {
		t.Errorf("room_id = %x, want %x", res.RoomId, b16(0x01))
	}
}

func TestAddMember(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	if _, err := s.AddMember(context.Background(), &chatv1.AddMemberRequest{
		RoomId: b16(0x01), UserId: b16(0x02), Role: "member",
	}); err != nil {
		t.Fatal(err)
	}
	if f.addRoom != room || f.addUser != user || f.addRole != chat.RoleMember {
		t.Errorf("fake got room %x user %x role %s", f.addRoom, f.addUser, f.addRole)
	}
}

func TestRemoveMember(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	if _, err := s.RemoveMember(context.Background(), &chatv1.RemoveMemberRequest{
		RoomId: b16(0x01), UserId: b16(0x02),
	}); err != nil {
		t.Fatal(err)
	}
	if f.removeRoom != room || f.removeUser != user {
		t.Errorf("fake got room %x user %x", f.removeRoom, f.removeUser)
	}
}

func TestPostMessage(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	res, err := s.PostMessage(context.Background(), &chatv1.PostMessageRequest{
		RoomId:   b16(0x01),
		SenderId: b16(0x03),
		Payload: &chatv1.EncryptedPayload{
			MessageId:  b16(0x11),
			DeviceId:   dev(),
			Ciphertext: []byte("cipher"),
			Header:     []byte("header"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.postRoom != room || f.postSender != sender {
		t.Errorf("fake got room %x sender %x", f.postRoom, f.postSender)
	}
	want := chat.EncryptedPayload{
		MessageID:  [16]byte{15: 0x11},
		DeviceID:   [16]byte{14: 0x22},
		Ciphertext: []byte("cipher"),
		Header:     []byte("header"),
	}
	if f.postPayload.MessageID != want.MessageID || f.postPayload.DeviceID != want.DeviceID ||
		string(f.postPayload.Ciphertext) != string(want.Ciphertext) || string(f.postPayload.Header) != string(want.Header) {
		t.Errorf("fake got payload %+v, want %+v", f.postPayload, want)
	}
	if res.Seq != 7 {
		t.Errorf("seq = %d, want 7", res.Seq)
	}
}

// TestErrorMapping checks that pkg/chat's error distinctions survive the
// adapter as gRPC codes, per operation.
func TestErrorMapping(t *testing.T) {
	sentinel := map[string]error{
		"invalid":   chat.ErrInvalidArgument,
		"room404":   chat.ErrRoomNotFound,
		"member404": chat.ErrMemberNotFound,
		"already":   chat.ErrAlreadyMember,
		"notmem":    chat.ErrNotMember,
		"forbid":    chat.ErrForbidden,
		"payload":   chat.ErrPayloadTooLarge,
		"closed":    chat.ErrClosed,
		"other":     errors.New("boom"),
	}
	wantCode := map[string]codes.Code{
		"invalid":   codes.InvalidArgument,
		"room404":   codes.NotFound,
		"member404": codes.NotFound,
		"already":   codes.AlreadyExists,
		"notmem":    codes.FailedPrecondition,
		"forbid":    codes.PermissionDenied,
		"payload":   codes.InvalidArgument,
		"closed":    codes.Unavailable,
		"other":     codes.Internal,
	}

	for name, err := range sentinel {
		t.Run(name, func(t *testing.T) {
			cf := &fakeChat{createErr: err}
			if _, e := grpcapi.New(cf).CreateRoom(context.Background(), &chatv1.CreateRoomRequest{Kind: "dm"}); code(t, e) != wantCode[name] {
				t.Errorf("create room: code = %s, want %s", code(t, e), wantCode[name])
			}
			af := &fakeChat{addErr: err}
			if _, e := grpcapi.New(af).AddMember(context.Background(), &chatv1.AddMemberRequest{RoomId: b16(1), UserId: b16(2)}); code(t, e) != wantCode[name] {
				t.Errorf("add member: code = %s, want %s", code(t, e), wantCode[name])
			}
			rf := &fakeChat{removeErr: err}
			if _, e := grpcapi.New(rf).RemoveMember(context.Background(), &chatv1.RemoveMemberRequest{RoomId: b16(1), UserId: b16(2)}); code(t, e) != wantCode[name] {
				t.Errorf("remove member: code = %s, want %s", code(t, e), wantCode[name])
			}
			pf := &fakeChat{postErr: err}
			req := &chatv1.PostMessageRequest{RoomId: b16(1), SenderId: b16(2), Payload: &chatv1.EncryptedPayload{MessageId: b16(0x11), DeviceId: dev()}}
			if _, e := grpcapi.New(pf).PostMessage(context.Background(), req); code(t, e) != wantCode[name] {
				t.Errorf("post message: code = %s, want %s", code(t, e), wantCode[name])
			}
			sf := &fakeChat{subErr: err}
			st := &fakeStream{ctx: context.Background()}
			if e := grpcapi.New(sf).Subscribe(&chatv1.SubscribeRequest{RoomId: b16(1)}, st); code(t, e) != wantCode[name] {
				t.Errorf("subscribe: code = %s, want %s", code(t, e), wantCode[name])
			}
		})
	}
}

// TestBadUUID checks that a room or user ID that is not 16 bytes is rejected
// as InvalidArgument before it reaches the chat service.
func TestBadUUID(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	ctx := context.Background()

	if _, err := s.CreateRoom(ctx, &chatv1.CreateRoomRequest{Kind: "dm"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"add room", func() error {
			_, err := s.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: []byte("short"), UserId: b16(2)})
			return err
		}},
		{"add user", func() error {
			_, err := s.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: b16(1), UserId: []byte("short")})
			return err
		}},
		{"remove room", func() error {
			_, err := s.RemoveMember(ctx, &chatv1.RemoveMemberRequest{RoomId: nil, UserId: b16(2)})
			return err
		}},
		{"post room", func() error {
			_, err := s.PostMessage(ctx, &chatv1.PostMessageRequest{SenderId: b16(3)})
			return err
		}},
		{"post message_id", func() error {
			_, err := s.PostMessage(ctx, &chatv1.PostMessageRequest{RoomId: b16(1), SenderId: b16(3), Payload: &chatv1.EncryptedPayload{MessageId: []byte("short")}})
			return err
		}},
		{"subscribe room", func() error {
			return s.Subscribe(&chatv1.SubscribeRequest{RoomId: []byte("short")}, &fakeStream{ctx: ctx})
		}},
	} {
		if err := tc.call(); code(t, err) != codes.InvalidArgument {
			t.Errorf("%s: code = %s (%v), want InvalidArgument", tc.name, code(t, err), err)
		}
	}
	// The fake saw nothing: every call failed on conversion.
	if f.addUser != (chat.UserID{}) || f.postSender != (chat.UserID{}) {
		t.Errorf("fake was called with a bad UUID: %+v", f)
	}
}

func TestSubscribe(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	st := &fakeStream{ctx: context.Background()}
	if err := s.Subscribe(&chatv1.SubscribeRequest{RoomId: b16(0x01), FromSeq: 4}, st); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if f.subRoom != room || f.subFromSeq != 4 {
		t.Errorf("fake got room %x from_seq %d", f.subRoom, f.subFromSeq)
	}
	if len(st.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(st.sent))
	}
	want := &chatv1.Message{
		RoomId:     b16(0x01),
		Seq:        3,
		MessageId:  b16(0x11),
		SenderId:   b16(0x03),
		DeviceId:   dev(),
		Ciphertext: []byte("cipher"),
		Header:     []byte("header"),
		CreatedAt:  timestamppb.New(time.Date(2026, 11, 13, 8, 30, 0, 0, time.UTC)),
	}
	if st.sent[0].String() != want.String() {
		t.Errorf("sent message:\n%s\nwant:\n%s", st.sent[0].String(), want.String())
	}
}

// TestSubscribeSendError checks that a failing Send ends the stream with the
// send's error rather than the range silently swallowing it.
func TestSubscribeSendError(t *testing.T) {
	f, _ := happyChat()
	sendErr := errors.New("send failed")
	st := &fakeStream{ctx: context.Background(), sendErr: sendErr}
	if err := grpcapi.New(f).Subscribe(&chatv1.SubscribeRequest{RoomId: b16(0x01)}, st); !errors.Is(err, sendErr) {
		t.Errorf("subscribe err = %v, want the send error", err)
	}
}

// TestSubscribeStreamContext checks that the stream's context is what the
// subscription runs under, so a disconnecting client ends its subscription.
func TestSubscribeStreamContext(t *testing.T) {
	f := &fakeChat{subDiscard: true, subErr: io.EOF}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := &fakeStream{ctx: ctx}
	_ = grpcapi.New(f).Subscribe(&chatv1.SubscribeRequest{RoomId: b16(0x01)}, st)
	if !f.subCtxCancel {
		t.Error("the subscription context was not the canceled stream context")
	}
}

// deviceBundle is a valid-shaped proto bundle.
func deviceBundle() *chatv1.PrekeyBundle {
	return &chatv1.PrekeyBundle{
		IdentityKey:           make([]byte, 32),
		IdentityDhKey:         make([]byte, 32),
		SignedPrekeyId:        3,
		SignedPrekey:          make([]byte, 32),
		SignedPrekeySignature: make([]byte, 64),
	}
}

// TestDeviceRPCs checks request and response conversion for the device
// registration and prekey endpoints.
func TestDeviceRPCs(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	ctx := context.Background()

	if _, err := s.RegisterDevice(ctx, &chatv1.RegisterDeviceRequest{
		UserId: b16(0x02), DeviceId: dev(),
		Bundle:         deviceBundle(),
		OneTimePrekeys: []*chatv1.Prekey{{Id: 1, Key: make([]byte, 32)}},
	}); err != nil {
		t.Fatal(err)
	}
	if f.regUser != user || f.regDevice != (chat.DeviceID{14: 0x22}) {
		t.Errorf("fake got user %x device %x", f.regUser, f.regDevice)
	}
	if f.regBundle.SignedPrekeyID != 3 || len(f.regBundle.IdentityKey) != 32 || len(f.regBundle.SignedPrekeySignature) != 64 {
		t.Errorf("fake got bundle %+v", f.regBundle)
	}
	if len(f.regPrekeys) != 1 || f.regPrekeys[0].ID != 1 {
		t.Errorf("fake got prekeys %+v", f.regPrekeys)
	}

	if _, err := s.DeviceBundle(ctx, &chatv1.DeviceBundleRequest{UserId: b16(0x02), DeviceId: dev()}); err != nil {
		t.Fatal(err)
	}
	if f.bundleUser != user || f.bundleDevice != (chat.DeviceID{14: 0x22}) {
		t.Errorf("fake got user %x device %x", f.bundleUser, f.bundleDevice)
	}

	f.bundleOut = chat.PrekeyBundle{IdentityKey: make([]byte, 32), SignedPrekeyID: 9, SignedPrekey: make([]byte, 32)}
	f.takenOut = chat.ConsumedPrekey{ID: 4, Key: make([]byte, 32), Remaining: 2}
	res, err := s.DeviceBundle(ctx, &chatv1.DeviceBundleRequest{UserId: b16(0x02), DeviceId: dev()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bundle.SignedPrekeyId != 9 || res.OneTimePrekey.Id != 4 || res.Remaining != 2 {
		t.Errorf("bundle response = %+v, want prekey 4, remaining 2", res)
	}

	f.takenOut = chat.ConsumedPrekey{} // exhausted: no one-time prekey
	res, err = s.DeviceBundle(ctx, &chatv1.DeviceBundleRequest{UserId: b16(0x02), DeviceId: dev()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OneTimePrekey != nil {
		t.Errorf("exhausted fetch still carries a prekey: %+v", res)
	}

	if _, err := s.AddDevicePrekeys(ctx, &chatv1.AddDevicePrekeysRequest{
		UserId: b16(0x02), DeviceId: dev(),
		OneTimePrekeys: []*chatv1.Prekey{{Id: 5, Key: make([]byte, 32)}, {Id: 6, Key: make([]byte, 32)}},
	}); err != nil {
		t.Fatal(err)
	}
	if f.addPrekeysDevice != (chat.DeviceID{14: 0x22}) || len(f.addPrekeys) != 2 || f.addPrekeys[1].ID != 6 {
		t.Errorf("fake got replenish device %x prekeys %+v", f.addPrekeysDevice, f.addPrekeys)
	}

	f.listOut = []chat.DeviceInfo{{UserID: user, DeviceID: regDevice}}
	res2, err := s.ListDevices(ctx, &chatv1.ListDevicesRequest{UserId: b16(0x02)})
	if err != nil {
		t.Fatal(err)
	}
	if f.listUser != user || len(res2.Devices) != 1 || string(res2.Devices[0].DeviceId) != string(dev()) {
		t.Errorf("list response = %+v fake got user %x", res2, f.listUser)
	}
}

// TestDeviceRPCValidation checks the bundle-free registration path and that
// a missing bundle is InvalidArgument before reaching the service.
func TestDeviceRPCValidation(t *testing.T) {
	f, _ := happyChat()
	s := grpcapi.New(f)
	ctx := context.Background()

	if _, err := s.RegisterDevice(ctx, &chatv1.RegisterDeviceRequest{UserId: b16(2), DeviceId: dev()}); code(t, err) != codes.InvalidArgument {
		t.Errorf("missing bundle: code = %s (%v), want InvalidArgument", code(t, err), err)
	}
	if f.regUser != (chat.UserID{}) {
		t.Errorf("fake was called with a missing bundle")
	}
}
