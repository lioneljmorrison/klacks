//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	chatv1 "github.com/lioneljmorrison/klacks/api/gen/klacks/chat/v1"
	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

// S-45: klacks serve runs the gRPC API next to /ws over one core, so the two
// transports see each other's messages live and a removal through gRPC
// reaches the WebSocket hub.

const (
	svcToken = "s45-service-token"
	actorStr = "a0000000-0000-4000-8000-0000000000a1"
	wsUser   = "a0000000-0000-4000-8000-0000000000b2"
	wsDevice = "d0000000-0000-4000-8000-0000000000b2"
)

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}

func (bearer) RequireTransportSecurity() bool { return false }

type stack struct {
	httpBase string
	grpcAddr string
	cancel   context.CancelFunc
	done     chan error
}

func startStack(t *testing.T) *stack {
	t.Helper()
	pool := dbtest.MigratedPostgres(t)
	scylla := dbtest.MigratedScylla(t)
	cfg := config.Default()
	cfg.Env = config.EnvDev
	cfg.HTTP.ShutdownTimeout = config.Duration(5 * time.Second)
	cfg.GRPC = config.GRPC{Addr: "127.0.0.1:0", ServiceTokens: []string{svcToken}, Actor: actorStr}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := newServers(cfg, pool, scylla, log)
	if err != nil {
		t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &stack{
		httpBase: "http://" + httpLn.Addr().String(),
		grpcAddr: grpcLn.Addr().String(),
		cancel:   cancel,
		done:     make(chan error, 1),
	}
	go func() { st.done <- s.serve(ctx, httpLn, grpcLn) }()
	t.Cleanup(func() { st.stop(t) })
	return st
}

// stop shuts the servers down and fails if that takes too long.
func (st *stack) stop(t *testing.T) {
	t.Helper()
	st.cancel()
	select {
	case err := <-st.done:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
		st.done <- nil // later stops return at once
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func grpcClient(t *testing.T, addr, token string) chatv1.ChatServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(bearer(token)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return chatv1.NewChatServiceClient(conn)
}

func mustParse(t *testing.T, s string) protocol.UUID {
	t.Helper()
	var u protocol.UUID
	if err := u.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	return u
}

// wsConn is a dev-stub WebSocket client speaking raw frames.
type wsConn struct {
	t *testing.T
	c *websocket.Conn
}

func dialWS(t *testing.T, base string) *wsConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	h := http.Header{"X-Klacks-User": {wsUser}, "X-Klacks-Device": {wsDevice}}
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/ws", &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return &wsConn{t: t, c: c}
}

func (w *wsConn) send(f protocol.Frame) {
	w.t.Helper()
	b, err := protocol.Encode(f)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.c.Write(w.t.Context(), websocket.MessageText, b); err != nil {
		w.t.Fatal(err)
	}
}

// next returns the next server frame of type typ decoded into a new T,
// skipping other types and failing on an error frame.
func next[T any](w *wsConn, typ protocol.Type) *T {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.t.Context(), 10*time.Second)
	defer cancel()
	for {
		_, b, err := w.c.Read(ctx)
		if err != nil {
			w.t.Fatalf("read: %v", err)
		}
		var env protocol.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			w.t.Fatal(err)
		}
		if env.Type == protocol.TypeError {
			w.t.Fatalf("error frame: %s", b)
		}
		if env.Type != typ {
			continue
		}
		v := new(T)
		if err := json.Unmarshal(b, v); err != nil {
			w.t.Fatal(err)
		}
		return v
	}
}

func TestServeGRPCSharesCoreWithWS(t *testing.T) {
	st := startStack(t)
	ctx := t.Context()
	g := grpcClient(t, st.grpcAddr, svcToken)

	created, err := g.CreateRoom(ctx, &chatv1.CreateRoomRequest{Kind: "group"})
	if err != nil {
		t.Fatal(err)
	}
	room := created.GetRoomId()
	user := mustParse(t, wsUser)
	if _, err := g.AddMember(ctx, &chatv1.AddMemberRequest{RoomId: room, UserId: user[:], Role: "member"}); err != nil {
		t.Fatal(err)
	}

	ws := dialWS(t, st.httpBase)
	ws.send(&protocol.Resume{RoomID: protocol.UUID(room), LastSeenSeq: 0})
	next[protocol.Members](ws, protocol.TypeMembers)

	// gRPC Subscribe as the actor, open before anything is posted.
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	stream, err := g.Subscribe(subCtx, &chatv1.SubscribeRequest{RoomId: room})
	if err != nil {
		t.Fatal(err)
	}

	// gRPC → WebSocket, live.
	actor := mustParse(t, actorStr)
	if _, err := g.PostMessage(ctx, &chatv1.PostMessageRequest{
		RoomId: room, SenderId: actor[:],
		Payload: &chatv1.EncryptedPayload{MessageId: bytes16(1), DeviceId: bytes16(0xdd), Ciphertext: []byte("from grpc")},
	}); err != nil {
		t.Fatal(err)
	}
	if d := next[protocol.Deliver](ws, protocol.TypeDeliver); d.Seq != 1 || string(d.Ciphertext) != "from grpc" {
		t.Fatalf("ws got seq %d %q; want 1 \"from grpc\"", d.Seq, d.Ciphertext)
	}

	// WebSocket → gRPC Subscribe, live.
	ws.send(&protocol.Publish{RoomID: protocol.UUID(room), MessageID: protocol.UUID(bytes16(2)),
		DeviceID: mustParse(t, wsDevice), Ciphertext: []byte("from ws")})
	for _, want := range []string{"from grpc", "from ws"} {
		m, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if string(m.GetCiphertext()) != want {
			t.Fatalf("grpc stream got %q; want %q", m.GetCiphertext(), want)
		}
	}

	// A gRPC removal reaches the WebSocket hub: the subscribers are told.
	if _, err := g.RemoveMember(ctx, &chatv1.RemoveMemberRequest{RoomId: room, UserId: user[:]}); err != nil {
		t.Fatal(err)
	}
	if r := next[protocol.MemberRemoved](ws, protocol.TypeMemberRemoved); r.User != user || r.Actor != actor {
		t.Fatalf("member_removed %+v; want user %v actor %v", r, user, actor)
	}

	// Shutdown completes with the Subscribe stream still open.
	st.stop(t)
	if _, err := stream.Recv(); err == nil {
		t.Error("stream still open after shutdown")
	}
}

func TestServeGRPCNeedsServiceToken(t *testing.T) {
	st := startStack(t)
	for _, tok := range []string{"", "wrong"} {
		_, err := grpcClient(t, st.grpcAddr, tok).ListDevices(t.Context(), &chatv1.ListDevicesRequest{UserId: bytes16(1)})
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("token %q: %v; want Unauthenticated", tok, err)
		}
	}
}

func bytes16(b byte) []byte {
	u := make([]byte, 16)
	u[15] = b
	return u
}
