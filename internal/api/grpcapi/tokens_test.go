package grpcapi_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	chatv1 "github.com/lioneljmorrison/klacks/api/gen/klacks/chat/v1"
	"github.com/lioneljmorrison/klacks/internal/api/grpcapi"
)

// Service tokens (S-31): every RPC, unary or streaming, needs
// "authorization: Bearer <token>" naming one of the configured tokens.
func TestServiceTokens(t *testing.T) {
	tokens, err := grpcapi.NewServiceTokens("tok-a", "tok-b")
	if err != nil {
		t.Fatal(err)
	}
	f, done := happyChat()
	defer done()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(tokens.ServerOptions()...)
	chatv1.RegisterChatServiceServer(gs, grpcapi.New(f))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	client := chatv1.NewChatServiceClient(cc)

	with := func(md ...string) context.Context {
		return metadata.AppendToOutgoingContext(t.Context(), md...)
	}
	for name, tc := range map[string]struct {
		ctx  context.Context
		want codes.Code
	}{
		"token a":      {with("authorization", "Bearer tok-a"), codes.OK},
		"token b":      {with("authorization", "bearer tok-b"), codes.OK},
		"no metadata":  {t.Context(), codes.Unauthenticated},
		"wrong token":  {with("authorization", "Bearer tok-c"), codes.Unauthenticated},
		"prefix only":  {with("authorization", "Bearer tok-"), codes.Unauthenticated},
		"not bearer":   {with("authorization", "Basic tok-a"), codes.Unauthenticated},
		"bare token":   {with("authorization", "tok-a"), codes.Unauthenticated},
		"empty bearer": {with("authorization", "Bearer "), codes.Unauthenticated},
	} {
		t.Run(name+"/unary", func(t *testing.T) {
			_, err := client.CreateRoom(tc.ctx, &chatv1.CreateRoomRequest{Kind: "group"})
			if got := code(t, err); got != tc.want {
				t.Errorf("code %v; want %v (err %v)", got, tc.want, err)
			}
		})
		t.Run(name+"/stream", func(t *testing.T) {
			s, err := client.Subscribe(tc.ctx, &chatv1.SubscribeRequest{RoomId: b16(1)})
			if err == nil {
				_, err = s.Recv()
			}
			got := code(t, err)
			if tc.want == codes.Unauthenticated && got != codes.Unauthenticated {
				t.Errorf("code %v; want Unauthenticated (err %v)", got, err)
			}
			if tc.want == codes.OK && got == codes.Unauthenticated {
				t.Errorf("authorized stream refused: %v", err)
			}
		})
	}
}

func TestNewServiceTokensRejectsEmpty(t *testing.T) {
	if _, err := grpcapi.NewServiceTokens(); err == nil {
		t.Error("no tokens accepted")
	}
	if _, err := grpcapi.NewServiceTokens("ok", ""); err == nil {
		t.Error("empty token accepted")
	}
}
