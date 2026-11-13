package chat_test

import (
	"context"
	"log/slog"
	"time"

	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// Opening a ChatService: both stores must already be migrated, exactly as
// for the standalone server. This example is compile-only; it needs running
// stores.
func ExampleOpen() {
	var serviceUserID [16]byte // the embedder's service identity

	svc, err := chat.Open(context.Background(), chat.Config{
		PostgresDSN: "postgres://klacks:secret@localhost/klacks",
		ScyllaHosts: []string{"localhost"},
		// Must exceed ScyllaTimeout: a publish holds the room lock across
		// its ScyllaDB write.
		ScyllaTimeout:   5 * time.Second,
		RoomLockTimeout: 10 * time.Second,
		Actor:           chat.UserID(serviceUserID),
		Log:             slog.Default(),
	})
	if err != nil {
		// A bad configuration or unreachable store fails here, at startup.
		return
	}
	defer svc.Close()

	_ = svc // rooms, membership, publishing and subscriptions, plan §3.6
}

// Creating a room and streaming it. This example is compile-only; it needs
// running stores.
func ExampleChatService_Subscribe() {
	var svc *chat.Service
	ctx := context.Background()

	room, err := svc.CreateRoom(ctx, chat.RoomSpec{Kind: chat.KindGroup})
	if err != nil {
		return
	}
	if err := svc.AddMember(ctx, room, senderID, chat.RoleAdmin); err != nil {
		return
	}

	// Everything the room has, then live fan-out. The channel closes when
	// ctx is done, the service is closed, or the consumer falls behind:
	// resubscribe from the last seq received.
	messages, err := svc.Subscribe(ctx, room, 0)
	if err != nil {
		return
	}
	for m := range messages {
		// m.Ciphertext and m.Header are opaque to the server.
		_ = m.Seq
	}
}

var senderID chat.UserID
