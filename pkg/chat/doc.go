// Package chat is the public, importable interface to the klacks messaging
// core (ChatService). Embedders depend on this package only; everything under
// internal/ may change without notice.
//
// # Embedding
//
// Open wires both stores (PostgreSQL for rooms, membership and the per-room
// seq; ScyllaDB for the message stream) and returns a Service implementing
// ChatService. Both stores must already be migrated, exactly as for the
// standalone server (`klacks migrate up`; see the repository README). Close
// releases them.
//
//	room, err := chat.Open(ctx, chat.Config{
//	    PostgresDSN:     dsn,
//	    ScyllaHosts:     []string{"scylla"},
//	    ScyllaKeyspace:  "klacks",
//	    ScyllaTimeout:   5 * time.Second,
//	    RoomLockTimeout: 10 * time.Second,
//	    Actor:           serviceUserID,
//	})
//
// # The service identity
//
// ChatService's methods carry no acting user: the embedder acts through one
// configured service identity, Config.Actor. CreateRoom makes the actor the
// room's owner; AddMember and RemoveMember act as that actor (owner
// authority, so the embedder manages membership); Subscribe authorizes the
// actor as the reader. PostMessage keeps its explicit sender, who must be a
// room member to post.
//
// # Subscriptions
//
// Subscribe streams a room's messages from fromSeq (0 replays the whole
// room) through the same resume path the WebSocket endpoint uses: authorize,
// read the committed watermark, replay every committed message above
// fromSeq, then continue with live fan-out. Each subscription sequences its
// own stream, so messages arrive exactly once and in seq order even when
// publishes race.
//
// The returned channel closes when the context is cancelled, the service is
// closed, a store error ends delivery, or the consumer falls behind: core
// fan-out runs in publish order and must never block, so a subscription
// whose delivery queue fills (Config.SendQueue) is closed instead. The
// consumer keeps the last seq it received and subscribes again from there.
package chat
