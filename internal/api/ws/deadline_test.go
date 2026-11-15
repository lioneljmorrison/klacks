package ws

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/blackhole"
)

// S-47: with PostgreSQL partitioned, a publish and a resume each end in an
// "unavailable" error frame instead of hanging until the client leaves.
func TestStoreDeadlines(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@"+blackhole.Listen(t)+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	for name, tc := range map[string]struct {
		lockTimeout, publishTimeout time.Duration
		frame                       protocol.Frame
	}{
		// The room lock timeout alone would allow a minute: the publish
		// deadline is what ends it.
		"publish": {time.Minute, 300 * time.Millisecond, &protocol.Publish{
			RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr), Ciphertext: []byte{1}}},
		// Resume has no overall deadline (a replay may be long); each
		// store call is bounded by the lock timeout.
		"resume": {300 * time.Millisecond, 0, &protocol.Resume{RoomID: mustID(t, roomStr)}},
	} {
		t.Run(name, func(t *testing.T) {
			m, srv := newTestServer(t, time.Minute, time.Minute)
			m.Chat = core.New(store.NewRooms(pool, tc.lockTimeout), nil, nil, nil)
			m.PublishTimeout = tc.publishTimeout
			c := dial(t, srv)
			b, err := protocol.Encode(tc.frame)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			e := readError(t, c)
			if e.Code != protocol.CodeUnavailable || e.RoomID != mustID(t, roomStr) {
				got, _ := json.Marshal(e)
				t.Errorf("got %s; want an unavailable error naming the room", got)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
}
