package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/ratelimit"
)

// A publish over the per-user limit (S-32) is refused before it reaches the
// core, with a rate_limited error naming the room and message.
func TestPublishUserRateLimit(t *testing.T) {
	chat := &fakeChat{}
	srv := limitedServer(t, chat, func(m *Manager) {
		m.PublishPerUser = ratelimit.New(ratelimit.Limit{Rate: 1e-6, Burst: 2})
	})
	c := dial(t, srv)
	frames := readFrames(c)

	for i := range 3 {
		msg := mustID(t, msgStr)
		msg[15] = byte(i)
		sendFrame(t, c, &protocol.Publish{
			RoomID: mustID(t, roomStr), MessageID: msg, DeviceID: mustID(t, deviceStr),
			Ciphertext: []byte("ct"),
		})
	}
	// Requests run concurrently, so which of the three is refused is not
	// fixed: exactly one is, and its frame names it.
	e := errorOf(t, next(t, frames, 5*time.Second))
	base := mustID(t, msgStr)
	if e.Code != protocol.CodeRateLimited || e.RoomID != mustID(t, roomStr) || [15]byte(e.MessageID[:15]) != [15]byte(base[:15]) || e.MessageID[15] > 2 {
		t.Errorf("error = %+v; want rate_limited naming the room and one of the messages", e)
	}
	wantNothing(t, frames, 100*time.Millisecond)
	if n := chat.postCount(); n != 2 {
		t.Errorf("core saw %d posts; want 2", n)
	}
}

// Connection attempts over the per-user limit get 429 with Retry-After,
// before the upgrade.
func TestConnectUserRateLimit(t *testing.T) {
	srv := limitedServer(t, &fakeChat{}, func(m *Manager) {
		m.ConnectPerUser = ratelimit.New(ratelimit.Limit{Rate: 0.5, Burst: 2})
	})
	for i := range 3 {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		c, resp, err := websocket.Dial(ctx, wsURL(srv), nil)
		cancel()
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if i < 2 {
			if err != nil {
				t.Fatalf("attempt %d: %v", i, err)
			}
			_ = c.CloseNow()
			continue
		}
		if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: resp %v err %v; want 429", i, resp, err)
		}
		if got := resp.Header.Get("Retry-After"); got != "2" {
			t.Errorf("Retry-After = %q; want 2 (one token at 0.5/s)", got)
		}
	}
}

// limitedServer is newChatTestServer with set applied before serving.
func limitedServer(t *testing.T, chat Chat, set func(*Manager)) *httptest.Server {
	t.Helper()
	m := NewManager(auth.Dev{}, discard)
	m.PingInterval, m.PingTimeout = time.Minute, time.Minute
	m.Chat = chat
	set(m)
	srv := httptest.NewServer(m)
	t.Cleanup(func() {
		m.Close()
		srv.Close()
	})
	return srv
}
