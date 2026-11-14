package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/protocol"
)

// A read loop busy delivering when the client drops and redials must exit
// once it is done with that delivery: it belongs to the old connection and
// must never read from the new one (S-41).
func TestReadLoopDoesNotFollowRedial(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		if conns.Add(1) == 1 {
			b, err := protocol.Encode(&protocol.Deliver{
				RoomID: protocol.UUID{9}, Seq: 1, MessageID: protocol.UUID{1},
				SenderID: protocol.UUID{2}, DeviceID: protocol.UUID{3},
				Header: []byte{0xFF}, Ciphertext: []byte{0},
			})
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Write(r.Context(), websocket.MessageText, b)
		}
		// Read until the client closes, so its close handshake completes.
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	c, err := NewClient(srv.URL, [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A full inbox holds the first read loop inside its delivery.
	for len(c.Inbox) < cap(c.Inbox) {
		c.Inbox <- Received{}
	}
	if err := c.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	firstDone := c.readerDone
	c.mu.Unlock()
	time.Sleep(50 * time.Millisecond) // the deliver reaches the full inbox
	c.Disconnect()
	if err := c.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	// Free the inbox: the first loop finishes its delivery.
	for len(c.Inbox) > 0 {
		<-c.Inbox
	}
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the dropped connection's read loop is still running: it followed the redial")
	}
}
