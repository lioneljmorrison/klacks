package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

const (
	userStr   = "11111111-1111-1111-1111-111111111111"
	deviceStr = "22222222-2222-2222-2222-222222222222"
	roomStr   = "33333333-3333-3333-3333-333333333333"
	msgStr    = "44444444-4444-4444-4444-444444444444"
)

var discard = slog.New(slog.DiscardHandler)

func newTestServer(t *testing.T, pingInterval, pingTimeout time.Duration) (*Manager, *httptest.Server) {
	t.Helper()
	m := NewManager(auth.Dev{}, discard)
	m.PingInterval, m.PingTimeout = pingInterval, pingTimeout
	srv := httptest.NewServer(m)
	t.Cleanup(func() {
		m.Close()
		srv.Close()
	})
	return m, srv
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?user=" + userStr + "&device=" + deviceStr
}

func dial(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	c.SetReadLimit(-1)
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

func readError(t *testing.T, c *websocket.Conn) protocol.Error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	typ, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("message type %v; want text", typ)
	}
	var e protocol.Error
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	if e.V != protocol.Version || e.Type != protocol.TypeError {
		t.Fatalf("got %s; want an error frame", b)
	}
	return e
}

// waitConns waits until the manager holds n connections.
func waitConns(t *testing.T, m *Manager, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for m.Len() != n {
		if time.Now().After(deadline) {
			t.Fatalf("manager holds %d connections; want %d", m.Len(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUnauthenticatedGets401BeforeUpgrade(t *testing.T) {
	_, srv := newTestServer(t, time.Minute, time.Minute)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err == nil {
		t.Fatal("dial succeeded without credentials")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("resp = %v; want 401", resp)
	}
	resp.Body.Close()
}

func TestCrossOriginRejected(t *testing.T) {
	_, srv := newTestServer(t, time.Minute, time.Minute)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, wsURL(srv), &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {"https://evil.example"}},
	})
	if err == nil {
		t.Fatal("cross-origin dial succeeded")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("resp = %v; want 403", resp)
	}
	resp.Body.Close()
}

func TestConnectionState(t *testing.T) {
	m, srv := newTestServer(t, time.Minute, time.Minute)
	dial(t, srv)
	waitConns(t, m, 1)
	conns := m.snapshot()
	c := conns[0]
	want := auth.Identity{UserID: store.UUID(mustID(t, userStr)), DeviceID: store.UUID(mustID(t, deviceStr))}
	if got := c.Identity(); got != want {
		t.Errorf("identity = %+v", got)
	}
	if c.SessionID() == (store.UUID{}) {
		t.Error("session ID is zero")
	}
	dial(t, srv)
	waitConns(t, m, 2)
	if cs := m.snapshot(); cs[0].SessionID() == cs[1].SessionID() {
		t.Error("two connections share a session ID")
	}
}

func TestBadFrameGetsErrorFrame(t *testing.T) {
	_, srv := newTestServer(t, time.Minute, time.Minute)
	c := dial(t, srv)
	if err := c.Write(t.Context(), websocket.MessageText, []byte(`{"v":1,"type":"subscribe"}`)); err != nil {
		t.Fatal(err)
	}
	if e := readError(t, c); e.Code != protocol.CodeBadFrame {
		t.Errorf("code = %q; want bad_frame", e.Code)
	}
	// The connection stays open after a bad frame.
	if err := c.Write(t.Context(), websocket.MessageText, []byte(`{"v":9}`)); err != nil {
		t.Fatal(err)
	}
	if e := readError(t, c); e.Code != protocol.CodeUnsupportedVersion {
		t.Errorf("code = %q; want unsupported_version", e.Code)
	}
}

// Until S-13..S-15 handle them, valid frames are answered with an error that
// names the request.
func TestValidFrameAnsweredWithRefs(t *testing.T) {
	_, srv := newTestServer(t, time.Minute, time.Minute)
	c := dial(t, srv)
	b, _ := protocol.Encode(&protocol.Publish{
		RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr),
		Ciphertext: []byte("ct"),
	})
	if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
	e := readError(t, c)
	if e.RoomID != mustID(t, roomStr) || e.MessageID != mustID(t, msgStr) {
		t.Errorf("error frame refs = %v %v; want the publish's room and message", e.RoomID, e.MessageID)
	}
}

func TestBinaryMessageClosesConnection(t *testing.T) {
	_, srv := newTestServer(t, time.Minute, time.Minute)
	c := dial(t, srv)
	if err := c.Write(t.Context(), websocket.MessageBinary, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	if got := websocket.CloseStatus(err); got != websocket.StatusUnsupportedData {
		t.Errorf("close status = %v (%v); want StatusUnsupportedData", got, err)
	}
}

// The largest legal publish reaches the protocol layer; one byte more than
// MaxFrameSize closes the connection.
func TestReadLimit(t *testing.T) {
	_, srv := newTestServer(t, time.Minute, time.Minute)
	c := dial(t, srv)
	b, _ := protocol.Encode(&protocol.Publish{
		RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr),
		Ciphertext: bytes.Repeat([]byte{0xff}, core.MaxPayloadSize),
	})
	if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
	readError(t, c) // answered, not dropped

	big := append([]byte(`{"v":1,"type":"ack","pad":"`), bytes.Repeat([]byte("x"), protocol.MaxFrameSize)...)
	big = append(big, `"}`...)
	if err := c.Write(t.Context(), websocket.MessageText, big); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	if got := websocket.CloseStatus(err); got != websocket.StatusMessageTooBig {
		t.Errorf("close status = %v (%v); want StatusMessageTooBig", got, err)
	}
}

// A client that stops reading never answers pings and is dropped.
func TestDeadConnectionDropped(t *testing.T) {
	m, srv := newTestServer(t, 20*time.Millisecond, 50*time.Millisecond)
	dial(t, srv) // never reads, so never sends a pong
	waitConns(t, m, 1)
	waitConns(t, m, 0)
}

// A client that keeps reading answers pings and stays connected.
func TestLiveConnectionKept(t *testing.T) {
	m, srv := newTestServer(t, 10*time.Millisecond, time.Second)
	c := dial(t, srv)
	ctx := c.CloseRead(t.Context()) // reads, so pongs are sent
	time.Sleep(200 * time.Millisecond)
	if m.Len() != 1 || ctx.Err() != nil {
		t.Fatalf("live connection dropped: len=%d ctx=%v", m.Len(), ctx.Err())
	}
}

func TestClientDisconnectRemovesConn(t *testing.T) {
	m, srv := newTestServer(t, time.Minute, time.Minute)
	c := dial(t, srv)
	waitConns(t, m, 1)
	c.Close(websocket.StatusNormalClosure, "")
	waitConns(t, m, 0)
}

func TestCloseSendsGoingAwayAndWaits(t *testing.T) {
	m, srv := newTestServer(t, time.Minute, time.Minute)
	c1, c2 := dial(t, srv), dial(t, srv)
	waitConns(t, m, 2)

	errs := make(chan error, 2)
	for _, c := range []*websocket.Conn{c1, c2} {
		go func() {
			_, _, err := c.Read(context.Background())
			errs <- err
		}()
	}
	m.Close()
	if m.Len() != 0 {
		t.Errorf("Close returned with %d connections", m.Len())
	}
	for range 2 {
		select {
		case err := <-errs:
			if got := websocket.CloseStatus(err); got != websocket.StatusGoingAway {
				t.Errorf("close status = %v (%v); want StatusGoingAway", got, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("client not closed")
		}
	}

	// No new connections after Close.
	resp, err := http.Get(srv.URL + "/ws?user=" + userStr + "&device=" + deviceStr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("after Close: status %d; want 503", resp.StatusCode)
	}
}

func mustID(t *testing.T, s string) protocol.UUID {
	t.Helper()
	var u protocol.UUID
	if err := u.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	return u
}
