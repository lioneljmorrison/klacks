// Package ws is the client WebSocket endpoint (/ws): it authenticates and
// accepts connections, keeps per-connection state, reads frames and detects
// dead peers with ping/pong.
package ws

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// Defaults for Manager's ping settings.
const (
	DefaultPingInterval = 30 * time.Second
	DefaultPingTimeout  = 10 * time.Second
)

// writeTimeout bounds one frame write.
const writeTimeout = 10 * time.Second

// Manager accepts and tracks WebSocket connections. It is an http.Handler
// for /ws.
type Manager struct {
	// PingInterval is how often each connection is pinged; PingTimeout is how
	// long a pong may take before the connection is dropped. Set them before
	// serving.
	PingInterval time.Duration
	PingTimeout  time.Duration

	auth auth.Authenticator
	log  *slog.Logger

	mu     sync.Mutex
	conns  map[*Conn]struct{}
	closed bool
	wg     sync.WaitGroup // one per connection being served
}

// NewManager returns a Manager that identifies clients with a.
func NewManager(a auth.Authenticator, log *slog.Logger) *Manager {
	return &Manager{
		PingInterval: DefaultPingInterval,
		PingTimeout:  DefaultPingTimeout,
		auth:         a,
		log:          log,
		conns:        make(map[*Conn]struct{}),
	}
}

// Conn is one client connection.
type Conn struct {
	id      auth.Identity
	session store.UUID
	ws      *websocket.Conn
}

// Identity is the authenticated user and device.
func (c *Conn) Identity() auth.Identity { return c.id }

// SessionID identifies this connection; it is random and unique per
// connection.
func (c *Conn) SessionID() store.UUID { return c.session }

// ServeHTTP authenticates the request, upgrades it and serves the connection
// until either side closes it. Authentication happens before the upgrade, so
// a failure is a plain 401. Accept's default same-origin check stays on: with
// credentials in the query string it is the defense against cross-site
// WebSocket hijacking.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := m.auth.Authenticate(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	wsc, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept has written the response
	}
	wsc.SetReadLimit(protocol.MaxFrameSize)
	c := &Conn{id: id, ws: wsc}
	_, _ = rand.Read(c.session[:]) // never fails (crypto/rand)
	if !m.add(c) {
		_ = wsc.Close(websocket.StatusGoingAway, "server shutting down")
		return
	}
	defer m.remove(c)
	m.serve(c)
}

func (m *Manager) add(c *Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.conns[c] = struct{}{}
	m.wg.Add(1)
	return true
}

func (m *Manager) remove(c *Conn) {
	m.mu.Lock()
	delete(m.conns, c)
	m.mu.Unlock()
	m.wg.Done()
}

// serve reads frames until the connection ends. The read loop runs for the
// connection's whole life: pongs are only processed while a Read is active.
func (m *Manager) serve(c *Conn) {
	log := m.log.With("session", store.FormatUUID(c.session),
		"user", store.FormatUUID(c.id.UserID), "device", store.FormatUUID(c.id.DeviceID))
	log.Info("ws connected")
	ctx, cancel := context.WithCancel(context.Background())
	var pinger sync.WaitGroup
	pinger.Go(func() { m.ping(ctx, c, log) })
	defer func() {
		cancel()
		pinger.Wait()
		_ = c.ws.CloseNow()
	}()
	for {
		typ, b, err := c.ws.Read(ctx)
		if err != nil {
			log.Info("ws disconnected", "status", websocket.CloseStatus(err), "err", err)
			return
		}
		if typ != websocket.MessageText {
			_ = c.ws.Close(websocket.StatusUnsupportedData, "frames must be text")
			log.Info("ws disconnected: binary frame")
			return
		}
		if err := m.handle(ctx, c, b); err != nil {
			log.Info("ws disconnected: write failed", "err", err)
			return
		}
	}
}

// ping drops the connection when the peer stops answering pings.
func (m *Manager) ping(ctx context.Context, c *Conn, log *slog.Logger) {
	t := time.NewTicker(m.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, m.PingTimeout)
		err := c.ws.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				log.Info("ws peer not answering pings", "err", err)
			}
			_ = c.ws.CloseNow()
			return
		}
	}
}

// handle answers one frame. Frames are not acted on yet: subscribe and
// publish arrive with S-13, resume with S-14, ack with S-15.
func (m *Manager) handle(ctx context.Context, c *Conn, b []byte) error {
	f, err := protocol.Decode(b)
	if err != nil {
		return m.send(ctx, c, protocol.ErrorFor(err))
	}
	e := &protocol.Error{Code: protocol.CodeInternal, Message: "not implemented yet"}
	setRefs(e, f)
	return m.send(ctx, c, e)
}

// setRefs names the request f in its error frame e.
func setRefs(e *protocol.Error, f protocol.Frame) {
	switch f := f.(type) {
	case *protocol.Subscribe:
		e.RoomID = f.RoomID
	case *protocol.Resume:
		e.RoomID = f.RoomID
	case *protocol.Ack:
		e.RoomID = f.RoomID
	case *protocol.Publish:
		e.RoomID, e.MessageID = f.RoomID, f.MessageID
	}
}

func (m *Manager) send(ctx context.Context, c *Conn, f protocol.Frame) error {
	b, err := protocol.Encode(f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, b)
}

// Close stops accepting connections, closes every open one with
// StatusGoingAway and waits until all of them have finished. Calling it again
// waits again.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	conns := make([]*Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() {
			err := c.ws.Close(websocket.StatusGoingAway, "server shutting down")
			if err != nil && !errors.Is(err, context.Canceled) {
				m.log.Debug("ws close", "err", err)
			}
		})
	}
	wg.Wait()
	m.wg.Wait()
}

// Len returns the number of open connections.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.conns)
}

// snapshot returns the open connections.
func (m *Manager) snapshot() []*Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs := make([]*Conn, 0, len(m.conns))
	for c := range m.conns {
		cs = append(cs, c)
	}
	return cs
}
