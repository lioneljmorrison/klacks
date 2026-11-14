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
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// Defaults for Manager's ping and queue settings.
const (
	DefaultPingInterval = 30 * time.Second
	DefaultPingTimeout  = 10 * time.Second

	// DefaultSendQueue is the per-connection send queue, in frames (S-16):
	// a consumer slower than that, sustained, is disconnected and must
	// resume.
	DefaultSendQueue = 256

	// DefaultReplayWindow and DefaultReplayEntries bound the per-room
	// in-memory replay buffer (S-15): entries older than the window, or
	// beyond the entry count, are dropped and resume falls back to the
	// database.
	DefaultReplayWindow  = 5 * time.Minute
	DefaultReplayEntries = 1024
)

// writeTimeout bounds one frame write.
const writeTimeout = 10 * time.Second

// closeSlowConsumer is the application-defined close code sent to a
// connection dropped for backpressure (S-16): the client should reconnect
// and resume from its last seen seq.
const closeSlowConsumer websocket.StatusCode = 4000

// Manager accepts and tracks WebSocket connections. It is an http.Handler
// for /ws.
type Manager struct {
	// PingInterval is how often each connection is pinged; PingTimeout is how
	// long a pong may take before the connection is dropped. Set them before
	// serving.
	PingInterval time.Duration
	PingTimeout  time.Duration

	// SendQueue is the per-connection send queue, in frames. 0 picks the
	// default. A full queue disconnects the connection with
	// closeSlowConsumer (S-16).
	SendQueue int

	// ReplayWindow is the maximum age of an in-memory replay buffer entry,
	// and ReplayEntries the maximum count per room. 0 picks the defaults
	// (S-15).
	ReplayWindow  time.Duration
	ReplayEntries int

	// OriginPatterns are the cross-origin hosts allowed to upgrade
	// (websocket.AcceptOptions.OriginPatterns, S-43). Empty keeps the
	// same-origin check. Set it only with an authenticator whose credential
	// is never ambient (JWT): with the dev stub, same-origin is the defense
	// against cross-site WebSocket hijacking.
	OriginPatterns []string

	// Chat serves the client frames. It must be set before serving; while it
	// is nil, every valid frame is answered with a "not implemented yet"
	// error (unit tests, and the endpoint before S-13).
	Chat Chat

	auth auth.Authenticator
	log  *slog.Logger

	mu     sync.Mutex
	conns  map[*Conn]struct{}
	closed bool
	wg     sync.WaitGroup // one per connection being served

	hubMu           sync.Mutex                // guards rooms
	rooms           map[store.UUID]*roomState // per-room subscribers and replay buffers
	slowDisconnects atomic.Int64              // conns dropped for backpressure (S-16)
}

// NewManager returns a Manager that identifies clients with a.
func NewManager(a auth.Authenticator, log *slog.Logger) *Manager {
	return &Manager{
		PingInterval:  DefaultPingInterval,
		PingTimeout:   DefaultPingTimeout,
		SendQueue:     DefaultSendQueue,
		ReplayWindow:  DefaultReplayWindow,
		ReplayEntries: DefaultReplayEntries,
		auth:          a,
		log:           log,
		conns:         make(map[*Conn]struct{}),
		rooms:         make(map[store.UUID]*roomState),
	}
}

// Conn is one client connection.
type Conn struct {
	id      auth.Identity
	session store.UUID
	ws      *websocket.Conn

	// out is the bounded send queue, drained by a dedicated writer
	// goroutine (S-16). mu guards closed. Enqueue and the close path hold
	// mu, so a send observed while out is open can never race its close.
	out    chan []byte
	mu     sync.Mutex
	closed bool
}

// Identity is the authenticated user and device.
func (c *Conn) Identity() auth.Identity { return c.id }

// SessionID identifies this connection; it is random and unique per
// connection.
func (c *Conn) SessionID() store.UUID { return c.session }

// ServeHTTP authenticates the request, upgrades it and serves the connection
// until either side closes it. Authentication happens before the upgrade, so
// a failure is a plain 401. Accept's same-origin check stays on, widened only
// by OriginPatterns (S-43).
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
	wsc, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: m.OriginPatterns})
	if err != nil {
		return // Accept has written the response
	}
	wsc.SetReadLimit(protocol.MaxFrameSize)
	c := &Conn{
		id:  id,
		ws:  wsc,
		out: make(chan []byte, m.SendQueue),
	}
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
// The read loop never blocks on a database or on writing: requests are
// answered from the handlers goroutine group, and frames go out through the
// connection's send queue (S-16), so pings keep being answered while the
// server works.
func (m *Manager) serve(c *Conn) {
	log := m.log.With("session", store.FormatUUID(c.session),
		"user", store.FormatUUID(c.id.UserID), "device", store.FormatUUID(c.id.DeviceID))
	log.Info("ws connected")
	ctx, cancel := context.WithCancel(context.Background())
	var pinger, writers, handlers sync.WaitGroup
	pinger.Go(func() { m.ping(ctx, c, log) })
	writers.Go(func() { m.writeOut(c, log) })
	defer func() {
		cancel()
		handlers.Wait() // requests stop (their ctx is canceled) before the hub forgets the connection
		pinger.Wait()
		m.detach(c) // hub: forget subscriptions; fan-out can no longer enqueue
		c.mu.Lock()
		c.closed = true // no further enqueues
		c.mu.Unlock()
		_ = c.ws.CloseNow() // unblocks the writer if it is mid-write
		close(c.out)        // the writer's receive ends
		writers.Wait()
		log.Info("ws disconnected")
	}()
	for {
		typ, b, err := c.ws.Read(ctx)
		if err != nil {
			log.Info("ws read ended", "status", websocket.CloseStatus(err), "err", err)
			return
		}
		if typ != websocket.MessageText {
			_ = c.ws.Close(websocket.StatusUnsupportedData, "frames must be text")
			log.Info("ws disconnected: binary frame")
			return
		}
		m.handle(ctx, c, b, &handlers, log)
	}
}

// writeOut drains the connection's send queue, one text frame at a time. It
// returns when the queue is closed or a write fails; the connection is dead
// either way, and serve's cleanup owns the rest.
func (m *Manager) writeOut(c *Conn, log *slog.Logger) {
	for b := range c.out {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := c.ws.Write(ctx, websocket.MessageText, b)
		cancel()
		if err != nil {
			log.Debug("ws write failed", "err", err)
			return
		}
	}
}

// enqueue encodes f onto the connection's queue without blocking (S-16). A
// full queue marks the connection closed and disconnects it with
// closeSlowConsumer: it is a slow consumer, and it must reconnect and
// resume. A closed connection takes nothing further.
func (m *Manager) enqueue(c *Conn, f protocol.Frame) {
	b, err := protocol.Encode(f)
	if err != nil {
		// Encoding a defined frame type cannot fail; close rather than
		// continue with a connection the server cannot speak to.
		m.log.Error("ws frame encode failed", "err", err)
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		_ = c.ws.CloseNow()
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	select {
	case c.out <- b:
		c.mu.Unlock()
	default:
		c.closed = true
		c.mu.Unlock()
		m.slowDisconnect(c)
	}
}

// slowDisconnect drops a slow consumer and counts it. The close handshake
// contends with the writer's current frame (the library serializes writes),
// so it runs on its own goroutine: a consumer that is merely slow sees the
// closeSlowConsumer code and resumes; one that is stalled hard gets the
// connection force-closed instead and resumes all the same.
func (m *Manager) slowDisconnect(c *Conn) {
	m.slowDisconnects.Add(1)
	m.log.Warn("ws slow consumer: disconnecting",
		"session", store.FormatUUID(c.session), "user", store.FormatUUID(c.id.UserID))
	go func() {
		_ = c.ws.Close(closeSlowConsumer, "slow consumer: reconnect and resume")
	}()
}

// SlowDisconnects returns how many connections have been dropped for
// backpressure (S-16).
func (m *Manager) SlowDisconnects() int64 { return m.slowDisconnects.Load() }

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

// handle answers one frame. Subscribe, resume and publish run on their own
// goroutine: they may block on the stores, and the read loop must keep
// reading so pongs keep being answered. Ack is cheap and runs inline. All
// replies and deliveries go through the connection's send queue.
func (m *Manager) handle(ctx context.Context, c *Conn, b []byte, handlers *sync.WaitGroup, log *slog.Logger) {
	f, err := protocol.Decode(b)
	if err != nil {
		m.enqueue(c, protocol.ErrorFor(err))
		return
	}
	if m.Chat == nil {
		e := &protocol.Error{Code: protocol.CodeInternal, Message: "not implemented yet"}
		setRefs(e, f)
		m.enqueue(c, e)
		return
	}
	switch f := f.(type) {
	case *protocol.Subscribe:
		handlers.Go(func() { m.doSubscribe(ctx, c, f, log) })
	case *protocol.Resume:
		handlers.Go(func() { m.doResume(ctx, c, f, log) })
	case *protocol.Publish:
		handlers.Go(func() { m.doPublish(ctx, c, f, log) })
	case *protocol.Ack:
		m.ack(c, f)
	}
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
