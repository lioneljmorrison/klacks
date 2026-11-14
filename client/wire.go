package client

// The WebSocket messaging path: dial /ws, resume rooms, publish sealed
// envelopes, and turn delivers into decrypted inbox events. Frames are the
// server's protocol package, which is the transport side of the same
// document (docs/protocol.md) this client is the crypto side of.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/protocol"
)

// Dial opens the WebSocket as this device and starts its read loop. The
// dev server takes the identity as query parameters.
func (c *Client) Dial(ctx context.Context) error {
	url := "ws" + strings.TrimPrefix(c.base, "http") + "/ws?user=" + format(c.user) + "&device=" + format(c.device)
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(dialCtx, url, nil)
	if err != nil {
		return fmt.Errorf("dial /ws: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	conn.SetReadLimit(-1)
	c.conn = conn
	c.readCtx, c.readCancel = context.WithCancel(context.WithoutCancel(ctx))
	go c.readLoop()
	return nil
}

// Close closes the connection and the client's channels.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		if c.readCancel != nil {
			c.readCancel()
		}
		if c.conn != nil {
			_ = c.conn.Close(websocket.StatusNormalClosure, "")
		}
		// The read loop is the only sender on Inbox and Errs: wait for it
		// to exit before closing what it feeds.
		<-c.readerDone
		close(c.done)
		close(c.Inbox)
		close(c.Errs)
	})
}

// sendFrame writes one frame.
func (c *Client) sendFrame(ctx context.Context, f protocol.Frame) error {
	if c.conn == nil {
		return errors.New("client: not connected")
	}
	b, err := protocol.Encode(f)
	if err != nil {
		return err
	}
	return c.conn.Write(ctx, websocket.MessageText, b)
}

// Resume asks for every message in room after lastSeen, then live delivery.
func (c *Client) Resume(ctx context.Context, room [16]byte, lastSeen int64) error {
	return c.sendFrame(ctx, &protocol.Resume{
		RoomID:      protocol.UUID(room),
		LastSeenSeq: lastSeen,
	})
}

// Subscribe asks for live delivery of a room's new messages.
func (c *Client) Subscribe(ctx context.Context, room [16]byte) error {
	return c.sendFrame(ctx, &protocol.Subscribe{RoomID: protocol.UUID(room)})
}

// Publish sends one already-sealed envelope.
func (c *Client) publish(ctx context.Context, room [16]byte, e encryptResult) error {
	return c.sendFrame(ctx, &protocol.Publish{
		RoomID:     protocol.UUID(room),
		MessageID:  protocol.UUID(e.MessageID),
		DeviceID:   protocol.UUID(c.device),
		Header:     e.Header,
		Ciphertext: e.Ciphertext,
	})
}

// Send seals plaintext for every device of every other member the caller
// lists and publishes one envelope per recipient device. In a DM room pass
// the single peer; each published message carries its own message id.
func (c *Client) Send(ctx context.Context, room [16]byte, peers []Peer, plaintext []byte) error {
	for _, p := range peers {
		e, err := c.sealFor(ctx, room, p, plaintext)
		if err != nil {
			return err
		}
		if err := c.publish(ctx, room, e); err != nil {
			return err
		}
	}
	return nil
}

// readLoop consumes frames until the connection or the client ends. Delivers
// go through the ordering check and the ratchet; error frames and read
// failures surface on Errs.
func (c *Client) readLoop() {
	defer close(c.readerDone)
	for {
		var f protocol.Frame
		err := c.readFrame(&f)
		if err != nil {
			select {
			case <-c.done:
			case c.Errs <- fmt.Errorf("read: %w", err):
			}
			return
		}
		switch f := f.(type) {
		case *protocol.Deliver:
			c.handleDeliver(*f)
		case *protocol.MemberRemoved:
			c.handleMemberRemoved(f)
		case *protocol.Members:
			c.handleMembers(f)
		case *protocol.Error:
			select {
			case <-c.done:
				return
			case c.Errs <- fmt.Errorf("server error %s: %s", f.Code, f.Message):
			}
		}
	}
}

// readFrame reads one text frame and decodes it. The server's messages are
// server-to-client frames.
func (c *Client) readFrame(out *protocol.Frame) error {
	kind, data, err := c.conn.Read(c.readCtx)
	if err != nil {
		return err
	}
	if kind != websocket.MessageText {
		return errors.New("client: non-text frame from server")
	}
	f, err := decodeServerFrame(data)
	if err != nil {
		return err
	}
	*out = f
	return nil
}

// decodeServerFrame decodes a deliver or error frame.
func decodeServerFrame(b []byte) (protocol.Frame, error) {
	var env protocol.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	switch env.Type {
	case protocol.TypeDeliver:
		var d protocol.Deliver
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		return &d, nil
	case protocol.TypeError:
		var e protocol.Error
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		return &e, nil
	case protocol.TypeMemberRemoved:
		var e protocol.MemberRemoved
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		return &e, nil
	case protocol.TypeMembers:
		var m protocol.Members
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		return &m, nil
	default:
		return nil, fmt.Errorf("client: unexpected frame type %q", env.Type)
	}
}

// deliver is the parts of a deliver frame the crypto path needs.
type deliver struct {
	Room         [16]byte
	Seq          int64
	Sender       [16]byte
	SenderDevice [16]byte
	MessageID    [16]byte
	Header       []byte
	Ciphertext   []byte
}

// handleDeliver runs one deliver through the receive path: room ordering
// first (the server's seq promise, verified independently of the AEAD),
// then the recipient check, then the ratchet. The outcome lands on Inbox.
// A room this device was removed from (S-29) is dropped unread.
func (c *Client) handleDeliver(f protocol.Deliver) {
	d := deliver{
		Room:         [16]byte(f.RoomID),
		Seq:          f.Seq,
		Sender:       [16]byte(f.SenderID),
		SenderDevice: [16]byte(f.DeviceID),
		MessageID:    [16]byte(f.MessageID),
		Header:       f.Header,
		Ciphertext:   f.Ciphertext,
	}
	c.mu.Lock()
	rs, ok := c.rooms[d.Room]
	removed := ok && rs.removed
	c.mu.Unlock()
	if removed {
		return
	}
	redelivery, err := c.checkOrdering(d.Room, d.Seq, d.MessageID)
	if err != nil {
		c.inbox(Received{
			Room: d.Room, Seq: d.Seq, Sender: d.Sender,
			SenderDevice: d.SenderDevice, MessageID: d.MessageID, Err: err,
		})
		return
	}
	// A sender-key group message (header type 0x03) is not a pairwise
	// message: it decrypts under the sender device's installed chain
	// (S-28). Everything else rides the pairwise ratchet.
	if isSenderKeyMessage(d.Header) {
		c.groupDeliver(d, redelivery)
		return
	}
	c.decryptDeliver(d, redelivery)
}

// decryptDeliver runs one ordering-checked deliver through the ratchet and
// emits the outcome. Messages stashed pending the session's first message
// say so silently; when a decrypt succeeds and any stash exists, the stash
// is decrypted and emitted too.
func (c *Client) decryptDeliver(d deliver, redelivery bool) {
	r := Received{
		Room:         d.Room,
		Seq:          d.Seq,
		Sender:       d.Sender,
		SenderDevice: d.SenderDevice,
		MessageID:    d.MessageID,
	}
	pt, uerr := c.unseal(d.Room, d)
	switch {
	case errors.Is(uerr, errPending):
		// Stashed; nothing to emit yet.
		return
	case errors.Is(uerr, errNotForMe):
		// Another member's copy: expected in multi-member rooms, silent.
		return
	case uerr != nil:
		r.Err = uerr
		c.inbox(r)
		c.ack(d.Room, d.Seq)
		return
	}
	// A distribution payload is a control message: install the sender
	// device's chain and emit nothing (a conflict, which no honest sender
	// produces, is reported). An application plaintext is emitted unless
	// it is a verified redelivery.
	if k, derr := unmarshalSenderKeyDistribution(pt); derr == nil {
		c.ack(d.Room, d.Seq)
		c.installDistribution(d, k)
	} else if redelivery {
		// Already delivered once and it re-verifies: stay silent.
		c.ack(d.Room, d.Seq)
	} else {
		r.Plaintext = pt
		c.inbox(r)
		c.ack(d.Room, d.Seq)
	}
	// The session now exists; anything that arrived before the session's
	// first message can finally be decrypted, in arrival order (the
	// ratchet's skipped-key handling puts the chain back together).
	for _, pd := range c.takePending(d.Room, d.SenderDevice) {
		c.decryptDeliver(pd, false)
	}
}

// takePending returns and clears the messages stashed for a sender device.
func (c *Client) takePending(room, senderDevice [16]byte) []deliver {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sessionKey{room: room, peer: senderDevice}
	out := c.pending[key]
	delete(c.pending, key)
	return out
}

// checkOrdering verifies the room's seq stream: strictly increasing, no
// gaps, one message id per seq, no id at two seqs. The server owns this
// promise; a violation means the stream was tampered with. A true
// redelivery flag marks a message already seen at the same seq, which the
// caller may then verify and suppress instead of re-emitting.
func (c *Client) checkOrdering(room [16]byte, seq int64, mid [16]byte) (redelivery bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rs, ok := c.rooms[room]
	if !ok {
		rs = &roomState{seen: make(map[int64][16]byte), ids: make(map[[16]byte]int64)}
		c.rooms[room] = rs
	}
	if id, dup := rs.ids[mid]; dup && id != seq {
		return false, fmt.Errorf("room stream: message %s appears at seq %d and %d", format(mid), id, seq)
	}
	if !rs.started {
		// Baseline: subscribe anchors live delivery above any history this
		// connection did not see, so the first seq starts the check.
		rs.started = true
		rs.lastSeq = seq
		rs.seen[seq] = mid
		rs.ids[mid] = seq
		return false, nil
	}
	switch {
	case seq == rs.lastSeq+1:
		rs.lastSeq = seq
		rs.seen[seq] = mid
		rs.ids[mid] = seq
		return false, nil
	case seq <= rs.lastSeq:
		if id, ok := rs.seen[seq]; ok && id == mid {
			// A redelivery of something already consumed: resume and
			// live delivery can overlap; idempotent.
			return true, nil
		}
		return false, fmt.Errorf("room stream: seq %d redelivered with message %s, was %s",
			seq, format(mid), format(rs.seen[seq]))
	default: // seq > lastSeq+1: a gap
		return false, fmt.Errorf("room stream: gap: seq %d after %d", seq, rs.lastSeq)
	}
}

// inbox delivers a Received event without blocking the read loop.
func (c *Client) inbox(r Received) {
	select {
	case <-c.done:
	case c.Inbox <- r:
	}
}

// ack confirms consumption up to seq.
func (c *Client) ack(room [16]byte, seq int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.sendFrame(ctx, &protocol.Ack{RoomID: protocol.UUID(room), Seq: seq})
}
