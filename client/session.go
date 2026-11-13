package client

// Session glue: one Double Ratchet session per (room, peer device) pair,
// and the encrypt/decrypt path that turns a room's plaintext into
// published envelopes and delivered envelopes back into plaintext.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
)

// Peer names one of a room's members: a user and one of their devices.
// A DM has one other peer; a group has one copy per member device.
type Peer struct {
	User   [16]byte
	Device [16]byte
}

// session is one ratchet with the peer device it lives under.
type session struct {
	peer    Peer
	ratchet *Ratchet
	// first marks a session whose next message is its first: it carries
	// the X3DH prelude in its header.
	first bool
	pre   PrekeyHeader
	// usedOneTime is the one-time prekey id this session's initiation
	// consumed from the peer's bundle (0 when none was used).
	usedOneTime int64
}

// sessionKey names a session: per room and per peer device.
type sessionKey struct {
	room [16]byte
	peer [16]byte // the peer's device
}

// encryptResult is one sealed envelope, ready to publish.
type encryptResult struct {
	MessageID  [16]byte
	Header     []byte
	Ciphertext []byte
}

// errNotForMe marks a delivered message addressed to another recipient
// device: the header names its recipient, so a receiver drops it without
// touching the ratchet state it might otherwise consume.
var errNotForMe = errors.New("not addressed to this device")

// sealFor seals plaintext for one peer device over its session, creating
// the session — an X3DH initiation against a freshly fetched bundle — when
// this is the first message to that peer in that room.
func (c *Client) sealFor(ctx context.Context, room [16]byte, peer Peer, plaintext []byte) (encryptResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sessionKey{room: room, peer: peer.Device}
	s, ok := c.sessions[key]
	if !ok {
		var err error
		if s, err = c.initiateLocked(ctx, room, peer); err != nil {
			return encryptResult{}, err
		}
	}
	var pre *PrekeyHeader
	if s.first {
		pre = &s.pre
	}
	mid, err := newUUID()
	if err != nil {
		return encryptResult{}, err
	}
	// The message id is bound into the associated data, so it is reserved
	// here and returned for the publish frame to carry.
	ad := AD{
		Room:            room,
		Sender:          c.user,
		SenderDevice:    c.device,
		RecipientDevice: peer.Device,
		MessageID:       mid,
	}
	header, ciphertext, err := s.ratchet.Encrypt(plaintext, ad.Bytes(), c.device, peer.Device, pre)
	if err != nil {
		return encryptResult{}, fmt.Errorf("encrypt: %w", err)
	}
	if s.first {
		s.first = false
	}
	return encryptResult{MessageID: mid, Header: header, Ciphertext: ciphertext}, nil
}

// initiateLocked creates a session by running X3DH against the peer's
// bundle, fetched live. The caller holds c.mu.
func (c *Client) initiateLocked(ctx context.Context, room [16]byte, peer Peer) (*session, error) {
	b, err := c.fetchBundle(ctx, peer.User, peer.Device)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle for %s/%s: %w", format(peer.User), format(peer.Device), err)
	}
	if err := b.Verify(); err != nil {
		return nil, err
	}
	root, pre, err := Initiate(c.id, &b)
	if err != nil {
		return nil, err
	}
	var spk [32]byte
	copy(spk[:], b.SignedPrekey)
	r, err := NewInitiatorRatchet(root, spk)
	if err != nil {
		return nil, err
	}
	s := &session{peer: peer, ratchet: r, first: true, pre: pre}
	if b.OneTimePrekey != nil {
		s.usedOneTime = b.OneTimePrekey.ID
	}
	c.sessions[sessionKey{room: room, peer: peer.Device}] = s
	return s, nil
}

// errPending marks a message stashed until the session's first message
// arrives and establishes the session.
var errPending = errors.New("client: awaiting the session's first message")

// unseal decrypts one delivered message addressed to this device: it
// establishes the responding session on a session's first message, then
// runs the ratchet. The AD is rebuilt from the delivered frame's fields,
// so any tampered field breaks the AEAD check.
func (c *Client) unseal(room [16]byte, d deliver) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	h, err := decodeHeader(d.Header)
	if err != nil {
		return nil, err
	}
	// The header names the sending device, the session's routing key; a
	// delivered frame whose device_id disagrees with it is a tampered
	// stream. The AEAD additionally binds the frame's device_id.
	if h.device != d.SenderDevice {
		return nil, fmt.Errorf("decrypt: header names device %s, delivered from %s",
			format(h.device), format(d.SenderDevice))
	}
	key := sessionKey{room: room, peer: h.device}
	s, ok := c.sessions[key]
	if h.recipient != c.device {
		return nil, errNotForMe
	}
	if !ok {
		if !h.isPrekey() {
			// The session's first message commits after some of its
			// successors (publishes race for the room lock): stash this
			// one until the prekey message arrives and establishes the
			// session; the ratchet's skipped-key handling then orders
			// them.
			c.pending[key] = append(c.pending[key], d)
			return nil, errPending
		}
		if s, err = c.respondLocked(room, Peer{User: d.Sender, Device: d.SenderDevice}, h); err != nil {
			return nil, err
		}
	} else if h.isPrekey() && h.dh != s.ratchet.dhRemote {
		// A prekey header under a different ratchet key: the peer
		// re-initiated (a new session). The same header again — a
		// redelivery, or the honest copy after a tampered attempt —
		// decrypts over the session that was already established.
		if s, err = c.respondLocked(room, Peer{User: d.Sender, Device: d.SenderDevice}, h); err != nil {
			return nil, err
		}
	}
	ad := AD{
		Room:            room,
		Sender:          d.Sender,
		SenderDevice:    d.SenderDevice,
		RecipientDevice: c.device,
		MessageID:       d.MessageID,
	}
	return s.ratchet.Decrypt(d.Header, d.Ciphertext, ad.Bytes())
}

// respondLocked establishes the responding side of a session from a
// prekey header, consuming the named one-time prekey if there is one.
// The caller holds c.mu.
func (c *Client) respondLocked(room [16]byte, peer Peer, h ratchetHeader) (*session, error) {
	if h.pre == nil {
		return nil, errors.New("decrypt: not a prekey header")
	}
	if h.pre.SignedPrekeyID != c.spk.ID {
		return nil, fmt.Errorf("decrypt: header names signed prekey %d, hold %d", h.pre.SignedPrekeyID, c.spk.ID)
	}
	var opk *OneTimePrekey
	if h.pre.OneTimePrekeyID != 0 {
		p, ok := c.opkPrivs[h.pre.OneTimePrekeyID]
		if !ok {
			return nil, fmt.Errorf("decrypt: header names one-time prekey %d, none held", h.pre.OneTimePrekeyID)
		}
		opk = &p
	}
	root, err := Respond(c.id, c.spk, opk, *h.pre)
	if err != nil {
		return nil, err
	}
	r, err := NewResponderRatchet(root, c.spk, h.dh)
	if err != nil {
		return nil, err
	}
	s := &session{peer: peer, ratchet: r}
	if opk != nil {
		s.usedOneTime = opk.ID
		// Consumed: the server deleted it at fetch time; drop the private.
		delete(c.opkPrivs, opk.ID)
	}
	c.sessions[sessionKey{room: room, peer: peer.Device}] = s
	return s, nil
}

// newUUID generates a random v4-shaped UUID for a message id.
func newUUID() ([16]byte, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return u, fmt.Errorf("message id: %w", err)
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u, nil
}
