package client

// Session glue: one Double Ratchet session per (room, peer device) pair,
// and the encrypt/decrypt path that turns a room's plaintext into
// published envelopes and delivered envelopes back into plaintext.

import (
	"bytes"
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
	// initiator records whose X3DH initiation the session serves: the
	// initiating device's identity DH key and ephemeral key, both from
	// the session's prekey header (the device's own initiation uses its
	// own). Simultaneous initiations — both devices of a pair distribute
	// before either processes the other's message — are settled by a
	// deterministic tie-break on these, so both sides converge on one
	// active session; the losing sessions stay as receive-only fallbacks
	// while their in-flight messages arrive.
	initID  [32]byte
	initEph [32]byte
}

// sessionKey names a session: per room and per peer device.
type sessionKey struct {
	room [16]byte
	peer [16]byte // the peer's device
}

// fallbackKey names a receive-only fallback session: per room, per peer
// device, per initiation (the initiation's ephemeral key).
type fallbackKey struct {
	room    [16]byte
	peer    [16]byte
	initEph [32]byte
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
	s := &session{peer: peer, ratchet: r, first: true, pre: pre,
		initID: pre.IdentityDH, initEph: pre.Ephemeral}
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
	if h.isPrekey() {
		s, err = c.sessionForPrekey(room, key, d.Sender, h)
		if err != nil {
			return nil, err
		}
	} else {
		if !ok {
			// The session's first message commits after some of its
			// successors (publishes race for the room lock): stash this
			// one until the prekey message arrives and establishes the
			// session; the ratchet's skipped-key handling then orders
			// them.
			c.pending[key] = append(c.pending[key], d)
			return nil, errPending
		}
		if h.dh != s.ratchet.dhRemote {
			// Not the active session's chain: the peer may still be
			// sending over a session this device demoted in the
			// initiation tie-break — route by ratchet key. Anything
			// else is a legitimate DH ratchet step on the active
			// session.
			if fb, fok := c.fallbackByDH(room, key.peer, h.dh); fok {
				s = fb
			}
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

// sessionForPrekey resolves a prekey-header message to its session. A
// redelivered initiation decrypts where it was processed before; a new
// initiation competes with the active session in the deterministic
// tie-break — the lower (identity DH, ephemeral) initiation wins, the
// same verdict on both sides — and the loser becomes a receive-only
// fallback while its in-flight messages arrive. The caller holds c.mu.
func (c *Client) sessionForPrekey(room [16]byte, key sessionKey, sender [16]byte, h ratchetHeader) (*session, error) {
	if s, ok := c.sessions[key]; ok && s.initEph == h.pre.Ephemeral {
		return s, nil // redelivery of the active session's initiation
	}
	if s, ok := c.fallbacks[fallbackKey{room: room, peer: key.peer, initEph: h.pre.Ephemeral}]; ok {
		return s, nil // redelivery of a demoted session's initiation
	}
	ns, err := c.respondLocked(room, Peer{User: sender, Device: key.peer}, h)
	if err != nil {
		return nil, err
	}
	active, ok := c.sessions[key]
	if !ok || newcomerWins(*h.pre, active) {
		// The incoming initiation wins: it becomes active and the
		// demoted session keeps receiving while its messages arrive.
		if ok {
			c.addFallback(room, key.peer, active)
		}
		c.sessions[key] = ns
		return ns, nil
	}
	// The active session keeps its place; the loser receives only.
	c.addFallback(room, key.peer, ns)
	return ns, nil
}

// newcomerWins settles two competing X3DH initiations: the lower
// (identity DH key, ephemeral) pair wins, the same verdict on both sides.
// in is the incoming initiation; active records the one the active
// session was established by — the device's own when it initiated.
func newcomerWins(in PrekeyHeader, active *session) bool {
	if in.IdentityDH == active.initID {
		// The same initiator re-initiated: the comparison falls to the
		// ephemerals, deterministic on both sides.
		return bytes.Compare(in.Ephemeral[:], active.initEph[:]) < 0
	}
	if c := bytes.Compare(in.IdentityDH[:], active.initID[:]); c != 0 {
		return c < 0
	}
	return bytes.Compare(in.Ephemeral[:], active.initEph[:]) < 0
}

// addFallback stores a receive-only session for a peer and bounds the
// peer's fallbacks, evicting the oldest. The caller holds c.mu.
func (c *Client) addFallback(room [16]byte, peer [16]byte, s *session) {
	k := fallbackKey{room: room, peer: peer, initEph: s.initEph}
	if _, ok := c.fallbacks[k]; !ok {
		c.fallbackOrder = append(c.fallbackOrder, k)
	}
	c.fallbacks[k] = s
	var kept []fallbackKey
	perPeer := 0
	for i := len(c.fallbackOrder) - 1; i >= 0; i-- {
		fk := c.fallbackOrder[i]
		if fk.peer != peer || fk.room != room {
			continue
		}
		perPeer++
		if perPeer > fallbacksKept {
			delete(c.fallbacks, fk)
			continue
		}
		kept = append([]fallbackKey{fk}, kept...)
	}
	c.fallbackOrder = kept
}

// fallbackByDH finds a peer's fallback session whose remote ratchet key
// matches a delivered message's header key. The caller holds c.mu.
func (c *Client) fallbackByDH(room, peer [16]byte, dh [32]byte) (*session, bool) {
	for k, s := range c.fallbacks {
		if k.room == room && k.peer == peer && s.ratchet.dhRemote == dh {
			return s, true
		}
	}
	return nil, false
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
	// The session is returned uninstalled: the caller decides whether the
	// initiation's tie-break makes it active or a receive-only fallback.
	s := &session{peer: peer, ratchet: r,
		initID: h.pre.IdentityDH, initEph: h.pre.Ephemeral}
	if opk != nil {
		s.usedOneTime = opk.ID
		// Consumed: the server deleted it at fetch time; drop the private.
		delete(c.opkPrivs, opk.ID)
	}
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
