package client

// The Sender Key scheme (S-27, S-28), per Signal's group messaging
// (libsignal's SenderChainKey, SenderMessageKey, GroupCipher, with the
// distribution message from SenderKeyDistributionMessage): each member
// device generates one chain per room and distributes it pairwise over the
// existing Double Ratchet sessions; group messages are then encrypted once
// under the sender's chain and broadcast as a single ciphertext.
//
// Chain derivation follows libsignal's ratchet exactly, one step per
// message:
//
//	message key seed = HMAC-SHA256(chainKey, 0x01)
//	next chain key   = HMAC-SHA256(chainKey, 0x02)
//	message key      = HKDF-SHA256(ikm = seed, salt = 0, info = label, 44)
//	                   → key(32) + nonce(12), so a (key, nonce) pair is
//	                   drawn once per chain step and never repeats
//
// Deviations from libsignal, both deliberate and documented in
// docs/protocol.md: the AEAD is ChaCha20-Poly1305 (klacks' envelope
// primitive) instead of AES-CBC+HMAC, and the associated data is the same
// fixed-width AD the 1:1 envelope binds, with the recipient device zero for
// the broadcast copy. The distribution payload is prefixed with a magic tag
// so a pairwise message that carries one is recognizable after decryption.
//
// A group message's header is the publish frame's header field:
//
//	version(1) || type 0x03(1) || key id(4) || iteration(4) || signature(64)
//
// The signature is Ed25519 under the chain's signing key, over
// header[:10] || ciphertext: everyone holding the sender key could
// otherwise forge that sender's messages, and the signing key proves the
// message came from the distributing device. The AEAD associated data is
// AD || header[:10] — the signature signs the prefix and the ciphertext, so
// the signature cannot be inside the AEAD's input; the prefix alone goes in.

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ratchetVersion (ratchet.go) is shared: one wire version byte.
	skTypeMessage = 0x03 // header type byte: a sender-key group message

	// skDistMagic prefixes a distribution payload inside a pairwise
	// message's plaintext. An application plaintext that begins with it
	// would be read as a distribution; the tag is what makes the two
	// distinguishable after the ratchet opens the envelope.
	skDistMagic = "skd1"

	// skMaxSkip caps how far ahead of the installed chain a message may
	// be, in chain steps: libsignal's GroupCipher limit.
	skMaxSkip uint32 = 2000

	// skStatesKept bounds the installed chains per sender device: recent
	// rotations stay decryptable while late messages from them arrive;
	// older ones drop.
	skStatesKept = 4

	// skCacheLimit bounds each chain's redelivery cache, as the Double
	// Ratchet's does.
	skCacheLimit = 512

	// skPendingLimit bounds the group messages stashed per sender device
	// while its distribution is still in flight.
	skPendingLimit = 64

	kdfSenderKeyMessage = "klacks sender key message v1"
)

// errSenderKeyUnknown marks a group message whose key id has no installed
// chain: the caller stashes it until the chain's distribution arrives.
var errSenderKeyUnknown = errors.New("sender key: no installed chain with this key id")

// errTooManyPending marks a group message dropped because its sender
// device's pending stash is full: no distribution ever arrived for the
// chains those messages use.
var errTooManyPending = errors.New("sender key: too many messages pending the chain's distribution")

// SenderKey is a distribution payload: what a sender device shares so the
// other members can decrypt its group chain from Iteration forward.
type SenderKey struct {
	KeyID     uint32
	Iteration uint32
	ChainKey  [32]byte
	Signing   ed25519.PublicKey
}

// SenderChain is one member device's sending half for one room: the chain
// that ratchets once per group message, and the Ed25519 key that signs
// them. Not safe for concurrent use; the client serializes its sends.
type SenderChain struct {
	KeyID     uint32
	iteration uint32
	chainKey  [32]byte
	signing   ed25519.PrivateKey
}

// NewSenderChain generates a fresh chain: random key id and chain key, and
// a fresh Ed25519 signing pair.
func NewSenderChain() (*SenderChain, error) {
	var ck [32]byte
	if _, err := rand.Read(ck[:]); err != nil {
		return nil, fmt.Errorf("sender key: chain key: %w", err)
	}
	var id [4]byte
	// Key id 0 is refused on install (a corrupt-distribution guard), so a
	// fresh chain never draws it.
	for binary.BigEndian.Uint32(id[:]) == 0 {
		if _, err := rand.Read(id[:]); err != nil {
			return nil, fmt.Errorf("sender key: key id: %w", err)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sender key: signing pair: %w", err)
	}
	return &SenderChain{
		KeyID:     binary.BigEndian.Uint32(id[:]),
		chainKey:  ck,
		signing:   priv,
		iteration: 0,
	}, nil
}

// Distribution returns the payload to distribute pairwise.
func (s *SenderChain) Distribution() SenderKey {
	return SenderKey{
		KeyID:     s.KeyID,
		Iteration: s.iteration,
		ChainKey:  s.chainKey,
		Signing:   s.signing.Public().(ed25519.PublicKey),
	}
}

// hmacSHA256 is HMAC-SHA256(key, msg).
func hmacSHA256(key, msg []byte) [32]byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// messageKey derives the group message key at one chain step: the seed is
// HMAC(chainKey, 0x01), the key and nonce split HKDF's output. The next
// chain step is HMAC(chainKey, 0x02).
func messageKey(chainKey [32]byte) (mk MessageKey, next [32]byte) {
	seed := hmacSHA256(chainKey[:], []byte{0x01})
	out, err := hkdfSHA256(make([]byte, 32), seed[:], []byte(kdfSenderKeyMessage), 32+12)
	if err != nil {
		// hkdf.Read on a 44-byte output from SHA-256 never fails.
		panic("sender key: message key KDF: " + err.Error())
	}
	copy(mk.Key[:], out[:32])
	copy(mk.Nonce[:], out[32:44])
	return mk, hmacSHA256(chainKey[:], []byte{0x02})
}

// marshalSenderKeyDistribution encodes a distribution payload:
// magic(4) || key id(4) || iteration(4) || chain key(32) || signing(32).
func marshalSenderKeyDistribution(k SenderKey) []byte {
	out := make([]byte, 0, 4+4+4+32+32)
	out = append(out, skDistMagic...)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], k.KeyID)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint32(b[:], k.Iteration)
	out = append(out, b[:]...)
	out = append(out, k.ChainKey[:]...)
	out = append(out, k.Signing...)
	return out
}

// unmarshalSenderKeyDistribution parses one. Only fixed-width, magic-prefixed
// payloads parse.
func unmarshalSenderKeyDistribution(b []byte) (SenderKey, error) {
	if len(b) != 4+4+4+32+32 || string(b[:4]) != skDistMagic {
		return SenderKey{}, errors.New("sender key: not a distribution payload")
	}
	var k SenderKey
	k.KeyID = binary.BigEndian.Uint32(b[4:8])
	k.Iteration = binary.BigEndian.Uint32(b[8:12])
	copy(k.ChainKey[:], b[12:44])
	k.Signing = ed25519.PublicKey(append([]byte(nil), b[44:76]...))
	return k, nil
}

// skHeaderPrefix is a group message header's signature-free prefix:
// version(1) || type 0x03(1) || key id(4) || iteration(4).
const skHeaderPrefix = 10

func isSenderKeyMessage(header []byte) bool {
	return len(header) >= 2 && header[0] == ratchetVersion && header[1] == skTypeMessage
}

// encodeSKHeaderPrefix builds the signature-free header prefix.
func encodeSKHeaderPrefix(keyID, iteration uint32) []byte {
	out := make([]byte, 0, skHeaderPrefix)
	out = append(out, ratchetVersion, skTypeMessage)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], keyID)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint32(b[:], iteration)
	out = append(out, b[:]...)
	return out
}

// decodeSKHeader splits a group message header into its prefix and its
// trailing Ed25519 signature, and returns the key id and iteration.
func decodeSKHeader(header []byte) (prefix, sig []byte, keyID, iteration uint32, err error) {
	if !isSenderKeyMessage(header) {
		return nil, nil, 0, 0, errors.New("sender key: not a group message header")
	}
	if len(header) < skHeaderPrefix+SignatureSize {
		return nil, nil, 0, 0, fmt.Errorf("sender key: header is %d bytes, want %d",
			len(header), skHeaderPrefix+SignatureSize)
	}
	prefix = header[:skHeaderPrefix]
	sig = header[skHeaderPrefix:]
	keyID = binary.BigEndian.Uint32(header[2:6])
	iteration = binary.BigEndian.Uint32(header[6:10])
	return prefix, sig, keyID, iteration, nil
}

// skState is one installed chain from a sender device: the distribution's
// material, the skipped message keys for out-of-order arrivals, and the
// redelivery cache.
type skState struct {
	keyID     uint32
	iteration uint32
	chainKey  [32]byte
	signing   ed25519.PublicKey
	skipped   map[uint32]MessageKey
	cache     map[uint32]skCacheEntry
	cacheOnce []uint32 // insertion order, for cache eviction
}

type skCacheEntry struct {
	adHash [32]byte
	ctHash [32]byte
	pt     []byte
}

// SenderKeys is one sender device's installed chains in one room: the
// current distribution, plus recent rotations kept decryptable while their
// late messages arrive.
type SenderKeys struct {
	states []*skState // newest last
}

// NewSenderKeys returns an empty set.
func NewSenderKeys() *SenderKeys { return &SenderKeys{} }

// Install adds a distribution. Installing the same payload again is a
// no-op (redelivery); the same key id with different material is a
// conflict and is refused, leaving the installed state intact. Bounded:
// beyond skStatesKept states the oldest drops.
func (r *SenderKeys) Install(k SenderKey) error {
	if k.KeyID == 0 {
		return errors.New("sender key: key id 0 is not installable")
	}
	for _, s := range r.states {
		if s.keyID != k.KeyID {
			continue
		}
		if s.iteration != k.Iteration || s.chainKey != k.ChainKey || !equalPub(s.signing, k.Signing) {
			return fmt.Errorf("sender key: key id %d installed with different material", k.KeyID)
		}
		return nil // identical redelivery
	}
	s := &skState{
		keyID:     k.KeyID,
		iteration: k.Iteration,
		chainKey:  k.ChainKey,
		signing:   k.Signing,
		skipped:   make(map[uint32]MessageKey),
		cache:     make(map[uint32]skCacheEntry),
	}
	r.states = append(r.states, s)
	if len(r.states) > skStatesKept {
		r.states = r.states[len(r.states)-skStatesKept:]
	}
	return nil
}

func equalPub(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// state returns the installed chain with keyID.
func (r *SenderKeys) state(keyID uint32) *skState {
	for _, s := range r.states {
		if s.keyID == keyID {
			return s
		}
	}
	return nil
}

// Decrypt opens one group message from this sender device: signature first,
// then the chain step at the header's iteration, then the AEAD with the AD
// the caller rebuilt from the delivered frame. Like the Double Ratchet, the
// whole step runs on a copy of the state and commits only on success, so a
// tampered message cannot desynchronize the chain, and an identical
// redelivery returns its original plaintext while different content at the
// same position is refused.
func (r *SenderKeys) Decrypt(header, ciphertext, ad []byte) ([]byte, error) {
	prefix, sig, keyID, iteration, err := decodeSKHeader(header)
	if err != nil {
		return nil, err
	}
	s := r.state(keyID)
	if s == nil {
		return nil, fmt.Errorf("%w: %d", errSenderKeyUnknown, keyID)
	}
	if !ed25519.Verify(s.signing, append(append([]byte(nil), prefix...), ciphertext...), sig) {
		return nil, errors.New("sender key: bad signature")
	}
	c := s.clone()
	pt, err := c.open(iteration, ciphertext, ad, prefix)
	if err != nil {
		return nil, err
	}
	*s = *c
	return pt, nil
}

// clone deep-copies one state so a failed decrypt cannot leak into it.
func (s *skState) clone() *skState {
	c := *s
	c.skipped = make(map[uint32]MessageKey, len(s.skipped))
	for k, v := range s.skipped {
		c.skipped[k] = v
	}
	c.cache = make(map[uint32]skCacheEntry, len(s.cache))
	for k, v := range s.cache {
		c.cache[k] = v
	}
	c.cacheOnce = append([]uint32(nil), s.cacheOnce...)
	return &c
}

// open derives the message key at iteration — stashing the keys it skips —
// and opens the ciphertext. Called on a clone.
func (s *skState) open(iteration uint32, ciphertext, ad, prefix []byte) ([]byte, error) {
	// An identical redelivery returns the original plaintext; different
	// content at the same chain position is refused.
	adSum := sha256.Sum256(ad)
	ctSum := sha256.Sum256(ciphertext)
	if e, ok := s.cache[iteration]; ok {
		if e.adHash == adSum && e.ctHash == ctSum {
			return e.pt, nil
		}
		return nil, fmt.Errorf("sender key: replay of iteration %d with different content", iteration)
	}
	if iteration < s.iteration {
		if mk, ok := s.skipped[iteration]; ok {
			pt, err := Open(mk, ciphertext, ad, prefix)
			if err != nil {
				return nil, err
			}
			delete(s.skipped, iteration)
			return s.remember(iteration, adSum, ctSum, pt), nil
		}
		return nil, fmt.Errorf("sender key: iteration %d already consumed", iteration)
	}
	if iteration-s.iteration > skMaxSkip {
		return nil, fmt.Errorf("sender key: chain jumped %d ahead, over %d",
			iteration-s.iteration, skMaxSkip)
	}
	for s.iteration < iteration {
		mk, next := messageKey(s.chainKey)
		s.skipped[s.iteration] = mk
		s.chainKey = next
		s.iteration++
	}
	mk, next := messageKey(s.chainKey)
	s.chainKey = next
	s.iteration++
	pt, err := Open(mk, ciphertext, ad, prefix)
	if err != nil {
		return nil, err
	}
	return s.remember(iteration, adSum, ctSum, pt), nil
}

// remember caches a decrypted message for redelivery and returns it.
func (s *skState) remember(iteration uint32, adSum, ctSum [32]byte, pt []byte) []byte {
	if _, ok := s.cache[iteration]; !ok {
		s.cacheOnce = append(s.cacheOnce, iteration)
	}
	s.cache[iteration] = skCacheEntry{adHash: adSum, ctHash: ctSum, pt: pt}
	for len(s.cacheOnce) > skCacheLimit {
		delete(s.cache, s.cacheOnce[0])
		s.cacheOnce = s.cacheOnce[1:]
	}
	return pt
}

// Encrypt seals one group message under the chain: the message key at the
// current step, the AEAD with ad (the caller's AD bytes) and the header
// prefix, then the Ed25519 signature over prefix || ciphertext. The header
// field carries prefix || signature. The chain advances one step.
func (s *SenderChain) Encrypt(plaintext, ad []byte) (header, ciphertext []byte, err error) {
	mk, next := messageKey(s.chainKey)
	iteration := s.iteration
	s.chainKey = next
	s.iteration++
	prefix := encodeSKHeaderPrefix(s.KeyID, iteration)
	ct, err := Seal(mk, plaintext, ad, prefix)
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(s.signing, append(append([]byte(nil), prefix...), ct...))
	return append(append([]byte(nil), prefix...), sig...), ct, nil
}

// skRef keys per-sender-device sender-key state: room and the sending
// device, exactly as the pairwise sessions are keyed.
type skRef struct {
	room   [16]byte
	device [16]byte
}

// sealDistribution seals this device's distribution payload for one peer
// device over their pairwise session, creating this device's chain for the
// room first when it has none. The caller publishes the result.
func (c *Client) sealDistribution(ctx context.Context, room [16]byte, peer Peer) (encryptResult, error) {
	c.mu.Lock()
	if c.skOwn[room] == nil {
		ch, err := NewSenderChain()
		if err != nil {
			c.mu.Unlock()
			return encryptResult{}, err
		}
		c.skOwn[room] = ch
	}
	pt := marshalSenderKeyDistribution(c.skOwn[room].Distribution())
	c.mu.Unlock()
	return c.sealFor(ctx, room, peer, pt)
}

// installDistribution installs a received distribution and decrypts
// whatever group messages were stashed waiting for it. A conflicting
// distribution — the same key id with different material, which no honest
// sender produces — is reported as a rejected message; the installed state
// stays untouched.
func (c *Client) installDistribution(d deliver, k SenderKey) {
	key := skRef{room: d.Room, device: d.SenderDevice}
	c.mu.Lock()
	r, ok := c.skPeers[key]
	if !ok {
		r = NewSenderKeys()
		c.skPeers[key] = r
	}
	err := r.Install(k)
	c.mu.Unlock()
	if err != nil {
		c.inbox(Received{
			Room: d.Room, Sender: d.Sender, SenderDevice: d.SenderDevice,
			MessageID: d.MessageID, Err: err,
		})
		return
	}
	for _, pd := range c.takeGroupPending(d.Room, d.SenderDevice) {
		c.groupDeliver(pd, false)
	}
}

// takeGroupPending returns and clears the group messages stashed for a
// sender device.
func (c *Client) takeGroupPending(room, senderDevice [16]byte) []deliver {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := skRef{room: room, device: senderDevice}
	out := c.skPending[key]
	delete(c.skPending, key)
	return out
}

// groupAD rebuilds a group message's associated data from the delivered
// frame, with the recipient device zero: the broadcast copy binds no
// single recipient (see docs/protocol.md).
func groupAD(d deliver) AD {
	return AD{
		Room:         d.Room,
		Sender:       d.Sender,
		SenderDevice: d.SenderDevice,
		MessageID:    d.MessageID,
	}
}

// decryptGroup decrypts one group message under the sender device's
// installed chain. With no chain yet — the distribution is still in flight
// — the message is stashed (bounded) and the unknown-key sentinel
// returned; the caller stays silent about it.
func (c *Client) decryptGroup(d deliver) ([]byte, error) {
	key := skRef{room: d.Room, device: d.SenderDevice}
	c.mu.Lock()
	r, ok := c.skPeers[key]
	if !ok {
		if n := len(c.skPending[key]); n >= skPendingLimit {
			c.mu.Unlock()
			return nil, errTooManyPending
		}
		c.skPending[key] = append(c.skPending[key], d)
		c.mu.Unlock()
		return nil, errSenderKeyUnknown
	}
	c.mu.Unlock()
	ad := groupAD(d)
	return r.Decrypt(d.Header, d.Ciphertext, ad.Bytes())
}

// groupDeliver runs one ordering-checked group message through the chain
// and emits the outcome. The sender's own echo is silent (it knows its
// plaintext); a stashed message is silent; anything else lands on Inbox.
func (c *Client) groupDeliver(d deliver, redelivery bool) {
	if d.SenderDevice == c.device {
		return
	}
	pt, err := c.decryptGroup(d)
	switch {
	case errors.Is(err, errSenderKeyUnknown):
		return // stashed pending the distribution
	case err != nil:
		c.inbox(Received{
			Room: d.Room, Seq: d.Seq, Sender: d.Sender,
			SenderDevice: d.SenderDevice, MessageID: d.MessageID, Err: err,
		})
		c.ack(d.Room, d.Seq)
		return
	case redelivery:
		// Already delivered once and it re-verifies: stay silent.
		c.ack(d.Room, d.Seq)
		return
	}
	c.inbox(Received{
		Room: d.Room, Seq: d.Seq, Sender: d.Sender,
		SenderDevice: d.SenderDevice, MessageID: d.MessageID, Plaintext: pt,
	})
	c.ack(d.Room, d.Seq)
}

// sealGroup encrypts one group message once under this device's chain for
// the room, as the single ciphertext the publish broadcasts. The chain
// must already have been distributed; without one the send fails.
func (c *Client) sealGroup(room [16]byte, plaintext []byte) (encryptResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.skOwn[room]
	if !ok {
		return encryptResult{}, errors.New("client: no sender key for this room: distribute first")
	}
	mid, err := newUUID()
	if err != nil {
		return encryptResult{}, err
	}
	// The message id is bound into the associated data, as the pairwise
	// envelope binds it; the recipient device is zero for a broadcast.
	ad := AD{
		Room:         room,
		Sender:       c.user,
		SenderDevice: c.device,
		MessageID:    mid,
	}
	header, ciphertext, err := ch.Encrypt(plaintext, ad.Bytes())
	if err != nil {
		return encryptResult{}, fmt.Errorf("group encrypt: %w", err)
	}
	return encryptResult{MessageID: mid, Header: header, Ciphertext: ciphertext}, nil
}
