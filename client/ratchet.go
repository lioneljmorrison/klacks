package client

// The Double Ratchet, per the Signal specification (v1 reference), on
// HKDF-SHA256 and the envelope's ChaCha20-Poly1305. One ratchet per
// (room, peer device) direction pair: the initiator's ratchet starts with
// the X3DH root key and the responder's with the same root key.
//
// Headers are versioned, fixed-width frames; every field is big-endian:
//
//	0x02: version || dh(32) || pn(4) || n(4) || recipient(16) || device(16)
//	0x01: version || identity_ed(32) || identity_dh(32) ||
//	      ephemeral(32) || spk_id(8) || opk_id(8) || dh(32) ||
//	      pn(4) || n(4) || recipient(16) || device(16)
//
// recipient is the recipient device's UUID: the receiver skips messages
// addressed to another device before its ratchet sees them, so one member's
// copy of a room message cannot consume another member's ratchet state.
// device is the sending device's UUID, the routing key for the session; a
// delivered frame whose device_id differs from it is a tampered stream and
// is rejected before the session is touched. The header is authenticated
// (the envelope binds it into the AEAD) but not encrypted, as Signal's.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Ratchet header version and type bytes.
const (
	ratchetVersion        = 1
	headerNormal          = 0x02
	headerPrekey          = 0x01
	maxSkip        uint32 = 1000 // chain keys skipped silently before refusing
	skippedLimit          = 5000 // stored skipped message keys before refusing
)

// Root and chain KDF labels.
const (
	kdfRootInfo    = "klacks ratchet root v1"
	kdfMessageInfo = "klacks ratchet message v1"
)

// Ratchet is one Double Ratchet session's crypto state. It is not safe for
// concurrent use: a session serializes its sends and receives.
type Ratchet struct {
	RootKey   [32]byte
	dhSelf    [32]byte // our current ratchet key pair, private half
	dhSelfPub [32]byte
	dhRemote  [32]byte // peer's current ratchet public key
	ckSend    [32]byte // the send chain key; hasSend until started
	ckRecv    [32]byte // the receive chain key; hasRecv until started
	hasSend   bool
	hasRecv   bool
	nSend     uint32
	nRecv     uint32
	pn        uint32 // the previous send chain's length, for the header
	skipped   map[skippedID]MessageKey

	// cache holds recently decrypted messages by (ratchet key, chain
	// index), so an identical redelivery — the transport re-sends on
	// resume — decrypts to the same plaintext, while a replay with
	// different content (a tampered row, a spliced message) is refused.
	// Bounded: evicting the oldest keeps it flat.
	cache      map[skippedID]cacheEntry
	cacheOrder []skippedID
}

// cacheLimit bounds the decrypt cache.
const cacheLimit = 512

type cacheEntry struct {
	adHash [32]byte // sha256 of the associated data
	ctHash [32]byte // sha256 of the ciphertext
	pt     []byte
}

// skippedID names a skipped message key: (ratchet key, chain index).
type skippedID struct {
	dh [32]byte
	n  uint32
}

// NewInitiatorRatchet starts the initiator's ratchet from the X3DH root
// key: it takes a fresh ratchet key pair and runs the first DH ratchet
// step against the peer's signed prekey, producing the send chain.
func NewInitiatorRatchet(root [32]byte, peerSignedPrekey [32]byte) (*Ratchet, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("ratchet: key pair: %w", err)
	}
	pub, err := x25519Base(priv)
	if err != nil {
		return nil, err
	}
	r := &Ratchet{
		RootKey: root,
		dhSelf:  priv, dhSelfPub: pub,
		dhRemote: peerSignedPrekey,
		skipped:  make(map[skippedID]MessageKey),
		cache:    make(map[skippedID]cacheEntry),
	}
	// RK, CKs = KDF_RK(SK, DH(DHs, DHr)): the initiator can send at once.
	dh, err := x25519(priv, peerSignedPrekey)
	if err != nil {
		return nil, fmt.Errorf("ratchet: initial DH: %w", err)
	}
	nextRoot, ck, err := kdfRoot(root, dh)
	if err != nil {
		return nil, err
	}
	r.RootKey = nextRoot
	r.ckSend = ck
	r.hasSend = true
	return r, nil
}

// NewResponderRatchet starts the responder's ratchet from the X3DH root
// key: its ratchet key pair is the signed prekey the initiator used, and
// the remote key is the initiator's first ratchet key (from the first
// message's header), producing the receive chain.
func NewResponderRatchet(root [32]byte, signedPrekey SignedPrekey, dhRemote [32]byte) (*Ratchet, error) {
	pub, err := x25519Base(signedPrekey.Priv)
	if err != nil {
		return nil, err
	}
	r := &Ratchet{
		RootKey: root,
		dhSelf:  signedPrekey.Priv, dhSelfPub: pub,
		dhRemote: dhRemote,
		skipped:  make(map[skippedID]MessageKey),
		cache:    make(map[skippedID]cacheEntry),
	}
	// RK, CKr = KDF_RK(SK, DH(DHs, DHr)): the responder can receive at
	// once; it sends only after its first DH ratchet step.
	dh, err := x25519(signedPrekey.Priv, dhRemote)
	if err != nil {
		return nil, fmt.Errorf("ratchet: initial DH: %w", err)
	}
	nextRoot, ck, err := kdfRoot(root, dh)
	if err != nil {
		return nil, err
	}
	r.RootKey = nextRoot
	r.ckRecv = ck
	r.hasRecv = true
	return r, nil
}

// startSendChain gives a responder without a send chain one: a fresh
// ratchet key pair, RK' = KDF_RK(RK, DH(DHs', DHr)), CKs from the new root.
func (r *Ratchet) startSendChain() error {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return fmt.Errorf("ratchet: send key pair: %w", err)
	}
	pub, err := x25519Base(priv)
	if err != nil {
		return err
	}
	dh, err := x25519(priv, r.dhRemote)
	if err != nil {
		return fmt.Errorf("ratchet: send chain DH: %w", err)
	}
	root, ck, err := kdfRoot(r.RootKey, dh)
	if err != nil {
		return err
	}
	r.RootKey = root
	r.dhSelf, r.dhSelfPub = priv, pub
	r.ckSend = ck
	r.hasSend = true
	return nil
}

// kdfRoot mixes one DH output into the root key and returns the next root
// key and chain key: HKDF(salt = current root, ikm = DH output).
func kdfRoot(root [32]byte, dh [32]byte) (nextRoot, ck [32]byte, err error) {
	out, err := hkdfSHA256(root[:], dh[:], []byte(kdfRootInfo), 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("ratchet: root KDF: %w", err)
	}
	copy(nextRoot[:], out[:32])
	copy(ck[:], out[32:64])
	return nextRoot, ck, nil
}

// kdfChain is KDF_CK: one step of the chain key, producing the message key
// with its nonce derived alongside it, and the next chain key.
func kdfChain(ck [32]byte) (mk MessageKey, next [32]byte, err error) {
	out, err := hkdfSHA256(ck[:], make([]byte, 32), []byte(kdfMessageInfo), 44+32)
	if err != nil {
		return MessageKey{}, [32]byte{}, fmt.Errorf("ratchet: chain KDF: %w", err)
	}
	copy(mk.Key[:], out[:32])
	copy(mk.Nonce[:], out[32:44])
	copy(next[:], out[44:76])
	return mk, next, nil
}

// Encrypt advances the send chain one step and seals plaintext. pre carries
// the X3DH prelude on a session's first message and must be nil afterwards;
// sender and recipient are the sending and receiving devices' UUIDs.
func (r *Ratchet) Encrypt(plaintext, ad []byte, sender, recipient [16]byte, pre *PrekeyHeader) ([]byte, []byte, error) {
	if !r.hasSend {
		// The responder's first send: a send-side DH ratchet step. Its
		// root is the one both sides share after initialization, so the
		// initiator's next DH ratchet step (on receiving this header's
		// key) lands on the same chain.
		if err := r.startSendChain(); err != nil {
			return nil, nil, err
		}
	}
	mk, next, err := kdfChain(r.ckSend)
	if err != nil {
		return nil, nil, err
	}
	r.ckSend = next
	n := r.nSend
	r.nSend++

	var hdr []byte
	if pre != nil {
		hdr = encodePrekeyHeader(*pre, r.dhSelfPub, r.pn, n, sender, recipient)
	} else {
		hdr = encodeHeader(r.dhSelfPub, r.pn, n, sender, recipient)
	}
	ct, err := Seal(mk, plaintext, ad, hdr)
	if err != nil {
		return nil, nil, err
	}
	return hdr, ct, nil
}

// Decrypt opens a received message. Skipped messages (up to maxSkip in one
// chain) are decrypted from stashed message keys, so out-of-order delivery
// works; a message key is consumed exactly once.
//
// The whole step runs on a copy of the state and commits only on success:
// a tampered or malformed message leaves the ratchet untouched, so it
// cannot desynchronize the session. Replay of an already-consumed chain
// index is rejected: redeliveries are the transport's to dedupe by
// (seq, message_id) before they reach the ratchet.
func (r *Ratchet) Decrypt(header, ciphertext, ad []byte) ([]byte, error) {
	c := r.clone()
	pt, err := c.decrypt(header, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	*r = *c
	return pt, nil
}

// clone deep-copies the state, so a failed decrypt cannot leak into it.
func (r *Ratchet) clone() *Ratchet {
	c := *r
	c.skipped = make(map[skippedID]MessageKey, len(r.skipped))
	for k, v := range r.skipped {
		c.skipped[k] = v
	}
	c.cache = make(map[skippedID]cacheEntry, len(r.cache))
	for k, v := range r.cache {
		c.cache[k] = v
	}
	c.cacheOrder = append([]skippedID(nil), r.cacheOrder...)
	return &c
}

// decrypt is Decrypt's mutating body: it runs on a clone.
func (r *Ratchet) decrypt(header, ciphertext, ad []byte) ([]byte, error) {
	h, err := decodeHeader(header)
	if err != nil {
		return nil, err
	}
	// An identical replay of a decrypted message returns the same
	// plaintext; the same position with different content is refused.
	adSum := sha256.Sum256(ad)
	ctSum := sha256.Sum256(ciphertext)
	if e, ok := r.cache[skippedID{dh: h.dh, n: h.n}]; ok {
		if e.adHash == adSum && e.ctHash == ctSum {
			return e.pt, nil
		}
		return nil, fmt.Errorf("ratchet: replay of message %d with different content", h.n)
	}
	// A skipped message key decrypts this without advancing anything.
	if mk, ok := r.skipped[skippedID{dh: h.dh, n: h.n}]; ok {
		pt, err := Open(mk, ciphertext, ad, header)
		if err != nil {
			return nil, err
		}
		delete(r.skipped, skippedID{dh: h.dh, n: h.n})
		return r.remember(h, adSum, ctSum, pt), nil
	}
	if h.dh != r.dhRemote {
		// New ratchet key from the peer: stash the rest of the current
		// receive chain as skipped keys, then DH ratchet forward.
		if h.n > maxSkip {
			return nil, fmt.Errorf("ratchet: peer jumped %d ahead, over %d", h.n, maxSkip)
		}
		if err := r.skipMessageKeys(h.n); err != nil {
			return nil, err
		}
		if err := r.dhRatchet(h); err != nil {
			return nil, err
		}
	} else if h.n > r.nRecv {
		if h.n-r.nRecv > maxSkip {
			return nil, fmt.Errorf("ratchet: peer jumped %d ahead, over %d", h.n-r.nRecv, maxSkip)
		}
		if err := r.skipMessageKeys(h.n); err != nil {
			return nil, err
		}
	} else if h.n < r.nRecv {
		// Consumed in this chain and not in the decrypt cache: a replay
		// the ratchet cannot answer with its original plaintext.
		return nil, fmt.Errorf("ratchet: message %d of chain already consumed", h.n)
	}
	if !r.hasRecv {
		return nil, errors.New("ratchet: no receive chain")
	}
	mk, next, err := kdfChain(r.ckRecv)
	if err != nil {
		return nil, err
	}
	r.ckRecv = next
	r.nRecv++
	pt, err := Open(mk, ciphertext, ad, header)
	if err != nil {
		return nil, err
	}
	return r.remember(h, adSum, ctSum, pt), nil
}

// remember caches a decrypted message and returns the plaintext.
func (r *Ratchet) remember(h ratchetHeader, adSum, ctSum [32]byte, pt []byte) []byte {
	id := skippedID{dh: h.dh, n: h.n}
	if _, ok := r.cache[id]; !ok {
		r.cacheOrder = append(r.cacheOrder, id)
	}
	r.cache[id] = cacheEntry{adHash: adSum, ctHash: ctSum, pt: pt}
	for len(r.cacheOrder) > cacheLimit {
		delete(r.cache, r.cacheOrder[0])
		r.cacheOrder = r.cacheOrder[1:]
	}
	return pt
}

// skipMessageKeys stashes message keys 0..until-1 of the current receive
// chain, so later out-of-order arrivals decrypt. Callers pass until > nRecv;
// the guard makes the uint32 arithmetic safe regardless.
func (r *Ratchet) skipMessageKeys(until uint32) error {
	if !r.hasRecv || until <= r.nRecv {
		return nil
	}
	if len(r.skipped)+int(until-r.nRecv) > skippedLimit {
		return errors.New("ratchet: too many skipped message keys")
	}
	for r.nRecv < until {
		mk, next, err := kdfChain(r.ckRecv)
		if err != nil {
			return err
		}
		r.ckRecv = next
		r.skipped[skippedID{dh: r.dhRemote, n: r.nRecv}] = mk
		r.nRecv++
	}
	return nil
}

// dhRatchet performs a DH ratchet step on the peer's new key: the receive
// chain restarts under the new root, then a fresh send chain is started.
func (r *Ratchet) dhRatchet(h ratchetHeader) error {
	// RK, CKr = KDF_RK(RK, DH(DHs, DHr)).
	dh, err := x25519(r.dhSelf, h.dh)
	if err != nil {
		return fmt.Errorf("ratchet: DH step: %w", err)
	}
	root, ckRecv, err := kdfRoot(r.RootKey, dh)
	if err != nil {
		return err
	}
	r.RootKey = root
	r.ckRecv = ckRecv
	r.hasRecv = true
	r.nRecv = 0

	// A new send key pair; RK, CKs = KDF_RK(RK, DH(DHs', DHr)).
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return fmt.Errorf("ratchet: new send key: %w", err)
	}
	pub, err := x25519Base(priv)
	if err != nil {
		return err
	}
	r.dhSelf, r.dhSelfPub = priv, pub
	dh2, err := x25519(priv, h.dh)
	if err != nil {
		return fmt.Errorf("ratchet: DH step (send): %w", err)
	}
	root2, ckSend, err := kdfRoot(r.RootKey, dh2)
	if err != nil {
		return err
	}
	r.RootKey = root2
	r.pn = r.nSend
	r.ckSend = ckSend
	r.hasSend = true
	r.nSend = 0
	r.dhRemote = h.dh
	return nil
}

// ratchetHeader is a decoded header.
type ratchetHeader struct {
	dh        [32]byte
	pn, n     uint32
	recipient [16]byte
	device    [16]byte      // the sending device
	pre       *PrekeyHeader // set on prekey-type headers
}

func (h ratchetHeader) isPrekey() bool { return h.pre != nil }

func encodeHeader(dh [32]byte, pn, n uint32, sender, recipient [16]byte) []byte {
	out := make([]byte, 0, 2+32+4+4+16+16)
	out = append(out, ratchetVersion, headerNormal)
	out = append(out, dh[:]...)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], pn)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint32(b[:], n)
	out = append(out, b[:]...)
	out = append(out, recipient[:]...)
	out = append(out, sender[:]...)
	return out
}

// idToWire converts a prekey id to its big-endian 8 bytes. Ids are
// validated >= 1 at every entry point (bundle verification, key
// generation), so the conversion cannot lose information.
func idToWire(id int64) uint64 {
	if id < 0 {
		return 0
	}
	return uint64(id)
}

// wireToID is idToWire's inverse: a wire value above int64's range is a
// corrupted header.
func wireToID(u uint64) (int64, error) {
	if u > math.MaxInt64 {
		return 0, errors.New("prekey id out of range")
	}
	return int64(u), nil
}

func encodePrekeyHeader(pre PrekeyHeader, dh [32]byte, pn, n uint32, sender, recipient [16]byte) []byte {
	out := make([]byte, 0, 2+32*3+8+8+32+4+4+16+16)
	out = append(out, ratchetVersion, headerPrekey)
	out = append(out, pre.IdentityEd[:]...)
	out = append(out, pre.IdentityDH[:]...)
	out = append(out, pre.Ephemeral[:]...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], idToWire(pre.SignedPrekeyID))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], idToWire(pre.OneTimePrekeyID))
	out = append(out, b[:]...)
	out = append(out, dh[:]...)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], pn)
	out = append(out, c[:]...)
	binary.BigEndian.PutUint32(c[:], n)
	out = append(out, c[:]...)
	out = append(out, recipient[:]...)
	out = append(out, sender[:]...)
	return out
}

func decodeHeader(b []byte) (ratchetHeader, error) {
	fail := func(what string) error { return fmt.Errorf("ratchet: header: %s", what) }
	if len(b) < 2 || b[0] != ratchetVersion {
		return ratchetHeader{}, fail("unknown version")
	}
	h := ratchetHeader{}
	read32 := func(at int) ([32]byte, error) {
		var v [32]byte
		if len(b) < at+32 {
			return v, fail("truncated")
		}
		copy(v[:], b[at:at+32])
		return v, nil
	}
	u32 := func(at int) (uint32, error) {
		if len(b) < at+4 {
			return 0, fail("truncated")
		}
		return binary.BigEndian.Uint32(b[at : at+4]), nil
	}
	u64 := func(at int) (int64, error) {
		if len(b) < at+8 {
			return 0, fail("truncated")
		}
		return wireToID(binary.BigEndian.Uint64(b[at : at+8]))
	}
	copyRecipient := func(h *ratchetHeader, at int) error {
		if len(b) < at+16 {
			return fail("truncated")
		}
		copy(h.recipient[:], b[at:at+16])
		copy(h.device[:], b[at+16:at+32])
		return nil
	}
	switch b[1] {
	case headerNormal:
		dh, err := read32(2)
		if err != nil {
			return ratchetHeader{}, err
		}
		h.dh = dh
		pn, err := u32(34)
		if err != nil {
			return ratchetHeader{}, err
		}
		n, err := u32(38)
		if err != nil {
			return ratchetHeader{}, err
		}
		h.pn, h.n = pn, n
		if err := copyRecipient(&h, 42); err != nil {
			return ratchetHeader{}, err
		}
		return h, nil
	case headerPrekey:
		identityEd, err := read32(2)
		if err != nil {
			return ratchetHeader{}, err
		}
		identityDH, err := read32(34)
		if err != nil {
			return ratchetHeader{}, err
		}
		ek, err := read32(66)
		if err != nil {
			return ratchetHeader{}, err
		}
		spkID, err := u64(98)
		if err != nil {
			return ratchetHeader{}, err
		}
		opkID, err := u64(106)
		if err != nil {
			return ratchetHeader{}, err
		}
		dh, err := read32(114)
		if err != nil {
			return ratchetHeader{}, err
		}
		pn, err := u32(146)
		if err != nil {
			return ratchetHeader{}, err
		}
		n, err := u32(150)
		if err != nil {
			return ratchetHeader{}, err
		}
		h.pre = &PrekeyHeader{
			IdentityEd: identityEd, IdentityDH: identityDH, Ephemeral: ek,
			SignedPrekeyID: spkID, OneTimePrekeyID: opkID,
		}
		h.dh, h.pn, h.n = dh, pn, n
		if err := copyRecipient(&h, 154); err != nil {
			return ratchetHeader{}, err
		}
		return h, nil
	default:
		return ratchetHeader{}, fail("unknown type")
	}
}
