package client

// X3DH (Extended Triple Diffie-Hellman) session establishment, per the
// Signal specification's DH structure, with two format decisions (see the
// S-22 decision log): the identity's Montgomery form is uploaded as
// identity_dh_key and bound by the bundle signature, so every DH below is
// plain X25519; and the shared secret mixes a 32-byte 0xFF prefix, as the
// spec prescribes for Curve25519.

import (
	"crypto/rand"
	"fmt"
)

// x3dhInfo is the HKDF info label, versioned.
const x3dhInfo = "klacks X3DH v1"

// PrekeyHeader is the X3DH prelude the initiator sends in its first
// message: everything the responder needs to rebuild the shared secret.
// IdentityEd and IdentityDH are the initiator's identity public keys
// (Ed25519 and its Montgomery form); Ephemeral is a fresh X25519 key pair's
// public half, used for this session only.
type PrekeyHeader struct {
	IdentityEd      [32]byte
	IdentityDH      [32]byte
	Ephemeral       [32]byte
	SignedPrekeyID  int64
	OneTimePrekeyID int64 // 0 when no one-time prekey was used
}

// x3dh mixes the DH outputs in the spec's order — DH1(ik, spk),
// DH2(ek, ik), DH3(ek, spk), DH4(ek, opk), the last only when a one-time
// prekey was used — into the 32-byte root key.
func x3dh(dh1, dh2, dh3, dh4 *[32]byte) ([32]byte, error) {
	// F: for Curve25519, 32 bytes of 0xFF (the X3DH spec).
	sk := make([]byte, 0, DHKeySize+4*DHKeySize)
	sk = append(sk, make([]byte, DHKeySize)...)
	for i := range sk {
		sk[i] = 0xFF
	}
	for _, dh := range []*[32]byte{dh1, dh2, dh3, dh4} {
		if dh == nil {
			continue
		}
		sk = append(sk, dh[:]...)
	}
	out, err := hkdfSHA256(nil, sk, []byte(x3dhInfo), 32)
	if err != nil {
		return [32]byte{}, err
	}
	var root [32]byte
	copy(root[:], out)
	return root, nil
}

// Initiate runs X3DH as the initiator against a verified bundle and returns
// the ratchet root key and the prekey header the first message must carry.
// The bundle must already have passed Verify: this function does not check
// the signature again.
func Initiate(me IdentityKey, b *Bundle) (root [32]byte, pre PrekeyHeader, err error) {
	if err := b.Verify(); err != nil {
		return [32]byte{}, PrekeyHeader{}, err
	}
	var identityDH, spk [32]byte
	copy(identityDH[:], b.IdentityDHKey)
	copy(spk[:], b.SignedPrekey)

	// DH1 = DH(IK_me, SPK_peer): my identity's Montgomery private key with
	// the peer's signed prekey.
	dh1, err := x25519(me.DH, spk)
	if err != nil {
		return [32]byte{}, PrekeyHeader{}, fmt.Errorf("x3dh: DH1: %w", err)
	}
	// The fresh ephemeral.
	var ekPriv [32]byte
	if _, err := rand.Read(ekPriv[:]); err != nil {
		return [32]byte{}, PrekeyHeader{}, fmt.Errorf("x3dh: ephemeral: %w", err)
	}
	ekPub, err := x25519Base(ekPriv)
	if err != nil {
		return [32]byte{}, PrekeyHeader{}, err
	}
	// DH2 = DH(EK_me, IK_peer), DH3 = DH(EK_me, SPK_peer).
	dh2, err := x25519(ekPriv, identityDH)
	if err != nil {
		return [32]byte{}, PrekeyHeader{}, fmt.Errorf("x3dh: DH2: %w", err)
	}
	dh3, err := x25519(ekPriv, spk)
	if err != nil {
		return [32]byte{}, PrekeyHeader{}, fmt.Errorf("x3dh: DH3: %w", err)
	}
	// DH4 = DH(EK_me, OPK_peer), only when the bundle had one.
	var dh4 *[32]byte
	var opkID int64
	if b.OneTimePrekey != nil {
		var opk [32]byte
		copy(opk[:], b.OneTimePrekey.Key)
		if dh4, err = dhPtr(x25519(ekPriv, opk)); err != nil {
			return [32]byte{}, PrekeyHeader{}, fmt.Errorf("x3dh: DH4: %w", err)
		}
		opkID = b.OneTimePrekey.ID
	}
	root, err = x3dh(&dh1, &dh2, &dh3, dh4)
	if err != nil {
		return [32]byte{}, PrekeyHeader{}, err
	}
	pub, err := me.DHPublic()
	if err != nil {
		return [32]byte{}, PrekeyHeader{}, err
	}
	pre = PrekeyHeader{
		IdentityEd:      [32]byte(me.EdPublic()),
		IdentityDH:      pub,
		Ephemeral:       ekPub,
		SignedPrekeyID:  b.SignedPrekeyID,
		OneTimePrekeyID: opkID,
	}
	return root, pre, nil
}

// Respond runs X3DH as the responder on a received prekey header. spk must
// be the signed prekey whose id the header names; opk, when the header used
// one, must be the key pair whose id it names and is then consumed by the
// caller (the server deleted it at fetch time). It returns the same root
// key Initiate produced.
func Respond(me IdentityKey, spk SignedPrekey, opk *OneTimePrekey, pre PrekeyHeader) (root [32]byte, err error) {
	if pre.SignedPrekeyID != spk.ID {
		return [32]byte{}, fmt.Errorf("x3dh: header names signed prekey %d, hold %d", pre.SignedPrekeyID, spk.ID)
	}
	if pre.OneTimePrekeyID != 0 && (opk == nil || opk.ID != pre.OneTimePrekeyID) {
		return [32]byte{}, fmt.Errorf("x3dh: header names one-time prekey %d, hold %v",
			pre.OneTimePrekeyID, opk)
	}
	// DH1 = DH(IK_peer, SPK_me): my signed prekey private key with the
	// peer's Montgomery identity.
	dh1, err := x25519(spk.Priv, pre.IdentityDH)
	if err != nil {
		return [32]byte{}, fmt.Errorf("x3dh: DH1: %w", err)
	}
	// DH2 = DH(IK_me, EK_peer): my identity's Montgomery private key.
	dh2, err := x25519(me.DH, pre.Ephemeral)
	if err != nil {
		return [32]byte{}, fmt.Errorf("x3dh: DH2: %w", err)
	}
	dh3, err := x25519(spk.Priv, pre.Ephemeral)
	if err != nil {
		return [32]byte{}, fmt.Errorf("x3dh: DH3: %w", err)
	}
	var dh4 *[32]byte
	if pre.OneTimePrekeyID != 0 {
		if dh4, err = dhPtr(x25519(opk.Priv, pre.Ephemeral)); err != nil {
			return [32]byte{}, fmt.Errorf("x3dh: DH4: %w", err)
		}
	}
	root, err = x3dh(&dh1, &dh2, &dh3, dh4)
	if err != nil {
		return [32]byte{}, err
	}
	return root, nil
}

// dhPtr returns a pointer to v, nil when err is set — the shape x3dh wants.
func dhPtr(dh [32]byte, err error) (*[32]byte, error) {
	if err != nil {
		return nil, err
	}
	return &dh, nil
}
