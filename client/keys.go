package client

// Long-term and prekey material. The identity key is Ed25519 and signs the
// bundle; its X25519 (Montgomery) form participates in X3DH's DHs. The
// Montgomery private key is derived from the Ed25519 seed — the clamped
// first 32 bytes of SHA-512(seed) — which is the standard XEdDSA identity
// conversion: for A = a·B (Edwards), the Montgomery u-coordinate of A is
// X25519(a, 9), so both forms share one scalar and no Edwards arithmetic
// is needed (see the S-22 decision log).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Key and signature sizes, matching the server's accepted shapes.
const (
	EdKeySize     = 32 // Ed25519 public key
	DHKeySize     = 32 // X25519 public key
	SignatureSize = 64 // Ed25519 signature
	EDPrivSize    = ed25519.PrivateKeySize
)

// IdentityKey is a device's long-term key pair: the Ed25519 signing key and
// the X25519 private key derived from its seed.
type IdentityKey struct {
	Ed ed25519.PrivateKey // 64 bytes: seed + public
	DH [32]byte           // X25519 private key
}

// NewIdentity generates a fresh identity key pair.
func NewIdentity() (IdentityKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return IdentityKey{}, fmt.Errorf("identity: %w", err)
	}
	return NewIdentityFromSeed(seed)
}

// NewIdentityFromSeed derives the identity key pair from an Ed25519 seed,
// so a device can reproduce its keys from stored secret material.
func NewIdentityFromSeed(seed []byte) (IdentityKey, error) {
	if len(seed) != ed25519.SeedSize {
		return IdentityKey{}, errors.New("identity: seed must be 32 bytes")
	}
	ed := ed25519.NewKeyFromSeed(seed)
	dh, err := dhFromSeed(seed)
	if err != nil {
		return IdentityKey{}, err
	}
	return IdentityKey{Ed: ed, DH: dh}, nil
}

// dhFromSeed is the identity's X25519 private key: the clamped SHA-512 of
// the Ed25519 seed.
func dhFromSeed(seed []byte) ([32]byte, error) {
	h := sha512.Sum512(seed)
	var dh [32]byte
	copy(dh[:], h[:32])
	dh[0] &= 248
	dh[31] &= 127
	dh[31] |= 64
	return dh, nil
}

// EdPublic returns the Ed25519 public key that signs the bundle.
func (k IdentityKey) EdPublic() ed25519.PublicKey { return k.Ed.Public().(ed25519.PublicKey) }

// DHPublic returns the identity's X25519 (Montgomery) public key.
func (k IdentityKey) DHPublic() ([32]byte, error) {
	return x25519Base(k.DH)
}

// x25519Base is X25519(priv, 9), the base-point DH.
func x25519Base(priv [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, fmt.Errorf("x25519: %w", err)
	}
	var pub [32]byte
	copy(pub[:], out)
	return pub, nil
}

// x25519 is the Diffie-Hellman function: X25519(priv, pub).
func x25519(priv, pub [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("x25519: %w", err)
	}
	var dh [32]byte
	copy(dh[:], out)
	return dh, nil
}

// SignedPrekey is the device's medium-term X25519 key pair. The id is per
// device, from 1, and goes in the bundle and in every initial message.
type SignedPrekey struct {
	ID   int64
	Priv [32]byte
	Pub  [32]byte
}

// NewSignedPrekey generates the prekey with the next id.
func NewSignedPrekey(id int64) (SignedPrekey, error) {
	if id < 1 {
		return SignedPrekey{}, errors.New("signed prekey id must be >= 1")
	}
	var p SignedPrekey
	p.ID = id
	if _, err := rand.Read(p.Priv[:]); err != nil {
		return SignedPrekey{}, fmt.Errorf("signed prekey: %w", err)
	}
	pub, err := x25519Base(p.Priv)
	if err != nil {
		return SignedPrekey{}, err
	}
	p.Pub = pub
	return p, nil
}

// OneTimePrekey is one single-use X25519 key pair. The server stores only
// the public half and deletes it on use; the private half stays here.
type OneTimePrekey struct {
	ID   int64
	Priv [32]byte
	Pub  [32]byte
}

// NewOneTimePrekeys generates n prekeys with ids from, from, from+1, …
func NewOneTimePrekeys(from, n int) ([]OneTimePrekey, error) {
	if from < 1 || n < 0 {
		return nil, errors.New("one-time prekeys: bad id range")
	}
	out := make([]OneTimePrekey, n)
	for i := range out {
		p := &out[i]
		p.ID = int64(from + i)
		if _, err := rand.Read(p.Priv[:]); err != nil {
			return nil, fmt.Errorf("one-time prekeys: %w", err)
		}
		pub, err := x25519Base(p.Priv)
		if err != nil {
			return nil, err
		}
		p.Pub = pub
	}
	return out, nil
}

// SignBundleKeys signs the bundle's X25519 keys — the identity's Montgomery
// form and the signed prekey, each length-prefixed so the encoding is
// unambiguous. The signature binds identity_dh_key to the identity: an
// attacker who swaps it must re-sign, which takes the identity key.
func (k IdentityKey) SignBundleKeys(identityDH, signedPrekey [32]byte) []byte {
	return ed25519.Sign(k.Ed, bundleKeysMessage(identityDH, signedPrekey))
}

// VerifyBundleKeys checks a bundle's signature.
func VerifyBundleKeys(edPub ed25519.PublicKey, identityDH, signedPrekey [32]byte, sig []byte) bool {
	return ed25519.Verify(edPub, bundleKeysMessage(identityDH, signedPrekey), sig)
}

// bundleKeysMessage is the signed bytes: length-prefixed keys.
func bundleKeysMessage(identityDH, signedPrekey [32]byte) []byte {
	msg := make([]byte, 0, 2*4+DHKeySize*2)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], DHKeySize)
	msg = append(msg, n[:]...)
	msg = append(msg, identityDH[:]...)
	msg = append(msg, n[:]...)
	msg = append(msg, signedPrekey[:]...)
	return msg
}

// hkdfSHA256 derives n bytes with HKDF-SHA256.
func hkdfSHA256(salt, ikm, info []byte, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, n)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}
