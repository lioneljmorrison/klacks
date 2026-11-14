package client

// The prekey bundle a device uploads and a peer fetches, with verification.
// This is the format's client-side definition; the server validates shapes
// only (internal/store/devices.go mirrors the sizes).

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Bundle is a fetched prekey bundle. UserID and DeviceID are the canonical
// UUID strings naming the device it belongs to.
type Bundle struct {
	UserID   string
	DeviceID string

	IdentityKey            []byte // Ed25519 public key, 32 bytes
	IdentityDHKey          []byte // X25519 (Montgomery) form, 32 bytes
	SignedPrekeyID         int64
	SignedPrekey           []byte // X25519 public key, 32 bytes
	SignedPrekeySignature  []byte // Ed25519 signature, 64 bytes
	SignedPrekeyCreateTime []byte // reserved; the server does not return it yet

	// OneTimePrekey is the one-time prekey the fetch consumed (S-23); nil
	// when the device had none, in which case X3DH runs without its final
	// DH. OneTimePrekeysRemaining is the count left after the fetch: below
	// the device's low watermark, the device should replenish.
	OneTimePrekey           *Prekey
	OneTimePrekeysRemaining int
}

// Prekey is one one-time prekey.
type Prekey struct {
	ID  int64
	Key []byte // X25519 public key, 32 bytes
}

// Verify checks the bundle's shapes and its signature: the identity key
// must have signed the bundle's X25519 keys. A failed verify is fatal for
// the peer: the fetcher refuses to initiate with it.
func (b *Bundle) Verify() error {
	switch {
	case len(b.IdentityKey) != EdKeySize:
		return fmt.Errorf("bundle: identity key is %d bytes, want %d", len(b.IdentityKey), EdKeySize)
	case len(b.IdentityDHKey) != DHKeySize:
		return fmt.Errorf("bundle: identity DH key is %d bytes, want %d", len(b.IdentityDHKey), DHKeySize)
	case len(b.SignedPrekey) != DHKeySize:
		return fmt.Errorf("bundle: signed prekey is %d bytes, want %d", len(b.SignedPrekey), DHKeySize)
	case len(b.SignedPrekeySignature) != SignatureSize:
		return fmt.Errorf("bundle: signature is %d bytes, want %d", len(b.SignedPrekeySignature), SignatureSize)
	case b.SignedPrekeyID < 1:
		return fmt.Errorf("bundle: signed prekey id %d < 1", b.SignedPrekeyID)
	case b.OneTimePrekey != nil && len(b.OneTimePrekey.Key) != DHKeySize:
		return fmt.Errorf("bundle: one-time prekey is %d bytes, want %d", len(b.OneTimePrekey.Key), DHKeySize)
	}
	var identityDH, spk [32]byte
	copy(identityDH[:], b.IdentityDHKey)
	copy(spk[:], b.SignedPrekey)
	if !VerifyBundleKeys(ed25519.PublicKey(b.IdentityKey), identityDH, spk, b.SignedPrekeySignature) {
		return errors.New("bundle: signature does not verify")
	}
	return nil
}

// Wire shapes for the prekey REST endpoints; the transport marshals them.

// wirePrekey is one entry of a one_time_prekeys list.
type wirePrekey struct {
	ID  int64  `json:"id"`
	Key []byte `json:"key"`
}

// wireBundle is a GET /v1/users/{user}/devices/{device}/bundle response.
type wireBundle struct {
	UserID                  string      `json:"user_id"`
	DeviceID                string      `json:"device_id"`
	IdentityKey             []byte      `json:"identity_key"`
	IdentityDHKey           []byte      `json:"identity_dh_key"`
	SignedPrekeyID          int64       `json:"signed_prekey_id"`
	SignedPrekey            []byte      `json:"signed_prekey"`
	SignedPrekeySignature   []byte      `json:"signed_prekey_signature"`
	OneTimePrekey           *wirePrekey `json:"one_time_prekey,omitempty"`
	OneTimePrekeysRemaining int         `json:"one_time_prekeys_remaining"`
}

func (w wireBundle) bundle() Bundle {
	b := Bundle{
		UserID:                  w.UserID,
		DeviceID:                w.DeviceID,
		IdentityKey:             w.IdentityKey,
		IdentityDHKey:           w.IdentityDHKey,
		SignedPrekeyID:          w.SignedPrekeyID,
		SignedPrekey:            w.SignedPrekey,
		SignedPrekeySignature:   w.SignedPrekeySignature,
		OneTimePrekeysRemaining: w.OneTimePrekeysRemaining,
	}
	if w.OneTimePrekey != nil {
		b.OneTimePrekey = &Prekey{ID: w.OneTimePrekey.ID, Key: w.OneTimePrekey.Key}
	}
	return b
}
