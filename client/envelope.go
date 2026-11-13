package client

// The AEAD message envelope (S-25).
//
// REVIEW GATE: any change to this file changes the wire format that other
// implementations interoperate with and the security envelope every message
// travels in. It requires a code review that states the (key, nonce) reuse
// and associated-data consequences of the change. Do not drive-by-edit.

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EnvelopeVersion is the envelope's version byte, the first byte of its
// associated data. A change that breaks interop bumps it.
const EnvelopeVersion = 1

// adSize is the associated data's fixed width: the version byte plus five
// 16-byte IDs. Fixed width, not concatenation, so field boundaries are
// unambiguous and no parser is needed.
const adSize = 1 + 5*16

// AD is the envelope's associated data, bound into every AEAD computation.
// Tampering with any bound field — in the database, on the wire, anywhere —
// makes verification fail:
//
//	version(1) || room_id(16) || sender_id(16) || sender_device_id(16) ||
//	recipient_device_id(16) || message_id(16)
//
// Why these fields and not the plan's original four (room || sender ||
// device || seq), resolved in the S-25 decision log:
//
//   - recipient_device_id is bound so a receiver skips messages addressed
//     to another of its peer's recipients before touching its ratchet
//     state; without it, a stray group copy could corrupt a session.
//   - message_id is bound instead of seq because seq is assigned by the
//     server after the WS publish is sent: the sender cannot know it when
//     it encrypts. The client-generated message_id is stored with the
//     message and echoed in every deliver, so it is authenticated on
//     arrival just like the rest.
//   - seq is verified separately, against the room's per-room ordering
//     promise the server owns (gap-free, strictly increasing, one message
//     per seq): tampering with a stored seq shows up as a gap or a
//     duplicate message_id and the client rejects the stream.
type AD struct {
	Room            [16]byte
	Sender          [16]byte // the sending user
	SenderDevice    [16]byte // the sending device
	RecipientDevice [16]byte
	MessageID       [16]byte
}

// Bytes returns the AD's fixed-width encoding.
func (a AD) Bytes() []byte {
	out := make([]byte, 0, adSize)
	out = append(out, EnvelopeVersion)
	out = append(out, a.Room[:]...)
	out = append(out, a.Sender[:]...)
	out = append(out, a.SenderDevice[:]...)
	out = append(out, a.RecipientDevice[:]...)
	out = append(out, a.MessageID[:]...)
	if len(out) != adSize {
		panic("envelope: associated data size changed")
	}
	return out
}

// MessageKey is one message's AEAD key with the nonce derived alongside it.
// Both come from the same KDF step of the ratchet chain, so a (key, nonce)
// pair is never reused: message keys are unique per ratchet step, and each
// key's nonce is drawn from that key's material, not from a counter that
// could collide across chains.
type MessageKey struct {
	Key   [32]byte
	Nonce [12]byte
}

// Seal encrypts plaintext under key, binding ad and the ratchet header
// bytes into the AEAD associated data (ad || header), so the header — the
// ratchet's routing state — is authenticated too.
func Seal(key MessageKey, plaintext, ad, header []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key.Key[:])
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	aad := make([]byte, 0, len(ad)+len(header))
	aad = append(aad, ad...)
	aad = append(aad, header...)
	return aead.Seal(nil, key.Nonce[:], plaintext, aad), nil
}

// Open decrypts ciphertext sealed by Seal. chacha20poly1305's Open already
// prefers failure to plaintext on any mismatch, but a nil-plaintext check
// makes the contract explicit for callers and reviewers.
func Open(key MessageKey, ciphertext, ad, header []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key.Key[:])
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	aad := make([]byte, 0, len(ad)+len(header))
	aad = append(aad, ad...)
	aad = append(aad, header...)
	pt, err := aead.Open(nil, key.Nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("envelope: open: %w", err)
	}
	if pt == nil {
		return nil, errors.New("envelope: open: nil plaintext")
	}
	return pt, nil
}
