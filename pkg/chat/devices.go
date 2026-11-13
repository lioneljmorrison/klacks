// Device registration and prekey bundles (S-22) with one-time prekey
// consumption (S-23), as part of the public ChatService. The server validates
// shapes only: it stores and hands out public keys, never sees private key
// material, and never verifies signatures — a client verifying another's
// bundle does that itself at fetch time.
package chat

import (
	"context"
	"fmt"
	"time"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// DeviceID identifies a device: 16-byte UUID, like RoomID and UserID.
type DeviceID [16]byte

// PrekeyBundle is a device's uploaded X3DH prekey bundle, public keys only.
// See client/bundle.go for the format and docs/protocol.md (Encryption) for
// the field roles.
type PrekeyBundle struct {
	// IdentityKey is the Ed25519 public key that signs the bundle.
	IdentityKey []byte
	// IdentityDHKey is the identity's X25519 (Montgomery) form, used in
	// X3DH's DHs. The signature covers it, binding it to IdentityKey.
	IdentityDHKey []byte
	// SignedPrekeyID names the signed prekey, per device from 1.
	SignedPrekeyID int64
	// SignedPrekey is the X25519 signed prekey public key.
	SignedPrekey []byte
	// SignedPrekeySignature is IdentityKey's Ed25519 signature over the
	// bundle's X25519 keys.
	SignedPrekeySignature []byte
}

// Prekey is one one-time prekey: an X25519 public key with its per-device id.
type Prekey struct {
	ID  int64
	Key []byte
}

// ConsumedPrekey is the one-time prekey a DeviceBundle fetch used (S-23) and
// the count the device still holds, the fetcher's low-watermark signal to
// replenish. ID 0 means the device had none: the fetcher establishes its
// session without the final DH.
type ConsumedPrekey struct {
	ID        int64
	Key       []byte
	Remaining int
}

// DeviceInfo is one registered device, as ListDevices reports it.
type DeviceInfo struct {
	UserID   UserID
	DeviceID DeviceID
	// LastSeen is the device's last bundle upload or replenishment.
	LastSeen *time.Time
}

// RegisterDevice upserts the device's bundle and its initial one-time
// prekeys. A re-upload replaces the whole bundle and discards its previous
// one-time prekeys.
func (s *Service) RegisterDevice(ctx context.Context, user UserID, device DeviceID, bundle PrekeyBundle, oneTimePrekeys []Prekey) error {
	b, prekeys, err := deviceArgs(bundle, oneTimePrekeys, true)
	if err != nil {
		return err
	}
	if err := s.devices.UploadBundle(ctx, store.UUID(user), store.UUID(device), b, prekeys); err != nil {
		return fmt.Errorf("register device: %w", err)
	}
	return nil
}

// DeviceBundle returns the device's bundle and consumes one one-time prekey:
// the consumed key is deleted server-side in the same transaction, so
// concurrent fetchers never receive the same one. A device with no one-time
// prekeys yields ConsumedPrekey.ID 0. ErrDeviceNotFound when unregistered.
func (s *Service) DeviceBundle(ctx context.Context, user UserID, device DeviceID) (PrekeyBundle, ConsumedPrekey, error) {
	b, taken, err := s.devices.Bundle(ctx, store.UUID(user), store.UUID(device))
	if err != nil {
		return PrekeyBundle{}, ConsumedPrekey{}, fmt.Errorf("device bundle: %w", err)
	}
	return PrekeyBundle{
		IdentityKey:           b.IdentityKey,
		IdentityDHKey:         b.IdentityDHKey,
		SignedPrekeyID:        b.SignedPrekeyID,
		SignedPrekey:          b.SignedPrekey,
		SignedPrekeySignature: b.SignedPrekeySig,
	}, ConsumedPrekey{ID: taken.ID, Key: taken.Key, Remaining: taken.Remaining}, nil
}

// AddDevicePrekeys replenishes a registered device's one-time prekeys.
func (s *Service) AddDevicePrekeys(ctx context.Context, user UserID, device DeviceID, oneTimePrekeys []Prekey) error {
	_, prekeys, err := deviceArgs(PrekeyBundle{}, oneTimePrekeys, false)
	if err != nil {
		return err
	}
	if err := s.devices.AddOneTimePrekeys(ctx, store.UUID(user), store.UUID(device), prekeys); err != nil {
		return fmt.Errorf("add device prekeys: %w", err)
	}
	return nil
}

// ListDevices returns the user's registered devices.
func (s *Service) ListDevices(ctx context.Context, user UserID) ([]DeviceInfo, error) {
	devs, err := s.devices.ListDevices(ctx, store.UUID(user))
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	out := make([]DeviceInfo, 0, len(devs))
	for _, d := range devs {
		out = append(out, DeviceInfo{
			UserID:   UserID(d.UserID),
			DeviceID: DeviceID(d.DeviceID),
			LastSeen: d.LastSeen,
		})
	}
	return out, nil
}

// deviceArgs converts the public API shapes to the store's and rejects
// anything invalid early, with the same error the store would return.
// withBundle validates the bundle too (registration, not replenishment).
func deviceArgs(bundle PrekeyBundle, prekeys []Prekey, withBundle bool) (store.Bundle, []store.OneTimePrekey, error) {
	b := store.Bundle{
		IdentityKey:     bundle.IdentityKey,
		IdentityDHKey:   bundle.IdentityDHKey,
		SignedPrekeyID:  bundle.SignedPrekeyID,
		SignedPrekey:    bundle.SignedPrekey,
		SignedPrekeySig: bundle.SignedPrekeySignature,
	}
	out := make([]store.OneTimePrekey, len(prekeys))
	for i, p := range prekeys {
		out[i] = store.OneTimePrekey{ID: p.ID, Key: p.Key}
	}
	if withBundle {
		if err := store.ValidateBundle(b); err != nil {
			return store.Bundle{}, nil, fmt.Errorf("register device: %w: %w", ErrInvalidBundle, err)
		}
	}
	if err := store.ValidatePrekeys(out); err != nil {
		return store.Bundle{}, nil, fmt.Errorf("register device: %w: %w", ErrInvalidBundle, err)
	}
	return b, out, nil
}
