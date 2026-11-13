package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Device/prekey bundle errors.
var (
	// ErrDeviceNotFound: no registered device for the (user, device) pair.
	ErrDeviceNotFound = errors.New("device not found")
	// ErrInvalidBundle: the bundle or its keys are not usable. The server
	// validates shapes only (sizes, id ranges, counts); it never sees
	// private key material and never verifies signatures — clients verify
	// each other's bundles when they fetch them.
	ErrInvalidBundle = errors.New("invalid prekey bundle")
)

// Key material sizes of the X3DH bundle (see client/bundle.go, the format's
// executable definition).
const (
	// IdentityKeySize is an Ed25519 public key, which signs the bundle.
	IdentityKeySize = 32
	// DHKeySize is an X25519 public key: the identity's Montgomery form,
	// the signed prekey and every one-time prekey.
	DHKeySize = 32
	// SignatureSize is an Ed25519 signature over the bundle's X25519 keys.
	SignatureSize = 64
	// MaxPrekeysPerUpload caps one bundle upload or replenishment, so a
	// request cannot balloon the table.
	MaxPrekeysPerUpload = 1000
)

// Bundle is a device's uploaded X3DH prekey bundle, public keys only.
type Bundle struct {
	// IdentityKey is the Ed25519 public key that signs the bundle.
	IdentityKey []byte
	// IdentityDHKey is the identity's X25519 (Montgomery) form, used in
	// X3DH's DHs. The signature covers it, binding it to IdentityKey.
	IdentityDHKey []byte
	// SignedPrekeyID names the signed prekey; an initial message references
	// it. It is per device, from 1.
	SignedPrekeyID int64
	// SignedPrekey is the X25519 signed prekey public key.
	SignedPrekey []byte
	// SignedPrekeySig is IdentityKey's Ed25519 signature over the bundle's
	// X25519 keys (IdentityDHKey and SignedPrekey, length-prefixed).
	SignedPrekeySig []byte
}

// OneTimePrekey is one uploaded one-time prekey. Keys are per device, from 1,
// chosen by the uploading client.
type OneTimePrekey struct {
	ID  int64
	Key []byte // X25519 public key
}

// Taken is the one-time prekey a bundle fetch consumed (S-23) and the count
// the device still holds, for the client's low-watermark check. ID 0 means
// none was available: the fetcher establishes the session without DH4.
type Taken struct {
	OneTimePrekey
	Remaining int
}

// Device is one registered device.
type Device struct {
	UserID   UUID
	DeviceID UUID
	Bundle   Bundle
	// LastSeen is the device's last bundle upload or replenishment. Nil
	// until the first one.
	LastSeen *time.Time
}

// Devices is the PostgreSQL store for devices and their prekey bundles
// (S-22), with one-time prekey consumption (S-23).
type Devices struct {
	pool *pgxpool.Pool
}

// NewDevices returns a Devices on a pool whose database is migrated.
func NewDevices(pool *pgxpool.Pool) *Devices { return &Devices{pool: pool} }

// UploadBundle upserts the device's bundle and its initial one-time prekeys.
// A re-upload replaces the whole bundle — and discards the previous bundle's
// one-time prekeys, which the new signed prekey cannot decrypt for.
func (d *Devices) UploadBundle(ctx context.Context, user, device UUID, b Bundle, prekeys []OneTimePrekey) error {
	if err := validateBundle(b); err != nil {
		return fmt.Errorf("devices: %w: %w", ErrInvalidBundle, err)
	}
	if err := validatePrekeys(prekeys); err != nil {
		return fmt.Errorf("devices: %w: %w", ErrInvalidBundle, err)
	}
	return pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO devices
			(user_id, device_id, identity_key, identity_dh_key, signed_prekey_id, signed_prekey, signed_prekey_sig, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (user_id, device_id) DO UPDATE SET
				identity_key = excluded.identity_key,
				identity_dh_key = excluded.identity_dh_key,
				signed_prekey_id = excluded.signed_prekey_id,
				signed_prekey = excluded.signed_prekey,
				signed_prekey_sig = excluded.signed_prekey_sig,
				last_seen_at = now()`,
			user, device, b.IdentityKey, b.IdentityDHKey, b.SignedPrekeyID, b.SignedPrekey, b.SignedPrekeySig)
		if err != nil {
			return fmt.Errorf("devices: upload %x/%x: %w", user, device, err)
		}
		// A fresh bundle invalidates the old one-time prekeys.
		if _, err := tx.Exec(ctx, `DELETE FROM one_time_prekeys WHERE user_id = $1 AND device_id = $2`, user, device); err != nil {
			return fmt.Errorf("devices: upload %x/%x: clear prekeys: %w", user, device, err)
		}
		if err := insertPrekeys(ctx, tx, user, device, prekeys); err != nil {
			return fmt.Errorf("devices: upload %x/%x: %w", user, device, err)
		}
		return nil
	})
}

// AddOneTimePrekeys replenishes a device's one-time prekeys (S-22). Uploading
// an id the device already holds replaces its key; clients upload fresh ids.
// The device must be registered.
func (d *Devices) AddOneTimePrekeys(ctx context.Context, user, device UUID, prekeys []OneTimePrekey) error {
	if err := validatePrekeys(prekeys); err != nil {
		return fmt.Errorf("devices: %w: %w", ErrInvalidBundle, err)
	}
	return pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		if err := deviceExists(ctx, tx, user, device); err != nil {
			return err
		}
		if err := insertPrekeys(ctx, tx, user, device, prekeys); err != nil {
			return fmt.Errorf("devices: add prekeys %x/%x: %w", user, device, err)
		}
		// Replenishment counts as being seen.
		if _, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at = now() WHERE user_id = $1 AND device_id = $2`, user, device); err != nil {
			return fmt.Errorf("devices: add prekeys %x/%x: seen: %w", user, device, err)
		}
		return nil
	})
}

// Bundle returns the device's bundle and consumes one one-time prekey (S-23):
// the consumed key is deleted in the same transaction, so concurrent fetchers
// never receive the same one. Remaining is the device's count after the
// fetch, the client's low-watermark signal to replenish. A device that holds
// no one-time prekeys yields Taken.ID 0: the fetcher establishes its session
// without the final DH. ErrDeviceNotFound when the device is unregistered.
func (d *Devices) Bundle(ctx context.Context, user, device UUID) (Bundle, Taken, error) {
	var (
		b     Bundle
		taken Taken
	)
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT identity_key, identity_dh_key, signed_prekey_id, signed_prekey, signed_prekey_sig
			FROM devices WHERE user_id = $1 AND device_id = $2`, user, device).
			Scan(&b.IdentityKey, &b.IdentityDHKey, &b.SignedPrekeyID, &b.SignedPrekey, &b.SignedPrekeySig)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("devices: %x/%x: %w", user, device, ErrDeviceNotFound)
		}
		if err != nil {
			return fmt.Errorf("devices: bundle %x/%x: %w", user, device, err)
		}
		// Consume in one statement: the subquery locks (SKIP LOCKED skips a
		// row a concurrent fetcher is taking) and the DELETE removes exactly
		// the row it selected. READ COMMITTED re-checks the deleted row on
		// release, so two fetchers can never take the same key.
		err = tx.QueryRow(ctx, `DELETE FROM one_time_prekeys
			WHERE user_id = $1 AND device_id = $2 AND prekey_id = (
				SELECT prekey_id FROM one_time_prekeys
				WHERE user_id = $1 AND device_id = $2
				ORDER BY prekey_id
				LIMIT 1
				FOR UPDATE SKIP LOCKED)
			RETURNING prekey_id, prekey`, user, device).
			Scan(&taken.ID, &taken.Key)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("devices: take prekey %x/%x: %w", user, device, err)
		}
		// Count after the delete, in the same transaction.
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM one_time_prekeys
			WHERE user_id = $1 AND device_id = $2`, user, device).Scan(&taken.Remaining); err != nil {
			return fmt.Errorf("devices: count prekeys %x/%x: %w", user, device, err)
		}
		return nil
	})
	if err != nil {
		return Bundle{}, Taken{}, err
	}
	return b, taken, nil
}

// ListDevices returns user's registered devices, ordered by device id.
func (d *Devices) ListDevices(ctx context.Context, user UUID) ([]Device, error) {
	rows, err := d.pool.Query(ctx, `SELECT device_id, identity_key, identity_dh_key, signed_prekey_id, signed_prekey, signed_prekey_sig, last_seen_at
		FROM devices WHERE user_id = $1 ORDER BY device_id`, user)
	if err != nil {
		return nil, fmt.Errorf("devices: list %x: %w", user, err)
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var dev Device
		dev.UserID = user
		if err := rows.Scan(&dev.DeviceID, &dev.Bundle.IdentityKey, &dev.Bundle.IdentityDHKey,
			&dev.Bundle.SignedPrekeyID, &dev.Bundle.SignedPrekey, &dev.Bundle.SignedPrekeySig, &dev.LastSeen); err != nil {
			return nil, fmt.Errorf("devices: list %x: %w", user, err)
		}
		out = append(out, dev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("devices: list %x: %w", user, err)
	}
	return out, nil
}

// deviceExists reports ErrDeviceNotFound unless the device row is there.
func deviceExists(ctx context.Context, tx pgx.Tx, user, device UUID) error {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT true FROM devices WHERE user_id = $1 AND device_id = $2`, user, device).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("devices: %x/%x: %w", user, device, ErrDeviceNotFound)
	}
	if err != nil {
		return fmt.Errorf("devices: exists %x/%x: %w", user, device, err)
	}
	return nil
}

// insertPrekeys inserts prekeys, replacing any keys already held for their
// ids (a replenishment may never reuse an id, but a retry of the same
// upload should not fail).
func insertPrekeys(ctx context.Context, tx pgx.Tx, user, device UUID, prekeys []OneTimePrekey) error {
	for _, p := range prekeys {
		if _, err := tx.Exec(ctx, `INSERT INTO one_time_prekeys (user_id, device_id, prekey_id, prekey)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, device_id, prekey_id) DO UPDATE SET prekey = excluded.prekey`,
			user, device, p.ID, p.Key); err != nil {
			return err
		}
	}
	return nil
}

// ValidateBundle checks a bundle's shapes: key sizes and id ranges. It
// rejects nothing but shape — the server never verifies signatures.
func ValidateBundle(b Bundle) error {
	return validateBundle(b)
}

func validateBundle(b Bundle) error {
	switch {
	case len(b.IdentityKey) != IdentityKeySize:
		return fmt.Errorf("identity key is %d bytes, want %d", len(b.IdentityKey), IdentityKeySize)
	case len(b.IdentityDHKey) != DHKeySize:
		return fmt.Errorf("identity DH key is %d bytes, want %d", len(b.IdentityDHKey), DHKeySize)
	case len(b.SignedPrekey) != DHKeySize:
		return fmt.Errorf("signed prekey is %d bytes, want %d", len(b.SignedPrekey), DHKeySize)
	case len(b.SignedPrekeySig) != SignatureSize:
		return fmt.Errorf("signed prekey signature is %d bytes, want %d", len(b.SignedPrekeySig), SignatureSize)
	case b.SignedPrekeyID < 1:
		return fmt.Errorf("signed prekey id %d < 1", b.SignedPrekeyID)
	}
	return nil
}

// ValidatePrekeys checks a one-time prekey batch's shapes.
func ValidatePrekeys(prekeys []OneTimePrekey) error {
	return validatePrekeys(prekeys)
}

func validatePrekeys(prekeys []OneTimePrekey) error {
	if len(prekeys) > MaxPrekeysPerUpload {
		return fmt.Errorf("%d one-time prekeys exceeds %d", len(prekeys), MaxPrekeysPerUpload)
	}
	for _, p := range prekeys {
		switch {
		case p.ID < 1:
			return fmt.Errorf("one-time prekey id %d < 1", p.ID)
		case len(p.Key) != DHKeySize:
			return fmt.Errorf("one-time prekey %d is %d bytes, want %d", p.ID, len(p.Key), DHKeySize)
		}
	}
	return nil
}
