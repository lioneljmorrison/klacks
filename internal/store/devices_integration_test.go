//go:build integration

// Devices and prekey bundles (S-22), one-time prekey consumption (S-23),
// against a migrated Postgres.
package store_test

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

func bundle(id int64) store.Bundle {
	return store.Bundle{
		IdentityKey:     make([]byte, store.IdentityKeySize),
		IdentityDHKey:   make([]byte, store.DHKeySize),
		SignedPrekeyID:  id,
		SignedPrekey:    make([]byte, store.DHKeySize),
		SignedPrekeySig: make([]byte, store.SignatureSize),
	}
}

func prekey(id int64) store.OneTimePrekey {
	return store.OneTimePrekey{ID: id, Key: make([]byte, store.DHKeySize)}
}

func TestDevicesUploadAndFetch(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	d := store.NewDevices(pool)
	user, device := store.UUID{1}, store.UUID{2}

	if _, _, err := d.Bundle(t.Context(), user, device); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("fetch unregistered: %v, want ErrDeviceNotFound", err)
	}

	want := bundle(7)
	if err := d.UploadBundle(t.Context(), user, device, want, []store.OneTimePrekey{prekey(1), prekey(2)}); err != nil {
		t.Fatal(err)
	}
	got, taken, err := d.Bundle(t.Context(), user, device)
	if err != nil {
		t.Fatal(err)
	}
	if !bundleEqual(got, want) {
		t.Fatalf("fetched bundle %+v, want %+v", got, want)
	}
	if taken.ID != 1 || taken.Remaining != 1 {
		t.Fatalf("taken = %+v, want prekey 1, remaining 1", taken)
	}

	// The consumed key is gone; the next fetch takes the last one, then the
	// device is exhausted and fetches come without a one-time prekey.
	if taken, err = takeOne(t, d, user, device); err != nil || taken.ID != 2 || taken.Remaining != 0 {
		t.Fatalf("second take = %+v err %v, want prekey 2, remaining 0", taken, err)
	}
	if taken, err = takeOne(t, d, user, device); err != nil || taken.ID != 0 || taken.Remaining != 0 {
		t.Fatalf("exhausted take = %+v err %v, want no prekey, remaining 0", taken, err)
	}
}

func bundleEqual(a, b store.Bundle) bool {
	return slices.Equal(a.IdentityKey, b.IdentityKey) &&
		slices.Equal(a.IdentityDHKey, b.IdentityDHKey) &&
		a.SignedPrekeyID == b.SignedPrekeyID &&
		slices.Equal(a.SignedPrekey, b.SignedPrekey) &&
		slices.Equal(a.SignedPrekeySig, b.SignedPrekeySig)
}

// takeOne is Bundle with the bundle discarded.
func takeOne(t *testing.T, d *store.Devices, user, device store.UUID) (store.Taken, error) {
	t.Helper()
	_, taken, err := d.Bundle(t.Context(), user, device)
	return taken, err
}

func TestDevicesUploadReplacesBundleAndPrekeys(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	d := store.NewDevices(pool)
	user, device := store.UUID{1}, store.UUID{2}

	if err := d.UploadBundle(t.Context(), user, device, bundle(1), []store.OneTimePrekey{prekey(1), prekey(2)}); err != nil {
		t.Fatal(err)
	}
	// A re-upload with a new signed prekey invalidates the old one-time
	// prekeys: they only fit the bundle that carried them.
	if err := d.UploadBundle(t.Context(), user, device, bundle(5), []store.OneTimePrekey{prekey(10)}); err != nil {
		t.Fatal(err)
	}
	taken, err := takeOne(t, d, user, device)
	if err != nil || taken.ID != 10 || taken.Remaining != 0 {
		t.Fatalf("take after re-upload = %+v err %v, want prekey 10, remaining 0", taken, err)
	}
}

func TestDevicesReplenish(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	d := store.NewDevices(pool)
	user, device := store.UUID{1}, store.UUID{2}

	if err := d.UploadBundle(t.Context(), user, device, bundle(1), nil); err != nil {
		t.Fatal(err)
	}
	// Replenishing an unregistered device fails.
	other := store.UUID{3}
	if err := d.AddOneTimePrekeys(t.Context(), user, other, []store.OneTimePrekey{prekey(1)}); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("replenish unregistered: %v, want ErrDeviceNotFound", err)
	}

	if err := d.AddOneTimePrekeys(t.Context(), user, device, []store.OneTimePrekey{prekey(1), prekey(2), prekey(3)}); err != nil {
		t.Fatal(err)
	}
	taken, err := takeOne(t, d, user, device)
	if err != nil || taken.ID != 1 || taken.Remaining != 2 {
		t.Fatalf("take = %+v err %v, want prekey 1, remaining 2", taken, err)
	}
}

func TestDevicesList(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	d := store.NewDevices(pool)
	user := store.UUID{1}
	if err := d.UploadBundle(t.Context(), user, store.UUID{2}, bundle(1), nil); err != nil {
		t.Fatal(err)
	}
	if err := d.UploadBundle(t.Context(), user, store.UUID{3}, bundle(2), nil); err != nil {
		t.Fatal(err)
	}
	if err := d.UploadBundle(t.Context(), store.UUID{9}, store.UUID{2}, bundle(3), nil); err != nil {
		t.Fatal(err)
	}
	devs, err := d.ListDevices(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0].DeviceID != (store.UUID{2}) || devs[1].DeviceID != (store.UUID{3}) {
		t.Fatalf("list = %+v, want devices 2 and 3 of user 1", devs)
	}
	for _, dev := range devs {
		if dev.UserID != user || dev.LastSeen == nil {
			t.Fatalf("device %+v: missing user or last_seen_at", dev)
		}
	}
	if other, err := d.ListDevices(t.Context(), store.UUID{8}); err != nil || len(other) != 0 {
		t.Fatalf("list unknown user = %+v err %v, want empty", other, err)
	}
}

func TestDevicesConcurrentFetchesAreUnique(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	d := store.NewDevices(pool)
	user, device := store.UUID{1}, store.UUID{2}
	if err := d.UploadBundle(t.Context(), user, device, bundle(1), []store.OneTimePrekey{
		prekey(1), prekey(2), prekey(3), prekey(4), prekey(5),
	}); err != nil {
		t.Fatal(err)
	}

	const n = 5
	ids := make(chan int64, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, taken, err := d.Bundle(t.Context(), user, device)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- taken.ID
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[int64]bool, n)
	for id := range ids {
		if id == 0 || seen[id] {
			t.Fatalf("prekey %d handed out twice or zero; concurrent fetchers must be unique", id)
		}
		seen[id] = true
	}
	if _, taken, err := d.Bundle(t.Context(), user, device); err != nil || taken.ID != 0 || taken.Remaining != 0 {
		t.Fatalf("exhausted take = %+v err %v, want none left", taken, err)
	}
}

func TestDevicesUploadValidation(t *testing.T) {
	pool := dbtest.MigratedPostgres(t)
	d := store.NewDevices(pool)
	user, device := store.UUID{1}, store.UUID{2}

	b := bundle(1)
	b.IdentityKey = b.IdentityKey[:31]
	if err := d.UploadBundle(t.Context(), user, device, b, nil); !errors.Is(err, store.ErrInvalidBundle) {
		t.Fatalf("short identity key: %v, want ErrInvalidBundle", err)
	}
	b = bundle(0) // signed prekey id 0
	if err := d.UploadBundle(t.Context(), user, device, b, nil); !errors.Is(err, store.ErrInvalidBundle) {
		t.Fatalf("signed prekey id 0: %v, want ErrInvalidBundle", err)
	}
	if err := d.UploadBundle(t.Context(), user, device, bundle(1), []store.OneTimePrekey{prekey(0)}); !errors.Is(err, store.ErrInvalidBundle) {
		t.Fatalf("prekey id 0: %v, want ErrInvalidBundle", err)
	}
	tooMany := make([]store.OneTimePrekey, store.MaxPrekeysPerUpload+1)
	for i := range tooMany {
		tooMany[i] = prekey(int64(i + 1))
	}
	if err := d.UploadBundle(t.Context(), user, device, bundle(1), tooMany); !errors.Is(err, store.ErrInvalidBundle) {
		t.Fatalf("too many prekeys: %v, want ErrInvalidBundle", err)
	}
	// A valid bundle goes through.
	if err := d.UploadBundle(t.Context(), user, device, bundle(1), []store.OneTimePrekey{prekey(1)}); err != nil {
		t.Fatal(err)
	}
}
