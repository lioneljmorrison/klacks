//go:build integration

// The prekey bundle REST endpoints (S-22, S-23) against a migrated Postgres.
package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

var (
	userA = "a1000000-0000-0000-0000-000000000001"
	userB = "a1000000-0000-0000-0000-000000000002"
	devA  = "b2000000-0000-0000-0000-000000000001"
)

func key(n int) string { return fmt.Sprintf(`"%s"`, make([]byte, n)) }

// testDevices builds a server with the devices endpoints on migrated
// Postgres and returns its client-facing base URL.
func testDevices(t *testing.T) (base string, devices *store.Devices) {
	t.Helper()
	pool := dbtest.MigratedPostgres(t)
	devices = store.NewDevices(pool)
	srv := NewServer(testHTTPConfig(), NewHealth(nil, time.Second, discard),
		nil, NewDevices(auth.Dev{}, devices, discard), discard)
	ts := httptest.NewServer(srv.srv.Handler)
	t.Cleanup(ts.Close)
	return ts.URL, devices
}

// do performs a request with dev identity headers.
func do(t *testing.T, method, url string, user, device string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(auth.HeaderUser, user)
	req.Header.Set(auth.HeaderDevice, device)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, buf.Bytes()
}

func b64(n int) []byte {
	return []byte(`"` + string(make([]byte, n)) + `"`)
}

func TestDevicesRESTFlow(t *testing.T) {
	base, _ := testDevices(t)

	// Upload a bundle for (userA, devA) with two one-time prekeys.
	upload := []byte(fmt.Sprintf(`{
		"identity_key": %s, "identity_dh_key": %s,
		"signed_prekey_id": 1, "signed_prekey": %s, "signed_prekey_signature": %s,
		"one_time_prekeys": [{"id": 1, "key": %s}, {"id": 2, "key": %s}]
	}`, b64(32), b64(32), b64(32), b64(64), b64(32), b64(32)))
	code, body := do(t, http.MethodPut, base+"/v1/device/bundle", userA, devA, upload)
	if code != http.StatusNoContent {
		t.Fatalf("upload code %d body %s", code, body)
	}

	// Fetching it consumes one-time prekey 1 and reports 1 remaining.
	code, body = do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices/"+devA+"/bundle", userB, devA, nil)
	if code != http.StatusOK {
		t.Fatalf("fetch code %d body %s", code, body)
	}
	var got bundleResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.SignedPrekeyID != 1 || got.OneTimePrekey == nil || got.OneTimePrekey.ID != 1 || got.OneTimePrekeysRemaining != 1 {
		t.Fatalf("fetch = %+v, want prekey 1 with 1 remaining", got)
	}
	if got.UserID != userA || got.DeviceID != devA {
		t.Fatalf("fetch ids = %s/%s", got.UserID, got.DeviceID)
	}

	// The second fetch takes prekey 2; a third is exhausted.
	code, body = do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices/"+devA+"/bundle", userB, devA, nil)
	_ = json.Unmarshal(body, &got)
	if code != http.StatusOK || got.OneTimePrekey == nil || got.OneTimePrekey.ID != 2 || got.OneTimePrekeysRemaining != 0 {
		t.Fatalf("second fetch code %d = %+v, want prekey 2, 0 remaining", code, got)
	}
	code, body = do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices/"+devA+"/bundle", userB, devA, nil)
	_ = json.Unmarshal(body, &got)
	if code != http.StatusOK || got.OneTimePrekey != nil || got.OneTimePrekeysRemaining != 0 {
		t.Fatalf("exhausted fetch code %d = %+v, want no prekey", code, got)
	}

	// Replenish.
	code, body = do(t, http.MethodPost, base+"/v1/device/prekeys", userA, devA, []byte(`{"one_time_prekeys":[{"id": 3, "key": `+string(b64(32))+`}]}`))
	if code != http.StatusNoContent {
		t.Fatalf("replenish code %d body %s", code, body)
	}
	code, body = do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices/"+devA+"/bundle", userB, devA, nil)
	_ = json.Unmarshal(body, &got)
	if code != http.StatusOK || got.OneTimePrekey == nil || got.OneTimePrekey.ID != 3 || got.OneTimePrekeysRemaining != 0 {
		t.Fatalf("post-replenish fetch = %+v, want prekey 3", got)
	}

	// List devices.
	code, body = do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices", userB, devA, nil)
	var devs []struct {
		DeviceID string `json:"device_id"`
		LastSeen string `json:"last_seen"`
	}
	_ = json.Unmarshal(body, &devs)
	if code != http.StatusOK || len(devs) != 1 || devs[0].DeviceID != devA || devs[0].LastSeen == "" {
		t.Fatalf("list code %d = %s", code, body)
	}
}

func TestDevicesRESTErrors(t *testing.T) {
	base, _ := testDevices(t)

	// No identity.
	if code, _ := do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices", "", devA, nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated code %d, want 401", code)
	}
	// Invalid bundle shape.
	upload := []byte(`{"identity_key": ` + string(b64(8)) + `}`)
	if code, body := do(t, http.MethodPut, base+"/v1/device/bundle", userA, devA, upload); code != http.StatusBadRequest {
		t.Fatalf("invalid bundle code %d body %s, want 400", code, body)
	}
	// Unknown device on fetch and replenish.
	if code, body := do(t, http.MethodGet, base+"/v1/users/"+userA+"/devices/"+devA+"/bundle", userB, devA, nil); code != http.StatusNotFound {
		t.Fatalf("fetch unknown device code %d body %s, want 404", code, body)
	}
	if code, _ := do(t, http.MethodPost, base+"/v1/device/prekeys", userA, devA, []byte(`{"one_time_prekeys":[{"id": 1, "key": `+string(b64(32))+`}]}`)); code != http.StatusNotFound {
		t.Fatalf("replenish unknown device code %d, want 404", code)
	}
	// Bad path IDs.
	if code, _ := do(t, http.MethodGet, base+"/v1/users/not-a-uuid/devices", userB, devA, nil); code != http.StatusBadRequest {
		t.Fatalf("bad user path code %d, want 400", code)
	}
	// Bad JSON body.
	if code, _ := do(t, http.MethodPut, base+"/v1/device/bundle", userA, devA, []byte(`{`)); code != http.StatusBadRequest {
		t.Fatalf("bad JSON code %d, want 400", code)
	}
}
