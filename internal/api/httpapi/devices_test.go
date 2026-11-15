package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/blackhole"
)

// failingDevices fails every call with err.
type failingDevices struct{ err error }

func (f failingDevices) UploadBundle(context.Context, store.UUID, store.UUID, store.Bundle, []store.OneTimePrekey) error {
	return f.err
}
func (f failingDevices) AddOneTimePrekeys(context.Context, store.UUID, store.UUID, []store.OneTimePrekey) error {
	return f.err
}
func (f failingDevices) Bundle(context.Context, store.UUID, store.UUID) (store.Bundle, store.Taken, error) {
	return store.Bundle{}, store.Taken{}, f.err
}
func (f failingDevices) ListDevices(context.Context, store.UUID) ([]store.Device, error) {
	return nil, f.err
}

// S-46: a store outage is a 503 "unavailable" the client may retry; any
// other failure stays a 500 "internal".
func TestDevicesStoreOutage(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{context.DeadlineExceeded, http.StatusServiceUnavailable, "unavailable"},
		{errors.New("boom"), http.StatusInternalServerError, "internal"},
	} {
		mux := http.NewServeMux()
		NewDevices(auth.Dev{}, failingDevices{err: tc.err}, discard).Register(mux)
		req := httptest.NewRequest(http.MethodGet, "/v1/users/11111111-1111-4111-8111-111111111111/devices", nil)
		req.Header.Set("X-Klacks-User", "22222222-2222-4222-8222-222222222222")
		req.Header.Set("X-Klacks-Device", "33333333-3333-4333-8333-333333333333")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var body errorResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != tc.status || body.Code != tc.code {
			t.Errorf("%v: %d %q; want %d %q", tc.err, rec.Code, body.Code, tc.status, tc.code)
		}
	}
}

// S-51: with PostgreSQL partitioned, each prekey endpoint answers 503
// "unavailable" within the store's per-call deadline instead of hanging.
func TestDevicesPartitionedPostgres(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@"+blackhole.Listen(t)+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	mux := http.NewServeMux()
	NewDevices(auth.Dev{}, store.NewDevices(pool, 200*time.Millisecond), discard).Register(mux)

	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	bundle := fmt.Sprintf(`{"identity_key":%q,"identity_dh_key":%q,"signed_prekey_id":1,"signed_prekey":%q,"signed_prekey_signature":%q}`,
		b64(store.IdentityKeySize), b64(store.DHKeySize), b64(store.DHKeySize), b64(store.SignatureSize))
	const user = "/v1/users/11111111-1111-4111-8111-111111111111"
	for _, rt := range []struct{ method, path, body string }{
		{http.MethodPut, "/v1/device/bundle", bundle},
		{http.MethodPost, "/v1/device/prekeys", `{"one_time_prekeys":[]}`},
		{http.MethodGet, user + "/devices/44444444-4444-4444-8444-444444444444/bundle", ""},
		{http.MethodGet, user + "/devices", ""},
	} {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
			req.Header.Set("X-Klacks-User", "22222222-2222-4222-8222-222222222222")
			req.Header.Set("X-Klacks-Device", "33333333-3333-4333-8333-333333333333")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { mux.ServeHTTP(rec, req); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("still hanging after 5s")
			}
			var body errorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != http.StatusServiceUnavailable || body.Code != "unavailable" {
				t.Errorf("%d %q; want 503 \"unavailable\"", rec.Code, body.Code)
			}
		})
	}
}
