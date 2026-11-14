package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/store"
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
