package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// noDevices is a DeviceStore with no devices; the CORS tests never reach
// the others.
type noDevices struct{ DeviceStore }

func (noDevices) ListDevices(context.Context, store.UUID) ([]store.Device, error) { return nil, nil }

// rejectAll authenticates nobody.
type rejectAll struct{}

func (rejectAll) Authenticate(*http.Request) (auth.Identity, error) {
	return auth.Identity{}, auth.ErrUnauthenticated
}

// S-50: a browser app on an allowed origin can call the prekey API with an
// Authorization header: its preflight is answered and its responses carry
// Access-Control-Allow-Origin. Other origins get no CORS headers.
func TestDevicesCORS(t *testing.T) {
	d := NewDevices(rejectAll{}, noDevices{}, discard)
	d.AllowedOrigins = []string{"app.example.com", "https://*.example.org"}
	mux := http.NewServeMux()
	d.Register(mux)

	do := func(method, path, origin string, h http.Header) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		for k, v := range h {
			req.Header[k] = v
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	preflight := func(path, origin, method string) *httptest.ResponseRecorder {
		return do(http.MethodOptions, path, origin, http.Header{
			"Access-Control-Request-Method":  {method},
			"Access-Control-Request-Headers": {"authorization,content-type"},
		})
	}

	const bundle = "/v1/users/0b5d4c8e-6c2e-4f0e-9a51-3f1b8a6a2d10/devices/5a1f7c3e-2b4d-4e8f-9c6a-1d2e3f4a5b6c/bundle"
	routes := []struct{ method, path string }{
		{http.MethodPut, "/v1/device/bundle"},
		{http.MethodPost, "/v1/device/prekeys"},
		{http.MethodGet, bundle},
		{http.MethodGet, "/v1/users/0b5d4c8e-6c2e-4f0e-9a51-3f1b8a6a2d10/devices"},
	}
	for _, rt := range routes {
		for _, origin := range []string{"https://app.example.com", "https://x.example.org"} {
			rec := preflight(rt.path, origin, rt.method)
			if rec.Code != http.StatusNoContent {
				t.Errorf("preflight %s %s from %s: status %d; want 204", rt.method, rt.path, origin, rec.Code)
			}
			h := rec.Header()
			if got := h.Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("preflight %s from %s: Allow-Origin %q", rt.path, origin, got)
			}
			if got := h.Get("Access-Control-Allow-Methods"); got != rt.method {
				t.Errorf("preflight %s: Allow-Methods %q; want %q", rt.path, got, rt.method)
			}
			if got := h.Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type" {
				t.Errorf("preflight %s: Allow-Headers %q", rt.path, got)
			}
			if got := h.Get("Access-Control-Allow-Credentials"); got != "" {
				t.Errorf("preflight %s: Allow-Credentials %q; want none", rt.path, got)
			}
			if got := h.Get("Vary"); got != "Origin" {
				t.Errorf("preflight %s: Vary %q; want Origin", rt.path, got)
			}
		}
		// Any other origin: no CORS headers, so the browser blocks it.
		for _, origin := range []string{"https://evil.example.net", "http://x.example.org", "not a url"} {
			rec := preflight(rt.path, origin, rt.method)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("preflight %s from %s: Allow-Origin %q; want none", rt.path, origin, got)
			}
			if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "" {
				t.Errorf("preflight %s from %s: Allow-Methods %q; want none", rt.path, origin, got)
			}
		}
	}

	// The actual request: errors too carry Allow-Origin, so the app can
	// read the 401.
	rec := do(http.MethodGet, "/v1/users/0b5d4c8e-6c2e-4f0e-9a51-3f1b8a6a2d10/devices", "https://app.example.com", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET devices: status %d; want 401", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("GET devices: Allow-Origin %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("GET devices: Vary %q; want Origin", got)
	}
	rec = do(http.MethodGet, "/v1/users/0b5d4c8e-6c2e-4f0e-9a51-3f1b8a6a2d10/devices", "https://evil.example.net", nil)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("GET devices from other origin: Allow-Origin %q; want none", got)
	}
}

// Without allowed origins (the default, and always with the dev stub), the
// API stays same-origin: no CORS headers for anyone.
func TestDevicesNoCORSByDefault(t *testing.T) {
	d := NewDevices(rejectAll{}, noDevices{}, discard)
	mux := http.NewServeMux()
	d.Register(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/users/0b5d4c8e-6c2e-4f0e-9a51-3f1b8a6a2d10/devices", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin %q; want none", got)
	}
}
