package ws

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// /ws behind JWT auth (S-31): a token in the Authorization header or, for
// browsers, the access_token query parameter connects as the token's
// identity; a bad token or a mismatched claimed device is a 401.
func TestJWTUpgrade(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewJWT(pub, "iss", "aud")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(a, discard)
	srv := httptest.NewServer(m)
	t.Cleanup(func() {
		m.Close()
		srv.Close()
	})
	base := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	sign := func(k ed25519.PrivateKey) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": "iss", "aud": "aud", "sub": userStr, auth.ClaimDeviceID: deviceStr,
			"exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	good := sign(priv)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	dialStatus := func(url string, h http.Header) int {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: h})
		if err == nil {
			defer func() { _ = c.CloseNow() }()
		}
		if resp == nil {
			t.Fatalf("dial %s: %v", url, err)
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return resp.StatusCode
	}

	if got := dialStatus(base, http.Header{"Authorization": {"Bearer " + good}}); got != http.StatusSwitchingProtocols {
		t.Errorf("header token: status %d", got)
	}
	if got := dialStatus(base+"?access_token="+good, nil); got != http.StatusSwitchingProtocols {
		t.Errorf("query token: status %d", got)
	}
	if got := dialStatus(base+"?access_token="+sign(otherPriv), nil); got != http.StatusUnauthorized {
		t.Errorf("wrong key: status %d; want 401", got)
	}
	if got := dialStatus(base+"?access_token="+good+"&device="+roomStr, nil); got != http.StatusUnauthorized {
		t.Errorf("mismatched device: status %d; want 401", got)
	}
	if got := dialStatus(base+"?user="+userStr+"&device="+deviceStr, nil); got != http.StatusUnauthorized {
		t.Errorf("dev-style identity only: status %d; want 401", got)
	}

	waitConns(t, m, 0)
	c := dialConn(t, base, http.Header{"Authorization": {"Bearer " + good}})
	defer func() { _ = c.CloseNow() }()
	waitConns(t, m, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	for conn := range m.conns {
		want := auth.Identity{UserID: mustUUID(t, userStr), DeviceID: mustUUID(t, deviceStr)}
		if conn.Identity() != want {
			t.Errorf("identity %+v; want %+v", conn.Identity(), want)
		}
	}
}

func dialConn(t *testing.T, url string, h http.Header) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	return c
}

func mustUUID(t *testing.T, s string) store.UUID {
	t.Helper()
	u, err := store.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// S-43: a browser app on another origin connects when its origin is in
// OriginPatterns; any other cross-origin upgrade is a 403.
func TestOriginPatterns(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewJWT(pub, "iss", "aud")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "iss", "aud": "aud", "sub": userStr, auth.ClaimDeviceID: deviceStr,
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	status := func(m *Manager, origin string) int {
		srv := httptest.NewServer(m)
		defer srv.Close()
		defer m.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		h := http.Header{"Authorization": {"Bearer " + tok}, "Origin": {origin}}
		c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", &websocket.DialOptions{HTTPHeader: h})
		if err == nil {
			_ = c.CloseNow()
		}
		if resp == nil {
			t.Fatalf("dial: %v", err)
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return resp.StatusCode
	}

	m := NewManager(a, discard)
	if got := status(m, "https://app.example.com"); got != http.StatusForbidden {
		t.Errorf("no patterns, cross origin: status %d; want 403", got)
	}
	m = NewManager(a, discard)
	m.OriginPatterns = []string{"app.example.com"}
	if got := status(m, "https://app.example.com"); got != http.StatusSwitchingProtocols {
		t.Errorf("allowed origin: status %d; want 101", got)
	}
	m = NewManager(a, discard)
	m.OriginPatterns = []string{"app.example.com"}
	if got := status(m, "https://evil.example.net"); got != http.StatusForbidden {
		t.Errorf("other origin: status %d; want 403", got)
	}
}
