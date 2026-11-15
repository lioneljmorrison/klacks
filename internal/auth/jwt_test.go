package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://issuer.example"
	testAudience = "klacks"
)

var testNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newJWT(t *testing.T, pub ed25519.PublicKey) *JWT {
	t.Helper()
	a, err := NewJWT(pub, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return testNow }
	return a
}

// goodClaims are valid claims for user/device; tests mutate a copy.
func goodClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":         testIssuer,
		"aud":         testAudience,
		"sub":         userStr,
		ClaimDeviceID: deviceStr,
		"exp":         testNow.Add(time.Hour).Unix(),
		"iat":         testNow.Add(-time.Minute).Unix(),
	}
}

func sign(t *testing.T, priv ed25519.PrivateKey, c jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func bearer(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/device/bundle", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestJWTAccepts(t *testing.T) {
	pub, priv := newKey(t)
	got, err := newJWT(t, pub).Authenticate(bearer(sign(t, priv, goodClaims())))
	if err != nil {
		t.Fatal(err)
	}
	if got != (Identity{UserID: user, DeviceID: device}) {
		t.Errorf("got %+v", got)
	}
}

func TestJWTRejects(t *testing.T) {
	pub, priv := newKey(t)
	_, otherPriv := newKey(t)
	a := newJWT(t, pub)
	with := func(k string, v any) string {
		c := goodClaims()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return sign(t, priv, c)
	}
	hs256, err := jwt.NewWithClaims(jwt.SigningMethodHS256, goodClaims()).SignedString([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, goodClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"garbage":            "not.a.token",
		"other key":          sign(t, otherPriv, goodClaims()),
		"alg none":           none,
		"hs256 with pub key": hs256,
		"expired":            with("exp", testNow.Add(-time.Hour).Unix()),
		"no exp":             with("exp", nil),
		"not yet valid":      with("nbf", testNow.Add(time.Hour).Unix()),
		"wrong issuer":       with("iss", "https://evil.example"),
		"no issuer":          with("iss", nil),
		"wrong audience":     with("aud", "someone-else"),
		"no audience":        with("aud", nil),
		"no sub":             with("sub", nil),
		"bad sub":            with("sub", "alice"),
		"zero sub":           with("sub", "00000000-0000-0000-0000-000000000000"),
		"no device":          with(ClaimDeviceID, nil),
		"bad device":         with(ClaimDeviceID, "x"),
		"zero device":        with(ClaimDeviceID, "00000000-0000-0000-0000-000000000000"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := a.Authenticate(bearer(tok))
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("err = %v; want ErrUnauthenticated", err)
			}
		})
	}
}

func TestJWTClockSkewLeeway(t *testing.T) {
	pub, priv := newKey(t)
	c := goodClaims()
	c["exp"] = testNow.Add(-JWTLeeway / 2).Unix()
	if _, err := newJWT(t, pub).Authenticate(bearer(sign(t, priv, c))); err != nil {
		t.Errorf("expired within leeway: %v", err)
	}
}

func TestJWTNoToken(t *testing.T) {
	pub, _ := newKey(t)
	a := newJWT(t, pub)
	for name, h := range map[string]string{
		"none":       "",
		"basic":      "Basic dXNlcjpwYXNz",
		"empty":      "Bearer ",
		"lower only": "bearer",
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/device/bundle", nil)
			if h != "" {
				r.Header.Set("Authorization", h)
			}
			if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("err = %v; want ErrUnauthenticated", err)
			}
		})
	}
}

// Browsers cannot set headers on a WebSocket, so the token may ride in the
// access_token query parameter, but only on a WebSocket upgrade: elsewhere a
// query token would end up in logs and Referer headers for no reason.
func TestJWTQueryTokenOnlyOnUpgrade(t *testing.T) {
	pub, priv := newKey(t)
	a := newJWT(t, pub)
	tok := sign(t, priv, goodClaims())

	up := httptest.NewRequest("GET", "/ws?access_token="+tok, nil)
	up.Header.Set("Connection", "Upgrade")
	up.Header.Set("Upgrade", "websocket")
	if _, err := a.Authenticate(up); err != nil {
		t.Errorf("upgrade with query token: %v", err)
	}

	plain := httptest.NewRequest("GET", "/v1/device/bundle?access_token="+tok, nil)
	if _, err := a.Authenticate(plain); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("plain request with query token: err = %v; want ErrUnauthenticated", err)
	}
}

// The token names the device. A request that also claims an identity the
// dev way (headers or query) must claim the token's, so a token for one
// device can never act for another.
func TestJWTDeviceBinding(t *testing.T) {
	pub, priv := newKey(t)
	a := newJWT(t, pub)
	tok := sign(t, priv, goodClaims())
	const other = "33333333-3333-3333-3333-333333333333"

	for name, tc := range map[string]struct {
		header, value string
		target        string
		ok            bool
	}{
		"matching device header": {HeaderDevice, deviceStr, "/x", true},
		"matching user header":   {HeaderUser, userStr, "/x", true},
		"other device header":    {HeaderDevice, other, "/x", false},
		"other user header":      {HeaderUser, other, "/x", false},
		"other device query":     {"", "", "/x?device=" + other, false},
		"other user query":       {"", "", "/x?user=" + other, false},
		"matching device query":  {"", "", "/x?device=" + deviceStr, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.target, nil)
			r.Header.Set("Authorization", "Bearer "+tok)
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			_, err := a.Authenticate(r)
			if tc.ok && err != nil {
				t.Errorf("err = %v; want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("err = %v; want ErrUnauthenticated", err)
			}
		})
	}
}

func TestNewJWTRequiresIssuerAudienceAndKey(t *testing.T) {
	pub, _ := newKey(t)
	if _, err := NewJWT(pub, "", testAudience); err == nil {
		t.Error("empty issuer accepted")
	}
	if _, err := NewJWT(pub, testIssuer, ""); err == nil {
		t.Error("empty audience accepted")
	}
	if _, err := NewJWT(pub[:10], testIssuer, testAudience); err == nil {
		t.Error("short key accepted")
	}
}

func TestParseEd25519PublicKeyPEM(t *testing.T) {
	pub, _ := newKey(t)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEd25519PublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Error("key mismatch")
	}
	if _, err := ParseEd25519PublicKeyPEM([]byte("nope")); err == nil {
		t.Error("garbage accepted")
	}
}
