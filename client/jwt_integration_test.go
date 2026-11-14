//go:build integration

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lioneljmorrison/klacks/internal/auth"
)

// S-44: the reference client talks to a JWT-configured server — prekey
// registration and bundle fetch over REST, the /ws dial, and an encrypted
// DM exchange — with bearer tokens only.
func TestE2EDMExchangeWithJWT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewJWT(pub, "https://id.test", "klacks")
	if err != nil {
		t.Fatal(err)
	}
	s := newE2EStackWith(t, a)

	tokens := func(user, device string) func(context.Context) (string, error) {
		return func(context.Context) (string, error) {
			return jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
				"iss": "https://id.test", "aud": "klacks", "sub": user, auth.ClaimDeviceID: device,
				"exp": time.Now().Add(time.Minute).Unix(),
			}).SignedString(priv)
		}
	}

	// Without a token the server refuses the client.
	anon := newClientFor(t, s.srv.base, e2eUserA, e2eDevA)
	if err := anon.Register(context.Background()); err == nil {
		t.Fatal("Register without a token: no error")
	}
	anon.Close()

	alice := newClientFor(t, s.srv.base, e2eUserA, e2eDevA)
	alice.SetTokenSource(tokens(e2eUserA, e2eDevA))
	bob := newClientFor(t, s.srv.base, e2eUserB, e2eDevB)
	bob.SetTokenSource(tokens(e2eUserB, e2eDevB))
	ctx := context.Background()
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Dial(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Resume(ctx, s.room, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		alice.Close()
		bob.Close()
	})
	exchange(t, s, alice, bob, 3)
}
