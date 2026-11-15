package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// ClaimDeviceID is the JWT claim naming the device; "sub" names the user.
// Both are UUIDs in their canonical text form.
const ClaimDeviceID = "device_id"

// JWTLeeway is the clock skew allowed on exp, nbf and iat.
const JWTLeeway = 30 * time.Second

// QueryToken is the query parameter that may carry the token on a WebSocket
// upgrade, since browsers cannot set headers there (RFC 6750 §2.3 name).
const QueryToken = "access_token"

// JWT verifies bearer tokens signed with Ed25519 (alg EdDSA, RFC 8037) by
// the embedder's identity provider. klacks only verifies tokens; it never
// issues them. A token must carry iss and aud equal to the configured
// values, an exp, sub (the user) and device_id (the device).
//
// The token comes from the Authorization: Bearer header or, on a WebSocket
// upgrade only, the access_token query parameter. It is checked when the
// request arrives; a WebSocket outlives its token's exp.
type JWT struct {
	key    ed25519.PublicKey
	parser *jwt.Parser
	now    func() time.Time // tests pin the clock
}

// NewJWT returns a verifier for tokens signed by key's private half and
// issued by issuer for audience. Both issuer and audience are required.
func NewJWT(key ed25519.PublicKey, issuer, audience string) (*JWT, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth: ed25519 public key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("auth: jwt issuer and audience are required")
	}
	a := &JWT{key: key, now: time.Now}
	a.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithLeeway(JWTLeeway),
		jwt.WithTimeFunc(func() time.Time { return a.now() }),
	)
	return a, nil
}

type claims struct {
	jwt.RegisteredClaims
	DeviceID string `json:"device_id"`
}

// Authenticate implements Authenticator.
func (a *JWT) Authenticate(r *http.Request) (Identity, error) {
	raw := bearerToken(r)
	if raw == "" {
		return Identity{}, fmt.Errorf("%w: no bearer token", ErrUnauthenticated)
	}
	var c claims
	if _, err := a.parser.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) { return a.key, nil }); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	id, err := identityFromClaims(c)
	if err != nil {
		return Identity{}, err
	}
	if err := bound(r, id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

func identityFromClaims(c claims) (Identity, error) {
	u, err := store.ParseUUID(c.Subject)
	if err != nil || u == (store.UUID{}) {
		return Identity{}, fmt.Errorf("%w: invalid sub", ErrUnauthenticated)
	}
	d, err := store.ParseUUID(c.DeviceID)
	if err != nil || d == (store.UUID{}) {
		return Identity{}, fmt.Errorf("%w: invalid %s", ErrUnauthenticated, ClaimDeviceID)
	}
	return Identity{UserID: u, DeviceID: d}, nil
}

// bearerToken returns the request's token: the Authorization: Bearer header,
// or the access_token query parameter on a WebSocket upgrade.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, tok, ok := strings.Cut(h, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return ""
		}
		return strings.TrimSpace(tok)
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return r.URL.Query().Get(QueryToken)
	}
	return ""
}

// bound checks that any identity the request also claims the dev way
// (X-Klacks-User/-Device headers or user/device query parameters) is the
// token's, so a token for one device never acts for another.
func bound(r *http.Request, id Identity) error {
	for _, f := range []struct {
		header, param string
		want          store.UUID
	}{
		{HeaderUser, "user", id.UserID},
		{HeaderDevice, "device", id.DeviceID},
	} {
		s := r.Header.Get(f.header)
		if s == "" {
			s = r.URL.Query().Get(f.param)
		}
		if s == "" {
			continue
		}
		if got, err := store.ParseUUID(s); err != nil || got != f.want {
			return fmt.Errorf("%w: claimed %s does not match the token", ErrUnauthenticated, f.param)
		}
	}
	return nil
}

// ParseEd25519PublicKeyPEM reads a PEM "PUBLIC KEY" block (PKIX, as
// `openssl pkey -pubout` writes) holding an Ed25519 key.
func ParseEd25519PublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("auth: no PEM PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("auth: public key is %T, want ed25519", k)
	}
	return pub, nil
}
