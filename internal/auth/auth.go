// Package auth identifies the client behind an HTTP or WebSocket request.
package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// ErrUnauthenticated means the request carries no valid identity.
var ErrUnauthenticated = errors.New("unauthenticated")

// Identity is who a connection acts as.
type Identity struct {
	UserID   store.UUID
	DeviceID store.UUID
}

// Authenticator identifies the client behind r. It returns an error wrapping
// ErrUnauthenticated when r carries no valid identity. Real auth (S-31)
// implements it with JWT/mTLS.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// Dev auth header names.
const (
	HeaderUser   = "X-Klacks-User"
	HeaderDevice = "X-Klacks-Device"
)

// Dev trusts whatever identity the client claims: the X-Klacks-User and
// X-Klacks-Device headers or, since browsers cannot set headers on a
// WebSocket, the user and device query parameters. It proves nothing, so it
// must only be used when env is dev.
type Dev struct{}

// Authenticate implements Authenticator.
func (Dev) Authenticate(r *http.Request) (Identity, error) {
	user, err := devID(r, HeaderUser, "user")
	if err != nil {
		return Identity{}, err
	}
	device, err := devID(r, HeaderDevice, "device")
	if err != nil {
		return Identity{}, err
	}
	return Identity{UserID: user, DeviceID: device}, nil
}

func devID(r *http.Request, header, param string) (store.UUID, error) {
	s := r.Header.Get(header)
	if s == "" {
		s = r.URL.Query().Get(param)
	}
	if s == "" {
		return store.UUID{}, fmt.Errorf("%w: no %s", ErrUnauthenticated, param)
	}
	id, err := store.ParseUUID(s)
	if err != nil || id == (store.UUID{}) {
		return store.UUID{}, fmt.Errorf("%w: invalid %s", ErrUnauthenticated, param)
	}
	return id, nil
}
