package auth

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/store"
)

const (
	userStr   = "11111111-1111-1111-1111-111111111111"
	deviceStr = "22222222-2222-2222-2222-222222222222"
)

var (
	user   = store.UUID{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	device = store.UUID{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
)

func TestDevAuthenticatorHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set(HeaderUser, userStr)
	r.Header.Set(HeaderDevice, deviceStr)
	got, err := Dev{}.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Identity{UserID: user, DeviceID: device}) {
		t.Errorf("got %+v", got)
	}
}

func TestDevAuthenticatorQuery(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws?user="+userStr+"&device="+deviceStr, nil)
	got, err := Dev{}.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Identity{UserID: user, DeviceID: device}) {
		t.Errorf("got %+v", got)
	}
}

func TestDevAuthenticatorRejects(t *testing.T) {
	for name, target := range map[string]string{
		"nothing":     "/ws",
		"no device":   "/ws?user=" + userStr,
		"no user":     "/ws?device=" + deviceStr,
		"bad user":    "/ws?user=alice&device=" + deviceStr,
		"bad device":  "/ws?user=" + userStr + "&device=x",
		"zero user":   "/ws?user=00000000-0000-0000-0000-000000000000&device=" + deviceStr,
		"zero device": "/ws?user=" + userStr + "&device=00000000-0000-0000-0000-000000000000",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Dev{}.Authenticate(httptest.NewRequest("GET", target, nil))
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("err = %v; want ErrUnauthenticated", err)
			}
		})
	}
}
