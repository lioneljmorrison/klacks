package main

import (
	"testing"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
)

func TestClientAuthenticatorDevOnly(t *testing.T) {
	if _, ok := clientAuthenticator(config.EnvDev).(auth.Dev); !ok {
		t.Errorf("env=dev: want auth.Dev")
	}
	if a := clientAuthenticator(config.EnvProd); a != nil {
		t.Errorf("env=prod: got %T; want nil (no client auth until S-31)", a)
	}
}
