package main

import (
	"testing"
	"time"

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

// S-47: a publish may wait out the room lock and then its ScyllaDB write.
func TestPublishTimeout(t *testing.T) {
	cfg := config.Default()
	cfg.Scylla.Timeout = config.Duration(5 * time.Second)
	if got, want := publishTimeout(cfg), roomLockTimeout+5*time.Second; got != want {
		t.Errorf("publishTimeout = %v; want %v", got, want)
	}
}
