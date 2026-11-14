package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
)

func jwtConfig(t *testing.T, env string) config.Config {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jwt.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Env = env
	cfg.Auth.JWT = config.JWT{PublicKeyFile: path, Issuer: "https://id.example", Audience: "klacks"}
	return cfg
}

func TestClientAuthenticator(t *testing.T) {
	devCfg := config.Default()
	prodCfg := config.Default()
	prodCfg.Env = config.EnvProd

	for name, tc := range map[string]struct {
		cfg      config.Config
		wantDev  bool
		wantJWT  bool
		devTools bool
	}{
		"dev, no jwt":  {cfg: devCfg, wantDev: true, devTools: true},
		"prod, no jwt": {cfg: prodCfg},
		"dev, jwt":     {cfg: jwtConfig(t, config.EnvDev), wantJWT: true},
		"prod, jwt":    {cfg: jwtConfig(t, config.EnvProd), wantJWT: true},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := clientAuthenticator(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := a.(auth.Dev); ok != tc.wantDev {
				t.Errorf("got %T; dev stub want %v", a, tc.wantDev)
			}
			if _, ok := a.(*auth.JWT); ok != tc.wantJWT {
				t.Errorf("got %T; jwt want %v", a, tc.wantJWT)
			}
			if !tc.wantDev && !tc.wantJWT && a != nil {
				t.Errorf("got %T; want nil", a)
			}
			// The dev UI and dev room shim trust claimed identities: they
			// mount only alongside the dev stub, never next to real auth.
			if got := devTools(a); got != tc.devTools {
				t.Errorf("devTools = %v; want %v", got, tc.devTools)
			}
		})
	}
}

func TestClientAuthenticatorBadKeyFile(t *testing.T) {
	cfg := jwtConfig(t, config.EnvProd)
	if err := os.WriteFile(cfg.Auth.JWT.PublicKeyFile, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := clientAuthenticator(cfg); err == nil {
		t.Error("bad key file accepted")
	}
	cfg.Auth.JWT.PublicKeyFile = filepath.Join(t.TempDir(), "missing")
	if _, err := clientAuthenticator(cfg); err == nil {
		t.Error("missing key file accepted")
	}
}
