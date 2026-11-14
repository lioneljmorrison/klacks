package main

import (
	"testing"

	"github.com/lioneljmorrison/klacks/internal/api/ws"
	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/core"
)

func TestClientAuthenticatorDevOnly(t *testing.T) {
	if _, ok := clientAuthenticator(config.EnvDev).(auth.Dev); !ok {
		t.Errorf("env=dev: want auth.Dev")
	}
	if a := clientAuthenticator(config.EnvProd); a != nil {
		t.Errorf("env=prod: got %T; want nil (no client auth until S-31)", a)
	}
}

func TestApplyRateLimits(t *testing.T) {
	on := config.Default().RateLimit
	svc, mgr := core.New(nil, nil, nil, nil), ws.NewManager(auth.Dev{}, nil)
	applyRateLimits(on, svc, mgr)
	if mgr.PublishPerUser == nil || mgr.ConnectPerUser == nil || svc.AllowRoomPost == nil {
		t.Errorf("default limits not installed")
	}
	svc, mgr = core.New(nil, nil, nil, nil), ws.NewManager(auth.Dev{}, nil)
	applyRateLimits(config.RateLimit{}, svc, mgr)
	if mgr.PublishPerUser != nil || mgr.ConnectPerUser != nil || svc.AllowRoomPost != nil {
		t.Errorf("off limits installed something")
	}
}
