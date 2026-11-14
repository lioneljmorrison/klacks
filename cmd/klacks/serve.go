package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/lioneljmorrison/klacks/internal/api/devui"
	"github.com/lioneljmorrison/klacks/internal/api/httpapi"
	"github.com/lioneljmorrison/klacks/internal/api/ws"
	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// cmdServe connects to both stores and serves HTTP until ctx is cancelled
// (SIGINT/SIGTERM). It fails fast if a store is unreachable at startup;
// after that, /readyz reports store outages.
func cmdServe(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	log.Info("starting klacks", "version", version, "env", cfg.Env)

	connectCtx, cancel := context.WithTimeout(ctx, cfg.Scylla.Timeout.D()*2)
	defer cancel()
	pg, err := store.OpenPostgres(connectCtx, cfg.Postgres.DSN)
	if err != nil {
		return err
	}
	defer pg.Close()
	scylla, err := store.OpenScylla(cfg.Scylla)
	if err != nil {
		return fmt.Errorf("%w (has `klacks migrate up` created keyspace %q?)", err, cfg.Scylla.Keyspace)
	}
	defer scylla.Close()

	health := httpapi.NewHealth([]httpapi.Check{
		store.PostgresCheck{Pool: pg},
		store.ScyllaCheck{Session: scylla},
	}, cfg.HTTP.ReadyTimeout.D(), log)

	var (
		mgr       *ws.Manager
		wsHandler http.Handler
		devices   *httpapi.Devices
		devRooms  *httpapi.DevRooms
	)
	a, err := clientAuthenticator(cfg)
	if err != nil {
		return err
	}
	dev := devTools(a)
	if a != nil {
		rooms := store.NewRooms(pg, roomLockTimeout)
		messages := store.NewScyllaMessages(scylla)
		devices = httpapi.NewDevices(a, store.NewDevices(pg), log)
		mgr = ws.NewManager(a, log)
		// Fan-out goes through the manager: after each commit the core
		// hands the message to the hub (S-13).
		svc := core.New(rooms, messages, mgr.Deliver, mgr.MemberRemoved)
		mgr.Chat = svc
		wsHandler = mgr
		// The dev room endpoints shim core's room management over REST,
		// so the browser test client can create and populate rooms.
		if dev {
			devRooms = httpapi.NewDevRooms(a, roomAdmin{svc: svc}, log)
			log.Warn("client auth is the dev stub: any claimed identity is trusted")
		} else {
			log.Info("client auth is JWT", "issuer", cfg.Auth.JWT.Issuer, "audience", cfg.Auth.JWT.Audience)
		}
	} else {
		log.Warn("no client authenticator for this env (set auth.jwt); /ws and the prekey bundle API are not served", "env", cfg.Env)
	}

	handler := http.Handler(nil)
	// The dev UI rides the dev gate too: it exists for testing against the
	// dev authenticator and mounts nowhere else.
	if dev {
		ui, err := devui.New()
		if err != nil {
			return err
		}
		handler = ui
	}

	srv := httpapi.NewServer(cfg.HTTP, health, wsHandler, devices, log)
	// The browser client must share the server's origin (/ws rejects
	// cross-origin upgrades), so the dev tooling is mounted on the mux the
	// server serves rather than a separate listener. A wrapper mux routes
	// /devui and /v1/dev/rooms to their handlers and everything else to the
	// server's routes; the server's graceful shutdown and Handler() keep
	// working through it.
	if handler != nil || devRooms != nil {
		outer := http.NewServeMux()
		if handler != nil {
			outer.Handle("GET /devui", handler)
			outer.Handle("GET /devui/", handler)
		}
		if devRooms != nil {
			devRooms.Register(outer)
		}
		outer.Handle("/", srv.Handler())
		srv.UseHandler(outer)
	}
	err = srv.ListenAndServe(ctx)
	if mgr != nil {
		// Shutdown does not track WebSockets: close them now that HTTP has
		// stopped, and wait for them.
		mgr.Close()
	}
	if err != nil {
		return err
	}
	log.Info("klacks stopped")
	return nil
}

// roomLockTimeout bounds every publish's and membership change's room lock
// (store.NewRooms). It must be longer than the ScyllaDB write timeout, since
// a publish holds the lock across its ScyllaDB write.
const roomLockTimeout = 10 * time.Second

// roomAdmin adapts core.Service's typed Kind/Role to the dev rooms
// handlers' string form.
type roomAdmin struct {
	svc *core.Service
}

func (a roomAdmin) CreateRoomWithID(ctx context.Context, room store.UUID, kind string, creator store.UUID) error {
	return a.svc.CreateRoomWithID(ctx, room, core.Kind(kind), creator)
}

func (a roomAdmin) AddMember(ctx context.Context, room, actor, user store.UUID, role string) error {
	if role == "" {
		role = string(core.RoleMember)
	}
	return a.svc.AddMember(ctx, room, actor, user, core.Role(role))
}

func (a roomAdmin) RemoveMember(ctx context.Context, room, actor, user store.UUID) error {
	return a.svc.RemoveMember(ctx, room, actor, user)
}

func (a roomAdmin) Members(ctx context.Context, room store.UUID) ([]store.UUID, error) {
	return a.svc.Members(ctx, room)
}

// clientAuthenticator returns the authenticator for client connections, or
// nil if there is none. A configured JWT key wins in every env; without one,
// env dev gets the dev stub, which trusts any claimed identity, and any other
// env gets nothing.
func clientAuthenticator(cfg config.Config) (auth.Authenticator, error) {
	if cfg.Auth.JWT.Enabled() {
		b, err := os.ReadFile(cfg.Auth.JWT.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt.public_key_file: %w", err)
		}
		key, err := auth.ParseEd25519PublicKeyPEM(b)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt.public_key_file %s: %w", cfg.Auth.JWT.PublicKeyFile, err)
		}
		return auth.NewJWT(key, cfg.Auth.JWT.Issuer, cfg.Auth.JWT.Audience)
	}
	if cfg.Env == config.EnvDev {
		return auth.Dev{}, nil
	}
	return nil, nil
}

// devTools reports whether the dev UI and dev room endpoints are mounted:
// only alongside the dev stub, since they exist to test with claimed
// identities and must never sit next to real auth.
func devTools(a auth.Authenticator) bool {
	_, ok := a.(auth.Dev)
	return ok
}
