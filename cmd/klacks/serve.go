package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	var met *metrics
	if cfg.Metrics.Addr != "" {
		met = newMetrics(
			func() poolStats {
				st := pg.Stat()
				return poolStats{Acquired: st.AcquiredConns(), Idle: st.IdleConns(), Total: st.TotalConns(), Max: st.MaxConns()}
			},
			func() int {
				if mgr == nil {
					return 0
				}
				return mgr.Connections()
			},
			func() int64 {
				if mgr == nil {
					return 0
				}
				return mgr.SlowDisconnects()
			},
		)
	}
	dev := clientAuthenticator(cfg.Env) != nil
	if a := clientAuthenticator(cfg.Env); a != nil {
		rooms := store.NewRooms(pg, roomLockTimeout)
		var messages store.MessageStore = store.NewScyllaMessages(scylla)
		if met != nil {
			rooms.OnLockHeld = met.lockHeld
			messages = met.timed(messages)
		}
		devices = httpapi.NewDevices(a, store.NewDevices(pg), log)
		mgr = ws.NewManager(a, log)
		// Fan-out goes through the manager: after each commit the core
		// hands the message to the hub (S-13).
		svc := core.New(rooms, messages, mgr.Deliver, mgr.MemberRemoved)
		mgr.Chat = svc
		mgr.PublishTimeout = publishTimeout(cfg)
		wsHandler = mgr
		// The dev room endpoints shim core's room management over REST,
		// so the browser test client can create and populate rooms.
		if dev {
			devRooms = httpapi.NewDevRooms(a, roomAdmin{svc: svc}, log)
		}
		log.Warn("client auth is the dev stub: any claimed identity is trusted")
	} else {
		log.Warn("no client authenticator for this env; /ws and the prekey bundle API are not served", "env", cfg.Env)
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
	if met != nil {
		stop, err := serveMetrics(ctx, cfg.Metrics.Addr, met.handler(), log)
		if err != nil {
			return err
		}
		defer stop()
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

// publishTimeout bounds a WebSocket publish end to end (S-47): it may wait
// for the room lock and then hold it across its ScyllaDB write.
func publishTimeout(cfg config.Config) time.Duration {
	return roomLockTimeout + cfg.Scylla.Timeout.D()
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
// nil if there is none. The dev stub trusts any claimed identity, so it is
// only used when env is dev; other envs get none until real auth (S-31).
func clientAuthenticator(env string) auth.Authenticator {
	if env == config.EnvDev {
		return auth.Dev{}
	}
	return nil
}

// serveMetrics serves GET /metrics on addr, its own listener, until stop.
// A listener that cannot open fails startup.
func serveMetrics(ctx context.Context, addr string, h http.Handler, log *slog.Logger) (stop func(), err error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server failed", "err", err)
		}
	}()
	log.Info("metrics listening", "addr", ln.Addr().String())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}
