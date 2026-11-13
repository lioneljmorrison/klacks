package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/lioneljmorrison/klacks/internal/api/httpapi"
	"github.com/lioneljmorrison/klacks/internal/api/ws"
	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
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
	)
	if a := clientAuthenticator(cfg.Env); a != nil {
		mgr = ws.NewManager(a, log)
		wsHandler = mgr
		log.Warn("client auth is the dev stub: any claimed identity is trusted")
	} else {
		log.Warn("no client authenticator for this env; /ws is not served", "env", cfg.Env)
	}

	srv := httpapi.NewServer(cfg.HTTP, health, wsHandler, log)
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

// clientAuthenticator returns the authenticator for client connections, or
// nil if there is none. The dev stub trusts any claimed identity, so it is
// only used when env is dev; other envs get none until real auth (S-31).
func clientAuthenticator(env string) auth.Authenticator {
	if env == config.EnvDev {
		return auth.Dev{}
	}
	return nil
}
