package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/lioneljmorrison/klacks/internal/api/httpapi"
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

	srv := httpapi.NewServer(cfg.HTTP, health, log)
	if err := srv.ListenAndServe(ctx); err != nil {
		return err
	}
	log.Info("klacks stopped")
	return nil
}
