package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/store/migrate"
	"github.com/lioneljmorrison/klacks/migrations"
)

const migrateUsage = `Usage: klacks migrate [-store all|postgres|scylla] <action>

Actions:
  up            Apply all pending migrations (postgres, then scylla)
  version       Print the applied version of each store
  down [N]      Roll back the newest N migrations (default 1); needs -store
  force V       Mark version V applied and clean after repairing a dirty
                store (0 = nothing applied); needs -store
`

func cmdMigrate(ctx context.Context, cfg config.Config, log *slog.Logger, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, migrateUsage) }
	storeFlag := fs.String("store", "all", "store to migrate: all, postgres or scylla")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	args = fs.Args()
	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	var stores []string
	switch *storeFlag {
	case "all":
		stores = []string{"postgres", "scylla"}
	case "postgres", "scylla":
		stores = []string{*storeFlag}
	default:
		fmt.Fprintf(stderr, "klacks migrate: unknown store %q\n", *storeFlag)
		return 2
	}

	action := args[0]
	var n uint64
	switch action {
	case "up", "version":
		if len(args) != 1 {
			fs.Usage()
			return 2
		}
	case "down", "force":
		if len(stores) != 1 {
			fmt.Fprintf(stderr, "klacks migrate %s: pick one store with -store postgres or -store scylla\n", action)
			return 2
		}
		if action == "down" {
			n = 1
		}
		if len(args) == 2 {
			var err error
			if n, err = strconv.ParseUint(args[1], 10, 32); err != nil {
				fmt.Fprintf(stderr, "klacks migrate %s: %q is not a number\n", action, args[1])
				return 2
			}
		} else if len(args) > 2 || action == "force" {
			fs.Usage()
			return 2
		}
		if action == "down" && n == 0 {
			fmt.Fprintln(stderr, "klacks migrate down: N must be at least 1")
			return 2
		}
	default:
		fmt.Fprintf(stderr, "klacks migrate: unknown action %q\n\n", action)
		fs.Usage()
		return 2
	}

	for _, s := range stores {
		if err := migrateOne(ctx, cfg, log, s, action, uint(n), stdout); err != nil {
			log.Error("migrate failed", "store", s, "action", action, "err", err)
			return 1
		}
	}
	return 0
}

func migrateOne(ctx context.Context, cfg config.Config, log *slog.Logger, store, action string, n uint, stdout io.Writer) error {
	var (
		m   migrate.Migrator
		err error
	)
	switch store {
	case "postgres":
		m, err = migrate.NewPostgres(ctx, cfg.Postgres.DSN, migrations.Postgres(), log)
	case "scylla":
		m, err = migrate.NewScylla(ctx, cfg.Scylla, migrations.Scylla(), log)
	}
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	switch action {
	case "up":
		err = m.Up(ctx)
	case "down":
		err = m.Down(ctx, int(n)) //nolint:gosec // parsed as uint32
	case "force":
		err = m.Force(ctx, n)
	}
	if err != nil {
		return err
	}
	v, dirty, err := m.Version(ctx)
	if err != nil {
		return err
	}
	if action == "version" {
		fmt.Fprintf(stdout, "%s\tversion=%d\tdirty=%t\n", store, v, dirty)
	} else {
		log.Info("migrate done", "store", store, "action", action, "version", v, "dirty", dirty)
	}
	return nil
}
