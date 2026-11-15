package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// cmdReconcile runs store.Reconcile: after restoring PostgreSQL to an
// earlier point than ScyllaDB holds, it moves each room's counter past the
// messages ScyllaDB still has, and the write-timestamp sequence past the
// clock. Run it with every server stopped, before serving again (see
// docs/operations.md).
func cmdReconcile(ctx context.Context, cfg config.Config, log *slog.Logger, stdout io.Writer) error {
	pg, err := store.OpenPostgres(ctx, cfg.Postgres.DSN)
	if err != nil {
		return err
	}
	defer pg.Close()
	scylla, err := store.OpenScylla(cfg.Scylla)
	if err != nil {
		return err
	}
	defer scylla.Close()
	rep, err := store.Reconcile(ctx, store.NewRooms(pg, roomLockTimeout), store.NewScyllaMessages(scylla))
	for _, a := range rep.Advanced {
		fmt.Fprintf(stdout, "room %s: next_seq %d -> %d\n", store.FormatUUID(a.Room), a.From, a.To)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "checked %d rooms, advanced %d; message_write_ts = %d\n", rep.Rooms, len(rep.Advanced), rep.WriteTS)
	log.Info("reconcile done", "rooms", rep.Rooms, "advanced", len(rep.Advanced))
	return nil
}
