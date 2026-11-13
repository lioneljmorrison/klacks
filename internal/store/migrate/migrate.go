// Package migrate applies schema migrations to PostgreSQL and ScyllaDB.
//
// PostgreSQL uses golang-migrate. ScyllaDB uses a small helper in this package
// that records applied versions in <keyspace>.schema_migrations, using the same
// file naming and dirty-state semantics as golang-migrate.
package migrate

import (
	"context"
	"errors"
)

// Migrator applies migrations to one store.
type Migrator interface {
	// Up applies every pending migration.
	Up(ctx context.Context) error
	// Down rolls back the newest `steps` migrations.
	Down(ctx context.Context, steps int) error
	// Version reports the newest applied version (0 when none) and whether a
	// migration failed part-way (dirty). A dirty store refuses Up and Down
	// until it is repaired by hand and marked with Force.
	Version(ctx context.Context) (version uint, dirty bool, err error)
	// Force records version as applied and clean without running anything.
	// Use it after repairing a dirty store; 0 means "nothing applied".
	Force(ctx context.Context, version uint) error
	Close() error
}

// ErrDirty is returned when a previous migration failed part-way.
var ErrDirty = errors.New("migrate: store is dirty: a previous migration failed part-way; repair it, then run force")
