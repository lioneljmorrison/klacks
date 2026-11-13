// Package migrations embeds the schema migrations for both stores.
//
// File naming, for both directories:
//
//	NNNNNN_short_name.up.sql   / NNNNNN_short_name.down.sql   (postgres/)
//	NNNNNN_short_name.up.cql   / NNNNNN_short_name.down.cql   (scylla/)
//
// Versions are applied in ascending order. Create a pair with
// `make migrate-create STORE=postgres|scylla NAME=short_name`.
//
// A ScyllaDB migration may hold several CQL statements separated by `;`.
// CQL DDL is not transactional: keep one schema change per migration where
// possible, so a failure leaves an obvious, recoverable state.
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed all:postgres
var postgresFS embed.FS

//go:embed all:scylla
var scyllaFS embed.FS

// Postgres returns the PostgreSQL migrations.
func Postgres() fs.FS { return sub(postgresFS, "postgres") }

// Scylla returns the ScyllaDB migrations.
func Scylla() fs.FS { return sub(scyllaFS, "scylla") }

func sub(f embed.FS, dir string) fs.FS {
	s, err := fs.Sub(f, dir)
	if err != nil {
		panic(err) // dir is a compile-time constant embedded above
	}
	return s
}
