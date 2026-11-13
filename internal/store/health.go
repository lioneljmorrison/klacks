package store

import (
	"context"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresCheck is a readiness check that pings the pool.
type PostgresCheck struct{ Pool *pgxpool.Pool }

func (PostgresCheck) Name() string { return "postgres" }

func (c PostgresCheck) Check(ctx context.Context) error { return c.Pool.Ping(ctx) }

// ScyllaCheck is a readiness check that runs a trivial query.
type ScyllaCheck struct{ Session *gocql.Session }

func (ScyllaCheck) Name() string { return "scylla" }

func (c ScyllaCheck) Check(ctx context.Context) error {
	var now gocql.UUID
	return c.Session.Query(`SELECT now() FROM system.local`).ScanContext(ctx, &now)
}
