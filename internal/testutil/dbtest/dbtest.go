// Package dbtest gives integration tests throwaway PostgreSQL databases and
// ScyllaDB keyspaces on the local stack (`make up`).
//
// Tests that use it skip unless KLACKS_TEST_POSTGRES_DSN / KLACKS_TEST_SCYLLA_HOSTS
// are set; `make test-integration` sets them from .env. Integration test files
// carry the `integration` build tag so `make test` never needs the stack.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/store/migrate"
	"github.com/lioneljmorrison/klacks/migrations"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// MigratedPostgres returns a pool on a fresh database with the embedded
// migrations applied.
func MigratedPostgres(t testing.TB) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	dsn := Postgres(t)
	m, err := migrate.NewPostgres(ctx, dsn, migrations.Postgres(), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	pool, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// MigratedScylla returns a session on a fresh keyspace with the embedded
// migrations applied.
func MigratedScylla(t testing.TB) *gocql.Session {
	t.Helper()
	ctx := context.Background()
	cfg := Scylla(t)
	m, err := migrate.NewScylla(ctx, cfg, migrations.Scylla(), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenScylla(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Postgres creates an empty database for the test, drops it on cleanup, and
// returns its DSN.
func Postgres(t testing.TB) string {
	t.Helper()
	base := os.Getenv("KLACKS_TEST_POSTGRES_DSN")
	if base == "" {
		t.Skip("KLACKS_TEST_POSTGRES_DSN not set (run `make up test-integration`)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("dbtest: connect postgres: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	name := "t_" + randHex(t)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("dbtest: create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Errorf("dbtest: cleanup connect: %v", err)
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("dbtest: drop database %s: %v", name, err)
		}
	})
	return withDatabase(t, base, name)
}

// withDatabase returns dsn pointed at database name.
func withDatabase(t testing.TB, dsn, name string) string {
	t.Helper()
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("dbtest: parse dsn: %v", err)
		}
		u.Path = "/" + name
		return u.String()
	}
	return dsn + " dbname=" + name // later keys win in key=value DSNs
}

// Scylla returns a config whose keyspace is unique to the test; the keyspace
// is dropped on cleanup if anything created it.
func Scylla(t testing.TB) config.Scylla {
	t.Helper()
	hosts := os.Getenv("KLACKS_TEST_SCYLLA_HOSTS")
	if hosts == "" {
		t.Skip("KLACKS_TEST_SCYLLA_HOSTS not set (run `make up test-integration`)")
	}
	cfg := config.Default().Scylla
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.Hosts = append(cfg.Hosts, h)
		}
	}
	cfg.Username = os.Getenv("KLACKS_TEST_SCYLLA_USERNAME")
	cfg.Password = os.Getenv("KLACKS_TEST_SCYLLA_PASSWORD")
	cfg.Timeout = config.Duration(10 * time.Second)
	cfg.Keyspace = "t_" + randHex(t)
	t.Cleanup(func() {
		s, err := store.ScyllaCluster(cfg, "").CreateSession()
		if err != nil {
			t.Errorf("dbtest: cleanup connect scylla: %v", err)
			return
		}
		defer s.Close()
		if err := s.Query("DROP KEYSPACE IF EXISTS " + cfg.Keyspace).Exec(); err != nil {
			t.Errorf("dbtest: drop keyspace %s: %v", cfg.Keyspace, err)
		}
	})
	return cfg
}

func randHex(t testing.TB) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
