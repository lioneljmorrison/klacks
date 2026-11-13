//go:build integration

package migrate_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"

	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/store/migrate"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
	"github.com/lioneljmorrison/klacks/migrations"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

// exercise runs the shared lifecycle: up, idempotent up, down, up again,
// dirty failure, force recovery.
func exercise(t *testing.T, open func(fstest.MapFS) migrate.Migrator, good, broken fstest.MapFS, exists func(table string) bool) {
	ctx := context.Background()
	check := func(m migrate.Migrator, wantV uint, wantDirty bool) {
		t.Helper()
		v, dirty, err := m.Version(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if v != wantV || dirty != wantDirty {
			t.Fatalf("version=%d dirty=%t, want %d %t", v, dirty, wantV, wantDirty)
		}
	}

	m := open(good)
	check(m, 0, false)
	if err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	check(m, 2, false)
	if !exists("alpha") || !exists("beta") {
		t.Fatal("tables missing after up")
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("second up: %v", err)
	}
	check(m, 2, false)

	if err := m.Down(ctx, 1); err != nil {
		t.Fatal(err)
	}
	check(m, 1, false)
	if exists("beta") || !exists("alpha") {
		t.Fatal("down 1 removed the wrong table")
	}
	if err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	check(m, 2, false)
	_ = m.Close()

	// A broken migration 3 leaves the store dirty and blocks further runs.
	m = open(broken)
	if err := m.Up(ctx); err == nil {
		t.Fatal("broken migration succeeded")
	}
	check(m, 3, true)
	if err := m.Up(ctx); !errors.Is(err, migrate.ErrDirty) {
		t.Fatalf("up on dirty store: err = %v, want ErrDirty", err)
	}
	if err := m.Force(ctx, 2); err != nil {
		t.Fatal(err)
	}
	check(m, 2, false)
	_ = m.Close()
}

func TestPostgresLifecycle(t *testing.T) {
	dsn := dbtest.Postgres(t)
	ctx := context.Background()
	good := fstest.MapFS{
		"000001_alpha.up.sql":   file("CREATE TABLE alpha (id int PRIMARY KEY);"),
		"000001_alpha.down.sql": file("DROP TABLE alpha;"),
		"000002_beta.up.sql":    file("CREATE TABLE beta (id int PRIMARY KEY);"),
		"000002_beta.down.sql":  file("DROP TABLE beta;"),
	}
	broken := fstest.MapFS{}
	for k, v := range good {
		broken[k] = v
	}
	broken["000003_bad.up.sql"] = file("CREATE TABLE gamma (id int PRIMARY KEY); THIS IS NOT SQL;")
	broken["000003_bad.down.sql"] = file("DROP TABLE IF EXISTS gamma;")

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	exists := func(table string) bool {
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	exercise(t, func(src fstest.MapFS) migrate.Migrator {
		m, err := migrate.NewPostgres(ctx, dsn, src, discard)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}, good, broken, exists)
}

func TestScyllaLifecycle(t *testing.T) {
	cfg := dbtest.Scylla(t)
	ctx := context.Background()
	good := fstest.MapFS{
		"000001_alpha.up.cql":   file("-- first\nCREATE TABLE alpha (id int PRIMARY KEY);"),
		"000001_alpha.down.cql": file("DROP TABLE alpha;"),
		"000002_beta.up.cql":    file("CREATE TABLE beta (id int PRIMARY KEY);\nCREATE TABLE beta2 (id int PRIMARY KEY);"),
		"000002_beta.down.cql":  file("DROP TABLE beta2;\nDROP TABLE beta;"),
	}
	broken := fstest.MapFS{}
	for k, v := range good {
		broken[k] = v
	}
	broken["000003_bad.up.cql"] = file("CREATE TABLE gamma (id int PRIMARY KEY);\nTHIS IS NOT CQL;")
	broken["000003_bad.down.cql"] = file("DROP TABLE IF EXISTS gamma;")

	exists := func(table string) bool {
		s, err := store.OpenScylla(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		var n int
		if err := s.Query(`SELECT count(*) FROM system_schema.tables WHERE keyspace_name = ? AND table_name = ?`,
			cfg.Keyspace, table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	exercise(t, func(src fstest.MapFS) migrate.Migrator {
		m, err := migrate.NewScylla(ctx, cfg, src, discard)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}, good, broken, exists)
}

// TestEmbeddedMigrations applies the real, embedded migrations to fresh
// stores, rolls them all back and applies them again, so a bad up or down
// migration file fails CI.
func TestEmbeddedMigrations(t *testing.T) {
	ctx := context.Background()
	pg, err := migrate.NewPostgres(ctx, dbtest.Postgres(t), migrations.Postgres(), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pg.Close() }()
	upDownUp(t, pg)
	sc, err := migrate.NewScylla(ctx, dbtest.Scylla(t), migrations.Scylla(), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sc.Close() }()
	upDownUp(t, sc)
}

func upDownUp(t *testing.T, m migrate.Migrator) {
	t.Helper()
	ctx := context.Background()
	if err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		v, _, err := m.Version(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if v == 0 {
			break
		}
		if err := m.Down(ctx, 1); err != nil {
			t.Fatalf("down from version %d: %v", v, err)
		}
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}
