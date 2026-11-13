package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// Postgres migrates a PostgreSQL database with golang-migrate. It takes an
// advisory lock, so concurrent runs are safe.
type Postgres struct {
	db    *sql.DB
	m     *gomigrate.Migrate // nil when the source holds no migrations
	log   *slog.Logger
	empty bool
}

// NewPostgres prepares a migrator for the database at dsn (URL or key=value
// form) using the .sql migrations in src.
func NewPostgres(ctx context.Context, dsn string, src fs.FS, log *slog.Logger) (*Postgres, error) {
	migs, err := readSource(src, "sql")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("migrate postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate postgres: ping: %w", err)
	}
	p := &Postgres{db: db, log: log.With("store", "postgres")}
	if len(migs) == 0 {
		// golang-migrate rejects an empty source; nothing to do is not an error.
		p.empty = true
		return p, nil
	}
	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate postgres: %w", err)
	}
	source, err := iofs.New(src, ".")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate postgres: source: %w", err)
	}
	p.m, err = gomigrate.NewWithInstance("iofs", source, "pgx5", driver)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate postgres: %w", err)
	}
	return p, nil
}

// stopOnCancel asks golang-migrate to stop after the current migration when
// ctx is cancelled. The returned func must be called when the run ends.
func (p *Postgres) stopOnCancel(ctx context.Context) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case p.m.GracefulStop <- true:
			default:
			}
		case <-done:
		}
	}()
	return func() { close(done) }
}

func (p *Postgres) Up(ctx context.Context) error {
	if p.empty {
		p.log.Info("no migrations")
		return nil
	}
	defer p.stopOnCancel(ctx)()
	err := p.m.Up()
	if errors.Is(err, gomigrate.ErrNoChange) {
		p.log.Info("up to date")
		return nil
	}
	return p.wrap(err)
}

func (p *Postgres) Down(ctx context.Context, steps int) error {
	if steps < 1 {
		return fmt.Errorf("migrate postgres: steps must be at least 1")
	}
	if p.empty {
		p.log.Info("no migrations")
		return nil
	}
	defer p.stopOnCancel(ctx)()
	err := p.m.Steps(-steps)
	return p.wrap(err)
}

func (p *Postgres) Version(context.Context) (uint, bool, error) {
	if p.empty {
		return 0, false, nil
	}
	v, dirty, err := p.m.Version()
	if errors.Is(err, gomigrate.ErrNilVersion) {
		return 0, false, nil
	}
	return v, dirty, p.wrap(err)
}

func (p *Postgres) Force(_ context.Context, version uint) error {
	if p.empty {
		if version == 0 {
			return nil
		}
		return fmt.Errorf("migrate postgres: no migrations; cannot force version %d", version)
	}
	v := int(version) //nolint:gosec // versions are small
	if version == 0 {
		v = database.NilVersion
	}
	return p.wrap(p.m.Force(v))
}

func (p *Postgres) Close() error {
	if p.m != nil {
		srcErr, dbErr := p.m.Close() // also closes db
		return errors.Join(srcErr, dbErr)
	}
	return p.db.Close()
}

func (p *Postgres) wrap(err error) error {
	if err == nil {
		return nil
	}
	var dirty gomigrate.ErrDirty
	if errors.As(err, &dirty) {
		return fmt.Errorf("%w (postgres version %d)", ErrDirty, dirty.Version)
	}
	return fmt.Errorf("migrate postgres: %w", err)
}
