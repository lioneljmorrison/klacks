package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// Scylla migrates a ScyllaDB keyspace. It creates the keyspace (with
// NetworkTopologyStrategy and cfg.ReplicationFactor) if it does not exist,
// and records applied versions in <keyspace>.schema_migrations.
//
// It takes no cluster-wide lock: run one migrate job at a time.
type Scylla struct {
	session *gocql.Session
	src     fs.FS
	migs    []migration
	log     *slog.Logger
}

// NewScylla connects to the cluster, ensures the keyspace and the version
// table exist, and loads the .cql migrations in src.
func NewScylla(ctx context.Context, cfg config.Scylla, src fs.FS, log *slog.Logger) (*Scylla, error) {
	migs, err := readSource(src, "cql")
	if err != nil {
		return nil, err
	}
	if err := ensureKeyspace(ctx, cfg); err != nil {
		return nil, err
	}
	session, err := store.OpenScylla(cfg)
	if err != nil {
		return nil, fmt.Errorf("migrate scylla: %w", err)
	}
	s := &Scylla{session: session, src: src, migs: migs, log: log.With("store", "scylla", "keyspace", cfg.Keyspace)}
	if err := s.ddl(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		name text,
		dirty boolean,
		applied_at timestamp)`); err != nil {
		session.Close()
		return nil, err
	}
	return s, nil
}

func ensureKeyspace(ctx context.Context, cfg config.Scylla) error {
	session, err := store.ScyllaCluster(cfg, "").CreateSession()
	if err != nil {
		return fmt.Errorf("migrate scylla: %w", err)
	}
	defer session.Close()
	// The keyspace name is validated by config (letters, digits, underscore),
	// so it is safe to splice; CQL cannot bind identifiers.
	stmt := fmt.Sprintf(`CREATE KEYSPACE IF NOT EXISTS %s WITH replication = {'class': 'NetworkTopologyStrategy', 'replication_factor': %d}`,
		cfg.Keyspace, cfg.ReplicationFactor)
	if err := session.Query(stmt).ExecContext(ctx); err != nil {
		return fmt.Errorf("migrate scylla: create keyspace: %w", err)
	}
	if err := session.AwaitSchemaAgreement(ctx); err != nil {
		return fmt.Errorf("migrate scylla: schema agreement: %w", err)
	}
	return nil
}

// ddl runs one schema statement and waits for every node to agree on the
// resulting schema before the next statement runs.
func (s *Scylla) ddl(ctx context.Context, stmt string) error {
	if err := s.session.Query(stmt).ExecContext(ctx); err != nil {
		return fmt.Errorf("migrate scylla: %w\nstatement: %s", err, stmt)
	}
	if err := s.session.AwaitSchemaAgreement(ctx); err != nil {
		return fmt.Errorf("migrate scylla: schema agreement: %w", err)
	}
	return nil
}

type applied struct {
	version uint
	name    string
	dirty   bool
}

func (s *Scylla) applied(ctx context.Context) ([]applied, error) {
	iter := s.session.Query(`SELECT version, name, dirty FROM schema_migrations`).IterContext(ctx)
	var (
		out   []applied
		v     int64
		name  string
		dirty bool
	)
	for iter.Scan(&v, &name, &dirty) {
		out = append(out, applied{version: uint(v), name: name, dirty: dirty}) //nolint:gosec // versions are positive
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("migrate scylla: read versions: %w", err)
	}
	slices.SortFunc(out, func(a, b applied) int { return int(a.version) - int(b.version) })
	return out, nil
}

func (s *Scylla) setVersion(ctx context.Context, m migration, dirty bool) error {
	err := s.session.Query(`INSERT INTO schema_migrations (version, name, dirty, applied_at) VALUES (?, ?, ?, ?)`,
		int64(m.Version), m.Name, dirty, time.Now().UTC()).ExecContext(ctx) //nolint:gosec // versions are parsed as uint32
	if err != nil {
		return fmt.Errorf("migrate scylla: record version %d: %w", m.Version, err)
	}
	return nil
}

func (s *Scylla) deleteVersion(ctx context.Context, v uint) error {
	if err := s.session.Query(`DELETE FROM schema_migrations WHERE version = ?`, int64(v)).ExecContext(ctx); err != nil { //nolint:gosec // versions are parsed as uint32
		return fmt.Errorf("migrate scylla: delete version %d: %w", v, err)
	}
	return nil
}

func (s *Scylla) run(ctx context.Context, file string) error {
	b, err := fs.ReadFile(s.src, file)
	if err != nil {
		return fmt.Errorf("migrate scylla: %w", err)
	}
	for _, stmt := range splitCQL(string(b)) {
		if err := s.ddl(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	return nil
}

// state returns the applied rows, refusing to continue if any is dirty.
func (s *Scylla) state(ctx context.Context) ([]applied, error) {
	rows, err := s.applied(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.dirty {
			return nil, fmt.Errorf("%w (scylla version %d)", ErrDirty, r.version)
		}
	}
	return rows, nil
}

func (s *Scylla) Up(ctx context.Context) error {
	rows, err := s.state(ctx)
	if err != nil {
		return err
	}
	done := map[uint]bool{}
	var current uint
	for _, r := range rows {
		done[r.version] = true
		current = max(current, r.version)
	}
	ran := 0
	for _, m := range s.migs {
		if done[m.Version] {
			continue
		}
		if m.Version < current {
			return fmt.Errorf("migrate scylla: migration %d (%s) is older than applied version %d; renumber it", m.Version, m.Name, current)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		s.log.Info("applying", "version", m.Version, "name", m.Name)
		if err := s.setVersion(ctx, m, true); err != nil {
			return err
		}
		if err := s.run(ctx, m.Up); err != nil {
			return err // the row stays dirty
		}
		if err := s.setVersion(ctx, m, false); err != nil {
			return err
		}
		ran++
	}
	if ran == 0 {
		s.log.Info("up to date")
	}
	return nil
}

func (s *Scylla) Down(ctx context.Context, steps int) error {
	if steps < 1 {
		return fmt.Errorf("migrate scylla: steps must be at least 1")
	}
	rows, err := s.state(ctx)
	if err != nil {
		return err
	}
	byVersion := map[uint]migration{}
	for _, m := range s.migs {
		byVersion[m.Version] = m
	}
	for i := len(rows) - 1; i >= 0 && steps > 0; i, steps = i-1, steps-1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, ok := byVersion[rows[i].version]
		if !ok || m.Down == "" {
			return fmt.Errorf("migrate scylla: no .down.cql for applied version %d", rows[i].version)
		}
		s.log.Info("reverting", "version", m.Version, "name", m.Name)
		if err := s.setVersion(ctx, m, true); err != nil {
			return err
		}
		if err := s.run(ctx, m.Down); err != nil {
			return err
		}
		if err := s.deleteVersion(ctx, m.Version); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scylla) Version(ctx context.Context) (uint, bool, error) {
	rows, err := s.applied(ctx)
	if err != nil {
		return 0, false, err
	}
	var (
		v     uint
		dirty bool
	)
	for _, r := range rows {
		v = max(v, r.version)
		dirty = dirty || r.dirty
	}
	return v, dirty, nil
}

func (s *Scylla) Force(ctx context.Context, version uint) error {
	var target *migration
	for i := range s.migs {
		if s.migs[i].Version <= version {
			// Every known migration up to version counts as applied.
			if err := s.setVersion(ctx, s.migs[i], false); err != nil {
				return err
			}
		}
		if s.migs[i].Version == version {
			target = &s.migs[i]
		}
	}
	if version != 0 && target == nil {
		return fmt.Errorf("migrate scylla: no migration with version %d", version)
	}
	rows, err := s.applied(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range rows {
		if r.version > version {
			errs = append(errs, s.deleteVersion(ctx, r.version))
		}
	}
	return errors.Join(errs...)
}

func (s *Scylla) Close() error {
	s.session.Close()
	return nil
}
