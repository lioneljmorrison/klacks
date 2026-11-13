package chat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// ChatService is the messaging core an embedder talks to, as plan §3.6
// defines it. *Service is the implementation Open returns.
type ChatService interface {
	CreateRoom(ctx context.Context, spec RoomSpec) (RoomID, error)
	AddMember(ctx context.Context, room RoomID, user UserID, role Role) error
	PostMessage(ctx context.Context, room RoomID, sender UserID, payload EncryptedPayload) (Seq, error)
	Subscribe(ctx context.Context, room RoomID, fromSeq Seq) (<-chan Message, error)
	RemoveMember(ctx context.Context, room RoomID, user UserID) error

	// Device registration and prekey bundles (S-22, S-23).
	RegisterDevice(ctx context.Context, user UserID, device DeviceID, bundle PrekeyBundle, oneTimePrekeys []Prekey) error
	DeviceBundle(ctx context.Context, user UserID, device DeviceID) (PrekeyBundle, ConsumedPrekey, error)
	AddDevicePrekeys(ctx context.Context, user UserID, device DeviceID, oneTimePrekeys []Prekey) error
	ListDevices(ctx context.Context, user UserID) ([]DeviceInfo, error)
}

// Defaults for Config fields left at zero.
const (
	// DefaultPostgresMaxConns sizes the pool for in-flight publishes and
	// resumes: each publish holds a connection across its ScyllaDB write,
	// each resume across its bucket scans. Size it to the embedder's peak
	// concurrency, not to requests per second.
	DefaultPostgresMaxConns = 16

	// DefaultSendQueue is the per-subscription delivery queue, in messages
	// (see Subscribe): a consumer slower than that, sustained, has its
	// channel closed and must resubscribe from its last seen seq.
	DefaultSendQueue = 256
)

// Config configures Open.
type Config struct {
	// PostgresDSN connects to the migrated relational store (rooms,
	// membership, room_seq). Required.
	PostgresDSN string

	// PostgresMaxConns caps the pool. 0 picks DefaultPostgresMaxConns.
	PostgresMaxConns int32

	// ScyllaHosts and ScyllaKeyspace address the migrated message stream
	// store. Both required; the keyspace must be a plain CQL identifier.
	ScyllaHosts    []string
	ScyllaKeyspace string
	// ScyllaUsername and ScyllaPassword authenticate when the cluster has
	// auth enabled.
	ScyllaUsername string
	ScyllaPassword string

	// ScyllaTimeout bounds one ScyllaDB statement, and with it how long a
	// publish may hold its room lock across the write. Required.
	ScyllaTimeout time.Duration

	// RoomLockTimeout bounds every publish's and membership change's room
	// lock: the transaction's lock_timeout, statement_timeout and
	// idle_in_transaction_session_timeout. It must be longer than
	// ScyllaTimeout (a publish holds the lock across its ScyllaDB write);
	// Open fails otherwise. 0 disables all three timeouts, which releases a
	// lock only when its transaction ends — use knowingly.
	RoomLockTimeout time.Duration

	// Actor is the embedder's service identity (see the package comment):
	// rooms' owner on CreateRoom, the acting user of AddMember and
	// RemoveMember, the authorized reader of Subscribe. Required.
	Actor UserID

	// SendQueue is the per-subscription delivery queue, in messages. 0 picks
	// DefaultSendQueue.
	SendQueue int

	// Log receives diagnostics, such as closed slow consumers. Nil discards.
	Log *slog.Logger
}

// Service is the ChatService implementation: the core wrapped with the
// public types and an in-process subscription hub fed by the core's
// post-commit fan-out.
type Service struct {
	cfg     Config
	log     *slog.Logger
	core    *core.Service
	pool    *pgxpool.Pool
	scylla  *gocql.Session
	devices *store.Devices

	closeOnce sync.Once

	hubMu    sync.Mutex // guards hub, stopping, and every subscription
	hub      map[[16]byte]map[*subscription]struct{}
	stopping bool
	wg       sync.WaitGroup // one per subscription's resume pump
}

var _ ChatService = (*Service)(nil)

// Open wires both stores and returns a running ChatService. Both stores must
// already be migrated. It fails at startup on an unusable configuration (see
// Config) or an unreachable store; after that the stores are the embedder's
// to monitor. Close releases everything Open built.
func Open(ctx context.Context, cfg Config) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	pc, err := pgxpool.ParseConfig(cfg.PostgresDSN)
	if err != nil {
		return nil, fmt.Errorf("chat: postgres: %w", err)
	}
	if max := cfg.PostgresMaxConns; max > 0 {
		pc.MaxConns = max
	} else {
		pc.MaxConns = DefaultPostgresMaxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("chat: postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("chat: postgres ping: %w", err)
	}

	sc, err := store.OpenScylla(config.Scylla{
		Hosts:    cfg.ScyllaHosts,
		Keyspace: cfg.ScyllaKeyspace,
		Username: cfg.ScyllaUsername,
		Password: cfg.ScyllaPassword,
		Timeout:  config.Duration(cfg.ScyllaTimeout),
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("chat: scylla: %w (have the stores been migrated up?)", err)
	}

	s := &Service{
		cfg:     cfg,
		log:     log,
		pool:    pool,
		devices: store.NewDevices(pool),
		hub:     make(map[[16]byte]map[*subscription]struct{}),
	}
	s.core = core.New(store.NewRooms(pool, cfg.RoomLockTimeout), store.NewScyllaMessages(sc), s.Deliver, nil)
	return s, nil
}

// validate reports every problem with the configuration at once. It runs
// before anything is opened, so a bad configuration never touches a store.
func (c Config) validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.PostgresDSN == "" {
		bad("postgres dsn is required")
	}
	if c.PostgresMaxConns < 0 {
		bad("postgres max conns must not be negative")
	}
	if len(c.ScyllaHosts) == 0 {
		bad("scylla hosts are required")
	}
	if !keyspaceRE.MatchString(c.ScyllaKeyspace) {
		bad("scylla keyspace %q must be a letter followed by up to 47 letters, digits or underscores", c.ScyllaKeyspace)
	}
	if c.ScyllaTimeout <= 0 {
		bad("scylla timeout must be positive")
	}
	switch {
	case c.RoomLockTimeout < 0:
		bad("room lock timeout must not be negative")
	case c.RoomLockTimeout > 0 && c.RoomLockTimeout <= c.ScyllaTimeout:
		bad("room lock timeout %s must be longer than the scylla timeout %s: a publish holds the lock across its scylla write", c.RoomLockTimeout, c.ScyllaTimeout)
	}
	if c.Actor == (UserID{}) {
		bad("actor is required: the service identity every room change acts as")
	}
	if c.SendQueue < 0 {
		bad("send queue must not be negative")
	}
	if len(errs) > 0 {
		return fmt.Errorf("chat: %w: %w", ErrInvalidArgument, errors.Join(errs...))
	}
	return nil
}

// keyspaceRE matches names CQL accepts unquoted; the keyspace is spliced
// into CQL statements, so nothing else is allowed.
var keyspaceRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,47}$`)

// queueSize is the subscription delivery queue: the config's, or the
// default when unset.
func (s *Service) queueSize() int {
	if s.cfg.SendQueue > 0 {
		return s.cfg.SendQueue
	}
	return DefaultSendQueue
}

// CreateRoom creates a room of the spec's kind with the service actor as its
// owner and returns the generated room ID.
func (s *Service) CreateRoom(ctx context.Context, spec RoomSpec) (RoomID, error) {
	id, err := s.core.CreateRoom(ctx, core.Kind(spec.Kind), store.UUID(s.cfg.Actor))
	if err != nil {
		return RoomID{}, fmt.Errorf("create room: %w", err)
	}
	return RoomID(id), nil
}

// AddMember adds user to room with role, acting as the service actor.
func (s *Service) AddMember(ctx context.Context, room RoomID, user UserID, role Role) error {
	if err := s.core.AddMember(ctx, store.UUID(room), store.UUID(s.cfg.Actor), store.UUID(user), core.Role(role)); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// RemoveMember removes user from room, acting as the service actor. The
// actor's owner role may remove anyone; leaving as an end user is not part
// of the embedded API yet.
func (s *Service) RemoveMember(ctx context.Context, room RoomID, user UserID) error {
	if err := s.core.RemoveMember(ctx, store.UUID(room), store.UUID(s.cfg.Actor), store.UUID(user)); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return nil
}

// PostMessage publishes payload to room as sender and returns its seq. Seqs
// are per room, gap-free and start at 1. Sender must be a member.
func (s *Service) PostMessage(ctx context.Context, room RoomID, sender UserID, payload EncryptedPayload) (Seq, error) {
	seq, err := s.core.PostMessage(ctx, store.UUID(room), store.UUID(sender), core.Payload{
		MessageID:  payload.MessageID,
		DeviceID:   payload.DeviceID,
		Ciphertext: payload.Ciphertext,
		Header:     payload.Header,
	})
	if err != nil {
		return 0, fmt.Errorf("post message: %w", err)
	}
	return Seq(seq), nil
}

// Close stops every subscription (their channels close), waits for the
// in-flight replays to end, and closes both stores. Publishing or
// subscribing after Close fails; the embedder must stop its callers first.
// Close is idempotent.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.hubMu.Lock()
		s.stopping = true
		for room := range s.hub {
			for sub := range s.hub[room] {
				if sub.cancel != nil {
					sub.cancel()
				}
				s.closeSubLocked(sub)
			}
		}
		s.hubMu.Unlock()
		s.wg.Wait()
		if s.scylla != nil {
			s.scylla.Close()
		}
		if s.pool != nil {
			s.pool.Close()
		}
	})
}
