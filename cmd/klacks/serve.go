package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	chatv1 "github.com/lioneljmorrison/klacks/api/gen/klacks/chat/v1"
	"github.com/lioneljmorrison/klacks/internal/api/devui"
	"github.com/lioneljmorrison/klacks/internal/api/grpcapi"
	"github.com/lioneljmorrison/klacks/internal/api/httpapi"
	"github.com/lioneljmorrison/klacks/internal/api/ws"
	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// cmdServe connects to both stores and serves HTTP, and gRPC when
// configured, until ctx is cancelled (SIGINT/SIGTERM). It fails fast if a
// store is unreachable at startup; after that, /readyz reports store
// outages.
func cmdServe(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	log.Info("starting klacks", "version", version, "env", cfg.Env)

	connectCtx, cancel := context.WithTimeout(ctx, cfg.Scylla.Timeout.D()*2)
	defer cancel()
	pg, err := store.OpenPostgres(connectCtx, cfg.Postgres.DSN)
	if err != nil {
		return err
	}
	defer pg.Close()
	scylla, err := store.OpenScylla(cfg.Scylla)
	if err != nil {
		return fmt.Errorf("%w (has `klacks migrate up` created keyspace %q?)", err, cfg.Scylla.Keyspace)
	}
	defer scylla.Close()

	s, err := newServers(cfg, pg, scylla, log)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	httpLn, err := lc.Listen(ctx, "tcp", cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	var grpcLn net.Listener
	if s.grpc != nil {
		if grpcLn, err = lc.Listen(ctx, "tcp", cfg.GRPC.Addr); err != nil {
			_ = httpLn.Close()
			return fmt.Errorf("grpc: %w", err)
		}
	}
	if err := s.serve(ctx, httpLn, grpcLn); err != nil {
		return err
	}
	log.Info("klacks stopped")
	return nil
}

// servers is everything klacks serve runs over one pair of stores: the
// HTTP server (health, /ws, prekey API, dev tooling) and, when configured,
// the gRPC API. Both transports share one core (S-45).
type servers struct {
	log  *slog.Logger
	http *httpapi.Server
	mgr  *ws.Manager // nil without a client authenticator

	grpc     *grpc.Server  // nil without grpc.addr
	grpcTLS  bool          // for the listening log line
	chat     *chat.Service // the gRPC adapter's service; nil without gRPC
	stopWait time.Duration // how long gRPC may take to stop gracefully
}

// newServers builds the servers over pg and scylla.
func newServers(cfg config.Config, pg *pgxpool.Pool, scylla *gocql.Session, log *slog.Logger) (*servers, error) {
	health := httpapi.NewHealth([]httpapi.Check{
		store.PostgresCheck{Pool: pg},
		store.ScyllaCheck{Session: scylla},
	}, cfg.HTTP.ReadyTimeout.D(), log)

	s := &servers{log: log, stopWait: cfg.HTTP.ShutdownTimeout.D()}
	var (
		wsHandler http.Handler
		devices   *httpapi.Devices
		devRooms  *httpapi.DevRooms
	)
	a, err := clientAuthenticator(cfg)
	if err != nil {
		return nil, err
	}
	dev := devTools(a)
	if a != nil {
		s.mgr = ws.NewManager(a, log)
	}

	// The room and message stores are built once, for whichever core
	// serves: anything that instruments them sees both transports.
	rooms := store.NewRooms(pg, roomLockTimeout)
	var messages store.MessageStore = store.NewScyllaMessages(scylla)

	// One core serves both transports. Its post-commit fan-out and its
	// removals reach the WebSocket hub and, with gRPC, the chat service's
	// subscription hub, so each transport sees the other's messages live
	// and a removal through gRPC still reaches the removed member's
	// sockets (S-29).
	var svc *core.Service
	if cfg.GRPC.Enabled() {
		actor, err := store.ParseUUID(cfg.GRPC.Actor)
		if err != nil {
			return nil, fmt.Errorf("grpc.actor: %w", err)
		}
		var (
			posted  func(context.Context, store.Message)
			removed func(context.Context, core.MemberRemoved)
		)
		if s.mgr != nil {
			posted, removed = s.mgr.Deliver, s.mgr.MemberRemoved
		}
		s.chat, svc, err = chat.NewShared(chat.Config{
			Actor: chat.UserID(actor),
			Log:   log,
		}, pg, rooms, messages, posted, removed)
		if err != nil {
			return nil, err
		}
		if s.grpc, err = newGRPCServer(cfg.GRPC, s.chat); err != nil {
			return nil, err
		}
		s.grpcTLS = cfg.GRPC.TLS()
		if !s.grpcTLS {
			log.Warn("grpc is plaintext (no grpc.tls_cert_file): service tokens cross the network in the clear unless a TLS proxy fronts it")
		}
	} else if s.mgr != nil {
		svc = core.New(rooms, messages, s.mgr.Deliver, s.mgr.MemberRemoved)
	}

	if s.mgr != nil {
		devices = httpapi.NewDevices(a, store.NewDevices(pg), log)
		s.mgr.Chat = svc
		wsHandler = s.mgr
		// The dev room endpoints shim core's room management over REST,
		// so the browser test client can create and populate rooms.
		if dev {
			devRooms = httpapi.NewDevRooms(a, roomAdmin{svc: svc}, log)
			log.Warn("client auth is the dev stub: any claimed identity is trusted")
		} else {
			log.Info("client auth is JWT", "issuer", cfg.Auth.JWT.Issuer, "audience", cfg.Auth.JWT.Audience)
		}
	} else {
		log.Warn("no client authenticator for this env (set auth.jwt); /ws and the prekey bundle API are not served", "env", cfg.Env)
	}

	handler := http.Handler(nil)
	// The dev UI rides the dev gate too: it exists for testing against the
	// dev authenticator and mounts nowhere else.
	if dev {
		ui, err := devui.New()
		if err != nil {
			return nil, err
		}
		handler = ui
	}

	s.http = httpapi.NewServer(cfg.HTTP, health, wsHandler, devices, log)
	// The browser client must share the server's origin (/ws rejects
	// cross-origin upgrades), so the dev tooling is mounted on the mux the
	// server serves rather than a separate listener. A wrapper mux routes
	// /devui and /v1/dev/rooms to their handlers and everything else to the
	// server's routes; the server's graceful shutdown and Handler() keep
	// working through it.
	if handler != nil || devRooms != nil {
		outer := http.NewServeMux()
		if handler != nil {
			outer.Handle("GET /devui", handler)
			outer.Handle("GET /devui/", handler)
		}
		if devRooms != nil {
			devRooms.Register(outer)
		}
		outer.Handle("/", s.http.Handler())
		s.http.UseHandler(outer)
	}
	return s, nil
}

// newGRPCServer builds the gRPC server for ChatService behind the service
// tokens, over TLS when configured.
func newGRPCServer(cfg config.GRPC, svc *chat.Service) (*grpc.Server, error) {
	tokens, err := grpcapi.NewServiceTokens(cfg.ServiceTokens...)
	if err != nil {
		return nil, err
	}
	opts := tokens.ServerOptions()
	if cfg.TLS() {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("grpc tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	gs := grpc.NewServer(opts...)
	chatv1.RegisterChatServiceServer(gs, grpcapi.New(svc))
	return gs, nil
}

// serve serves HTTP on httpLn and, with gRPC, gRPC on grpcLn, until ctx is
// cancelled or either server fails; then it stops both. HTTP drains and
// shuts down first, then the WebSockets close. The chat service closes
// next, ending every Subscribe stream (they never end on their own, so a
// graceful stop would otherwise wait out the timeout), and gRPC stops
// gracefully, forcibly after the shutdown timeout.
func (s *servers) serve(ctx context.Context, httpLn, grpcLn net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		grpcErr  error
		grpcDone = make(chan struct{})
	)
	if s.grpc != nil {
		go func() {
			defer close(grpcDone)
			grpcErr = s.grpc.Serve(grpcLn)
			cancel() // a failed gRPC server takes HTTP down with it
		}()
		s.log.Info("grpc server listening", "addr", grpcLn.Addr().String(), "tls", s.grpcTLS)
	} else {
		close(grpcDone)
	}

	httpErr := s.http.Serve(ctx, httpLn)
	if s.mgr != nil {
		// Shutdown does not track WebSockets: close them now that HTTP
		// has stopped, and wait for them.
		s.mgr.Close()
	}
	if s.grpc != nil {
		s.chat.Close()
		stopped := make(chan struct{})
		go func() {
			s.grpc.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(s.stopWait):
			s.log.Warn("grpc graceful stop timed out; stopping")
			s.grpc.Stop()
			<-stopped
		}
		s.log.Info("grpc server stopped")
	}
	<-grpcDone
	if grpcErr != nil {
		grpcErr = fmt.Errorf("grpc: %w", grpcErr)
	}
	return errors.Join(httpErr, grpcErr)
}

// roomLockTimeout bounds every publish's and membership change's room lock
// (store.NewRooms). It must be longer than the ScyllaDB write timeout, since
// a publish holds the lock across its ScyllaDB write.
const roomLockTimeout = 10 * time.Second

// roomAdmin adapts core.Service's typed Kind/Role to the dev rooms
// handlers' string form.
type roomAdmin struct {
	svc *core.Service
}

func (a roomAdmin) CreateRoomWithID(ctx context.Context, room store.UUID, kind string, creator store.UUID) error {
	return a.svc.CreateRoomWithID(ctx, room, core.Kind(kind), creator)
}

func (a roomAdmin) AddMember(ctx context.Context, room, actor, user store.UUID, role string) error {
	if role == "" {
		role = string(core.RoleMember)
	}
	return a.svc.AddMember(ctx, room, actor, user, core.Role(role))
}

func (a roomAdmin) RemoveMember(ctx context.Context, room, actor, user store.UUID) error {
	return a.svc.RemoveMember(ctx, room, actor, user)
}

func (a roomAdmin) Members(ctx context.Context, room store.UUID) ([]store.UUID, error) {
	return a.svc.Members(ctx, room)
}

// clientAuthenticator returns the authenticator for client connections, or
// nil if there is none. A configured JWT key wins in every env; without one,
// env dev gets the dev stub, which trusts any claimed identity, and any other
// env gets nothing.
func clientAuthenticator(cfg config.Config) (auth.Authenticator, error) {
	if cfg.Auth.JWT.Enabled() {
		b, err := os.ReadFile(cfg.Auth.JWT.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt.public_key_file: %w", err)
		}
		key, err := auth.ParseEd25519PublicKeyPEM(b)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt.public_key_file %s: %w", cfg.Auth.JWT.PublicKeyFile, err)
		}
		return auth.NewJWT(key, cfg.Auth.JWT.Issuer, cfg.Auth.JWT.Audience)
	}
	if cfg.Env == config.EnvDev {
		return auth.Dev{}, nil
	}
	return nil, nil
}

// devTools reports whether the dev UI and dev room endpoints are mounted:
// only alongside the dev stub, since they exist to test with claimed
// identities and must never sit next to real auth.
func devTools(a auth.Authenticator) bool {
	_, ok := a.(auth.Dev)
	return ok
}
