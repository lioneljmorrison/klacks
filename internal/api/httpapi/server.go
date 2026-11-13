package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/lioneljmorrison/klacks/internal/config"
)

// Server is the HTTP server with graceful shutdown.
type Server struct {
	cfg    config.HTTP
	srv    *http.Server
	health *Health
	log    *slog.Logger
}

// NewServer builds the server and its routes. ws serves GET /ws; if it is
// nil, /ws is not mounted.
func NewServer(cfg config.HTTP, health *Health, ws http.Handler, log *slog.Logger) *Server {
	mux := http.NewServeMux()
	health.Register(mux)
	if ws != nil {
		mux.Handle("GET /ws", ws)
	}
	return &Server{
		cfg:    cfg,
		health: health,
		log:    log,
		srv: &http.Server{
			Addr:              cfg.Addr,
			Handler:           mux,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout.D(),
			ReadTimeout:       cfg.ReadTimeout.D(),
			WriteTimeout:      cfg.WriteTimeout.D(),
			IdleTimeout:       cfg.IdleTimeout.D(),
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		},
	}
}

// OnShutdown registers f to run when shutdown begins, for long-lived
// connections (such as WebSockets) that Shutdown does not track.
func (s *Server) OnShutdown(f func()) { s.srv.RegisterOnShutdown(f) }

// ListenAndServe listens on cfg.Addr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled, then shuts down gracefully:
// /readyz starts failing, then after cfg.DrainDelay the listener closes and
// in-flight requests get up to cfg.ShutdownTimeout to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- s.srv.Serve(ln) }()
	s.log.Info("http server listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		return fmt.Errorf("http: %w", err)
	case <-ctx.Done():
	}

	s.health.Drain()
	if d := s.cfg.DrainDelay.D(); d > 0 {
		s.log.Info("draining: /readyz now fails; waiting before closing the listener", "delay", d)
		time.Sleep(d)
	}
	s.log.Info("http server shutting down", "timeout", s.cfg.ShutdownTimeout.D())
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownTimeout.D())
	defer cancel()
	if err := s.srv.Shutdown(shutdownCtx); err != nil {
		_ = s.srv.Close()
		return fmt.Errorf("http: shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http: %w", err)
	}
	s.log.Info("http server stopped")
	return nil
}
