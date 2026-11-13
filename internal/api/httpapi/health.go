// Package httpapi is the HTTP transport: health endpoints now, REST and the
// WebSocket endpoint later.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Check is one readiness dependency, such as a database.
type Check interface {
	Name() string
	Check(ctx context.Context) error
}

// Health serves /healthz (liveness) and /readyz (readiness).
type Health struct {
	checks   []Check
	timeout  time.Duration
	log      *slog.Logger
	draining atomic.Bool
}

// NewHealth returns health handlers that run checks, each with its own
// timeout, on every /readyz request.
func NewHealth(checks []Check, timeout time.Duration, log *slog.Logger) *Health {
	return &Health{checks: checks, timeout: timeout, log: log}
}

// Drain makes /readyz fail from now on, so load balancers stop sending new
// traffic while in-flight requests finish.
func (h *Health) Drain() { h.draining.Store(true) }

// Register adds the endpoints to mux.
func (h *Health) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.liveness)
	mux.HandleFunc("GET /readyz", h.readiness)
}

type readyResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

func (h *Health) liveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, readyResponse{Status: "ok"})
}

func (h *Health) readiness(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, readyResponse{Status: "draining"})
		return
	}
	results := make(map[string]string, len(h.checks))
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		ready = true
	)
	for _, c := range h.checks {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
			defer cancel()
			err := c.Check(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				ready = false
				results[c.Name()] = "unavailable"
				// Details go to the log, not to unauthenticated callers.
				h.log.Warn("readiness check failed", "check", c.Name(), "err", err)
				return
			}
			results[c.Name()] = "ok"
		})
	}
	wg.Wait()
	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, readyResponse{Status: "unavailable", Checks: results})
		return
	}
	writeJSON(w, http.StatusOK, readyResponse{Status: "ready", Checks: results})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
