package main

// Prometheus metrics (S-37), served on their own listener (metrics.addr),
// never on the client-facing one. The instrumentation lives here, in the
// binary: the store and core expose plain hooks, so embedders of pkg/chat
// do not compile a metrics stack.

import (
	"context"
	"iter"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lioneljmorrison/klacks/internal/store"
)

// poolStats is the Postgres pool's state at scrape time.
type poolStats struct {
	Acquired, Idle, Total, Max int32
}

// latencyBuckets span 0.5ms to ~4s: a lock hold, a Scylla write or a
// bucket read is a few milliseconds when healthy and seconds when not.
var latencyBuckets = prometheus.ExponentialBuckets(0.0005, 2, 14)

type metrics struct {
	reg          *prometheus.Registry
	lockHeldH    prometheus.Histogram
	scyllaInsert prometheus.Histogram
	scyllaRange  prometheus.Histogram
}

// newMetrics registers the klacks metrics, plus the Go runtime and process
// collectors, on a registry of its own. The functions are read at scrape
// time.
func newMetrics(pool func() poolStats, wsConns func() int, slowDisconnects func() int64) *metrics {
	m := &metrics{
		reg: prometheus.NewRegistry(),
		lockHeldH: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "klacks_room_lock_held_seconds",
			Help:    "How long each publish or membership change held its room's room_seq row lock, commit included.",
			Buckets: latencyBuckets,
		}),
		scyllaInsert: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "klacks_scylla_insert_seconds",
			Help:    "ScyllaDB message insert latency (QUORUM), failures included.",
			Buckets: latencyBuckets,
		}),
		scyllaRange: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "klacks_scylla_range_seconds",
			Help:    "ScyllaDB resume read latency (LOCAL_QUORUM): time spent in the store for one whole range, not in its consumer.",
			Buckets: latencyBuckets,
		}),
	}
	gauge := func(name, help string, f func() float64) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, f)
	}
	m.reg.MustRegister(
		m.lockHeldH, m.scyllaInsert, m.scyllaRange,
		gauge("klacks_pg_pool_acquired_conns", "Postgres pool connections in use.", func() float64 { return float64(pool().Acquired) }),
		gauge("klacks_pg_pool_idle_conns", "Postgres pool connections idle.", func() float64 { return float64(pool().Idle) }),
		gauge("klacks_pg_pool_total_conns", "Postgres pool connections open.", func() float64 { return float64(pool().Total) }),
		gauge("klacks_pg_pool_max_conns", "Postgres pool size limit.", func() float64 { return float64(pool().Max) }),
		gauge("klacks_ws_connections", "Open client WebSocket connections.", func() float64 { return float64(wsConns()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "klacks_ws_slow_disconnects_total",
			Help: "Client connections closed because they could not keep up (backpressure).",
		}, func() float64 { return float64(slowDisconnects()) }),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// lockHeld records one room lock hold; store.Rooms.OnLockHeld.
func (m *metrics) lockHeld(d time.Duration) { m.lockHeldH.Observe(d.Seconds()) }

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// timed wraps a message store so its inserts and range reads are timed.
func (m *metrics) timed(s store.MessageStore) store.MessageStore {
	return timedMessages{MessageStore: s, m: m}
}

type timedMessages struct {
	store.MessageStore
	m *metrics
}

func (t timedMessages) Insert(ctx context.Context, msg store.Message, writeTS int64) error {
	start := time.Now()
	err := t.MessageStore.Insert(ctx, msg, writeTS)
	t.m.scyllaInsert.Observe(time.Since(start).Seconds())
	return err
}

func (t timedMessages) Range(ctx context.Context, room store.UUID, after, hi int64) iter.Seq2[store.Message, error] {
	// Only the time spent producing rows counts: the clock stops while the
	// consumer handles each one.
	return func(yield func(store.Message, error) bool) {
		var inStore time.Duration
		resumed := time.Now()
		defer func() { t.m.scyllaRange.Observe((inStore + time.Since(resumed)).Seconds()) }()
		for msg, err := range t.MessageStore.Range(ctx, room, after, hi) {
			inStore += time.Since(resumed)
			if !yield(msg, err) {
				resumed = time.Now()
				return
			}
			resumed = time.Now()
		}
	}
}
