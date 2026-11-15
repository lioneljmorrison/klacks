package main

import (
	"strings"
	"testing"
	"time"
)

func TestPercentiles(t *testing.T) {
	var lat []time.Duration
	for i := 1; i <= 1000; i++ {
		lat = append(lat, time.Duration(i)*time.Millisecond)
	}
	s := summarize(lat)
	if s.N != 1000 || s.P50 != 500*time.Millisecond || s.P99 != 990*time.Millisecond || s.Max != time.Second {
		t.Fatalf("summary = %+v", s)
	}
	if (summarize(nil) != stats{}) {
		t.Fatal("empty summary not zero")
	}
}

func TestPayloadCarriesSendTime(t *testing.T) {
	at := time.Unix(1700000000, 123456789)
	p := payload(at, 64)
	if len(p) != 64 {
		t.Fatalf("len %d", len(p))
	}
	got, ok := sentAt(p)
	if !ok || !got.Equal(at) {
		t.Fatalf("sentAt = %v %v", got, ok)
	}
	if _, ok := sentAt([]byte{1, 2}); ok {
		t.Fatal("short payload parsed")
	}
}

// histogramQuantile estimates a quantile from a Prometheus text exposition
// histogram as the upper bound of the first bucket reaching it.
func TestHistogramQuantile(t *testing.T) {
	text := strings.Join([]string{
		`# TYPE klacks_room_lock_held_seconds histogram`,
		`klacks_room_lock_held_seconds_bucket{le="0.001"} 10`,
		`klacks_room_lock_held_seconds_bucket{le="0.002"} 90`,
		`klacks_room_lock_held_seconds_bucket{le="0.004"} 99`,
		`klacks_room_lock_held_seconds_bucket{le="0.008"} 100`,
		`klacks_room_lock_held_seconds_bucket{le="+Inf"} 100`,
		`klacks_room_lock_held_seconds_count 100`,
		`klacks_pg_pool_acquired_conns 7`,
	}, "\n")
	q, n, ok := histogramQuantile(text, "klacks_room_lock_held_seconds", 0.99)
	if !ok || n != 100 || q != 0.004 {
		t.Fatalf("p99 = %v (n %d, ok %v); want 0.004", q, n, ok)
	}
	if q, _, _ := histogramQuantile(text, "klacks_room_lock_held_seconds", 0.5); q != 0.002 {
		t.Fatalf("p50 = %v; want 0.002", q)
	}
	if v, ok := gaugeValue(text, "klacks_pg_pool_acquired_conns"); !ok || v != 7 {
		t.Fatalf("gauge = %v %v", v, ok)
	}
	if _, _, ok := histogramQuantile(text, "nope", 0.99); ok {
		t.Fatal("missing histogram ok")
	}
}
