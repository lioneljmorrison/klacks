// Package ratelimit is an in-memory, per-key token bucket (S-32). It is
// single-node: each klacks process limits what it sees.
package ratelimit

import (
	"errors"
	"math"
	"sync"
	"time"
)

// Limit is a token bucket: Rate tokens per second refill up to Burst. The
// zero Limit means unlimited.
type Limit struct {
	Rate  float64 `json:"rate"`
	Burst int     `json:"burst"`
}

// Off reports whether l is the zero, unlimited Limit.
func (l Limit) Off() bool { return l.Rate == 0 && l.Burst == 0 }

// Validate reports a Limit that is neither off nor a usable bucket.
func (l Limit) Validate() error {
	if l.Off() {
		return nil
	}
	if l.Rate <= 0 || l.Burst < 1 {
		return errors.New("rate must be positive and burst at least 1 (or both 0 for no limit)")
	}
	return nil
}

// sweepEvery is how often idle, full buckets are dropped.
const sweepEvery = time.Minute

// Keyed limits each key separately. A nil *Keyed allows everything.
type Keyed struct {
	limit Limit
	now   func() time.Time // tests pin the clock

	mu        sync.Mutex
	buckets   map[[16]byte]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter for l, or nil (unlimited) when l is off.
func New(l Limit) *Keyed {
	if l.Off() {
		return nil
	}
	return &Keyed{limit: l, now: time.Now, buckets: make(map[[16]byte]*bucket)}
}

// Allow takes a token from key's bucket and reports whether there was one.
func (k *Keyed) Allow(key [16]byte) bool {
	if k == nil {
		return true
	}
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sweepLocked(now)
	b, ok := k.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(k.limit.Burst), last: now}
		k.buckets[key] = b
	}
	k.refill(b, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfter is how many whole seconds one token takes to refill: a
// Retry-After hint for a refused caller. It is at least 1.
func (k *Keyed) RetryAfter() int {
	if k == nil {
		return 1
	}
	return max(1, int(math.Ceil(1/k.limit.Rate)))
}

func (k *Keyed) refill(b *bucket, now time.Time) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(float64(k.limit.Burst), b.tokens+el*k.limit.Rate)
		b.last = now
	}
}

// sweepLocked drops buckets that have refilled to Burst: a full bucket
// answers exactly like a fresh one, so dropping it changes nothing but
// memory.
func (k *Keyed) sweepLocked(now time.Time) {
	if k.lastSweep.IsZero() {
		k.lastSweep = now
	}
	if now.Sub(k.lastSweep) < sweepEvery {
		return
	}
	k.lastSweep = now
	for key, b := range k.buckets {
		k.refill(b, now)
		if b.tokens >= float64(k.limit.Burst) {
			delete(k.buckets, key)
		}
	}
}

func (k *Keyed) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}
