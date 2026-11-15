package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest(l Limit) (*Keyed, *clock) {
	c := &clock{t: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}
	k := New(l)
	k.now = c.now
	return k, c
}

var a, b = [16]byte{1}, [16]byte{2}

func allowN(k *Keyed, key [16]byte, n int) int {
	ok := 0
	for range n {
		if k.Allow(key) {
			ok++
		}
	}
	return ok
}

func TestBurstThenRefill(t *testing.T) {
	k, c := newTest(Limit{Rate: 2, Burst: 5})
	if got := allowN(k, a, 10); got != 5 {
		t.Fatalf("burst: %d allowed; want 5", got)
	}
	c.advance(500 * time.Millisecond) // 1 token
	if got := allowN(k, a, 10); got != 1 {
		t.Fatalf("after 0.5s at 2/s: %d allowed; want 1", got)
	}
	c.advance(time.Hour) // refills, but never beyond burst
	if got := allowN(k, a, 10); got != 5 {
		t.Fatalf("after idle: %d allowed; want burst 5", got)
	}
}

func TestKeysIndependent(t *testing.T) {
	k, _ := newTest(Limit{Rate: 1, Burst: 1})
	if !k.Allow(a) || k.Allow(a) {
		t.Fatal("a: want one allowed then refused")
	}
	if !k.Allow(b) {
		t.Fatal("b refused because of a")
	}
}

func TestZeroLimitIsOff(t *testing.T) {
	for _, k := range []*Keyed{New(Limit{}), nil} {
		if got := allowN(k, a, 10000); got != 10000 {
			t.Errorf("%v: %d allowed; want all", k, got)
		}
	}
	if New(Limit{}) != nil {
		t.Error("New(zero) should be nil (off)")
	}
}

// A bucket idle long enough to be full again is indistinguishable from a
// fresh one, so sweeping it must not change any answer.
func TestSweepEvictsOnlyFullBuckets(t *testing.T) {
	k, c := newTest(Limit{Rate: 1, Burst: 3})
	allowN(k, a, 3) // a empty
	c.advance(sweepEvery)
	allowN(k, b, 1) // triggers a sweep; a has refilled fully, b just used
	if n := k.len(); n != 1 {
		t.Fatalf("after sweep: %d buckets; want 1 (b)", n)
	}
	if got := allowN(k, a, 10); got != 3 {
		t.Fatalf("a after eviction: %d allowed; want 3", got)
	}
	// A bucket still refilling is kept.
	allowN(k, a, 3)
	c.advance(sweepEvery)
	k2, _ := newTest(Limit{Rate: 0.001, Burst: 3})
	k2.now = c.now
	allowN(k2, a, 3)
	c.advance(sweepEvery)
	allowN(k2, b, 1)
	if got := allowN(k2, a, 10); got != 0 {
		t.Fatalf("slow bucket swept while refilling: %d allowed; want 0", got)
	}
}

func TestConcurrentAllowNeverExceedsBurst(t *testing.T) {
	k, _ := newTest(Limit{Rate: 1e-9, Burst: 50})
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := allowN(k, a, 10)
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 50 {
		t.Fatalf("%d allowed concurrently; want burst 50", total)
	}
}

func TestLimitValidate(t *testing.T) {
	for _, l := range []Limit{{}, {Rate: 1, Burst: 1}, {Rate: 0.5, Burst: 10}} {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
	for _, l := range []Limit{{Rate: -1, Burst: 1}, {Rate: 1, Burst: 0}, {Rate: 0, Burst: 5}} {
		if err := l.Validate(); err == nil {
			t.Errorf("%+v accepted", l)
		}
	}
}
