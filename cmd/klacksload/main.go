// Command klacksload is the S-34 load generator: many WebSocket clients in
// rooms, a sustained publish rate spread across the rooms, and end-to-end
// delivery latency measured at every receiver.
//
// It speaks the wire protocol directly with opaque payloads (the server
// never decrypts, so E2EE adds nothing to its load) and needs a dev server
// (env=dev: dev auth and the /v1/dev/rooms API). Each payload carries its
// send time; generator and server share the host's clock.
//
//	klacksload -base http://127.0.0.1:8080 -metrics http://127.0.0.1:9090 \
//	    -rooms 1000 -members 10 -rate 1000 -duration 60s
//
// After the steady phase every room is resumed once from seq 0 by one
// member (ScyllaDB range reads), then the server's /metrics is scraped for
// lock hold, ScyllaDB insert and range p99, and pool use.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/lioneljmorrison/klacks/internal/protocol"
	"github.com/lioneljmorrison/klacks/internal/store"
)

type config struct {
	base, metrics    string
	rooms, members   int
	rate             float64
	duration, warmup time.Duration
	size             int
	dialers          int
	runID            string
	phase            string
	maxP99           time.Duration
}

// result is what a load run measured, for the gate's verdict.
type result struct {
	p99                       time.Duration
	expected, delivered       int64
	gaps, errFrames           int
	pubErrs, slowDisconnects  int64
	roomsWithHistory, resumed int
}

// maxShortfall is the fraction of expected deliveries a run may miss and
// still pass: deliveries in flight when the drain ends are not counted,
// while a lost message also shows up as a seq gap or a short resume.
const maxShortfall = 0.001

// check returns one failure per threshold r misses (none: the run passes).
// A zero maxP99 reports latency without checking it.
func check(r result, maxP99 time.Duration) []string {
	var f []string
	if r.expected == 0 {
		return []string{"no measured deliveries were expected: nothing was published in the measured window"}
	}
	if maxP99 > 0 && r.p99 > maxP99 {
		f = append(f, fmt.Sprintf("delivery p99 %v is over the %v limit", r.p99, maxP99))
	}
	if r.gaps > 0 {
		f = append(f, fmt.Sprintf("%d seq gap(s) seen", r.gaps))
	}
	if r.errFrames > 0 {
		f = append(f, fmt.Sprintf("%d error frame(s) received", r.errFrames))
	}
	if r.pubErrs > 0 {
		f = append(f, fmt.Sprintf("%d publish write error(s)", r.pubErrs))
	}
	if r.slowDisconnects > 0 {
		f = append(f, fmt.Sprintf("%d slow-consumer disconnect(s)", r.slowDisconnects))
	}
	if short := r.expected - r.delivered; float64(short) > maxShortfall*float64(r.expected) {
		f = append(f, fmt.Sprintf("%d of %d expected deliveries missing", short, r.expected))
	}
	if r.resumed < r.roomsWithHistory {
		f = append(f, fmt.Sprintf("%d of %d rooms did not finish the resume phase", r.roomsWithHistory-r.resumed, r.roomsWithHistory))
	}
	return f
}

func main() {
	var c config
	flag.StringVar(&c.base, "base", "http://127.0.0.1:8080", "dev server base URL")
	flag.StringVar(&c.metrics, "metrics", "", "server metrics base URL (empty: skip server-side stats)")
	flag.IntVar(&c.rooms, "rooms", 100, "rooms")
	flag.IntVar(&c.members, "members", 10, "members per room; one connection each")
	flag.Float64Var(&c.rate, "rate", 100, "publishes per second, all rooms together")
	flag.DurationVar(&c.duration, "duration", 30*time.Second, "measured steady phase")
	flag.DurationVar(&c.warmup, "warmup", 5*time.Second, "unmeasured publishing before it")
	flag.IntVar(&c.size, "size", 256, "ciphertext bytes per message")
	flag.IntVar(&c.dialers, "dialers", 200, "concurrent dials while connecting")
	flag.StringVar(&c.runID, "run-id", "", "UUID naming this run's rooms and users (default: random); reuse it for -phase resume")
	flag.StringVar(&c.phase, "phase", "load", "load: create rooms, connect, publish, resume; resume: only resume each room from 0 (run after restarting the server, so reads come from ScyllaDB, not the replay buffer)")
	flag.DurationVar(&c.maxP99, "max-p99", 0, "load phase: fail (exit 1) if delivery p99 exceeds this; seq gaps, error frames, publish errors, slow-consumer disconnects, missing deliveries and unfinished resumes always fail (0: don't check p99)")
	flag.Parse()
	if err := run(context.Background(), c, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "klacksload:", err)
		os.Exit(1)
	}
}

// conn is one member's connection.
type conn struct {
	user, device store.UUID
	room         int
	ws           *websocket.Conn

	mu        sync.Mutex
	lat       []time.Duration // measured deliveries from other senders
	lastSeq   int64
	gaps      int
	errFrames int
	resumed   chan int64 // resume phase: seqs seen at or below the target
}

type room struct {
	id      store.UUID
	members []*conn
	nextPub int // round-robin publisher among members
}

func run(ctx context.Context, c config, out io.Writer) error {
	if c.size < 8 {
		return fmt.Errorf("size must be at least 8")
	}
	if c.rooms < 1 || c.rooms > math.MaxUint32 || c.members < 2 || c.members > math.MaxUint16 || c.rate <= 0 {
		return fmt.Errorf("need 1..%d rooms, 2..%d members and a positive rate", uint32(math.MaxUint32), math.MaxUint16)
	}
	run := newID() // keeps rooms and users of separate runs apart
	if c.runID != "" {
		var err error
		if run, err = store.ParseUUID(c.runID); err != nil {
			return fmt.Errorf("-run-id: %w", err)
		}
	}
	fmt.Fprintf(out, "run id %s\n", store.FormatUUID(run))
	rooms := make([]*room, c.rooms)
	var all []*conn
	for r := range rooms {
		rm := &room{id: derive(run, "room", r, 0)}
		for m := 0; m < c.members; m++ {
			cn := &conn{user: derive(run, "user", r, m), device: derive(run, "device", r, m), room: r}
			rm.members = append(rm.members, cn)
			all = append(all, cn)
		}
		rooms[r] = rm
	}

	if c.phase == "resume" {
		return coldResume(ctx, c, rooms, out)
	}
	fmt.Fprintf(out, "setup: %d rooms x %d members = %d connections\n", c.rooms, c.members, len(all))
	t0 := time.Now()
	if err := parallel(len(rooms), c.dialers, func(i int) error { return createRoom(ctx, c.base, rooms[i]) }); err != nil {
		return fmt.Errorf("create rooms: %w", err)
	}
	fmt.Fprintf(out, "rooms created in %v\n", time.Since(t0).Round(time.Millisecond))

	var measuring atomic.Bool
	t0 = time.Now()
	var dialFail atomic.Int64
	err := parallel(len(all), c.dialers, func(i int) error {
		cn := all[i]
		if err := cn.dial(ctx, c.base, rooms[cn.room].id); err != nil {
			dialFail.Add(1)
			return err
		}
		go cn.read(&measuring)
		return nil
	})
	if err != nil {
		return fmt.Errorf("connect (%d failed): %w", dialFail.Load(), err)
	}
	fmt.Fprintf(out, "connected %d in %v\n", len(all), time.Since(t0).Round(time.Millisecond))
	time.Sleep(2 * time.Second) // let subscriptions settle

	poolMax := sampleGauge(c.metrics, "klacks_pg_pool_acquired_conns")
	defer poolMax.stop()

	fmt.Fprintf(out, "publishing %.0f/s: %v warmup, %v measured\n", c.rate, c.warmup, c.duration)
	sent, pubErrs := publish(ctx, rooms, c, &measuring)
	time.Sleep(3 * time.Second) // drain in-flight deliveries
	measuring.Store(false)

	var lat []time.Duration
	gaps, errFrames := 0, 0
	for _, cn := range all {
		cn.mu.Lock()
		lat = append(lat, cn.lat...)
		gaps += cn.gaps
		errFrames += cn.errFrames
		cn.mu.Unlock()
	}
	s := summarize(lat)
	expected := int64(float64(sent) * float64(c.members-1))
	fmt.Fprintf(out, "\nmeasured publishes: %d (%.0f/s), publish write errors: %d\n", sent, float64(sent)/c.duration.Seconds(), pubErrs)
	fmt.Fprintf(out, "deliveries to other members: %d of %d expected (%.0f/s)\n", s.N, expected, float64(s.N)/c.duration.Seconds())
	fmt.Fprintf(out, "delivery latency: p50 %v  p95 %v  p99 %v  max %v\n", s.P50, s.P95, s.P99, s.Max)
	fmt.Fprintf(out, "seq gaps seen: %d, error frames: %d\n", gaps, errFrames)

	t0 = time.Now()
	resumed, withHistory := resumeAll(ctx, rooms)
	fmt.Fprintf(out, "resume phase: %d of %d rooms resumed from 0 in %v\n", resumed, withHistory, time.Since(t0).Round(time.Millisecond))

	res := result{
		p99: s.P99, expected: expected, delivered: int64(s.N),
		gaps: gaps, errFrames: errFrames, pubErrs: pubErrs,
		roomsWithHistory: withHistory, resumed: resumed,
	}
	if c.metrics != "" {
		text, err := scrape(c.metrics)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "\nserver (cumulative since start; p99 = upper bound of the bucket reaching 99%):")
		for _, h := range []string{"klacks_room_lock_held_seconds", "klacks_scylla_insert_seconds", "klacks_scylla_range_seconds"} {
			p99, n, ok := histogramQuantile(text, h, 0.99)
			p50, _, _ := histogramQuantile(text, h, 0.5)
			if ok {
				fmt.Fprintf(out, "  %-32s n=%-8d p50<=%-8s p99<=%s\n", h, n, secs(p50), secs(p99))
			}
		}
		maxConns, _ := gaugeValue(text, "klacks_pg_pool_max_conns")
		fmt.Fprintf(out, "  pg pool acquired: max sampled %.0f of %.0f\n", poolMax.stop(), maxConns)
		if v, ok := gaugeValue(text, "klacks_ws_slow_disconnects_total"); ok {
			fmt.Fprintf(out, "  slow-consumer disconnects: %.0f\n", v)
			res.slowDisconnects = int64(v)
		}
	}
	for _, cn := range all {
		_ = cn.ws.Close(websocket.StatusNormalClosure, "")
	}
	if f := check(res, c.maxP99); len(f) > 0 {
		fmt.Fprintln(out, "\nFAIL")
		for _, s := range f {
			fmt.Fprintln(out, "  "+s)
		}
		return fmt.Errorf("%d check(s) failed", len(f))
	}
	if c.maxP99 > 0 {
		fmt.Fprintf(out, "\nPASS (p99 limit %v)\n", c.maxP99)
	}
	return nil
}

func secs(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return time.Duration(f * float64(time.Second)).String()
}

// publish runs warmup then the measured phase at c.rate, round-robin over
// rooms and, within a room, over its members. It returns the measured
// publishes sent and write errors.
func publish(ctx context.Context, rooms []*room, c config, measuring *atomic.Bool) (sent, errs int64) {
	interval := time.Duration(float64(time.Second) / c.rate)
	start := time.Now()
	end := start.Add(c.warmup + c.duration)
	var wg sync.WaitGroup
	var nSent, nErr atomic.Int64
	sem := make(chan struct{}, 512)
	r := 0
	for i := int64(0); ; i++ {
		at := start.Add(time.Duration(i) * interval)
		if at.After(end) {
			break
		}
		if d := time.Until(at); d > 0 {
			time.Sleep(d)
		}
		if !measuring.Load() && time.Since(start) >= c.warmup {
			measuring.Store(true)
		}
		rm := rooms[r]
		r = (r + 1) % len(rooms)
		pub := rm.members[rm.nextPub]
		rm.nextPub = (rm.nextPub + 1) % len(rm.members)
		measured := measuring.Load()
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := pub.publish(ctx, rm.id, c.size); err != nil {
				nErr.Add(1)
				return
			}
			if measured {
				nSent.Add(1)
			}
		}()
	}
	wg.Wait()
	return nSent.Load(), nErr.Load()
}

func (cn *conn) dial(ctx context.Context, base string, room store.UUID) error {
	u := "ws" + strings.TrimPrefix(base, "http") + "/ws?user=" + store.FormatUUID(cn.user) + "&device=" + store.FormatUUID(cn.device)
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(dctx, u, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return err
	}
	ws.SetReadLimit(-1)
	cn.ws = ws
	return cn.send(ctx, &protocol.Subscribe{RoomID: protocol.UUID(room)})
}

func (cn *conn) send(ctx context.Context, f protocol.Frame) error {
	b, err := protocol.Encode(f)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return cn.ws.Write(wctx, websocket.MessageText, b)
}

func (cn *conn) publish(ctx context.Context, room store.UUID, size int) error {
	return cn.send(ctx, &protocol.Publish{
		RoomID:     protocol.UUID(room),
		MessageID:  protocol.UUID(newID()),
		DeviceID:   protocol.UUID(cn.device),
		Ciphertext: payload(time.Now(), size),
	})
}

// read consumes server frames until the connection closes, recording
// latency for deliveries from other members while measuring, and checking
// the room's seqs are gap-free.
func (cn *conn) read(measuring *atomic.Bool) {
	for {
		_, b, err := cn.ws.Read(context.Background())
		if err != nil {
			return
		}
		now := time.Now()
		var env protocol.Envelope
		if json.Unmarshal(b, &env) != nil {
			continue
		}
		switch env.Type {
		case protocol.TypeDeliver:
			var d protocol.Deliver
			if json.Unmarshal(b, &d) != nil {
				continue
			}
			cn.mu.Lock()
			if ch := cn.resumed; ch != nil {
				cn.mu.Unlock()
				ch <- d.Seq
				continue
			}
			switch {
			case cn.lastSeq == 0 || d.Seq == cn.lastSeq+1:
				cn.lastSeq = d.Seq
			case d.Seq <= cn.lastSeq: // overlap: a duplicate, not a gap
			default:
				cn.gaps++
				cn.lastSeq = d.Seq
			}
			if measuring.Load() && store.UUID(d.DeviceID) != cn.device {
				if at, ok := sentAt(d.Ciphertext); ok {
					cn.lat = append(cn.lat, now.Sub(at))
				}
			}
			cn.mu.Unlock()
		case protocol.TypeError:
			cn.mu.Lock()
			cn.errFrames++
			cn.mu.Unlock()
		}
	}
}

// resumeAll resumes each room from 0 on one member's connection and waits
// until it has replayed up to that member's last seq. It returns the rooms
// that finished and the rooms that had history to replay.
func resumeAll(ctx context.Context, rooms []*room) (resumed, withHistory int) {
	var done, history atomic.Int64
	_ = parallel(len(rooms), 50, func(i int) error {
		cn := rooms[i].members[0]
		ch := make(chan int64, 1024)
		cn.mu.Lock()
		target := cn.lastSeq
		cn.resumed = ch
		cn.mu.Unlock()
		defer func() {
			cn.mu.Lock()
			cn.resumed = nil
			cn.mu.Unlock()
		}()
		if target == 0 {
			return nil
		}
		history.Add(1)
		if err := cn.send(ctx, &protocol.Resume{RoomID: protocol.UUID(rooms[i].id)}); err != nil {
			return nil
		}
		timeout := time.After(30 * time.Second)
		for {
			select {
			case seq := <-ch:
				if seq >= target {
					done.Add(1)
					return nil
				}
			case <-timeout:
				return nil
			}
		}
	})
	return int(done.Load()), int(history.Load())
}

// coldResume connects one member per room and resumes it from 0, reading
// until the room goes quiet: after a server restart the replay buffer is
// empty, so every read is a ScyllaDB range read.
func coldResume(ctx context.Context, c config, rooms []*room, out io.Writer) error {
	t0 := time.Now()
	var msgs, nonEmpty atomic.Int64
	err := parallel(len(rooms), c.dialers, func(i int) error {
		cn := rooms[i].members[0]
		if err := cn.dial(ctx, c.base, rooms[i].id); err != nil {
			return err
		}
		defer func() { _ = cn.ws.Close(websocket.StatusNormalClosure, "") }()
		if err := cn.send(ctx, &protocol.Resume{RoomID: protocol.UUID(rooms[i].id)}); err != nil {
			return err
		}
		n := 0
		for {
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, b, err := cn.ws.Read(rctx)
			cancel()
			if err != nil {
				break // quiet for 2s (or closed): the replay is done
			}
			if bytes.Contains(b, []byte(`"type":"deliver"`)) {
				n++
			}
		}
		msgs.Add(int64(n))
		if n > 0 {
			nonEmpty.Add(1)
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "cold resume: %d rooms, %d with history, %d messages replayed in %v (includes 2s quiet wait per room)\n",
		len(rooms), nonEmpty.Load(), msgs.Load(), time.Since(t0).Round(time.Millisecond))
	if c.metrics != "" {
		text, err := scrape(c.metrics)
		if err != nil {
			return err
		}
		p99, n, _ := histogramQuantile(text, "klacks_scylla_range_seconds", 0.99)
		p50, _, _ := histogramQuantile(text, "klacks_scylla_range_seconds", 0.5)
		fmt.Fprintf(out, "  klacks_scylla_range_seconds n=%d p50<=%s p99<=%s\n", n, secs(p50), secs(p99))
	}
	return nil
}

// createRoom creates the room as its first member with the others invited.
func createRoom(ctx context.Context, base string, rm *room) error {
	var members []string
	for _, m := range rm.members[1:] {
		members = append(members, store.FormatUUID(m.user))
	}
	body, _ := json.Marshal(map[string]any{"room_id": store.FormatUUID(rm.id), "kind": "group", "members": members})
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/dev/rooms", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Klacks-User", store.FormatUUID(rm.members[0].user))
	req.Header.Set("X-Klacks-Device", store.FormatUUID(rm.members[0].device))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create room: %s: %s", resp.Status, b)
	}
	return nil
}

// parallel runs f(0..n-1) with at most k at once and returns the first error.
func parallel(n, k int, f func(int) error) error {
	var wg sync.WaitGroup
	var first atomic.Value
	sem := make(chan struct{}, k)
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := f(i); err != nil {
				first.CompareAndSwap(nil, err)
			}
		}()
	}
	wg.Wait()
	if err, ok := first.Load().(error); ok {
		return err
	}
	return nil
}

type stats struct {
	N                  int
	P50, P95, P99, Max time.Duration
}

// summarize returns nearest-rank percentiles.
func summarize(lat []time.Duration) stats {
	if len(lat) == 0 {
		return stats{}
	}
	s := slices.Clone(lat)
	slices.Sort(s)
	rank := func(p float64) time.Duration {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		return s[max(0, i)]
	}
	return stats{N: len(s), P50: rank(0.50), P95: rank(0.95), P99: rank(0.99), Max: s[len(s)-1]}
}

// payload is size bytes: the send time (unix nanos, big-endian) then
// random padding.
func payload(at time.Time, size int) []byte {
	p := make([]byte, size)
	_, _ = rand.Read(p[8:])
	binary.BigEndian.PutUint64(p, uint64(at.UnixNano()))
	return p
}

func sentAt(p []byte) (time.Time, bool) {
	if len(p) < 8 {
		return time.Time{}, false
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(p))), true //nolint:gosec // reads back what payload wrote from an int64
}

func newID() store.UUID {
	var u store.UUID
	_, _ = rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return u
}

// derive makes a distinct UUID per (run, kind, room, member).
func derive(run store.UUID, kind string, r, m int) store.UUID {
	u := run
	k := byte(0)
	switch kind {
	case "user":
		k = 1
	case "device":
		k = 2
	}
	u[0] = k
	binary.BigEndian.PutUint32(u[9:13], uint32(r))  //nolint:gosec // run checks rooms fit
	binary.BigEndian.PutUint16(u[13:15], uint16(m)) //nolint:gosec // run checks members fit
	return u
}

// --- server metrics ---

func scrape(base string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/metrics", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// histogramQuantile estimates quantile q of histogram name from Prometheus
// text exposition: the upper bound of the first bucket whose cumulative
// count reaches q of the total.
func histogramQuantile(text, name string, q float64) (bound float64, total int64, ok bool) {
	type bucket struct {
		le float64
		n  int64
	}
	var bs []bucket
	prefix := name + `_bucket{le="`
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line[len(prefix):]
		end := strings.Index(rest, `"}`)
		if end < 0 {
			continue
		}
		le, err := strconv.ParseFloat(rest[:end], 64)
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(rest[end+2:]), 10, 64)
		if err != nil {
			continue
		}
		bs = append(bs, bucket{le, n})
	}
	if len(bs) == 0 {
		return 0, 0, false
	}
	slices.SortFunc(bs, func(a, b bucket) int { return int(math.Copysign(1, a.le-b.le)) })
	total = bs[len(bs)-1].n
	for _, b := range bs {
		if float64(b.n) >= q*float64(total) {
			return b.le, total, true
		}
	}
	return math.Inf(1), total, true
}

func gaugeValue(text, name string) (float64, bool) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, name+" ") {
			v, err := strconv.ParseFloat(strings.TrimSpace(line[len(name):]), 64)
			return v, err == nil
		}
	}
	return 0, false
}

// gaugeSampler records the maximum of a gauge, sampled every 250ms.
type gaugeSampler struct {
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	maxVal float64
}

func sampleGauge(base, name string) *gaugeSampler {
	g := &gaugeSampler{done: make(chan struct{})}
	if base == "" {
		return g
	}
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-g.done:
				return
			case <-t.C:
				if text, err := scrape(base); err == nil {
					if v, ok := gaugeValue(text, name); ok {
						g.mu.Lock()
						g.maxVal = max(g.maxVal, v)
						g.mu.Unlock()
					}
				}
			}
		}
	}()
	return g
}

func (g *gaugeSampler) stop() float64 {
	g.once.Do(func() { close(g.done) })
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maxVal
}
