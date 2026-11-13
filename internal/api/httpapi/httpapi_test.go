package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/config"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeCheck struct {
	name  string
	err   error
	delay time.Duration
}

func (f fakeCheck) Name() string { return f.name }

func (f fakeCheck) Check(ctx context.Context) error {
	select {
	case <-time.After(f.delay):
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func get(t *testing.T, h http.Handler, path string) (int, readyResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body readyResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return rec.Code, body
}

func mux(h *Health) *http.ServeMux {
	m := http.NewServeMux()
	h.Register(m)
	return m
}

func TestHealthz(t *testing.T) {
	h := NewHealth([]Check{fakeCheck{name: "db", err: errors.New("down")}}, time.Second, discard)
	if code, _ := get(t, mux(h), "/healthz"); code != http.StatusOK {
		t.Fatalf("liveness must not depend on stores; code = %d", code)
	}
}

func TestReadyz(t *testing.T) {
	cases := []struct {
		name   string
		checks []Check
		code   int
		want   map[string]string
	}{
		{"all ok", []Check{fakeCheck{name: "postgres"}, fakeCheck{name: "scylla"}}, 200,
			map[string]string{"postgres": "ok", "scylla": "ok"}},
		{"one down", []Check{fakeCheck{name: "postgres"}, fakeCheck{name: "scylla", err: errors.New("secret host 10.0.0.1")}}, 503,
			map[string]string{"postgres": "ok", "scylla": "unavailable"}},
		{"timeout", []Check{fakeCheck{name: "postgres", delay: time.Hour}}, 503,
			map[string]string{"postgres": "unavailable"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := NewHealth(c.checks, 50*time.Millisecond, discard)
			code, body := get(t, mux(h), "/readyz")
			if code != c.code {
				t.Fatalf("code = %d, want %d", code, c.code)
			}
			for k, v := range c.want {
				if body.Checks[k] != v {
					t.Errorf("checks[%s] = %q, want %q (body %+v)", k, body.Checks[k], v, body)
				}
			}
		})
	}
}

func TestReadyzDraining(t *testing.T) {
	h := NewHealth([]Check{fakeCheck{name: "postgres"}}, time.Second, discard)
	h.Drain()
	if code, body := get(t, mux(h), "/readyz"); code != 503 || body.Status != "draining" {
		t.Fatalf("code=%d body=%+v", code, body)
	}
}

func testHTTPConfig() config.HTTP {
	c := config.Default().HTTP
	c.ShutdownTimeout = config.Duration(5 * time.Second)
	return c
}

// TestGracefulShutdown cancels the server while a request is in flight and
// checks that the request still completes and Serve returns cleanly.
func TestGracefulShutdown(t *testing.T) {
	h := NewHealth(nil, time.Second, discard)
	srv := NewServer(testHTTPConfig(), h, discard)
	started := make(chan struct{})
	srv.srv.Handler.(*http.ServeMux).HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "done")
	})
	onShutdown := make(chan struct{})
	srv.OnShutdown(func() { close(onShutdown) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()

	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/slow")
		if err != nil {
			got <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		got <- result{string(b), err}
	}()

	<-started
	cancel()

	r := <-got
	if r.err != nil || r.body != "done" {
		t.Fatalf("in-flight request: body=%q err=%v", r.body, r.err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	select {
	case <-onShutdown:
	default:
		t.Fatal("OnShutdown hook not called")
	}
	if resp, err := http.Get("http://" + ln.Addr().String() + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatal("server still accepting connections after shutdown")
	}
}

func TestShutdownTimeout(t *testing.T) {
	cfg := testHTTPConfig()
	cfg.ShutdownTimeout = config.Duration(100 * time.Millisecond)
	srv := NewServer(cfg, NewHealth(nil, time.Second, discard), discard)
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	srv.srv.Handler.(*http.ServeMux).HandleFunc("GET /stuck", func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/stuck")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	cancel()
	select {
	case err := <-served:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Serve err = %v, want deadline exceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve ignored the shutdown timeout")
	}
}
