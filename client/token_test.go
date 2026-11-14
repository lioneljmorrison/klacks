package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/coder/websocket"
)

// S-44: with a token source, every REST call and every WebSocket dial
// carries Authorization: Bearer with a token fetched for that request (a
// redial gets a fresh one), and none of the dev stub's identity claims.
func TestTokenSourceAuthenticatesRESTAndDial(t *testing.T) {
	type seen struct {
		path, authz, devUser, devDevice, query string
	}
	var (
		mu   sync.Mutex
		reqs []seen
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, seen{r.URL.Path, r.Header.Get("Authorization"),
			r.Header.Get("X-Klacks-User"), r.Header.Get("X-Klacks-Device"), r.URL.RawQuery})
		mu.Unlock()
		if r.URL.Path == "/ws" {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = conn.CloseNow() }()
			for {
				if _, _, err := conn.Read(r.Context()); err != nil {
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n := 0
	c.SetTokenSource(func(context.Context) (string, error) {
		n++
		return fmt.Sprintf("tok%d", n), nil
	})
	ctx := context.Background()
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	c.Disconnect()
	if err := c.Dial(ctx); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []seen{
		{path: "/v1/device/bundle", authz: "Bearer tok1"},
		{path: "/ws", authz: "Bearer tok2"},
		{path: "/ws", authz: "Bearer tok3"},
	}
	if len(reqs) != len(want) {
		t.Fatalf("requests %+v; want %+v", reqs, want)
	}
	for i := range want {
		if reqs[i] != want[i] {
			t.Errorf("request %d: %+v; want %+v", i, reqs[i], want[i])
		}
	}
}

// A token source error fails the call before anything is sent.
func TestTokenSourceError(t *testing.T) {
	c, err := NewClient("http://127.0.0.1:1", [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetTokenSource(func(context.Context) (string, error) { return "", fmt.Errorf("idp down") })
	if err := c.Register(context.Background()); err == nil {
		t.Error("Register: no error")
	}
	if err := c.Dial(context.Background()); err == nil {
		t.Error("Dial: no error")
	}
}
