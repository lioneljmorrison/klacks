// Package blackhole is a TCP listener that accepts connections and never
// answers, for tests of what happens when a store is partitioned: the
// network takes the bytes, nothing comes back (S-47).
package blackhole

import (
	"context"
	"net"
	"sync"
	"testing"
)

// Listen starts a blackhole on 127.0.0.1 and returns its address. It closes
// with the test.
func Listen(t testing.TB) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c) // held open, never read or written
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}
