//go:build !unix

package main

// lockDevice is a no-op where flock is unavailable: running the same
// -user twice at once is not detected there. See lock_unix.go.
func lockDevice(string) (func(), error) { return func() {}, nil }
