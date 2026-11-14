//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockDevice takes an exclusive lock on this device's state
// (<key file>.lock) for the life of the process, so the same -user cannot
// run twice at once. Two processes with one device's keys build the same
// sessions from the same incoming messages and then seal at the same chain
// positions: the same message key and nonce twice, which peers reject and
// which breaks the AEAD's guarantees. The kernel drops the lock when the
// process exits, kill -9 included, so a crash leaves nothing stale.
func lockDevice(keyPath string) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(keyPath+".lock", os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // derived from the device identity, not user input
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close() // the lock error is the one to report
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("this device is already running in another testchat; quit that one first (or use another -user / -device)")
		}
		return nil, fmt.Errorf("lock %s: %w", keyPath+".lock", err)
	}
	return func() { _ = f.Close() }, nil // closing drops the lock
}
