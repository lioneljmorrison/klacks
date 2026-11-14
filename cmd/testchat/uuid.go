package main

// UUID helpers: the client package's format/parse are unexported, and the
// flags, prompt and member records all speak the canonical string form the
// REST API and wire protocol use.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// uuidString renders a UUID canonically.
func uuidString(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// parseUUID parses the canonical 36-character form
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, case-insensitively.
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	s = strings.ToLower(s)
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("invalid UUID %q", s)
	}
	hexPart := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(u[:], []byte(hexPart)); err != nil {
		return u, fmt.Errorf("invalid UUID %q", s)
	}
	return u, nil
}

// randomUUID generates a random v4 UUID: version nibble 4, RFC 4122
// variant, everything else random.
func randomUUID() ([16]byte, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return u, fmt.Errorf("generate uuid: %w", err)
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u, nil
}
