package store

import (
	"encoding/hex"
	"fmt"
)

// ParseUUID parses the canonical 36-character form
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (hex digits in either case). It
// accepts nothing else: no braces, no missing or misplaced hyphens.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("invalid UUID %q", s)
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return UUID{}, fmt.Errorf("invalid UUID %q", s)
	}
	return u, nil
}

// FormatUUID returns u in canonical lowercase form.
func FormatUUID(u UUID) string {
	var b [36]byte
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], u[10:16])
	return string(b[:])
}
