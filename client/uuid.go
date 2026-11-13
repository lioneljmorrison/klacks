package client

// UUID helpers: format/parse between [16]byte and the canonical string
// form the REST API and wire protocol use.

import (
	"encoding/hex"
	"fmt"
)

// format renders a UUID canonically.
func format(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// parseUUID parses the canonical 36-character form
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx and nothing else.
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("invalid UUID %q", s)
	}
	hexPart := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(u[:], []byte(hexPart)); err != nil {
		return u, fmt.Errorf("invalid UUID %q", s)
	}
	return u, nil
}
