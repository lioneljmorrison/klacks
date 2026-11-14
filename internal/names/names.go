// Package names maps human-readable names to the UUIDs klacks identities
// and rooms use, so test clients never require a human to invent a UUID.
//
// The mapping is deterministic (UUIDv5, SHA-1, under one fixed namespace),
// so every client resolves the same name to the same UUID with no shared
// state: "alice" is one user everywhere, "standup" is one room everywhere.
// A canonical UUID is always accepted anywhere a name is, and takes
// precedence, so the scheme never blocks explicit identities.
//
// The scheme (name forms, case-sensitive):
//
//	user "alice"          → v5(ns, "user/alice")
//	device "phone" of
//	user alice            → v5(ns, "device/<alice's user UUID>/phone")
//	room "standup"        → v5(ns, "room/standup")
//
// The device derivation includes the user's resolved UUID, so the same
// device name under different users is a different device — which is what
// a device is.
//
// The browser test client (internal/api/devui/web/js/names.mjs) implements
// the same scheme; its unit tests pin identical outputs to this package's
// through the dev UI interop vectors.
package names

import (
	"crypto/sha1" //nolint:gosec // UUIDv5 is defined over SHA-1; this is identity mapping, not a security primitive.
	"errors"
	"fmt"
	"regexp"
)

// Namespace is the fixed UUIDv5 namespace for klacks test names:
// uuid5(NAMESPACE_DNS, "klacks.dev"). Never change it: every name resolves
// through it, and changing it orphans every identity and room.
const Namespace = "3a13d177-ee00-5919-82dc-c039cb9f63c6"

var namespaceBytes = mustParseHex(Namespace)

// uuidPattern matches a canonical UUID, the form everywhere accepts.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID reports whether s is already a canonical UUID.
func IsUUID(s string) bool { return uuidPattern.MatchString(s) }

// UUIDv5 returns the name-based (SHA-1) UUID of name under the package
// namespace.
func UUIDv5(name string) string {
	h := sha1.New() //nolint:gosec // UUIDv5 is defined over SHA-1.
	h.Write(namespaceBytes)
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return format(u)
}

// User resolves a user name or canonical UUID to a user UUID string.
func User(nameOrUUID string) string {
	if IsUUID(nameOrUUID) {
		return normalize(nameOrUUID)
	}
	return UUIDv5("user/" + nameOrUUID)
}

// Device resolves a device name to its UUID under user (already resolved).
func Device(user, deviceName string) string {
	if IsUUID(deviceName) {
		return normalize(deviceName)
	}
	return UUIDv5("device/" + user + "/" + deviceName)
}

// Room resolves a room name or canonical UUID to a room UUID string.
func Room(nameOrUUID string) string {
	if IsUUID(nameOrUUID) {
		return normalize(nameOrUUID)
	}
	return UUIDv5("room/" + nameOrUUID)
}

func mustParseHex(s string) []byte {
	var hexOnly []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		n, err := hexNibble(s[i])
		if err != nil {
			panic("names: bad namespace")
		}
		hexOnly = append(hexOnly, n)
	}
	if len(hexOnly) != 32 {
		panic("names: bad namespace")
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[i] = hexOnly[i*2]<<4 | hexOnly[i*2+1]
	}
	return out[:]
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("not a hex digit")
}

func format(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// normalize lowercases a canonical UUID in place.
func normalize(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// FormatUUID16 renders 16 raw bytes as a canonical UUID string; the wire
// forms use it.
func FormatUUID16(b [16]byte) string { return format(b) }
