// Package client is the Go reference implementation of the klacks end-to-end
// encryption format: X3DH session establishment and Double Ratchet messaging
// over the klacks wire protocol (docs/protocol.md). It is the executable
// definition of the format and the test oracle (S-24), so shipped clients
// must match what this package produces byte for byte.
//
// It lives outside the server packages on purpose: encryption happens
// entirely here and in real client apps. The server stores and relays
// ciphertext and never gains a decryption path.
//
// Crypto choices (S-24, S-25): Ed25519 identity keys, X25519 for every DH,
// HKDF-SHA256 for key derivation, ChaCha20-Poly1305 for message encryption.
// The bundle's exact shape and every wire encoding below are the format.
package client
