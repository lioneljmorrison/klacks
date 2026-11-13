// Package core holds the messaging core: rooms, membership, sequence
// assignment, fan-out and resume. It never sees plaintext; message payloads
// are opaque ciphertext blobs.
package core
