package client

import (
	"bytes"
	"testing"
)

func TestADEncodingIsFixedWidth(t *testing.T) {
	a := AD{
		Room:            [16]byte{1},
		Sender:          [16]byte{2},
		SenderDevice:    [16]byte{3},
		RecipientDevice: [16]byte{4},
		MessageID:       [16]byte{5},
	}
	b := a.Bytes()
	if len(b) != adSize {
		t.Fatalf("AD is %d bytes, want %d", len(b), adSize)
	}
	if b[0] != EnvelopeVersion {
		t.Fatalf("AD version byte = %d", b[0])
	}
	// Field boundaries are at fixed offsets; every byte of every field must
	// land exactly where the next reader will split them.
	for i, want := range []byte{1, 2, 3, 4, 5} {
		if b[1+i*16] != want {
			t.Fatalf("field %d first byte = %d, want %d", i, b[1+i*16], want)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := MessageKey{Key: [32]byte{1}, Nonce: [12]byte{2}}
	ad := []byte("associated data")
	hdr := []byte("header bytes")
	ct, err := Seal(key, []byte("hello"), ad, hdr)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, ct, ad, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hello")) {
		t.Fatalf("open = %q", pt)
	}
	// Every one of the authenticated inputs must match exactly.
	if _, err := Open(key, ct, []byte("other ad"), hdr); err == nil {
		t.Fatal("tampered AD accepted")
	}
	if _, err := Open(key, ct, ad, []byte("other header")); err == nil {
		t.Fatal("tampered header accepted")
	}
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0xFF
	if _, err := Open(key, bad, ad, hdr); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestMessageKeysNeverRepeatKeyOrNonce(t *testing.T) {
	// 5000 chain steps: every (key, nonce) pair must be distinct, and each
	// key distinct from every chain key too.
	ck := [32]byte{7}
	type pair struct {
		key   [32]byte
		nonce [12]byte
	}
	seen := make(map[pair]bool, 5000)
	chainKeys := make(map[[32]byte]bool)
	chainKeys[ck] = true
	for i := 0; i < 5000; i++ {
		mk, next, err := kdfChain(ck)
		if err != nil {
			t.Fatal(err)
		}
		p := pair{mk.Key, mk.Nonce}
		if seen[p] {
			t.Fatalf("(key, nonce) pair reused at step %d", i)
		}
		if chainKeys[mk.Key] {
			t.Fatalf("message key at step %d equals a chain key", i)
		}
		if chainKeys[next] {
			t.Fatalf("chain key cycle at step %d", i)
		}
		seen[p] = true
		chainKeys[next] = true
		ck = next
	}
}
