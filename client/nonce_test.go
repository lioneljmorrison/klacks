package client

import (
	"bytes"
	"testing"
)

// nextSendKey returns the MessageKey r's next Encrypt will seal with,
// derived exactly as Encrypt derives it: start the send chain if it has not
// started, then one chain KDF step. Encrypt then finds the chain started
// and takes the same step.
func nextSendKey(t *testing.T, r *Ratchet) MessageKey {
	t.Helper()
	if !r.hasSend {
		if err := r.startSendChain(); err != nil {
			t.Fatal(err)
		}
	}
	mk, _, err := kdfChain(r.ckSend)
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

// TestNonceUniquenessAcrossConversation is the plan's nonce property (S-35):
// over a whole two-way conversation, through many DH ratchet steps, no
// message key and no nonce is ever used twice, by either side. The keys are
// read from the ratchet's own derivation, not inferred from ciphertexts.
func TestNonceUniquenessAcrossConversation(t *testing.T) {
	alice, bob, ad := ratchetPair(t)
	keys := make(map[[32]byte]string)
	nonces := make(map[[12]byte]string)
	sent := 0
	send := func(from, to *Ratchet, who string, burst int) {
		for i := 0; i < burst; i++ {
			mk := nextSendKey(t, from)
			where := who
			if prev, dup := keys[mk.Key]; dup {
				t.Fatalf("message key reused: %s and %s (message %d)", prev, where, sent)
			}
			if prev, dup := nonces[mk.Nonce]; dup {
				t.Fatalf("nonce reused: %s and %s (message %d)", prev, where, sent)
			}
			keys[mk.Key], nonces[mk.Nonce] = where, where
			pt := []byte("same plaintext every time")
			hdr, ct, err := from.Encrypt(pt, ad, [16]byte{9}, [16]byte{8}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// The predicted key is the one actually used.
			if got, err := Open(mk, ct, ad, hdr); err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("predicted key does not open message %d: %v", sent, err)
			}
			if got, err := to.Decrypt(hdr, ct, ad); err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("decrypt %d: %v", sent, err)
			}
			sent++
		}
	}
	// Alternating turns force a DH ratchet step each turn; uneven bursts
	// exercise chains of different lengths.
	for turn := 0; turn < 60; turn++ {
		send(alice, bob, "alice", 1+turn%7)
		send(bob, alice, "bob", 1+(turn*3)%5)
	}
	if sent < 300 {
		t.Fatalf("only %d messages", sent)
	}
}

// TestSenderKeyNonceUniqueness: along one sender chain, and across two
// independent chains, no message key or nonce repeats.
func TestSenderKeyNonceUniqueness(t *testing.T) {
	keys := make(map[[32]byte]bool)
	nonces := make(map[[12]byte]bool)
	for c := 0; c < 2; c++ {
		ch, err := NewSenderChain()
		if err != nil {
			t.Fatal(err)
		}
		ck := ch.chainKey
		for i := 0; i < 5000; i++ {
			mk, next := messageKey(ck)
			if keys[mk.Key] || nonces[mk.Nonce] {
				t.Fatalf("chain %d step %d: key or nonce reused", c, i)
			}
			keys[mk.Key], nonces[mk.Nonce] = true, true
			ck = next
		}
	}
}

// FuzzADBytes: the associated-data encoding is fixed-width and injective,
// so two different ADs never authenticate as each other.
func FuzzADBytes(f *testing.F) {
	f.Add(make([]byte, 80), make([]byte, 80))
	f.Add(bytes.Repeat([]byte{1}, 80), append(bytes.Repeat([]byte{1}, 79), 2))
	f.Fuzz(func(t *testing.T, x, y []byte) {
		if len(x) < 80 || len(y) < 80 {
			t.Skip()
		}
		ad := func(b []byte) AD {
			var a AD
			copy(a.Room[:], b[0:16])
			copy(a.Sender[:], b[16:32])
			copy(a.SenderDevice[:], b[32:48])
			copy(a.RecipientDevice[:], b[48:64])
			copy(a.MessageID[:], b[64:80])
			return a
		}
		a, b := ad(x), ad(y)
		ab, bb := a.Bytes(), b.Bytes()
		if len(ab) != adSize || len(bb) != adSize {
			t.Fatalf("AD sizes %d, %d; want %d", len(ab), len(bb), adSize)
		}
		if (a == b) != bytes.Equal(ab, bb) {
			t.Fatalf("AD encoding not injective: %+v / %+v", a, b)
		}
	})
}
