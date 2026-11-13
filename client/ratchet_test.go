package client

import (
	"bytes"
	"fmt"
	"testing"
)

// ratchetPair builds a working session pair: alice initiated against bob's
// bundle; bob holds the responder state.
func ratchetPair(t *testing.T) (alice, bob *Ratchet, ad []byte) {
	t.Helper()
	aliceID := newPeerKeys(t, 0)
	bobID := newPeerKeys(t, 1)
	b := bobID.bundle(t, true)
	root, pre, err := Initiate(aliceID.id, &b)
	if err != nil {
		t.Fatal(err)
	}
	var opk *OneTimePrekey
	if pre.OneTimePrekeyID != 0 {
		opk = bobID.opk(pre.OneTimePrekeyID)
		if opk == nil {
			t.Fatalf("responder has no key pair for opk id %d", pre.OneTimePrekeyID)
		}
	}
	root2, err := Respond(bobID.id, bobID.spk, opk, pre)
	if err != nil {
		t.Fatal(err)
	}
	if root != root2 {
		t.Fatal("roots disagree")
	}
	var spk [32]byte
	copy(spk[:], b.SignedPrekey)
	aliceR, err := NewInitiatorRatchet(root, spk)
	if err != nil {
		t.Fatal(err)
	}
	// The first message's header carries the prelude and the initiator's
	// first ratchet key; the responder's ratchet starts from it. It is
	// encrypted and consumed here, exactly as the transport would deliver it.
	hdr, ct, err := aliceR.Encrypt([]byte("first"), []byte("ad"), [16]byte{9}, [16]byte{8}, &pre)
	if err != nil {
		t.Fatal(err)
	}
	h, err := decodeHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	bobR, err := NewResponderRatchet(root, bobID.spk, h.dh)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := bobR.Decrypt(hdr, ct, []byte("ad")); err != nil || string(pt) != "first" {
		t.Fatalf("first message: %q %v", pt, err)
	}
	return aliceR, bobR, []byte("ad")
}

func TestRatchetBidirectional(t *testing.T) {
	alice, bob, ad := ratchetPair(t)

	for i := 0; i < 50; i++ {
		msg := fmt.Sprintf("a->b %d", i)
		hdr, ct, err := alice.Encrypt([]byte(msg), ad, [16]byte{9}, [16]byte{8}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := bob.Decrypt(hdr, ct, ad)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("decrypt %d = %q", i, got)
		}
	}
	// The responder's first reply performs its send-side DH ratchet step;
	// from then on both sides ratchet freely, in both directions.
	for i := 0; i < 50; i++ {
		msg := fmt.Sprintf("b->a %d", i)
		hdr, ct, err := bob.Encrypt([]byte(msg), ad, [16]byte{9}, [16]byte{8}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := alice.Decrypt(hdr, ct, ad)
		if err != nil {
			t.Fatalf("decrypt reply %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("decrypt reply %d = %q", i, got)
		}
	}
	// And back to alice sending.
	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("a->b again %d", i)
		hdr, ct, err := alice.Encrypt([]byte(msg), ad, [16]byte{9}, [16]byte{8}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := bob.Decrypt(hdr, ct, ad)
		if err != nil {
			t.Fatalf("decrypt again %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("decrypt again %d = %q", i, got)
		}
	}
}

func TestRatchetOutOfOrder(t *testing.T) {
	alice, bob, ad := ratchetPair(t)

	// Send five; deliver 3, 5, 4, 1, 2 — every order must decrypt.
	type env struct {
		hdr, ct []byte
	}
	var msgs []env
	for i := 0; i < 5; i++ {
		hdr, ct, err := alice.Encrypt([]byte(fmt.Sprintf("m%d", i)), ad, [16]byte{9}, [16]byte{8}, nil)
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, env{hdr, ct})
	}
	for _, i := range []int{3, 5, 4, 1, 2} {
		got, err := bob.Decrypt(msgs[i-1].hdr, msgs[i-1].ct, ad)
		if err != nil {
			t.Fatalf("out-of-order decrypt %d: %v", i, err)
		}
		if string(got) != fmt.Sprintf("m%d", i-1) {
			t.Fatalf("out-of-order decrypt %d = %q", i, got)
		}
	}
}

func TestRatchetRejects(t *testing.T) {
	alice, bob, ad := ratchetPair(t)

	hdr, ct, err := alice.Encrypt([]byte("secret"), ad, [16]byte{9}, [16]byte{8}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong associated data.
	if _, err := bob.Decrypt(hdr, ct, []byte("wrong ad")); err == nil {
		t.Fatal("wrong AD accepted")
	}
	// Tampered ciphertext.
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0xFF
	if _, err := bob.Decrypt(hdr, bad, ad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// Tampered header (trades the ratchet key).
	badHdr := append([]byte(nil), hdr...)
	badHdr[5] ^= 0xFF
	if _, err := bob.Decrypt(badHdr, ct, ad); err == nil {
		t.Fatal("tampered header accepted")
	}
	// The real message decrypts; an identical replay returns the same
	// plaintext (resume re-delivers), while a replay with tampered
	// content is refused.
	if got, err := bob.Decrypt(hdr, ct, ad); err != nil || string(got) != "secret" {
		t.Fatalf("real message: %q %v", got, err)
	}
	if got, err := bob.Decrypt(hdr, ct, ad); err != nil || string(got) != "secret" {
		t.Fatalf("identical replay: %q %v", got, err)
	}
	tamperedCT := append([]byte(nil), ct...)
	tamperedCT[0] ^= 0xFF
	if _, err := bob.Decrypt(hdr, tamperedCT, ad); err == nil {
		t.Fatal("replay with tampered ciphertext accepted")
	}
	if _, err := bob.Decrypt(hdr, ct, []byte("other ad")); err == nil {
		t.Fatal("replay with tampered AD accepted")
	}
	// And the original state still works: the failed attempts above must
	// not have desynchronized the session.
	hdr2, ct2, err := alice.Encrypt([]byte("still fine"), ad, [16]byte{9}, [16]byte{8}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bob.Decrypt(hdr2, ct2, ad)
	if err != nil || string(got) != "still fine" {
		t.Fatalf("session desynchronized by rejected messages: %q %v", got, err)
	}
}

func TestRatchetNonceAndKeyUniqueness(t *testing.T) {
	alice, bob, ad := ratchetPair(t)
	// ChaCha20-Poly1305 is deterministic: the same (key, nonce) with the
	// same plaintext and AD yields the same ciphertext. Sealing the same
	// plaintext 2000 times must therefore produce 2000 distinct
	// ciphertexts if and only if no (key, nonce) pair repeats — the
	// property the envelope depends on (S-25).
	seen := make(map[string]bool)
	for i := 0; i < 2000; i++ {
		hdr, ct, err := alice.Encrypt([]byte("same plaintext"), ad, [16]byte{9}, [16]byte{8}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(hdr)] {
			t.Fatalf("header (ratchet key and counter) repeated at %d", i)
		}
		if seen[string(ct)] {
			t.Fatalf("ciphertext repeated at %d: a (key, nonce) pair was reused", i)
		}
		seen[string(ct)] = true
		got, err := bob.Decrypt(hdr, ct, ad)
		if err != nil || !bytes.Equal(got, []byte("same plaintext")) {
			t.Fatalf("decrypt %d = %q %v", i, got, err)
		}
	}
}
