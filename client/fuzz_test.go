package client

import (
	"bytes"
	"testing"
)

// Header and payload parsers over bytes a peer or the server controls
// (S-35). They must never panic, and what they accept must re-encode to
// exactly the bytes they read, so a parsed header is the authenticated one.

func FuzzDecodeHeader(f *testing.F) {
	var dh [32]byte
	dh[0] = 7
	normal := encodeHeader(dh, 3, 9, [16]byte{1}, [16]byte{2})
	prekey := encodePrekeyHeader(PrekeyHeader{SignedPrekeyID: 5, OneTimePrekeyID: 6}, dh, 0, 0, [16]byte{1}, [16]byte{2})
	f.Add(normal)
	f.Add(prekey)
	f.Add(normal[:len(normal)-8]) // truncated inside the sender device
	f.Add(prekey[:len(prekey)-1])
	f.Add([]byte{ratchetVersion})
	f.Add([]byte{ratchetVersion, 0x7f})
	f.Fuzz(func(t *testing.T, b []byte) {
		// Hide any spare capacity, so reading past len panics here as it
		// would for a buffer that happened to end at len.
		b = b[:len(b):len(b)]
		h, err := decodeHeader(b)
		if err != nil {
			return
		}
		var re []byte
		if h.pre != nil {
			re = encodePrekeyHeader(*h.pre, h.dh, h.pn, h.n, h.device, h.recipient)
		} else {
			re = encodeHeader(h.dh, h.pn, h.n, h.device, h.recipient)
		}
		if !bytes.Equal(re, b) {
			t.Fatalf("decoded header re-encodes differently:\n in  %x\n out %x", b, re)
		}
	})
}

func FuzzUnmarshalSenderKeyDistribution(f *testing.F) {
	ch, err := NewSenderChain()
	if err != nil {
		f.Fatal(err)
	}
	good := marshalSenderKeyDistribution(ch.Distribution())
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add(append(append([]byte(nil), good...), 0))
	f.Add([]byte(skDistMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := unmarshalSenderKeyDistribution(b)
		if err != nil {
			return
		}
		if re := marshalSenderKeyDistribution(k); !bytes.Equal(re, b) {
			t.Fatalf("distribution re-encodes differently:\n in  %x\n out %x", b, re)
		}
	})
}

// FuzzSenderKeysDecrypt mutates a genuine group message (S-35): nothing
// panics, only the genuine (header, ciphertext) opens, and no rejected
// input disturbs the chain.
func FuzzSenderKeysDecrypt(f *testing.F) {
	ch, err := NewSenderChain()
	if err != nil {
		f.Fatal(err)
	}
	dist := ch.Distribution() // before Encrypt advances the chain
	ad := AD{Room: [16]byte{1}, MessageID: [16]byte{2}}.Bytes()
	hdr, ct, err := ch.Encrypt([]byte("group hello"), ad)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hdr, ct)
	f.Add(hdr[:skHeaderPrefix], ct)
	f.Add(append(append([]byte(nil), hdr...), 0), ct)
	f.Add(hdr, ct[:len(ct)-1])
	f.Add(hdr, []byte{})
	f.Fuzz(func(t *testing.T, h, c []byte) {
		r := NewSenderKeys()
		if err := r.Install(dist); err != nil {
			t.Fatal(err)
		}
		pt, err := r.Decrypt(h, c, ad)
		genuine := bytes.Equal(h, hdr) && bytes.Equal(c, ct)
		if err == nil && !genuine {
			t.Fatalf("forged group message opened: %q", pt)
		}
		if genuine && (err != nil || string(pt) != "group hello") {
			t.Fatalf("genuine message: %q %v", pt, err)
		}
		if got, err := r.Decrypt(hdr, ct, ad); err != nil || string(got) != "group hello" {
			t.Fatalf("chain disturbed by rejected input: %q %v", got, err)
		}
	})
}

// FuzzRatchetDecrypt does the same for a Double Ratchet session.
func FuzzRatchetDecrypt(f *testing.F) {
	alice, bob, ad := ratchetPair(f)
	hdr, ct, err := alice.Encrypt([]byte("hello"), ad, [16]byte{9}, [16]byte{8}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hdr, ct)
	f.Add(hdr[:len(hdr)-1], ct)
	f.Add(hdr, ct[1:])
	bad := append([]byte(nil), hdr...)
	bad[40] ^= 0xff // n: far ahead, past maxSkip
	f.Add(bad, ct)
	f.Fuzz(func(t *testing.T, h, c []byte) {
		r := bob.clone()
		pt, err := r.Decrypt(h, c, ad)
		genuine := bytes.Equal(h, hdr) && bytes.Equal(c, ct)
		if err == nil && !genuine {
			t.Fatalf("forged message opened: %q", pt)
		}
		if genuine && (err != nil || string(pt) != "hello") {
			t.Fatalf("genuine message: %q %v", pt, err)
		}
		if got, err := r.Decrypt(hdr, ct, ad); err != nil || string(got) != "hello" {
			t.Fatalf("session disturbed by rejected input: %q %v", got, err)
		}
	})
}

// FuzzOpen: an envelope opens only with the exact ciphertext, AD and header
// it was sealed with.
func FuzzOpen(f *testing.F) {
	key := MessageKey{Key: [32]byte{1}, Nonce: [12]byte{2}}
	ad, hdr := []byte("ad"), []byte("hdr")
	ct, err := Seal(key, []byte("pt"), ad, hdr)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ct, ad, hdr)
	f.Add(ct, []byte("adh"), []byte("dr")) // same ad||header bytes, split differently
	f.Add(ct[:len(ct)-1], ad, hdr)
	f.Add([]byte{}, ad, hdr)
	f.Fuzz(func(t *testing.T, c, a, h []byte) {
		pt, err := Open(key, c, a, h)
		exact := bytes.Equal(c, ct) && bytes.Equal(append(append([]byte(nil), a...), h...), []byte("adhdr"))
		if err == nil && !exact {
			t.Fatalf("opened with altered input: %q", pt)
		}
		if exact && (err != nil || string(pt) != "pt") {
			t.Fatalf("genuine envelope: %q %v", pt, err)
		}
	})
}
