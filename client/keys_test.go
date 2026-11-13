package client

import (
	"crypto/ed25519"
	"slices"
	"testing"
)

func TestIdentityKeyMontgomeryConsistency(t *testing.T) {
	k, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.DHPublic()
	if err != nil {
		t.Fatal(err)
	}
	// The Montgomery form is X25519(the derived scalar, base point), and
	// the same scalar must reproduce it after another derivation.
	dh2, err := dhFromSeed(k.Ed.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if dh2 != k.DH {
		t.Fatalf("derived DH scalar differs: %x vs %x", dh2, k.DH)
	}
	direct, err := x25519Base(dh2)
	if err != nil {
		t.Fatal(err)
	}
	if direct != pub {
		t.Fatalf("Montgomery public mismatch: %x vs %x", direct, pub)
	}
	// DH round trip with a peer prekey.
	spk, err := NewSignedPrekey(1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := x25519(k.DH, spk.Pub)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x25519(spk.Priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("X25519 round trip disagrees")
	}
}

func TestIdentityKeyFromSeedIsDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	a, err := NewIdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.EdPublic(), b.EdPublic()) || a.DH != b.DH {
		t.Fatal("same seed produced different identity keys")
	}
	if _, err := NewIdentityFromSeed(make([]byte, 16)); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestBundleSignatureRoundTrip(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spk, err := NewSignedPrekey(2)
	if err != nil {
		t.Fatal(err)
	}
	dhPub, err := id.DHPublic()
	if err != nil {
		t.Fatal(err)
	}
	sig := id.SignBundleKeys(dhPub, spk.Pub)
	if len(sig) != SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), SignatureSize)
	}
	if !VerifyBundleKeys(id.EdPublic(), dhPub, spk.Pub, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyBundleKeys(id.EdPublic(), dhPub, spk.Pub, make([]byte, SignatureSize)) {
		t.Fatal("zero signature accepted")
	}
	// A swapped Montgomery form must fail: the signature binds it.
	other, _ := NewSignedPrekey(3)
	if VerifyBundleKeys(id.EdPublic(), other.Pub, spk.Pub, sig) {
		t.Fatal("swapped identity DH key verified")
	}
	if VerifyBundleKeys(ed25519.PublicKey(make([]byte, 32)), dhPub, spk.Pub, sig) {
		t.Fatal("wrong identity key verified the signature")
	}
}
