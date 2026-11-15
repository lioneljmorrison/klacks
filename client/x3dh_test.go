package client

import "testing"

// A bundle and its owner's private material, as a device holds them.
type peerKeys struct {
	id      IdentityKey
	spk     SignedPrekey
	opks    []OneTimePrekey // all of them; the bundle offers them in order
	opkNext int
}

func newPeerKeys(t testing.TB, opkCount int) *peerKeys {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spk, err := NewSignedPrekey(1)
	if err != nil {
		t.Fatal(err)
	}
	opks, err := NewOneTimePrekeys(1, opkCount)
	if err != nil {
		t.Fatal(err)
	}
	return &peerKeys{id: id, spk: spk, opks: opks}
}

// bundle returns the owner's fetched bundle: public halves only. takeOpk
// offers the next one-time prekey, as the server would hand one out.
func (p *peerKeys) bundle(t testing.TB, takeOpk bool) Bundle {
	t.Helper()
	dhPub, err := p.id.DHPublic()
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{
		IdentityKey:           p.id.EdPublic(),
		IdentityDHKey:         dhPub[:],
		SignedPrekeyID:        p.spk.ID,
		SignedPrekey:          p.spk.Pub[:],
		SignedPrekeySignature: p.id.SignBundleKeys(dhPub, p.spk.Pub),
	}
	if takeOpk && p.opkNext < len(p.opks) {
		opk := p.opks[p.opkNext]
		p.opkNext++
		b.OneTimePrekey = &Prekey{ID: opk.ID, Key: opk.Pub[:]}
	}
	return b
}

// opk returns the owner's key pair for an id, or nil.
func (p *peerKeys) opk(id int64) *OneTimePrekey {
	for _, o := range p.opks {
		if o.ID == id {
			opk := o
			return &opk
		}
	}
	return nil
}

func TestX3DHAgreement(t *testing.T) {
	alice := newPeerKeys(t, 0)
	bob := newPeerKeys(t, 1)

	// With a one-time prekey (four DHs).
	b := bob.bundle(t, true)
	root, pre, err := Initiate(alice.id, &b)
	if err != nil {
		t.Fatal(err)
	}
	if pre.OneTimePrekeyID == 0 {
		t.Fatal("header does not name the one-time prekey")
	}
	opk := bob.opk(pre.OneTimePrekeyID)
	if opk == nil {
		t.Fatalf("responder has no key pair for opk id %d", pre.OneTimePrekeyID)
	}
	root2, err := Respond(bob.id, bob.spk, opk, pre)
	if err != nil {
		t.Fatal(err)
	}
	if root != root2 {
		t.Fatal("X3DH roots disagree (with one-time prekey)")
	}

	// Without one (three DHs): exhaustion is allowed and both sides agree.
	b = bob.bundle(t, false)
	root, pre, err = Initiate(alice.id, &b)
	if err != nil {
		t.Fatal(err)
	}
	if pre.OneTimePrekeyID != 0 {
		t.Fatal("header names a one-time prekey the bundle did not have")
	}
	root2, err = Respond(bob.id, bob.spk, nil, pre)
	if err != nil {
		t.Fatal(err)
	}
	if root != root2 {
		t.Fatal("X3DH roots disagree (no one-time prekey)")
	}
}

func TestX3DHRespondMismatch(t *testing.T) {
	alice := newPeerKeys(t, 0)
	bob := newPeerKeys(t, 1)
	b := bob.bundle(t, true)
	root, pre, err := Initiate(alice.id, &b)
	if err != nil {
		t.Fatal(err)
	}
	_ = root
	// The header names opk 1; answering without it must fail.
	if _, err := Respond(bob.id, bob.spk, nil, pre); err == nil {
		t.Fatal("respond without the named one-time prekey succeeded")
	}
	// The wrong signed prekey must fail.
	other, err := NewSignedPrekey(9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Respond(bob.id, other, nil, pre); err == nil {
		t.Fatal("respond with the wrong signed prekey succeeded")
	}
}

func TestBundleVerify(t *testing.T) {
	bob := newPeerKeys(t, 1)
	b := bob.bundle(t, true)
	if err := b.Verify(); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	// Tamper the signature.
	sig := append([]byte(nil), b.SignedPrekeySignature...)
	b.SignedPrekeySignature[0] ^= 0xFF
	if err := b.Verify(); err == nil {
		t.Fatal("tampered signature accepted")
	}
	b.SignedPrekeySignature = sig
	// Tamper the signed prekey (signature no longer covers it).
	spk := append([]byte(nil), b.SignedPrekey...)
	b.SignedPrekey[0] ^= 0xFF
	if err := b.Verify(); err == nil {
		t.Fatal("tampered signed prekey accepted")
	}
	b.SignedPrekey = spk
	// A truncated key.
	b.IdentityKey = b.IdentityKey[:31]
	if err := b.Verify(); err == nil {
		t.Fatal("short identity key accepted")
	}
}
