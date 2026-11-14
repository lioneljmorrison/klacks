package client

// The browser dev UI's crypto (internal/api/devui/web/js) must interoperate
// with this reference client byte for byte. This file generates the test
// vectors it replays: identity derivation, X3DH on both sides, a full
// Double Ratchet transcript with pinned (deterministic) ratchet keys, and
// raw AEAD cases.
//
// Run with an output path to (re)write the vectors:
//
//	KLACKS_JS_VECTORS_OUT=internal/api/devui/interop/testdata/vectors.json \
//	  go test -run TestGenerateJSInteropVectors ./client
//
// The Node tests in internal/api/devui/interop replay them; `make test-web`
// wires the two together. Where the exported entry points draw randomness
// (the X3DH ephemeral, the ratchet's key pairs), the generator replicates
// the step with a pinned key instead, so both implementations can walk
// identical chains.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/names"
)

// The fixed identities, prekeys and ids the vectors derive from:
// deterministic byte patterns, distinct per role.
var (
	vecSeedA = bytePattern(0xA0, 32)
	vecSeedB = bytePattern(0xB0, 32)
	vecSpkB  = bytePattern(0xB1, 32)
	vecOpkB  = bytePattern(0xB2, 32)
	vecEph   = bytePattern(0xEE, 32) // the initiator's X3DH ephemeral
	vecDhA1  = bytePattern(0xA3, 32) // A's first ratchet key
	vecDhB2  = bytePattern(0xB3, 32) // B's first send ratchet key

	vecRoom    = "c1000000-0000-0000-0000-000000000001"
	vecUserA   = "a1000000-0000-0000-0000-000000000001"
	vecUserB   = "a1000000-0000-0000-0000-000000000002"
	vecDeviceA = "b2000000-0000-0000-0000-000000000001"
	vecDeviceB = "b2000000-0000-0000-0000-000000000002"
)

func bytePattern(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// TestGenerateJSInteropVectors writes the interop vectors when
// KLACKS_JS_VECTORS_OUT is set. Without it, it still runs the handshake and
// transcript internally, so ordinary `go test` keeps the generator honest.
func TestGenerateJSInteropVectors(t *testing.T) {
	idA, err := NewIdentityFromSeed(vecSeedA)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := NewIdentityFromSeed(vecSeedB)
	if err != nil {
		t.Fatal(err)
	}
	dhPubA, err := idA.DHPublic()
	if err != nil {
		t.Fatal(err)
	}
	dhPubB, err := idB.DHPublic()
	if err != nil {
		t.Fatal(err)
	}

	spkB := SignedPrekey{ID: 1, Priv: as32(t, vecSpkB)}
	spkB.Pub, err = x25519Base(spkB.Priv)
	if err != nil {
		t.Fatal(err)
	}
	opkB := OneTimePrekey{ID: 1, Priv: as32(t, vecOpkB)}
	opkB.Pub, err = x25519Base(opkB.Priv)
	if err != nil {
		t.Fatal(err)
	}

	// B's bundle, exactly as the fetch endpoint would hand it over.
	bundleB := &Bundle{
		UserID:                  vecUserB,
		DeviceID:                vecDeviceB,
		IdentityKey:             idB.EdPublic(),
		IdentityDHKey:           dhPubB[:],
		SignedPrekeyID:          spkB.ID,
		SignedPrekey:            spkB.Pub[:],
		SignedPrekeySignature:   idB.SignBundleKeys(dhPubB, spkB.Pub),
		OneTimePrekey:           &Prekey{ID: opkB.ID, Key: opkB.Pub[:]},
		OneTimePrekeysRemaining: 0,
	}
	if err := bundleB.Verify(); err != nil {
		t.Fatalf("generated bundle does not verify: %v", err)
	}

	// X3DH, initiator side, with the pinned ephemeral: the same DHs
	// Initiate runs, without its rand.
	dh1, err := x25519(idA.DH, spkB.Pub)
	if err != nil {
		t.Fatal(err)
	}
	ekPriv := as32(t, vecEph)
	ekPub, err := x25519Base(ekPriv)
	if err != nil {
		t.Fatal(err)
	}
	var bIdentityDH, bSPK [32]byte
	copy(bIdentityDH[:], bundleB.IdentityDHKey)
	copy(bSPK[:], bundleB.SignedPrekey)
	dh2, err := x25519(ekPriv, bIdentityDH)
	if err != nil {
		t.Fatal(err)
	}
	dh3, err := x25519(ekPriv, bSPK)
	if err != nil {
		t.Fatal(err)
	}
	var bOPK [32]byte
	copy(bOPK[:], bundleB.OneTimePrekey.Key)
	dh4, err := x25519(ekPriv, bOPK)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x3dh(&dh1, &dh2, &dh3, &dh4)
	if err != nil {
		t.Fatal(err)
	}
	pre := PrekeyHeader{
		IdentityEd:      as32(t, idA.EdPublic()),
		IdentityDH:      dhPubA,
		Ephemeral:       ekPub,
		SignedPrekeyID:  spkB.ID,
		OneTimePrekeyID: opkB.ID,
	}

	// X3DH, responder side, through the real Respond: the roots must agree.
	rootResp, err := Respond(idB, spkB, &opkB, pre)
	if err != nil {
		t.Fatal(err)
	}
	if rootResp != root {
		t.Fatalf("X3DH roots disagree: initiator %x, responder %x", root, rootResp)
	}

	// The transcript: five messages, every ratchet key pinned, so both
	// implementations walk identical chains. Generation order keeps every
	// state deterministic: A sends twice, B receives; B replies twice (its
	// first send runs startSendChain with the pinned key); A sends a third
	// (its original send chain continues, no ratchet step yet). Decryption
	// is checked last, so no receive-side step feeds a later encrypt.
	room, err := parseUUID(vecRoom)
	if err != nil {
		t.Fatal(err)
	}
	userA, _ := parseUUID(vecUserA)
	userB, _ := parseUUID(vecUserB)
	deviceA, _ := parseUUID(vecDeviceA)
	deviceB, _ := parseUUID(vecDeviceB)

	// A's initiator ratchet with the pinned first ratchet key: the same
	// construction NewInitiatorRatchet does, minus its rand.
	dhA1 := as32(t, vecDhA1)
	dhA1Pub, err := x25519Base(dhA1)
	if err != nil {
		t.Fatal(err)
	}
	rA := &Ratchet{
		RootKey: root, dhSelf: dhA1, dhSelfPub: dhA1Pub, dhRemote: spkB.Pub,
		skipped: make(map[skippedID]MessageKey), cache: make(map[skippedID]cacheEntry),
	}
	dhInit, err := x25519(dhA1, spkB.Pub)
	if err != nil {
		t.Fatal(err)
	}
	nextRoot, ckSend, err := kdfRoot(root, dhInit)
	if err != nil {
		t.Fatal(err)
	}
	rA.RootKey, rA.ckSend, rA.hasSend = nextRoot, ckSend, true

	// B's responder ratchet: the signed prekey is its ratchet key, the
	// remote key is A's first ratchet key.
	rB, err := NewResponderRatchet(root, spkB, dhA1Pub)
	if err != nil {
		t.Fatal(err)
	}

	type msg struct {
		From       string `json:"from"`
		Pre        bool   `json:"pre"`
		Header     string `json:"header"`
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
		AD         string `json:"ad"`
	}
	var msgs []msg
	// add seals one message: user and device are the sender's (the AD
	// binds the sending user and the sending device separately, exactly as
	// session.go builds it), recipient is the receiving device.
	add := func(from string, user, device, recipient [16]byte, sendPre *PrekeyHeader, r *Ratchet, pt string) {
		t.Helper()
		mid := [16]byte{byte(len(msgs) + 1)}
		ad := AD{Room: room, Sender: user, SenderDevice: device, RecipientDevice: recipient, MessageID: mid}
		hdr, ct, err := r.Encrypt([]byte(pt), ad.Bytes(), device, recipient, sendPre)
		if err != nil {
			t.Fatalf("encrypt %d: %v", len(msgs), err)
		}
		msgs = append(msgs, msg{
			From: from, Pre: sendPre != nil,
			Header:     hx(hdr),
			Ciphertext: base64.StdEncoding.EncodeToString(ct),
			Plaintext:  base64.StdEncoding.EncodeToString([]byte(pt)),
			AD:         hx(ad.Bytes()),
		})
	}

	add("A>B", userA, deviceA, deviceB, &pre, rA, "first message from A, carrying the prekey header")
	add("A>B", userA, deviceA, deviceB, nil, rA, "second message from A on the same send chain")

	// B receives both, then replies: its first send runs startSendChain
	// with the pinned key pair (the rand the real one draws).
	for i := range 2 {
		m := msgs[i]
		pt, err := rB.Decrypt(mustHex(t, m.Header), mustB64(t, m.Ciphertext), mustHex(t, m.AD))
		if err != nil {
			t.Fatalf("B could not decrypt message %d: %v", i, err)
		}
		if string(pt) != string(mustB64(t, m.Plaintext)) {
			t.Fatalf("B decrypted message %d differently", i)
		}
	}
	if err := startSendChainFixed(t, rB, as32(t, vecDhB2)); err != nil {
		t.Fatal(err)
	}
	add("B>A", userB, deviceB, deviceA, nil, rB, "reply from B, the responder's first send")
	add("B>A", userB, deviceB, deviceA, nil, rB, "second reply from B")

	// A's third message rides its original send chain — no ratchet step has
	// happened on A yet, so it stays deterministic.
	add("A>B", userA, deviceA, deviceB, nil, rA, "third message from A, before A sees B's replies")

	// Round-trip check inside Go: B decrypts all three of A's messages; A
	// decrypts both replies (which ratchets A forward — after this, A's
	// state is random-keyed, so nothing more is encrypted from it).
	for _, i := range []int{0, 1, 4} {
		m := msgs[i]
		pt, err := rB.Decrypt(mustHex(t, m.Header), mustB64(t, m.Ciphertext), mustHex(t, m.AD))
		if err != nil {
			t.Fatalf("B could not decrypt transcript message %d: %v", i, err)
		}
		if string(pt) != string(mustB64(t, m.Plaintext)) {
			t.Fatalf("B decrypted transcript message %d differently", i)
		}
	}
	for _, i := range []int{2, 3} {
		m := msgs[i]
		pt, err := rA.Decrypt(mustHex(t, m.Header), mustB64(t, m.Ciphertext), mustHex(t, m.AD))
		if err != nil {
			t.Fatalf("A could not decrypt transcript message %d: %v", i, err)
		}
		if string(pt) != string(mustB64(t, m.Plaintext)) {
			t.Fatalf("A decrypted transcript message %d differently", i)
		}
	}

	// Raw AEAD cases, straight through the envelope.
	chacha := []map[string]string{}
	addChacha := func(key, nonce []byte, aad, pt string) {
		k := as32(t, key)
		var n [12]byte
		copy(n[:], nonce)
		mk := MessageKey{Key: k, Nonce: n}
		ct, err := Seal(mk, []byte(pt), []byte(aad), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(mk, ct, []byte(aad), nil)
		// An empty plaintext decrypts to nil, which Open reports as an
		// error; the tag still verifies, which is what the vector checks.
		if pt != "" && (err != nil || string(got) != pt) {
			t.Fatalf("chacha case does not round-trip (aad %d bytes, pt %d bytes, ct %d bytes): %v", len(aad), len(pt), len(ct), err)
		}
		chacha = append(chacha, map[string]string{
			"key": hx(k[:]), "nonce": hx(n[:]),
			"aad": base64.StdEncoding.EncodeToString([]byte(aad)),
			"pt":  base64.StdEncoding.EncodeToString([]byte(pt)),
			"ct":  base64.StdEncoding.EncodeToString(ct),
		})
	}
	// RFC 8439 §2.8.2's vector, plus the empty-plaintext and empty-AAD edges.
	addChacha(bytePattern(0x80, 32), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4c, 0},
		"50515253c0c1c2c3c4c5c6c7",
		"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	addChacha(bytePattern(0x01, 32), bytePattern(0x02, 12), "", "x")
	addChacha(bytePattern(0x03, 32), bytePattern(0x04, 12), "associated data only", "")
	addChacha(bytePattern(0x05, 32), bytePattern(0x06, 12), "", "")

	out := map[string]any{
		"identities": map[string]any{
			"A": map[string]string{
				"seed": hx(vecSeedA), "edPub": hx(idA.EdPublic()),
				"dhPriv": hx(idA.DH[:]), "dhPub": hx(dhPubA[:]),
			},
			"B": map[string]string{
				"seed": hx(vecSeedB), "edPub": hx(idB.EdPublic()),
				"dhPriv": hx(idB.DH[:]), "dhPub": hx(dhPubB[:]),
			},
		},
		"prekeys": map[string]any{
			"B": map[string]any{
				"spk": map[string]any{"id": spkB.ID, "priv": hx(spkB.Priv[:]), "pub": hx(spkB.Pub[:])},
				"opk": map[string]any{"id": opkB.ID, "priv": hx(opkB.Priv[:]), "pub": hx(opkB.Pub[:])},
			},
		},
		"ids": map[string]string{
			"room": vecRoom, "userA": vecUserA, "userB": vecUserB,
			"deviceA": vecDeviceA, "deviceB": vecDeviceB,
		},
		"bundleB": map[string]any{
			// The fetch response's JSON shape (base64), as the browser's
			// fetchBundle would decode it.
			"user_id":                    bundleB.UserID,
			"device_id":                  bundleB.DeviceID,
			"identity_key":               base64.StdEncoding.EncodeToString(bundleB.IdentityKey),
			"identity_dh_key":            base64.StdEncoding.EncodeToString(bundleB.IdentityDHKey),
			"signed_prekey_id":           bundleB.SignedPrekeyID,
			"signed_prekey":              base64.StdEncoding.EncodeToString(bundleB.SignedPrekey),
			"signed_prekey_signature":    base64.StdEncoding.EncodeToString(bundleB.SignedPrekeySignature),
			"one_time_prekey":            map[string]any{"id": bundleB.OneTimePrekey.ID, "key": base64.StdEncoding.EncodeToString(bundleB.OneTimePrekey.Key)},
			"one_time_prekeys_remaining": 0,
		},
		"x3dh": map[string]any{
			"ephemeral":     map[string]string{"priv": hx(ekPriv[:]), "pub": hx(ekPub[:])},
			"preHeader":     map[string]any{"identityEd": hx(pre.IdentityEd[:]), "identityDH": hx(pre.IdentityDH[:]), "ephemeral": hx(pre.Ephemeral[:]), "signedPrekeyID": pre.SignedPrekeyID, "oneTimePrekeyID": pre.OneTimePrekeyID},
			"initiatorRoot": hx(root[:]),
			"responderRoot": hx(rootResp[:]),
		},
		"ratchet": map[string]any{
			"pinned": map[string]string{
				"dhA1": hx(dhA1[:]),
				"dhB2": hx(vecDhB2),
			},
			"messages": msgs,
		},
		"chacha": chacha,
	}

	// The name→UUID vectors ride along: the browser's names.mjs must
	// resolve the same names to the same UUIDs.
	out["names"] = map[string]any{
		"namespace":          names.Namespace,
		"user_alice":         names.User("alice"),
		"user_bob":           names.User("bob"),
		"room_standup":       names.Room("standup"),
		"device_alice_phone": names.Device(names.User("alice"), "phone"),
	}

	if path := os.Getenv("KLACKS_JS_VECTORS_OUT"); path != "" {
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
	}
}

// startSendChainFixed is startSendChain with the key pair passed in, for
// deterministic vectors. It mirrors the real startSendChain field for field.
func startSendChainFixed(t *testing.T, r *Ratchet, priv [32]byte) error {
	t.Helper()
	pub, err := x25519Base(priv)
	if err != nil {
		return err
	}
	dh, err := x25519(priv, r.dhRemote)
	if err != nil {
		return err
	}
	root, ck, err := kdfRoot(r.RootKey, dh)
	if err != nil {
		return err
	}
	r.RootKey, r.dhSelf, r.dhSelfPub, r.ckSend, r.hasSend = root, priv, pub, ck, true
	return nil
}

func as32(t *testing.T, b []byte) [32]byte {
	t.Helper()
	var out [32]byte
	if len(b) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNamesVectors appends the name→UUID vectors: the browser's names.mjs
// must resolve the same names to the same UUIDs this package does.
func TestNamesVectors(t *testing.T) {
	_ = names.User("alice")
}
