package client

// Sender Key tests (S-27): each member device generates a chain and
// distributes it pairwise; receivers install it. The distribution rides the
// existing pairwise Double Ratchet sessions, so the loopback here delivers
// distribution envelopes the way the wire would. Group-message encryption
// and decryption are S-28.

import (
	"bytes"
	"context"
	"testing"
)

// sameSenderKey compares two distribution payloads field by field (the
// signing key is a slice, so the structs cannot be compared directly).
func sameSenderKey(a, b SenderKey) bool {
	return a.KeyID == b.KeyID && a.Iteration == b.Iteration &&
		a.ChainKey == b.ChainKey && bytes.Equal(a.Signing, b.Signing)
}

func TestSenderChainDistributionShape(t *testing.T) {
	ch, err := NewSenderChain()
	if err != nil {
		t.Fatal(err)
	}
	k := ch.Distribution()

	// The wire shape is fixed width: "skd1" || keyID(4) || iteration(4) ||
	// chainKey(32) || signing key(32).
	b := marshalSenderKeyDistribution(k)
	if !bytes.HasPrefix(b, []byte(skDistMagic)) {
		t.Fatalf("distribution lacks the magic prefix: %x", b[:4])
	}
	if len(b) != 4+4+4+32+32 {
		t.Fatalf("distribution is %d bytes, want 76", len(b))
	}
	back, err := unmarshalSenderKeyDistribution(b)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSenderKey(back, k) {
		t.Fatalf("round trip: got %+v, want %+v", back, k)
	}

	// Two chains never share a key id or chain key.
	other, err := NewSenderChain()
	if err != nil {
		t.Fatal(err)
	}
	if sameSenderKey(other.Distribution(), k) {
		t.Fatal("two chains produced the same distribution")
	}

	// Refuse malformed payloads.
	for _, bad := range [][]byte{
		nil,
		b[:10],
		append([]byte("nope"), b[4:]...),
	} {
		if _, err := unmarshalSenderKeyDistribution(bad); err == nil {
			t.Fatalf("accepted malformed distribution %v", bad)
		}
	}
}

func TestInstallSenderKey(t *testing.T) {
	ch1, _ := NewSenderChain()
	ch2, _ := NewSenderChain()
	r := NewSenderKeys()

	k1 := ch1.Distribution()
	if err := r.Install(k1); err != nil {
		t.Fatal(err)
	}
	// Redelivery of the same distribution is a no-op, not an error.
	if err := r.Install(k1); err != nil {
		t.Fatalf("re-installing the same distribution: %v", err)
	}
	// The same key id with different material is a conflict.
	conflict := k1
	conflict.ChainKey[0] ^= 0xFF
	if err := r.Install(conflict); err == nil {
		t.Fatal("accepted a conflicting distribution for the same key id")
	}
	// The honest copy still decrypts later (S-28), so the state must be
	// intact after the conflict.
	if len(r.states) != 1 {
		t.Fatalf("installed %d states after a conflict, want 1", len(r.states))
	}

	// A new key id (a rotation) is installed alongside the old one.
	if err := r.Install(ch2.Distribution()); err != nil {
		t.Fatal(err)
	}
	if len(r.states) != 2 {
		t.Fatalf("installed %d states, want 2", len(r.states))
	}

	// Installed states are bounded: the oldest drops when the room grows.
	for i := 0; i < skStatesKept; i++ {
		ch, err := NewSenderChain()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Install(ch.Distribution()); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.states) != skStatesKept {
		t.Fatalf("installed %d states, want %d", len(r.states), skStatesKept)
	}
}

// TestDistributionLoopback: alice distributes to bob over the pairwise
// session, delivered the way the wire would. The distribution is a control
// message: no inbox event, and bob's own copy of nothing leaks.
func TestDistributionLoopback(t *testing.T) {
	base := restDevices(t)
	ctx := context.Background()
	alice, err := NewClient(base, [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewClient(base, [16]byte{2}, [16]byte{0xB1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	room := [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}

	e, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	// The server delivers the publish back to its sender too; the pairwise
	// recipient check drops it silently.
	alice.handleDeliver(deliverOf(room, 1, alice, e))
	select {
	case r := <-alice.Inbox:
		t.Fatalf("distribution echoed to its sender: %+v", r)
	default:
	}
	// No distribution before delivery.
	if _, ok := bob.skPeers[skRef{room: room, device: alice.device}]; ok {
		t.Fatal("bob installed a sender key before any distribution")
	}
	bob.handleDeliver(deliverOf(room, 1, alice, e))
	select {
	case r := <-bob.Inbox:
		t.Fatalf("distribution produced an inbox event: %+v", r)
	default:
	}
	installed, ok := bob.skPeers[skRef{room: room, device: alice.device}]
	if !ok {
		t.Fatal("bob did not install alice's sender key")
	}
	k := alice.skOwn[room].Distribution()
	if len(installed.states) != 1 || installed.states[0].keyID != k.KeyID {
		t.Fatalf("bob installed %+v, want alice's key %d", installed.states, k.KeyID)
	}
}

// TestGroupMessageAwaitsDistribution: a group message that arrives before
// its sender device's distribution is stashed silently, and decrypts when
// the distribution lands (S-27's processing and S-28's receive path).
func TestGroupMessageAwaitsDistribution(t *testing.T) {
	base := restDevices(t)
	ctx := context.Background()
	alice, err := NewClient(base, [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewClient(base, [16]byte{2}, [16]byte{0xB1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	room := [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}

	// Alice creates her chain by sealing the distribution — but the
	// publishes commit out of send order, so bob receives the group
	// message before the distribution.
	d, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	// Bob's device has never received a distribution from alice's.
	g, err := alice.sealGroup(room, []byte("early group message"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, g))
	select {
	case r := <-bob.Inbox:
		t.Fatalf("group message arrived without its distribution: %+v", r)
	default:
	}
	if n := len(bob.skPending[skRef{room: room, device: alice.device}]); n != 1 {
		t.Fatalf("stashed %d messages, want 1", n)
	}

	// The distribution lands (committed after the message it enables, the
	// publish race) and the stash decrypts.
	bob.handleDeliver(deliverOf(room, 2, alice, d))
	r := inbox(t, bob)
	if r.Err != nil || string(r.Plaintext) != "early group message" {
		t.Fatalf("stashed group message: %+v", r)
	}
	if n := len(bob.skPending[skRef{room: room, device: alice.device}]); n != 0 {
		t.Fatalf("stash not drained: %d left", n)
	}
}

// TestDistributionPerRoom: the same sender device's chains installed for
// one room do not appear in another room.
func TestDistributionPerRoom(t *testing.T) {
	base := restDevices(t)
	ctx := context.Background()
	alice, err := NewClient(base, [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewClient(base, [16]byte{2}, [16]byte{0xB1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	roomA, roomB := [16]byte{9}, [16]byte{10}
	peerBob := Peer{User: bob.user, Device: bob.device}

	ea, err := alice.sealDistribution(ctx, roomA, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := alice.sealDistribution(ctx, roomB, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	// One chain per room: the two rooms' distributions differ even though
	// the same device sent both.
	if bytes.Equal(ea.Ciphertext, eb.Ciphertext) {
		t.Fatal("two rooms shared a sender chain")
	}
	bob.handleDeliver(deliverOf(roomA, 1, alice, ea))
	bob.handleDeliver(deliverOf(roomB, 1, alice, eb))
	installed := 0
	for _, r := range bob.skPeers {
		installed += len(r.states)
	}
	if installed != 2 {
		t.Fatalf("bob installed %d chains across two rooms, want 2", installed)
	}
}
