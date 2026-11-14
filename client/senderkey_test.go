package client

// Sender Key tests (S-27): each member device generates a chain and
// distributes it pairwise; receivers install it. The distribution rides the
// existing pairwise Double Ratchet sessions, so the loopback here delivers
// distribution envelopes the way the wire would. Group-message encryption
// and decryption are S-28.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/protocol"
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

// TestGroupMessageAwaitsNextRotation: with an older chain from the same
// sender device already installed, a message under the sender's NEXT key
// id — its rotation distribution still in flight — is stashed (not
// dropped), and drains when the distribution lands. The drop variant of
// this race is what the e2e removal tests caught.
func TestGroupMessageAwaitsNextRotation(t *testing.T) {
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

	d1, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, d1))

	// Rotation: the new chain's distribution is sealed but its delivery
	// loses the publish race to the first message it enables.
	if err := alice.rotateOwn(room); err != nil {
		t.Fatal(err)
	}
	d2, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	g, err := alice.sealGroup(room, []byte("post-rotation"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 2, alice, g))
	select {
	case r := <-bob.Inbox:
		t.Fatalf("post-rotation message arrived before its distribution: %+v", r)
	default:
	}
	if n := len(bob.skPending[skRef{room: room, device: alice.device}]); n != 1 {
		t.Fatalf("stashed %d messages, want 1", n)
	}

	// The rotation distribution lands and the stash decrypts.
	bob.handleDeliver(deliverOf(room, 3, alice, d2))
	r := inbox(t, bob)
	if r.Err != nil || string(r.Plaintext) != "post-rotation" {
		t.Fatalf("stashed post-rotation message: %+v", r)
	}
	if n := len(bob.skPending[skRef{room: room, device: alice.device}]); n != 0 {
		t.Fatalf("stash not drained: %d left", n)
	}
}

// TestConcurrentInitiationConverges: both devices initiate before either
// processes the other's prekey message — the race simultaneous group
// distribution hits under load. Each side's late prekey message must be
// settled by the same deterministic tie-break, and both directions must
// then decrypt.
func TestConcurrentInitiationConverges(t *testing.T) {
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
	peerAlice := Peer{User: alice.user, Device: alice.device}

	// Both initiate before anything is delivered.
	ea, err := alice.sealFor(ctx, room, peerBob, []byte("a-init"))
	if err != nil {
		t.Fatal(err)
	}
	eb, err := bob.sealFor(ctx, room, peerAlice, []byte("b-init"))
	if err != nil {
		t.Fatal(err)
	}

	// The wire delivers in seq order; each sender also gets its own echo.
	alice.handleDeliver(deliverOf(room, 1, alice, ea)) // own echo
	bob.handleDeliver(deliverOf(room, 1, alice, ea))
	bob.handleDeliver(deliverOf(room, 2, bob, eb)) // own echo
	alice.handleDeliver(deliverOf(room, 2, bob, eb))

	// Both directions send over whatever session each side settled on;
	// each side's first message is the initiation payload itself.
	ea2, err := alice.sealFor(ctx, room, peerBob, []byte("a-later"))
	if err != nil {
		t.Fatal(err)
	}
	eb2, err := bob.sealFor(ctx, room, peerAlice, []byte("b-later"))
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 3, alice, ea2)) // own echo
	bob.handleDeliver(deliverOf(room, 3, alice, ea2))
	bob.handleDeliver(deliverOf(room, 4, bob, eb2)) // own echo
	alice.handleDeliver(deliverOf(room, 4, bob, eb2))

	for _, tc := range []struct {
		c        *Client
		firstGot string
		want     string
	}{{bob, "a-init", "a-later"}, {alice, "b-init", "b-later"}} {
		if r := inbox(t, tc.c); r.Err != nil || string(r.Plaintext) != tc.firstGot {
			t.Fatalf("%p initiation message: %+v, want %q", tc.c, r, tc.firstGot)
		}
		if r := inbox(t, tc.c); r.Err != nil || string(r.Plaintext) != tc.want {
			t.Fatalf("%p later message: %+v, want %q", tc.c, r, tc.want)
		}
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

// --- S-28: group message encryption with Sender Keys. ---

// skFixture builds one sender device's chain, a receiver that has installed
// it, and seals n messages, returning them with the ADs they were bound to.
func skFixture(t *testing.T, n int) (ch *SenderChain, r *SenderKeys, envs []encryptResult, ads [][]byte) {
	t.Helper()
	ch, err := NewSenderChain()
	if err != nil {
		t.Fatal(err)
	}
	r = NewSenderKeys()
	if err := r.Install(ch.Distribution()); err != nil {
		t.Fatal(err)
	}
	room, sender, dev := [16]byte{3}, [16]byte{4}, [16]byte{5}
	for i := 0; i < n; i++ {
		mid, err := newUUID()
		if err != nil {
			t.Fatal(err)
		}
		ad := AD{Room: room, Sender: sender, SenderDevice: dev, MessageID: mid}
		hdr, ct, err := ch.Encrypt([]byte(fmt.Sprintf("msg %d", i)), ad.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		envs = append(envs, encryptResult{MessageID: mid, Header: hdr, Ciphertext: ct})
		ads = append(ads, ad.Bytes())
	}
	return ch, r, envs, ads
}

// TestSenderChainRoundtripOutOfOrder: the receiver decrypts the chain's
// messages in any order — the stashed message keys put it back together.
func TestSenderChainRoundtripOutOfOrder(t *testing.T) {
	_, r, envs, ads := skFixture(t, 3)
	for _, i := range []int{2, 0, 1} {
		pt, err := r.Decrypt(envs[i].Header, envs[i].Ciphertext, ads[i])
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if string(pt) != fmt.Sprintf("msg %d", i) {
			t.Fatalf("message %d: got %q", i, pt)
		}
	}
}

// TestSenderKeyTamperRejected: any change to the ciphertext, the header or
// the associated data fails, and failed attempts leave the chain intact.
func TestSenderKeyTamperRejected(t *testing.T) {
	_, r, envs, ads := skFixture(t, 2)

	badCT := append([]byte(nil), envs[0].Ciphertext...)
	badCT[0] ^= 0xFF
	if _, err := r.Decrypt(envs[0].Header, badCT, ads[0]); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	badHdr := append([]byte(nil), envs[0].Header...)
	badHdr[len(badHdr)-1] ^= 0xFF // a signature byte
	if _, err := r.Decrypt(badHdr, envs[0].Ciphertext, ads[0]); err == nil {
		t.Fatal("tampered header accepted")
	}
	badAD := append([]byte(nil), ads[0]...)
	badAD[0] ^= 0xFF
	if _, err := r.Decrypt(envs[0].Header, envs[0].Ciphertext, badAD); err == nil {
		t.Fatal("tampered associated data accepted")
	}
	// The honest copy still decrypts: nothing advanced on failure.
	pt, err := r.Decrypt(envs[0].Header, envs[0].Ciphertext, ads[0])
	if err != nil || string(pt) != "msg 0" {
		t.Fatalf("honest copy after tamper attempts: %q, %v", pt, err)
	}
	// And the chain's next message is where it should be.
	if _, err := r.Decrypt(envs[1].Header, envs[1].Ciphertext, ads[1]); err != nil {
		t.Fatalf("next message after tamper attempts: %v", err)
	}
}

// TestSenderKeyRedelivery: an identical redelivery decrypts to the same
// plaintext (resume replays it); the same chain position with different
// content is refused.
func TestSenderKeyRedelivery(t *testing.T) {
	_, r, envs, ads := skFixture(t, 1)
	pt1, err := r.Decrypt(envs[0].Header, envs[0].Ciphertext, ads[0])
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := r.Decrypt(envs[0].Header, envs[0].Ciphertext, ads[0])
	if err != nil {
		t.Fatalf("identical redelivery: %v", err)
	}
	if !bytes.Equal(pt1, pt2) {
		t.Fatalf("redelivery: got %q, want %q", pt2, pt1)
	}
	// Different content at the same position is a tampered stream.
	badCT := append([]byte(nil), envs[0].Ciphertext...)
	badCT[len(badCT)-1] ^= 0xFF
	// ...signed honestly, as a re-encrypted message at the same iteration
	// would be: the AEAD still refuses, and the cache refuses the unsigned
	// form before that.
	if _, err := r.Decrypt(envs[0].Header, badCT, ads[0]); err == nil {
		t.Fatal("replay with different content accepted")
	}
}

// TestSenderKeySkipLimit: at most skMaxSkip chain steps may be skipped; one
// more is refused.
func TestSenderKeySkipLimit(t *testing.T) {
	_, r, envs, ads := skFixture(t, int(skMaxSkip)+2)
	// Message skMaxSkip+1 is exactly one too far ahead.
	if _, err := r.Decrypt(envs[skMaxSkip+1].Header, envs[skMaxSkip+1].Ciphertext, ads[skMaxSkip+1]); err == nil {
		t.Fatal("accepted a message beyond the skip limit")
	}
	// The limit itself decrypts, stashing everything between.
	pt, err := r.Decrypt(envs[skMaxSkip].Header, envs[skMaxSkip].Ciphertext, ads[skMaxSkip])
	if err != nil || string(pt) != fmt.Sprintf("msg %d", skMaxSkip) {
		t.Fatalf("message at the skip limit: %q, %v", pt, err)
	}
}

// TestSenderKeyRotationStates: after a rotation (a new key id installed for
// the same sender device) both chains decrypt, until the retained-state
// bound drops the oldest.
func TestSenderKeyRotationStates(t *testing.T) {
	_, r, envs1, ads1 := skFixture(t, 1)
	ch2, err := NewSenderChain()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(ch2.Distribution()); err != nil {
		t.Fatal(err)
	}
	mid, _ := newUUID()
	ad2 := AD{Room: [16]byte{3}, Sender: [16]byte{4}, SenderDevice: [16]byte{5}, MessageID: mid}
	hdr2, ct2, err := ch2.Encrypt([]byte("new"), ad2.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := r.Decrypt(hdr2, ct2, ad2.Bytes()); err != nil || string(pt) != "new" {
		t.Fatalf("new chain: %q, %v", pt, err)
	}
	// The old chain's message still decrypts.
	if pt, err := r.Decrypt(envs1[0].Header, envs1[0].Ciphertext, ads1[0]); err != nil || string(pt) != "msg 0" {
		t.Fatalf("old chain after rotation: %q, %v", pt, err)
	}

	// Filling the retained-state bound drops the oldest chain; its
	// messages become unknown-key stashes again, not failures.
	for i := 0; i < skStatesKept-1; i++ {
		ch, err := NewSenderChain()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Install(ch.Distribution()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Decrypt(envs1[0].Header, envs1[0].Ciphertext, ads1[0]); !errors.Is(err, errSenderKeyUnknown) {
		t.Fatalf("evicted chain: want unknown-key, got %v", err)
	}
}

// TestGroupLoopback: two devices, both chains distributed pairwise, then
// group messages both ways — each encrypted once, broadcast, delivered
// back to its sender as an echo that stays silent.
func TestGroupLoopback(t *testing.T) {
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
	peerAlice := Peer{User: alice.user, Device: alice.device}

	// Both chains distribute pairwise, as the wire would deliver them.
	da, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	db, err := bob.sealDistribution(ctx, room, peerAlice)
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 1, alice, da)) // alice's echo: silent
	bob.handleDeliver(deliverOf(room, 1, alice, da))
	bob.handleDeliver(deliverOf(room, 2, bob, db)) // bob's echo: silent
	alice.handleDeliver(deliverOf(room, 2, bob, db))
	for _, c := range []*Client{alice, bob} {
		select {
		case r := <-c.Inbox:
			t.Fatalf("distribution leaked to %p: %+v", c, r)
		default:
		}
	}

	// Group messages both ways over the established chains, with echoes.
	seq := int64(3)
	for i := 0; i < 3; i++ {
		ea, err := alice.sealGroup(room, []byte(fmt.Sprintf("a%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		alice.handleDeliver(deliverOf(room, seq, alice, ea)) // own echo: silent
		bob.handleDeliver(deliverOf(room, seq, alice, ea))
		if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != fmt.Sprintf("a%d", i) {
			t.Fatalf("bob on a%d: %+v", i, r)
		}
		select {
		case r := <-alice.Inbox:
			t.Fatalf("alice took her own echo: %+v", r)
		default:
		}
		seq++
		eb, err := bob.sealGroup(room, []byte(fmt.Sprintf("b%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		bob.handleDeliver(deliverOf(room, seq, bob, eb))
		alice.handleDeliver(deliverOf(room, seq, bob, eb))
		if r := inbox(t, alice); r.Err != nil || string(r.Plaintext) != fmt.Sprintf("b%d", i) {
			t.Fatalf("alice on b%d: %+v", i, r)
		}
		seq++
	}
}

// TestGroupRotationLoopback: alice rotates (as a removal triggers in S-29);
// bob installs the new distribution; messages from both chains decrypt.
func TestGroupRotationLoopback(t *testing.T) {
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

	da, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, da))
	e1, err := alice.sealGroup(room, []byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 2, alice, e1))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "before" {
		t.Fatalf("before rotation: %+v", r)
	}

	// Rotation: an explicit new chain (a removal triggers it in S-29),
	// distributed again. A late message from the old chain — sealed before
	// the rotation, delivered after — still decrypts.
	oldChain := alice.skOwn[room]
	eLate, err := alice.sealGroup(room, []byte("late from old"))
	if err != nil {
		t.Fatal(err)
	}
	_ = alice.rotateOwn(room) // the test asserts the chain changed below
	if alice.skOwn[room] == oldChain {
		t.Fatal("rotateOwn did not replace the chain")
	}
	d2, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 3, alice, d2))
	e2, err := alice.sealGroup(room, []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 4, alice, e2))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "after" {
		t.Fatalf("after rotation: %+v", r)
	}
	// A late message from the old chain still decrypts.
	bob.handleDeliver(deliverOf(room, 5, alice, eLate))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "late from old" {
		t.Fatalf("late old-chain message: %+v", r)
	}
}

// --- S-29: rotation on member removal. ---

// TestSelfRemovalClosesRoom: a device told it was removed drops its
// sender-key state for the room and drops everything the room still sends
// its (still live) connection: distributions must not install, and group
// messages are not even stashed.
func TestSelfRemovalClosesRoom(t *testing.T) {
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
	peerAlice := Peer{User: alice.user, Device: alice.device}

	da, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	db, err := bob.sealDistribution(ctx, room, peerAlice)
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, da))
	alice.handleDeliver(deliverOf(room, 2, bob, db))

	// Alice is removed.
	alice.handleMemberRemoved(&protocol.MemberRemoved{
		RoomID: protocol.UUID(room), User: protocol.UUID(alice.user), Actor: protocol.UUID(bob.user),
	})
	if chain := alice.skOwn[room]; chain != nil {
		t.Fatal("removed device kept its own chain")
	}
	if _, ok := alice.skPeers[skRef{room: room, device: bob.device}]; ok {
		t.Fatal("removed device kept the peer's chain")
	}

	// The room's stream keeps arriving: a distribution does not install,
	// and a group message is neither decrypted nor stashed.
	bob.handleDeliver(deliverOf(room, 3, bob, db)) // bob's echo: silent either way
	g, err := bob.sealGroup(room, []byte("after removal"))
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 4, bob, g))
	select {
	case r := <-alice.Inbox:
		t.Fatalf("removed device processed a group message: %+v", r)
	default:
	}
	if n := len(alice.skPending[skRef{room: room, device: bob.device}]); n != 0 {
		t.Fatalf("removed device stashed %d messages", n)
	}
	d2, err := bob.sealDistribution(ctx, room, peerAlice)
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 5, bob, d2))
	if _, ok := alice.skPeers[skRef{room: room, device: bob.device}]; ok {
		t.Fatal("removed device installed a fresh distribution")
	}
}

// TestRemovalTriggersRotation: on another member's removal the device
// rotates its chain, updates its view, and redistributes to those that
// remain — which in the loopback fails at publish (no connection), a
// failure that surfaces on Errs.
func TestRemovalTriggersRotation(t *testing.T) {
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
	carol, err := NewClient(base, [16]byte{3}, [16]byte{0xC1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{alice, bob, carol} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	room := [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}
	peerCarol := Peer{User: carol.user, Device: carol.device}

	da1, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	da2, err := alice.sealDistribution(ctx, room, peerCarol)
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, da1))
	carol.handleDeliver(deliverOf(room, 1, alice, da2))
	// Distribute seeds the view; in the loopback the publish half fails,
	// so the view is set directly the way a real run would leave it.
	alice.setRoomPeers(room, []Peer{peerBob, peerCarol})
	oldChain := alice.skOwn[room]

	// Bob is removed; alice rotates and redistributes to carol.
	alice.handleMemberRemoved(&protocol.MemberRemoved{
		RoomID: protocol.UUID(room), User: protocol.UUID(bob.user), Actor: protocol.UUID(carol.user),
	})
	if alice.skOwn[room] == oldChain {
		t.Fatal("member removal did not rotate the chain")
	}
	view, _ := alice.roomPeersFor(room)
	if len(view) != 1 || view[0].Device != carol.device {
		t.Fatalf("view after removal = %+v; want only carol", view)
	}
	// The redistribution's publish fails with no connection: Errs says so.
	select {
	case err := <-alice.Errs:
		if err == nil || !strings.Contains(err.Error(), "redistribute") {
			t.Fatalf("Errs = %v; want the redistribute failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("redistribution failure never surfaced on Errs")
	}
}

// TestMembersFrameReconcile: the resume flow's member list is
// authoritative — every tracked member absent from it triggers one
// rotation for the whole difference, and an absent self closes the room.
func TestMembersFrameReconcile(t *testing.T) {
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
	carol, err := NewClient(base, [16]byte{3}, [16]byte{0xC1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{alice, bob, carol} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	room := [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}
	peerCarol := Peer{User: carol.user, Device: carol.device}

	da1, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	da2, err := alice.sealDistribution(ctx, room, peerCarol)
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, da1))
	carol.handleDeliver(deliverOf(room, 1, alice, da2))
	alice.setRoomPeers(room, []Peer{peerBob, peerCarol})
	oldChain := alice.skOwn[room]

	// While alice was offline both bob and carol were removed.
	alice.handleMembers(&protocol.Members{
		RoomID:  protocol.UUID(room),
		Members: []protocol.UUID{protocol.UUID(alice.user)},
	})
	if alice.skOwn[room] == oldChain {
		t.Fatal("member-list difference did not rotate the chain")
	}
	view, _ := alice.roomPeersFor(room)
	if len(view) != 0 {
		t.Fatalf("view after both peers removed = %+v; want empty", view)
	}
	// And one rotation is one distribution attempt per remaining peer:
	// none remain, so the only Err is nothing at all.
	select {
	case err := <-alice.Errs:
		t.Fatalf("unexpected Errs entry: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}
