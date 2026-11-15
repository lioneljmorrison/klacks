package client

import (
	"context"
	"errors"
	"sort"
	"testing"
)

// restart builds a new client from c's keys and the given session snapshot:
// a device restarting from its saved state.
func restart(t *testing.T, c *Client, sessions []byte) *Client {
	t.Helper()
	held := c.HeldOneTimePrekeys()
	sort.Slice(held, func(i, j int) bool { return held[i].ID < held[j].ID })
	c2, err := NewClientWithKeys(c.base, c.user, c.device, c.id, c.spk, held)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.RestoreState(sessions); err != nil {
		t.Fatal(err)
	}
	return c2
}

// pairOf registers alice and bob and runs one exchange each way, so both
// hold established sessions.
func pairOf(t *testing.T) (alice, bob *Client, room [16]byte) {
	t.Helper()
	base := restDevices(t)
	ctx := context.Background()
	var err error
	if alice, err = NewClient(base, [16]byte{1}, [16]byte{0xA1}); err != nil {
		t.Fatal(err)
	}
	if bob, err = NewClient(base, [16]byte{2}, [16]byte{0xB1}); err != nil {
		t.Fatal(err)
	}
	if err := alice.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bob.Register(ctx); err != nil {
		t.Fatal(err)
	}
	room = [16]byte{9}
	e, err := alice.sealFor(ctx, room, Peer{User: bob.user, Device: bob.device}, []byte("a1"))
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 1, alice, e)) // her own echo: silent
	bob.handleDeliver(deliverOf(room, 1, alice, e))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "a1" {
		t.Fatalf("bob got %+v", r)
	}
	e, err = bob.sealFor(ctx, room, Peer{User: alice.user, Device: alice.device}, []byte("b1"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 2, bob, e)) // his own echo: silent
	alice.handleDeliver(deliverOf(room, 2, bob, e))
	if r := inbox(t, alice); r.Err != nil || string(r.Plaintext) != "b1" {
		t.Fatalf("alice got %+v", r)
	}
	return alice, bob, room
}

// A restarted device keeps its sessions: the peer's next message, sealed
// over the session the device held before the restart, decrypts — and the
// device's reply continues that session instead of starting a new one.
func TestRestoredSessionsDecryptAndReply(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := pairOf(t)

	snap, err := bob.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	bob2 := restart(t, bob, snap)

	e, err := alice.sealFor(ctx, room, Peer{User: bob.user, Device: bob.device}, []byte("after restart"))
	if err != nil {
		t.Fatal(err)
	}
	alice.handleDeliver(deliverOf(room, 3, alice, e)) // her own echo
	bob2.handleDeliver(deliverOf(room, 3, alice, e))
	if r := inbox(t, bob2); r.Err != nil || string(r.Plaintext) != "after restart" {
		t.Fatalf("restarted bob got %+v", r)
	}

	e, err = bob2.sealFor(ctx, room, Peer{User: alice.user, Device: alice.device}, []byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := decodeHeader(e.Header)
	if err != nil {
		t.Fatal(err)
	}
	if h.isPrekey() {
		t.Fatal("restarted bob started a new session instead of continuing the saved one")
	}
	alice.handleDeliver(deliverOf(room, 4, bob, e))
	if r := inbox(t, alice); r.Err != nil || string(r.Plaintext) != "reply" {
		t.Fatalf("alice got %+v", r)
	}
}

// Send hands the state to BeforePublish after sealing each envelope and
// before publishing it: a snapshot taken there already holds the advanced
// send chain, so a device that dies after transmitting cannot restart one
// step back and seal its next message under the same key and nonce. A
// hook error stops the send.
func TestSendSavesBeforePublish(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := pairOf(t)
	peerBob := Peer{User: bob.user, Device: bob.device}

	before, err := alice.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	var snap []byte
	stop := errors.New("stop before publish")
	alice.SetBeforePublish(func() error {
		var err error
		snap, err = alice.MarshalState()
		if err != nil {
			return err
		}
		return stop
	})
	if err := alice.Send(ctx, room, []Peer{peerBob}, []byte("on the wire")); !errors.Is(err, stop) {
		t.Fatalf("Send = %v, want the hook's error", err)
	}

	alice2 := restart(t, alice, snap)
	next, err := alice2.sealFor(ctx, room, peerBob, []byte("next"))
	if err != nil {
		t.Fatal(err)
	}
	hNext, err := decodeHeader(next.Header)
	if err != nil {
		t.Fatal(err)
	}
	// A copy restored from before the send seals at the chain position the
	// transmitted message used; the hook's snapshot must be past it.
	stale, err := restart(t, alice, before).sealFor(ctx, room, peerBob, []byte("stale"))
	if err != nil {
		t.Fatal(err)
	}
	hStale, err := decodeHeader(stale.Header)
	if err != nil {
		t.Fatal(err)
	}
	if hNext.dh == hStale.dh && hNext.n == hStale.n {
		t.Fatalf("the hook's snapshot predates the sealed message: next seals at n=%d again", hNext.n)
	}
}

// A snapshot that does not parse is refused rather than half-applied.
func TestRestoreStateRejectsGarbage(t *testing.T) {
	c, err := NewClient("http://test.invalid", [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RestoreState([]byte("{not json")); err == nil {
		t.Fatal("garbage snapshot accepted")
	}
}

// Joining replays history from seq 0, so a restarted device sees the
// peer's session-opening message again. That must not reset the restored
// session: the device's next message still continues the session the peer
// holds.
func TestRestoredSessionSurvivesReplayOfOpeningMessage(t *testing.T) {
	ctx := context.Background()
	base := restDevices(t)
	dave, err := NewClient(base, [16]byte{4}, [16]byte{0xD1})
	if err != nil {
		t.Fatal(err)
	}
	carol, err := NewClient(base, [16]byte{3}, [16]byte{0xC1})
	if err != nil {
		t.Fatal(err)
	}
	if err := dave.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := carol.Register(ctx); err != nil {
		t.Fatal(err)
	}
	room := [16]byte{9}
	peerCarol := Peer{User: carol.user, Device: carol.device}
	peerDave := Peer{User: dave.user, Device: dave.device}

	open, err := dave.sealFor(ctx, room, peerCarol, []byte("hi ladies"))
	if err != nil {
		t.Fatal(err)
	}
	opening := deliverOf(room, 1, dave, open)
	dave.handleDeliver(opening) // his own echo
	carol.handleDeliver(opening)
	if r := inbox(t, carol); r.Err != nil {
		t.Fatalf("carol: %v", r.Err)
	}
	e, err := carol.sealFor(ctx, room, peerDave, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	carol.handleDeliver(deliverOf(room, 2, carol, e)) // her own echo
	dave.handleDeliver(deliverOf(room, 2, carol, e))
	if r := inbox(t, dave); r.Err != nil {
		t.Fatalf("dave: %v", r.Err)
	}

	snap, err := carol.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	carol2 := restart(t, carol, snap)
	carol2.handleDeliver(opening) // a resume from seq 0 replays it
	// Already consumed before the restart (S-42): silent, not shown again.
	wantNoInbox(t, carol2)
	carol2.handleDeliver(deliverOf(room, 2, carol, e)) // and her own message

	e, err = carol2.sealFor(ctx, room, peerDave, []byte("why are my messages missing"))
	if err != nil {
		t.Fatal(err)
	}
	dave.handleDeliver(deliverOf(room, 3, carol, e))
	if r := inbox(t, dave); r.Err != nil || string(r.Plaintext) != "why are my messages missing" {
		t.Fatalf("dave got %+v", r)
	}
}

// The seq a peer's initiation arrived at survives a restart: it is what
// tells a replay of an older initiation from a new one (newcomerWins).
func TestRestoreKeepsEstablishmentSeq(t *testing.T) {
	c, err := NewClient("http://unused", [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponderRatchet([32]byte{1}, c.spk, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	room, peer := [16]byte{7}, [16]byte{0xB1}
	c.sessions[sessionKey{room: room, peer: peer}] = &session{
		peer: Peer{User: [16]byte{2}, Device: peer}, ratchet: r, estSeq: 42,
	}
	b, err := c.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewClient("http://unused", [16]byte{1}, [16]byte{0xA1})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RestoreState(b); err != nil {
		t.Fatal(err)
	}
	if got := d.sessions[sessionKey{room: room, peer: peer}].estSeq; got != 42 {
		t.Fatalf("estSeq after restore = %d, want 42", got)
	}
}

// snapRestart snapshots c and restarts it from the snapshot.
func snapRestart(t *testing.T, c *Client) *Client {
	t.Helper()
	snap, err := c.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	return restart(t, c, snap)
}

func wantNoInbox(t *testing.T, c *Client) {
	t.Helper()
	select {
	case r := <-c.Inbox:
		t.Fatalf("unexpected inbox event: %+v", r)
	default:
	}
}

// S-42: a restarted device keeps each room's ordering state. It knows where
// it left off (LastSeq, for resume), a replay of what it already consumed is
// silent instead of shown again, and the gap check continues from the
// restored position instead of re-anchoring.
func TestRestoredRoomOrdering(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := pairOf(t) // both consumed seqs 1 and 2
	peerBob := Peer{User: bob.user, Device: bob.device}
	e3, err := alice.sealFor(ctx, room, peerBob, []byte("a3"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 3, alice, e3))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "a3" {
		t.Fatalf("bob got %+v", r)
	}

	bob2 := snapRestart(t, bob)
	if seq, ok := bob2.LastSeq(room); !ok || seq != 3 {
		t.Fatalf("LastSeq = %d, %v; want 3, true", seq, ok)
	}
	if _, ok := bob2.LastSeq([16]byte{0xee}); ok {
		t.Fatal("LastSeq of an unknown room is ok")
	}
	// A resume from 0 replays seq 3: already consumed, so silent.
	bob2.handleDeliver(deliverOf(room, 3, alice, e3))
	wantNoInbox(t, bob2)
	// The gap check continues from 3 rather than re-anchoring.
	e4, err := alice.sealFor(ctx, room, peerBob, []byte("a4"))
	if err != nil {
		t.Fatal(err)
	}
	bob2.handleDeliver(deliverOf(room, 5, alice, e4))
	if r := inbox(t, bob2); r.Err == nil {
		t.Fatalf("seq 5 after 3: want a gap error, got %+v", r)
	}
	bob3 := snapRestart(t, bob)
	bob3.handleDeliver(deliverOf(room, 4, alice, e4))
	if r := inbox(t, bob3); r.Err != nil || string(r.Plaintext) != "a4" {
		t.Fatalf("seq 4: %+v", r)
	}
}

// S-42: a message stashed pending its session's first message survives a
// restart and decrypts once that first message arrives. A device resuming
// from its saved position would never see it again otherwise: its seq is
// already behind the room's last seq.
func TestRestoredPendingStash(t *testing.T) {
	ctx := context.Background()
	base := restDevices(t)
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
	first, err := alice.sealFor(ctx, room, peerBob, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := alice.sealFor(ctx, room, peerBob, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	// The second commits first (publish race): stashed.
	bob.handleDeliver(deliverOf(room, 1, alice, second))
	wantNoInbox(t, bob)

	bob2 := snapRestart(t, bob)
	bob2.handleDeliver(deliverOf(room, 2, alice, first))
	got := []string{}
	for range 2 {
		r := inbox(t, bob2)
		if r.Err != nil {
			t.Fatalf("restored stash: %+v", r)
		}
		got = append(got, string(r.Plaintext))
	}
	if got[0] != "first" || got[1] != "second" {
		t.Fatalf("got %q; want first, second", got)
	}
}

// groupPair registers alice and bob and installs alice's sender key at bob
// (seq 1).
func groupPair(t *testing.T) (alice, bob *Client, room [16]byte) {
	t.Helper()
	ctx := context.Background()
	base := restDevices(t)
	var err error
	if alice, err = NewClient(base, [16]byte{1}, [16]byte{0xA1}); err != nil {
		t.Fatal(err)
	}
	if bob, err = NewClient(base, [16]byte{2}, [16]byte{0xB1}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	room = [16]byte{9}
	peerBob := Peer{User: bob.user, Device: bob.device}
	d, err := alice.sealDistribution(ctx, room, peerBob)
	if err != nil {
		t.Fatal(err)
	}
	alice.setRoomPeers(room, []Peer{peerBob}) // as Distribute records it
	bob.handleDeliver(deliverOf(room, 1, alice, d))
	wantNoInbox(t, bob)
	return alice, bob, room
}

// S-42: sender-key state survives a restart on both sides: the restarted
// sender continues its chain (the receiver would refuse a reused
// iteration), and the restarted receiver still opens the sender's messages.
func TestRestoredSenderKeys(t *testing.T) {
	alice, bob, room := groupPair(t)
	g1, err := alice.sealGroup(room, []byte("g1"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 2, alice, g1))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "g1" {
		t.Fatalf("g1: %+v", r)
	}

	alice2, bob2 := snapRestart(t, alice), snapRestart(t, bob)
	g2, err := alice2.sealGroup(room, []byte("g2"))
	if err != nil {
		t.Fatalf("restored sender has no chain: %v", err)
	}
	bob2.handleDeliver(deliverOf(room, 3, alice, g2))
	if r := inbox(t, bob2); r.Err != nil || string(r.Plaintext) != "g2" {
		t.Fatalf("g2 after both restarted: %+v", r)
	}
	if peers := alice2.roomPeers[room]; len(peers) != 1 || peers[0].Device != bob.device {
		t.Fatalf("restored membership view = %+v", peers)
	}
}

// S-42: a group message stashed while its distribution is in flight
// survives a restart.
func TestRestoredGroupStash(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := groupPair(t)
	// Alice rotates (to nobody yet); her message under the new key
	// overtakes the new key's distribution to bob.
	if err := alice.Rotate(ctx, room, nil); err != nil {
		t.Fatal(err)
	}
	d2, err := alice.sealDistribution(ctx, room, Peer{User: bob.user, Device: bob.device})
	if err != nil {
		t.Fatal(err)
	}
	g, err := alice.sealGroup(room, []byte("under the new key"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 2, alice, g))
	wantNoInbox(t, bob)

	bob2 := snapRestart(t, bob)
	bob2.handleDeliver(deliverOf(room, 3, alice, d2))
	if r := inbox(t, bob2); r.Err != nil || string(r.Plaintext) != "under the new key" {
		t.Fatalf("restored group stash: %+v", r)
	}
}

// S-42: every publish path saves first, not only Send. A group message, a
// distribution and a rotation all advance key state that must be on disk
// before the envelope leaves.
func TestGroupPublishesSaveBeforePublish(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := groupPair(t)
	peerBob := Peer{User: bob.user, Device: bob.device}
	stop := errors.New("stop before publish")
	var snap []byte
	calls := 0
	alice.SetBeforePublish(func() error {
		calls++
		var err error
		snap, err = alice.MarshalState()
		if err != nil {
			return err
		}
		return stop
	})
	if err := alice.SendGroup(ctx, room, []byte("g")); !errors.Is(err, stop) {
		t.Fatalf("SendGroup = %v; want the hook's error", err)
	}
	// The snapshot is past the sealed message: a restart seals at the next
	// iteration, not the one already sealed.
	g, err := restart(t, alice, snap).sealGroup(room, []byte("next"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, iter, err := decodeSKHeader(g.Header)
	if err != nil {
		t.Fatal(err)
	}
	if iter != 1 {
		t.Fatalf("restored chain seals at iteration %d; want 1 (0 went out)", iter)
	}
	if err := alice.Distribute(ctx, room, []Peer{peerBob}); !errors.Is(err, stop) {
		t.Fatalf("Distribute = %v; want the hook's error", err)
	}
	if err := alice.Rotate(ctx, room, []Peer{peerBob}); !errors.Is(err, stop) {
		t.Fatalf("Rotate = %v; want the hook's error", err)
	}
	if calls != 3 {
		t.Fatalf("hook ran %d times; want 3", calls)
	}
}

// A version-1 snapshot (sessions only, S-40) still restores.
func TestRestoreStateV1(t *testing.T) {
	c, err := NewClient("http://test.invalid", [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RestoreState([]byte(`{"v":1,"sessions":[],"fallbacks":[]}`)); err != nil {
		t.Fatalf("v1 snapshot: %v", err)
	}
}
