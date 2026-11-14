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
	if err := c2.RestoreSessions(sessions); err != nil {
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
	bob.handleDeliver(deliverOf(room, 1, alice, e))
	if r := inbox(t, bob); r.Err != nil || string(r.Plaintext) != "a1" {
		t.Fatalf("bob got %+v", r)
	}
	e, err = bob.sealFor(ctx, room, Peer{User: alice.user, Device: alice.device}, []byte("b1"))
	if err != nil {
		t.Fatal(err)
	}
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

	snap, err := bob.MarshalSessions()
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

	before, err := alice.MarshalSessions()
	if err != nil {
		t.Fatal(err)
	}
	var snap []byte
	stop := errors.New("stop before publish")
	alice.SetBeforePublish(func() error {
		var err error
		snap, err = alice.MarshalSessions()
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
func TestRestoreSessionsRejectsGarbage(t *testing.T) {
	c, err := NewClient("http://test.invalid", [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RestoreSessions([]byte("{not json")); err == nil {
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

	snap, err := carol.MarshalSessions()
	if err != nil {
		t.Fatal(err)
	}
	carol2 := restart(t, carol, snap)
	carol2.handleDeliver(opening) // /join replays from seq 0
	if r := inbox(t, carol2); r.Err != nil || string(r.Plaintext) != "hi ladies" {
		t.Fatalf("replayed opening: %+v", r)
	}
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
