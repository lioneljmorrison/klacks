package client

import (
	"bytes"
	"context"
	"testing"
)

// incRestart restarts c from an incremental save: the state without seen
// sets, plus every seen entry logged so far.
func incRestart(t *testing.T, c *Client, log []SeenEntry) *Client {
	t.Helper()
	state, _, err := c.MarshalStateIncremental()
	if err != nil {
		t.Fatal(err)
	}
	c2 := restart(t, c, state)
	c2.RestoreSeen(log)
	return c2
}

// drain takes the entries c has to log and acknowledges them, as a caller
// that appended them to its log would.
func drainSeen(t *testing.T, c *Client) []SeenEntry {
	t.Helper()
	_, seen, err := c.MarshalStateIncremental()
	if err != nil {
		t.Fatal(err)
	}
	c.SeenPersisted(len(seen))
	return seen
}

// S-49: with incremental saves, the state a device writes on every save no
// longer carries each room's seen set, so its size does not grow with
// history; the seen entries go to an append-only log, each one once.
func TestIncrementalSaveSizeAndLog(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := pairOf(t) // bob consumed seqs 1 and 2
	peerBob := Peer{User: bob.user, Device: bob.device}
	var log []SeenEntry
	log = append(log, drainSeen(t, bob)...)
	if len(log) != 2 {
		t.Fatalf("first drain: %d entries; want 2", len(log))
	}
	deliver := func(seq int64) {
		e, err := alice.sealFor(ctx, room, peerBob, []byte("m"))
		if err != nil {
			t.Fatal(err)
		}
		bob.handleDeliver(deliverOf(room, seq, alice, e))
		inbox(t, bob)
		got := drainSeen(t, bob)
		if len(got) != 1 || got[0].Seq != seq || got[0].Room != room {
			t.Fatalf("seq %d: drained %+v; want just this seq", seq, got)
		}
		log = append(log, got...)
	}
	// Fill the ratchet's bounded decrypt cache first (cacheLimit), so what
	// is left to grow is only what grows with history.
	seq := int64(3)
	for ; seq < 3+cacheLimit+10; seq++ {
		deliver(seq)
	}
	state0, _, err := bob.MarshalStateIncremental()
	if err != nil {
		t.Fatal(err)
	}
	for end := seq + 200; seq < end; seq++ {
		deliver(seq)
	}
	state1, _, err := bob.MarshalStateIncremental()
	if err != nil {
		t.Fatal(err)
	}
	if d := len(state1) - len(state0); d > 256 {
		t.Errorf("state grew by %d bytes over 200 deliveries", d)
	}
	full, err := bob.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	if len(full) <= len(state1) {
		t.Errorf("full snapshot (%d) not larger than incremental (%d)", len(full), len(state1))
	}
	// Unacknowledged entries are offered again.
	e, _ := alice.sealFor(ctx, room, peerBob, []byte("m"))
	bob.handleDeliver(deliverOf(room, seq, alice, e))
	inbox(t, bob)
	for range 2 {
		if _, seen, _ := bob.MarshalStateIncremental(); len(seen) != 1 {
			t.Fatalf("unacknowledged: %d entries; want 1 offered again", len(seen))
		}
	}
}

// S-49: after a restart from the incremental state and the log, a replay of
// an old message at its seq is silent, a different message at an old seq is
// tampering, and an old message copied to a new seq is tampering — the
// same checks a full snapshot gives.
func TestIncrementalRestoreKeepsOrderingChecks(t *testing.T) {
	ctx := context.Background()
	alice, bob, room := pairOf(t)
	peerBob := Peer{User: bob.user, Device: bob.device}
	var log []SeenEntry
	var sealed []encryptResult
	for seq := int64(3); seq <= 10; seq++ {
		e, err := alice.sealFor(ctx, room, peerBob, []byte{byte(seq)})
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, e)
		bob.handleDeliver(deliverOf(room, seq, alice, e))
		inbox(t, bob)
	}
	log = append(log, drainSeen(t, bob)...)

	b := incRestart(t, bob, log)
	if seq, ok := b.LastSeq(room); !ok || seq != 10 {
		t.Fatalf("LastSeq = %d, %v; want 10", seq, ok)
	}
	b.handleDeliver(deliverOf(room, 4, alice, sealed[1])) // seq 4, as delivered
	wantNoInbox(t, b)

	tampered := deliverOf(room, 5, alice, sealed[1]) // seq 4's message at seq 5
	b.handleDeliver(tampered)
	if r := inbox(t, b); r.Err == nil {
		t.Fatalf("seq 4's message at seq 5: want a tamper error, got %+v", r)
	}
	b = incRestart(t, bob, log)
	b.handleDeliver(deliverOf(room, 11, alice, sealed[0])) // seq 3's message at new seq 11
	if r := inbox(t, b); r.Err == nil || bytes.Equal(r.Plaintext, []byte{3}) {
		t.Fatalf("seq 3's message at seq 11: want a tamper error, got %+v", r)
	}
}

// S-49: a snapshot from before incremental saves carries its seen sets;
// restoring it queues them for the log, so the first incremental save
// migrates them instead of dropping them.
func TestFullSnapshotMigratesToLog(t *testing.T) {
	_, bob, room := pairOf(t)
	b := snapRestart(t, bob)
	_, seen, err := b.MarshalStateIncremental()
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0].Room != room {
		t.Fatalf("migrated %+v; want bob's 2 seen entries", seen)
	}
}
