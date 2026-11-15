package client

import (
	"context"
	"testing"
)

// twoClients registers alice and bob with no session between them.
func twoClients(t *testing.T) (alice, bob *Client) {
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
	for _, c := range []*Client{alice, bob} {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return alice, bob
}

// emitted drains bob's inbox and returns what arrived.
func emitted(c *Client) []Received {
	var out []Received
	for {
		select {
		case r := <-c.Inbox:
			out = append(out, r)
		default:
			return out
		}
	}
}

// S-52: a message stashed until its session's first message, and
// redelivered while it waits (resume and live delivery overlap), is
// stashed once and emitted once.
func TestPairwiseStashRedeliveredOnce(t *testing.T) {
	ctx := context.Background()
	alice, bob := twoClients(t)
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
	bob.handleDeliver(deliverOf(room, 1, alice, second))
	bob.handleDeliver(deliverOf(room, 1, alice, second))
	bob.handleDeliver(deliverOf(room, 2, alice, first))
	got := emitted(bob)
	if len(got) != 2 || string(got[0].Plaintext) != "first" || string(got[1].Plaintext) != "second" ||
		got[0].Err != nil || got[1].Err != nil {
		t.Fatalf("emitted %+v; want first, second once each", got)
	}
}

// S-52: the same for a group message stashed until its sender key's
// distribution lands.
func TestGroupStashRedeliveredOnce(t *testing.T) {
	ctx := context.Background()
	alice, bob := twoClients(t)
	room := [16]byte{9}
	d, err := alice.sealDistribution(ctx, room, Peer{User: bob.user, Device: bob.device})
	if err != nil {
		t.Fatal(err)
	}
	g, err := alice.sealGroup(room, []byte("group"))
	if err != nil {
		t.Fatal(err)
	}
	bob.handleDeliver(deliverOf(room, 1, alice, g))
	bob.handleDeliver(deliverOf(room, 1, alice, g))
	if n := len(bob.skPending[skRef{room: room, device: alice.device}]); n != 1 {
		t.Errorf("stashed %d copies; want 1", n)
	}
	bob.handleDeliver(deliverOf(room, 2, alice, d))
	got := emitted(bob)
	if len(got) != 1 || string(got[0].Plaintext) != "group" || got[0].Err != nil {
		t.Fatalf("emitted %+v; want the group message once", got)
	}
}
