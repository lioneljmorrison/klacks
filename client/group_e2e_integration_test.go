//go:build integration

// Group end to end (S-30): three reference clients over a real server — a
// group room, Sender Keys distributed pairwise over it, group messages
// encrypted once and broadcast, and the removal of a member rotating the
// remaining members' keys so the removed one reads nothing new. Includes
// posts racing the removal, a member offline during the removal, and
// concurrent removals.
package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/api/ws"
	"github.com/lioneljmorrison/klacks/internal/core"
)

// One more member than the DM e2e has.
const (
	e2eUserC = "a1000000-0000-0000-0000-000000000003"
	e2eDevC  = "b2000000-0000-0000-0000-000000000003"
)

// groupStack is the full serve path on fresh stores, with a group room.
type groupStack struct {
	srv  *testServer
	core *core.Service
	hub  *ws.Manager
	room [16]byte
}

func newGroupStack(t *testing.T) *groupStack {
	t.Helper()
	s := newE2EStack(t) // the same stack: real stores, ws manager with member_removed wired
	ctx := context.Background()
	room, err := s.core.CreateRoom(ctx, core.KindGroup, mustUUID(t, e2eUserA))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{e2eUserB, e2eUserC} {
		if err := s.core.AddMember(ctx, room, mustUUID(t, e2eUserA), mustUUID(t, u), core.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	return &groupStack{srv: s.srv, core: s.core, hub: s.hub, room: room}
}

// trio brings all three members online: registered, dialed, resuming from
// the start, and each having distributed its sender key pairwise.
func (s *groupStack) trio(t *testing.T) (alice, bob, carol *Client) {
	t.Helper()
	ctx := context.Background()
	alice = newClientFor(t, s.srv.base, e2eUserA, e2eDevA)
	bob = newClientFor(t, s.srv.base, e2eUserB, e2eDevB)
	carol = newClientFor(t, s.srv.base, e2eUserC, e2eDevC)
	clients := []*Client{alice, bob, carol}
	for _, c := range clients {
		if err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Dial(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Resume(ctx, s.room, 0); err != nil {
			t.Fatal(err)
		}
	}
	// The resume flow's members frame lists all three while no client has
	// a membership view yet: nothing to reconcile.
	for _, c := range clients {
		wantNothingInbox(t, c, 200*time.Millisecond)
	}
	users, err := s.core.Members(ctx, s.room)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		if err := c.Distribute(ctx, s.room, peerDevicesOf(t, c, users)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, c := range clients {
			c.Close()
		}
	})
	return alice, bob, carol
}

// peerDevicesOf turns the room's member users into every other member
// device, the way an application would: the members it knows, each
// member's registered devices.
func peerDevicesOf(t *testing.T, c *Client, members [][16]byte) []Peer {
	t.Helper()
	var out []Peer
	for _, u := range members {
		if u == c.user {
			continue
		}
		devs, err := c.ListDevices(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range devs {
			out = append(out, Peer{User: u, Device: d})
		}
	}
	return out
}

// wantNothingErrs fails if a client error arrives within d.
func wantNothingErrs(t *testing.T, c *Client, d time.Duration) {
	t.Helper()
	select {
	case err := <-c.Errs:
		t.Fatalf("unexpected client error: %v", err)
	case <-time.After(d):
	}
}

// wantNothingInbox fails if an inbox event arrives within d.
func wantNothingInbox(t *testing.T, c *Client, d time.Duration) {
	t.Helper()
	select {
	case r := <-c.Inbox:
		t.Fatalf("unexpected inbox event: %+v", r)
	case err := <-c.Errs:
		t.Fatalf("unexpected client error: %v", err)
	case <-time.After(d):
	}
}

// eachSends drives n group messages from every member and checks every
// member decrypts all the others' (its own echo is silent by design).
func eachSends(t *testing.T, s *groupStack, members []*Client, n int, tag string) {
	t.Helper()
	ctx := context.Background()
	sender := make(map[string]int) // plaintext → the member that sent it
	for i, c := range members {
		for j := 0; j < n; j++ {
			pt := fmt.Sprintf("%s-%c-%d", tag, 'A'+i, j)
			sender[pt] = i
			if err := c.SendGroup(ctx, s.room, []byte(pt)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Every member receives n from each of the others, in some order.
	for i, c := range members {
		got := make(map[string]bool, n*(len(members)-1))
		for k := 0; k < n*(len(members)-1); k++ {
			r := waitRecv(t, c)
			if r.Err != nil {
				t.Fatalf("%s: rejected: %v", tag, r.Err)
			}
			pt := string(r.Plaintext)
			from, ok := sender[pt]
			if !ok || from == i {
				t.Fatalf("%s: unexpected plaintext %q at member %d", tag, pt, i)
			}
			if got[pt] {
				t.Fatalf("%s: %q delivered twice to member %d", tag, pt, i)
			}
			got[pt] = true
		}
		for pt, from := range sender {
			if from != i && !got[pt] {
				t.Fatalf("%s: %q never arrived at member %d", tag, pt, i)
			}
		}
		wantNothingInbox(t, c, 300*time.Millisecond)
	}
}

// TestE2EGroupExchange: three members form a group — sender keys
// distributed pairwise over the room's own stream — and every member
// decrypts every other member's single-ciphertext group messages.
func TestE2EGroupExchange(t *testing.T) {
	s := newGroupStack(t)
	alice, bob, carol := s.trio(t)
	eachSends(t, s, []*Client{alice, bob, carol}, 3, "form")
}

// TestE2EGroupRemovalRotation: removing carol rotates alice's and bob's
// keys; the messages they exchange afterwards decrypt for them and never
// reach carol's inbox — her device drops the room after its removal event.
func TestE2EGroupRemovalRotation(t *testing.T) {
	s := newGroupStack(t)
	alice, bob, carol := s.trio(t)
	eachSends(t, s, []*Client{alice, bob, carol}, 2, "form")

	ctx := context.Background()
	if err := s.core.RemoveMember(ctx, s.room, mustUUID(t, e2eUserA), mustUUID(t, e2eUserC)); err != nil {
		t.Fatal(err)
	}

	// Alice and bob rotate on the event and redistribute to each other;
	// their next exchange decrypts under the new chains.
	if err := alice.SendGroup(ctx, s.room, []byte("after-A")); err != nil {
		t.Fatal(err)
	}
	if err := bob.SendGroup(ctx, s.room, []byte("after-B")); err != nil {
		t.Fatal(err)
	}
	// Each decrypts the other's message; own echoes stay silent, and the
	// removed carol reads nothing at all.
	for _, tc := range []struct {
		c    *Client
		want string
	}{{bob, "after-A"}, {alice, "after-B"}} {
		r := waitRecv(t, tc.c)
		if r.Err != nil || string(r.Plaintext) != tc.want {
			t.Fatalf("post-rotation: %+v, want %q", r, tc.want)
		}
	}
	wantNothingInbox(t, alice, 300*time.Millisecond)
	wantNothingInbox(t, bob, 300*time.Millisecond)
	// Carol's device was told it is out: it processes nothing further.
	wantNothingInbox(t, carol, 500*time.Millisecond)
}

// TestE2EPostDuringRemoval: posts racing the removal. Messages alice
// publishes while the removal commits and the rotation runs decrypt for
// bob — the retained pre-rotation chain takes the ones sent before it —
// and carol, already out, reads nothing at all.
func TestE2EPostDuringRemoval(t *testing.T) {
	s := newGroupStack(t)
	alice, bob, carol := s.trio(t)
	eachSends(t, s, []*Client{alice, bob, carol}, 1, "form")

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for i := 0; i < 10; i++ {
			if err := alice.SendGroup(ctx, s.room, []byte(fmt.Sprintf("race-%02d", i))); err != nil {
				t.Errorf("post %d: %v", i, err)
				return
			}
			if i == 4 {
				if err := s.core.RemoveMember(ctx, s.room, mustUUID(t, e2eUserA), mustUUID(t, e2eUserC)); err != nil {
					t.Errorf("remove: %v", err)
					return
				}
			}
		}
	}()
	wg.Wait()

	// Bob decrypts all ten: whichever chain each used, the retained
	// states keep the stream continuous.
	bobGot := make(map[string]bool, 10)
	for i := 0; i < 10; i++ {
		r := waitRecv(t, bob)
		if r.Err != nil {
			t.Fatalf("bob rejected: %v", r.Err)
		}
		pt := string(r.Plaintext)
		if !strings.HasPrefix(pt, "race-") {
			i-- // an event outside the race set; keep counting
			continue
		}
		if bobGot[pt] {
			t.Fatalf("bob got %q twice", pt)
		}
		bobGot[pt] = true
	}
	for i := 0; i < 10; i++ {
		if !bobGot[fmt.Sprintf("race-%02d", i)] {
			t.Fatalf("bob never got race-%02d", i)
		}
	}
	wantNothingInbox(t, bob, 300*time.Millisecond)

	// The group still works after the race: one exchange under the rotated
	// chains. Carol can never decrypt these — she holds no distribution
	// for them — whether or not her removal event has landed yet.
	if err := alice.SendGroup(ctx, s.room, []byte("quiet-A")); err != nil {
		t.Fatal(err)
	}
	if err := bob.SendGroup(ctx, s.room, []byte("quiet-B")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    *Client
		want string
	}{{bob, "quiet-A"}, {alice, "quiet-B"}} {
		r := waitRecv(t, tc.c)
		if r.Err != nil || string(r.Plaintext) != tc.want {
			t.Fatalf("post-race: %+v, want %q", r, tc.want)
		}
	}
	// Carol decrypts no post-rotation message; the pre-removal race
	// messages she may still receive are legitimate.
	for {
		select {
		case r := <-carol.Inbox:
			if r.Err != nil {
				t.Fatalf("carol rejected: %v", r.Err)
			}
			pt := string(r.Plaintext)
			if pt == "quiet-A" || pt == "quiet-B" {
				t.Fatalf("carol decrypted a post-rotation message: %q", pt)
			}
			continue
		case e := <-carol.Errs:
			_ = e // drain: a removed member's late publish may fail
			continue
		case <-time.After(500 * time.Millisecond):
		}
		break
	}
}

// TestE2EReconnectReconcilesRemoval: bob was offline when carol was
// removed. He reconnects and resumes; the members frame names the current
// membership, bob rotates for the difference, and the group keeps working.
func TestE2EReconnectReconcilesRemoval(t *testing.T) {
	s := newGroupStack(t)
	alice, bob, carol := s.trio(t)
	eachSends(t, s, []*Client{alice, bob, carol}, 1, "form")

	// Bob goes offline before the removal: the connection drops, the
	// client's keys and chains survive, as a device would.
	ctx := context.Background()
	bob.Disconnect()
	// Drain the disconnect's read error from Errs.
	for {
		select {
		case <-bob.Inbox:
			continue
		case e := <-bob.Errs:
			_ = e // drain: the disconnect's read error
			continue
		case <-time.After(100 * time.Millisecond):
		}
		break
	}

	if err := s.core.RemoveMember(ctx, s.room, mustUUID(t, e2eUserA), mustUUID(t, e2eUserC)); err != nil {
		t.Fatal(err)
	}
	// Alice rotates on the live event; carol is out.
	wantNothingInbox(t, alice, 300*time.Millisecond)

	// Bob returns: resume leads with the member list, which no longer
	// names carol, and bob rotates for the difference.
	if err := bob.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bob.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bob.Resume(ctx, s.room, 0); err != nil {
		t.Fatal(err)
	}
	// The resume replays the room's history; every pairwise envelope
	// re-verifies silently and the group ciphertexts re-verify via their
	// chains. No rejection may appear.
	wantNothingErrs(t, bob, 500*time.Millisecond)

	// The rotated group still works: each of alice and bob decrypts the
	// other's message (own echoes stay silent).
	if err := alice.SendGroup(ctx, s.room, []byte("rejoined-A")); err != nil {
		t.Fatal(err)
	}
	if err := bob.SendGroup(ctx, s.room, []byte("rejoined-B")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    *Client
		want string
	}{{bob, "rejoined-A"}, {alice, "rejoined-B"}} {
		r := waitRecv(t, tc.c)
		if r.Err != nil || string(r.Plaintext) != tc.want {
			t.Fatalf("after rejoined: %+v, want %q", r, tc.want)
		}
	}
	wantNothingInbox(t, alice, 300*time.Millisecond)
	wantNothingInbox(t, bob, 300*time.Millisecond)
}

// TestE2EConcurrentRemovals: two members removed back to back. The last
// member rotates for each event, serialized by the room lock, and stays
// consistent.
func TestE2EConcurrentRemovals(t *testing.T) {
	s := newGroupStack(t)
	alice, bob, carol := s.trio(t)
	eachSends(t, s, []*Client{alice, bob, carol}, 1, "form")

	ctx := context.Background()
	if err := s.core.RemoveMember(ctx, s.room, mustUUID(t, e2eUserA), mustUUID(t, e2eUserB)); err != nil {
		t.Fatal(err)
	}
	if err := s.core.RemoveMember(ctx, s.room, mustUUID(t, e2eUserA), mustUUID(t, e2eUserC)); err != nil {
		t.Fatal(err)
	}
	// Alice alone: her view is empty — both events arrived and were
	// applied — and nothing broke on the wire. The removals' late
	// publishes (a member whose own removal is still in flight racing its
	// last redistribution) legitimately fail with not_member, so the
	// removed members' Errs are drained, not asserted empty.
	for deadline := time.Now().Add(5 * time.Second); ; {
		view, _ := alice.roomPeersFor(s.room)
		if len(view) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("alice's view after both removals = %+v; want empty", view)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, c := range []*Client{bob, carol} {
		for {
			select {
			case e := <-c.Errs:
				_ = e // drain: a removed member's late publish may fail
				continue
			case <-time.After(100 * time.Millisecond):
			}
			break
		}
	}
	wantNothingErrs(t, alice, 500*time.Millisecond)
	wantNothingInbox(t, bob, 200*time.Millisecond)
	wantNothingInbox(t, carol, 200*time.Millisecond)
}
