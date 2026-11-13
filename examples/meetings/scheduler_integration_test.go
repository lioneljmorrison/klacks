//go:build integration

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// This is the Phase 3 end-to-end check: the toy scheduler drives a real
// ChatService on a migrated stack — room created with the meeting,
// attendees added, invite and updates posted, and everything arriving
// through Subscribe, replayed and live.

// openChat opens a ChatService on a fresh migrated stack.
func openChat(t *testing.T) (*chat.Service, chat.UserID) {
	t.Helper()
	cfg := chat.Config{
		PostgresDSN:     dbtest.MigratedPostgresDSN(t),
		ScyllaTimeout:   10 * time.Second,
		RoomLockTimeout: 20 * time.Second,
		Actor:           chat.UserID{15: 0xa1},
		Log:             slog.New(slog.NewTextHandler(testlog{t}, nil)),
	}
	sc := dbtest.MigratedScyllaConfig(t)
	cfg.ScyllaHosts = sc.Hosts
	cfg.ScyllaKeyspace = sc.Keyspace
	cfg.ScyllaUsername = sc.Username
	cfg.ScyllaPassword = sc.Password
	svc, err := chat.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc, cfg.Actor
}

// testlog writes slog output through t, so a failed test shows the log.
type testlog struct{ t *testing.T }

func (l testlog) Write(p []byte) (int, error) {
	l.t.Log(string(p))
	return len(p), nil
}

// mustUUID builds one random ID for the test.
func mustUUID(t *testing.T) [16]byte {
	t.Helper()
	u, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// collect receives exactly n messages from ch; the channel closing early or
// a timeout fails the test.
func collect(t *testing.T, ch <-chan chat.Message, n int) []chat.Message {
	t.Helper()
	got := make([]chat.Message, 0, n)
	for len(got) < n {
		select {
		case m, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed after %d of %d messages", len(got), n)
			}
			got = append(got, m)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out after %d of %d messages", len(got), n)
		}
	}
	return got
}

func TestSchedulerEndToEnd(t *testing.T) {
	svc, actor := openChat(t)
	s := NewScheduler(svc, actor)
	ctx := context.Background()

	organizer, alice, bob, late :=
		chat.UserID(mustUUID(t)), chat.UserID(mustUUID(t)),
		chat.UserID(mustUUID(t)), chat.UserID(mustUUID(t))

	// Scheduling the meeting creates its room, adds its attendees and
	// posts its invite.
	m, inviteSeq, err := s.CreateMeeting(ctx, "Sprint planning", organizer, alice, bob)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribing replays what the room has, then delivers live.
	ch, err := svc.Subscribe(ctx, m.ID, 0)
	if err != nil {
		t.Fatal(err)
	}

	invite := collect(t, ch, 1)[0]
	if invite.Seq != inviteSeq || invite.SenderID != organizer ||
		string(invite.Header) != inviteHeader || string(invite.Ciphertext) != "Sprint planning" {
		t.Errorf("invite = %+v, want seq %d from the organizer with the title", invite, inviteSeq)
	}

	// A late attendee joins; the update arrives live.
	m, joinSeq, err := s.AddAttendee(ctx, m, late)
	if err != nil {
		t.Fatal(err)
	}
	if m.Attendees[len(m.Attendees)-1] != late {
		t.Errorf("attendees = %+v, want the late attendee appended", m.Attendees)
	}
	join := collect(t, ch, 1)[0]
	if join.Seq != joinSeq || join.SenderID != late ||
		string(join.Header) != attendeeHeader || string(join.Ciphertext) != "joined" {
		t.Errorf("join update = %+v, want seq %d from the late attendee", join, joinSeq)
	}

	// A member posts directly — the other half of the embed pattern.
	seq, err := svc.PostMessage(ctx, m.ID, alice, chat.EncryptedPayload{
		MessageID:  mustUUID(t),
		DeviceID:   mustUUID(t),
		Ciphertext: []byte("see you there"),
		Header:     []byte("note/v1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	note := collect(t, ch, 1)[0]
	if note.Seq != seq || note.SenderID != alice || string(note.Ciphertext) != "see you there" {
		t.Errorf("note = %+v, want seq %d from alice", note, seq)
	}

	// Seqs are gap-free per room and start at 1: invite, join, note.
	if inviteSeq != 1 || joinSeq != 2 || seq != 3 {
		t.Errorf("seqs = %d, %d, %d, want 1, 2, 3", inviteSeq, joinSeq, seq)
	}
}
