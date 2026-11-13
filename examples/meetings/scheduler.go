package main

import (
	"context"
	"fmt"
	"slices"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// Message headers the toy scheduler uses. The server treats header and
// ciphertext as opaque; a real embedder defines its own schema and encrypts
// the body client-side. The toy sends plaintext so the run is legible.
const (
	inviteHeader   = "invite/v1"
	attendeeHeader = "attendee/v1"
)

// Meeting is a scheduled meeting: its chat room and who is in it.
type Meeting struct {
	ID        chat.RoomID
	Title     string
	Organizer chat.UserID
	Attendees []chat.UserID // organizer first, then attendees in add order
}

// Scheduler schedules meetings as chat rooms: creating a meeting creates
// its room, its attendees join as members, and its messages are posted into
// the room.
type Scheduler struct {
	svc   chat.ChatService
	actor chat.UserID
}

// NewScheduler builds a scheduler over svc. actor is the embedder's service
// identity: the owner of every room it creates.
func NewScheduler(svc chat.ChatService, actor chat.UserID) *Scheduler {
	return &Scheduler{svc: svc, actor: actor}
}

// CreateMeeting creates the meeting's room — a space, the kind the plan
// reserves for rooms an embedding ecosystem makes — adds the organizer and
// every attendee as members, and posts the invite from the organizer. It
// returns the meeting and the invite's seq.
func (s *Scheduler) CreateMeeting(ctx context.Context, title string, organizer chat.UserID, attendees ...chat.UserID) (Meeting, chat.Seq, error) {
	room, err := s.svc.CreateRoom(ctx, chat.RoomSpec{Kind: chat.KindSpace})
	if err != nil {
		return Meeting{}, 0, fmt.Errorf("create meeting room: %w", err)
	}

	// The actor owns the room, so it is never added; the organizer leads
	// the attendee list and everyone appears once.
	m := Meeting{ID: room, Title: title, Organizer: organizer, Attendees: []chat.UserID{organizer}}
	if organizer != s.actor {
		if err := s.svc.AddMember(ctx, room, organizer, chat.RoleMember); err != nil {
			return Meeting{}, 0, fmt.Errorf("add organizer: %w", err)
		}
	}
	for _, a := range attendees {
		if a == s.actor || a == organizer || slices.Contains(m.Attendees, a) {
			continue
		}
		if err := s.svc.AddMember(ctx, room, a, chat.RoleMember); err != nil {
			return Meeting{}, 0, fmt.Errorf("add attendee: %w", err)
		}
		m.Attendees = append(m.Attendees, a)
	}

	seq, err := s.post(ctx, room, organizer, inviteHeader, title)
	if err != nil {
		return Meeting{}, 0, err
	}
	return m, seq, nil
}

// AddAttendee adds attendee to the meeting's room and posts the join update
// from the new attendee. It returns the meeting with attendee appended.
func (s *Scheduler) AddAttendee(ctx context.Context, m Meeting, attendee chat.UserID) (Meeting, chat.Seq, error) {
	if err := s.svc.AddMember(ctx, m.ID, attendee, chat.RoleMember); err != nil {
		return Meeting{}, 0, fmt.Errorf("add attendee: %w", err)
	}
	seq, err := s.post(ctx, m.ID, attendee, attendeeHeader, "joined")
	if err != nil {
		return Meeting{}, 0, err
	}
	m.Attendees = append(m.Attendees, attendee)
	return m, seq, nil
}

// post sends body with header from sender, who must already be a member.
// The toy posts plaintext; a real embedder encrypts.
func (s *Scheduler) post(ctx context.Context, room chat.RoomID, sender chat.UserID, header, body string) (chat.Seq, error) {
	messageID, err := randomUUID()
	if err != nil {
		return 0, fmt.Errorf("post %s: %w", header, err)
	}
	deviceID, err := randomUUID()
	if err != nil {
		return 0, fmt.Errorf("post %s: %w", header, err)
	}
	seq, err := s.svc.PostMessage(ctx, room, sender, chat.EncryptedPayload{
		MessageID:  messageID,
		DeviceID:   deviceID,
		Ciphertext: []byte(body),
		Header:     []byte(header),
	})
	if err != nil {
		return 0, fmt.Errorf("post %s: %w", header, err)
	}
	return seq, nil
}

// randomUUID makes a caller-generated ID: message IDs are client-generated,
// and users, rooms and devices are nothing but 16-byte UUIDs — nothing
// registers them.
func randomUUID() ([16]byte, error) {
	u, err := gocql.RandomUUID()
	return [16]byte(u), err
}

// uuid formats a 16-byte ID as its canonical UUID string.
func uuid(v [16]byte) string { return gocql.UUID(v).String() }
