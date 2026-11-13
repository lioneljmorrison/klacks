package main

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/lioneljmorrison/klacks/pkg/chat"
)

// fakeChat records what the scheduler asks the chat service to do, so the
// scheduler's tests run without stores.
type fakeChat struct {
	specs  []chat.RoomSpec
	adds   []fakeAdd
	posts  []fakePost
	roomID chat.RoomID
	seq    chat.Seq
}

type fakeAdd struct {
	room chat.RoomID
	user chat.UserID
	role chat.Role
}

type fakePost struct {
	room    chat.RoomID
	sender  chat.UserID
	payload chat.EncryptedPayload
}

var _ chat.ChatService = (*fakeChat)(nil)

func (f *fakeChat) CreateRoom(ctx context.Context, spec chat.RoomSpec) (chat.RoomID, error) {
	f.specs = append(f.specs, spec)
	return f.roomID, nil
}

func (f *fakeChat) AddMember(ctx context.Context, room chat.RoomID, user chat.UserID, role chat.Role) error {
	f.adds = append(f.adds, fakeAdd{room, user, role})
	return nil
}

func (f *fakeChat) PostMessage(ctx context.Context, room chat.RoomID, sender chat.UserID, payload chat.EncryptedPayload) (chat.Seq, error) {
	f.seq++
	f.posts = append(f.posts, fakePost{room, sender, payload})
	return f.seq, nil
}

func (f *fakeChat) Subscribe(ctx context.Context, room chat.RoomID, fromSeq chat.Seq) (<-chan chat.Message, error) {
	return nil, errors.New("not expected")
}

func (f *fakeChat) RemoveMember(ctx context.Context, room chat.RoomID, user chat.UserID) error {
	return errors.New("not expected")
}

// uid builds a distinct user ID per test.
func uid(b byte) chat.UserID { return chat.UserID{15: b} }

func roomID(b byte) chat.RoomID { r := chat.RoomID{}; r[0] = b; return r }

func TestCreateMeeting(t *testing.T) {
	actor, organizer, alice, bob := uid(1), uid(2), uid(3), uid(4)
	room := roomID(0xaa)
	f := &fakeChat{roomID: room}
	s := NewScheduler(f, actor)

	m, seq, err := s.CreateMeeting(context.Background(), "Sprint planning", organizer, alice, bob)
	if err != nil {
		t.Fatal(err)
	}

	if len(f.specs) != 1 || f.specs[0].Kind != chat.KindSpace {
		t.Errorf("CreateRoom = %+v, want one room of kind space", f.specs)
	}
	if m.ID != room {
		t.Errorf("meeting ID = %v, want %v", m.ID, room)
	}

	// The organizer and every attendee join as members; the actor already
	// owns the room, so it is not added.
	wantAdds := []fakeAdd{
		{room, organizer, chat.RoleMember},
		{room, alice, chat.RoleMember},
		{room, bob, chat.RoleMember},
	}
	if !slices.Equal(f.adds, wantAdds) {
		t.Errorf("AddMember = %+v, want %+v", f.adds, wantAdds)
	}

	// The invite is posted from the organizer: header names the schema,
	// ciphertext carries the title.
	if len(f.posts) != 1 {
		t.Fatalf("PostMessage = %+v, want one invite", f.posts)
	}
	p := f.posts[0]
	if p.room != room || p.sender != organizer {
		t.Errorf("invite room/sender = %v/%v, want %v/%v", p.room, p.sender, room, organizer)
	}
	if string(p.payload.Header) != inviteHeader {
		t.Errorf("invite header = %q, want %q", p.payload.Header, inviteHeader)
	}
	if string(p.payload.Ciphertext) != "Sprint planning" {
		t.Errorf("invite ciphertext = %q, want the title", p.payload.Ciphertext)
	}
	if p.payload.MessageID == ([16]byte{}) || p.payload.DeviceID == ([16]byte{}) {
		t.Errorf("invite message/device ID not set: %+v", p.payload)
	}
	if seq != 1 {
		t.Errorf("invite seq = %d, want 1", seq)
	}

	if m.Title != "Sprint planning" || m.Organizer != organizer ||
		!slices.Equal(m.Attendees, []chat.UserID{organizer, alice, bob}) {
		t.Errorf("meeting = %+v, want title/organizer/attendees as scheduled", m)
	}
}

func TestCreateMeetingSkipsDuplicates(t *testing.T) {
	actor, organizer, alice := uid(1), uid(2), uid(3)
	room := roomID(0xbb)
	f := &fakeChat{roomID: room}
	s := NewScheduler(f, actor)

	// The organizer listed again, the actor posing as an attendee, and a
	// repeated attendee are all collapsed.
	m, _, err := s.CreateMeeting(context.Background(), "Sync", organizer, organizer, actor, alice, alice)
	if err != nil {
		t.Fatal(err)
	}

	wantAdds := []fakeAdd{
		{room, organizer, chat.RoleMember},
		{room, alice, chat.RoleMember},
	}
	if !slices.Equal(f.adds, wantAdds) {
		t.Errorf("AddMember = %+v, want %+v", f.adds, wantAdds)
	}
	want := []chat.UserID{organizer, alice}
	if !slices.Equal(m.Attendees, want) {
		t.Errorf("attendees = %+v, want %+v", m.Attendees, want)
	}
}

func TestCreateMeetingActorOrganizes(t *testing.T) {
	actor, alice := uid(1), uid(2)
	room := roomID(0xcc)
	f := &fakeChat{roomID: room}
	s := NewScheduler(f, actor)

	m, _, err := s.CreateMeeting(context.Background(), "Sync", actor, alice)
	if err != nil {
		t.Fatal(err)
	}

	wantAdds := []fakeAdd{{room, alice, chat.RoleMember}}
	if !slices.Equal(f.adds, wantAdds) {
		t.Errorf("AddMember = %+v, want %+v (the actor owns the room)", f.adds, wantAdds)
	}
	if f.posts[0].sender != actor {
		t.Errorf("invite sender = %v, want the actor as organizer", f.posts[0].sender)
	}
	if !slices.Equal(m.Attendees, []chat.UserID{actor, alice}) {
		t.Errorf("attendees = %+v, want actor first", m.Attendees)
	}
}

func TestAddAttendee(t *testing.T) {
	actor, organizer, alice, late := uid(1), uid(2), uid(3), uid(9)
	room := roomID(0xdd)
	f := &fakeChat{roomID: room, seq: 1} // the invite is already seq 1
	s := NewScheduler(f, actor)
	m := Meeting{ID: room, Title: "Sync", Organizer: organizer, Attendees: []chat.UserID{organizer, alice}}
	m, seq, err := s.AddAttendee(context.Background(), m, late)
	if err != nil {
		t.Fatal(err)
	}

	wantAdds := []fakeAdd{{room, late, chat.RoleMember}}
	if !slices.Equal(f.adds, wantAdds) {
		t.Errorf("AddMember = %+v, want %+v", f.adds, wantAdds)
	}
	if len(f.posts) != 1 {
		t.Fatalf("PostMessage = %+v, want one join update", f.posts)
	}
	p := f.posts[0]
	if p.room != room || p.sender != late {
		t.Errorf("update room/sender = %v/%v, want %v/%v", p.room, p.sender, room, late)
	}
	if string(p.payload.Header) != attendeeHeader {
		t.Errorf("update header = %q, want %q", p.payload.Header, attendeeHeader)
	}
	if string(p.payload.Ciphertext) != "joined" {
		t.Errorf("update ciphertext = %q, want %q", p.payload.Ciphertext, "joined")
	}
	if seq != 2 {
		t.Errorf("update seq = %d, want 2", seq)
	}
	if !slices.Equal(m.Attendees, []chat.UserID{organizer, alice, late}) {
		t.Errorf("attendees = %+v, want the late attendee appended", m.Attendees)
	}
}
