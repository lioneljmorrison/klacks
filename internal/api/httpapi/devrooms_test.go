package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// fakeRoomAdmin validates kinds as core does and refuses a second add of
// the same member, as the store does.
type fakeRoomAdmin struct {
	created map[store.UUID]bool
	members map[store.UUID]map[store.UUID]bool
}

func newFakeRoomAdmin() *fakeRoomAdmin {
	return &fakeRoomAdmin{created: map[store.UUID]bool{}, members: map[store.UUID]map[store.UUID]bool{}}
}

func (f *fakeRoomAdmin) CreateRoomWithID(_ context.Context, room store.UUID, kind string, creator store.UUID) error {
	switch kind {
	case "dm", "group", "space":
	default:
		return fmt.Errorf("create room: kind %q: %w", kind, core.ErrInvalidArgument)
	}
	f.created[room] = true
	f.members[room] = map[store.UUID]bool{creator: true}
	return nil
}

func (f *fakeRoomAdmin) AddMember(_ context.Context, room, _, user store.UUID, _ string) error {
	if f.members[room][user] {
		return store.ErrAlreadyMember
	}
	f.members[room][user] = true
	return nil
}

func (f *fakeRoomAdmin) RemoveMember(context.Context, store.UUID, store.UUID, store.UUID) error {
	return nil
}

func (f *fakeRoomAdmin) Members(context.Context, store.UUID) ([]store.UUID, error) { return nil, nil }

const (
	devAlice = "00000000-0000-4000-8000-0000000000a1"
	devBob   = "00000000-0000-4000-8000-0000000000b1"
)

func postCreate(t *testing.T, admin RoomAdmin, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	NewDevRooms(auth.Dev{}, admin, nil).Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/dev/rooms", strings.NewReader(body))
	req.Header.Set(auth.HeaderUser, devAlice)
	req.Header.Set(auth.HeaderDevice, devAlice)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// An unknown kind is the caller's mistake, not the server's.
func TestDevRoomsCreateRejectsUnknownKind(t *testing.T) {
	rec := postCreate(t, newFakeRoomAdmin(), `{"kind":"channel"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
}

// A member listed twice is invited once: the room is created and the
// request succeeds rather than failing after the room exists.
func TestDevRoomsCreateInvitesRepeatedMemberOnce(t *testing.T) {
	admin := newFakeRoomAdmin()
	rec := postCreate(t, admin, `{"kind":"group","members":["`+devBob+`","`+devBob+`"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body)
	}
	if strings.Count(rec.Body.String(), devBob) != 1 {
		t.Fatalf("response lists bob other than once: %s", rec.Body)
	}
}
