// Dev-only room management over REST (POST /v1/dev/rooms and friends), so
// the browser test client can create and populate rooms without the CLI.
// Like the dev UI, it exists only for testing against the dev
// authenticator: cmdServe registers it only when env is dev, and nothing in
// it is part of the server's client surface. Real room management belongs
// to the embedder API (pkg/chat); this is the thin remote shim over it.
//
// Room IDs may be supplied by the caller — the UUID a human-readable name
// resolved to (internal/names) — or omitted, in which case the room gets a
// generated one.

package httpapi

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// maxDevRoomBody caps a dev room request body: a member list of UUIDs.
const maxDevRoomBody = 64 << 10

// RoomAdmin is the room-management API the dev rooms handlers serve.
// *core.Service satisfies it through the adapter in cmdServe.
type RoomAdmin interface {
	CreateRoomWithID(ctx context.Context, room store.UUID, kind string, creator store.UUID) error
	AddMember(ctx context.Context, room, actor, user store.UUID, role string) error
	RemoveMember(ctx context.Context, room, actor, user store.UUID) error
	Members(ctx context.Context, room store.UUID) ([]store.UUID, error)
}

// DevRooms serves the dev room endpoints. A nil authenticator or admin is
// not allowed: build it only when there is one.
type DevRooms struct {
	auth  auth.Authenticator
	admin RoomAdmin
	log   *slog.Logger
}

// NewDevRooms returns the dev room handlers. Nil log discards.
func NewDevRooms(a auth.Authenticator, admin RoomAdmin, log *slog.Logger) *DevRooms {
	if log == nil {
		log = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &DevRooms{auth: a, admin: admin, log: log}
}

// Register adds the endpoints to mux.
func (d *DevRooms) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/dev/rooms", d.create)
	mux.HandleFunc("POST /v1/dev/rooms/{room}/members", d.invite)
	mux.HandleFunc("DELETE /v1/dev/rooms/{room}/members/{user}", d.remove)
	mux.HandleFunc("GET /v1/dev/rooms/{room}/members", d.members)
}

// createRequest is one room creation: an optional caller-chosen room ID,
// the kind, and the users to invite after the creator (who owns the room).
type createRequest struct {
	RoomID  string   `json:"room_id,omitempty"`
	Kind    string   `json:"kind"`
	Members []string `json:"members,omitempty"`
}

type createResponse struct {
	RoomID  string   `json:"room_id"`
	Kind    string   `json:"kind"`
	Members []string `json:"members"`
}

// create creates the room, owned by the authenticated user, and invites the
// listed users as members.
func (d *DevRooms) create(w http.ResponseWriter, r *http.Request) {
	id, ok := d.identity(w, r)
	if !ok {
		return
	}
	var req createRequest
	if !d.decode(w, r, &req) {
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "group"
	}
	var room store.UUID
	if req.RoomID != "" {
		var err error
		if room, err = store.ParseUUID(req.RoomID); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "room_id is not a UUID"})
			return
		}
		if room == (store.UUID{}) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "room_id must not be the zero UUID"})
			return
		}
	}
	users, ok := d.users(w, req.Members)
	if !ok {
		return
	}
	var generated bool
	if room == (store.UUID{}) {
		generated = true
		room = randomRoomUUID()
	}
	err := d.admin.CreateRoomWithID(r.Context(), room, kind, id.UserID)
	if err != nil {
		// A caller-chosen ID that already exists is a name collision: say
		// so, rather than "internal error".
		if !generated && isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, errorResponse{Code: "already_exists", Message: "a room with this id already exists"})
			return
		}
		d.log.Error("dev rooms: create failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Code: "internal", Message: "internal error"})
		return
	}
	for _, u := range users {
		if u == id.UserID {
			continue // the creator is already the owner
		}
		if err := d.admin.AddMember(r.Context(), room, id.UserID, u, "member"); err != nil {
			d.log.Error("dev rooms: invite failed", "room", store.FormatUUID(room), "err", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Code: "internal", Message: "internal error"})
			return
		}
	}
	out := []string{store.FormatUUID(id.UserID)}
	out = append(out, uuidStrings(users, id.UserID)...)
	writeJSON(w, http.StatusOK, createResponse{RoomID: store.FormatUUID(room), Kind: kind, Members: out})
}

// inviteRequest is one member addition.
type inviteRequest struct {
	User string `json:"user"`
	Role string `json:"role,omitempty"`
}

// invite adds one user to the room, if the authenticated user may.
func (d *DevRooms) invite(w http.ResponseWriter, r *http.Request) {
	id, ok := d.identity(w, r)
	if !ok {
		return
	}
	room, ok := d.room(w, r)
	if !ok {
		return
	}
	var req inviteRequest
	if !d.decode(w, r, &req) {
		return
	}
	user, err := store.ParseUUID(req.User)
	if err != nil || user == (store.UUID{}) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "user is not a UUID"})
		return
	}
	role := req.Role
	if role == "" {
		role = "member"
	}
	if err := d.admin.AddMember(r.Context(), room, id.UserID, user, role); err != nil {
		d.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"room_id": store.FormatUUID(room), "user": store.FormatUUID(user), "role": role})
}

// remove takes one user out of the room, if the authenticated user may.
func (d *DevRooms) remove(w http.ResponseWriter, r *http.Request) {
	id, ok := d.identity(w, r)
	if !ok {
		return
	}
	room, ok := d.room(w, r)
	if !ok {
		return
	}
	user, err := store.ParseUUID(r.PathValue("user"))
	if err != nil || user == (store.UUID{}) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "user is not a UUID"})
		return
	}
	if err := d.admin.RemoveMember(r.Context(), room, id.UserID, user); err != nil {
		d.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"room_id": store.FormatUUID(room), "removed": store.FormatUUID(user)})
}

// members returns the room's current member list.
func (d *DevRooms) members(w http.ResponseWriter, r *http.Request) {
	if _, ok := d.identity(w, r); !ok {
		return
	}
	room, ok := d.room(w, r)
	if !ok {
		return
	}
	users, err := d.admin.Members(r.Context(), room)
	if err != nil {
		d.writeError(w, err)
		return
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, store.FormatUUID(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"room_id": store.FormatUUID(room), "members": out})
}

// identity authenticates the request and writes the error when it fails.
func (d *DevRooms) identity(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	id, err := d.auth.Authenticate(r)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Code: "unauthenticated", Message: "identity headers required"})
			return auth.Identity{}, false
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Code: "internal", Message: "internal error"})
		return auth.Identity{}, false
	}
	return id, true
}

// room parses the {room} path value.
func (d *DevRooms) room(w http.ResponseWriter, r *http.Request) (store.UUID, bool) {
	room, err := store.ParseUUID(r.PathValue("room"))
	if err != nil || room == (store.UUID{}) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "room is not a UUID"})
		return store.UUID{}, false
	}
	return room, true
}

// users parses a member list, rejecting empty and non-UUID entries.
func (d *DevRooms) users(w http.ResponseWriter, in []string) ([]store.UUID, bool) {
	out := make([]store.UUID, 0, len(in))
	for _, s := range in {
		u, err := store.ParseUUID(s)
		if err != nil || u == (store.UUID{}) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "member is not a UUID: " + s})
			return nil, false
		}
		out = append(out, u)
	}
	return out, true
}

// uuidStrings renders a member list, skipping one user.
func uuidStrings(users []store.UUID, skip store.UUID) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		if u == skip {
			continue
		}
		out = append(out, store.FormatUUID(u))
	}
	return out
}

// decode reads and unmarshals a bounded JSON body.
func (d *DevRooms) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxDevRoomBody)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "invalid body"})
		return false
	}
	if err := json.Unmarshal(data, v); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "invalid JSON body"})
		return false
	}
	return true
}

// writeError maps a room-management error to its REST status. Unexpected
// errors are logged, not sent.
func (d *DevRooms) writeError(w http.ResponseWriter, err error) {
	switch {
	case isUniqueViolation(err):
		writeJSON(w, http.StatusConflict, errorResponse{Code: "already_exists", Message: "already exists"})
	case errors.Is(err, store.ErrRoomNotFound), errors.Is(err, core.ErrRoomNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{Code: "room_not_found", Message: "room not found"})
	case errors.Is(err, store.ErrMemberNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{Code: "member_not_found", Message: "member not found"})
	case errors.Is(err, store.ErrAlreadyMember):
		writeJSON(w, http.StatusConflict, errorResponse{Code: "already_exists", Message: "already a member"})
	case errors.Is(err, core.ErrNotMember):
		writeJSON(w, http.StatusForbidden, errorResponse{Code: "not_member", Message: "not a member of the room"})
	case errors.Is(err, core.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errorResponse{Code: "forbidden", Message: "the role does not allow this"})
	case errors.Is(err, core.ErrInvalidArgument):
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "invalid argument"})
	default:
		d.log.Error("dev rooms: request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Code: "internal", Message: "internal error"})
	}
}

// randomRoomUUID generates a random v4-shaped UUID for a generated room.
func randomRoomUUID() store.UUID {
	var u [16]byte
	if _, err := crand.Read(u[:]); err != nil {
		panic("dev rooms: randomness unavailable: " + err.Error())
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

// isUniqueViolation reports whether err is Postgres's duplicate-key error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
