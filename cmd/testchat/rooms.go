package main

// Room bookkeeping and the dev-API room-management commands. The CLI talks
// to the server's dev-only REST endpoints (/v1/dev/rooms), so rooms it
// creates and members it invites are visible to the server and to every
// other client — the same path the browser test client uses.

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"github.com/lioneljmorrison/klacks/internal/names"
)

// roomInfo is the CLI's record of one room: the member users it has seen or
// created, and the furthest delivery seq this session has seen. A room
// joined by name or UUID starts with a stub; /members refreshes the member
// view from the server.
type roomInfo struct {
	members  map[[16]byte]bool
	lastSeen int64
}

// cmdCreate dispatches /create: a room by name, group by default, or a DM.
//
//	/create <roomName>              group room owned by this user
//	/create <roomName> dm <peer>    DM room owned by this user, peer invited
func (a *app) cmdCreate(ctx context.Context, args []string) {
	if len(args) == 0 || len(args) > 3 {
		a.outf("usage: /create <roomName> | /create <roomName> dm <peerUser>")
		return
	}
	roomStr := names.Room(args[0])
	room, err := parseUUID(roomStr)
	if err != nil {
		a.outf("create: %v", err)
		return
	}
	kind := "group"
	var members []string
	if len(args) > 1 {
		if args[1] != "dm" {
			a.outf("usage: /create <roomName> | /create <roomName> dm <peerUser>")
			return
		}
		if len(args) != 3 {
			a.outf("usage: /create <roomName> dm <peerUser>")
			return
		}
		kind = "dm"
		members = []string{names.User(args[2])}
	}
	var resp createResponse
	if err := a.rest(ctx, "POST", "/v1/dev/rooms", &createRequest{
		RoomID:  roomStr,
		Kind:    kind,
		Members: members,
	}, &resp); err != nil {
		a.outf("create %s: %v", args[0], err)
		return
	}
	summary := "just you"
	if others := otherMembers(resp.Members, uuidString(a.user)); len(others) > 0 {
		summary = "you + " + strings.Join(others, ", ")
	}
	a.outf("%s room %s (%s): %s", resp.Kind, resp.RoomID, args[0], summary)
	a.join(ctx, room) // auto-join: resume from 0
}

// otherMembers is members without self: the server's create response lists
// the creator too.
func otherMembers(members []string, self string) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		if m != self {
			out = append(out, m)
		}
	}
	return out
}

// createRequest / createResponse are the dev room endpoint's JSON shapes.
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

// cmdInvite adds a member through the dev API and records them as a known
// peer, which is what /send resolves.
func (a *app) cmdInvite(ctx context.Context, args []string) {
	if len(args) < 2 || len(args) > 3 {
		a.outf("usage: /invite <room> <user> [owner|admin|member]")
		return
	}
	room, err := resolveRoomArg(args[0])
	if err != nil {
		a.outf("invite: %v", err)
		return
	}
	userStr := names.User(args[1])
	user, err := parseUUID(userStr)
	if err != nil {
		a.outf("invite: %v", err)
		return
	}
	role := "member"
	if len(args) == 3 {
		role = args[2]
		switch role {
		case "owner", "admin", "member":
		default:
			a.outf("invite: role must be owner, admin or member")
			return
		}
	}
	body := map[string]string{"user": userStr, "role": role}
	if err := a.rest(ctx, "POST", "/v1/dev/rooms/"+uuidString(room)+"/members", body, nil); err != nil {
		a.outf("invite: %v", err)
		return
	}
	a.recordMember(room, user)
	a.outf("invited %s (%s) to %s as %s", args[1], userStr, uuidString(room), role)
}

// cmdRemove removes a member through the dev API and drops them from the
// CLI's known set, so later sends stop sealing for their devices.
func (a *app) cmdRemove(ctx context.Context, args []string) {
	if len(args) != 2 {
		a.outf("usage: /remove <room> <user>")
		return
	}
	room, err := resolveRoomArg(args[0])
	if err != nil {
		a.outf("remove: %v", err)
		return
	}
	userStr := names.User(args[1])
	user, err := parseUUID(userStr)
	if err != nil {
		a.outf("remove: %v", err)
		return
	}
	if err := a.rest(ctx, "DELETE", "/v1/dev/rooms/"+uuidString(room)+"/members/"+userStr, nil, nil); err != nil {
		a.outf("remove: %v", err)
		return
	}
	a.forgetMember(room, user)
	a.outf("removed %s (%s) from %s", args[1], userStr, uuidString(room))
}

// cmdMembers refreshes the CLI's member view of a room from the server.
func (a *app) cmdMembers(ctx context.Context, args []string) {
	if len(args) != 1 {
		a.outf("usage: /members <room>")
		return
	}
	room, err := resolveRoomArg(args[0])
	if err != nil {
		a.outf("members: %v", err)
		return
	}
	var resp membersResponse
	if err := a.rest(ctx, "GET", "/v1/dev/rooms/"+uuidString(room)+"/members", nil, &resp); err != nil {
		a.outf("members: %v", err)
		return
	}
	users := make(map[[16]byte]bool)
	for _, s := range resp.Members {
		u, err := parseUUID(s)
		if err != nil {
			continue
		}
		users[u] = true
	}
	a.mu.Lock()
	r := a.rooms[room]
	if r == nil {
		r = &roomInfo{members: users}
		a.rooms[room] = r
	} else {
		r.members = users
	}
	a.mu.Unlock()
	a.outf("members of %s: %s", uuidString(room), resp.Members)
}

// cmdJoin subscribes to a room by name or UUID: resume from 0 replays its
// history and subscribes live delivery.
func (a *app) cmdJoin(ctx context.Context, args []string) {
	if len(args) != 1 {
		a.outf("usage: /join <roomNameOrUUID>")
		return
	}
	room, err := resolveRoomArg(args[0])
	if err != nil {
		a.outf("join: %v", err)
		return
	}
	a.join(ctx, room)
}

// join resumes the room from 0 and makes sure it is tracked.
func (a *app) join(ctx context.Context, room [16]byte) {
	a.recordMember(room, a.user)
	if err := a.c.Resume(ctx, room, 0); err != nil {
		a.outf("join %s: resume failed: %v", uuidString(room), err)
		return
	}
	a.markSubscribed(room)
	a.outf("joined %s (resumed from 0)", uuidString(room))
}

// resolveRoomArg resolves a room argument: canonical UUID or name.
func resolveRoomArg(s string) ([16]byte, error) {
	return parseUUID(names.Room(s))
}

type membersResponse struct {
	RoomID  string   `json:"room_id"`
	Members []string `json:"members"`
}

// recordMember adds one member to a room's known set, creating a stub
// record when the room is not tracked yet.
func (a *app) recordMember(room, user [16]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.rooms[room]
	if !ok {
		r = &roomInfo{members: make(map[[16]byte]bool)}
		a.rooms[room] = r
	}
	r.members[user] = true
}

// forgetMember drops one member from a room's known set.
func (a *app) forgetMember(room, user [16]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r, ok := a.rooms[room]; ok {
		delete(r.members, user)
	}
}

// noteSeq advances the room's furthest seen seq, creating a stub record for
// a room the CLI never tracked: live delivery can arrive for any room this
// device's user is a member of.
func (a *app) noteSeq(room [16]byte, seq int64) {
	if seq <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.rooms[room]
	if !ok {
		r = &roomInfo{members: make(map[[16]byte]bool)}
		a.rooms[room] = r
	}
	if seq > r.lastSeen {
		r.lastSeen = seq
	}
}

// memberUsers returns the room's known member users, self excluded, in a
// stable order: the peers a send must seal for.
func (a *app) memberUsers(room [16]byte) [][16]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.rooms[room]
	if !ok {
		return nil
	}
	users := make([][16]byte, 0, len(r.members))
	for u := range r.members {
		if u != a.user {
			users = append(users, u)
		}
	}
	sort.Slice(users, func(i, j int) bool {
		return bytes.Compare(users[i][:], users[j][:]) < 0
	})
	return users
}
