package main

// The interactive shell: command dispatch, the prompt, and the commands
// that talk to the reference client (messaging) rather than to pkg/chat
// (room management, in rooms.go).

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lioneljmorrison/klacks/client"
)

// handle runs one command line and reports whether the shell continues.
func (a *app) handle(ctx context.Context, line string) bool {
	fields := strings.Fields(line)
	cmd, args := fields[0], fields[1:]
	switch cmd {
	case "/help":
		a.help()
	case "/quit":
		return false
	case "/status":
		a.status()
	case "/create":
		a.cmdCreate(ctx, args)
	case "/invite":
		a.cmdInvite(ctx, args)
	case "/remove":
		a.cmdRemove(ctx, args)
	case "/members":
		a.cmdMembers(ctx, args)
	case "/join":
		a.cmdJoin(ctx, args)
	case "/send":
		a.cmdSend(ctx, args)
	case "/drop":
		a.cmdDrop()
	case "/dial":
		a.cmdDial(ctx)
	case "/register":
		a.cmdRegister(ctx)
	case "/resume":
		a.cmdResume(ctx, args)
	case "/replenish":
		a.cmdReplenish(ctx, args)
	default:
		a.outf("unknown command %q — try /help", cmd)
	}
	return true
}

// help is the command list, one line each. Rooms and users accept names
// ("standup", "alice") or canonical UUIDs, everywhere.
func (a *app) help() {
	a.outf(`commands (rooms and users accept names or UUIDs):
  /help                          this list
  /status                        connection, known rooms, last seen seq, prekeys held
  /create <roomName>             create a group room by name and join it
  /create <roomName> dm <peer>   create a DM room by name, invite the peer, join
  /invite <room> <user> [owner|admin|member]   add a member (default member)
  /remove <room> <user>          remove a member
  /members <room>                refresh the member list from the server
  /join <room>                   subscribe to a room: resume from seq 0
  /send <room> <text...>         seal and publish text to every member device
  /resume <room> [lastSeenSeq]   replay after seq (default: where this device left off)
  /drop                          drop the connection (simulates an outage)
  /dial                          (re)connect the WebSocket
  /register                      upload this device's bundle (automatic at startup)
  /replenish <n>                 upload n fresh one-time prekeys
  /quit                          leave (Ctrl-D or Ctrl-C also work)`)
}

// status reports the session: connection, registration, every room the CLI
// knows with its member count and last seen seq, and the one-time prekey
// stock the server has not consumed yet.
func (a *app) status() {
	a.mu.Lock()
	connected := a.connected
	rows := make([]string, 0, len(a.rooms))
	for id, r := range a.rooms {
		rows = append(rows, fmt.Sprintf("room %s  known_members=%d  last_seen_seq=%d",
			uuidString(id), len(r.members), r.lastSeen))
	}
	a.mu.Unlock()
	sort.Strings(rows)

	a.outf("connected=%v  registered=%v  user=%s", connected, a.registered, uuidString(a.user))
	for _, line := range rows {
		a.outf("%s", line)
	}
	a.outf("one-time prekeys held: %d", a.c.OneTimePrekeysHeld())
}

// cmdSend resolves the room's peers — every member user's registered
// devices, self excluded — and seals pairwise for each device via the
// reference client's Send. Group rooms send the same way: one envelope per
// recipient device rather than the sender-key broadcast (see the package
// comment for why).
func (a *app) cmdSend(ctx context.Context, args []string) {
	if len(args) < 2 {
		a.outf("usage: /send <room> <text...>")
		return
	}
	room, err := resolveRoomArg(args[0])
	if err != nil {
		a.outf("send: %v", err)
		return
	}
	text := strings.Join(args[1:], " ")

	a.mu.Lock()
	connected := a.connected
	a.mu.Unlock()
	if !connected {
		a.outf("send: not connected — /dial first")
		return
	}
	// A room not subscribed on this connection delivers nothing back:
	// watch it live here. Subscribe, not resume: /send is for talking, and
	// /join or /resume replay history when it is wanted.
	if a.needsSubscribe(room) {
		if err := a.c.Subscribe(ctx, room); err != nil {
			a.outf("send: %v", err)
			return
		}
		a.markSubscribed(room)
		a.recordMember(room, a.user)
		a.outf("watching %s for new messages (new messages only — /resume replays history)", uuidString(room))
	}

	peers, err := a.resolvePeers(ctx, room)
	if err != nil {
		a.outf("send: %v", err)
		return
	}
	if err := a.c.Send(ctx, room, peers, []byte(text)); err != nil {
		a.outf("send: %v", err)
		return
	}
	a.outf("sent to %d device(s) in %s", len(peers), uuidString(room))
}

// resolvePeers turns the room's member users into every other member
// device. The authoritative list comes from the server's dev members
// endpoint, refreshed each send, so a joined room needs no local bookkeeping;
// when the endpoint fails the CLI falls back to the members it knows.
func (a *app) resolvePeers(ctx context.Context, room [16]byte) ([]client.Peer, error) {
	var resp membersResponse
	if err := a.rest(ctx, "GET", "/v1/dev/rooms/"+uuidString(room)+"/members", nil, &resp); err != nil {
		a.outf("send: member list refresh failed (%v); using locally known members", err)
	} else {
		users := make(map[[16]byte]bool, len(resp.Members))
		for _, s := range resp.Members {
			if u, err := parseUUID(s); err == nil {
				users[u] = true
			}
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
	}
	users := a.memberUsers(room)
	if len(users) == 0 {
		return nil, fmt.Errorf("no other members in %s — /invite someone, or /members to refresh", uuidString(room))
	}
	var peers []client.Peer
	for _, u := range users {
		devs, err := a.c.ListDevices(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("list devices of %s: %w", uuidString(u), err)
		}
		if len(devs) == 0 {
			a.outf("send: %s has no registered devices; skipping", uuidString(u))
			continue
		}
		for _, d := range devs {
			peers = append(peers, client.Peer{User: u, Device: d})
		}
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("every known member of %s has no registered devices", uuidString(room))
	}
	return peers, nil
}

// cmdDrop disconnects like an outage would: key material, sessions and the
// room bookkeeping stay. The read loop's error surfaces once as
// "server: read: …" — that is the drop itself, not a fault.
func (a *app) cmdDrop() {
	a.c.Disconnect()
	a.mu.Lock()
	a.connected = false
	a.mu.Unlock()
	a.outf("dropped — /dial to reconnect, /resume to replay anything missed")
}

// cmdDial (re)connects the WebSocket.
func (a *app) cmdDial(ctx context.Context) {
	if err := a.dial(ctx); err != nil {
		a.outf("dial: %v", err)
		return
	}
	a.outf("dialed %s", a.base)
}

// cmdRegister uploads this device's bundle, re-uploading the current
// one-time prekey pool. Startup registers only when the key state says the
// bundle is not on the server yet; this is the manual path after a failed
// startup register. A server wipe (make nuke) needs -fresh instead: see
// the registration comment in run.
func (a *app) cmdRegister(ctx context.Context) {
	if err := a.c.Register(ctx); err != nil {
		a.outf("register: %v", err)
		return
	}
	if err := a.saveRegistered(); err != nil {
		a.outf("registered, but saving the key state failed: %v", err)
		return
	}
	a.registered = true
	a.outf("registered device %s for user %s", uuidString(a.device), uuidString(a.user))
}

// cmdResume asks the server for everything in the room after lastSeen, then
// live delivery. With no seq argument the default is the device's resume
// point: the last seq it consumed, across restarts.
func (a *app) cmdResume(ctx context.Context, args []string) {
	if len(args) < 1 || len(args) > 2 {
		a.outf("usage: /resume <room> [lastSeenSeq]")
		return
	}
	room, err := resolveRoomArg(args[0])
	if err != nil {
		a.outf("resume: %v", err)
		return
	}
	var from int64
	if len(args) == 2 {
		if from, err = strconv.ParseInt(args[1], 10, 64); err != nil || from < 0 {
			a.outf("resume: lastSeenSeq must be a non-negative integer")
			return
		}
	} else {
		from = a.resumePoint(room)
	}
	if err := a.c.Resume(ctx, room, from); err != nil {
		a.outf("resume: %v", err)
		return
	}
	a.markSubscribed(room)
	a.outf("resumed %s from seq %d", uuidString(room), from)
}

// cmdReplenish uploads n fresh one-time prekeys for peers to consume and
// adds their private halves to the persisted key state, so a later run can
// still answer session initiations that consumed them.
func (a *app) cmdReplenish(ctx context.Context, args []string) {
	if len(args) != 1 {
		a.outf("usage: /replenish <n>")
		return
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 || n > 1000 {
		a.outf("replenish: n must be an integer in 1..1000")
		return
	}
	// Generate locally, persist the private halves, then upload the public
	// ones via the dev REST shape — the same work client.Replenish does,
	// split so the key file can follow along. Saving comes first: a crash
	// after the upload but before the save would leave public keys on the
	// server whose private halves never reached the disk, and initiations
	// that consume them could not be answered after a restart. The other
	// way round, a crash only leaves unused private halves behind.
	opks, err := a.c.NewOneTimePrekeys(n)
	if err != nil {
		a.outf("replenish: %v", err)
		return
	}
	// saveState writes the client's whole pool, the new keys included,
	// under the lock the pump's per-delivery saves take.
	if err := a.saveState(); err != nil {
		a.outf("replenish: keys generated but saving failed, nothing uploaded: %v", err)
		return
	}
	wire := make([]map[string]any, len(opks))
	for i, p := range opks {
		wire[i] = map[string]any{"id": p.ID, "key": base64.StdEncoding.EncodeToString(p.Pub[:])}
	}
	if err := a.rest(ctx, "POST", "/v1/device/prekeys", map[string]any{"one_time_prekeys": wire}, nil); err != nil {
		a.outf("replenish: %v", err)
		return
	}
	a.outf("uploaded %d one-time prekeys (%d held)", n, a.c.OneTimePrekeysHeld())
}

// outf prints one line; every output funnels here so the pump goroutine and
// the shell never interleave mid-line.
func (a *app) outf(format string, args ...any) {
	a.outMu.Lock()
	fmt.Fprintf(a.out, format+"\n", args...)
	a.outMu.Unlock()
}

// prompt prints the prompt line. The pump re-prints it after an incoming
// message, so the shell stays usable while deliveries stream in.
func (a *app) prompt() {
	a.outMu.Lock()
	fmt.Fprintf(a.out, "%s>> ", a.name)
	a.outMu.Unlock()
}
