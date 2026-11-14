package client

// Saving and restoring a device's pairwise sessions, so a restarted device
// keeps decrypting what peers seal over the sessions it already held, and
// keeps sending on them instead of starting new ones.
//
// What is saved: every active session and every receive-only fallback,
// with the full ratchet state — chain keys, counters, the skipped message
// keys still owed, and the decrypt cache that answers redeliveries.
// What is not: per-room ordering state (a restarted device re-anchors on
// its first delivery, as a fresh one does), messages stashed pending their
// session's first message (resume redelivers them), and sender-key state.
//
// The snapshot holds secret key material. Callers store it as they store
// the identity key.
//
// Saving must happen before a sealed message is transmitted, not after:
// a send chain step on the wire but not on disk would come back after a
// restart and seal the next message under the same key and nonce. Send
// therefore calls the BeforePublish hook after sealing each envelope and
// before publishing it.

import (
	"encoding/json"
	"errors"
	"fmt"
)

// sessionsVersion versions the snapshot format.
const sessionsVersion = 1

type sessionsSnapshot struct {
	V         int               `json:"v"`
	Sessions  []sessionSnapshot `json:"sessions"`
	Fallbacks []sessionSnapshot `json:"fallbacks"` // in fallbackOrder
}

type sessionSnapshot struct {
	Room        [16]byte        `json:"room"`
	Peer        Peer            `json:"peer"`
	First       bool            `json:"first"`
	Pre         PrekeyHeader    `json:"pre"`
	UsedOneTime int64           `json:"used_one_time"`
	InitID      [32]byte        `json:"init_id"`
	InitEph     [32]byte        `json:"init_eph"`
	Ratchet     ratchetSnapshot `json:"ratchet"`
}

type ratchetSnapshot struct {
	RootKey   [32]byte          `json:"root_key"`
	DHSelf    [32]byte          `json:"dh_self"`
	DHSelfPub [32]byte          `json:"dh_self_pub"`
	DHRemote  [32]byte          `json:"dh_remote"`
	CKSend    [32]byte          `json:"ck_send"`
	CKRecv    [32]byte          `json:"ck_recv"`
	HasSend   bool              `json:"has_send"`
	HasRecv   bool              `json:"has_recv"`
	NSend     uint32            `json:"n_send"`
	NRecv     uint32            `json:"n_recv"`
	PN        uint32            `json:"pn"`
	Skipped   []skippedSnapshot `json:"skipped"`
	Cache     []cacheSnapshot   `json:"cache"` // in cacheOrder, oldest first
}

type skippedSnapshot struct {
	DH  [32]byte   `json:"dh"`
	N   uint32     `json:"n"`
	Key MessageKey `json:"key"`
}

type cacheSnapshot struct {
	DH     [32]byte `json:"dh"`
	N      uint32   `json:"n"`
	ADHash [32]byte `json:"ad_hash"`
	CTHash [32]byte `json:"ct_hash"`
	PT     []byte   `json:"pt"`
}

// SetBeforePublish installs f, which Send calls after sealing each
// envelope and before publishing it — the point at which a caller that
// saves sessions (MarshalSessions) must save. An error from f stops the
// send before that envelope leaves. Nil removes the hook.
func (c *Client) SetBeforePublish(f func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforePublish = f
}

// MarshalSessions returns a snapshot of the client's pairwise sessions for
// RestoreSessions. It holds secret key material.
func (c *Client) MarshalSessions() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap := sessionsSnapshot{V: sessionsVersion}
	for k, s := range c.sessions {
		snap.Sessions = append(snap.Sessions, snapshotSession(k.room, s))
	}
	for _, fk := range c.fallbackOrder {
		s, ok := c.fallbacks[fk]
		if !ok {
			continue
		}
		snap.Fallbacks = append(snap.Fallbacks, snapshotSession(fk.room, s))
	}
	return json.Marshal(snap)
}

// RestoreSessions replaces the client's pairwise sessions with a snapshot
// from MarshalSessions. Call it before Dial. A snapshot that does not
// parse, or has another version, changes nothing.
func (c *Client) RestoreSessions(b []byte) error {
	var snap sessionsSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("restore sessions: %w", err)
	}
	if snap.V != sessionsVersion {
		return fmt.Errorf("restore sessions: snapshot version %d, want %d", snap.V, sessionsVersion)
	}
	sessions := make(map[sessionKey]*session, len(snap.Sessions))
	for _, ss := range snap.Sessions {
		if ss.Peer.Device == ([16]byte{}) {
			return errors.New("restore sessions: session without a peer device")
		}
		sessions[sessionKey{room: ss.Room, peer: ss.Peer.Device}] = restoreSession(ss)
	}
	fallbacks := make(map[fallbackKey]*session, len(snap.Fallbacks))
	order := make([]fallbackKey, 0, len(snap.Fallbacks))
	for _, ss := range snap.Fallbacks {
		fk := fallbackKey{room: ss.Room, peer: ss.Peer.Device, initEph: ss.InitEph}
		fallbacks[fk] = restoreSession(ss)
		order = append(order, fk)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = sessions
	c.fallbacks = fallbacks
	c.fallbackOrder = order
	return nil
}

func snapshotSession(room [16]byte, s *session) sessionSnapshot {
	r := s.ratchet
	rs := ratchetSnapshot{
		RootKey: r.RootKey, DHSelf: r.dhSelf, DHSelfPub: r.dhSelfPub, DHRemote: r.dhRemote,
		CKSend: r.ckSend, CKRecv: r.ckRecv, HasSend: r.hasSend, HasRecv: r.hasRecv,
		NSend: r.nSend, NRecv: r.nRecv, PN: r.pn,
	}
	for id, mk := range r.skipped {
		rs.Skipped = append(rs.Skipped, skippedSnapshot{DH: id.dh, N: id.n, Key: mk})
	}
	for _, id := range r.cacheOrder {
		e, ok := r.cache[id]
		if !ok {
			continue
		}
		rs.Cache = append(rs.Cache, cacheSnapshot{DH: id.dh, N: id.n, ADHash: e.adHash, CTHash: e.ctHash, PT: e.pt})
	}
	return sessionSnapshot{
		Room: room, Peer: s.peer, First: s.first, Pre: s.pre, UsedOneTime: s.usedOneTime,
		InitID: s.initID, InitEph: s.initEph, Ratchet: rs,
	}
}

func restoreSession(ss sessionSnapshot) *session {
	rs := ss.Ratchet
	r := &Ratchet{
		RootKey: rs.RootKey, dhSelf: rs.DHSelf, dhSelfPub: rs.DHSelfPub, dhRemote: rs.DHRemote,
		ckSend: rs.CKSend, ckRecv: rs.CKRecv, hasSend: rs.HasSend, hasRecv: rs.HasRecv,
		nSend: rs.NSend, nRecv: rs.NRecv, pn: rs.PN,
		skipped: make(map[skippedID]MessageKey, len(rs.Skipped)),
		cache:   make(map[skippedID]cacheEntry, len(rs.Cache)),
	}
	for _, sk := range rs.Skipped {
		r.skipped[skippedID{dh: sk.DH, n: sk.N}] = sk.Key
	}
	for _, ce := range rs.Cache {
		id := skippedID{dh: ce.DH, n: ce.N}
		r.cache[id] = cacheEntry{adHash: ce.ADHash, ctHash: ce.CTHash, pt: ce.PT}
		r.cacheOrder = append(r.cacheOrder, id)
	}
	return &session{
		peer: ss.Peer, ratchet: r, first: ss.First, pre: ss.Pre, usedOneTime: ss.UsedOneTime,
		initID: ss.InitID, initEph: ss.InitEph,
	}
}
