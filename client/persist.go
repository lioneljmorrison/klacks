package client

// Saving and restoring a device's client state, so a restarted device
// resumes where it left off: it keeps decrypting what peers seal over the
// sessions and sender keys it already held, keeps sending on them instead
// of starting new ones, and does not show a room's history again.
//
// What is saved (S-40, S-42):
//   - every active pairwise session and every receive-only fallback, with
//     the full ratchet state: chain keys, counters, the skipped message
//     keys still owed, and the decrypt cache that answers redeliveries;
//   - each room's ordering state: the last seq consumed and the message id
//     at every seq (LastSeq gives the resume point), and whether this
//     device was removed;
//   - messages stashed until their session's first message, and group
//     messages stashed until their sender key's distribution: their seqs
//     are behind the saved position, so a resume would not bring them back;
//   - sender keys: this device's own chain per room (signing key
//     included), every installed peer chain with its skipped keys and
//     decrypt cache, and each room's membership view (the devices a
//     rotation redistributes to).
//
// Each peer-initiated session keeps the room seq its initiation arrived at,
// which is how a replayed older initiation is told from a new one
// (newcomerWins). A snapshot is therefore tied to the server's seq history:
// after the server's data is wiped and seqs restart, discard it.
//
// The snapshot holds secret key material. Callers store it as they store
// the identity key.
//
// Saving must happen before a sealed message is transmitted, not after:
// a chain step on the wire but not on disk would come back after a restart
// and seal the next message under the same key and nonce. Every publish
// (Send, SendGroup, Distribute, Rotate, and the rotation a removal
// triggers) therefore calls the BeforePublish hook after sealing and
// before publishing.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// stateVersion versions the snapshot format. Version 1 (S-40) held only
// sessions and fallbacks; it still restores, with everything else empty.
const stateVersion = 2

type stateSnapshot struct {
	V         int               `json:"v"`
	Sessions  []sessionSnapshot `json:"sessions"`
	Fallbacks []sessionSnapshot `json:"fallbacks"` // in fallbackOrder

	Rooms     []roomSnapshot      `json:"rooms,omitempty"`
	Pending   []stashSnapshot     `json:"pending,omitempty"`    // pairwise, by (room, peer device)
	SKOwn     []ownChainSnapshot  `json:"sk_own,omitempty"`     // this device's chain per room
	SKPeers   []peerKeysSnapshot  `json:"sk_peers,omitempty"`   // installed chains per (room, sender device)
	SKPending []stashSnapshot     `json:"sk_pending,omitempty"` // group, by (room, sender device)
	RoomPeers []roomPeersSnapshot `json:"room_peers,omitempty"`
}

type roomSnapshot struct {
	Room    [16]byte       `json:"room"`
	Started bool           `json:"started"`
	LastSeq int64          `json:"last_seq"`
	Seen    []seenSnapshot `json:"seen"` // ids is rebuilt from it
	Removed bool           `json:"removed,omitempty"`
}

type seenSnapshot struct {
	Seq int64    `json:"seq"`
	ID  [16]byte `json:"id"`
}

type stashSnapshot struct {
	Room     [16]byte  `json:"room"`
	Device   [16]byte  `json:"device"`
	Delivers []deliver `json:"delivers"` // in arrival order
}

type ownChainSnapshot struct {
	Room      [16]byte `json:"room"`
	KeyID     uint32   `json:"key_id"`
	Iteration uint32   `json:"iteration"`
	ChainKey  [32]byte `json:"chain_key"`
	Signing   []byte   `json:"signing"` // ed25519 private key
}

type peerKeysSnapshot struct {
	Room   [16]byte          `json:"room"`
	Device [16]byte          `json:"device"`
	States []skStateSnapshot `json:"states"` // oldest first
}

type skStateSnapshot struct {
	KeyID     uint32            `json:"key_id"`
	DistIter  uint32            `json:"dist_iter"`
	DistChain [32]byte          `json:"dist_chain"`
	Iteration uint32            `json:"iteration"`
	ChainKey  [32]byte          `json:"chain_key"`
	Signing   []byte            `json:"signing"` // ed25519 public key
	Skipped   []skSkipped       `json:"skipped"`
	Cache     []skCacheSnapshot `json:"cache"` // in cacheOnce order
}

type skSkipped struct {
	Iteration uint32     `json:"iteration"`
	Key       MessageKey `json:"key"`
}

type skCacheSnapshot struct {
	Iteration uint32   `json:"iteration"`
	ADHash    [32]byte `json:"ad_hash"`
	CTHash    [32]byte `json:"ct_hash"`
	PT        []byte   `json:"pt"`
}

type roomPeersSnapshot struct {
	Room  [16]byte `json:"room"`
	Peers []Peer   `json:"peers"`
}

type sessionSnapshot struct {
	Room        [16]byte        `json:"room"`
	Peer        Peer            `json:"peer"`
	First       bool            `json:"first"`
	Pre         PrekeyHeader    `json:"pre"`
	UsedOneTime int64           `json:"used_one_time"`
	InitID      [32]byte        `json:"init_id"`
	InitEph     [32]byte        `json:"init_eph"`
	EstSeq      int64           `json:"est_seq,omitempty"`
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

// SetBeforePublish installs f, which every publish calls after sealing an
// envelope and before publishing it — the point at which a caller that
// saves state (MarshalState) must save. An error from f stops the publish
// before that envelope leaves. Nil removes the hook.
func (c *Client) SetBeforePublish(f func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforePublish = f
}

// LastSeq returns the last seq this device consumed in room, the point to
// resume from after a restart; ok is false for a room it has no record of.
func (c *Client) LastSeq(room [16]byte) (seq int64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rs, ok := c.rooms[room]
	if !ok || !rs.started {
		return 0, false
	}
	return rs.lastSeq, true
}

// MarshalState returns a snapshot of the client's state for RestoreState.
// It holds secret key material.
func (c *Client) MarshalState() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap := stateSnapshot{V: stateVersion}
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
	for room, rs := range c.rooms {
		r := roomSnapshot{Room: room, Started: rs.started, LastSeq: rs.lastSeq, Removed: rs.removed}
		for seq, id := range rs.seen {
			r.Seen = append(r.Seen, seenSnapshot{Seq: seq, ID: id})
		}
		snap.Rooms = append(snap.Rooms, r)
	}
	for k, ds := range c.pending {
		snap.Pending = append(snap.Pending, stashSnapshot{Room: k.room, Device: k.peer, Delivers: ds})
	}
	for room, ch := range c.skOwn {
		snap.SKOwn = append(snap.SKOwn, ownChainSnapshot{
			Room: room, KeyID: ch.KeyID, Iteration: ch.iteration, ChainKey: ch.chainKey, Signing: ch.signing,
		})
	}
	for ref, keys := range c.skPeers {
		p := peerKeysSnapshot{Room: ref.room, Device: ref.device}
		for _, st := range keys.states {
			p.States = append(p.States, snapshotSKState(st))
		}
		snap.SKPeers = append(snap.SKPeers, p)
	}
	for ref, ds := range c.skPending {
		snap.SKPending = append(snap.SKPending, stashSnapshot{Room: ref.room, Device: ref.device, Delivers: ds})
	}
	for room, peers := range c.roomPeers {
		snap.RoomPeers = append(snap.RoomPeers, roomPeersSnapshot{Room: room, Peers: peers})
	}
	return json.Marshal(snap)
}

// RestoreState replaces the client's state with a snapshot from
// MarshalState. Call it before Dial. A snapshot that does not parse, or
// has an unknown version, changes nothing.
func (c *Client) RestoreState(b []byte) error {
	var snap stateSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("restore state: %w", err)
	}
	if snap.V != 1 && snap.V != stateVersion {
		return fmt.Errorf("restore state: snapshot version %d, want 1 or %d", snap.V, stateVersion)
	}
	sessions := make(map[sessionKey]*session, len(snap.Sessions))
	for _, ss := range snap.Sessions {
		if ss.Peer.Device == ([16]byte{}) {
			return errors.New("restore state: session without a peer device")
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
	rooms := make(map[[16]byte]*roomState, len(snap.Rooms))
	for _, r := range snap.Rooms {
		rs := &roomState{
			started: r.Started, lastSeq: r.LastSeq, removed: r.Removed,
			seen: make(map[int64][16]byte, len(r.Seen)), ids: make(map[[16]byte]int64, len(r.Seen)),
		}
		for _, sn := range r.Seen {
			rs.seen[sn.Seq] = sn.ID
			rs.ids[sn.ID] = sn.Seq
		}
		rooms[r.Room] = rs
	}
	pending := make(map[sessionKey][]deliver, len(snap.Pending))
	for _, p := range snap.Pending {
		pending[sessionKey{room: p.Room, peer: p.Device}] = p.Delivers
	}
	skOwn := make(map[[16]byte]*SenderChain, len(snap.SKOwn))
	for _, o := range snap.SKOwn {
		if len(o.Signing) != ed25519.PrivateKeySize {
			return fmt.Errorf("restore state: own sender key for room %s: bad signing key", format(o.Room))
		}
		skOwn[o.Room] = &SenderChain{KeyID: o.KeyID, iteration: o.Iteration, chainKey: o.ChainKey, signing: ed25519.PrivateKey(o.Signing)}
	}
	skPeers := make(map[skRef]*SenderKeys, len(snap.SKPeers))
	for _, p := range snap.SKPeers {
		keys := NewSenderKeys()
		for _, st := range p.States {
			if len(st.Signing) != ed25519.PublicKeySize {
				return fmt.Errorf("restore state: sender key %d: bad signing key", st.KeyID)
			}
			keys.states = append(keys.states, restoreSKState(st))
		}
		skPeers[skRef{room: p.Room, device: p.Device}] = keys
	}
	skPending := make(map[skRef][]deliver, len(snap.SKPending))
	for _, p := range snap.SKPending {
		skPending[skRef{room: p.Room, device: p.Device}] = p.Delivers
	}
	roomPeers := make(map[[16]byte][]Peer, len(snap.RoomPeers))
	for _, rp := range snap.RoomPeers {
		roomPeers[rp.Room] = rp.Peers
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = sessions
	c.fallbacks = fallbacks
	c.fallbackOrder = order
	c.rooms = rooms
	c.pending = pending
	c.skOwn = skOwn
	c.skPeers = skPeers
	c.skPending = skPending
	c.roomPeers = roomPeers
	return nil
}

func snapshotSKState(st *skState) skStateSnapshot {
	out := skStateSnapshot{
		KeyID: st.keyID, DistIter: st.distIter, DistChain: st.distChain,
		Iteration: st.iteration, ChainKey: st.chainKey, Signing: st.signing,
	}
	for it, mk := range st.skipped {
		out.Skipped = append(out.Skipped, skSkipped{Iteration: it, Key: mk})
	}
	for _, it := range st.cacheOnce {
		e, ok := st.cache[it]
		if !ok {
			continue
		}
		out.Cache = append(out.Cache, skCacheSnapshot{Iteration: it, ADHash: e.adHash, CTHash: e.ctHash, PT: e.pt})
	}
	return out
}

func restoreSKState(ss skStateSnapshot) *skState {
	st := &skState{
		keyID: ss.KeyID, distIter: ss.DistIter, distChain: ss.DistChain,
		iteration: ss.Iteration, chainKey: ss.ChainKey,
		signing: ed25519.PublicKey(append([]byte(nil), ss.Signing...)),
		skipped: make(map[uint32]MessageKey, len(ss.Skipped)),
		cache:   make(map[uint32]skCacheEntry, len(ss.Cache)),
	}
	for _, sk := range ss.Skipped {
		st.skipped[sk.Iteration] = sk.Key
	}
	for _, ce := range ss.Cache {
		st.cache[ce.Iteration] = skCacheEntry{adHash: ce.ADHash, ctHash: ce.CTHash, pt: ce.PT}
		st.cacheOnce = append(st.cacheOnce, ce.Iteration)
	}
	return st
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
		InitID: s.initID, InitEph: s.initEph, EstSeq: s.estSeq, Ratchet: rs,
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
		initID: ss.InitID, initEph: ss.InitEph, estSeq: ss.EstSeq,
	}
}
