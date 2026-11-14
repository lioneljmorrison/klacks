// The messaging path: WebSocket connect, the v1 JSON frames, room ordering,
// and the session glue that turns delivered envelopes into plaintext — the
// browser's side of client/wire.go and client/session.go.
//
// What the browser test client supports: pairwise E2EE (X3DH + Double
// Ratchet) in rooms it joins, in both directions, with the Go reference
// client as its peer. Sender-key group broadcasts (ratchet header type
// 0x03) are reported as unsupported rather than decrypted, and Sender Key
// distributions ("skd1" pairwise payloads) are noted and ignored.

import { base64, concat, hex, hexBytes, newIdentity, newOneTimePrekeys, newSignedPrekey, random, signBundle, unbase64, uuid, verifyBundle, x25519Public } from "./keys.mjs";
import { initiate as x3dhInitiate, respond as x3dhRespond } from "./x3dh.mjs";
import { Ratchet, newInitiatorRatchet, newResponderRatchet, decodeHeader } from "./ratchet.mjs";

// protocolVersion is the only wire version this client speaks.
const protocolVersion = 1;

// envelopeVersion opens the AEAD associated data.
const envelopeVersion = 1;

// ablob is TextEncoder shared by the frame JSON path.
const encoder = new TextEncoder();

// state is the client's whole serializable state (localStorage-backed).
// Sessions live per (room, peer device); identity and prekeys per device.
export class KlacksTestClient {
  constructor(opts = {}) {
    this.user = opts.user; // canonical UUID string
    this.device = opts.device; // canonical UUID string
    this.identity = opts.identity; // {seed, ed:{public, privateKey}, dh:{priv, pub}}
    this.signedPrekey = opts.signedPrekey; // {id, priv, pub}
    this.oneTimePrivs = new Map(Object.entries(opts.oneTimePrivs || {})); // id → priv
    this.spkNext = opts.spkNext || 1;
    this.opkNext = opts.opkNext || 1;
    this.base = opts.base || `${location.protocol}//${location.host}`;
    this.log = opts.log || (() => {});

    // Live connection state (not persisted).
    this.ws = null;
    this.connected = false;
    this.onEvent = () => {};
    this.onFrame = () => {};

    // Per-room receive bookkeeping: lastSeq, plus the ordering maps while
    // the page lives. After a reload, resume re-anchors at lastSeq and
    // redeliveries of already-seen seqs are silently ignored.
    this.rooms = new Map(); // room → {lastSeq, members:Set}
    this.sessions = new Map(); // "room|peerDev" → session
    this.fallbacks = new Map(); // "room|peerDev|initEph" → session
    this.pending = new Map(); // "room|peerDev" → [deliver]
    this.toDrain = []; // stashed delivers a new session can now open

    // queue runs deliveries and sends one at a time: both read and write
    // the session maps across awaits, so overlapping ones would build
    // duplicate sessions, lose stashed messages, or reorder a room.
    this.queue = Promise.resolve();
  }

  // serial runs fn after every earlier queued delivery and send settled.
  serial(fn) {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => {});
    return run;
  }

  // persist saves the state, logging (not throwing) on failure: for
  // receive-side bookkeeping, a lost save only means a redelivery.
  persist() {
    try {
      this.save();
    } catch (e) {
      this.log(`persist failed: ${e.message}`);
    }
  }

  // save serializes identity, prekeys, rooms and sessions to localStorage,
  // throwing when it cannot. A send saves before it transmits: a chain
  // step on the wire but not on disk would come back after a reload and
  // seal the next message under the same key and nonce.
  save() {
    if (!this.storageKey) return;
    const state = {
      user: this.user,
      device: this.device,
      identity: {
        seed: hex(this.identity.seed),
        edPub: hex(this.identity.ed.public),
        dhPriv: hex(this.identity.dh.priv),
        dhPub: hex(this.identity.dh.pub),
      },
      signedPrekey: { id: this.signedPrekey.id, priv: hex(this.signedPrekey.priv), pub: hex(this.signedPrekey.pub) },
      oneTimePrivs: Object.fromEntries([...this.oneTimePrivs].map(([id, priv]) => [id, hex(priv)])),
      spkNext: this.spkNext,
      opkNext: this.opkNext,
      rooms: [...this.rooms].map(([room, r]) => [room, { lastSeq: r.lastSeq, members: [...r.members] }]),
      sessions: [...this.sessions].map(([k, s]) => [k, sessionToPersisted(s)]),
      fallbacks: [...this.fallbacks].map(([k, s]) => [k, sessionToPersisted(s)]),
      estNext: this.estNext || 0,
      pending: [...this.pending].map(([k, v]) => [k, v.map(d => ({ ...d, room: hex(d.room), sender: hex(d.sender), senderDevice: hex(d.senderDevice), messageId: hex(d.messageId), header: base64(d.header), ciphertext: base64(d.ciphertext) }))]),
    };
    localStorage.setItem(this.storageKey, JSON.stringify(state));
  }

  // loadFromStorage rebuilds a client from its saved state; returns null
  // when nothing usable is stored.
  static async loadFromStorage(storageKey, log) {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return null;
    let s;
    try {
      s = JSON.parse(raw);
    } catch {
      return null;
    }
    const identity = await newIdentity(hexBytes(s.identity.seed));
    const c = new KlacksTestClient({
      user: s.user,
      device: s.device,
      identity,
      signedPrekey: { id: s.signedPrekey.id, priv: hexBytes(s.signedPrekey.priv), pub: hexBytes(s.signedPrekey.pub) },
      oneTimePrivs: Object.fromEntries(Object.entries(s.oneTimePrivs || {}).map(([id, priv]) => [id, hexBytes(priv)])),
      spkNext: s.spkNext,
      opkNext: s.opkNext,
      log,
    });
    for (const [room, r] of s.rooms || []) {
      c.rooms.set(room, { lastSeq: r.lastSeq, members: new Set(r.members), restored: true });
    }
    for (const [k, sp] of s.sessions || []) {
      try {
        c.sessions.set(k, sessionFromPersisted(sp));
      } catch (e) {
        log(`session ${k} could not be restored: ${e.message}`);
      }
    }
    c.estNext = s.estNext || 0;
    for (const [k, sp] of s.fallbacks || []) {
      try {
        c.fallbacks.set(k, sessionFromPersisted(sp));
      } catch (e) {
        log(`fallback ${k} could not be restored: ${e.message}`);
      }
    }
    for (const [k, v] of s.pending || []) {
      c.pending.set(
        k,
        v.map((d) => ({
          room: hexBytes(d.room),
          seq: d.seq,
          sender: hexBytes(d.sender),
          senderDevice: hexBytes(d.senderDevice),
          messageId: hexBytes(d.messageId),
          header: unbase64(d.header),
          ciphertext: unbase64(d.ciphertext),
        }))
      );
    }
    return c;
  }

  // fresh builds a brand-new client: identity, signed prekey, and an
  // initial batch of one-time prekeys.
  static async fresh(user, device, log) {
    const identity = await newIdentity();
    const signedPrekey = await newSignedPrekey(1);
    const c = new KlacksTestClient({ user, device, identity, signedPrekey, spkNext: 2, opkNext: 11, log });
    for (let i = 1; i <= 10; i++) {
      c.oneTimePrivs.set(String(i), random(32));
    }
    return c;
  }

  // ---- REST: the prekey bundle endpoints, dev-auth headers ----

  headers() {
    return { "X-Klacks-User": this.user, "X-Klacks-Device": this.device };
  }

  async rest(method, path, body) {
    const resp = await fetch(this.base + path, {
      method,
      headers: { ...this.headers(), ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`${method} ${path}: status ${resp.status}: ${text}`);
    }
    if (resp.status === 204) return null;
    return resp.json();
  }

  // register uploads this device's bundle with its one-time prekeys.
  async register() {
    const sig = await signBundle(this.identity, this.identity.dh.pub, this.signedPrekey.pub);
    const opks = await Promise.all(
      [...this.oneTimePrivs].map(async ([id, priv]) => ({
        id: Number(id),
        key: base64(await x25519Public(priv)),
      }))
    );
    const body = {
      identity_key: base64(this.identity.ed.public),
      identity_dh_key: base64(this.identity.dh.pub),
      signed_prekey_id: this.signedPrekey.id,
      signed_prekey: base64(this.signedPrekey.pub),
      signed_prekey_signature: base64(sig),
      one_time_prekeys: opks,
    };
    await this.rest("PUT", "/v1/device/bundle", body);
  }

  // ensureRegistered uploads the bundle when the server needs it: always
  // for fresh keys, and for restored keys only when the server does not
  // list this device (its data was wiped). Re-uploading a restored bundle
  // would hand out again one-time prekeys peers have already fetched.
  async ensureRegistered({ fresh }) {
    if (!fresh && (await this.listDevices(this.user)).includes(this.device)) return;
    await this.register();
  }

  // replenish uploads n fresh one-time prekeys.
  async replenish(n) {
    const keys = await newOneTimePrekeys(this.opkNext, n);
    this.opkNext += n;
    for (const k of keys) this.oneTimePrivs.set(String(k.id), k.priv);
    await this.rest("POST", "/v1/device/prekeys", {
      one_time_prekeys: keys.map((k) => ({ id: k.id, key: base64(k.pub) })),
    });
  }

  // fetchBundle gets (user, device)'s bundle, consuming one of its
  // one-time prekeys server-side.
  async fetchBundle(user, device) {
    const w = await this.rest("GET", `/v1/users/${user}/devices/${device}/bundle`);
    return {
      identityKey: unbase64(w.identity_key),
      identityDHKey: unbase64(w.identity_dh_key),
      signedPrekeyID: w.signed_prekey_id,
      signedPrekey: unbase64(w.signed_prekey),
      signedPrekeySignature: unbase64(w.signed_prekey_signature),
      oneTimePrekey: w.one_time_prekey ? { id: w.one_time_prekey.id, key: unbase64(w.one_time_prekey.key) } : null,
      oneTimePrekeysRemaining: w.one_time_prekeys_remaining,
    };
  }

  // listDevices returns a user's registered device UUIDs.
  async listDevices(user) {
    const devs = await this.rest("GET", `/v1/users/${user}/devices`);
    return devs.map((d) => d.device_id);
  }

  // ---- WebSocket ----

  connect() {
    if (this.ws) throw new Error("already connected");
    const url = `ws://${location.host}/ws?user=${encodeURIComponent(this.user)}&device=${encodeURIComponent(this.device)}`;
    const ws = new WebSocket(url);
    this.ws = ws;
    ws.onopen = () => {
      this.connected = true;
      this.onEvent({ kind: "status", connected: true });
    };
    ws.onclose = (e) => {
      this.connected = false;
      this.ws = null;
      this.onEvent({ kind: "status", connected: false, closeCode: e.code, reason: e.reason });
    };
    ws.onerror = () => this.onEvent({ kind: "error", message: "websocket error" });
    ws.onmessage = (e) => this.handleFrame(e.data);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close(1000, "");
      this.ws = null;
      this.connected = false;
    }
  }

  sendJSON(frame) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error("not connected");
    this.ws.send(JSON.stringify(frame));
  }

  subscribe(room) {
    this.sendJSON({ v: protocolVersion, type: "subscribe", room_id: room });
  }

  resume(room, lastSeen) {
    this.sendJSON({ v: protocolVersion, type: "resume", room_id: room, last_seen_seq: lastSeen });
  }

  ack(room, seq) {
    try {
      this.sendJSON({ v: protocolVersion, type: "ack", room_id: room, seq });
    } catch {
      // A failed ack only grows server memory; delivery is unaffected.
    }
  }

  // ---- Receiving ----

  handleFrame(data) {
    let f;
    try {
      f = JSON.parse(data);
    } catch (e) {
      this.onEvent({ kind: "error", message: `bad frame from server: ${e.message}` });
      return;
    }
    this.onFrame(f);
    switch (f.type) {
      case "deliver":
        return this.serial(() => this.handleDeliver(f)).catch((e) => this.onEvent({ kind: "error", message: `deliver: ${e.message}` }));
      case "error":
        this.onEvent({ kind: "serverError", code: f.code, message: f.message, room: f.room_id, messageId: f.message_id });
        return;
      case "member_removed":
        this.handleMemberRemoved(f);
        return;
      case "members":
        this.handleMembers(f);
        return;
      default:
        this.onEvent({ kind: "error", message: `unexpected frame type ${f.type}` });
    }
  }

  // handleMembers updates the room's member view (users, not devices).
  handleMembers(f) {
    let r = this.rooms.get(f.room_id);
    if (!r) {
      r = { lastSeq: 0, members: new Set() };
      this.rooms.set(f.room_id, r);
    }
    r.members = new Set(f.members);
    this.onEvent({ kind: "members", room: f.room_id, members: f.members });
    this.persist();
  }

  // handleMemberRemoved marks a removal. Like the reference client, a room
  // this device was removed from is dropped unread.
  handleMemberRemoved(f) {
    const r = this.rooms.get(f.room_id);
    if (r) {
      r.members.delete(f.user);
      this.persist();
    }
    this.onEvent({ kind: "memberRemoved", room: f.room_id, user: f.user, actor: f.actor });
    if (f.user === this.user) {
      this.onEvent({ kind: "info", message: "you were removed from the room" });
    }
  }

  // checkOrdering verifies the room's seq stream, as client/wire.go does:
  // strictly increasing, no gaps, one message id per seq. A violation means
  // the stored stream was tampered with. After a reload the page's maps are
  // empty but the persisted lastSeq is known: anything at or below it is a
  // known redelivery (silently verified later by the ratchet's cache), and
  // the check re-anchors at the first seq above it.
  checkOrdering(room, seq, mid) {
    let r = this.rooms.get(room);
    if (!r) {
      r = { lastSeq: 0, members: new Set(), anchored: false };
      this.rooms.set(room, r);
    }
    if (r.restored && seq <= r.lastSeq) {
      return { redelivery: true };
    }
    if (!r.anchored) {
      // Baseline: the first seq this page saw starts the check.
      r.anchored = true;
      r.restored = false;
      r.lastSeq = seq;
      r.seen = new Map([[seq, mid]]);
      r.ids = new Map([[mid, seq]]);
      return { redelivery: false };
    }
    if (r.ids.has(mid) && r.ids.get(mid) !== seq) {
      throw new Error(`room stream: message ${mid} appears at seq ${r.ids.get(mid)} and ${seq}`);
    }
    if (seq === r.lastSeq + 1) {
      r.lastSeq = seq;
      r.seen.set(seq, mid);
      r.ids.set(mid, seq);
      return { redelivery: false };
    }
    if (seq <= r.lastSeq) {
      if (r.seen.get(seq) === mid) return { redelivery: true };
      throw new Error(`room stream: seq ${seq} redelivered with a different message`);
    }
    throw new Error(`room stream: gap: seq ${seq} after ${r.lastSeq}`);
  }

  // handleDeliver processes one delivered frame, then opens anything the
  // frame's session released and saves the state — whichever way the
  // frame itself turned out.
  async handleDeliver(f) {
    await this.deliverOne(f);
    await this.drainStashed();
    this.persist();
  }

  async deliverOne(f) {
    const room = f.room_id;
    const d = {
      room: hexBytes(room.replaceAll("-", "")),
      seq: f.seq,
      sender: hexBytes(f.sender_id.replaceAll("-", "")),
      senderDevice: hexBytes(f.device_id.replaceAll("-", "")),
      messageId: hexBytes(f.message_id.replaceAll("-", "")),
      header: unbase64(f.header || ""),
      ciphertext: unbase64(f.ciphertext),
    };
    // A room this device was removed from is dropped unread.
    try {
      var ord = this.checkOrdering(room, d.seq, f.message_id);
    } catch (e) {
      this.onEvent({ kind: "message", room, seq: d.seq, sender: f.sender_id, senderDevice: f.device_id, err: e });
      this.ack(room, d.seq);
      return;
    }
    // Sender-key group broadcasts (ratchet header type 0x03) are outside
    // the browser client's pairwise scope.
    if (d.header.length > 1 && d.header[1] === 0x03) {
      this.onEvent({ kind: "message", room, seq: d.seq, sender: f.sender_id, senderDevice: f.device_id, err: new Error("sender-key group message: not supported by the browser test client") });
      this.ack(room, d.seq);
      return;
    }
    try {
      const pt = await this.unseal(d);
      if (pt === null) return; // stashed pending, or not for this device
      if (startsSKD(pt)) {
        // A Sender Key distribution over the pairwise session: the browser
        // client does not send group messages, so it notes and ignores it.
        this.onEvent({ kind: "info", message: `sender key distribution from ${f.device_id} (ignored)` });
        this.ack(room, d.seq);
        return;
      }
      if (ord.redelivery) {
        // Verified redelivery: stay silent, as the reference client does.
        this.ack(room, d.seq);
        return;
      }
      this.onEvent({ kind: "message", room, seq: d.seq, sender: f.sender_id, senderDevice: f.device_id, messageId: f.message_id, plaintext: pt });
      const r = this.rooms.get(room);
      if (r && d.seq > r.lastSeq) r.lastSeq = d.seq;
      this.ack(room, d.seq);
    } catch (e) {
      this.onEvent({ kind: "message", room, seq: d.seq, sender: f.sender_id, senderDevice: f.device_id, messageId: f.message_id, err: e });
      this.ack(room, d.seq);
    }
  }

  // drainStashed opens the delivers a just-established session released,
  // in arrival order, still inside the caller's queued turn.
  async drainStashed() {
    while (this.toDrain.length > 0) {
      const pd = this.toDrain.shift();
      const room = bufToRoomHex(pd.room);
      const ev = { kind: "message", room, seq: pd.seq, sender: hexToUUID(pd.sender), senderDevice: hexToUUID(pd.senderDevice), messageId: hexToUUID(pd.messageId) };
      try {
        const pt = await this.unseal(pd);
        if (pt === null) continue;
        if (!startsSKD(pt)) this.onEvent({ ...ev, plaintext: pt });
      } catch (e) {
        this.onEvent({ ...ev, err: e });
      }
      this.ack(room, pd.seq);
    }
  }

  // unseal decrypts one delivered message addressed to this device: it
  // establishes the responding session on a prekey header, routes by
  // ratchet key through fallbacks, and stashes messages that arrive before
  // their session's first message — the client/session.go path.
  async unseal(d) {
    const h = decodeHeader(d.header);
    // The header names the sending device, the session's routing key; a
    // delivered frame whose device_id disagrees is a tampered stream.
    if (!bytesEqual(h.device, d.senderDevice)) {
      throw new Error("decrypt: header names a device the frame was not delivered from");
    }
    if (!bytesEqual(h.recipient, hexBytes(this.device.replaceAll("-", "")))) {
      return null; // another member's copy: expected in multi-member rooms
    }
    const key = `${bufToRoomHex(d.room)}|${hex(h.device)}`;
    let session = this.sessions.get(key);
    let freshResponse = false;
    if (h.pre) {
      const before = session;
      session = await this.sessionForPrekey(key, d.sender, h);
      freshResponse = session !== before && session.justResponded === true;
    } else if (!session) {
      // The session's first message commits after some of its successors:
      // stash until the prekey message arrives and establishes the session.
      const list = this.pending.get(key) || [];
      list.push(d);
      this.pending.set(key, list);
      return null;
    } else if (!bytesEqual(h.dh, session.ratchet.dhRemote)) {
      // Not the active session's chain: the peer may still be sending over
      // a session this device demoted in the initiation tie-break.
      const fb = this.fallbackByDH(key, h.dh);
      if (fb) session = fb;
    }
    const ad = associatedData(d.room, d.sender, d.senderDevice, hexBytes(this.device.replaceAll("-", "")), d.messageId);
    try {
      const pt = await session.ratchet.decrypt(d.header, d.ciphertext, ad);
      // The message opened, so the session is real: consume its one-time
      // prekey now (respondNew deliberately defers this).
      if (freshResponse && session.usedOneTime) {
        this.oneTimePrivs.delete(String(session.usedOneTime));
        session.justResponded = false;
        this.persist();
      }
      return pt;
    } catch (e) {
      if (freshResponse) {
        // A session built from a message that will not open is garbage —
        // it was sealed under a bundle this device no longer matches.
        // Drop it (and any active session it displaced) so the next
        // legitimate initiation takes over cleanly; the OPK stays.
        if (this.sessions.get(key) === session) this.sessions.delete(key);
        this.fallbacks.delete(`${key}|${hex(session.initEph)}`);
        this.persist();
      } else if (/message authentication failed/.test(e.message) && this.sessions.get(key) === session) {
        // A failed open on the active session's own chain poisons it: drop
        // it so the next send re-initiates rather than sealing into a
        // session the peer no longer holds.
        this.sessions.delete(key);
        this.persist();
      }
      throw e;
    }
  }

  // sessionForPrekey resolves a prekey-header message to its session, with
  // the deterministic initiation tie-break of client/session.go.
  async sessionForPrekey(key, sender, h) {
    const [room, peerDevice] = splitSessionKey(key);
    const active = this.sessions.get(key);
    if (active && bytesEqual(active.initEph, h.pre.ephemeral)) {
      return active; // redelivery of the active session's initiation
    }
    const fbKey = `${key}|${hex(h.pre.ephemeral)}`;
    if (this.fallbacks.has(fbKey)) {
      return this.fallbacks.get(fbKey); // redelivery of a demoted initiation
    }
    const ns = await this.respondNew(key, room, peerDevice, sender, h);
    if (!active || newcomerWins(h.pre, active)) {
      if (active) this.fallbacks.set(fbKey, active);
      this.sessions.set(key, ns);
      this.persist();
      return ns;
    }
    this.fallbacks.set(fbKey, ns);
    this.persist();
    return ns;
  }

  // respondNew establishes the responding side of a session from a prekey
  // header, consuming the named one-time prekey if there is one. key names
  // the session ("room|peerDevice"), for the pending-message drain. The
  // OPK is NOT marked consumed here: a message sealed under a stale bundle
  // (a sender re-keyed, or history from before this device re-registered)
  // looks up the same prekey id but cannot decrypt — eating the OPK then
  // would starve the next legitimate initiation. Consumption happens in
  // unseal, once the message actually opens.
  async respondNew(key, room, peerDevice, senderUser, h) {
    if (h.pre.signedPrekeyID !== this.signedPrekey.id) {
      throw new Error(`decrypt: header names signed prekey ${h.pre.signedPrekeyID}, hold ${this.signedPrekey.id}`);
    }
    let opk = null;
    if (h.pre.oneTimePrekeyID !== 0) {
      const priv = this.oneTimePrivs.get(String(h.pre.oneTimePrekeyID));
      if (!priv) throw new Error(`decrypt: header names one-time prekey ${h.pre.oneTimePrekeyID}, none held`);
      opk = { id: h.pre.oneTimePrekeyID, priv };
    }
    const root = await x3dhRespond(this.identity, this.signedPrekey, opk, h.pre);
    const ratchet = await newResponderRatchet(root, this.signedPrekey, h.dh);
    const session = {
      peer: { user: senderUser, device: peerDevice },
      ratchet,
      first: false,
      pre: null,
      usedOneTime: opk ? opk.id : 0,
      initID: h.pre.identityDH,
      initEph: h.pre.ephemeral,
      justResponded: true,
      est: this.nextEst(),
      peerInitiated: true,
    };
    // Anything stashed while the session's first message was in flight
    // opens once this delivery finishes (handleDeliver drains toDrain);
    // the ratchet's skipped-key handling reorders them.
    this.toDrain.push(...(this.pending.get(key) || []));
    this.pending.delete(key);
    return session;
  }

  // fallbackByDH finds a peer's fallback session whose remote ratchet key
  // matches a delivered message's header key.
  fallbackByDH(key, dh) {
    for (const [k, s] of this.fallbacks) {
      if (k.startsWith(`${key}|`) && bytesEqual(s.ratchet.dhRemote, dh)) return s;
    }
    return null;
  }

  // ---- Sending ----

  // sealFor seals plaintext for one peer device over its session, creating
  // the session — an X3DH initiation against a freshly fetched bundle —
  // when this is the first message to that peer in that room.
  async sealFor(roomBytes, peerUser, peerDevice, pt) {
    const key = `${hexToUUID(roomBytes)}|${hex(peerDevice)}`;
    this.promoteNewestPeerSession(key);
    let session = this.sessions.get(key);
    if (!session) {
      // The bundle endpoint speaks canonical UUIDs; the crypto speaks bytes.
      const b = await this.fetchBundle(peerUser, hexToUUID(peerDevice));
      await verifyBundle(b);
      const { root, pre } = await x3dhInitiate(this.identity, b);
      const ratchet = await newInitiatorRatchet(root, b.signedPrekey);
      session = {
        peer: { user: peerUser, device: peerDevice },
        ratchet,
        first: true,
        pre,
        usedOneTime: b.oneTimePrekey ? b.oneTimePrekey.id : 0,
        initID: pre.identityDH,
        initEph: pre.ephemeral,
        est: this.nextEst(),
        peerInitiated: false,
      };
      this.sessions.set(key, session);
    }
    const mid = hexBytes(uuid().replaceAll("-", ""));
    const ad = associatedData(roomBytes, hexBytes(this.user.replaceAll("-", "")), hexBytes(this.device.replaceAll("-", "")), peerDevice, mid);
    const { header, ciphertext } = await session.ratchet.encrypt(pt, ad, hexBytes(this.device.replaceAll("-", "")), peerDevice, session.first ? session.pre : null);
    if (session.first) {
      session.first = false;
      session.pre = null;
    }
    return { messageId: mid, header, ciphertext };
  }

  // promoteNewestPeerSession picks the sending session when the peer has
  // re-initiated. A peer's active session is always its newest initiation:
  // after a CLI restart, its fresh initiation must carry the reply, even
  // though the deterministic initiation tie-break may keep an older session
  // active here for receiving. Only a peer-initiated session strictly newer
  // than the active one promotes, so the simultaneous-initiation case —
  // where the tie-break must rule for both sides to converge — is
  // unaffected: the peer-initiated session there is always the older one.
  promoteNewestPeerSession(key) {
    let newest = null;
    for (const [k, s] of this.fallbacks) {
      if (k.startsWith(`${key}|`) && s.peerInitiated && (!newest || s.est > newest.est)) newest = s;
    }
    const active = this.sessions.get(key);
    if (active && active.peerInitiated && (!newest || active.est >= newest.est)) return;
    if (!newest || (active && active.est > newest.est)) return;
    this.fallbacks.delete(`${key}|${hex(newest.initEph)}`);
    this.sessions.set(key, newest);
    if (active) this.fallbacks.set(`${key}|${hex(active.initEph)}`, active);
    this.persist();
  }

  // nextEst is the establishment counter's next value: sessions are
  // ordered by when they were established, across reloads.
  nextEst() {
    this.estNext = (this.estNext || 0) + 1;
    return this.estNext;
  }

  // refreshMembers replaces the room's member view with the server's list
  // (the dev room API). The WebSocket only announces removals, so members
  // added by someone else are learned here.
  async refreshMembers(room) {
    const resp = await this.rest("GET", `/v1/dev/rooms/${room}/members`);
    let r = this.rooms.get(room);
    if (!r) {
      r = { lastSeq: 0, members: new Set() };
      this.rooms.set(room, r);
    }
    r.members = new Set(resp.members);
    this.onEvent({ kind: "members", room, members: resp.members });
    this.persist();
  }

  // send refreshes the member list, then seals plaintext for every device
  // of every other member and publishes one envelope per recipient
  // device, as client/wire.go's Send does. It runs in the queue with
  // deliveries, which share its sessions.
  send(room, text) {
    return this.serial(() => this.sendNow(room, text));
  }

  async sendNow(room, text) {
    await this.refreshMembers(room);
    const r = this.rooms.get(room);
    const roomBytes = hexBytes(room.replaceAll("-", ""));
    const pt = encoder.encode(text);
    let sent = 0;
    for (const user of r.members) {
      if (user === this.user) continue;
      const devices = await this.listDevices(user);
      for (const device of devices) {
        const e = await this.sealFor(roomBytes, user, hexBytes(device.replaceAll("-", "")), pt);
        this.save(); // before transmitting: see save
        this.sendJSON({
          v: protocolVersion,
          type: "publish",
          room_id: room,
          message_id: hexToUUID(e.messageId),
          device_id: this.device,
          header: base64(e.header),
          ciphertext: base64(e.ciphertext),
        });
        sent++;
      }
    }
    if (sent === 0) {
      throw new Error("nobody else is in the room yet — invite someone below");
    }
    return sent;
  }
}

// ---- helpers ----

// associatedData is the envelope's fixed-width AD (client/envelope.go):
// version(1) || room(16) || sender(16) || senderDevice(16) ||
// recipientDevice(16) || messageID(16).
export function associatedData(room, sender, senderDevice, recipientDevice, messageId) {
  return concat(new Uint8Array([envelopeVersion]), room, sender, senderDevice, recipientDevice, messageId);
}

// newcomerWins settles two competing X3DH initiations: the lower (identity
// DH key, ephemeral) pair wins, the same verdict on both sides.
function newcomerWins(inPre, active) {
  if (bytesEqual(inPre.identityDH, active.initID)) {
    return compareBytes(inPre.ephemeral, active.initEph) < 0;
  }
  const c = compareBytes(inPre.identityDH, active.initID);
  if (c !== 0) return c < 0;
  return compareBytes(inPre.ephemeral, active.initEph) < 0;
}

function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// startsSKD reports whether a decrypted pairwise plaintext is a Sender Key
// distribution ("skd1" magic, 76 bytes total).
function startsSKD(pt) {
  return pt.length === 76 && pt[0] === 0x73 && pt[1] === 0x6b && pt[2] === 0x64 && pt[3] === 0x31;
}

// bufToRoomHex renders 16 room bytes as the canonical UUID string form the
// wire uses, via the standard formatting.
function bufToRoomHex(b) {
  return hexToUUID(b);
}

// hexToUUID turns 16 bytes into the canonical 8-4-4-4-12 string.
export function hexToUUID(b) {
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// splitSessionKey splits "room|peerDevice" back into its halves.
function splitSessionKey(key) {
  const at = key.indexOf("|");
  return [hexBytes(key.slice(0, at).replaceAll("-", "")), hexBytes(key.slice(at + 1))];
}

// sessionToPersisted / sessionFromPersisted round-trip a session (ratchet
// state and X3DH initiation identity) through JSON.
function sessionToPersisted(s) {
  return {
    peer: s.peer,
    first: s.first,
    est: s.est || 0,
    peerInitiated: s.peerInitiated === true,
    pre: s.pre
      ? {
          identityEd: hex(s.pre.identityEd),
          identityDH: hex(s.pre.identityDH),
          ephemeral: hex(s.pre.ephemeral),
          signedPrekeyID: s.pre.signedPrekeyID,
          oneTimePrekeyID: s.pre.oneTimePrekeyID,
        }
      : null,
    usedOneTime: s.usedOneTime,
    initID: hex(s.initID),
    initEph: hex(s.initEph),
    ratchet: s.ratchet.toState(),
  };
}

function sessionFromPersisted(p) {
  return {
    peer: p.peer,
    first: p.first,
    est: p.est || 0,
    peerInitiated: p.peerInitiated === true,
    pre: p.pre
      ? {
          identityEd: hexBytes(p.pre.identityEd),
          identityDH: hexBytes(p.pre.identityDH),
          ephemeral: hexBytes(p.pre.ephemeral),
          signedPrekeyID: p.pre.signedPrekeyID,
          oneTimePrekeyID: p.pre.oneTimePrekeyID,
        }
      : null,
    usedOneTime: p.usedOneTime,
    initID: hexBytes(p.initID),
    initEph: hexBytes(p.initEph),
    ratchet: Ratchet.fromState(p.ratchet),
  };
}
