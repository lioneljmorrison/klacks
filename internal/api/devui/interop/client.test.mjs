// KlacksTestClient end to end in Node: two real clients (X3DH, ratchet,
// session bookkeeping) talk through a fake server that answers the prekey
// and dev room REST calls. The browser globals wire.mjs touches (fetch,
// localStorage, location) are stubbed; frames are handed to handleFrame
// directly, as the WebSocket's onmessage would.

import test from "node:test";
import assert from "node:assert/strict";

import { KlacksTestClient, hexToUUID } from "../web/js/wire.mjs";
import { base64, hexBytes, unbase64, uuid } from "../web/js/keys.mjs";
import { decodeHeader } from "../web/js/ratchet.mjs";

const bytesEq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---- browser stubs ----

const storage = new Map();
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};
globalThis.location = { protocol: "http:", host: "test.invalid" };

// The fake server: bundles by device (one-time prekeys handed out once),
// devices by user, members by room.
const server = { bundles: new Map(), devices: new Map(), members: new Map() };

globalThis.fetch = async (url, opts = {}) => {
  const path = new URL(url).pathname;
  const method = opts.method || "GET";
  const hdr = opts.headers || {};
  const json = (status, body) => ({
    ok: status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
  let m;
  if (method === "PUT" && path === "/v1/device/bundle") {
    const body = JSON.parse(opts.body);
    server.bundles.set(hdr["X-Klacks-Device"], { ...body, one_time_prekeys: [...body.one_time_prekeys] });
    const devs = server.devices.get(hdr["X-Klacks-User"]) || new Set();
    devs.add(hdr["X-Klacks-Device"]);
    server.devices.set(hdr["X-Klacks-User"], devs);
    return json(204, null);
  }
  if (method === "GET" && (m = path.match(/^\/v1\/users\/([^/]+)\/devices\/([^/]+)\/bundle$/))) {
    const b = server.bundles.get(m[2]);
    const opk = b.one_time_prekeys.shift() || null;
    return json(200, { ...b, one_time_prekey: opk, one_time_prekeys_remaining: b.one_time_prekeys.length });
  }
  if (method === "GET" && (m = path.match(/^\/v1\/users\/([^/]+)\/devices$/))) {
    return json(200, [...(server.devices.get(m[1]) || [])].map((d) => ({ device_id: d })));
  }
  if (method === "GET" && (m = path.match(/^\/v1\/dev\/rooms\/([^/]+)\/members$/))) {
    return json(200, { room_id: m[1], members: server.members.get(m[1]) || [] });
  }
  return json(404, { code: "not_found", message: `${method} ${path}` });
};

// ---- helpers ----

async function newClient(storageKey) {
  const c = await KlacksTestClient.fresh(uuid(), uuid(), () => {});
  c.storageKey = storageKey;
  c.events = [];
  c.onEvent = (e) => c.events.push(e);
  await c.register();
  return c;
}

// seal makes one deliver frame from `from` to `to` at seq.
async function seal(from, to, room, seq, text) {
  const e = await from.sealFor(hexBytes(room.replaceAll("-", "")), to.user, hexBytes(to.device.replaceAll("-", "")), new TextEncoder().encode(text));
  return {
    v: 1,
    type: "deliver",
    room_id: room,
    seq,
    sender_id: from.user,
    device_id: from.device,
    message_id: hexToUUID(e.messageId),
    header: base64(e.header),
    ciphertext: base64(e.ciphertext),
  };
}

// messages waits until c has emitted n message events (or the deadline),
// then returns them as text or "ERR: ...".
async function messages(c, n, ms = 2000) {
  const t0 = Date.now();
  const got = () => c.events.filter((e) => e.kind === "message");
  while (got().length < n && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 10));
  await new Promise((r) => setTimeout(r, 50)); // let anything extra land
  return got().map((e) => (e.err ? `ERR: ${e.err.message}` : new TextDecoder().decode(e.plaintext)));
}

// ---- tests ----

test("a burst of frames opening a new session all decrypt, in order", async () => {
  const room = uuid();
  const alice = await newClient(`t1-alice`);
  const bob = await newClient(`t1-bob`);
  const frames = [];
  for (let i = 1; i <= 5; i++) frames.push(await seal(alice, bob, room, i, `m${i}`));
  // Delivered back to back, as a resume replay or a busy room does.
  for (const f of frames) bob.handleFrame(JSON.stringify(f));
  assert.deepEqual(await messages(bob, 5), ["m1", "m2", "m3", "m4", "m5"]);
});

test("a reloaded client keeps its sessions and decrypts the next message", async () => {
  const room = uuid();
  const alice = await newClient(`t2-alice`);
  const bob = await newClient(`t2-bob`);
  bob.handleFrame(JSON.stringify(await seal(alice, bob, room, 1, "before reload")));
  assert.deepEqual(await messages(bob, 1), ["before reload"]);

  // The page reloads: a new client from the same storage.
  const bob2 = await KlacksTestClient.loadFromStorage(`t2-bob`, () => {});
  bob2.storageKey = `t2-bob`;
  bob2.events = [];
  bob2.onEvent = (e) => bob2.events.push(e);
  assert.equal(bob2.sessions.size, 1, "the session survives the reload");
  // Saving again (any later persist) must not drop it either.
  bob2.persist();
  const bob3 = await KlacksTestClient.loadFromStorage(`t2-bob`, () => {});
  assert.equal(bob3.sessions.size, 1, "a persist after reload keeps the session");

  bob2.handleFrame(JSON.stringify(await seal(alice, bob, room, 2, "after reload")));
  assert.deepEqual(await messages(bob2, 1), ["after reload"]);
});

// The send chain must be saved before a message leaves: a reload between
// transmit and save would restore the chain one step back, and the next
// send would reuse the transmitted message's key and nonce.
test("a send is saved before it is transmitted", async () => {
  globalThis.WebSocket = { OPEN: 1 };
  const room = uuid();
  const alice = await newClient(`t5-alice`);
  const bob = await newClient(`t5-bob`);
  server.members.set(room, [alice.user, bob.user]);
  const frames = [];
  alice.ws = { readyState: 1, send: () => {} };
  await alice.send(room, "zero"); // opens the session
  alice.persist(); // the app's save after a send: the session is on disk
  alice.ws = { readyState: 1, send: (d) => frames.push(JSON.parse(d)) };
  await alice.send(room, "one");

  // The tab dies right after transmitting: nothing else saves.
  const alice2 = await KlacksTestClient.loadFromStorage(`t5-alice`, () => {});
  alice2.storageKey = `t5-alice`;
  alice2.ws = { readyState: 1, send: (d) => frames.push(JSON.parse(d)) };
  await alice2.send(room, "two");

  assert.equal(frames.length, 2);
  const [h1, h2] = frames.map((f) => decodeHeader(unbase64(f.header)));
  assert.ok(h1.n !== h2.n || !bytesEq(h1.dh, h2.dh), "the restored chain re-sent at the same position");
});

// A send whose state cannot be saved must not go out.
test("a send that cannot be saved is not transmitted", async () => {
  globalThis.WebSocket = { OPEN: 1 };
  const room = uuid();
  const alice = await newClient(`t6-alice`);
  const bob = await newClient(`t6-bob`);
  server.members.set(room, [alice.user, bob.user]);
  const frames = [];
  alice.ws = { readyState: 1, send: (d) => frames.push(JSON.parse(d)) };
  const setItem = globalThis.localStorage.setItem;
  globalThis.localStorage.setItem = () => {
    throw new Error("QuotaExceededError");
  };
  try {
    await assert.rejects(alice.send(room, "unsaved"));
  } finally {
    globalThis.localStorage.setItem = setItem;
  }
  assert.equal(frames.length, 0, "a message went out whose chain step was never saved");
});

// Starting again with restored keys must not re-upload one-time prekeys a
// peer already fetched: a second peer would get the same prekey, and its
// first message could not open once the first peer's had consumed it.
test("a restored client does not hand out a fetched one-time prekey again", async () => {
  const bob = await newClient(`t7-bob`);
  const first = (await bob.fetchBundle(bob.user, bob.device)).oneTimePrekey.id;
  const bob2 = await KlacksTestClient.loadFromStorage(`t7-bob`, () => {}) ?? bob;
  await bob2.ensureRegistered({ fresh: false });
  const second = (await bob2.fetchBundle(bob.user, bob.device)).oneTimePrekey.id;
  assert.notEqual(second, first);
});

// Fresh keys for a device the server already lists (this browser's
// storage was cleared) must replace the server's bundle.
test("fresh keys are registered even when the device is listed", async () => {
  const bob = await newClient(`t8-bob`);
  const bob2 = await KlacksTestClient.fresh(bob.user, bob.device, () => {});
  await bob2.ensureRegistered({ fresh: true });
  const b = await bob2.fetchBundle(bob.user, bob.device);
  assert.deepEqual([...b.identityKey], [...bob2.identity.ed.public]);
});

test("refreshMembers takes the server's member list", async () => {
  const room = uuid();
  const bob = await newClient(`t3-bob`);
  bob.rooms.set(room, { lastSeq: 0, members: new Set([bob.user, "old-member"]) });
  server.members.set(room, [bob.user, "new-member"]);
  await bob.refreshMembers(room);
  assert.deepEqual([...bob.rooms.get(room).members].sort(), [bob.user, "new-member"].sort());
});

test("a member_removed frame drops the user from the room's members", async () => {
  const room = uuid();
  const bob = await newClient(`t4-bob`);
  bob.rooms.set(room, { lastSeq: 0, members: new Set([bob.user, "carol", "dave"]) });
  bob.handleFrame(JSON.stringify({ v: 1, type: "member_removed", room_id: room, user: "carol", actor: bob.user }));
  assert.deepEqual([...bob.rooms.get(room).members].sort(), [bob.user, "dave"].sort());
});
