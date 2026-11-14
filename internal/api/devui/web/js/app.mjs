// The dev UI's controller: a three-step flow — who are you, which room,
// chat — with everything mechanical (key generation, bundle registration,
// connecting, create-or-join) happening behind the "Start" and "Open"
// buttons. The protocol and crypto live in wire.mjs; names.mjs keeps
// UUIDs out of sight.

import { KlacksTestClient } from "./wire.mjs";
import { resolveUser, resolveDevice, resolveRoom } from "./names.mjs";

const $ = (id) => document.getElementById(id);

const els = {
  connState: $("conn-state"),
  yourName: $("your-name"),
  btnContinue: $("btn-continue"),
  userError: $("user-error"),
  hello: $("hello-line"),
  roomName: $("room-name"),
  roomError: $("room-error"),
  recent: $("recent-rooms"),
  roomTitle: $("room-title"),
  memberLine: $("member-line"),
  inviteName: $("invite-name"),
  messages: $("messages"),
  chatInput: $("chat-input"),
  log: $("log"),
};

let client = null; // the live KlacksTestClient, once started
let currentRoom = null; // {name, id} while chatting
let serverFramesShown = false;

// logLine appends one styled debug line and scrolls to it.
function logLine(cls, text) {
  const div = document.createElement("div");
  div.className = cls;
  div.textContent = text;
  els.log.appendChild(div);
  while (els.log.childElementCount > 400) els.log.firstChild.remove();
  els.log.scrollTop = els.log.scrollHeight;
}

const log = (msg) => logLine("dim", msg);
const logErr = (msg) => logLine("err", msg);
const logWarn = (msg) => logLine("warn", msg);

const short = (s) => (s || "").slice(0, 8) + "…";

// ---- step switching ----

function show(step) {
  for (const id of ["step-user", "step-room", "step-chat"]) {
    $(id).hidden = id !== step;
  }
}

function setConn(connected) {
  els.connState.textContent = connected ? "connected" : "offline";
  els.connState.className = `state ${connected ? "connected" : "disconnected"}`;
}

function showError(el, msg) {
  el.textContent = msg;
  el.hidden = false;
}

// ---- dev room API ----

// devREST calls the dev room endpoints with this identity's headers.
async function devREST(method, path, body) {
  const headers = { "X-Klacks-User": client.user, "X-Klacks-Device": client.device };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await resp.text();
  if (!resp.ok) {
    let code = `status ${resp.status}`, msg = "";
    try {
      const e = JSON.parse(text);
      code = e.code;
      msg = e.message;
    } catch {}
    const err = new Error(msg || code);
    err.code = code;
    throw err;
  }
  return text ? JSON.parse(text) : null;
}

// ---- step 1: who are you ----

// start resolves the name, restores this browser's keys for it (or makes
// fresh ones), registers the bundle, connects — the whole ritual in one
// click.
async function start(rawName) {
  const name = rawName.trim();
  if (!name) {
    showError(els.userError, "type a name first — any name");
    return;
  }
  els.userError.hidden = true;
  $("btn-start").disabled = true;
  try {
    const user = await resolveUser(name);
    const device = await resolveDevice(user, "browser");
    const storageKey = `klacks-devui:${user}:${device}`;
    const restored = await KlacksTestClient.loadFromStorage(storageKey, log);
    client = restored ?? await KlacksTestClient.fresh(user, device, log);
    client.storageKey = storageKey;
    client.onEvent = handleEvent;
    client.onFrame = handleFrame;
    localStorage.setItem("klacks-devui-last", name);

    // Restored keys are already on the server unless its data was wiped;
    // fresh ones replace whatever bundle the device had.
    await client.ensureRegistered({ fresh: !restored });
    client.save();
    log(`identity ready: ${short(user)} / ${short(device)}`);
    client.connect();
    // Wait (briefly) for the socket so the room step starts connected.
    await waitFor(() => client.connected, 5000);

    els.hello.textContent = `Hi ${name} — you're in.`;
    show("step-room");
    renderRecent(name);
    els.roomName.focus();
  } catch (e) {
    showError(els.userError, e.message);
  } finally {
    $("btn-start").disabled = false;
  }
}

// Continue-as: when this browser already holds keys for a name, offer to
// pick up where it left off.
async function offerContinue() {
  const last = localStorage.getItem("klacks-devui-last");
  if (!last) return;
  const user = await resolveUser(last);
  const device = await resolveDevice(user, "browser");
  if (!localStorage.getItem(`klacks-devui:${user}:${device}`)) return;
  els.btnContinue.hidden = false;
  els.btnContinue.textContent = `Continue as ${last}`;
  els.btnContinue.onclick = () => start(last);
}

function waitFor(cond, ms) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      if (cond()) return resolve();
      if (Date.now() - t0 > ms) return reject(new Error("timed out connecting"));
      setTimeout(tick, 100);
    };
    tick();
  });
}

$("form-user").onsubmit = (e) => {
  e.preventDefault();
  start(els.yourName.value);
};

// ---- step 2: rooms ----

// recentRooms is this user's room history, newest first.
function recentKey() {
  return client ? `klacks-devui-rooms:${client.user}` : null;
}

function loadRecent() {
  if (!recentKey()) return [];
  try {
    return JSON.parse(localStorage.getItem(recentKey())) || [];
  } catch {
    return [];
  }
}

function saveRecent(room) {
  const list = loadRecent().filter((r) => r.id !== room.id);
  list.unshift(room);
  localStorage.setItem(recentKey(), JSON.stringify(list.slice(0, 8)));
}

function renderRecent() {
  const rooms = loadRecent();
  els.recent.replaceChildren(
    ...rooms.map((r) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = r.name;
      b.onclick = () => openRoom(r.name);
      return b;
    })
  );
}

// openRoom resolves the name, creates the room if it doesn't exist yet (an
// "already exists" answer is just "it's here — join"), then resumes and
// opens the chat.
async function openRoom(rawName) {
  const name = rawName.trim();
  if (!name) {
    showError(els.roomError, "give the room a name — any name");
    return;
  }
  els.roomError.hidden = true;
  $("btn-open").disabled = true;
  try {
    if (!client.connected) {
      client.connect();
      await waitFor(() => client.connected, 5000);
    }
    const id = await resolveRoom(name);
    try {
      await devREST("POST", "/v1/dev/rooms", { room_id: id, kind: "group" });
      log(`created room ${name}`);
    } catch (e) {
      if (e.code !== "already_exists") throw e;
      log(`room ${name} already exists — joining`);
    }
    if (!client.rooms.has(id)) {
      client.rooms.set(id, { lastSeq: 0, members: new Set() });
    }
    // Resume after what this device already processed: a reload keeps the
    // sessions and the seq, so replaying from 0 would only re-run old
    // initiations. A room new to this device starts at 0.
    client.resume(id, client.rooms.get(id).lastSeq);
    currentRoom = { name, id };
    saveRecent({ name, id });
    enterChat();
  } catch (e) {
    showError(els.roomError, e.message);
  } finally {
    $("btn-open").disabled = false;
  }
}

$("form-room").onsubmit = (e) => {
  e.preventDefault();
  openRoom(els.roomName.value);
};

$("btn-rooms").onclick = () => {
  currentRoom = null;
  show("step-room");
  renderRecent();
  els.roomName.focus();
};

// ---- step 3: chat ----

function enterChat() {
  els.roomTitle.textContent = `# ${currentRoom.name}`;
  renderMembers();
  els.messages.replaceChildren();
  show("step-chat");
  els.chatInput.focus();
}

function renderMembers() {
  const r = currentRoom && client.rooms.get(currentRoom.id);
  const n = r ? r.members.size : 0;
  els.memberLine.textContent = n ? `${n} member${n === 1 ? "" : "s"}` : "";
}

// addLine appends one chat line and scrolls.
function addLine(cls, who, text) {
  const div = document.createElement("div");
  div.className = cls;
  if (who !== null) {
    const w = document.createElement("span");
    w.className = "who";
    w.textContent = who + " ";
    div.appendChild(w);
  }
  div.appendChild(document.createTextNode(text));
  els.messages.appendChild(div);
  while (els.messages.childElementCount > 300) els.messages.firstChild.remove();
  els.messages.scrollTop = els.messages.scrollHeight;
}

const fmt = (bytes) => new TextDecoder().decode(bytes);

$("form-chat").onsubmit = async (e) => {
  e.preventDefault();
  const text = els.chatInput.value.trim();
  if (!text || !currentRoom) return;
  els.chatInput.value = "";
  await sendText(text);
};

// sendText seals pairwise to every member device and publishes, the same
// path as the CLI's /send.
async function sendText(text) {
  try {
    if (!client.connected) {
      client.connect();
      await waitFor(() => client.connected, 5000);
      client.resume(currentRoom.id, client.rooms.get(currentRoom.id)?.lastSeq ?? 0);
    }
    await client.send(currentRoom.id, text);
    addLine("msg mine", null, `you: ${text}`);
    client.persist();
  } catch (e) {
    addLine("err", null, `send failed: ${e.message}`);
    logErr(`send: ${e.message}`);
  }
}

$("form-invite").onsubmit = async (e) => {
  e.preventDefault();
  const name = els.inviteName.value.trim();
  if (!name || !currentRoom) return;
  els.inviteName.value = "";
  try {
    const user = await resolveUser(name);
    await devREST("POST", `/v1/dev/rooms/${currentRoom.id}/members`, { user });
    addLine("sys", null, `invited ${name}`);
    await client.refreshMembers(currentRoom.id);
  } catch (err) {
    addLine("err", null, `invite failed: ${err.message}`);
  }
};

// ---- events from the client ----

function handleEvent(ev) {
  switch (ev.kind) {
    case "status":
      setConn(ev.connected);
      if (!ev.connected && currentRoom) {
        addLine("sys", null, `disconnected (close ${ev.closeCode}) — sending will reconnect`);
      }
      return;
    case "message": {
      if (!currentRoom || ev.room !== currentRoom.id) return;
      if (ev.err) {
        addLine("err", null, `couldn't decrypt a message (seq ${ev.seq}) — ` + friendlyCryptoError(ev.err.message));
      } else {
        addLine("msg", short(ev.sender) + ":", fmt(ev.plaintext));
      }
      return;
    }
    case "members":
      if (currentRoom && ev.room === currentRoom.id) renderMembers();
      log(`members of ${currentRoom ? currentRoom.name : short(ev.room)}: ${ev.members.length}`);
      return;
    case "memberRemoved":
      if (currentRoom && ev.room === currentRoom.id) {
        addLine("sys", null, `${short(ev.actor)} removed ${short(ev.user)}`);
        renderMembers();
      }
      return;
    case "serverError":
      logErr(`server error ${ev.code}: ${ev.message}`);
      if (currentRoom && ev.code === "not_member") {
        addLine("err", null, "you're not a member of this room — ask someone to invite you");
      }
      return;
    case "info":
      log(ev.message);
      return;
    case "error":
      logErr(ev.message);
      return;
  }
}

function handleFrame(f) {
  if (serverFramesShown) logLine("frame", `← ${JSON.stringify(f)}`);
}

// friendlyCryptoError turns the crypto layer's raw failures into plain
// sentences. The common one: history sealed before someone's keys changed
// (a re-registered device, a fresh identity) can never be decrypted again.
function friendlyCryptoError(msg) {
  if (/message authentication failed/.test(msg)) {
    return "it was sealed over a session this browser no longer holds (its saved keys were cleared or reset), so it can't be read here";
  }
  if (/none held/.test(msg)) {
    return "it used a one-time prekey this device no longer holds (keys were reset)";
  }
  if (/already consumed/.test(msg)) {
    return "it was already consumed on this connection";
  }
  return msg;
}

$("show-frames").onchange = () => {
  serverFramesShown = $("show-frames").checked;
};

// boot: prefill the last name and offer continue.
setConn(false);
offerContinue().catch((e) => logErr(e.message));
show("step-user");
els.yourName.focus();
