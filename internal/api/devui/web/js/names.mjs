// Human-readable names resolve to the UUIDs the wire needs, byte for byte
// identically to the Go package internal/names: UUIDv5 (SHA-1) under one
// fixed namespace. "alice" is one user everywhere, "standup" is one room
// everywhere, no shared state. A canonical UUID is accepted anywhere a name
// is and takes precedence.
//
//	user "alice"            → v5(ns, "user/alice")
//	device "phone" of alice → v5(ns, "device/<alice's user UUID>/phone")
//	room "standup"          → v5(ns, "room/standup")

import { concat, hexBytes } from "./keys.mjs";

const subtle = globalThis.crypto.subtle;

// The shared namespace: uuid5(NAMESPACE_DNS, "klacks.dev"). Never change
// it — it is the same constant internal/names pins.
const NAMESPACE = hexBytes("3a13d177ee00591982dcc039cb9f63c6");

const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// uuidv5 is the name-based (SHA-1) UUID of name under the namespace.
export async function uuidv5(name) {
  const digest = new Uint8Array(await subtle.digest("SHA-1", concat(NAMESPACE, new TextEncoder().encode(name))));
  const u = digest.slice(0, 16);
  u[6] = (u[6] & 0x0f) | 0x50; // version 5
  u[8] = (u[8] & 0x3f) | 0x80; // RFC 4122 variant
  return hexToUUID(u);
}

// isUUID reports whether s is already a canonical UUID.
export function isUUID(s) {
  return UUID_PATTERN.test(s || "");
}

// resolveUser maps a user name or canonical UUID to the user UUID string.
export async function resolveUser(nameOrUUID) {
  return isUUID(nameOrUUID) ? nameOrUUID.toLowerCase() : uuidv5("user/" + nameOrUUID);
}

// resolveDevice maps a device name or canonical UUID to its UUID under the
// given (already resolved) user UUID.
export async function resolveDevice(userUUID, nameOrUUID) {
  return isUUID(nameOrUUID) ? nameOrUUID.toLowerCase() : uuidv5(`device/${userUUID}/${nameOrUUID}`);
}

// resolveRoom maps a room name or canonical UUID to the room UUID string.
export async function resolveRoom(nameOrUUID) {
  return isUUID(nameOrUUID) ? nameOrUUID.toLowerCase() : uuidv5("room/" + nameOrUUID);
}

// hexToUUID turns 16 bytes into the canonical 8-4-4-4-12 string.
export function hexToUUID(b) {
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
