// Name resolution interop: the browser's names.mjs must map the same human
// names to the same UUIDs the Go package internal/names does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { resolveUser, resolveDevice, resolveRoom, isUUID } from "../web/js/names.mjs";

const vectors = JSON.parse(
  await readFile(path.join(path.dirname(fileURLToPath(import.meta.url)), "testdata/vectors.json"), "utf8")
);

test("user names resolve to the Go package's UUIDs", async () => {
  assert.equal(await resolveUser("alice"), vectors.names.user_alice);
  assert.equal(await resolveUser("bob"), vectors.names.user_bob);
});

test("room names resolve to the Go package's UUIDs", async () => {
  assert.equal(await resolveRoom("standup"), vectors.names.room_standup);
});

test("device names resolve under their user, as in Go", async () => {
  const alice = await resolveUser("alice");
  assert.equal(await resolveDevice(alice, "phone"), vectors.names.device_alice_phone);
  // A different user's same device name is a different device.
  const bob = await resolveUser("bob");
  assert.notEqual(await resolveDevice(bob, "phone"), vectors.names.device_alice_phone);
});

test("canonical UUIDs pass through lowercased; names do not read as UUIDs", async () => {
  const id = "A1000000-0000-0000-0000-000000000001";
  assert.equal(await resolveUser(id), id.toLowerCase());
  assert.equal(await resolveRoom(id), id.toLowerCase());
  assert.equal(isUUID("alice"), false);
  assert.equal(isUUID(id), true);
});
