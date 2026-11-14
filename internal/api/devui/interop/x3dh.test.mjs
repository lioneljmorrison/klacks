// Identity and X3DH interop: the JS identity derivation (Ed25519 seed, the
// clamped SHA-512 Montgomery form) and both X3DH roles must agree with the
// Go reference (client/keys.go, client/x3dh.go) byte for byte.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { newIdentity, verifyBundle, bundleKeysMessage, hex, hexBytes, unbase64, u64be } from "../web/js/keys.mjs";
import { initiate, respond } from "../web/js/x3dh.mjs";
import { encodePrekeyHeader } from "../web/js/ratchet.mjs";

const vectors = JSON.parse(
  await readFile(path.join(path.dirname(fileURLToPath(import.meta.url)), "testdata/vectors.json"), "utf8")
);

test("identity derivation matches the Go reference", async () => {
  for (const who of ["A", "B"]) {
    const v = vectors.identities[who];
    const id = await newIdentity(hexBytes(v.seed));
    assert.equal(hex(id.ed.public), v.edPub, `${who}: Ed25519 public differs`);
    assert.equal(hex(id.dh.priv), v.dhPriv, `${who}: Montgomery private differs`);
    assert.equal(hex(id.dh.pub), v.dhPub, `${who}: Montgomery public differs`);
  }
});

test("the generated bundle verifies under the JS verifier", async () => {
  const b = vectors.bundleB;
  const bundle = {
    identityKey: unbase64(b.identity_key),
    identityDHKey: unbase64(b.identity_dh_key),
    signedPrekeyID: b.signed_prekey_id,
    signedPrekey: unbase64(b.signed_prekey),
    signedPrekeySignature: unbase64(b.signed_prekey_signature),
    oneTimePrekey: { id: b.one_time_prekey.id, key: unbase64(b.one_time_prekey.key) },
  };
  await assert.doesNotReject(() => verifyBundle(bundle));
});

test("the JS bundle signature message matches Go's length-prefixed encoding", () => {
  const b = vectors.bundleB;
  const msg = bundleKeysMessage(unbase64(b.identity_dh_key), unbase64(b.signed_prekey));
  // The signature in the bundle covers exactly these bytes; verifying it
  // (the test above) already proves equivalence, this pins the encoding.
  assert.equal(msg.length, 72);
  assert.deepEqual(msg.slice(0, 4), u32be32());
});

function u32be32() {
  return new Uint8Array([0, 0, 0, 32]);
}

test("X3DH initiate with the pinned ephemeral produces Go's root key and prekey header", async () => {
  const v = vectors.x3dh;
  const idA = await newIdentity(hexBytes(vectors.identities.A.seed));
  const b = vectors.bundleB;
  const bundle = {
    identityKey: unbase64(b.identity_key),
    identityDHKey: unbase64(b.identity_dh_key),
    signedPrekeyID: b.signed_prekey_id,
    signedPrekey: unbase64(b.signed_prekey),
    signedPrekeySignature: unbase64(b.signed_prekey_signature),
    oneTimePrekey: { id: b.one_time_prekey.id, key: unbase64(b.one_time_prekey.key) },
  };
  const { root, pre } = await initiate(idA, bundle, { ekPriv: hexBytes(v.ephemeral.priv) });
  assert.equal(hex(root), v.initiatorRoot, "initiator root key differs from Go");
  assert.equal(hex(pre.identityEd), v.preHeader.identityEd, "prekey header identityEd differs");
  assert.equal(hex(pre.identityDH), v.preHeader.identityDH, "prekey header identityDH differs");
  assert.equal(hex(pre.ephemeral), v.preHeader.ephemeral, "prekey header ephemeral differs");
  assert.equal(pre.signedPrekeyID, v.preHeader.signedPrekeyID, "prekey header spk id differs");
  assert.equal(pre.oneTimePrekeyID, v.preHeader.oneTimePrekeyID, "prekey header opk id differs");
});

test("X3DH respond produces Go's root key", async () => {
  const v = vectors.x3dh;
  const idB = await newIdentity(hexBytes(vectors.identities.B.seed));
  const spk = {
    id: vectors.prekeys.B.spk.id,
    priv: hexBytes(vectors.prekeys.B.spk.priv),
    pub: hexBytes(vectors.prekeys.B.spk.pub),
  };
  const opk = { id: vectors.prekeys.B.opk.id, priv: hexBytes(vectors.prekeys.B.opk.priv) };
  const pre = {
    identityEd: hexBytes(v.preHeader.identityEd),
    identityDH: hexBytes(v.preHeader.identityDH),
    ephemeral: hexBytes(v.preHeader.ephemeral),
    signedPrekeyID: v.preHeader.signedPrekeyID,
    oneTimePrekeyID: v.preHeader.oneTimePrekeyID,
  };
  const root = await respond(idB, spk, opk, pre);
  assert.equal(hex(root), v.responderRoot, "responder root key differs from Go");
  assert.equal(hex(root), v.initiatorRoot, "responder root differs from the initiator's");
});

test("the JS prekey header encoding matches Go's transcript header", async () => {
  // The transcript's first message carries the prekey header; encoding the
  // same prelude over the same ratchet state must produce those bytes.
  const v = vectors.x3dh;
  const first = vectors.ratchet.messages.find((m) => m.pre);
  const pre = {
    identityEd: hexBytes(v.preHeader.identityEd),
    identityDH: hexBytes(v.preHeader.identityDH),
    ephemeral: hexBytes(v.preHeader.ephemeral),
    signedPrekeyID: v.preHeader.signedPrekeyID,
    oneTimePrekeyID: v.preHeader.oneTimePrekeyID,
  };
  // The transcript header's own ratchet fields: decode from the recorded
  // bytes rather than re-derive, so the comparison is purely about the
  // encoder.
  const hdr = hexBytes(first.header);
  const dh = hdr.slice(114, 146);
  const pn = Number(readBE(hdr, 146, 4));
  const n = Number(readBE(hdr, 150, 4));
  const recipient = hdr.slice(154, 170);
  const device = hdr.slice(170, 186);
  const encoded = encodePrekeyHeader(pre, dh, pn, n, device, recipient);
  assert.deepEqual(encoded, hdr);
});

function readBE(b, at, n) {
  let v = 0n;
  for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[at + i]);
  return v;
}
