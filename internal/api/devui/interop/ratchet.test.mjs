// Double Ratchet interop: the JS ratchet must walk the Go reference's
// transcript byte for byte — re-encrypting produces identical headers and
// ciphertexts, and every message decrypts on the receiving side
// (client/ratchet.go is the definition).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { hex, hexBytes, unbase64, x25519Public } from "../web/js/keys.mjs";
import { Ratchet, newInitiatorRatchet, newResponderRatchet, decodeHeader, encodeHeader, encodePrekeyHeader } from "../web/js/ratchet.mjs";

const vectors = JSON.parse(
  await readFile(path.join(path.dirname(fileURLToPath(import.meta.url)), "testdata/vectors.json"), "utf8")
);

const root = hexBytes(vectors.x3dh.initiatorRoot);
const spkB = {
  id: vectors.prekeys.B.spk.id,
  priv: hexBytes(vectors.prekeys.B.spk.priv),
  pub: hexBytes(vectors.prekeys.B.spk.pub),
};
const dhA1 = hexBytes(vectors.ratchet.pinned.dhA1);
const dhA1Pub = await x25519Public(dhA1); // A's first ratchet public — the responder's remote key
const dhB2 = hexBytes(vectors.ratchet.pinned.dhB2);
const messages = vectors.ratchet.messages;
const deviceA = hexBytes(vectors.ids.deviceA.replaceAll("-", ""));
const deviceB = hexBytes(vectors.ids.deviceB.replaceAll("-", ""));

// seal mirrors the reference client's per-message arguments: the sending
// and receiving devices ride in the header, and a session's first message
// carries the prekey header.
function seal(r, m) {
  const sender = m.from === "A>B" ? deviceA : deviceB;
  const recipient = m.from === "A>B" ? deviceB : deviceA;
  return r.encrypt(unbase64(m.plaintext), hexBytes(m.ad), sender, recipient, m.pre ? preHeader() : null);
}

// preHeader rebuilds the X3DH prelude from the vectors.
function preHeader() {
  const v = vectors.x3dh.preHeader;
  return {
    identityEd: hexBytes(v.identityEd),
    identityDH: hexBytes(v.identityDH),
    ephemeral: hexBytes(v.ephemeral),
    signedPrekeyID: v.signedPrekeyID,
    oneTimePrekeyID: v.oneTimePrekeyID,
  };
}

test("the JS ratchet re-encrypts A's messages byte for byte", async () => {
  // The initiator's ratchet, pinned exactly as the generator pinned it.
  const rA = await newInitiatorRatchet(root, spkB.pub, { frozen: [dhA1] });
  for (const m of messages.filter((m) => m.from === "A>B")) {
    const { header, ciphertext } = await seal(rA, m);
    assert.equal(hex(header), m.header, `A's header differs (${m.plaintext})`);
    assert.deepEqual(ciphertext, unbase64(m.ciphertext), `A's ciphertext differs (${m.plaintext})`);
  }
});

test("B decrypts A's messages and its replies re-encrypt byte for byte", async () => {
  // B starts as the responder: its ratchet key is the signed prekey, the
  // remote key is A's first ratchet key. It must decrypt A's messages
  // before it can send, since its send chain starts on A's ratchet key;
  // startSendChain then runs with the pinned key, as the generator did.
  const rB = await newResponderRatchet(root, spkB, dhA1Pub);
  for (const m of messages.filter((m) => m.from === "A>B")) {
    const pt = await rB.decrypt(hexBytes(m.header), unbase64(m.ciphertext), hexBytes(m.ad));
    assert.deepEqual(pt, unbase64(m.plaintext));
  }
  rB.frozen = [dhB2];
  for (const m of messages.filter((m) => m.from === "B>A")) {
    const { header, ciphertext } = await seal(rB, m);
    assert.equal(hex(header), m.header, `B's header differs (${m.plaintext})`);
    assert.deepEqual(ciphertext, unbase64(m.ciphertext), `B's ciphertext differs (${m.plaintext})`);
  }
});

test("the transcript decrypts on both sides, in transcript order", async () => {
  // B's side: all three of A's messages (the prekey one included —
  // newResponderRatchet starts the session before any decrypt). B replies
  // mid-stream, exactly as the generator did.
  const rB = await newResponderRatchet(root, spkB, dhA1Pub);
  rB.frozen = [dhB2];
  for (const m of messages) {
    if (m.from === "B>A") {
      await seal(rB, m);
      continue;
    }
    const pt = await rB.decrypt(hexBytes(m.header), unbase64(m.ciphertext), hexBytes(m.ad));
    assert.deepEqual(pt, unbase64(m.plaintext), `B could not decrypt: ${m.plaintext}`);
  }
  // A's side: its own sends replay the chain, then the two replies ratchet
  // it forward (its new send key is random here; it sends nothing more).
  const rA = await newInitiatorRatchet(root, spkB.pub, { frozen: [dhA1] });
  for (const m of messages.filter((m) => m.from === "A>B")) {
    await seal(rA, m);
  }
  for (const m of messages.filter((m) => m.from === "B>A")) {
    const pt = await rA.decrypt(hexBytes(m.header), unbase64(m.ciphertext), hexBytes(m.ad));
    assert.deepEqual(pt, unbase64(m.plaintext), `A could not decrypt: ${m.plaintext}`);
  }
});

test("out-of-order delivery decrypts from skipped keys", async () => {
  // A's three messages delivered in the order 2, 1, 3 must decrypt.
  const rB = await newResponderRatchet(root, spkB, dhA1Pub);
  const fromA = messages.filter((m) => m.from === "A>B");
  for (const i of [1, 0, 2]) {
    const m = fromA[i];
    const pt = await rB.decrypt(hexBytes(m.header), unbase64(m.ciphertext), hexBytes(m.ad));
    assert.deepEqual(pt, unbase64(m.plaintext));
  }
});

test("an identical redelivery re-opens from the cache; different content is refused", async () => {
  const rB = await newResponderRatchet(root, spkB, dhA1Pub);
  const m = messages.find((m) => m.from === "A>B" && !m.pre);
  await rB.decrypt(hexBytes(m.header), unbase64(m.ciphertext), hexBytes(m.ad));
  const again = await rB.decrypt(hexBytes(m.header), unbase64(m.ciphertext), hexBytes(m.ad));
  assert.deepEqual(again, unbase64(m.plaintext));
  const tampered = unbase64(m.ciphertext);
  tampered[0] ^= 0xff;
  await assert.rejects(() => rB.decrypt(hexBytes(m.header), tampered, hexBytes(m.ad)));
});

test("ratchet headers decode to the recorded fields", () => {
  const h = decodeHeader(hexBytes(messages[0].header));
  assert.ok(h.pre);
  assert.deepEqual(h.recipient, deviceB);
  assert.deepEqual(h.device, deviceA);
  const h2 = decodeHeader(hexBytes(messages[2].header));
  assert.equal(h2.pre, null);
  assert.deepEqual(h2.recipient, deviceA);
  assert.deepEqual(h2.device, deviceB);
});

// Headers parse only at their exact encoded length (S-35), matching the Go
// reference's decodeHeader: truncated or padded headers are refused.
test("decodeHeader accepts only the exact length", () => {
  const dh = new Uint8Array(32).fill(7);
  const id = (v) => new Uint8Array(16).fill(v);
  const normal = encodeHeader(dh, 3, 9, id(1), id(2));
  const prekey = encodePrekeyHeader(
    { identityEd: dh, identityDH: dh, ephemeral: dh, signedPrekeyID: 5, oneTimePrekeyID: 6 },
    dh, 0, 0, id(1), id(2)
  );
  for (const h of [normal, prekey]) {
    assert.ok(decodeHeader(h));
    assert.throws(() => decodeHeader(h.slice(0, h.length - 8)));
    assert.throws(() => decodeHeader(h.slice(0, h.length - 1)));
    const padded = new Uint8Array(h.length + 1);
    padded.set(h);
    assert.throws(() => decodeHeader(padded));
  }
});
