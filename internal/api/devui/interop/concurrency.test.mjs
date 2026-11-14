// Overlapping ratchet calls must behave as if run one at a time. The
// browser fires a decrypt for every delivered frame and an encrypt for every
// send without waiting for the previous one; WebCrypto awaits inside both
// would otherwise let two calls read the same chain key (or let a decrypt's
// commit roll the send chain back) and seal two messages under one
// (key, nonce) pair.

import test from "node:test";
import assert from "node:assert/strict";

import { newInitiatorRatchet, newResponderRatchet, decodeHeader } from "../web/js/ratchet.mjs";
import { random, x25519Public } from "../web/js/keys.mjs";

const enc = new TextEncoder();
const ad = new Uint8Array(81);
const A = random(16);
const B = random(16);

// pair builds an initiator a and responder b with b's send chain started,
// so both sides can send and receive.
async function pair() {
  const root = random(32);
  const spkPriv = random(32);
  const spk = { priv: spkPriv, pub: await x25519Public(spkPriv) };
  const a = await newInitiatorRatchet(root, spk.pub);
  const first = await a.encrypt(enc.encode("hello"), ad, A, B, null);
  const b = await newResponderRatchet(root, spk, decodeHeader(first.header).dh);
  await b.decrypt(first.header, first.ciphertext, ad);
  const reply = await b.encrypt(enc.encode("reply"), ad, B, A, null);
  await a.decrypt(reply.header, reply.ciphertext, ad);
  return { a, b };
}

test("overlapping encrypts use distinct chain positions and both decrypt", async () => {
  const { a, b } = await pair();
  const [m1, m2] = await Promise.all([
    a.encrypt(enc.encode("one"), ad, A, B, null),
    a.encrypt(enc.encode("two"), ad, A, B, null),
  ]);
  assert.notEqual(decodeHeader(m1.header).n, decodeHeader(m2.header).n);
  assert.equal(new TextDecoder().decode(await b.decrypt(m1.header, m1.ciphertext, ad)), "one");
  assert.equal(new TextDecoder().decode(await b.decrypt(m2.header, m2.ciphertext, ad)), "two");
});

test("an encrypt overlapping a decrypt does not roll the send chain back", async () => {
  const { a, b } = await pair();
  const incoming = await b.encrypt(enc.encode("incoming"), ad, B, A, null);
  const [s1] = await Promise.all([
    a.encrypt(enc.encode("first"), ad, A, B, null),
    a.decrypt(incoming.header, incoming.ciphertext, ad),
  ]);
  const s2 = await a.encrypt(enc.encode("second"), ad, A, B, null);
  assert.notEqual(decodeHeader(s1.header).n, decodeHeader(s2.header).n);
  assert.equal(new TextDecoder().decode(await b.decrypt(s1.header, s1.ciphertext, ad)), "first");
  assert.equal(new TextDecoder().decode(await b.decrypt(s2.header, s2.ciphertext, ad)), "second");
});
