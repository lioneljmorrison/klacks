// X3DH session establishment, the browser's side of client/x3dh.go: the
// Signal spec's DH structure — DH1(ik, spk), DH2(ek, ik), DH3(ek, spk),
// DH4(ek, opk) when the bundle had a one-time prekey — mixed after a
// 32-byte 0xFF prefix into the root key via HKDF-SHA256 with the label
// "klacks X3DH v1", salt nil.

import { concat, hkdfSHA256, identityPublics, random, x25519, x25519Public } from "./keys.mjs";

// x3dhInfo is the HKDF info label, versioned.
const x3dhInfo = "klacks X3DH v1";

// sharedSecret mixes the DH outputs in the spec's order into the 32-byte
// root key. Each dh is 32 bytes or null.
async function sharedSecret(dh1, dh2, dh3, dh4) {
  // F: for Curve25519, 32 bytes of 0xFF (the X3DH spec).
  const parts = [new Uint8Array(32).fill(0xff)];
  for (const dh of [dh1, dh2, dh3, dh4]) {
    if (dh !== null) parts.push(dh);
  }
  const sk = concat(...parts);
  // Salt nil in the Go helper becomes HashLen zero bytes (RFC 5869); the
  // WebCrypto HKDF uses the salt as given, so the zeros are explicit here.
  const salt = new Uint8Array(32);
  const root = await hkdfSHA256(salt, sk, new TextEncoder().encode(x3dhInfo), 32);
  return root;
}

// initiate runs X3DH as the initiator against a verified bundle: the
// bundle's signature must already have passed verifyBundle. Returns the
// root key and the prekey header the session's first message must carry.
// opts.ekPriv pins the ephemeral (the interop test vectors use it; real
// callers omit it and a fresh ephemeral is drawn).
export async function initiate(me, b, opts = {}) {
  const dh1 = await x25519(me.dh.priv, b.signedPrekey);
  // The fresh ephemeral.
  const ekPriv = opts.ekPriv || random(32);
  const ekPub = await x25519Public(ekPriv);
  const dh2 = await x25519(ekPriv, b.identityDHKey);
  const dh3 = await x25519(ekPriv, b.signedPrekey);
  let dh4 = null;
  let opkID = 0;
  if (b.oneTimePrekey) {
    dh4 = await x25519(ekPriv, b.oneTimePrekey.key);
    opkID = b.oneTimePrekey.id;
  }
  const root = await sharedSecret(dh1, dh2, dh3, dh4);
  const pubs = identityPublics(me);
  const pre = {
    identityEd: pubs.identityEd,
    identityDH: pubs.identityDH,
    ephemeral: ekPub,
    signedPrekeyID: b.signedPrekeyID,
    oneTimePrekeyID: opkID,
  };
  return { root, pre };
}

// respond runs X3DH as the responder on a received prekey header: spk is
// the signed prekey pair whose id the header names; opk, when the header
// used one, is the key pair whose id it names and is consumed by the caller
// (the server deleted it at fetch time). Returns the root key initiate
// produced.
export async function respond(me, spk, opk, pre) {
  if (pre.signedPrekeyID !== spk.id) {
    throw new Error(`x3dh: header names signed prekey ${pre.signedPrekeyID}, hold ${spk.id}`);
  }
  if (pre.oneTimePrekeyID !== 0 && (opk === null || opk === undefined || opk.id !== pre.oneTimePrekeyID)) {
    throw new Error(`x3dh: header names one-time prekey ${pre.oneTimePrekeyID}, none held`);
  }
  const dh1 = await x25519(spk.priv, pre.identityDH);
  const dh2 = await x25519(me.dh.priv, pre.ephemeral);
  const dh3 = await x25519(spk.priv, pre.ephemeral);
  let dh4 = null;
  if (pre.oneTimePrekeyID !== 0) {
    dh4 = await x25519(opk.priv, pre.ephemeral);
  }
  return sharedSecret(dh1, dh2, dh3, dh4);
}
