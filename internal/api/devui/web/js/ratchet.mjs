// The Double Ratchet, the browser's side of client/ratchet.go, byte for
// byte: HKDF-SHA256 chains, ChaCha20-Poly1305 (chacha.js), and the same
// fixed-width headers. One session per (room, peer device) direction pair.
//
// Headers, all fields big-endian:
//
//	0x02: version || dh(32) || pn(4) || n(4) || recipient(16) || device(16)
//	0x01: version || identity_ed(32) || identity_dh(32) || ephemeral(32) ||
//	      spk_id(8) || opk_id(8) || dh(32) || pn(4) || n(4) ||
//	      recipient(16) || device(16)
//
// The whole decrypt step runs on a copy and commits only on success, and
// consumed chain positions are answered from the decrypt cache on
// redelivery, exactly as the Go ratchet does.

import { concat, hex, hexBytes, hkdfSHA256, random, sha256, u32be, u64be, x25519, x25519Public } from "./keys.mjs";
import { open as aeadOpen, seal as aeadSeal } from "./chacha.mjs";

// Header version and type bytes, and the chain KDF labels.
const ratchetVersion = 1;
const headerNormal = 0x02;
const headerPrekey = 0x01;
const maxSkip = 1000; // chain keys skipped silently before refusing
const skippedLimit = 5000; // stored skipped message keys before refusing
const cacheLimit = 512;

const kdfRootInfo = "klacks ratchet root v1";
const kdfMessageInfo = "klacks ratchet message v1";

// decodeBE reads a big-endian unsigned integer of n bytes at at.
function decodeBE(b, at, n) {
  let v = 0n;
  for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[at + i]);
  return v;
}

// toUint32 narrows for chain counters; the wire is 4 bytes.
function toUint32(v) {
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error("ratchet: counter out of range");
  return n;
}

// kdfRoot mixes one DH output into the root key: HKDF(salt = current root,
// ikm = DH output), 64 bytes → next root key, chain key.
async function kdfRoot(root, dh) {
  const out = await hkdfSHA256(root, dh, new TextEncoder().encode(kdfRootInfo), 64);
  return { nextRoot: out.slice(0, 32), ck: out.slice(32, 64) };
}

// kdfChain is KDF_CK: one chain step producing the message key with its
// nonce derived alongside it, and the next chain key.
async function kdfChain(ck) {
  const out = await hkdfSHA256(ck, new Uint8Array(32), new TextEncoder().encode(kdfMessageInfo), 76);
  return { key: out.slice(0, 32), nonce: out.slice(32, 44), next: out.slice(44, 76) };
}

// skippedKey names a skipped message key: (ratchet key, chain index), the
// same identity the Go map uses.
function skippedID(dh, n) {
  return `${hex(dh)}:${n}`;
}

// Ratchet is one session's crypto state. `frozen` (for the interop test
// vectors) pins the otherwise-random ratchet key pairs so JavaScript and
// Go walk identical chains.
export class Ratchet {
  constructor(opts = {}) {
    this.rootKey = opts.rootKey;
    this.dhSelf = opts.dhSelf || null; // private half
    this.dhSelfPub = opts.dhSelfPub || null;
    this.dhRemote = opts.dhRemote;
    this.ckSend = opts.ckSend || null;
    this.ckRecv = opts.ckRecv || null;
    this.hasSend = opts.hasSend || false;
    this.hasRecv = opts.hasRecv || false;
    this.nSend = opts.nSend || 0;
    this.nRecv = opts.nRecv || 0;
    this.pn = opts.pn || 0;
    this.skipped = new Map(); // skippedID → {key, nonce}
    this.cache = new Map(); // skippedID → {adHash, ctHash, pt}
    this.cacheOrder = [];
    this.frozen = opts.frozen || null; // array of pinned privates, consumed in order
    // queue serializes encrypt and decrypt: both await WebCrypto mid-step,
    // and two overlapping calls would otherwise read the same chain key
    // (or a decrypt's commit would roll the send chain back), sealing two
    // messages under one (key, nonce) pair.
    this.queue = Promise.resolve();
  }

  // serial runs fn after every earlier encrypt/decrypt on this ratchet has
  // settled, failures included.
  serial(fn) {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => {});
    return run;
  }

  // nextFrozen returns the pinned ratchet private to use, when testing.
  // An exhausted pin list falls back to randomness: pins exist to make
  // specific chains deterministic, not to constrain later steps.
  nextFrozen() {
    if (!this.frozen || this.frozen.length === 0) return null;
    return this.frozen.shift();
  }

  // newKeyPair generates the ratchet key pair (or takes the pinned one).
  async newKeyPair() {
    const priv = this.nextFrozen() || random(32);
    return { priv, pub: await x25519Public(priv) };
  }

  // startSendChain gives a responder without a send chain one: a fresh
  // ratchet key pair, RK' = KDF_RK(RK, DH(DHs', DHr)), CKs from the new root.
  async startSendChain() {
    const kp = await this.newKeyPair();
    const dh = await x25519(kp.priv, this.dhRemote);
    const { nextRoot, ck } = await kdfRoot(this.rootKey, dh);
    this.rootKey = nextRoot;
    this.dhSelf = kp.priv;
    this.dhSelfPub = kp.pub;
    this.ckSend = ck;
    this.hasSend = true;
  }

  // encrypt advances the send chain one step and seals plaintext. pre
  // carries the X3DH prelude on a session's first message and must be null
  // afterwards; sender and recipient are the sending and receiving devices'
  // UUIDs (16 bytes).
  encrypt(pt, ad, sender, recipient, pre) {
    return this.serial(() => this.encryptNow(pt, ad, sender, recipient, pre));
  }

  async encryptNow(pt, ad, sender, recipient, pre) {
    if (!this.hasSend) {
      // The responder's first send: a send-side DH ratchet step. Its root
      // is the one both sides share after initialization, so the
      // initiator's next DH ratchet step (on receiving this header's key)
      // lands on the same chain.
      await this.startSendChain();
    }
    const mk = await kdfChain(this.ckSend);
    this.ckSend = mk.next;
    const n = this.nSend;
    this.nSend++;

    const dh = this.dhSelfPub;
    const hdr = pre
      ? encodePrekeyHeader(pre, dh, this.pn, n, sender, recipient)
      : encodeHeader(dh, this.pn, n, sender, recipient);
    const ct = aeadSeal(mk.key, mk.nonce, concat(ad, hdr), pt);
    return { header: hdr, ciphertext: ct };
  }

  // decrypt opens a received message, or throws. Skipped messages (up to
  // maxSkip in one chain) decrypt from stashed message keys; a message key
  // is consumed exactly once; an identical redelivery returns the original
  // plaintext while different content at the same position is refused.
  decrypt(header, ciphertext, ad) {
    return this.serial(() => this.decryptNow(header, ciphertext, ad));
  }

  async decryptNow(header, ciphertext, ad) {
    const c = this.clone();
    const pt = await c.decryptBody(header, ciphertext, ad);
    this.commit(c);
    return pt;
  }

  clone() {
    const c = new Ratchet({
      rootKey: this.rootKey,
      dhSelf: this.dhSelf,
      dhSelfPub: this.dhSelfPub,
      dhRemote: this.dhRemote,
      ckSend: this.ckSend,
      ckRecv: this.ckRecv,
      hasSend: this.hasSend,
      hasRecv: this.hasRecv,
      nSend: this.nSend,
      nRecv: this.nRecv,
      pn: this.pn,
      frozen: this.frozen ? [...this.frozen] : null,
    });
    c.skipped = new Map(this.skipped);
    c.cache = new Map(this.cache);
    c.cacheOrder = [...this.cacheOrder];
    return c;
  }

  commit(c) {
    this.rootKey = c.rootKey;
    this.dhSelf = c.dhSelf;
    this.dhSelfPub = c.dhSelfPub;
    this.dhRemote = c.dhRemote;
    this.ckSend = c.ckSend;
    this.ckRecv = c.ckRecv;
    this.hasSend = c.hasSend;
    this.hasRecv = c.hasRecv;
    this.nSend = c.nSend;
    this.nRecv = c.nRecv;
    this.pn = c.pn;
    this.skipped = c.skipped;
    this.cache = c.cache;
    this.cacheOrder = c.cacheOrder;
  }

  async decryptBody(header, ciphertext, ad) {
    const h = decodeHeader(header);
    const adSum = await sha256(ad);
    const ctSum = await sha256(ciphertext);
    const id = skippedID(h.dh, h.n);
    // An identical replay of a decrypted message returns the same
    // plaintext; the same position with different content is refused.
    if (this.cache.has(id)) {
      const e = this.cache.get(id);
      if (bytesEqual(e.adHash, adSum) && bytesEqual(e.ctHash, ctSum)) return e.pt;
      throw new Error(`ratchet: replay of message ${h.n} with different content`);
    }
    // A skipped message key decrypts this without advancing anything.
    if (this.skipped.has(id)) {
      const mk = this.skipped.get(id);
      const pt = aeadOpen(mk.key, mk.nonce, concat(ad, header), ciphertext);
      this.skipped.delete(id);
      return this.remember(h, adSum, ctSum, pt);
    }
    if (!bytesEqual(h.dh, this.dhRemote)) {
      // New ratchet key from the peer: stash the rest of the current
      // receive chain as skipped keys, then DH ratchet forward.
      if (h.n > maxSkip) throw new Error(`ratchet: peer jumped ${h.n} ahead, over ${maxSkip}`);
      await this.skipMessageKeys(h.n);
      await this.dhRatchet(h);
    } else if (h.n > this.nRecv) {
      if (h.n - this.nRecv > maxSkip) {
        throw new Error(`ratchet: peer jumped ${h.n - this.nRecv} ahead, over ${maxSkip}`);
      }
      await this.skipMessageKeys(h.n);
    } else if (h.n < this.nRecv) {
      // Consumed in this chain and not in the decrypt cache: a replay the
      // ratchet cannot answer with its original plaintext.
      throw new Error(`ratchet: message ${h.n} of chain already consumed`);
    }
    if (!this.hasRecv) throw new Error("ratchet: no receive chain");
    const mk = await kdfChain(this.ckRecv);
    this.ckRecv = mk.next;
    this.nRecv++;
    const pt = aeadOpen(mk.key, mk.nonce, concat(ad, header), ciphertext);
    return this.remember(h, adSum, ctSum, pt);
  }

  // remember caches a decrypted message and returns the plaintext.
  remember(h, adSum, ctSum, pt) {
    const id = skippedID(h.dh, h.n);
    if (!this.cache.has(id)) this.cacheOrder.push(id);
    this.cache.set(id, { adHash: adSum, ctHash: ctSum, pt });
    while (this.cacheOrder.length > cacheLimit) {
      this.cache.delete(this.cacheOrder.shift());
    }
    return pt;
  }

  // skipMessageKeys stashes message keys 0..until-1 of the current receive
  // chain, so later out-of-order arrivals decrypt.
  async skipMessageKeys(until) {
    if (!this.hasRecv || until <= this.nRecv) return;
    if (this.skipped.size + (until - this.nRecv) > skippedLimit) {
      throw new Error("ratchet: too many skipped message keys");
    }
    while (this.nRecv < until) {
      const mk = await kdfChain(this.ckRecv);
      this.ckRecv = mk.next;
      this.skipped.set(skippedID(this.dhRemote, this.nRecv), { key: mk.key, nonce: mk.nonce });
      this.nRecv++;
    }
  }

  // dhRatchet performs a DH ratchet step on the peer's new key: the receive
  // chain restarts under the new root, then a fresh send chain is started.
  async dhRatchet(h) {
    const dh = await x25519(this.dhSelf, h.dh);
    const step1 = await kdfRoot(this.rootKey, dh);
    this.rootKey = step1.nextRoot;
    this.ckRecv = step1.ck;
    this.hasRecv = true;
    this.nRecv = 0;

    const kp = await this.newKeyPair();
    this.dhSelf = kp.priv;
    this.dhSelfPub = kp.pub;
    const dh2 = await x25519(kp.priv, h.dh);
    const step2 = await kdfRoot(this.rootKey, dh2);
    this.rootKey = step2.nextRoot;
    this.pn = this.nSend;
    this.ckSend = step2.ck;
    this.hasSend = true;
    this.nSend = 0;
    this.dhRemote = h.dh;
  }

  // toState / fromState carry the ratchet across a page reload: the state
  // is JSON, with byte arrays in hex.
  toState() {
    return {
      rootKey: hex(this.rootKey),
      dhSelf: this.dhSelf ? hex(this.dhSelf) : null,
      dhSelfPub: this.dhSelfPub ? hex(this.dhSelfPub) : null,
      dhRemote: hex(this.dhRemote),
      ckSend: this.ckSend ? hex(this.ckSend) : null,
      ckRecv: this.ckRecv ? hex(this.ckRecv) : null,
      hasSend: this.hasSend,
      hasRecv: this.hasRecv,
      nSend: this.nSend,
      nRecv: this.nRecv,
      pn: this.pn,
      skipped: [...this.skipped].map(([k, v]) => [k, { key: hex(v.key), nonce: hex(v.nonce) }]),
      cache: [...this.cache].map(([k, v]) => [
        k,
        { adHash: hex(v.adHash), ctHash: hex(v.ctHash), pt: hex(v.pt) },
      ]),
      cacheOrder: this.cacheOrder.map((id) => id),
    };
  }

  static fromState(s) {
    const r = new Ratchet({
      rootKey: hexBytes(s.rootKey),
      dhSelf: s.dhSelf ? hexBytes(s.dhSelf) : null,
      dhSelfPub: s.dhSelfPub ? hexBytes(s.dhSelfPub) : null,
      dhRemote: hexBytes(s.dhRemote),
      ckSend: s.ckSend ? hexBytes(s.ckSend) : null,
      ckRecv: s.ckRecv ? hexBytes(s.ckRecv) : null,
      hasSend: s.hasSend,
      hasRecv: s.hasRecv,
      nSend: s.nSend,
      nRecv: s.nRecv,
      pn: s.pn,
    });
    r.skipped = new Map(s.skipped.map(([k, v]) => [k, { key: hexBytes(v.key), nonce: hexBytes(v.nonce) }]));
    r.cache = new Map(
      s.cache.map(([k, v]) => [k, { adHash: hexBytes(v.adHash), ctHash: hexBytes(v.ctHash), pt: hexBytes(v.pt) }])
    );
    r.cacheOrder = [...s.cacheOrder];
    return r;
  }
}

// bytesEqual compares two byte arrays.
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// NewInitiatorRatchet starts the initiator's ratchet from the X3DH root
// key: a fresh ratchet key pair and the first DH ratchet step against the
// peer's signed prekey produce the send chain.
export async function newInitiatorRatchet(root, peerSignedPrekey, opts = {}) {
  const r = new Ratchet({ rootKey: root, dhRemote: peerSignedPrekey, ...opts });
  const kp = await r.newKeyPair();
  r.dhSelf = kp.priv;
  r.dhSelfPub = kp.pub;
  // RK, CKs = KDF_RK(SK, DH(DHs, DHr)): the initiator can send at once.
  const dh = await x25519(kp.priv, peerSignedPrekey);
  const { nextRoot, ck } = await kdfRoot(root, dh);
  r.rootKey = nextRoot;
  r.ckSend = ck;
  r.hasSend = true;
  return r;
}

// NewResponderRatchet starts the responder's ratchet from the X3DH root
// key: its ratchet key pair is the signed prekey the initiator used, and
// the remote key is the initiator's first ratchet key (from the first
// message's header), producing the receive chain.
export async function newResponderRatchet(root, signedPrekey, dhRemote) {
  const pub = await x25519Public(signedPrekey.priv);
  const r = new Ratchet({
    rootKey: root,
    dhSelf: signedPrekey.priv,
    dhSelfPub: pub,
    dhRemote: dhRemote,
  });
  // RK, CKr = KDF_RK(SK, DH(DHs, DHr)): the responder can receive at once;
  // it sends only after its first DH ratchet step.
  const dh = await x25519(signedPrekey.priv, dhRemote);
  const { nextRoot, ck } = await kdfRoot(root, dh);
  r.rootKey = nextRoot;
  r.ckRecv = ck;
  r.hasRecv = true;
  return r;
}

// encodeHeader is the normal (0x02) header: version, type, dh, pn, n,
// recipient, device.
export function encodeHeader(dh, pn, n, sender, recipient) {
  return concat(
    new Uint8Array([ratchetVersion, headerNormal]),
    dh,
    u32be(pn),
    u32be(n),
    recipient,
    sender
  );
}

// encodePrekeyHeader is the prekey (0x01) header carrying the X3DH prelude.
export function encodePrekeyHeader(pre, dh, pn, n, sender, recipient) {
  return concat(
    new Uint8Array([ratchetVersion, headerPrekey]),
    pre.identityEd,
    pre.identityDH,
    pre.ephemeral,
    u64be(pre.signedPrekeyID),
    u64be(pre.oneTimePrekeyID),
    dh,
    u32be(pn),
    u32be(n),
    recipient,
    sender
  );
}

// decodeHeader parses either header type, exactly client/ratchet.go's
// decodeHeader. Recipient and device are the receiving and sending devices'
// UUIDs.
export function decodeHeader(b) {
  const fail = (what) => new Error(`ratchet: header: ${what}`);
  if (b.length < 2 || b[0] !== ratchetVersion) throw fail("unknown version");
  const h = { dh: null, pn: 0, n: 0, recipient: null, device: null, pre: null };
  const read32 = (at) => {
    if (b.length < at + 32) throw fail("truncated");
    return b.slice(at, at + 32);
  };
  const copyTrailer = (at) => {
    if (b.length < at + 32) throw fail("truncated");
    h.recipient = b.slice(at, at + 16);
    h.device = b.slice(at + 16, at + 32);
  };
  switch (b[1]) {
    case headerNormal: {
      h.dh = read32(2);
      h.pn = toUint32(decodeBE(b, 34, 4));
      h.n = toUint32(decodeBE(b, 38, 4));
      copyTrailer(42);
      return h;
    }
    case headerPrekey: {
      h.pre = {
        identityEd: read32(2),
        identityDH: read32(34),
        ephemeral: read32(66),
        signedPrekeyID: Number(decodeBE(b, 98, 8)),
        oneTimePrekeyID: Number(decodeBE(b, 106, 8)),
      };
      h.dh = read32(114);
      h.pn = toUint32(decodeBE(b, 146, 4));
      h.n = toUint32(decodeBE(b, 150, 4));
      copyTrailer(154);
      return h;
    }
    default:
      throw fail("unknown type");
  }
}

// toUint32 guards a chain counter read back from the wire.
export { toUint32 };
