// ChaCha20-Poly1305 AEAD (RFC 8439) in plain JavaScript.
//
// WebCrypto has no ChaCha20-Poly1305, and the klacks envelope's primitive is
// exactly that (client/envelope.go), so the browser test client carries its
// own. Correctness outranks speed here — a test client seals one message at
// a time — so Poly1305 runs on BigInt, where mod-2^130-5 arithmetic is hard
// to get wrong, and ChaCha20 on Uint32Array words. The whole file is
// validated against RFC 8439's test vectors and against the Go reference
// (devui interop tests, internal/api/devui/interop/).

// rotl32 rotates x left by n bits, as uint32.
function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

// The ChaCha20 quarter round on four state words.
function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}

// initialState builds the working state: constants, key words (little-endian),
// block counter, nonce words (little-endian).
function initialState(key, nonce, counter) {
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) {
    s[4 + i] = leWord(key, i * 4);
  }
  s[12] = counter >>> 0;
  s[13] = leWord(nonce, 0);
  s[14] = leWord(nonce, 4);
  s[15] = leWord(nonce, 8);
  return s;
}

// leWord reads one little-endian uint32.
function leWord(b, at) {
  return (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
}

// putLeWord writes one little-endian uint32.
function putLeWord(out, at, w) {
  out[at] = w & 0xff;
  out[at + 1] = (w >>> 8) & 0xff;
  out[at + 2] = (w >>> 16) & 0xff;
  out[at + 3] = (w >>> 24) & 0xff;
}

// chachaBlock produces one 64-byte keystream block for (key, nonce, counter).
function chachaBlock(key, nonce, counter) {
  const s = initialState(key, nonce, counter);
  const work = s.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(work, 0, 4, 8, 12);
    quarterRound(work, 1, 5, 9, 13);
    quarterRound(work, 2, 6, 10, 14);
    quarterRound(work, 3, 7, 11, 15);
    quarterRound(work, 0, 5, 10, 15);
    quarterRound(work, 1, 6, 11, 12);
    quarterRound(work, 2, 7, 8, 13);
    quarterRound(work, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    putLeWord(out, i * 4, (work[i] + s[i]) >>> 0);
  }
  return out;
}

// The Poly1305 prime, 2^130 - 5.
const POLY_P = (1n << 130n) - 5n;

// poly1305Tag computes the 16-byte Poly1305 tag of msg under key (32 bytes:
// r then s). BigInt limbs, exactly the RFC's arithmetic: clamp r, then
// acc = (acc + block + 2^128) * r mod P per 16-byte block, and the tag is
// (acc + s) mod 2^128, little-endian.
function poly1305Tag(key, msg) {
  // r: little-endian, clamped per the RFC.
  let r = 0n;
  for (let i = 15; i >= 0; i--) r = (r << 8n) | BigInt(key[i]);
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;

  // s: the tag's addend, little-endian.
  let s = 0n;
  for (let i = 31; i >= 16; i--) s = (s << 8n) | BigInt(key[i]);

  let acc = 0n;
  for (let at = 0; at < msg.length; at += 16) {
    const n = Math.min(16, msg.length - at);
    let block = 0n;
    for (let i = n - 1; i >= 0; i--) block = (block << 8n) | BigInt(msg[at + i]);
    if (n < 16) block |= 1n << BigInt(8 * n); // the final partial block's high bit
    else block |= 1n << 128n;
    acc = ((acc + block) * r) % POLY_P;
  }
  acc = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  return out;
}

// pad16 pads b to a multiple of 16 bytes with zeros.
function pad16(b) {
  const rem = b.length % 16;
  if (rem === 0) return b;
  const out = new Uint8Array(b.length + (16 - rem));
  out.set(b);
  return out;
}

// le64 writes a length as 8 little-endian bytes.
function le64(n) {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

// macData is Poly1305's input: aad || pad16 || ct || pad16 || lengths.
function macData(aad, ct) {
  const a = pad16(aad);
  const c = pad16(ct);
  const out = new Uint8Array(a.length + c.length + 16);
  out.set(a, 0);
  out.set(c, a.length);
  out.set(le64(BigInt(aad.length)), a.length + c.length);
  out.set(le64(BigInt(ct.length)), a.length + c.length + 8);
  return out;
}

// constantTimeEqual compares two byte arrays in full, regardless of where a
// mismatch is.
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// chacha20poly1305Seal encrypts pt under (key, nonce) with aad, returning
// ciphertext || tag — the same shape Go's chacha20poly1305.Seal returns.
export function seal(key, nonce, aad, pt) {
  if (key.length !== 32) throw new Error("chacha: key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("chacha: nonce must be 12 bytes");
  // The Poly1305 one-time key is block 0's first 32 bytes; the message
  // keystream starts at block 1 (RFC 8439 §2.5).
  const polyKey = chachaBlock(key, nonce, 0).slice(0, 32);
  const ct = new Uint8Array(pt.length);
  let counter = 1;
  for (let at = 0; at < pt.length; at += 64) {
    const ks = chachaBlock(key, nonce, counter++);
    const n = Math.min(64, pt.length - at);
    for (let i = 0; i < n; i++) ct[at + i] = pt[at + i] ^ ks[i];
  }
  const tag = poly1305Tag(polyKey, macData(aad, ct));
  const out = new Uint8Array(ct.length + 16);
  out.set(ct);
  out.set(tag, ct.length);
  return out;
}

// chacha20poly1305Open decrypts sealed output, or throws on any
// authentication failure. Prefer failure to plaintext, as Go's Open.
export function open(key, nonce, aad, sealed) {
  if (key.length !== 32) throw new Error("chacha: key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("chacha: nonce must be 12 bytes");
  if (sealed.length < 16) throw new Error("chacha: ciphertext shorter than the tag");
  const ct = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);
  const polyKey = chachaBlock(key, nonce, 0).slice(0, 32);
  if (!constantTimeEqual(poly1305Tag(polyKey, macData(aad, ct)), tag)) {
    throw new Error("chacha: message authentication failed");
  }
  const pt = new Uint8Array(ct.length);
  let counter = 1;
  for (let at = 0; at < ct.length; at += 64) {
    const ks = chachaBlock(key, nonce, counter++);
    const n = Math.min(64, ct.length - at);
    for (let i = 0; i < n; i++) pt[at + i] = ct[at + i] ^ ks[i];
  }
  return pt;
}
