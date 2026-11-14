// Key material: the identity key pair, the signed prekey, the one-time
// prekeys, and the prekey bundle's signature — the browser's side of
// client/keys.go and client/bundle.go, byte for byte.
//
// The identity is an Ed25519 key that signs the bundle; its X25519
// (Montgomery) private key is the clamped first 32 bytes of SHA-512 of the
// Ed25519 seed, so both forms share one scalar (the standard XEdDSA identity
// conversion). WebCrypto provides Ed25519 and X25519 (Chrome 133+,
// Firefox 129+, Safari 17+); private keys import via PKCS#8 wrappers, and a
// private key's public half comes out of a JWK export, which carries both
// the scalar ("d") and the public key ("x") for OKP keys.

// base64 encodes bytes the way encoding/json does (standard, padded).
export function base64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// unbase64 decodes base64 — standard (padded) on the wire, and the
// base64url JWKs WebCrypto exports (no padding, - and _ alphabetics).
export function unbase64(s) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4 !== 0) s += "=";
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// hex encodes bytes lowercase; hexBytes reverses it. Key state is stored in
// localStorage as hex, which round-trips byte arrays without surprises.
export function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexBytes(s) {
  if (s.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

// subtle, lazily: this module also runs under Node's test runner, where
// globalThis.crypto.subtle is the same WebCrypto.
const subtle = globalThis.crypto.subtle;

// random fills a fresh byte array from the platform CSPRNG.
export function random(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

// uuid returns a random v4 UUID string, the shape message ids take.
export function uuid() {
  return globalThis.crypto.randomUUID();
}

// concat joins byte arrays.
export function concat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// u32be / u64be write big-endian unsigned integers, the wire's order.
export function u32be(n) {
  const out = new Uint8Array(4);
  for (let i = 3; i >= 0; i--) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return out;
}

export function u64be(n) {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function readBE(out, at, n) {
  let v = 0n;
  for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(out[at + i]);
  return v;
}

// pkcs8Private wraps a 32-byte private scalar/seed in the PKCS#8 DER
// envelope WebCrypto wants for private X25519 and Ed25519 keys:
// SEQUENCE { INTEGER 0, SEQUENCE { OID }, OCTET STRING { OCTET STRING key } }
// — 48 bytes: 30 2e | 02 01 00 | 30 05 06 03 <3 OID bytes> | 04 22 | 04 20.
function pkcs8Private(seed, algorithmOid) {
  if (seed.length !== 32) throw new Error("pkcs8: private key must be 32 bytes");
  const out = new Uint8Array(48);
  out.set([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
    algorithmOid[0], algorithmOid[1], algorithmOid[2],
    0x04, 0x22, 0x04, 0x20,
  ]);
  out.set(seed, 16);
  return out;
}

// Ed25519: 1.3.101.112 → 2b 65 70. X25519: 1.3.101.110 → 2b 65 6e.
const ED25519_OID = [0x2b, 0x65, 0x70];
const X25519_OID = [0x2b, 0x65, 0x6e];

// sha512 digests b with WebCrypto.
export async function sha512(b) {
  return new Uint8Array(await subtle.digest("SHA-512", b));
}

// x25519 is the DH function: X25519(privScalar, peerPub), 32 bytes. The
// peer's key rides in the algorithm parameters; the spec spells that member
// "publicKey", Node's implementation "public", so both are set — dictionary
// normalization ignores the unknown one.
export async function x25519(privScalar, peerPub) {
  const priv = await subtle.importKey("pkcs8", pkcs8Private(privScalar, X25519_OID), "X25519", false, ["deriveBits"]);
  const pub = await subtle.importKey("raw", peerPub, "X25519", false, []);
  const alg = { name: "X25519", publicKey: pub, public: pub };
  // deriveBits' length is in bits: 32 bytes = 256.
  return new Uint8Array(await subtle.deriveBits(alg, priv, 256));
}

// x25519Public derives the public half of an X25519 scalar: the JWK export
// of a private OKP key carries both halves ("d" the scalar, "x" the public).
export async function x25519Public(privScalar) {
  // deriveBits must be in the usages for a private import, even though the
  // call only exports the JWK.
  const priv = await subtle.importKey("pkcs8", pkcs8Private(privScalar, X25519_OID), "X25519", true, ["deriveBits"]);
  const jwk = await subtle.exportKey("jwk", priv);
  if (!jwk.x) throw new Error("keys: X25519 JWK export has no public half");
  return unbase64(jwk.x);
}

// ed25519KeyPairFromSeed builds the identity's Ed25519 signing key from its
// 32-byte seed and returns the seed, the public key, and a signing handle.
export async function ed25519KeyPairFromSeed(seed) {
  const priv = await subtle.importKey("pkcs8", pkcs8Private(seed, ED25519_OID), "Ed25519", true, ["sign"]);
  const jwk = await subtle.exportKey("jwk", priv);
  if (!jwk.x) throw new Error("keys: Ed25519 JWK export has no public half");
  return { seed, public: unbase64(jwk.x), privateKey: priv };
}

// ed25519Sign signs msg under the identity's private key.
export async function ed25519Sign(identityEd, msg) {
  return new Uint8Array(await subtle.sign("Ed25519", identityEd.privateKey, msg));
}

// ed25519Verify checks a signature under a raw 32-byte public key.
export async function ed25519Verify(pub, sig, msg) {
  const key = await subtle.importKey("raw", pub, "Ed25519", false, ["verify"]);
  return subtle.verify("Ed25519", key, sig, msg);
}

// hkdfSHA256 derives n bytes with HKDF-SHA256.
export async function hkdfSHA256(salt, ikm, info, n) {
  const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: salt, info: info },
    base,
    n * 8
  );
  return new Uint8Array(bits);
}

// sha256 digests b (the ratchet's decrypt cache keys on it).
export async function sha256(b) {
  return new Uint8Array(await subtle.digest("SHA-256", b));
}

// bundleKeysMessage is the bytes the bundle signature covers: the identity's
// Montgomery form and the signed prekey, each length-prefixed (4 bytes,
// big-endian) so the encoding is unambiguous — client/keys.go's
// bundleKeysMessage.
export function bundleKeysMessage(identityDH, signedPrekey) {
  return concat(u32be(32), identityDH, u32be(32), signedPrekey);
}

// Identity is one device's long-term keys: the Ed25519 pair (seed-derived)
// and the X25519 private key clamped out of the same seed's SHA-512.
export async function newIdentity(seed) {
  if (seed === undefined) seed = random(32);
  if (seed.length !== 32) throw new Error("identity: seed must be 32 bytes");
  const ed = await ed25519KeyPairFromSeed(seed);
  const h = await sha512(seed);
  const dhPriv = h.slice(0, 32);
  // Clamp, exactly as dhFromSeed does: WebCrypto clamps again on use, but
  // the stored private and its public half must be the clamped scalar.
  dhPriv[0] &= 248;
  dhPriv[31] &= 127;
  dhPriv[31] |= 64;
  const dhPub = await x25519Public(dhPriv);
  return {
    seed,
    ed: { public: ed.public, privateKey: ed.privateKey },
    dh: { priv: dhPriv, pub: dhPub },
  };
}

// identityPublics is what the bundle and prekey headers carry.
export function identityPublics(id) {
  return { identityEd: id.ed.public, identityDH: id.dh.pub };
}

// NewSignedPrekey: a fresh X25519 pair with an id, per device, from 1.
export async function newSignedPrekey(id) {
  if (id < 1) throw new Error("signed prekey id must be >= 1");
  const priv = random(32);
  return { id, priv, pub: await x25519Public(priv) };
}

// NewOneTimePrekeys: n single-use X25519 pairs with ids from `from`.
export async function newOneTimePrekeys(from, n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const priv = random(32);
    out.push({ id: from + i, priv, pub: await x25519Public(priv) });
  }
  return out;
}

// signBundle signs the bundle's X25519 keys with the identity key, exactly
// IdentityKey.SignBundleKeys.
export async function signBundle(id, identityDH, signedPrekey) {
  return ed25519Sign(id.ed, bundleKeysMessage(identityDH, signedPrekey));
}

// verifyBundle checks a fetched bundle's shapes and signature, exactly
// Bundle.Verify: any failure is fatal for the peer — refuse to initiate.
export async function verifyBundle(b) {
  const bad = (what) => new Error(`bundle: ${what}`);
  if (b.identityKey.length !== 32) throw bad("identity key is not 32 bytes");
  if (b.identityDHKey.length !== 32) throw bad("identity DH key is not 32 bytes");
  if (b.signedPrekey.length !== 32) throw bad("signed prekey is not 32 bytes");
  if (b.signedPrekeySignature.length !== 64) throw bad("signature is not 64 bytes");
  if (b.signedPrekeyID < 1) throw bad("signed prekey id < 1");
  if (b.oneTimePrekey !== null && b.oneTimePrekey !== undefined && b.oneTimePrekey.key.length !== 32) {
    throw bad("one-time prekey is not 32 bytes");
  }
  const ok = await ed25519Verify(b.identityKey, b.signedPrekeySignature, bundleKeysMessage(b.identityDHKey, b.signedPrekey));
  if (!ok) throw bad("signature does not verify");
}
