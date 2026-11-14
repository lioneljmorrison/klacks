// ChaCha20-Poly1305 interop: the JS implementation must produce exactly the
// Go reference's ciphertexts (client/envelope.go), and open them back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { seal, open } from "../web/js/chacha.mjs";
import { hexBytes, unbase64 } from "../web/js/keys.mjs";

const vectors = JSON.parse(
  await readFile(path.join(path.dirname(fileURLToPath(import.meta.url)), "testdata/vectors.json"), "utf8")
);

test("chacha20poly1305 seal matches the Go reference", async () => {
  for (const [i, v] of vectors.chacha.entries()) {
    const ct = seal(hexBytes(v.key), hexBytes(v.nonce), unbase64(v.aad), unbase64(v.pt));
    assert.deepEqual(ct, unbase64(v.ct), `case ${i}: ciphertext differs from Go`);
  }
});

test("chacha20poly1305 open verifies and decrypts Go's ciphertexts", async () => {
  for (const [i, v] of vectors.chacha.entries()) {
    const pt = open(hexBytes(v.key), hexBytes(v.nonce), unbase64(v.aad), unbase64(v.ct));
    assert.deepEqual(pt, unbase64(v.pt), `case ${i}: plaintext differs`);
  }
});

test("chacha20poly1305 open rejects a tampered tag", () => {
  const v = vectors.chacha[0];
  const sealed = unbase64(v.ct);
  sealed[sealed.length - 1] ^= 0xff;
  assert.throws(() => open(hexBytes(v.key), hexBytes(v.nonce), unbase64(v.aad), sealed));
});

test("chacha20poly1305 open rejects a tampered aad", () => {
  const v = vectors.chacha[0];
  const aad = unbase64(v.aad);
  aad[0] ^= 0xff;
  assert.throws(() => open(hexBytes(v.key), hexBytes(v.nonce), aad, unbase64(v.ct)));
});
