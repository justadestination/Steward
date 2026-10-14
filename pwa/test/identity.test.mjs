// Steward identity: key generation, Steward ID, and signed-request signing.
// Counterpart of steward/identity.py.
//
// The phone generates an ECDSA P-256 key pair with WebCrypto,
//   generateKey({name:'ECDSA',namedCurve:'P-256'}, false, ['sign','verify'])
// with extractable=false, so the private key is never transcribable.
// The Steward ID is stw_ + base64url(SHA-256(SPKI DER of the public key)),
// unpadded. The private half never leaves the phone.
//
// Signed request
//   Headers: X-Steward-Id, X-Steward-Key (base64url SPKI, only on register),
//            X-Steward-Date (UTC YYYY-MM-DDTHH:MM:SSZ),
//            X-Steward-Sig (base64url raw r||s, 64 bytes).
//   Signed string: METHOD \n PATH \n DATE \n base64url(SHA-256(body bytes)),
//   UTF-8, no trailing newline. The Steward derives the Steward ID from the
//   SPKI DER and the server verifies the signature with `cryptography`.
//
// CryptoKey objects are structured-cloneable, so the pair can be persisted in
// IndexedDB. createStewardKey() generates and persists the pair on first
// launch; loadStewardKey()/persistStewardKey() move it across runs.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  generateStewardKey,
  loadStewardKey,
  persistStewardKey,
  stewardId,
  signRequest,
} from "../identity.js";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const json = (path) => JSON.parse(readFileSync(join(root, path), "utf-8"));
const vector = json("vectors/identity/signing.json");

const b64urlDecode = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

// --- Steward ID derivation ---------------------------------------------------

test("stewardId derives stw_ + base64url(SHA-256(SPKI DER)), unpadded", async () => {
  const pair = await generateStewardKey();
  const id = await stewardId(pair.publicKey);
  assert.match(id, /^stw_[A-Za-z0-9_-]{43}$/);
});

test("stewardId is deterministic for a given public key", async () => {
  const pair = await generateStewardKey();
  const id1 = await stewardId(pair.publicKey);
  const id2 = await stewardId(pair.publicKey);
  assert.equal(id1, id2);
});

test("two generated keys give two different Steward IDs", async () => {
  const a = await generateStewardKey();
  const b = await generateStewardKey();
  assert.notEqual(await stewardId(a.publicKey), await stewardId(b.publicKey));
});

test("stewardId is not the SHA-256 of an empty SPKI", async () => {
  // stw_ + base64url(SHA-256("")): what every key yielded when exportKey was
  // not awaited.
  const pair = await generateStewardKey();
  assert.notEqual(await stewardId(pair.publicKey), "stw_47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
});

test("parity: stewardId of the vector's SPKI equals the vector's steward_id (as Python's steward_id)", async () => {
  const imported = await globalThis.crypto.subtle.importKey(
    "spki", fromHex(vector.spki_der), ECDSA_P256, true, ["verify"],
  );
  assert.equal(await stewardId(imported), vector.steward_id);
  assert.equal(vector["X-Steward-Id"], vector.steward_id);
});

// --- vector: raw r||s signature, base64url fields -----------------------------

test("vector: X-Steward-Key is base64url SPKI equal to spki_der", () => {
  assert.doesNotMatch(vector["X-Steward-Key"], /[+/=]/);
  assert.deepEqual(b64urlDecode(vector["X-Steward-Key"]), fromHex(vector.spki_der));
  assert.equal(vector.spki_der_b64url, vector["X-Steward-Key"]);
  assert.equal(vector.spki_der_b64, undefined);
});

test("vector: X-Steward-Sig is 64 raw bytes (r||s) and verifies over signed_string", async () => {
  assert.doesNotMatch(vector["X-Steward-Sig"], /[+/=]/);
  const sig = b64urlDecode(vector["X-Steward-Sig"]);
  assert.equal(sig.length, 64);
  const key = await globalThis.crypto.subtle.importKey(
    "spki", b64urlDecode(vector["X-Steward-Key"]), ECDSA_P256, true, ["verify"],
  );
  const ok = await globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, sig, new TextEncoder().encode(vector.signed_string),
  );
  assert.equal(ok, true);
  // A different string must not verify.
  const bad = await globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, sig, new TextEncoder().encode(vector.signed_string + "x"),
  );
  assert.equal(bad, false);
});

test("vector: signed_string is METHOD \\n PATH \\n DATE \\n body_digest", () => {
  assert.equal(
    vector.signed_string,
    `${vector.method}\n${vector.path}\n${vector.date}\n${vector.body_digest}`,
  );
});

// --- signRequest -------------------------------------------------------------

async function verifyHeaders(pair, headers, signedString) {
  const sig = b64urlDecode(headers["X-Steward-Sig"]);
  assert.equal(sig.length, 64);
  return globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, pair.publicKey, sig, new TextEncoder().encode(signedString),
  );
}

test("signRequest without includeKey omits X-Steward-Key and signs the canonical string", async () => {
  const pair = await generateStewardKey();
  const { method, path, date, body } = vector;
  const headers = await signRequest(pair, { method, path, date, body });

  assert.deepEqual(Object.keys(headers).sort(), ["X-Steward-Date", "X-Steward-Id", "X-Steward-Sig"]);
  assert.equal(headers["X-Steward-Id"], await stewardId(pair.publicKey));
  assert.equal(headers["X-Steward-Date"], date);
  // base64url of 64 bytes = 86 chars without padding
  assert.equal(headers["X-Steward-Sig"].length, 86);
  assert.equal(await verifyHeaders(pair, headers, vector.signed_string), true);
});

test("signRequest with includeKey (register) adds X-Steward-Key matching X-Steward-Id", async () => {
  const pair = await generateStewardKey();
  const { method, path, date, body } = vector;
  const headers = await signRequest(pair, { method, path, date, body }, { includeKey: true });

  assert.deepEqual(
    Object.keys(headers).sort(),
    ["X-Steward-Date", "X-Steward-Id", "X-Steward-Key", "X-Steward-Sig"],
  );
  assert.doesNotMatch(headers["X-Steward-Key"], /[+/=]/);
  const imported = await globalThis.crypto.subtle.importKey(
    "spki", b64urlDecode(headers["X-Steward-Key"]), ECDSA_P256, true, ["verify"],
  );
  assert.equal(await stewardId(imported), headers["X-Steward-Id"]);
  assert.equal(await verifyHeaders(pair, headers, vector.signed_string), true);
});

// --- key persistence (only when IndexedDB is available, as in the PWA) --------

if (typeof globalThis.indexedDB !== "undefined") {
  test("persistStewardKey and loadStewardKey round-trip a key pair", async () => {
    const pair = await generateStewardKey();
    await persistStewardKey(pair);
    const loaded = await loadStewardKey();
    // CryptoKey objects are structured-cloneable, so equality of the public key
    // bytes is enough for this test.
    const pub1 = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", pair.publicKey));
    const pub2 = new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", loaded.publicKey));
    assert.deepEqual(pub1, pub2);
  });
}

test("generateStewardKey returns an ECDSA P-256 pair with a non-extractable private key", async () => {
  const pair = await generateStewardKey();
  assert.equal(pair.publicKey.type, "public");
  assert.equal(pair.privateKey.extractable, false);
  assert.equal(pair.publicKey.algorithm.name, "ECDSA");
  assert.equal(pair.publicKey.algorithm.namedCurve, "P-256");
  assert.deepEqual(pair.privateKey.algorithm, pair.publicKey.algorithm);
});
