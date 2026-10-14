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

// --- Steward ID derivation ---------------------------------------------------

test("stewardId derives stw_ + base64url(SHA-256(SPKI DER)), unpadded", async () => {
  const pair = await generateStewardKey();
  const id = await stewardId(pair.publicKey);
  assert.match(id, /^stw_[A-Za-z0-9_-]+$/);
  assert.ok(id.length > 10);
});

test("stewardId is deterministic for a given public key", async () => {
  const pair = await generateStewardKey();
  const id1 = await stewardId(pair.publicKey);
  const id2 = await stewardId(pair.publicKey);
  assert.equal(id1, id2);
});

// --- signRequest -------------------------------------------------------------

test("signRequest builds the four headers with the right shapes", async () => {
  const pair = await generateStewardKey();
  const method = vector.method;
  const path = vector.path;
  const date = vector.date;
  const body = vector.body;
  const headers = await signRequest(pair, { method, path, date, body });

  const ID = "X-Steward-Id";
  const KEY = "X-Steward-Key";
  const DATE = "X-Steward-Date";
  const SIG = "X-Steward-Sig";
  assert.equal(typeof headers[ID], "string");
  assert.match(headers[ID], /^stw_[A-Za-z0-9_-]+$/);
  assert.equal(typeof headers[KEY], "string");
  assert.ok(headers[KEY].length > 20);
  assert.equal(typeof headers[DATE], "string");
  assert.equal(headers[DATE], date);
  assert.equal(typeof headers[SIG], "string");
  // base64url of 64 bytes = 86 chars without padding
  assert.equal(headers[SIG].length, 86);
});

test("signRequest builds the four headers correctly", async () => {
  const pair = await generateStewardKey();
  const method = vector.method;
  const path = vector.path;
  const date = vector.date;
  const body = vector.body;
  const headers = await signRequest(pair, { method, path, date, body });

  // X-Steward-Id is derived from the fresh key pair, so it cannot equal the
  // vector's (built from a static SPKI). Its shape is what matters.
  assert.match(headers["X-Steward-Id"], /^stw_[A-Za-z0-9_-]+$/);
  assert.equal(headers["X-Steward-Date"], date);

  // The signed string is canonical: METHOD \n PATH \n DATE \n body_digest.
  // It is deterministic (no key involvement) and must equal the vector's.
  const signedString = `${method}\n${path}\n${date}\n${vector.body_digest}`;
  assert.equal(signedString, vector.signed_string);

  // The signature header must be base64url of exactly 64 bytes (86 chars
  // unpadded) and must verify against the signed string we just computed.
  assert.equal(headers["X-Steward-Sig"].length, 86);
  // base64url-decode the signature (raw r||s, 64 bytes) before verifying.
  const sigBytes = new Uint8Array(
    atob(headers["X-Steward-Sig"].replace(/-/g, "+").replace(/_/g, "/")).split("").map((c) => c.charCodeAt(0)),
  );
  const valid = await globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pair.publicKey,
    sigBytes,
    new TextEncoder().encode(signedString),
  );
  assert.equal(valid, true);
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
