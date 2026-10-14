// Writes vectors/identity/signing.json.
//
//   node tools/make_identity_vector.mjs
//
// JS, not Python: stdlib Python cannot sign ECDSA. The script imports a fixed
// P-256 key from the JWK below, builds the signed string for a register
// request, signs it with WebCrypto (raw r||s, IEEE P1363, 64 bytes -- not DER)
// and writes the vector. Binary fields are base64url, unpadded; spki_der is hex.
//
// ECDSA signatures are randomized, so X-Steward-Sig changes on every run.
// Tests verify it against the key; they do not compare it byte for byte.

import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { signRequest, stewardId } from "../pwa/identity.js";

// TEST ONLY -- NEVER DEPLOY. Fixed P-256 key used solely to produce the
// identity test vector. It identifies no one and signs nothing real.
const TEST_ONLY_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "56T5nG_dz0HqVZY_JTb6dbaU9yL2diA__ZiVo0FvTzo",
  y: "x3WqAYpcBj4-G5Bfp7x4IHQ-0dvs1VH22BtJOv8QMdE",
  d: "g_pF5xwN6wiYa06EyXAxyX6RxA3eb95kkeLBNFYv5qc",
};

const ALG = { name: "ECDSA", namedCurve: "P-256" };

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const b64url = (bytes) =>
  Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function main() {
  const subtle = globalThis.crypto.subtle;
  const privateKey = await subtle.importKey("jwk", TEST_ONLY_JWK, ALG, false, ["sign"]);
  const { d: _d, ...publicJwk } = TEST_ONLY_JWK;
  const publicKey = await subtle.importKey("jwk", publicJwk, ALG, true, ["verify"]);
  const spki = new Uint8Array(await subtle.exportKey("spki", publicKey));

  const id = await stewardId(publicKey);
  const method = "POST";
  const path = "/register";
  const date = "2026-10-12T20:00:00Z";
  const body = JSON.stringify({ steward_id: id });
  const bodyDigest = b64url(new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode(body))));
  const signedString = `${method}\n${path}\n${date}\n${bodyDigest}`;

  const headers = await signRequest({ privateKey, publicKey }, { method, path, date, body }, { includeKey: true });

  // Sanity: the signature must be 64 raw bytes and verify over signed_string.
  const sig = Buffer.from(headers["X-Steward-Sig"], "base64url");
  if (sig.length !== 64) throw new Error(`signature is ${sig.length} bytes, want 64`);
  const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, sig, new TextEncoder().encode(signedString));
  if (!ok) throw new Error("signature does not verify");

  const vector = {
    source: "tools/make_identity_vector.mjs (WebCrypto ECDSA P-256, SHA-256, raw r||s; TEST ONLY key)",
    spki_der: hex(spki),
    spki_der_b64url: b64url(spki),
    steward_id: id,
    method,
    path,
    date,
    body,
    body_digest: bodyDigest,
    signed_string: signedString,
    "X-Steward-Id": headers["X-Steward-Id"],
    "X-Steward-Key": headers["X-Steward-Key"],
    "X-Steward-Date": headers["X-Steward-Date"],
    "X-Steward-Sig": headers["X-Steward-Sig"],
  };

  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const out = join(root, "vectors", "identity", "signing.json");
  writeFileSync(out, JSON.stringify(vector, null, 2) + "\n");
  console.log(`wrote ${out}`);
}

await main();
