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
// IndexedDB. createStewardKey() generates the pair and persists it; a pure
// generateStewardKey() is provided for tests and for callers that persist
// themselves.

const DB_NAME = "steward-identity";
const STEWARD_KEY_STORE = "steward-key";

function _db() {
  return new Promise((resolve, reject) => {
    if (typeof globalThis.indexedDB === "undefined") {
      reject(new Error("indexedDB not available"));
      return;
    }
    const req = globalThis.indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STEWARD_KEY_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function _tx(db, mode) {
  return db.transaction(STEWARD_KEY_STORE, mode);
}

export async function generateStewardKey() {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // extractable = false: private key never leaves the phone
    ["sign", "verify"],
  );
  return keyPair;
}

export async function createStewardKey() {
  const keyPair = await generateStewardKey();
  await persistStewardKey(keyPair);
  return keyPair;
}

export async function loadStewardKey() {
  const db = await _db();
  return new Promise((resolve, reject) => {
    const tx = _tx(db, "readonly");
    const req = tx.objectStore(STEWARD_KEY_STORE).get("key");
    req.onsuccess = () => {
      if (req.result === undefined) reject(new Error("no steward key persisted"));
      else resolve(req.result);
    };
    req.onerror = () => reject(req.error);
  });
}

export async function persistStewardKey(keyPair) {
  const db = await _db();
  return new Promise((resolve, reject) => {
    const tx = _tx(db, "readwrite");
    tx.objectStore(STEWARD_KEY_STORE).put(keyPair, "key");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function stewardId(publicKey) {
  const spki = new Uint8Array(globalThis.crypto.subtle.exportKey("spki", publicKey));
  const digest = await sha256(spki);
  return "stw_" + base64Url(digest);
}

export async function signRequest(keyPair, { method, path, date, body }) {
  const message = new TextEncoder().encode(
    `${method}\n${path}\n${date}\n${await base64UrlDigest(body)}`,
  );
  const sig = new Uint8Array(
    await globalThis.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, message),
  );
  return {
    "X-Steward-Id": await stewardId(keyPair.publicKey),
    "X-Steward-Key": base64Url(new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey))),
    "X-Steward-Date": date,
    "X-Steward-Sig": base64Url(sig),
  };
}

// ---- helpers ---------------------------------------------------------------

function base64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(bytes) {
  const hash = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(hash);
}

async function base64UrlDigest(body) {
  const bytes = new Uint8Array(body instanceof Uint8Array ? body : new TextEncoder().encode(body));
  return base64Url(await sha256(bytes));
}
