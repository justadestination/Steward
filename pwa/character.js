// The Steward's signed character file, for the PWA.
// Counterpart of steward/character.py.
//
// The House signs the character file with Ed25519 (House key on the server).
// A signed file is
//   { character: {...}, fingerprint: "<base64url SHA-256>", signature: "<base64url, 64 bytes>" }
// and the signature covers canonical(character) as UTF-8 bytes.
//
// fingerprint(obj) = base64url, unpadded, of SHA-256 over canonical(obj)
// (`canonical` from engine.js), the same bytes as steward/character.py;
// vectors/character/fingerprint.json pins both.
//
// Restore on connect (graph `restore`):
//   1. Send `connect` with local_fingerprint (this copy) and house_fingerprint
//      (from the /connect reply). Equal -> in_sync.
//   2. Otherwise the graph waits in `restore`. The runner calls
//      verifyCharacter(signedFile, housePublicKeyRaw) on the House's signed
//      file. ONLY IF it returns a character does the runner replace the local
//      copy and send the `restore` event (payload: its fingerprint) to the
//      graph. A file that fails verification is dropped and no `restore`
//      event is sent; the graph stays in `restore`.
// The reader profile is never read or written by any of this.

import { canonical } from "./engine.js";

const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);

const b64url = (bytes) => {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const fromB64url = (text) => {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

// UTF-8 bytes of canonical(obj).
export const canonicalBytes = (obj) => new TextEncoder().encode(canonical(obj));

export async function fingerprint(obj) {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalBytes(obj))));
}

// Returns the character if `signed.signature` is a valid Ed25519 signature by
// the House key over canonical(signed.character) AND signed.fingerprint is
// that character's fingerprint. Returns null otherwise, never throws.
export async function verifyCharacter(signed, housePublicKeyRaw) {
  try {
    if (!isObject(signed) || !isObject(signed.character)) return null;
    if (typeof signed.fingerprint !== "string") return null;
    const sig = fromB64url(signed.signature);
    if (sig.length !== 64) return null;
    const key = await crypto.subtle.importKey("raw", housePublicKeyRaw, { name: "Ed25519" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, canonicalBytes(signed.character));
    if (!ok) return null;
    if ((await fingerprint(signed.character)) !== signed.fingerprint) return null;
    return structuredClone(signed.character);
  } catch {
    return null;
  }
}
