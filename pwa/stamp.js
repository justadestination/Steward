// Proof of work for mail to @dontwastemytime (R8). Counterpart of
// steward/stamp.py: same bytes, same check. The app mints; the server verifies.
//
// A stamp identifies no one: { v: 1, at, nonce }.
//
// SHA-256 is implemented here because WebCrypto's digest() is async, one
// promise per hash, which is far too slow for ~260k tries. Tests check this
// implementation against node:crypto.

import { minutesBetween } from "./engine.js";

export class StampError extends Error {}

const PREFIX = "shadenet-stamp-v1\n";
const MAIL_ID = /^[A-Za-z0-9_-]{1,64}$/;
const NONCE = /^[0-9a-f]{1,16}$/;
const CLOCK_SKEW_MINUTES = 2;
const utf8 = new TextEncoder();

// ---- SHA-256 (FIPS 180-4) ------------------------------------------------------

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const W = new Uint32Array(64);
const H = new Uint32Array(8);
let PAD = new Uint8Array(1024);

// Hashes PAD[0..len) into H. The caller has written the message into PAD.
// Padding is written in place after `len`, so bytes before it are untouched:
// mint() writes the fixed part of the message once and only rewrites the nonce.
function digestPad(len) {
  const padLen = ((len + 9 + 63) >> 6) << 6;
  PAD.fill(0, len, padLen);
  PAD[len] = 0x80;
  const bitLen = len * 8;
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  PAD[padLen - 8] = hi >>> 24; PAD[padLen - 7] = hi >>> 16; PAD[padLen - 6] = hi >>> 8; PAD[padLen - 5] = hi;
  PAD[padLen - 4] = lo >>> 24; PAD[padLen - 3] = lo >>> 16; PAD[padLen - 2] = lo >>> 8; PAD[padLen - 1] = lo;

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0, o = off; i < 16; i++, o += 4) {
      W[i] = (PAD[o] << 24) | (PAD[o + 1] << 16) | (PAD[o + 2] << 8) | PAD[o + 3];
    }
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  H[0] = h0; H[1] = h1; H[2] = h2; H[3] = h3; H[4] = h4; H[5] = h5; H[6] = h6; H[7] = h7;
}

function ensurePad(len) {
  const need = (((len + 9 + 63) >> 6) << 6);
  if (PAD.length < need) {
    const bigger = new Uint8Array(need * 2);
    bigger.set(PAD);
    PAD = bigger;
  }
}

export function sha256(bytes) {
  ensurePad(bytes.length);
  PAD.set(bytes);
  digestPad(bytes.length);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = H[i] >>> 24; out[i * 4 + 1] = H[i] >>> 16; out[i * 4 + 2] = H[i] >>> 8; out[i * 4 + 3] = H[i];
  }
  return out;
}

// Leading zero bits of the digest in H, without building it.
function stateZeroBits() {
  let bits = 0;
  for (let i = 0; i < 8; i++) {
    if (H[i] === 0) { bits += 32; continue; }
    return bits + Math.clz32(H[i]);
  }
  return bits;
}

// ---- stamp ----------------------------------------------------------------------

// Length-prefixed, so no two different messages share a preimage. null is "~".
function field(value) {
  if (value === null) return "~";
  if (!value.isWellFormed()) throw new StampError("text is not valid Unicode");
  return `${utf8.encode(value).length}:${value}`;
}

export function preimage(mail, at, nonce) {
  return utf8.encode(PREFIX + [mail.mail_id, mail.case_id, mail.text, at, nonce].map(field).join(""));
}

export function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) { bits += 8; continue; }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

export function checkMail(mail) {
  const keys = mail && typeof mail === "object" ? Object.keys(mail).sort().join(",") : "";
  if (keys !== "case_id,mail_id,text") throw new StampError("mail keys must be exactly case_id, mail_id, text");
  if (typeof mail.mail_id !== "string" || !MAIL_ID.test(mail.mail_id)) throw new StampError("mail_id must be 1-64 of A-Z a-z 0-9 _ -");
  if (mail.case_id !== null && typeof mail.case_id !== "string") throw new StampError("case_id must be a string or null");
  if (typeof mail.text !== "string" || mail.text === "") throw new StampError("text must be a non-empty string");
}

// Runs in the app when the ward presses send. `at` is the send time.
// The fixed part of the preimage is written once; each try rewrites only
// the nonce field ("<len>:<hex>") after it.
export function mint(mail, at, bits) {
  checkMail(mail);
  minutesBetween(at, at); // validates the timestamp form
  const fixed = utf8.encode(PREFIX + [mail.mail_id, mail.case_id, mail.text, at].map(field).join(""));
  ensurePad(fixed.length + 32);
  PAD.set(fixed);
  for (let n = 0; ; n++) {
    const nonce = n.toString(16);
    const tail = `${nonce.length}:${nonce}`;
    for (let i = 0; i < tail.length; i++) PAD[fixed.length + i] = tail.charCodeAt(i);
    digestPad(fixed.length + tail.length);
    if (stateZeroBits() >= bits) return { v: 1, at, nonce };
  }
}

// The server's check, mirrored so the app can test itself and the vectors can
// prove both sides agree.
export function verify(mail, stamp, arrivedAt, houseRules) {
  checkMail(mail);
  const keys = stamp && typeof stamp === "object" ? Object.keys(stamp).sort().join(",") : "";
  if (keys !== "at,nonce,v") throw new StampError("stamp keys must be exactly at, nonce, v");
  if (stamp.v !== 1) throw new StampError("unknown stamp version"); // true !== 1, matching Python
  if (typeof stamp.nonce !== "string" || !NONCE.test(stamp.nonce)) throw new StampError("nonce must be 1-16 lowercase hex digits");
  let age;
  try {
    age = minutesBetween(stamp.at, arrivedAt);
  } catch (err) {
    throw new StampError(`stamp time: ${err.message}`);
  }
  const p = houseRules.parameters;
  if (age > p.operator_stamp_max_age_minutes) throw new StampError("stamp is too old");
  if (age < -CLOCK_SKEW_MINUTES) throw new StampError("stamp is from the future");
  if (leadingZeroBits(sha256(preimage(mail, stamp.at, stamp.nonce))) < p.operator_stamp_bits) {
    throw new StampError("not enough work");
  }
}

// Turns operator_line's forward_to_operators output into the request the
// server's door expects (steward/door.py). The transport adds steward_id from
// the Steward's signature; the web form sends null.
export function operatorMailRequest(output, mailId, at, houseRules, stewardId = null) {
  if (output.kind !== "forward_to_operators") throw new StampError(`not operator mail: ${output.kind}`);
  const mail = { mail_id: mailId, case_id: output.case_id, text: output.text };
  return { mail, stamp: mint(mail, at, houseRules.parameters.operator_stamp_bits), steward_id: stewardId };
}
