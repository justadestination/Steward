// RSA blind signatures, RFC 9474. Counterpart of steward/blind.py: same bytes.
//
// The phone runs prepare + blind before activation and finalize after it.
// blindSign is here only so tests and the parity vectors can run end to end;
// the real signer is the server's age checker.
//
// SHA-384 comes from WebCrypto (async). Integers are BigInt. `salt` and `r`
// options exist only to reproduce the RFC 9474 Appendix A vectors.

export class BlindError extends Error {}

const H_LEN = 48;
const SALT_LEN = 48;
const PREFIX_LEN = 32;

const subtle = globalThis.crypto.subtle;
const sha384 = async (bytes) => new Uint8Array(await subtle.digest("SHA-384", bytes));
const randomBytes = (len) => globalThis.crypto.getRandomValues(new Uint8Array(len));

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

const bitLength = (n) => n.toString(2).length;
const modulusLen = (n) => Math.ceil(bitLength(n) / 8);

function os2ip(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

function i2osp(x, len) {
  if (x < 0n || x >= 1n << BigInt(8 * len)) throw new BlindError("integer too large");
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function gcd(a, b) {
  while (b) [a, b] = [b, a % b];
  return a;
}

function modInverse(a, n) {
  let [r0, r1, s0, s1] = [a % n, n, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new BlindError("not invertible");
  return ((s0 % n) + n) % n;
}

function randomBelow(n) {
  // Uniform in [1, n): rejection sampling on whole bytes.
  const len = modulusLen(n);
  for (;;) {
    const x = os2ip(randomBytes(len)) % (1n << BigInt(bitLength(n)));
    if (x >= 1n && x < n) return x;
  }
}

async function mgf1(seed, length) {
  const parts = [];
  let total = 0;
  for (let counter = 0; total < length; counter++) {
    const c = new Uint8Array([counter >>> 24, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff]);
    const block = await sha384(concat(seed, c));
    parts.push(block);
    total += block.length;
  }
  return concat(...parts).slice(0, length);
}

/** RFC 9474 §4.1. Randomized: 32 random bytes before the message. */
export function prepare(msg, { randomize = true, prefix = null } = {}) {
  if (!randomize) return Uint8Array.from(msg);
  const p = prefix ?? randomBytes(PREFIX_LEN);
  if (p.length !== PREFIX_LEN) throw new BlindError("prefix must be 32 bytes");
  return concat(p, msg);
}

/** RFC 8017 §9.1.1, SHA-384 + MGF1-SHA-384. */
export async function emsaPssEncode(msg, emBits, salt) {
  const emLen = Math.ceil(emBits / 8);
  if (emLen < H_LEN + salt.length + 2) throw new BlindError("encoding error");
  const mHash = await sha384(msg);
  const h = await sha384(concat(new Uint8Array(8), mHash, salt));
  const db = concat(new Uint8Array(emLen - salt.length - H_LEN - 2), new Uint8Array([1]), salt);
  const mask = await mgf1(h, emLen - H_LEN - 1);
  const masked = db.map((b, i) => b ^ mask[i]);
  masked[0] &= 0xff >> (8 * emLen - emBits);
  return concat(masked, h, new Uint8Array([0xbc]));
}

async function emsaPssVerify(msg, em, emBits, sLen) {
  const emLen = Math.ceil(emBits / 8);
  if (em.length !== emLen || emLen < H_LEN + sLen + 2 || em[em.length - 1] !== 0xbc) return false;
  const masked = em.slice(0, emLen - H_LEN - 1);
  const h = em.slice(emLen - H_LEN - 1, emLen - 1);
  const topBits = 8 * emLen - emBits;
  if (masked[0] & (0xff << (8 - topBits)) & 0xff) return false;
  const mask = await mgf1(h, emLen - H_LEN - 1);
  const db = masked.map((b, i) => b ^ mask[i]);
  db[0] &= 0xff >> topBits;
  const padLen = emLen - H_LEN - sLen - 2;
  for (let i = 0; i < padLen; i++) if (db[i] !== 0) return false;
  if (db[padLen] !== 1) return false;
  const salt = sLen ? db.slice(db.length - sLen) : new Uint8Array(0);
  const want = await sha384(concat(new Uint8Array(8), await sha384(msg), salt));
  let diff = 0;
  for (let i = 0; i < H_LEN; i++) diff |= want[i] ^ h[i];
  return diff === 0;
}

/** RFC 9474 §4.2. Returns { blindedMsg, inv } as modulus-length bytes. */
export async function blind(n, e, preparedMsg, { sLen = SALT_LEN, salt = null, r = null } = {}) {
  const k = modulusLen(n);
  const s = salt ?? randomBytes(sLen);
  if (s.length !== sLen) throw new BlindError("salt length mismatch");
  const m = os2ip(await emsaPssEncode(preparedMsg, bitLength(n) - 1, s));
  if (gcd(m, n) !== 1n) throw new BlindError("invalid input");
  let factor = r;
  if (factor === null) {
    do factor = randomBelow(n);
    while (gcd(factor, n) !== 1n);
  } else if (factor < 1n || factor >= n || gcd(factor, n) !== 1n) {
    throw new BlindError("invalid blinding factor");
  }
  const inv = modInverse(factor, n);
  const z = (m * modPow(factor, e, n)) % n;
  return { blindedMsg: i2osp(z, k), inv: i2osp(inv, k) };
}

/** RFC 9474 §4.3. Test and parity use only; the real signer is the server. */
export function blindSign(n, e, d, blindedMsg) {
  const k = modulusLen(n);
  if (blindedMsg.length !== k) throw new BlindError("unexpected input size");
  const m = os2ip(blindedMsg);
  if (m >= n) throw new BlindError("invalid message length");
  const s = modPow(m, d, n);
  if (modPow(s, e, n) !== m) throw new BlindError("signing failure");
  return i2osp(s, k);
}

/** RSASSA-PSS-VERIFY over the prepared message. */
export async function verify(n, e, preparedMsg, sig, { sLen = SALT_LEN } = {}) {
  const k = modulusLen(n);
  if (sig.length !== k) return false;
  const s = os2ip(sig);
  if (s >= n) return false;
  const emBits = bitLength(n) - 1;
  const emLen = Math.ceil(emBits / 8);
  const m = modPow(s, e, n);
  if (m >= 1n << BigInt(8 * emLen)) return false;
  return emsaPssVerify(preparedMsg, i2osp(m, emLen), emBits, sLen);
}

/** RFC 9474 §4.4. Unblinds; refuses a signature that does not verify. */
export async function finalize(n, e, preparedMsg, blindSig, inv, { sLen = SALT_LEN } = {}) {
  const k = modulusLen(n);
  if (blindSig.length !== k || inv.length !== k) throw new BlindError("unexpected input size");
  const sig = i2osp((os2ip(blindSig) * os2ip(inv)) % n, k);
  if (!(await verify(n, e, preparedMsg, sig, { sLen }))) throw new BlindError("invalid signature");
  return sig;
}
