// RSA blind signatures (RFC 9474) in the PWA: same bytes as steward/blind.py.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { BlindError, blind, blindSign, emsaPssEncode, finalize, prepare, verify } from "../blind.js";

const root = new URL("../../", import.meta.url);
const { vectors } = JSON.parse(readFileSync(new URL("vectors/blind/rfc9474.json", root), "utf-8"));
const hex = (s) => Uint8Array.from((s || "").match(/../g) || [], (b) => parseInt(b, 16));
const toHex = (u8) => Buffer.from(u8).toString("hex");
const big = (s) => BigInt(`0x${s}`);
const modInverse = (a, n) => {
  let [r0, r1, s0, s1] = [a % n, n, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ((s0 % n) + n) % n;
};

for (const v of vectors) {
  test(`RFC 9474 ${v.section} ${v.name}: every step`, async () => {
    const [n, e, d] = [big(v.n), big(v.e), big(v.d)];
    const salt = hex(v.salt);
    const sLen = salt.length;
    const prepared = hex(v.prepared_msg);

    if (v.msg_prefix) assert.equal(toHex(prepare(hex(v.msg), { prefix: hex(v.msg_prefix) })), v.prepared_msg);
    else assert.equal(toHex(prepare(hex(v.msg), { randomize: false })), v.prepared_msg);

    const emBits = n.toString(2).length - 1;
    assert.equal(toHex(await emsaPssEncode(prepared, emBits, salt)), v.encoded_msg);

    const r = modInverse(big(v.inv), n);
    const { blindedMsg, inv } = await blind(n, e, prepared, { sLen, salt, r });
    assert.equal(toHex(blindedMsg), v.blinded_msg);
    assert.equal(toHex(inv), v.inv);

    const blindSig = blindSign(n, e, d, blindedMsg);
    assert.equal(toHex(blindSig), v.blind_sig);

    const sig = await finalize(n, e, prepared, blindSig, inv, { sLen });
    assert.equal(toHex(sig), v.sig);
    assert.equal(await verify(n, e, prepared, sig, { sLen }), true);
  });
}

test("random round trip and tampering", async () => {
  const v = vectors[0];
  const [n, e, d] = [big(v.n), big(v.e), big(v.d)];
  const prepared = prepare(new TextEncoder().encode("stw_example-steward-id"));
  assert.equal(prepared.length, 32 + 22);
  const { blindedMsg, inv } = await blind(n, e, prepared);
  const sig = await finalize(n, e, prepared, blindSign(n, e, d, blindedMsg), inv);
  assert.equal(await verify(n, e, prepared, sig), true);
  const flipped = Uint8Array.from(sig);
  flipped[0] ^= 1;
  assert.equal(await verify(n, e, prepared, flipped), false);
  const badBlind = Uint8Array.from(blindSign(n, e, d, blindedMsg));
  badBlind[0] ^= 1;
  await assert.rejects(finalize(n, e, prepared, badBlind, inv), BlindError);
});

const { cases } = JSON.parse(readFileSync(new URL("vectors/blind/cross.json", root), "utf-8"));
for (const [i, c] of cases.entries()) {
  test(`cross vector ${i + 1}: same bytes as Python`, async () => {
    const v = vectors[0];
    const [n, e, d] = [big(v.n), big(v.e), big(v.d)];
    const prepared = prepare(hex(c.msg), { prefix: hex(c.msg_prefix) });
    assert.equal(toHex(prepared), c.prepared_msg);
    const { blindedMsg, inv } = await blind(n, e, prepared, { salt: hex(c.salt), r: big(c.r) });
    assert.equal(toHex(blindedMsg), c.blinded_msg);
    assert.equal(toHex(inv), c.inv);
    assert.equal(toHex(blindSign(n, e, d, blindedMsg)), c.blind_sig);
    assert.equal(toHex(await finalize(n, e, prepared, hex(c.blind_sig), inv)), c.sig);
  });
}
