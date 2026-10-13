// R8 proof of work: the app's SHA-256 and stamp checks must agree with Python.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { StampError, mint, operatorMailRequest, sha256, verify } from "../stamp.js";

const root = new URL("../../", import.meta.url);
const json = (path) => JSON.parse(readFileSync(new URL(path, root), "utf-8"));
const rules = json("policy/house_rules.json");
const { cases } = json("vectors/stamps/cases.json");

test("sha256 matches node:crypto across block boundaries", () => {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 300, 1000]) {
    const bytes = new Uint8Array(len).map((_, i) => (i * 31 + len) & 0xff);
    const want = createHash("sha256").update(bytes).digest("hex");
    assert.equal(Buffer.from(sha256(bytes)).toString("hex"), want, `length ${len}`);
  }
});

for (const c of cases) {
  test(`stamp: ${c.name}`, () => {
    const r = { parameters: { operator_stamp_bits: c.bits, operator_stamp_max_age_minutes: c.max_age_minutes } };
    if (c.error === null) {
      verify(c.mail, c.stamp, c.arrived_at, r);
    } else {
      assert.throws(() => verify(c.mail, c.stamp, c.arrived_at, r), (err) => err instanceof StampError && err.message.includes(c.error));
    }
  });
}

test("the app mints at the posted difficulty, deterministically, and it verifies", () => {
  const out = { kind: "forward_to_operators", text: "about my case", case_id: "case-x3" };
  const t0 = performance.now();
  const req = operatorMailRequest(out, "m-42", "2026-10-13T20:00:00Z", rules);
  const ms = performance.now() - t0;
  verify(req.mail, req.stamp, "2026-10-13T20:01:00Z", rules);
  assert.deepEqual(req, operatorMailRequest(out, "m-42", "2026-10-13T20:00:00Z", rules));
  assert.equal(req.steward_id, null);
  console.log(`  minted ${rules.parameters.operator_stamp_bits}-bit stamp (nonce ${req.stamp.nonce}) in ${ms.toFixed(0)} ms`);
});

test("only operator mail can be stamped", () => {
  assert.throws(() => operatorMailRequest({ kind: "say", message: "x" }, "m", "2026-10-13T20:00:00Z", rules), StampError);
});
