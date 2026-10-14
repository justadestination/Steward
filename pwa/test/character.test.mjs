// Signed character file: canonical bytes, fingerprint, Ed25519 verification,
// and the restore graph gated on verification, through the shared engine.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { canonical, eventFromDict, loadGraph, start, step } from "../engine.js";
import { canonicalBytes, fingerprint, verifyCharacter } from "../character.js";
import { makeRegistry } from "../registry.js";

const root = new URL("../../", import.meta.url);
const json = (path) => JSON.parse(readFileSync(new URL(path, root), "utf-8"));
const vector = json("vectors/character/fingerprint.json");
const cases = Object.fromEntries(vector.cases.map((c) => [c.name, c]));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

// TEST ONLY: a throwaway House key generated per run. Never a real key.
async function testHouseKey() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { pair, raw };
}

async function signCharacter(privateKey, character) {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, canonicalBytes(character)));
  return { character, fingerprint: await fingerprint(character), signature: b64url(sig) };
}

for (const c of vector.cases) {
  test(`canonical + fingerprint match vector: ${c.name}`, async () => {
    assert.equal(hex(new TextEncoder().encode(canonical(c.character))), c.canonical_hex);
    assert.equal(hex(canonicalBytes(c.character)), c.canonical_hex);
    assert.equal(await fingerprint(c.character), c.fingerprint);
  });
}

test("the character file is the skeleton in the vector", async () => {
  const file = json("steward/data/character.json");
  assert.deepStrictEqual(file, cases.skeleton.character);
  assert.equal(await fingerprint(file), cases.skeleton.fingerprint);
});

test("verifyCharacter accepts a file signed by the House key", async () => {
  const { pair, raw } = await testHouseKey();
  const signed = await signCharacter(pair.privateKey, cases.non_ascii.character);
  assert.equal(signed.fingerprint, cases.non_ascii.fingerprint);
  assert.deepStrictEqual(await verifyCharacter(signed, raw), cases.non_ascii.character);
});

test("verifyCharacter rejects a tampered character", async () => {
  const { pair, raw } = await testHouseKey();
  const signed = await signCharacter(pair.privateKey, cases.skeleton.character);
  const tampered = structuredClone(signed);
  tampered.character.voice = { tampered: "yes" };
  assert.equal(await verifyCharacter(tampered, raw), null);
  // Re-fingerprinting the tampered copy does not help: the signature still fails.
  tampered.fingerprint = await fingerprint(tampered.character);
  assert.equal(await verifyCharacter(tampered, raw), null);
});

test("verifyCharacter rejects a wrong fingerprint even with a good signature", async () => {
  const { pair, raw } = await testHouseKey();
  const signed = await signCharacter(pair.privateKey, cases.skeleton.character);
  assert.equal(await verifyCharacter({ ...signed, fingerprint: cases.non_ascii.fingerprint }, raw), null);
});

test("verifyCharacter rejects a wrong key and malformed input", async () => {
  const house = await testHouseKey();
  const other = await testHouseKey();
  const signed = await signCharacter(house.pair.privateKey, cases.skeleton.character);
  assert.equal(await verifyCharacter(signed, other.raw), null);
  assert.equal(await verifyCharacter(signed, new Uint8Array(31)), null);
  assert.equal(await verifyCharacter({ ...signed, signature: "not base64url!" }, house.raw), null);
  assert.equal(await verifyCharacter({ ...signed, signature: b64url(new Uint8Array(63)) }, house.raw), null);
  assert.equal(await verifyCharacter(null, house.raw), null);
});

// ---- restore graph on the phone ---------------------------------------------

const signalValues = json("steward/data/signals.json");
const registry = makeRegistry(signalValues);
const restoreGraph = () => loadGraph(json("steward/graphs/restore.json"), registry);

test("restore graph loads in the PWA (fingerprint_matches is registered)", () => {
  assert.equal(restoreGraph().name, "restore");
  assert.equal(typeof registry.conditions.fingerprint_matches, "function");
  assert.equal(registry.conditions.presentation_valid_and_over_21, undefined);
});

// Runs the shared restore-mismatch vector the way the runner must: the
// `restore` event goes to the graph only after verifyCharacter succeeds.
async function runGated(signed, houseKeyRaw) {
  const v = json("vectors/restore-mismatch.json");
  const g = restoreGraph();
  let s = start(g, v.instance, v.context);
  const records = [s.record];
  const [connect, restore] = v.events;
  s = step(g, s.instance, eventFromDict(connect), v.policy, signalValues, registry);
  records.push(s.record);
  assert.equal(s.instance.state, "restore");
  const accepted = await verifyCharacter(signed, houseKeyRaw);
  if (accepted !== null) {
    assert.equal(restore.payload.fingerprint, await fingerprint(accepted));
    s = step(g, s.instance, eventFromDict(restore), v.policy, signalValues, registry);
    records.push(s.record);
  }
  return { v, records, state: s.instance.state };
}

test("mismatch -> restore -> in_sync, only after verification (matches shared vector)", async () => {
  const { pair, raw } = await testHouseKey();
  const signed = await signCharacter(pair.privateKey, cases.skeleton.character);
  const { v, records, state } = await runGated(signed, raw);
  assert.equal(state, "in_sync");
  assert.deepStrictEqual(records, v.expected);
});

test("a file that fails verification never reaches the graph", async () => {
  const house = await testHouseKey();
  const other = await testHouseKey();
  const signed = await signCharacter(other.pair.privateKey, cases.skeleton.character);
  const { v, records, state } = await runGated(signed, house.raw);
  assert.equal(state, "restore");
  assert.deepStrictEqual(records, v.expected.slice(0, 2));
});
