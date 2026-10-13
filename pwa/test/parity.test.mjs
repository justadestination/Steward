// The JS engine must reproduce every shared vector exactly.
// Run: node --test pwa/test/

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

import {
  EventError, ReplayMismatch, eventFromDict, loadGraph, replay, start, step,
} from "../engine.js";
import { makeRegistry } from "../registry.js";

const root = new URL("../../", import.meta.url);
const json = (path) => JSON.parse(readFileSync(new URL(path, root), "utf-8"));
const signalValues = json("steward/data/signals.json");
const registry = makeRegistry(signalValues);
const graph = (name) => loadGraph(json(`steward/graphs/${name}.json`), registry);

function run(vector) {
  const g = graph(vector.graph);
  let s = start(g, vector.instance, vector.context);
  const records = [s.record];
  for (const raw of vector.events) {
    s = step(g, s.instance, eventFromDict(raw), vector.policy, signalValues, registry);
    records.push(s.record);
  }
  return records;
}

const vectors = readdirSync(new URL("vectors/", root)).filter((f) => f.endsWith(".json")).sort();
assert.ok(vectors.length > 0, "no vectors found");

for (const file of vectors) {
  const vector = json(`vectors/${file}`);
  test(file, () => {
    if (vector.rejects) {
      const g = graph(vector.graph);
      vector.rejects.forEach((raw, i) => {
        assert.throws(
          () => step(g, start(g, "reject").instance, eventFromDict(raw), vector.policy, signalValues, registry),
          EventError,
          `reject #${i} was accepted: ${JSON.stringify(raw)}`,
        );
      });
      return;
    }
    assert.ok(vector.expected.length > 0, "vector has no expected records");
    const records = run(vector);
    assert.deepStrictEqual(records, vector.expected);
    // The JS ledger replays itself, and a tampered one fails.
    const g = graph(vector.graph);
    replay(g, records, vector.policy, signalValues, registry);
    if (records.length > 1) {
      const tampered = structuredClone(records);
      tampered[tampered.length - 1].to = "tampered";
      assert.throws(() => replay(g, tampered, vector.policy, signalValues, registry), ReplayMismatch);
    }
  });
}

test("house graph refuses to load in the PWA", () => {
  assert.throws(() => graph("house"), /does not run in the PWA/);
});
