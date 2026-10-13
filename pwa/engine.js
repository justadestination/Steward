// The graph engine for the PWA. A line-for-line counterpart of
// steward/events.py, steward/engine.py and steward/ledger.py.
//
// Python is the authority: `python3 -m steward check` validates every graph,
// and `python3 -m steward vectors` writes the records both engines must
// reproduce exactly (vectors/, checked by pwa/test/parity.test.mjs).
// Change behaviour here only together with the Python side.

export const OTHERWISE = "otherwise";
const EVENT_KEYS = ["at", "payload", "signals", "type"];
const INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;

export class EventError extends Error {}
export class PolicyError extends Error {}
export class GraphError extends Error {}
export class ReplayMismatch extends Error {}

const clone = (v) => structuredClone(v);
const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const sameKeys = (obj, keys) => {
  const got = Object.keys(obj).sort();
  const want = [...keys].sort();
  return got.length === want.length && got.every((k, i) => k === want[i]);
};

// ---- events -------------------------------------------------------------------

// One form, to the second: 2026-10-12T19:00:00Z. The round-trip rejects
// anything Date would normalise (Feb 30, T24:00:00, leap seconds).
export function parseInstant(text) {
  if (typeof text !== "string" || !INSTANT.test(text)) {
    throw new EventError(`timestamp must look like 2026-10-12T19:00:00Z: ${JSON.stringify(text)}`);
  }
  const ms = Date.parse(text);
  if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 19) + "Z" !== text) {
    throw new EventError(`timestamp is not a real instant: ${JSON.stringify(text)}`);
  }
  return ms;
}

export function minutesBetween(earlier, later) {
  return (parseInstant(later) - parseInstant(earlier)) / 60000;
}

export function eventFromDict(raw) {
  if (!isObject(raw)) throw new EventError("event must be a JSON object");
  if (!sameKeys(raw, EVENT_KEYS)) throw new EventError(`event keys must be exactly ${EVENT_KEYS}`);
  if (typeof raw.type !== "string" || raw.type === "") throw new EventError("event type must be a non-empty string");
  parseInstant(raw.at);
  if (!isObject(raw.payload)) throw new EventError("event payload must be an object");
  if (!isObject(raw.signals) || !Object.values(raw.signals).every((v) => typeof v === "string")) {
    throw new EventError("event signals must be an object of strings");
  }
  return Object.freeze({ type: raw.type, at: raw.at, payload: clone(raw.payload), signals: { ...raw.signals } });
}

const eventToDict = (e) => ({ type: e.type, at: e.at, payload: clone(e.payload), signals: { ...e.signals } });

// ---- graphs -------------------------------------------------------------------

// Not a full validator; Python's `check` is. This refuses any graph that
// names something the PWA registry does not have.
export function loadGraph(raw, registry) {
  const transitions = new Map();
  for (const tr of raw.transitions) {
    for (const br of tr.branches) {
      if (br.when !== OTHERWISE && !(br.when in registry.conditions)) {
        throw new GraphError(`${raw.graph}: condition ${br.when} does not run in the PWA`);
      }
      for (const call of br.do) {
        if (!(call.action in registry.actions)) {
          throw new GraphError(`${raw.graph}: action ${call.action} does not run in the PWA`);
        }
      }
    }
    transitions.set(`${tr.from}\u0000${tr.on}`, tr.branches);
  }
  return Object.freeze({
    name: raw.graph,
    version: raw.version,
    policy: raw.policy,
    initial: raw.initial,
    terminal: new Set(raw.terminal),
    events: raw.events,
    transitions,
  });
}

// ---- engine -------------------------------------------------------------------

export function start(graph, instanceId, context = {}) {
  const ctx = clone(context);
  return {
    instance: { graph: graph.name, id: instanceId, state: graph.initial, context: ctx, seq: 0 },
    record: {
      record: "start",
      graph: graph.name,
      version: graph.version,
      instance: instanceId,
      seq: 0,
      state: graph.initial,
      context: clone(ctx),
    },
  };
}

function checkEvent(graph, event, signalValues) {
  const decl = graph.events[event.type];
  if (!decl) throw new EventError(`graph ${graph.name} has no event ${event.type}`);
  if (!sameKeys(event.payload, decl.payload)) {
    throw new EventError(`${event.type}: payload keys must be exactly ${decl.payload}`);
  }
  if (!sameKeys(event.signals, decl.signals)) {
    throw new EventError(`${event.type}: signals must be exactly ${decl.signals}`);
  }
  for (const [name, value] of Object.entries(event.signals)) {
    if (!signalValues[name].includes(value)) throw new EventError(`${event.type}: signal ${name}=${value} not allowed`);
  }
}

export function step(graph, instance, event, policy, signalValues, registry) {
  if (instance.graph !== graph.name) throw new Error(`instance belongs to ${instance.graph}, not ${graph.name}`);
  if (policy.kind !== graph.policy) throw new PolicyError(`graph ${graph.name} runs against ${graph.policy}`);
  checkEvent(graph, event, signalValues);

  const seq = instance.seq + 1;
  const record = {
    record: "step",
    graph: graph.name,
    version: graph.version,
    instance: instance.id,
    seq,
    event: eventToDict(event),
    from: instance.state,
  };

  const branches = graph.terminal.has(instance.state)
    ? undefined
    : graph.transitions.get(`${instance.state}\u0000${event.type}`);
  if (!branches) {
    Object.assign(record, {
      outcome: "not_accepted", branch: null, when: null, to: instance.state, actions: [], outputs: [],
      context: clone(instance.context),
    });
    return { instance: { ...instance, seq }, record };
  }

  const view = Object.freeze(clone(instance.context));
  let index = 0;
  for (; index < branches.length; index++) {
    const { when } = branches[index];
    if (when === OTHERWISE) break;
    const result = registry.conditions[when](event, view, policy);
    if (typeof result !== "boolean") throw new TypeError(`condition ${when} returned ${typeof result}, not boolean`);
    if (result) break;
  }
  const branch = branches[index];

  const context = clone(instance.context);
  const outputs = [];
  for (const call of branch.do) {
    const res = registry.actions[call.action](event, Object.freeze(clone(context)), policy, call.args);
    Object.assign(context, clone(res.updates));
    for (const out of res.outputs) outputs.push(clone(out));
  }

  Object.assign(record, {
    outcome: "taken",
    branch: index,
    when: branch.when,
    to: branch.to,
    actions: branch.do.map((c) => ({ action: c.action, args: { ...c.args } })),
    outputs,
    context: clone(context),
  });
  return { instance: { graph: graph.name, id: instance.id, state: branch.to, context, seq }, record };
}

// ---- ledger -------------------------------------------------------------------

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function replay(graph, records, policy, signalValues, registry) {
  const [first, ...rest] = records;
  if (!first || first.record !== "start") throw new ReplayMismatch("ledger must begin with a start record");
  if (first.graph !== graph.name || first.version !== graph.version) throw new ReplayMismatch("ledger is for a different graph or version");
  let s = start(graph, first.instance, first.context);
  if (canonical(s.record) !== canonical(first)) throw new ReplayMismatch("start record differs");
  for (const expected of rest) {
    s = step(graph, s.instance, eventFromDict(expected.event), policy, signalValues, registry);
    if (canonical(s.record) !== canonical(expected)) throw new ReplayMismatch(`record seq=${expected.seq} differs on replay`);
  }
  return s.instance;
}
