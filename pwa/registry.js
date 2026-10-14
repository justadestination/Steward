// The Steward's conditions and actions, for the PWA.
//
// Mirrors steward/conditions.py and steward/actions.py for every name the
// Steward graphs use (introduction, outbox, inbox, conduct, operator_line,
// restore). House, review, appeal and activation names are deliberately
// absent: those run only on the server, and a graph naming one is refused
// at load.
//
// Same rules as Python: conditions return a real boolean; actions return
// { updates, outputs } and never touch storage, network or the clock.

import { minutesBetween } from "./engine.js";

const MINUTES_PER_DAY = 1440;

export function makeRegistry(signalValues) {
  const strikeLevel = (event, policy) => policy.conduct.strike_categories.includes(event.signals.abuse);

  // Sum of weights of strikes younger than the expiry period at `at`.
  const activeStrikeWeight = (context, at, policy) => {
    const expiry = policy.parameters.strike_expiry_days * MINUTES_PER_DAY;
    return (context.strikes ?? [])
      .filter((s) => minutesBetween(s.at, at) < expiry)
      .reduce((sum, s) => sum + s.weight, 0);
  };

  const conditions = {
    // Bullying, hate or threat, as posted. Swearing and a lone insult are not.
    abuse_at_strike_level: (event, context, policy) => strikeLevel(event, policy),

    // The threshold is the ward's own, from their profile.
    hostile_toward_reader: (event, context, policy) => {
      const order = signalValues.hostility;
      return order.indexOf(event.signals.hostility) >= order.indexOf(policy.inbox.hold_at);
    },

    not_a_strike: (event, context, policy) => !strikeLevel(event, policy),
    no_active_strikes: (event, context, policy) => activeStrikeWeight(context, event.at, policy) === 0,
    one_active_strike: (event, context, policy) => activeStrikeWeight(context, event.at, policy) === 1,
    time_out_over: (event, context) =>
      minutesBetween(context.time_out.started_at, event.at) >= context.time_out.minutes,
    strike_holds_time_out: (event, context) =>
      context.time_out != null && context.time_out.strike_id === event.payload.strike_id,

    // ---- restore ----

    // The Steward's character file is the House's current one. Both
    // fingerprints travel on the event (local, and the House's from the
    // /connect reply); nothing is read from the policy.
    fingerprint_matches: (event) => {
      const { local_fingerprint: local, house_fingerprint: house } = event.payload;
      return typeof local === "string" && typeof house === "string" && local === house;
    },
  };

  const none = (updates = {}) => ({ updates, outputs: [] });

  const actions = {
    say: (event, context, policy, args) => ({
      updates: {},
      outputs: [{ kind: "say", message: args.message }],
    }),

    // Append, never overwrite. A later answer to the same question names the
    // entry it corrects; the latest entry is the one in force.
    record_answer: (event, context, policy, args) => {
      const answers = [...(context.answers ?? [])];
      let previous = null;
      answers.forEach((a, i) => { if (a.question === args.question) previous = i; });
      answers.push({
        question: args.question,
        answer: args.answer,
        channel: args.channel,
        at: event.at,
        corrects: previous,
      });
      return none({ answers });
    },

    // Erase the whole model of the ward. Different from changing an answer.
    forget_answers: () => none({ answers: [] }),

    forward_to_house: (event) => ({
      updates: {},
      outputs: [{ kind: "forward_to_house", text: event.payload.text }],
    }),

    // R8. No signals are read: nothing about the text can stop it.
    forward_to_operators: (event) => ({
      updates: {},
      outputs: [{ kind: "forward_to_operators", text: event.payload.text, case_id: event.payload.case_id }],
    }),

    deliver: (event) => ({
      updates: {},
      outputs: [{ kind: "deliver", message_id: event.payload.message_id }],
    }),

    // ---- conduct (R5) ----

    // The strike's id is the exchange it came from.
    add_strike: (event, context) => none({
      strikes: [...(context.strikes ?? []), {
        id: event.payload.exchange_id,
        category: event.signals.abuse,
        at: event.at,
        weight: 1,
      }],
    }),

    // Length is set by category in the posted rules.
    start_time_out: (event, context, policy) => none({
      time_out: {
        strike_id: event.payload.exchange_id,
        started_at: event.at,
        minutes: policy.conduct.time_out_minutes[event.signals.abuse],
      },
    }),

    end_time_out: () => none({ time_out: null }),

    // Sealed on the phone, not sent and not destroyed. Only strikes travel.
    seal_and_open_case: (event, context) => {
      const caseId = "case-" + event.payload.exchange_id;
      return {
        updates: { sealed: true, case_id: caseId, time_out: null },
        outputs: [{ kind: "open_case", case_id: caseId, strikes: (context.strikes ?? []).map((s) => ({ ...s })) }],
      };
    },

    remove_strike: (event, context) => none({
      strikes: (context.strikes ?? []).filter((s) => s.id !== event.payload.strike_id),
    }),

    remove_strikes: (event, context) => {
      const gone = new Set(event.payload.overturned);
      return none({ strikes: (context.strikes ?? []).filter((s) => !gone.has(s.id)) });
    },

    // R7: the operator's penalty for a frivolous appeal, bounds checked on the server.
    set_strike_weight: (event, context) => none({
      strikes: (context.strikes ?? []).map((s) =>
        (s.id === event.payload.strike_id ? { ...s, weight: event.payload.weight } : { ...s })),
    }),

    unseal: () => none({ sealed: false, case_id: null }),

    destroy_sealed: (event, context) => ({
      updates: { strikes: [], time_out: null, sealed: false, case_id: null },
      outputs: [{ kind: "destroy_ward_data", case_id: context.case_id ?? null }],
    }),
  };

  return { conditions, actions };
}
