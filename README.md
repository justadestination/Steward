# Steward and House

Deterministic graphs of pre-defined actions. Python 3.11+ (stdlib) on the
server, plain ES modules in the PWA. No dependencies.

```
python3 -m steward check                 # validate every graph + the posted rules
python3 -m steward describe conduct      # Mermaid state diagram
python3 -m steward run introduction --events examples/introduction.events.jsonl \
        --policy policy/reader_profile.example.json [--ledger out.jsonl]
python3 tools/make_vectors.py            # rewrite shared vector inputs
python3 -m steward vectors [--write]     # check (or fill) expected records
python3 -m pytest -q                     # Python engine
npm test                                 # PWA engine against the same vectors
```

## Where things run

| Where | Graphs |
|---|---|
| **PWA** (`pwa/`) | `introduction`, `outbox`, `inbox`, `conduct`, `operator_line` |
| **Server** (`steward/`) | `house`, `review`, `strike_appeal`, `operator_inbox`; also `check` and generating vectors |

Both engines load the same graph JSON. `vectors/` holds event sequences and
the exact ledger records the Python engine produced; the JS engine must
reproduce them exactly. Server-only conditions and actions are absent from
`pwa/registry.js`, so those graphs refuse to load on a phone.

The server talks to a phone only through `tell_steward` outputs, each carrying
an event the `conduct` graph declares. `tests/test_review.py` checks that
contract.

## Words used here, and only these

| Word | Means | Never called |
|---|---|---|
| **Steward** | The ward's own agent. Loyal to the platform, working for it on the ward's behalf. Reports the what and how, never the who. Its character is a separate document, not kept in this repo. | assistant, bot |
| **Ward** | The person a Steward is with. Anonymous to everyone, including the platform. | user, account holder |
| **House** | The zone's agent. Upholds the **posted rules**, and nothing that isn't posted. | curator, moderator |
| **Posted rules** | `policy/house_rules.json`. Public. Every House action cites a rule id from it. | guidelines |
| **Reader profile** | One ward's settings. Belongs to the ward. | user model |
| **Strike** | Bullying, hate or a threat toward a Steward (R5). Expires after 90 days. Swearing and a lone insult are never strikes. | warning (a warning is what strike one *does*) |
| **Case** | Opened when a Steward leaves. Carries the strikes only: what, never who. | report, ticket |
| **Line** | A chain of Stewards, each the successor of the last. Marks live on the line, never on a person. | account |
| **@dontwastemytime** | The operators' address (R8). Always reaches them: from anyone, in any state, with or without a Steward. Reserved; no one else may take the name. | support, contact |
| **Mark** | A permanent record on a line that a departure was upheld. Category, date, outcome; nothing else. | ban, record |
| **Graph** | Declared states, events and branches for one flow. `steward/graphs/*.json`. | workflow, FSM |
| **Event** | The only input to a graph: type, UTC time, payload, signals. | message, request |
| **Signal** | A fixed-vocabulary fact about content (`abuse: bullying`), produced *before* the graph runs and stored with the event. | score, label |
| **Condition** | A registered yes/no question. `steward/conditions.py`, mirrored in `pwa/registry.js`. | guard, rule |
| **Action** | A registered, pure step returning context updates and outputs. `steward/actions.py`, mirrored in `pwa/registry.js`. | handler, effect |
| **Output** | An instruction to whatever runs the graph. Closed set, `registry.OUTPUT_KINDS`. | side effect |
| **Ledger** | Append-only record of every start and step, including `not_accepted`, with the context each step left behind. | log |

## The graphs

| Graph | Runs | What it does |
|---|---|---|
| `introduction` | PWA | Asks one question. Tap or Escape = no, reading past = yes. Answers append; a re-ask records a correction. `forget` erases everything. |
| `outbox` | PWA | Before a post leaves: bullying, hate or threats are held back with a nudge. Swearing and insults pass. |
| `inbox` | PWA | Holds incoming mail at or above the ward's own hostility level and asks before showing it. |
| `conduct` | PWA | R5. Strike one: warning. Two: time-out (bullying 1h, hate/threat 4h). Three: the Steward leaves, the ward's data is **sealed on the phone**, and a case opens. Overturned: everything returns. Final: everything is destroyed. |
| `operator_line` | PWA | R8. Mail to @dontwastemytime. One branch, no signals: nothing can stop it. A departed ward can name their case. |
| `house` | Server | R1 Steward → R4 hate (withheld, silent) → R2 bullying/threat (returned) → R3 cool-off → publish. |
| `review` | Server | R6. No ruling for 24h. An operator rules by 72h, or the case lapses in the ward's favour (with a warning to operators at 60h). Upheld: mark on the line and a successor issued; the ward's data stays sealed on the phone through the 14-day appeal window. Overturned on appeal: the original Steward returns with all preferences and memories, and the successor is retired. Frivolous: the operator sets the mark's weight, 1–3. |
| `strike_appeal` | Server | R7. Any strike, within 14 days. Upheld, overturned, or frivolous: the operator sets what the strike counts for, 1–3 (the posted limit; anything outside it is refused). No ruling within 72h means it's granted. |
| `operator_inbox` | Server | R8. Files everything, labelled with its abuse signal so operators know what they're opening. One branch, one outcome. |

**Runner rules for R8**, which a graph can't express:
- The PWA offers `operator_line` in every `conduct` state, including timed-out and departed.
- The server never routes @dontwastemytime through `house`.
- People without a Steward reach `operator_inbox` through a plain web form, with `steward_id` null.
- Every request carries a proof-of-work stamp (`pwa/stamp.js` mints, `steward/stamp.py`
  verifies): 18 zero bits of SHA-256 over the exact message and its time, under a second
  on average. `steward/door.py` checks it, refuses repeated mail ids, labels the text,
  and only then builds the event. A refused request never becomes an event, so the
  operator graphs stay single-path. The stamp identifies no one.
  `vectors/stamps/cases.json` holds cases both sides must judge the same way.

Branch order is the decision. In `house`, hate is checked before cool-off so a
withheld submission is never answered with a cool-off message.

Every ruling records which operator made it. Operators are accountable; wards
are anonymous.

## What makes it deterministic

- **Closed sets.** Graphs may only name registered conditions and actions,
  catalog messages (`steward/data/messages.json`), declared signals
  (`steward/data/signals.json`) and posted rule ids. Anything else fails `check`.
- **Exact contracts.** Each event declares its exact payload keys and signals. A
  condition or action that reads something its event doesn't declare fails `check`.
- **Total branches.** Every branch list ends in `otherwise`, and only there.
- **No hidden inputs.** Nothing reads the clock, network or disk during a step.
  Time comes from `event.at`, in exactly one form: `2026-10-12T19:00:00Z`.
- **Deadlines don't depend on ticks.** A ruling that arrives after its deadline
  takes the lapse branch, even if the scheduler missed a tick.
- **Replay.** Both engines re-run a ledger and fail on the first record that differs.

## Not in this scaffold, on purpose

- **Rendering the ward's web.** The introduction writes answers; the surface
  that reads them is the next layer.
- **Activation.** Over-21 proof, Steward keys, and the scrubbed container. To be
  built against a test issuer so development is never blocked.
- **Transport.** How events reach graphs, and who sets `sender.via_steward`. It
  must come from how a submission arrived, never from what the sender typed.
- **Model-based signals.** `classify.py` uses posted word lists only. A model can
  replace it without touching a graph. Bullying in particular is a pattern, not
  a word, and a word list will miss it.

## Open

- `policy/house_rules.json` `terms` holds placeholder words.
- **Operator panel:** `notify_operators` outputs exist; showing them in the ops
  console is not done. There's one operator for now;
  multi-person review comes later.
- **Strike appeal during a departure:** a strike ruling that arrives while the
  Steward is departed is recorded as `not_accepted` on the phone. The case
  ruling should account for it; not yet wired.
- **Evidence:** `open_case` names the strikes; attaching the exchanges' text is
  the runner's job and isn't built.
- **What marks do** to a line is undecided.
- **Wording:** every line in `messages.json` is a placeholder until it's
  written in the Steward's voice.
- Next graphs: activation, signed character file, restore-on-connect.
