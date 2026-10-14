# Steward and House

**The Steward** is a personal agent that lives in a phone app. It's the way
into ShadeNet: anyone can read NightCal, the public night calendar, but
posting, voting, submitting and messaging all go through a Steward. It holds
its ward's preferences, screens their mail, checks their posts against the
posted rules before they leave, and explains itself whenever it holds
anything back. We know which Steward someone is with, never who they are.

**The House** is the platform's side. It upholds the posted rules
(`policy/house_rules.json`) and nothing that isn't posted. It runs strike
reviews and appeals, and every action it takes cites a rule by id.

Both are built from **deterministic graphs of pre-defined actions**: every
decision is a declared branch, every input is recorded, and every ledger can
be replayed to the same result. Python 3.11+ (stdlib) on the server, plain
ES modules in the PWA. No dependencies.

Status: working core, not yet wired into an app. See **Open** below.

## Commands

```
python3 -m steward check                 # validate every graph + the posted rules
python3 -m steward describe conduct      # Mermaid state diagram
python3 -m steward run introduction --events examples/introduction.events.jsonl \
        --policy policy/reader_profile.example.json [--ledger out.jsonl]
python3 tools/make_vectors.py            # rewrite shared vector inputs
python3 tools/make_character_vector.py   # rewrite vectors/character/fingerprint.json
python3 -m steward vectors [--write]     # check (or fill) expected records
python3 -m pytest -q                     # Python engine
npm test                                 # PWA engine against the same vectors
```

## Where things run

| Where | Graphs |
|---|---|
| **PWA** (`pwa/`) | `introduction`, `outbox`, `inbox`, `conduct`, `operator_line`, `restore` |
| **Server** (`steward/`) | `house`, `review`, `strike_appeal`, `operator_inbox`, `activation`; also `check` and generating vectors |

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
| `activation` | Server | One over-21 check: `request` → `verdict` → signed or refused → `scrub`. Signs only when the presentation is valid and over 21. The ledger holds the path and the two yes/no signals, nothing from the request. |
| `restore` | PWA | On connect, compares the fingerprint of the Steward's character file with the House's. Equal: in sync. Different: waits for the House's signed file, which the PWA verifies before sending `restore`. Never touches the reader profile. |

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
- **Character voice:** `steward/data/character.json` is an empty skeleton;
  the owner writes the voice.
- **Presentation check:** `run_activation` takes `verify_presentation` and
  `signer` as arguments and is tested with stubs. The real mDL check, the
  trusted-issuer list, and the test issuer are not built.
- **Server side of request signing:** the phone signs; the server does not
  yet verify those signatures (needs ECDSA, outside the stdlib).
- **House signing of the character file:** the phone verifies Ed25519
  signatures; signing on the server (House key) and the `/connect` reply that
  carries the House's fingerprint are not built.
- **Transport** for activation, register and connect: no HTTP endpoints yet.

## Built

Each item below passes its tests in `python3 -m pytest -q` and `npm test`.

- **RSA blind signatures** (RFC 9474, RSABSSA-SHA384-PSS-Randomized), in
  `steward/blind.py` and `pwa/blind.js`. Both reproduce the RFC's Appendix A
  vectors and each other's output (`vectors/blind/`).
- **Activation runner.** `steward/activation.py` drives the `activation`
  graph with injected `verify_presentation` and `signer`; valid and over 21
  is signed, everything else (including a verifier error or a malformed
  request) is refused; the request is cleared on return and the ledger holds
  no payload bytes.
- **Token redemption.** `steward/register.py` `redeem()` registers a Steward
  key once: the token must name that key's Steward ID, verify under the
  checker's key, and not have been used before.
- **Steward identity and request signing (phone side).** Steward ID is `stw_` +
  base64url(SHA-256(SPKI DER)). Requests are signed with ECDSA P-256, raw
  r‖s, headers `X-Steward-Id`, `X-Steward-Date`, `X-Steward-Sig` (plus
  `X-Steward-Key` on register), signed string `METHOD \n PATH \n DATE \n
  base64url(SHA-256(body))`. See `docs/request-signing.md`.
- **Signed character file and restore-on-connect (phone side).**
  `steward/character.py` and `pwa/character.js` produce the same canonical
  bytes and fingerprint (`vectors/character/fingerprint.json`).
  `verifyCharacter` checks the House's Ed25519 signature and the fingerprint;
  only then does the PWA send `restore` to the `restore` graph.

## License

Apache License 2.0. See [LICENSE](LICENSE).
