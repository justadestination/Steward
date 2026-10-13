"""Writes the INPUT side of every shared vector in vectors/.

    python3 tools/make_vectors.py && python3 -m steward vectors --write

The first command rewrites inputs (events, policy, context) and empties
"expected"; the second fills "expected" from the Python engine. Review the
diff of both before committing.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "vectors"
RULES = json.loads((ROOT / "policy" / "house_rules.json").read_text())


def prof(hold="strong"):
    return {"kind": "reader_profile", "handle": "ward", "inbox": {"hold_at": hold}}


def e(t, at, payload=None, signals=None):
    return {"type": t, "at": at, "payload": payload or {}, "signals": signals or {}}


def T(m, s=0, h=20, d=12):
    return f"2026-10-{d:02d}T{h:02d}:{m:02d}:{s:02d}Z"


def write(name, **v):
    v.setdefault("context", {})
    v.setdefault("instance", name)
    if "events" in v:
        v["expected"] = []
    (D / f"{name}.json").write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n")


def remark(at, xid, abuse):
    return e("remark", at, {"exchange_id": xid}, {"abuse": abuse})


STAMPS = D / "stamps"


def write_stamp_cases():
    """Stamp cases are complete as written (Python mints them); both test
    suites verify each and must reach the same verdict."""
    sys.path.insert(0, str(ROOT))
    import hashlib
    from steward.stamp import StampError, leading_zero_bits, mint, preimage, verify

    posted = RULES["parameters"]
    at = "2026-10-13T20:00:00Z"
    mail = {"mail_id": "m-0001", "case_id": "case-x3", "text": "my Steward left and I think it was wrong"}
    plain = {"mail_id": "m-0002", "case_id": None, "text": "see you there ✨ — ok"}
    cases = []

    def case(name, mail_, stamp, arrived, bits=posted["operator_stamp_bits"], error=None):
        rules = {"parameters": {"operator_stamp_bits": bits,
                                "operator_stamp_max_age_minutes": posted["operator_stamp_max_age_minutes"]}}
        try:  # the generator checks its own expectation before writing it down
            verify(mail_, stamp, arrived, rules)
            got = None
        except StampError as exc:
            got = str(exc)
        assert (got is None) == (error is None) and (error is None or error in got), (name, got)
        cases.append({"name": name, "mail": mail_, "stamp": stamp, "arrived_at": arrived,
                      "bits": bits, "max_age_minutes": posted["operator_stamp_max_age_minutes"], "error": error})

    s18 = mint(mail, at, posted["operator_stamp_bits"])
    s12 = mint(plain, at, 12)
    actual = leading_zero_bits(hashlib.sha256(preimage(plain, at, s12["nonce"])).digest())
    case("valid at the posted difficulty", mail, s18, "2026-10-13T20:03:00Z")
    case("valid, unicode text, no case", plain, s12, at, bits=12)
    case("one bit short", plain, s12, at, bits=actual + 1, error="not enough work")
    case("text changed after minting", {**plain, "text": plain["text"] + "!"}, s12, at, bits=12, error="not enough work")
    case("null case_id is not empty case_id", {**plain, "case_id": ""}, s12, at, bits=12, error="not enough work")
    case("ten minutes old is fine", plain, s12, "2026-10-13T20:10:00Z", bits=12)
    case("eleven minutes old", plain, s12, "2026-10-13T20:11:00Z", bits=12, error="too old")
    case("two minutes early is fine", plain, s12, "2026-10-13T19:58:00Z", bits=12)
    case("three minutes early", plain, s12, "2026-10-13T19:57:00Z", bits=12, error="future")
    case("uppercase nonce", plain, {**s12, "nonce": s12["nonce"].upper() + "A"}, at, bits=12, error="nonce")
    case("long nonce", plain, {**s12, "nonce": "0" * 17}, at, bits=12, error="nonce")
    case("version 2", plain, {**s12, "v": 2}, at, bits=12, error="version")
    case("version true", plain, {**s12, "v": True}, at, bits=12, error="version")
    case("extra stamp key", plain, {**s12, "who": "me"}, at, bits=12, error="stamp keys")
    case("bad stamp time", plain, {**s12, "at": "2026-10-13 20:00:00Z"}, at, bits=12, error="stamp time")
    case("bad mail_id", {**plain, "mail_id": "has space"}, s12, at, bits=12, error="mail_id")
    case("empty text", {**plain, "text": ""}, s12, at, bits=12, error="text must")
    case("lone surrogate", {**plain, "text": "\ud800"}, s12, at, bits=12, error="Unicode")
    case("extra mail key", {**plain, "from": "x"}, s12, at, bits=12, error="mail keys")

    STAMPS.mkdir(exist_ok=True)
    (STAMPS / "cases.json").write_text(json.dumps({"cases": cases}, indent=2) + "\n")  # escaped: holds a lone surrogate


def main() -> int:
    for old in D.glob("*.json"):
        old.unlink()

    # ---- introduction
    write("introduction-full", graph="introduction", policy=prof(), events=[
        e("tap", T(0)),
        e("show_question", T(1)), e("read_past", T(2)), e("reask", T(3)), e("tap", T(4)),
        e("tap", T(5)),
        e("reask", T(6)), e("escape", T(7)),
        e("forget", T(8)), e("show_question", T(9)), e("tap", T(10)),
    ])
    write("introduction-forget-while-asking", graph="introduction", policy=prof(), events=[
        e("show_question", T(0)), e("forget", T(1)), e("show_question", T(2)), e("read_past", T(3)),
    ])
    write("introduction-prior-context", graph="introduction", policy=prof(),
          context={"answers": [{"question": "interruptions", "answer": "yes", "channel": "silence",
                                "at": "2026-10-01T00:00:00Z", "corrects": None}]},
          events=[e("show_question", T(0)), e("tap", T(1))])

    # ---- outbox: swearing and lone insults pass; strike-level is nudged
    write("outbox-nudge-revise-send", graph="outbox", policy=RULES, events=[
        e("submit", T(0), {"text": "rough"}, {"abuse": "threat"}),
        e("submit", T(1), {"text": "still rough"}, {"abuse": "bullying"}),
        e("submit", T(2), {"text": "see you at the show ✨"}, {"abuse": "insult"}),
        e("discard", T(3)),
    ])
    write("outbox-discard", graph="outbox", policy=RULES, events=[
        e("discard", T(0)), e("submit", T(1), {"text": "late"}, {"abuse": "none"})])

    # ---- inbox
    write("inbox-hold-mild-open", graph="inbox", policy=prof("mild"), events=[
        e("screen", T(0), {"message_id": "m1"}, {"hostility": "mild"}), e("open", T(1), {"message_id": "m1"})])
    write("inbox-strong-threshold-delivers-mild", graph="inbox", policy=prof("strong"), events=[
        e("screen", T(0), {"message_id": "m2"}, {"hostility": "mild"}), e("set_aside", T(1))])
    write("inbox-held-set-aside", graph="inbox", policy=prof("strong"), events=[
        e("screen", T(0), {"message_id": "m3"}, {"hostility": "strong"}), e("set_aside", T(1)),
        e("open", T(2), {"message_id": "m3"})])
    write("inbox-none-delivers", graph="inbox", policy=prof("mild"), events=[
        e("screen", T(0), {"message_id": "m4"}, {"hostility": "none"})])

    # ---- conduct (R5)
    write("conduct-three-strikes-then-final", graph="conduct", policy=RULES, events=[
        remark(T(0), "x0", "insult"),                    # not a strike
        remark(T(1), "x1", "bullying"),                  # warning
        remark(T(2), "x2", "threat"),                    # time-out 240
        remark(T(3), "x3", "hate"),                      # not accepted while away
        e("resume", T(30)),                              # still resting
        e("resume", T(2, h=0, d=13)),                    # 240 min after 20:02 is 00:02 next day
        remark(T(5, h=1, d=13), "x4", "hate"),           # third: departs, sealed
        e("resume", T(6, h=1, d=13)),                    # not accepted while departed
        e("case_final", T(0, h=2, d=14), {"case_id": "case-x4"}),
    ])
    write("conduct-strikes-expire", graph="conduct", policy=RULES, events=[
        remark("2026-07-01T20:00:00Z", "old1", "bullying"),
        remark("2026-07-02T20:00:00Z", "old2", "bullying"),  # time-out 60
        e("resume", "2026-07-02T21:00:00Z"),
        remark("2026-09-29T20:00:00Z", "new1", "bullying"),  # old1 is exactly 90 days old (expired), old2 active: time-out
        e("resume", "2026-09-29T21:00:00Z"),
        remark("2026-10-01T20:00:00Z", "new2", "threat"),    # old2 expired too: 1 active -> time-out, not departure
    ])
    write("conduct-overturned-returns", graph="conduct", policy=RULES, events=[
        remark(T(0), "a", "bullying"), remark(T(1), "b", "bullying"),
        e("resume", T(1, h=21)), remark(T(2, h=21), "c", "threat"),
        e("case_overturned", T(0, h=22), {"case_id": "case-c", "overturned": ["c"]}),
        e("resume", T(1, h=22)),
    ])
    write("conduct-appeals", graph="conduct", policy=RULES, events=[
        remark(T(0), "a", "bullying"),
        e("penalty_set", T(1), {"strike_id": "a", "weight": 2}),  # operator: counts for 2
        e("strike_upheld", T(2), {"strike_id": "a"}),
        remark(T(3), "b", "bullying"),                          # weight 2 -> departs
        e("strike_overturned", T(4), {"strike_id": "a"}),      # not accepted while departed
        e("case_overturned", T(5), {"case_id": "case-b", "overturned": ["a", "b"]}),
        remark(T(6), "c", "hate"),                              # fresh warning
        remark(T(7), "d", "threat"),                            # time-out 240 on d
        e("penalty_set", T(8), {"strike_id": "d", "weight": 3}),  # operator: counts for 3; time-out unchanged
        e("resume", T(8, h=0, d=13)),                           # 241 min: time-out over
        e("strike_overturned", T(9, h=0, d=13), {"strike_id": "d"}),
        e("appeal_refused", T(10, h=0, d=13), {"strike_id": "c"}),
    ])

    # ---- operator line (R8): nothing about the text can stop it
    write("operator-line-send", graph="operator_line", policy=RULES, events=[
        e("send", T(0), {"text": "my Steward left and I think it was wrong", "case_id": "case-x3"}),
        e("send", T(1), {"text": "again", "case_id": None}),  # terminal -> not_accepted
    ])
    write("operator-line-discard", graph="operator_line", policy=RULES, events=[e("discard", T(0))])
    write("operator-line-rejects", graph="operator_line", policy=RULES, rejects=[
        e("send", T(0), {"text": "x", "case_id": None}, {"abuse": "hate"}),  # no signals, ever
        e("send", T(0), {"text": "x"}),
    ])

    # ---- events both engines must refuse
    bad_times = ["2026-10-12T20:00:00", "2026-10-12T20:00:00+00:00", "2026-10-12 20:00:00Z",
                 "2026-10-12T20:00:00.5Z", "2026-02-30T20:00:00Z", "2026-10-12T24:00:00Z",
                 "2026-10-12T23:59:60Z", "2026-13-01T00:00:00Z", "２026-10-12T20:00:00Z",
                 "2026-10-12t20:00:00z", "", "yesterday"]
    rejects = [e("show_question", t) for t in bad_times]
    rejects += [
        {"type": "show_question", "at": T(0), "payload": {}},
        {"type": "show_question", "at": T(0), "payload": {}, "signals": {}, "extra": 1},
        {"type": "", "at": T(0), "payload": {}, "signals": {}},
        {"type": "show_question", "at": T(0), "payload": [], "signals": {}},
        {"type": "show_question", "at": T(0), "payload": {}, "signals": {"x": 1}},
        e("show_question", T(0), {"unexpected": True}),
        e("show_question", T(0), signals={"abuse": "none"}),
        e("never_declared", T(0)),
    ]
    write("introduction-rejects", graph="introduction", policy=prof(), rejects=rejects)
    write("outbox-rejects", graph="outbox", policy=RULES, rejects=[
        e("submit", T(0), {"text": "x"}),
        e("submit", T(0), {"text": "x"}, {"abuse": "rude"}),
        e("submit", T(0), {"text": "x"}, {"language": "ok"}),
        e("submit", T(0), {}, {"abuse": "none"}),
        e("submit", T(0), {"text": "x", "to": "y"}, {"abuse": "none"}),
    ])
    write("conduct-rejects", graph="conduct", policy=RULES, rejects=[
        e("remark", T(0), {"exchange_id": "x"}, {"abuse": "profanity"}),
        e("remark", T(0), {"exchange_id": "x"}),
        e("case_final", T(0), {}),
    ])
    write_stamp_cases()
    print(f"wrote {len(list(D.glob('*.json')))} vector inputs and {STAMPS.name}/cases.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
