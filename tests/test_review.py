"""R6 review and R7 appeals, run by the server. Operators rule; wards stay anonymous."""

import pytest

from conftest import ev
from steward import graph as graphs

CASE = {
    "case_id": "case-x3", "line_id": "line-7", "steward_id": "stw-a",
    "strikes": [
        {"id": "x1", "category": "bullying", "at": "2026-10-10T20:00:00Z", "weight": 1},
        {"id": "x2", "category": "threat", "at": "2026-10-11T20:00:00Z", "weight": 1},
        {"id": "x3", "category": "hate", "at": "2026-10-12T20:00:00Z", "weight": 1},
    ],
}
OPEN = "2026-10-12T20:00:00Z"


def at(hours: float) -> str:
    """OPEN plus whole hours, as a timestamp."""
    from datetime import datetime, timedelta
    t = datetime(2026, 10, 12, 20) + timedelta(hours=hours)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def kinds(step):
    return [o["kind"] for o in step.record["outputs"]]


def opened(load, house_rules, runner):
    r = runner(load("review"), house_rules, CASE)
    s = r.send(ev("open", at=OPEN))
    assert r.state == "waiting"
    assert s.record["outputs"] == [{"kind": "notify_operators", "message": "review.case_opened", "subject": "case-x3"}]
    return r


def test_no_ruling_before_24_hours(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    s = r.send(ev("uphold", at=at(23), payload={"reviewer": "op1"}))
    assert s.record["outcome"] == "not_accepted" and r.state == "waiting"
    r.send(ev("tick", at=at(23)))
    assert r.state == "waiting"
    s = r.send(ev("tick", at=at(24)))
    assert r.state == "ready" and kinds(s) == ["notify_operators"]


def test_operators_are_warned_once_before_the_deadline(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    assert kinds(r.send(ev("tick", at=at(59)))) == []
    s = r.send(ev("tick", at=at(60)))  # 72 - 12
    assert s.record["outputs"][0]["message"] == "review.deadline_near"
    assert kinds(r.send(ev("tick", at=at(61)))) == []


def test_unreviewed_case_lapses_in_the_wards_favour(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    s = r.send(ev("tick", at=at(72)))
    assert r.state == "lapsed"
    tell = s.record["outputs"][0]
    assert tell == {"kind": "tell_steward", "steward_id": "stw-a",
                    "event": {"type": "case_overturned", "payload": {"case_id": "case-x3", "overturned": ["x1", "x2", "x3"]}}}
    assert "record_mark" not in kinds(s)


def test_a_late_ruling_still_lapses(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    r.send(ev("uphold", at=at(80), payload={"reviewer": "op1"}))  # scheduler missed the 72h tick
    assert r.state == "lapsed"


def test_upheld_marks_the_line_and_issues_a_successor(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    s = r.send(ev("uphold", at=at(30), payload={"reviewer": "op1"}))
    assert r.state == "upheld"
    assert kinds(s) == ["record_mark", "issue_successor"]
    mark = s.record["outputs"][0]
    assert mark == {"kind": "record_mark", "line_id": "line-7", "case_id": "case-x3",
                    "categories": ["bullying", "hate", "threat"], "at": at(30), "weight": 1}
    assert r.instance.context["rulings"] == [{"reviewer": "op1", "event": "uphold", "at": at(30)}]
    # No appeal: after 14 days the decision is final and the evidence goes.
    s = r.send(ev("tick", at=at(30 + 14 * 24)))
    assert r.state == "final" and kinds(s) == ["tell_steward", "delete_evidence"]
    assert r.instance.context["strikes"] == [{"id": "x1", "category": "bullying"},
                                             {"id": "x2", "category": "threat"},
                                             {"id": "x3", "category": "hate"}]


def test_partial_overturn_returns_the_steward(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    s = r.send(ev("overturn", at=at(30), payload={"reviewer": "op1", "overturned": ["x3"]}))
    assert r.state == "overturned"
    assert s.record["outputs"][0]["event"] == {"type": "case_overturned", "payload": {"case_id": "case-x3", "overturned": ["x3"]}}


def appealed(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    r.send(ev("uphold", at=at(30), payload={"reviewer": "op1"}))
    s = r.send(ev("appeal", at=at(40)))
    assert r.state == "appealed" and s.record["outputs"][0]["message"] == "review.appeal_filed"
    return r


def test_appeal_upheld_is_final(load, house_rules, runner):
    r = appealed(load, house_rules, runner)
    s = r.send(ev("appeal_upheld", at=at(50), payload={"reviewer": "op2"}))
    assert r.state == "final" and kinds(s) == ["tell_steward", "delete_evidence"]


def test_frivolous_appeal_operator_sets_mark_weight(load, house_rules, runner):
    r = appealed(load, house_rules, runner)
    for bad in (0, 4, "2", True):
        s = r.send(ev("appeal_frivolous", at=at(50), payload={"reviewer": "op2", "weight": bad}))
        assert r.state == "appealed", bad
        assert s.record["outputs"][0]["message"] == "review.penalty_invalid"
    s = r.send(ev("appeal_frivolous", at=at(51), payload={"reviewer": "op2", "weight": 3}))
    assert r.state == "final"
    assert {"kind": "set_mark_weight", "line_id": "line-7", "case_id": "case-x3", "weight": 3} in s.record["outputs"]


def test_departure_overturned_on_appeal_restores_the_original(load, house_rules, runner):
    r = appealed(load, house_rules, runner)
    s = r.send(ev("appeal_overturned", at=at(50), payload={"reviewer": "op2"}))
    assert r.state == "overturned"
    assert kinds(s) == ["remove_mark", "retire_successor", "tell_steward", "delete_evidence"]
    assert s.record["outputs"][2]["event"]["type"] == "case_overturned"


def test_unanswered_appeal_is_granted(load, house_rules, runner):
    r = appealed(load, house_rules, runner)
    s = r.send(ev("tick", at=at(40 + 72)))
    assert r.state == "overturned" and {"remove_mark", "retire_successor"} <= set(kinds(s))


def test_appeal_after_window_is_final(load, house_rules, runner):
    r = opened(load, house_rules, runner)
    r.send(ev("tick", at=at(24)))
    r.send(ev("uphold", at=at(30), payload={"reviewer": "op1"}))
    r.send(ev("appeal", at=at(30 + 14 * 24)))
    assert r.state == "final"


# ---- strike appeals

STRIKE = {"appeal_id": "ap-1", "line_id": "line-7", "steward_id": "stw-a",
          "strike": {"id": "x1", "at": "2026-10-12T20:00:00Z", "category": "bullying"}}


@pytest.mark.parametrize("ruling, end, told", [
    ("appeal_upheld", "upheld", {"type": "strike_upheld", "payload": {"strike_id": "x1"}}),
    ("appeal_overturned", "overturned", {"type": "strike_overturned", "payload": {"strike_id": "x1"}}),
])
def test_strike_appeals(load, house_rules, runner, ruling, end, told):
    r = runner(load("strike_appeal"), house_rules, STRIKE)
    r.send(ev("open", at=at(1)))
    assert r.state == "filed"
    s = r.send(ev(ruling, at=at(5), payload={"reviewer": "op1"}))
    assert r.state == end and s.record["outputs"][0]["event"] == told


def test_frivolous_strike_appeal_operator_sets_weight(load, house_rules, runner):
    r = runner(load("strike_appeal"), house_rules, STRIKE)
    r.send(ev("open", at=at(1)))
    r.send(ev("appeal_frivolous", at=at(5), payload={"reviewer": "op1", "weight": 9}))
    assert r.state == "filed"
    s = r.send(ev("appeal_frivolous", at=at(6), payload={"reviewer": "op1", "weight": 2}))
    assert r.state == "penalised"
    assert s.record["outputs"][0]["event"] == {"type": "penalty_set", "payload": {"strike_id": "x1", "weight": 2}}


def test_strike_appeal_window_and_lapse(load, house_rules, runner):
    late = runner(load("strike_appeal"), house_rules, STRIKE)
    s = late.send(ev("open", at=at(14 * 24)))
    assert late.state == "refused" and s.record["outputs"][0]["event"]["type"] == "appeal_refused"

    slow = runner(load("strike_appeal"), house_rules, STRIKE)
    slow.send(ev("open", at=at(1)))
    slow.send(ev("tick", at=at(1 + 72)))
    assert slow.state == "overturned"


# ---- the contract between server and phone

def test_every_event_sent_to_a_steward_exists_on_the_conduct_graph(catalog, load, house_rules, runner):
    """Collect every tell_steward output the server graphs can produce, by
    walking each branch's actions, and check the phone can accept it."""
    from steward.actions import STEWARD_EVENTS_ABOUT_STRIKES
    conduct = load("conduct")
    sent = {"case_final": {"case_id"}, "case_overturned": {"case_id", "overturned"},
            "penalty_set": {"strike_id", "weight"}}
    sent.update({name: {"strike_id"} for name in STEWARD_EVENTS_ABOUT_STRIKES})
    for name, payload in sent.items():
        assert name in conduct.events, name
        assert conduct.events[name].payload == payload, name
        assert conduct.events[name].signals == frozenset(), name
    used = set()
    for g in (load("review"), load("strike_appeal")):
        for branches in g.transitions.values():
            for br in branches:
                for call in br.do:
                    if call.action == "tell_about_strike":
                        used.add(call.args["event"])
                    elif call.action == "tell_penalty_set":
                        used.add("penalty_set")
                    elif call.action == "tell_case_final":
                        used.add("case_final")
                    elif call.action.startswith("tell_case_overturned"):
                        used.add("case_overturned")
    assert used == set(sent)
