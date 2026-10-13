"""The House upholding the posted rules, in the declared branch order:
R1 steward -> R4 hate -> R2 bullying/threat -> R3 cool-off -> publish."""

import pytest

from conftest import ev

MEMBER = {"handle": "ana", "via_steward": True}


def review(sender=MEMBER, thread=(), signals=None, at="2026-10-12T20:00:00Z"):
    return ev(
        "review",
        at=at,
        payload={"submission_id": "s1", "sender": sender, "thread": list(thread), "text": "hello"},
        signals=signals or {"abuse": "none"},
    )


def outcome(load, house_rules, runner, event):
    r = runner(load("house"), house_rules)
    s = r.send(event)
    return r.state, s.record["outputs"]


def test_no_steward_means_watch_only(load, house_rules, runner):
    state, out = outcome(load, house_rules, runner, review(sender={"handle": "x", "via_steward": False}))
    assert state == "returned"
    assert out == [{"kind": "return_to_sender", "submission_id": "s1", "rule": "R1", "message": "house.needs_steward"}]


def test_hate_is_withheld_and_the_sender_gets_nothing(load, house_rules, runner):
    state, out = outcome(load, house_rules, runner, review(signals={"abuse": "hate"}))
    assert state == "withheld"
    assert out == [{"kind": "withhold", "submission_id": "s1", "rule": "R4"}]
    assert not any(o["kind"] == "return_to_sender" for o in out)


@pytest.mark.parametrize("abuse", ["bullying", "threat"])
def test_bullying_and_threats_are_returned_naming_r2(load, house_rules, runner, abuse):
    state, out = outcome(load, house_rules, runner, review(signals={"abuse": abuse}))
    assert state == "returned" and out[0]["rule"] == "R2"


@pytest.mark.parametrize("abuse", ["none", "insult"])
def test_a_lone_insult_is_published(load, house_rules, runner, abuse):
    assert outcome(load, house_rules, runner, review(signals={"abuse": abuse}))[0] == "accepted"


# ---- R3 cool-off

def posts(*authors_and_times):
    return [{"author": a, "at": t} for a, t in authors_and_times]


def test_first_post_is_accepted(load, house_rules, runner):
    state, out = outcome(load, house_rules, runner, review())
    assert state == "accepted" and out == [{"kind": "publish", "submission_id": "s1"}]


def test_one_before_is_fine(load, house_rules, runner):
    thread = posts(("ben", "2026-10-12T19:00:00Z"), ("ana", "2026-10-12T19:55:00Z"))
    assert outcome(load, house_rules, runner, review(thread=thread))[0] == "accepted"


def test_two_in_a_row_within_30_minutes_is_returned(load, house_rules, runner):
    thread = posts(("ben", "2026-10-12T19:00:00Z"), ("ana", "2026-10-12T19:50:00Z"), ("ana", "2026-10-12T19:55:00Z"))
    state, out = outcome(load, house_rules, runner, review(thread=thread))
    assert state == "returned" and out[0]["rule"] == "R3"


def test_someone_else_posting_resets_it(load, house_rules, runner):
    thread = posts(("ana", "2026-10-12T19:50:00Z"), ("ana", "2026-10-12T19:52:00Z"), ("ben", "2026-10-12T19:55:00Z"))
    assert outcome(load, house_rules, runner, review(thread=thread))[0] == "accepted"


def test_thirty_minutes_after_your_last_post_resets_it(load, house_rules, runner):
    thread = posts(("ana", "2026-10-12T19:20:00Z"), ("ana", "2026-10-12T19:30:00Z"))
    assert outcome(load, house_rules, runner, review(thread=thread, at="2026-10-12T20:00:00Z"))[0] == "accepted"


def test_twenty_nine_minutes_is_still_cooling_off(load, house_rules, runner):
    thread = posts(("ana", "2026-10-12T19:20:00Z"), ("ana", "2026-10-12T19:31:00Z"))
    assert outcome(load, house_rules, runner, review(thread=thread, at="2026-10-12T20:00:00Z"))[0] == "returned"


def test_order_hate_wins_over_cool_off(load, house_rules, runner):
    thread = posts(("ana", "2026-10-12T19:50:00Z"), ("ana", "2026-10-12T19:55:00Z"))
    state, _ = outcome(load, house_rules, runner, review(thread=thread, signals={"abuse": "hate"}))
    assert state == "withheld"
