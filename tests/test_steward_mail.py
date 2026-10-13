"""Outbox (the reader's posts on their way out) and inbox (mail on its way in)."""

from conftest import ev


def test_outbox_clean_post_goes_to_house(load, house_rules, runner):
    r = runner(load("outbox"), house_rules)
    s = r.send(ev("submit", payload={"text": "see you at the show"}, signals={"abuse": "none"}))
    assert r.state == "sent"
    assert s.record["outputs"] == [{"kind": "forward_to_house", "text": "see you at the show"}]


def test_outbox_nudges_then_sends_the_revision(load, house_rules, runner):
    r = runner(load("outbox"), house_rules)
    s = r.send(ev("submit", payload={"text": "x"}, signals={"abuse": "threat"}))
    assert r.state == "nudged"
    assert s.record["outputs"] == [{"kind": "say", "message": "outbox.abuse_nudge"}]
    r.send(ev("submit", payload={"text": "y"}, signals={"abuse": "insult"}))  # everybody slips
    assert r.state == "sent"


def test_outbox_discard_from_nudged(load, house_rules, runner):
    r = runner(load("outbox"), house_rules)
    r.send(ev("submit", payload={"text": "x"}, signals={"abuse": "bullying"}))
    s = r.send(ev("discard"))
    assert r.state == "discarded" and s.record["outputs"] == []


def test_inbox_below_hold_level_is_delivered(load, profile, runner):
    r = runner(load("inbox"), profile)  # profile holds at "strong"
    s = r.send(ev("screen", payload={"message_id": "m1"}, signals={"hostility": "mild"}))
    assert r.state == "delivered"
    assert s.record["outputs"] == [{"kind": "deliver", "message_id": "m1"}]


def test_inbox_at_hold_level_asks_first(load, profile, runner):
    r = runner(load("inbox"), profile)
    s = r.send(ev("screen", payload={"message_id": "m1"}, signals={"hostility": "strong"}))
    assert r.state == "held"
    assert s.record["outputs"] == [{"kind": "say", "message": "inbox.held"}]


def test_inbox_reader_threshold_is_theirs(load, profile, runner):
    stricter = {**profile, "inbox": {"hold_at": "mild"}}
    r = runner(load("inbox"), stricter)
    r.send(ev("screen", payload={"message_id": "m1"}, signals={"hostility": "mild"}))
    assert r.state == "held"


def test_inbox_held_then_opened_or_set_aside(load, profile, runner):
    a = runner(load("inbox"), profile)
    a.send(ev("screen", payload={"message_id": "m1"}, signals={"hostility": "strong"}))
    s = a.send(ev("open", payload={"message_id": "m1"}))
    assert a.state == "shown" and s.record["outputs"] == [{"kind": "deliver", "message_id": "m1"}]

    b = runner(load("inbox"), profile)
    b.send(ev("screen", payload={"message_id": "m2"}, signals={"hostility": "strong"}))
    s = b.send(ev("set_aside"))
    assert b.state == "set_aside" and s.record["outputs"] == []
