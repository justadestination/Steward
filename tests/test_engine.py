"""Validator, event contracts, policies, classifier and replay."""

import copy
import json

import pytest

from conftest import ev
from steward import graph as graphs
from steward.catalog import GRAPHS, load_json
from steward.classify import classify, select
from steward.engine import PolicyError, start, step
from steward.events import Event, EventError
from steward.ledger import ReplayMismatch, append, read, replay
from steward.policy import PolicyDocError, validate_house_rules, validate_reader_profile


# ---- validator: one fixture per fault ----------------------------------------

def base():
    return copy.deepcopy(load_json(GRAPHS / "outbox.json"))


def problems(raw, catalog):
    with pytest.raises(graphs.GraphError) as info:
        graphs.validate(raw, catalog)
    return "\n".join(info.value.problems)


def test_shipped_graphs_validate(catalog):
    for name in graphs.names():
        graphs.load(name, catalog)


@pytest.mark.parametrize("mutate, expect", [
    (lambda g: g.update(extra=1), "keys must be exactly"),
    (lambda g: g["transitions"][0]["branches"].pop(), "last branch must be 'otherwise'"),
    (lambda g: g["transitions"][0]["branches"].reverse(), "'otherwise' must be the last branch"),
    (lambda g: g["transitions"][0]["branches"][0].update(when="made_up"), "not registered"),
    (lambda g: g["transitions"][0]["branches"][1]["do"][0].update(action="made_up"), "action 'made_up' is not registered"),
    (lambda g: g["transitions"][0]["branches"][0]["do"][0]["args"].update(message="nope"), "not in messages.json"),
    (lambda g: g["transitions"][0]["branches"][0]["do"][0]["args"].update(extra="x"), "args must be exactly"),
    (lambda g: g["transitions"].append(copy.deepcopy(g["transitions"][0])), "duplicate (state, event)"),
    (lambda g: g["transitions"][0].update(on="undeclared"), "event is not declared"),
    (lambda g: g["events"]["submit"].update(signals=[]), "reads signal 'abuse' not declared"),
    (lambda g: g["events"]["submit"].update(payload=[]), "reads payload 'text' not declared"),
    (lambda g: g["events"]["submit"].update(signals=["abuse", "mood"]), "signal 'mood' is not in signals.json"),
    (lambda g: g["states"].update(orphan="never reached"), "unreachable"),
    (lambda g: g["terminal"].remove("sent"), "not terminal but has no outgoing transition"),
    (lambda g: g["transitions"].append({"from": "sent", "on": "discard", "branches": [{"when": "otherwise", "to": "discarded", "do": []}]}), "terminal state has an outgoing transition"),
    (lambda g: g.update(policy="anything"), "policy: must be one of"),
])
def test_validator_catches(catalog, mutate, expect):
    raw = base()
    mutate(raw)
    assert expect in problems(raw, catalog)


def test_validator_rejects_unposted_rule(catalog):
    raw = copy.deepcopy(load_json(GRAPHS / "house.json"))
    raw["transitions"][0]["branches"][0]["do"][0]["args"]["rule"] = "R99"
    assert "not a posted house rule" in problems(raw, catalog)


# ---- events -------------------------------------------------------------------

@pytest.mark.parametrize("at", ["2026-10-12T20:00:00", "2026-10-12T20:00:00+00:00", "yesterday", "2026-10-12 20:00:00Z", "2026-10-12T20:00:00.5Z", "2026-02-30T20:00:00Z", "２026-10-12T20:00:00Z"])
def test_only_utc_z_timestamps(at):
    with pytest.raises(EventError):
        Event.from_dict({"type": "x", "at": at, "payload": {}, "signals": {}})


def test_event_must_match_declaration_exactly(load, house_rules, catalog):
    g = load("outbox")
    inst = start(g, "i").instance
    with pytest.raises(EventError, match="signals must be exactly"):
        step(g, inst, ev("submit", payload={"text": "x"}), house_rules, catalog.signals)
    with pytest.raises(EventError, match="not in"):
        step(g, inst, ev("submit", payload={"text": "x"}, signals={"abuse": "rude"}), house_rules, catalog.signals)
    with pytest.raises(EventError, match="has no event"):
        step(g, inst, ev("reask"), house_rules, catalog.signals)


def test_wrong_policy_kind_is_refused(load, house_rules, catalog):
    g = load("introduction")  # runs against the reader's profile, not the posted rules
    with pytest.raises(PolicyError):
        step(g, start(g, "i").instance, ev("show_question"), house_rules, catalog.signals)


# ---- policies -----------------------------------------------------------------

def test_policies_refuse_bad_shapes(house_rules, profile, catalog):
    with pytest.raises(PolicyDocError):
        validate_house_rules({**house_rules, "parameters": {"max_consecutive_posts": 0, "cool_off_minutes": 30}})
    with pytest.raises(PolicyDocError):
        validate_house_rules({**house_rules, "terms": {**house_rules["terms"], "insult": ["Two Words"]}})
    with pytest.raises(PolicyDocError):  # swearing can never be made a strike
        validate_house_rules({**house_rules, "conduct": {"strike_categories": ["profanity"], "time_out_minutes": {"profanity": 60}}})
    with pytest.raises(PolicyDocError):  # R5: time-outs are one to four hours
        validate_house_rules({**house_rules, "conduct": {**house_rules["conduct"], "time_out_minutes": {"bullying": 30, "hate": 240, "threat": 240}}})
    with pytest.raises(PolicyDocError):
        validate_reader_profile({**profile, "inbox": {"hold_at": "none"}}, catalog)


# ---- classifier ---------------------------------------------------------------

def test_classifier_is_word_based_and_reader_relative(house_rules):
    assert classify("all good", house_rules) == {"abuse": "none", "profanity": "no", "hostility": "none"}
    assert classify("ExampleCurse!", house_rules) == {"abuse": "none", "profanity": "yes", "hostility": "none"}
    assert classify("exampleinsult", house_rules)["abuse"] == "insult"
    assert classify("exampleinsulted", house_rules)["abuse"] == "none"  # whole words only
    assert classify("exampleinsult examplethreat examplebully", house_rules)["abuse"] == "threat"  # most severe wins
    assert classify("@ward exampleinsult", house_rules, "ward")["hostility"] == "mild"
    assert classify("ward examplehate", house_rules, "@ward")["hostility"] == "strong"
    assert classify("examplehate", house_rules, "ward")["hostility"] == "none"
    assert classify("ward examplecurse", house_rules, "ward")["hostility"] == "none"  # swearing near you isn't at you
    assert select(classify("x", house_rules), frozenset({"abuse"})) == {"abuse": "none"}


# ---- determinism --------------------------------------------------------------

def test_ledger_replays_identically(tmp_path, load, profile, catalog, runner):
    r = runner(load("introduction"), profile)
    for e in [ev("show_question"), ev("read_past"), ev("reask"), ev("tap"), ev("tap"), ev("forget")]:
        r.send(e)
    path = tmp_path / "ledger.jsonl"
    for rec in r.records:
        append(path, rec)
    rebuilt = replay(load("introduction"), read(path), profile, catalog.signals)
    assert rebuilt == r.instance


def test_tampered_ledger_fails_replay(tmp_path, load, profile, catalog, runner):
    r = runner(load("introduction"), profile)
    r.send(ev("show_question"))
    r.send(ev("tap"))
    records = json.loads(json.dumps(r.records))
    records[2]["to"] = "unmet"
    with pytest.raises(ReplayMismatch):
        replay(load("introduction"), records, profile, catalog.signals)
