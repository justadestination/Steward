"""R8: @dontwastemytime always reaches the operators, no matter what."""

import pytest

from conftest import ev
from steward.policy import is_reserved_handle
from steward.registry import OTHERWISE


@pytest.mark.parametrize("name", ["operator_line", "operator_inbox"])
def test_there_is_exactly_one_way_through(load, name):
    """Every transition has a single 'otherwise' branch: no condition exists
    that could divert, return or withhold the message."""
    g = load(name)
    for (src, ev_), branches in g.transitions.items():
        assert [b.when for b in branches] == [OTHERWISE], (src, ev_)


def test_the_phone_side_reads_no_signals(load):
    g = load("operator_line")
    assert all(not decl.signals for decl in g.events.values())


@pytest.mark.parametrize("abuse", ["none", "insult", "bullying", "hate", "threat"])
@pytest.mark.parametrize("steward_id", ["stw-a", None])
def test_everything_is_filed_and_labelled(load, house_rules, runner, abuse, steward_id):
    r = runner(load("operator_inbox"), house_rules)
    s = r.send(ev("arrive", payload={"mail_id": "m1", "steward_id": steward_id, "case_id": None, "text": "hi"},
                  signals={"abuse": abuse}))
    assert r.state == "filed"
    mail = s.record["outputs"][0]
    assert mail["kind"] == "operator_mail" and mail["label"] == abuse and mail["steward_id"] == steward_id


def test_a_departed_ward_can_name_their_case(load, house_rules, runner):
    r = runner(load("operator_line"), house_rules)
    s = r.send(ev("send", payload={"text": "about my case", "case_id": "case-x3"}))
    assert r.state == "sent"
    assert s.record["outputs"] == [
        {"kind": "forward_to_operators", "text": "about my case", "case_id": "case-x3"},
        {"kind": "say", "message": "operators.sent"},
    ]


@pytest.mark.parametrize("handle", ["dontwastemytime", "@DontWasteMyTime", "DONTWASTEMYTIME"])
def test_the_address_is_reserved(house_rules, handle):
    assert is_reserved_handle(handle, house_rules)


def test_other_handles_are_not(house_rules):
    assert not is_reserved_handle("dontwastemytime2", house_rules)
