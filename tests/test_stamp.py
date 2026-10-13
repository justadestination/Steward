"""R8 proof of work, and the door in front of operator_inbox."""

import json

import pytest

from conftest import ev
from steward.catalog import ROOT
from steward.door import operator_mail_event
from steward.engine import start, step
from steward.stamp import SeenMail, StampError, mint, verify

CASES = json.loads((ROOT / "vectors" / "stamps" / "cases.json").read_text())["cases"]
AT = "2026-10-13T20:00:00Z"


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_stamp_cases(case):
    rules = {"parameters": {"operator_stamp_bits": case["bits"], "operator_stamp_max_age_minutes": case["max_age_minutes"]}}
    if case["error"] is None:
        verify(case["mail"], case["stamp"], case["arrived_at"], rules)
    else:
        with pytest.raises(StampError, match=case["error"]):
            verify(case["mail"], case["stamp"], case["arrived_at"], rules)


def request(text="hello", mail_id="m-1", house_rules=None, steward_id=None):
    mail = {"mail_id": mail_id, "case_id": None, "text": text}
    return {"mail": mail, "stamp": mint(mail, AT, house_rules["parameters"]["operator_stamp_bits"]), "steward_id": steward_id}


def test_door_then_inbox_files_it(house_rules, catalog, load):
    seen = SeenMail(house_rules)
    e = operator_mail_event(request("examplethreat", house_rules=house_rules, steward_id="stw-a"), AT, house_rules, seen)
    assert e.signals == {"abuse": "threat"}  # labelled, not stopped
    g = load("operator_inbox")
    s = step(g, start(g, "i").instance, e, house_rules, catalog.signals)
    assert s.record["to"] == "filed" and s.record["outputs"][0]["label"] == "threat"


def test_replay_is_refused_until_the_stamp_would_be_stale_anyway(house_rules):
    seen = SeenMail(house_rules)
    r = request(house_rules=house_rules)
    operator_mail_event(r, AT, house_rules, seen)
    with pytest.raises(StampError, match="already been delivered"):
        operator_mail_event(r, "2026-10-13T20:05:00Z", house_rules, seen)
    with pytest.raises(StampError, match="too old"):
        operator_mail_event(r, "2026-10-13T20:30:00Z", house_rules, seen)


def test_unstamped_or_forged_mail_never_becomes_an_event(house_rules):
    seen = SeenMail(house_rules)
    r = request(house_rules=house_rules)
    with pytest.raises(StampError):
        operator_mail_event({**r, "stamp": {"v": 1, "at": AT, "nonce": "0"}}, AT, house_rules, seen)
    with pytest.raises(StampError, match="request keys"):
        operator_mail_event({"mail": r["mail"], "stamp": r["stamp"]}, AT, house_rules, seen)
    # a refused request does not use up its mail_id
    operator_mail_event(r, AT, house_rules, seen)


def test_steward_id_comes_from_transport_shape(house_rules):
    with pytest.raises(StampError, match="steward_id"):
        operator_mail_event(request(house_rules=house_rules, steward_id=7), AT, house_rules, SeenMail(house_rules))
