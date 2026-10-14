"""Activation: one over-21 check, one blind signature, then scrub.
The ledger shows the path taken and nothing from the request."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from steward import blind
from steward import ledger as ledgers
from steward.activation import run_activation
from steward.policy import validate_house_rules
from steward.catalog import HOUSE_RULES, load_json

V = json.loads((Path(__file__).resolve().parent.parent / "vectors" / "blind" / "rfc9474.json").read_text())["vectors"][0]
assert V["section"] == "A.1"
N, E, D = int(V["n"], 16), int(V["e"], 16), int(V["d"], 16)
NOW = "2026-10-14T12:00:00Z"
STEWARD_ID = "stw_FkNXRMq6QcYPV-oUREGk0GWIwL4JqItv9pjRym7-5Ak"

PRESENTATION = {
    "issuer": "test-issuer-QX7Z",
    "credential": "mdoc-presentation-blob-9F3KX2",
    "claims": {"age_over_21": "claim-value-ZZ81", "family_name": "Weatherwax-Unique"},
}
KIND = "mdl-test-kind-K4"
CHALLENGE = "challenge-nonce-7HQ2LM"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def blinded():
    prepared = blind.prepare(STEWARD_ID.encode())
    blinded_msg, inv = blind.blind(N, E, prepared)
    return prepared, blinded_msg, inv


def request(blinded_msg: bytes) -> dict:
    return {
        "blinded_msg": b64url(blinded_msg),
        "presentation": json.loads(json.dumps(PRESENTATION)),
        "kind": KIND,
        "challenge": CHALLENGE,
    }


def verdict(valid: str, over: str):
    return lambda req: {"presentation_valid": valid, "over_21": over}


class Signer:
    def __init__(self):
        self.calls = 0

    def __call__(self, blinded_msg: bytes) -> bytes:
        self.calls += 1
        return blind.blind_sign(N, E, D, blinded_msg)


def states(records):
    return [r["state"] if r["record"] == "start" else r["to"] for r in records]


def test_valid_and_over_21_is_signed_and_the_token_finalizes():
    prepared, blinded_msg, inv = blinded()
    records: list = []
    req = request(blinded_msg)
    status, blind_sig = run_activation(req, verify_presentation=verdict("yes", "yes"), signer=Signer(), now=NOW, ledger=records)
    assert status == "signed"
    sig = blind.finalize(N, E, prepared, blind_sig, inv)
    assert blind.verify(N, E, prepared, sig)
    assert states(records) == ["requested", "checked", "signed", "scrubbed"]
    assert req == {}


@pytest.mark.parametrize("valid, over", [("yes", "no"), ("no", "yes"), ("no", "no")])
def test_anything_but_valid_and_over_21_is_refused(valid, over):
    _, blinded_msg, _ = blinded()
    signer, records = Signer(), []
    req = request(blinded_msg)
    status, sig = run_activation(req, verify_presentation=verdict(valid, over), signer=signer, now=NOW, ledger=records)
    assert (status, sig) == ("refused", None)
    assert signer.calls == 0
    assert states(records) == ["requested", "checked", "refused", "scrubbed"]
    assert records[2]["outputs"] == [{"kind": "say", "message": "activation.refused"}]
    assert req == {}


def test_valid_but_under_21_is_refused():
    _, blinded_msg, _ = blinded()
    signer = Signer()
    assert run_activation(request(blinded_msg), verify_presentation=verdict("yes", "no"), signer=signer, now=NOW) == ("refused", None)
    assert signer.calls == 0


def test_invalid_presentation_is_refused():
    _, blinded_msg, _ = blinded()
    signer = Signer()
    assert run_activation(request(blinded_msg), verify_presentation=verdict("no", "yes"), signer=signer, now=NOW) == ("refused", None)
    assert signer.calls == 0


def test_verifier_that_raises_is_refused():
    _, blinded_msg, _ = blinded()
    signer, records = Signer(), []

    def boom(req):
        raise RuntimeError("issuer list unreachable")

    req = request(blinded_msg)
    assert run_activation(req, verify_presentation=boom, signer=signer, now=NOW, ledger=records) == ("refused", None)
    assert signer.calls == 0
    assert states(records)[-2:] == ["refused", "scrubbed"]
    assert req == {}


@pytest.mark.parametrize("answer", [
    None, "yes", {"presentation_valid": "yes"}, {"presentation_valid": "yes", "over_21": "yes", "extra": "yes"},
    {"presentation_valid": "yes", "over_21": True}, {"presentation_valid": "YES", "over_21": "yes"},
])
def test_verifier_answer_that_is_not_exactly_yes_no_is_refused(answer):
    _, blinded_msg, _ = blinded()
    signer = Signer()
    status = run_activation(request(blinded_msg), verify_presentation=lambda r: answer, signer=signer, now=NOW)
    assert status == ("refused", None) and signer.calls == 0


def _malformed():
    _, blinded_msg, _ = blinded()
    good = request(blinded_msg)
    missing = dict(good); del missing["challenge"]
    extra = dict(good, steward_id=STEWARD_ID)
    return [
        None,
        "not a dict",
        {},
        missing,
        extra,
        dict(good, blinded_msg="not base64url!"),
        dict(good, blinded_msg=b64url(blinded_msg) + "=="),
        dict(good, blinded_msg=""),
        dict(good, blinded_msg=12345),
        dict(good, presentation={}),
        dict(good, presentation="a string"),
        dict(good, kind=""),
        dict(good, challenge=None),
    ]


@pytest.mark.parametrize("req", _malformed())
def test_malformed_request_is_refused_without_asking_the_verifier(req):
    signer, asked, records = Signer(), [], []
    status = run_activation(req, verify_presentation=lambda r: asked.append(1) or {"presentation_valid": "yes", "over_21": "yes"},
                            signer=signer, now=NOW, ledger=records)
    assert status == ("refused", None)
    assert signer.calls == 0 and asked == []
    assert states(records) == ["requested", "checked", "refused", "scrubbed"]
    if isinstance(req, dict):
        assert req == {}


def test_signer_failure_still_scrubs_and_clears():
    _, blinded_msg, _ = blinded()
    records: list = []
    req = request(blinded_msg)

    def broken(m):
        raise RuntimeError("hsm offline")

    with pytest.raises(RuntimeError):
        run_activation(req, verify_presentation=verdict("yes", "yes"), signer=broken, now=NOW, ledger=records)
    assert states(records)[-1] == "scrubbed"
    assert req == {}


@pytest.mark.parametrize("valid, over", [("yes", "yes"), ("yes", "no"), ("no", "no")])
def test_ledger_contains_no_payload_bytes(tmp_path, catalog, load, valid, over):
    _, blinded_msg, _ = blinded()
    path = tmp_path / "activation.jsonl"
    run_activation(request(blinded_msg), verify_presentation=verdict(valid, over), signer=Signer(), now=NOW, ledger=path)
    text = path.read_text(encoding="utf-8")
    records = ledgers.read(path)
    assert len(records) == 4
    serialized = text + json.dumps(records, sort_keys=True)

    forbidden = [
        blinded_msg.hex(),
        blinded_msg.hex().upper(),
        b64url(blinded_msg),
        base64.urlsafe_b64encode(blinded_msg).decode(),
        base64.b64encode(blinded_msg).decode(),
        KIND,
        CHALLENGE,
    ]

    def leaves(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield k
                yield from leaves(v)
        elif isinstance(obj, str):
            yield obj

    forbidden += [s for s in leaves(PRESENTATION) if s != "issuer"]  # "issuer" is too generic a key to search for
    for needle in forbidden:
        assert needle not in serialized, needle
    # Even a short slice of the blinded message must not appear.
    assert blinded_msg.hex()[:32] not in serialized
    assert b64url(blinded_msg)[:24] not in serialized

    for r in records[1:]:
        assert r["event"]["payload"] == {}
        assert r["context"] == {}

    # And the ledger replays: it is a real engine ledger, nothing hand-written.
    house_rules = validate_house_rules(load_json(HOUSE_RULES))
    assert ledgers.replay(load("activation"), records, house_rules, catalog.signals).state == "scrubbed"


def test_activation_graph_request_event_carries_no_payload(load):
    g = load("activation")
    assert all(not decl.payload for decl in g.events.values())
    assert g.transitions[("requested", "request")][0].to == "checked"
    assert ("checked", "verdict") in g.transitions
