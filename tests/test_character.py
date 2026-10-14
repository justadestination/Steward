"""Signed character file: canonical bytes, fingerprint, and the restore graph.
Signature checking is WebCrypto Ed25519 in pwa/character.js (tested there)."""

from __future__ import annotations

import json

import pytest

from steward import character
from steward.catalog import ROOT
from steward.registry import CONDITIONS

from conftest import ev

VECTOR = json.loads((ROOT / "vectors" / "character" / "fingerprint.json").read_text(encoding="utf-8"))
CASES = {c["name"]: c for c in VECTOR["cases"]}
SKELETON = {"version": 1, "voice": {}, "rules": {}, "source": "Owner writes the voice; see Steward-ID.md"}


@pytest.mark.parametrize("name", sorted(CASES))
def test_canonical_and_fingerprint_match_vector(name):
    c = CASES[name]
    assert character.canonical(c["character"]).hex() == c["canonical_hex"]
    assert character.fingerprint(c["character"]) == c["fingerprint"]


def test_non_ascii_is_written_unescaped():
    data = character.canonical(CASES["non_ascii"]["character"])
    assert "🌙".encode() in data and b"\\u" in data  # emoji raw; only the control char escaped
    assert data.count(b"\\u") == 1


def test_canonical_is_key_order_independent():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert character.canonical(a) == character.canonical(b) == b'{"a":{"x":3,"y":2},"b":1}'


def test_floats_refused():
    with pytest.raises(TypeError):
        character.canonical({"version": 1.0})


def test_character_file_is_the_skeleton_only():
    assert character.load() == SKELETON
    assert CASES["skeleton"]["character"] == SKELETON
    assert character.fingerprint(character.load()) == CASES["skeleton"]["fingerprint"]


# ---- restore graph --------------------------------------------------------

HOUSE_FP = CASES["skeleton"]["fingerprint"]
LOCAL_FP = character.fingerprint({**SKELETON, "voice": {"tampered": "yes"}})


def connect(local, house, at="2026-10-14T20:00:00Z"):
    return ev("connect", at, {"local_fingerprint": local, "house_fingerprint": house})


def test_restore_match_goes_in_sync(load, house_rules, runner):
    r = runner(load("restore"), house_rules)
    s = r.send(connect(HOUSE_FP, HOUSE_FP))
    assert r.state == "in_sync" and s.record["when"] == "fingerprint_matches"


def test_restore_mismatch_restores_then_in_sync(load, house_rules, runner):
    r = runner(load("restore"), house_rules)
    r.send(connect(LOCAL_FP, HOUSE_FP))
    assert r.state == "restore"
    r.send(ev("restore", "2026-10-14T20:00:01Z", {"fingerprint": HOUSE_FP}))
    assert r.state == "in_sync"


def test_fingerprint_matches_reads_only_the_event():
    cond = CONDITIONS["fingerprint_matches"]
    assert cond.payload == {"local_fingerprint", "house_fingerprint"} and not cond.signals
    # An empty policy proves nothing is read from it.
    assert cond.fn(connect(HOUSE_FP, HOUSE_FP), {}, {}) is True
    assert cond.fn(connect(LOCAL_FP, HOUSE_FP), {}, {}) is False


def test_restore_never_touches_the_reader_profile(load, profile):
    g = load("restore")
    assert g.policy == "house_rules"
    # No actions anywhere: no outputs, no context writes, nothing about the ward.
    assert all(not br.do for branches in g.transitions.values() for br in branches)
    from steward.engine import PolicyError, start, step
    with pytest.raises(PolicyError):
        step(g, start(g, "t").instance, connect(HOUSE_FP, HOUSE_FP), profile, {})
