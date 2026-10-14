"""Steward identity: Steward ID derivation and signed-request format.

The PWA derives the Steward ID from the ECDSA P-256 SPKI DER it exports
(WebCrypto). This test checks the id format and the signed-string
construction: the string a Steward signs is
"METHOD \n PATH \n DATE \n base64url(SHA-256(body bytes))",
UTF-8, with no trailing newline. Verification of the ECDSA P-256
signature is not stdlib, so the Python side checks the id derivation and
the signed-string construction; the server (S2) verifies the signature.
"""

import base64

import pytest

from steward import identity

VECTOR = (pytest.importorskip("json")
          .loads((pytest.importorskip("pathlib").Path(__file__).resolve().parent.parent / "vectors" / "identity" / "signing.json").read_text()))


def test_steward_id_derivation():
    spki_der = bytes.fromhex(VECTOR["spki_der"])
    sid = identity.steward_id(spki_der)
    assert sid == VECTOR["steward_id"]
    # unpadded base64url, prefixed with stw_
    assert sid.startswith("stw_")
    b64 = sid[len("stw_"):]
    assert b64 == b64.rstrip("=")
    decoded = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    assert len(decoded) == 32


def test_steward_id_matches_vector():
    spki_der = bytes.fromhex(VECTOR["spki_der"])
    assert identity.steward_id(spki_der) == VECTOR["steward_id"]


def test_signed_string_construction():
    method = VECTOR["method"]
    path = VECTOR["path"]
    date = VECTOR["date"]
    body = VECTOR["body"].encode("utf-8")
    want = VECTOR["signed_string"]
    got = identity.signed_string(method, path, date, body)
    assert got == want
    # UTF-8, no trailing newline
    assert got.endswith("\n") is False
    # intermediate parts
    head, digest = got.rsplit("\n", 1)
    assert head == f"{method}\n{path}\n{date}"
    assert digest == VECTOR["body_digest"]


def test_signed_string_for_activate():
    # The activation request (Task 2.1: Get /activate). The signature
    # verifies in S2 against this exact string; the vector below records it.
    method = "GET"
    path = "/activate"
    date = "2026-10-12T20:00:00Z"
    body = b""
    want = "GET\n/activate\n2026-10-12T20:00:00Z\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    got = identity.signed_string(method, path, date, body)
    assert got == want
