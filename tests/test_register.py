"""Redeeming an activation token registers exactly one Steward key, once."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steward import blind
from steward.identity import steward_id
from steward.register import RegisterError, redeem, token_key

ROOT = Path(__file__).resolve().parent.parent
V = json.loads((ROOT / "vectors" / "blind" / "rfc9474.json").read_text())["vectors"][0]
assert V["section"] == "A.1"
P, Q = int(V["p"], 16), int(V["q"], 16)
N, E, D = int(V["n"], 16), int(V["e"], 16), int(V["d"], 16)
SPKI = bytes.fromhex(json.loads((ROOT / "vectors" / "identity" / "signing.json").read_text())["spki_der"])
OTHER_SPKI = SPKI[:-1] + bytes([SPKI[-1] ^ 1])


def _probable_prime(n: int) -> bool:
    if n % 2 == 0:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _next_prime(n: int) -> int:
    n += 1 + n % 2
    while not (_probable_prime(n) and (n - 1) % E):
        n += 2
    return n


def _other_key() -> tuple[int, int, int]:
    """A second, deterministic test key: the primes after the RFC's p and q. TEST ONLY."""
    p, q = _next_prime(P), _next_prime(Q)
    n = p * q
    lam = (p - 1) * (q - 1)
    return n, E, pow(E, -1, lam)


OTHER = _other_key()


def token(spki: bytes, key=(N, E, D)) -> tuple[bytes, bytes]:
    n, e, d = key
    msg = blind.prepare(steward_id(spki).encode())
    blinded_msg, inv = blind.blind(n, e, msg)
    sig = blind.finalize(n, e, msg, blind.blind_sign(n, e, d, blinded_msg), inv)
    return msg, sig


def test_valid_redeem_returns_the_steward_id_and_marks_the_token_used():
    msg, sig = token(SPKI)
    seen: set = set()
    assert redeem(msg, sig, N, E, SPKI, seen) == steward_id(SPKI)
    assert seen == {token_key(sig)}


def test_reused_token_is_refused():
    msg, sig = token(SPKI)
    seen: set = set()
    redeem(msg, sig, N, E, SPKI, seen)
    with pytest.raises(RegisterError, match="already redeemed"):
        redeem(msg, sig, N, E, SPKI, seen)
    assert len(seen) == 1


def test_token_for_another_steward_id_is_refused():
    msg, sig = token(OTHER_SPKI)
    seen: set = set()
    with pytest.raises(RegisterError, match="another Steward ID"):
        redeem(msg, sig, N, E, SPKI, seen)
    assert seen == set()


def test_token_signed_by_the_wrong_key_is_refused():
    msg, sig = token(SPKI, key=OTHER)
    seen: set = set()
    with pytest.raises(RegisterError, match="does not verify"):
        redeem(msg, sig, N, E, SPKI, seen)
    good_msg, good_sig = token(SPKI)
    with pytest.raises(RegisterError, match="does not verify"):
        redeem(good_msg, good_sig, OTHER[0], OTHER[1], SPKI, seen)
    assert seen == set()


def test_tampered_signature_or_prefix_is_refused():
    msg, sig = token(SPKI)
    seen: set = set()
    with pytest.raises(RegisterError):
        redeem(msg, sig[:-1] + bytes([sig[-1] ^ 1]), N, E, SPKI, seen)
    with pytest.raises(RegisterError):
        redeem(bytes([msg[0] ^ 1]) + msg[1:], sig, N, E, SPKI, seen)
    assert seen == set()


@pytest.mark.parametrize("bad", [b"", "text", None])
def test_non_bytes_inputs_are_refused(bad):
    msg, sig = token(SPKI)
    with pytest.raises(RegisterError):
        redeem(bad, sig, N, E, SPKI, set())
    with pytest.raises(RegisterError):
        redeem(msg, bad, N, E, SPKI, set())
    with pytest.raises(RegisterError):
        redeem(msg, sig, N, E, bad, set())


def test_unprepared_message_is_refused():
    sid = steward_id(SPKI).encode()
    with pytest.raises(RegisterError, match="another Steward ID"):
        redeem(sid, b"\x01" * 256, N, E, SPKI, set())
