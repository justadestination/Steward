"""RSA blind signatures (RFC 9474) against the RFC's own Appendix A vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steward import blind

VECTORS = json.loads((Path(__file__).resolve().parent.parent / "vectors" / "blind" / "rfc9474.json").read_text())["vectors"]


def h(value: str) -> bytes:
    return bytes.fromhex(value)


def key(v: dict) -> tuple[int, int, int]:
    return int(v["n"], 16), int(v["e"], 16), int(v["d"], 16)


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_rfc_vector_every_step(v: dict) -> None:
    n, e, d = key(v)
    salt = h(v.get("salt", ""))
    s_len = len(salt)
    prepared = h(v["prepared_msg"])

    if "msg_prefix" in v:
        assert blind.prepare(h(v["msg"]), prefix=h(v["msg_prefix"])) == prepared
    else:
        assert blind.prepare(h(v["msg"]), randomize=False) == prepared

    assert blind.emsa_pss_encode(prepared, n.bit_length() - 1, salt) == h(v["encoded_msg"])

    r = pow(int(v["inv"], 16), -1, n)
    blinded_msg, inv = blind.blind(n, e, prepared, s_len=s_len, salt=salt, r=r)
    assert blinded_msg == h(v["blinded_msg"])
    assert inv == h(v["inv"])

    blind_sig = blind.blind_sign(n, e, d, blinded_msg)
    assert blind_sig == h(v["blind_sig"])

    sig = blind.finalize(n, e, prepared, blind_sig, inv, s_len=s_len)
    assert sig == h(v["sig"])
    assert blind.verify(n, e, prepared, sig, s_len=s_len)


def test_random_round_trip_with_rfc_key() -> None:
    v = VECTORS[0]
    n, e, d = key(v)
    prepared = blind.prepare(b"stw_example-steward-id")
    assert len(prepared) == 32 + len(b"stw_example-steward-id")
    blinded_msg, inv = blind.blind(n, e, prepared)
    sig = blind.finalize(n, e, prepared, blind.blind_sign(n, e, d, blinded_msg), inv)
    assert blind.verify(n, e, prepared, sig)


def test_tampering_is_refused() -> None:
    v = VECTORS[0]
    n, e, d = key(v)
    prepared = h(v["prepared_msg"])
    sig = h(v["sig"])
    flipped = bytes([sig[0] ^ 0x01]) + sig[1:]
    assert not blind.verify(n, e, prepared, flipped)
    assert not blind.verify(n, e, prepared + b"x", sig)
    bad_blind_sig = bytes([h(v["blind_sig"])[0] ^ 0x01]) + h(v["blind_sig"])[1:]
    with pytest.raises(blind.BlindError):
        blind.finalize(n, e, prepared, bad_blind_sig, h(v["inv"]))


def test_blind_sign_refuses_out_of_range_and_wrong_length() -> None:
    v = VECTORS[0]
    n, e, d = key(v)
    k = (n.bit_length() + 7) // 8
    with pytest.raises(blind.BlindError):
        blind.blind_sign(n, e, d, (n + 1).to_bytes(k + 1, "big"))
    with pytest.raises(blind.BlindError):
        blind.blind_sign(n, e, d, b"\x01" * (k - 1))


def _probable_prime(bits: int) -> int:
    """Test-only prime generator (Miller-Rabin, 40 random bases)."""
    import secrets

    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        d, s = c - 1, 0
        while d % 2 == 0:
            d, s = d // 2, s + 1
        for _ in range(40):
            a = secrets.randbelow(c - 3) + 2
            x = pow(a, d, c)
            if x in (1, c - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, c)
                if x == c - 1:
                    break
            else:
                break
        else:
            return c


def _fresh_key(bits: int = 2048) -> tuple[int, int, int]:
    import math

    e = 65537
    while True:
        p, q = _probable_prime(bits // 2), _probable_prime(bits // 2)
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if p != q and math.gcd(e, lam) == 1 and (p * q).bit_length() == bits:
            return p * q, e, pow(e, -1, lam)


def test_wrong_key_does_not_verify() -> None:
    n_a, e_a, _ = key(VECTORS[0])
    n_b, e_b, d_b = _fresh_key()
    assert n_b != n_a
    prepared = blind.prepare(b"stw_other")
    blinded_msg, inv = blind.blind(n_b, e_b, prepared)
    sig = blind.finalize(n_b, e_b, prepared, blind.blind_sign(n_b, e_b, d_b, blinded_msg), inv)
    assert blind.verify(n_b, e_b, prepared, sig)
    assert not blind.verify(n_a, e_a, prepared, sig)
