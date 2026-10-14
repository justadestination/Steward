"""RSA blind signatures, RFC 9474 (RSABSSA-SHA384-PSS[ZERO]-{Randomized,Deterministic}).

Activation uses RSABSSA-SHA384-PSS-Randomized: SHA-384, MGF1-SHA-384,
48-byte salt, and a 32-byte random prefix added by `prepare`. The other
variants exist only so every RFC 9474 Appendix A vector can be reproduced.

The phone blinds its Steward ID, the age checker signs the blinded bytes
without seeing them, and the phone finalizes a signature over its own
message. Nothing the checker sees can be matched to the finalized
signature later. Stdlib only: hashlib, secrets, and int pow.

`salt=` and `r=` exist only so tests can reproduce the RFC vectors. Real
callers leave them unset.
"""

from __future__ import annotations

import hashlib
import math
import secrets

HASH = hashlib.sha384
H_LEN = 48
SALT_LEN = 48
PREFIX_LEN = 32


class BlindError(ValueError):
    """Any refusal: bad input, failed self-check, or a signature that does not verify."""


def _modulus_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def _i2osp(x: int, length: int) -> bytes:
    if x < 0 or x >= 1 << (8 * length):
        raise BlindError("integer too large")
    return x.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += HASH(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def prepare(msg: bytes, *, randomize: bool = True, prefix: bytes | None = None) -> bytes:
    """RFC 9474 §4.1. Randomized: 32 random bytes before the message."""
    if not randomize:
        return bytes(msg)
    if prefix is None:
        prefix = secrets.token_bytes(PREFIX_LEN)
    if len(prefix) != PREFIX_LEN:
        raise BlindError("prefix must be 32 bytes")
    return bytes(prefix) + bytes(msg)


def emsa_pss_encode(msg: bytes, em_bits: int, salt: bytes) -> bytes:
    """RFC 8017 §9.1.1 with SHA-384 and MGF1-SHA-384."""
    em_len = (em_bits + 7) // 8
    s_len = len(salt)
    m_hash = HASH(msg).digest()
    if em_len < H_LEN + s_len + 2:
        raise BlindError("encoding error")
    m_prime = b"\x00" * 8 + m_hash + salt
    h = HASH(m_prime).digest()
    db = b"\x00" * (em_len - s_len - H_LEN - 2) + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, _mgf1(h, em_len - H_LEN - 1)))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked) + h + b"\xbc"


def emsa_pss_verify(msg: bytes, em: bytes, em_bits: int, s_len: int) -> bool:
    """RFC 8017 §9.1.2. Returns False for every inconsistency."""
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em_len < H_LEN + s_len + 2 or em[-1] != 0xBC:
        return False
    masked, h = em[: em_len - H_LEN - 1], em[em_len - H_LEN - 1 : -1]
    top_bits = 8 * em_len - em_bits
    if masked[0] & (0xFF << (8 - top_bits)) & 0xFF:
        return False
    db = bytearray(a ^ b for a, b in zip(masked, _mgf1(h, em_len - H_LEN - 1)))
    db[0] &= 0xFF >> top_bits
    pad_len = em_len - H_LEN - s_len - 2
    if any(db[:pad_len]) or db[pad_len] != 0x01:
        return False
    salt = bytes(db[len(db) - s_len :]) if s_len else b""
    m_prime = b"\x00" * 8 + HASH(msg).digest() + salt
    return secrets.compare_digest(HASH(m_prime).digest(), h)


def blind(
    n: int,
    e: int,
    prepared_msg: bytes,
    *,
    s_len: int = SALT_LEN,
    salt: bytes | None = None,
    r: int | None = None,
) -> tuple[bytes, bytes]:
    """RFC 9474 §4.2. Returns (blinded_msg, inv), both modulus-length bytes."""
    k = _modulus_len(n)
    if salt is None:
        salt = secrets.token_bytes(s_len)
    if len(salt) != s_len:
        raise BlindError("salt length mismatch")
    encoded = emsa_pss_encode(prepared_msg, n.bit_length() - 1, salt)
    m = _os2ip(encoded)
    if math.gcd(m, n) != 1:
        raise BlindError("invalid input")
    if r is None:
        while True:
            r = secrets.randbelow(n - 1) + 1
            if math.gcd(r, n) == 1:
                break
    elif not 1 <= r < n or math.gcd(r, n) != 1:
        raise BlindError("invalid blinding factor")
    inv = pow(r, -1, n)
    z = (m * pow(r, e, n)) % n
    return _i2osp(z, k), _i2osp(inv, k)


def blind_sign(n: int, e: int, d: int, blinded_msg: bytes) -> bytes:
    """RFC 9474 §4.3. The checker's step: sign without seeing the message."""
    k = _modulus_len(n)
    if len(blinded_msg) != k:
        raise BlindError("unexpected input size")
    m = _os2ip(blinded_msg)
    if m >= n:
        raise BlindError("invalid message length")
    s = pow(m, d, n)
    if pow(s, e, n) != m:
        raise BlindError("signing failure")
    return _i2osp(s, k)


def verify(n: int, e: int, prepared_msg: bytes, sig: bytes, *, s_len: int = SALT_LEN) -> bool:
    """RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) over the prepared message."""
    k = _modulus_len(n)
    if len(sig) != k:
        return False
    s = _os2ip(sig)
    if s >= n:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    m = pow(s, e, n)
    if m >= 1 << (8 * em_len):
        return False
    return emsa_pss_verify(prepared_msg, _i2osp(m, em_len), em_bits, s_len)


def finalize(
    n: int, e: int, prepared_msg: bytes, blind_sig: bytes, inv: bytes, *, s_len: int = SALT_LEN
) -> bytes:
    """RFC 9474 §4.4. Unblinds and refuses a signature that does not verify."""
    k = _modulus_len(n)
    if len(blind_sig) != k or len(inv) != k:
        raise BlindError("unexpected input size")
    s = (_os2ip(blind_sig) * _os2ip(inv)) % n
    sig = _i2osp(s, k)
    if not verify(n, e, prepared_msg, sig, s_len=s_len):
        raise BlindError("invalid signature")
    return sig
