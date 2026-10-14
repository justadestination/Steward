"""Registering a Steward key by redeeming its activation token, once.

    redeem(token_msg, token_sig, n, e, spki_der, seen_tokens) -> steward_id

The token is what the phone holds after activation: `token_msg` is the
prepared message `blind.prepare(steward_id.encode())` (a 32-byte random
prefix, then the UTF-8 Steward ID), and `token_sig` is the finalized RSA
blind signature over it (RFC 9474, RSABSSA-SHA384-PSS-Randomized).

A redeem succeeds only if all of these hold, checked in this order:
  1. token_msg names exactly the Steward ID of the key being registered
  2. token_sig verifies under the checker's public key (n, e)
  3. the token has not been redeemed before

Single use is keyed on sha256(token_sig) as a hex string, kept in
`seen_tokens` (any set-like with `in` and `add`). Only a successful redeem
adds to it. Every refusal raises RegisterError with a short reason.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import blind
from .identity import steward_id


class RegisterError(ValueError):
    """The token was refused. The message is a short reason."""


def token_key(token_sig: bytes) -> str:
    """The single-use key recorded for a redeemed token."""
    return hashlib.sha256(token_sig).hexdigest()


def redeem(
    token_msg: bytes,
    token_sig: bytes,
    n: int,
    e: int,
    spki_der: bytes,
    seen_tokens: Any,
) -> str:
    for name, value in (("token_msg", token_msg), ("token_sig", token_sig), ("spki_der", spki_der)):
        if not isinstance(value, (bytes, bytearray)) or not value:
            raise RegisterError(f"{name} must be non-empty bytes")
    token_msg, token_sig = bytes(token_msg), bytes(token_sig)

    sid = steward_id(bytes(spki_der))
    if len(token_msg) <= blind.PREFIX_LEN or token_msg[blind.PREFIX_LEN:] != sid.encode():
        raise RegisterError("token is for another Steward ID")
    if not blind.verify(n, e, token_msg, token_sig):
        raise RegisterError("token signature does not verify")
    key = token_key(token_sig)
    if key in seen_tokens:
        raise RegisterError("token already redeemed")
    seen_tokens.add(key)
    return sid
