"""Proof of work for mail to @dontwastemytime (R8).

The sender's app searches for a nonce that makes SHA-256 of the message
start with `operator_stamp_bits` zero bits. About a second on a phone; one
hash to check. The work is bound to the exact message and its time, so it
cannot be done in advance or reused for another message.

This runs at the door, before an event exists, the same way a malformed
event is refused. The operator graphs themselves stay single-path: anything
that reaches them is filed.

A stamp identifies no one. It carries a time and a number, nothing else.

pwa/stamp.js is the counterpart that mints stamps in the app. Both build
the same bytes; vectors/stamps/ holds cases both must agree on.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .events import EventError, minutes_between, parse_instant

PREFIX = b"shadenet-stamp-v1\n"
STAMP_KEYS = frozenset({"v", "at", "nonce"})
MAIL_KEYS = frozenset({"mail_id", "case_id", "text"})
MAIL_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
NONCE = re.compile(r"[0-9a-f]{1,16}")
CLOCK_SKEW_MINUTES = 2  # a stamp may be this far in the future, no more


class StampError(ValueError):
    """The mail was refused at the door. The reason says which check failed."""


def _field(value: str | None) -> bytes:
    """Length-prefixed, so no two different messages share a preimage.
    None is '~', which can never be confused with a string (those start
    with a digit)."""
    if value is None:
        return b"~"
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise StampError("text is not valid Unicode") from exc
    return str(len(raw)).encode("ascii") + b":" + raw


def preimage(mail: dict[str, Any], at: str, nonce: str) -> bytes:
    return PREFIX + b"".join(
        _field(v) for v in (mail["mail_id"], mail["case_id"], mail["text"], at, nonce)
    )


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + (8 - byte.bit_length())
    return bits


def check_mail(mail: Any) -> None:
    if not isinstance(mail, dict) or set(mail) != MAIL_KEYS:
        raise StampError(f"mail keys must be exactly {sorted(MAIL_KEYS)}")
    if not isinstance(mail["mail_id"], str) or not MAIL_ID.fullmatch(mail["mail_id"]):
        raise StampError("mail_id must be 1-64 of A-Z a-z 0-9 _ -")
    if mail["case_id"] is not None and not isinstance(mail["case_id"], str):
        raise StampError("case_id must be a string or null")
    if not isinstance(mail["text"], str) or not mail["text"]:
        raise StampError("text must be a non-empty string")


def mint(mail: dict[str, Any], at: str, bits: int) -> dict[str, Any]:
    """Used by tests and tools. The app mints with pwa/stamp.js."""
    check_mail(mail)
    parse_instant(at)
    fixed = hashlib.sha256(PREFIX + b"".join(_field(v) for v in (mail["mail_id"], mail["case_id"], mail["text"], at)))
    n = 0
    while True:
        nonce = format(n, "x")
        h = fixed.copy()
        h.update(_field(nonce))
        if leading_zero_bits(h.digest()) >= bits:
            return {"v": 1, "at": at, "nonce": nonce}
        n += 1


def verify(mail: Any, stamp: Any, arrived_at: str, house_rules: dict[str, Any]) -> None:
    """Raises StampError, or returns None if the mail may become an event."""
    check_mail(mail)
    if not isinstance(stamp, dict) or set(stamp) != STAMP_KEYS:
        raise StampError(f"stamp keys must be exactly {sorted(STAMP_KEYS)}")
    # JSON 1 and 1.0 are the same number to the JS side, so both are version 1 here too.
    if isinstance(stamp["v"], bool) or stamp["v"] != 1:
        raise StampError("unknown stamp version")
    if not isinstance(stamp["nonce"], str) or not NONCE.fullmatch(stamp["nonce"]):
        raise StampError("nonce must be 1-16 lowercase hex digits")
    try:
        age = minutes_between(stamp["at"], arrived_at)
    except EventError as exc:
        raise StampError(f"stamp time: {exc}") from exc
    params = house_rules["parameters"]
    if age > params["operator_stamp_max_age_minutes"]:
        raise StampError("stamp is too old")
    if age < -CLOCK_SKEW_MINUTES:
        raise StampError("stamp is from the future")
    digest = hashlib.sha256(preimage(mail, stamp["at"], stamp["nonce"])).digest()
    if leading_zero_bits(digest) < params["operator_stamp_bits"]:
        raise StampError("not enough work")


class SeenMail:
    """Refuses a mail_id seen within the stamp lifetime. Stamps bind the
    mail_id, so replaying one means replaying the same mail. Entries older
    than the lifetime are dropped: an old stamp fails the age check anyway."""

    def __init__(self, house_rules: dict[str, Any]):
        self._ttl = house_rules["parameters"]["operator_stamp_max_age_minutes"] + CLOCK_SKEW_MINUTES
        self._seen: dict[str, str] = {}

    def admit(self, mail_id: str, arrived_at: str) -> None:
        self._seen = {k: t for k, t in self._seen.items() if minutes_between(t, arrived_at) <= self._ttl}
        if mail_id in self._seen:
            raise StampError("this mail has already been delivered")
        self._seen[mail_id] = arrived_at
