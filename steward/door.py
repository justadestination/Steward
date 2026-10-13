"""The door for @dontwastemytime (R8): request in, event out, or refused.

Everything that can refuse happens here, before an event exists. Once a
request becomes an event, operator_inbox files it; there is no other path.

A request is exactly:
    {"mail": {"mail_id", "case_id", "text"},
     "stamp": {"v", "at", "nonce"},
     "steward_id": str or null}

steward_id is set by the transport from a verified Steward signature, or
null for the no-Steward web form. Never from anything the sender typed.
"""

from __future__ import annotations

from typing import Any

from .classify import classify
from .events import Event
from .stamp import SeenMail, StampError, verify

REQUEST_KEYS = frozenset({"mail", "stamp", "steward_id"})


def operator_mail_event(
    request: Any,
    arrived_at: str,
    house_rules: dict[str, Any],
    seen: SeenMail,
) -> Event:
    """Raises StampError with the reason, or returns the operator_inbox event."""
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise StampError(f"request keys must be exactly {sorted(REQUEST_KEYS)}")
    if request["steward_id"] is not None and not isinstance(request["steward_id"], str):
        raise StampError("steward_id must be a string or null")
    mail = request["mail"]
    verify(mail, request["stamp"], arrived_at, house_rules)
    seen.admit(mail["mail_id"], arrived_at)  # last: only stamped mail can occupy a mail_id
    return Event.from_dict({
        "type": "arrive",
        "at": arrived_at,
        "payload": {
            "mail_id": mail["mail_id"],
            "steward_id": request["steward_id"],
            "case_id": mail["case_id"],
            "text": mail["text"],
        },
        # A label for the operator reading it, never a reason to stop it.
        "signals": {"abuse": classify(mail["text"], house_rules)["abuse"]},
    })
