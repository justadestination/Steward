"""Events: the only input a graph ever receives.

An event is fully self-describing. Everything a condition or action may
consult is inside it (payload, signals, timestamp) or in the policy passed
alongside it. Nothing reads the wall clock, the network, or a database.
That is what makes a ledger replayable.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

EVENT_KEYS = frozenset({"type", "at", "payload", "signals"})
INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class EventError(ValueError):
    """The event is malformed or does not match the graph's declaration."""


def parse_instant(text: str) -> datetime:
    """One accepted timestamp form, to the second: 2026-10-12T19:00:00Z.
    Offsets, fractions, spaces and other spellings are refused rather than
    normalised, so the same instant is always the same string, and the
    PWA engine (pwa/engine.js) accepts exactly the same set."""
    if not isinstance(text, str) or not INSTANT.fullmatch(text):
        raise EventError(f"timestamp must look like 2026-10-12T19:00:00Z: {text!r}")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise EventError(f"timestamp is not ISO 8601: {text!r}") from exc
    # Round-trip: rejects anything the parser normalised, e.g. T24:00:00 -> next day.
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise EventError(f"timestamp is not a real instant: {text!r}")
    return parsed.astimezone(timezone.utc)


def minutes_between(earlier: str, later: str) -> float:
    """Minutes from `earlier` to `later`. Negative if they are out of order."""
    return (parse_instant(later) - parse_instant(earlier)).total_seconds() / 60.0


@dataclass(frozen=True)
class Event:
    type: str
    at: str
    payload: dict[str, Any]
    signals: dict[str, str]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        if not isinstance(raw, dict):
            raise EventError("event must be a JSON object")
        keys = set(raw)
        if keys != EVENT_KEYS:
            missing = sorted(EVENT_KEYS - keys)
            extra = sorted(keys - EVENT_KEYS)
            raise EventError(f"event keys wrong: missing {missing}, unexpected {extra}")
        if not isinstance(raw["type"], str) or not raw["type"]:
            raise EventError("event type must be a non-empty string")
        parse_instant(raw["at"])
        if not isinstance(raw["payload"], dict):
            raise EventError("event payload must be an object")
        if not isinstance(raw["signals"], dict) or not all(
            isinstance(v, str) for v in raw["signals"].values()
        ):
            raise EventError("event signals must be an object of strings")
        return cls(
            type=raw["type"],
            at=raw["at"],
            payload=copy.deepcopy(raw["payload"]),
            signals=dict(raw["signals"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "at": self.at,
            "payload": copy.deepcopy(self.payload),
            "signals": dict(self.signals),
        }
