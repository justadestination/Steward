"""Deterministic signal producer: posted word lists, nothing learned.

This is the floor, not the ceiling. A model can replace it later without
touching any graph, because graphs read signals, not text. Whatever
produces them, the values are stored with each event in the ledger, so
replay never re-runs the producer.

Matching is on whole lowercase ASCII words. Multi-word phrases are not
supported, and the posted terms are validated to be single words.
"""

from __future__ import annotations

import re
from typing import Any

WORD = re.compile(r"[a-z0-9]+")

# Most severe first. A text matching several categories gets the first one.
SEVERITY = ("threat", "hate", "bullying", "insult")


def words(text: str) -> set[str]:
    return set(WORD.findall(text.casefold()))


def classify(text: str, house_rules: dict[str, Any], reader_handle: str | None = None) -> dict[str, str]:
    """All signals for one piece of text.

    abuse      the most severe posted category that matches, else none
    profanity  yes if any posted profanity term appears. Never a strike.
    hostility  how hostile the text is *toward reader_handle*:
               strong = hate or threat, and names the reader
               mild   = insult or bullying, and names the reader
               none   = otherwise, including when no reader is given
    """
    found = words(text)
    terms = house_rules["terms"]
    abuse = next((c for c in SEVERITY if found & set(terms[c])), "none")
    named = reader_handle is not None and reader_handle.casefold().lstrip("@") in found
    if named and abuse in ("hate", "threat"):
        hostility = "strong"
    elif named and abuse in ("insult", "bullying"):
        hostility = "mild"
    else:
        hostility = "none"
    return {
        "abuse": abuse,
        "profanity": "yes" if found & set(terms["profanity"]) else "no",
        "hostility": hostility,
    }


def select(signals: dict[str, str], names: frozenset[str]) -> dict[str, str]:
    """Exactly the signals an event declares, no more."""
    return {k: signals[k] for k in sorted(names)}
