"""The fixed vocabularies: signals, messages, and the posted house rules.

Graphs refer to these by id. Validation fails if a graph names an id that
is not here, so a typo is caught when a graph loads, not when a reader hits
the branch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data"
GRAPHS = Path(__file__).resolve().parent / "graphs"
HOUSE_RULES = ROOT / "policy" / "house_rules.json"


@dataclass(frozen=True)
class Catalog:
    # signal name -> allowed values, lowest to highest where order matters
    signals: dict[str, tuple[str, ...]]
    # message id -> exact wording shown to a person
    messages: dict[str, str]
    # ids of the posted house rules
    rule_ids: frozenset[str]

    def rank(self, signal: str, value: str) -> int:
        """Position of `value` in the signal's declared order."""
        return self.signals[signal].index(value)


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_catalog(house_rules: Path = HOUSE_RULES) -> Catalog:
    signals = {k: tuple(v) for k, v in load_json(DATA / "signals.json").items()}
    messages = load_json(DATA / "messages.json")
    rules = load_json(house_rules)
    return Catalog(
        signals=signals,
        messages=messages,
        rule_ids=frozenset(r["id"] for r in rules["rules"]),
    )
