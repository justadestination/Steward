"""Shared test vectors: the contract between the Python and PWA engines.

Each file in vectors/ is one of two kinds:

  run      {"graph", "policy", "context", "instance", "events", "expected"}
           Feed the events in order from a fresh start; the ledger records
           must equal "expected" exactly, in both engines.
  rejects  {"graph", "policy", "rejects"}
           Each event, stepped from a fresh start, must be refused as an
           event error, in both engines.

`expected` is written by the Python engine (`python3 -m steward vectors
--write`) and then read by both test suites. Regenerate only when a change
in behaviour is intended, and review the diff.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import graph as graphs
from .catalog import ROOT, Catalog
from .engine import start, step
from .events import Event, EventError
from .policy import validate_house_rules, validate_reader_profile

VECTORS = ROOT / "vectors"


def _policy(doc: dict[str, Any], catalog: Catalog) -> dict[str, Any]:
    if doc.get("kind") == "house_rules":
        return validate_house_rules(doc)
    return validate_reader_profile(doc, catalog)


def run(vector: dict[str, Any], catalog: Catalog) -> list[dict[str, Any]]:
    g = graphs.load(vector["graph"], catalog)
    policy = _policy(vector["policy"], catalog)
    s = start(g, vector["instance"], vector["context"])
    records, inst = [s.record], s.instance
    for raw in vector["events"]:
        s = step(g, inst, Event.from_dict(raw), policy, catalog.signals)
        records.append(s.record)
        inst = s.instance
    return json.loads(json.dumps(records))


def rejected(vector: dict[str, Any], catalog: Catalog) -> list[int]:
    """Indexes of events that were NOT rejected. Empty means all good."""
    g = graphs.load(vector["graph"], catalog)
    policy = _policy(vector["policy"], catalog)
    accepted = []
    for i, raw in enumerate(vector["rejects"]):
        try:
            step(g, start(g, "reject").instance, Event.from_dict(raw), policy, catalog.signals)
        except EventError:
            continue
        accepted.append(i)
    return accepted


def files() -> list[Path]:
    return sorted(VECTORS.glob("*.json"))


def check_all(catalog: Catalog, write: bool = False) -> list[str]:
    problems = []
    for path in files():
        vector = json.loads(path.read_text(encoding="utf-8"))
        if "rejects" in vector:
            bad = rejected(vector, catalog)
            if bad:
                problems.append(f"{path.name}: events {bad} were accepted")
            continue
        got = run(vector, catalog)
        if write:
            vector["expected"] = got
            path.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        elif got != vector.get("expected"):
            problems.append(f"{path.name}: records differ from expected")
    return problems
