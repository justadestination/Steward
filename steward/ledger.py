"""Append-only ledger and replay.

One JSON object per line. Nothing is rewritten or removed. Every step
records the context it left behind, so the ledger alone shows what the
Steward knows. Replay rebuilds an instance from its start record by
re-running every recorded event, and fails on the first record that does
not come out identical. That is the determinism check: a ledger that
cannot be replayed is a bug.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .engine import Instance, start, step
from .events import Event
from .graph import Graph


class ReplayMismatch(AssertionError):
    pass


def append(path: Path, record: dict[str, Any]) -> None:
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def replay(
    graph: Graph,
    records: Iterable[dict[str, Any]],
    policy: dict[str, Any],
    signal_values: dict[str, tuple[str, ...]],
) -> Instance:
    records = list(records)
    if not records or records[0].get("record") != "start":
        raise ReplayMismatch("ledger must begin with a start record")
    first = records[0]
    if first["graph"] != graph.name or first["version"] != graph.version:
        raise ReplayMismatch(
            f"ledger is {first['graph']} v{first['version']}, graph is {graph.name} v{graph.version}"
        )
    s = start(graph, first["instance"], first["context"])
    if _canonical(s.record) != _canonical(first):
        raise ReplayMismatch("start record differs")
    inst = s.instance
    for expected in records[1:]:
        s = step(graph, inst, Event.from_dict(expected["event"]), policy, signal_values)
        if _canonical(s.record) != _canonical(expected):
            raise ReplayMismatch(f"record seq={expected.get('seq')} differs on replay")
        inst = s.instance
    return inst
