"""Loading and validating graph documents.

A graph is valid only if every one of these holds:

  shape       exact top-level keys; no unknown keys anywhere
  states      initial and every terminal are declared states
  events      every event declares its exact payload keys and signals;
              every signal exists in data/signals.json
  coverage    each (state, event) pair appears at most once
  branches    non-empty; the last branch, and only the last, is "otherwise"
  names       every condition and action is registered
  reads       everything a condition or action reads is declared on the event
  args        action args match the action's params exactly, by type
  terminals   terminal states have no outgoing transitions
  liveness    every non-terminal state has at least one outgoing transition
  reachable   every state is reachable from initial

All problems are collected and reported together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import actions as _actions  # noqa: F401  registers actions
from . import conditions as _conditions  # noqa: F401  registers conditions
from .catalog import GRAPHS, Catalog
from .registry import ACTIONS, CONDITIONS, MESSAGE_ID, OTHERWISE, QUESTION_ID, RULE_ID

GRAPH_KEYS = {"graph", "version", "policy", "initial", "terminal", "events", "states", "transitions"}
EVENT_DECL_KEYS = {"payload", "signals"}
TRANSITION_KEYS = {"from", "on", "branches"}
BRANCH_KEYS = {"when", "to", "do"}
CALL_KEYS = {"action", "args"}
POLICY_KINDS = {"house_rules", "reader_profile"}


class GraphError(ValueError):
    def __init__(self, name: str, problems: list[str]):
        self.problems = problems
        super().__init__(f"graph {name!r} is invalid:\n  - " + "\n  - ".join(problems))


@dataclass(frozen=True)
class Call:
    action: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Branch:
    when: str
    to: str
    do: tuple[Call, ...]


@dataclass(frozen=True)
class EventDecl:
    payload: frozenset[str]
    signals: frozenset[str]


@dataclass(frozen=True)
class Graph:
    name: str
    version: int
    policy: str
    initial: str
    terminal: frozenset[str]
    events: dict[str, EventDecl]
    states: dict[str, str]
    transitions: dict[tuple[str, str], tuple[Branch, ...]]


def _keys(problems: list[str], where: str, obj: Any, expected: set[str]) -> bool:
    if not isinstance(obj, dict):
        problems.append(f"{where}: must be an object")
        return False
    if set(obj) != expected:
        problems.append(
            f"{where}: keys must be exactly {sorted(expected)}, got {sorted(obj)}"
        )
        return False
    return True


def _check_arg(problems: list[str], where: str, kind: Any, value: Any, catalog: Catalog) -> None:
    if isinstance(kind, tuple):
        if value not in kind:
            problems.append(f"{where}: {value!r} is not one of {list(kind)}")
    elif kind == MESSAGE_ID:
        if value not in catalog.messages:
            problems.append(f"{where}: message {value!r} is not in messages.json")
    elif kind == RULE_ID:
        if value not in catalog.rule_ids:
            problems.append(f"{where}: rule {value!r} is not a posted house rule")
    elif kind == QUESTION_ID:
        if not isinstance(value, str) or not value:
            problems.append(f"{where}: question id must be a non-empty string")
    else:
        problems.append(f"{where}: unknown parameter type {kind!r}")


def validate(raw: Any, catalog: Catalog) -> Graph:
    name = raw.get("graph", "?") if isinstance(raw, dict) else "?"
    problems: list[str] = []
    if not _keys(problems, "graph", raw, GRAPH_KEYS):
        raise GraphError(name, problems)

    if not isinstance(raw["version"], int) or raw["version"] < 1:
        problems.append("version: must be a positive integer")
    if raw["policy"] not in POLICY_KINDS:
        problems.append(f"policy: must be one of {sorted(POLICY_KINDS)}")

    states = raw["states"]
    if not isinstance(states, dict) or not states or not all(
        isinstance(v, str) and v for v in states.values()
    ):
        problems.append("states: must map each state to a one-line description")
        states = {}
    if raw["initial"] not in states:
        problems.append(f"initial: {raw['initial']!r} is not a declared state")
    terminal = set(raw["terminal"]) if isinstance(raw["terminal"], list) else set()
    for t in sorted(terminal - set(states)):
        problems.append(f"terminal: {t!r} is not a declared state")

    events: dict[str, EventDecl] = {}
    if not isinstance(raw["events"], dict) or not raw["events"]:
        problems.append("events: must be a non-empty object")
    raw_events = raw["events"] if isinstance(raw["events"], dict) else {}
    if not isinstance(raw["transitions"], list):
        problems.append("transitions: must be a list")
        raise GraphError(name, problems)
    for ev, decl in raw_events.items():
        if not _keys(problems, f"events.{ev}", decl, EVENT_DECL_KEYS):
            continue
        for s in decl["signals"]:
            if s not in catalog.signals:
                problems.append(f"events.{ev}: signal {s!r} is not in signals.json")
        events[ev] = EventDecl(frozenset(decl["payload"]), frozenset(decl["signals"]))

    transitions: dict[tuple[str, str], tuple[Branch, ...]] = {}
    for i, tr in enumerate(raw["transitions"]):
        where = f"transitions[{i}]"
        if not _keys(problems, where, tr, TRANSITION_KEYS):
            continue
        src, ev = tr["from"], tr["on"]
        where = f"{where} ({src} --{ev}-->)"
        if src not in states:
            problems.append(f"{where}: from-state is not declared")
        if src in terminal:
            problems.append(f"{where}: terminal state has an outgoing transition")
        if ev not in events:
            problems.append(f"{where}: event is not declared")
            continue
        if (src, ev) in transitions:
            problems.append(f"{where}: duplicate (state, event) pair")
            continue
        decl = events[ev]
        branches = tr["branches"]
        if not isinstance(branches, list) or not branches:
            problems.append(f"{where}: branches must be a non-empty list")
            continue
        built: list[Branch] = []
        for j, br in enumerate(branches):
            bw = f"{where} branch {j}"
            if not _keys(problems, bw, br, BRANCH_KEYS):
                continue
            last = j == len(branches) - 1
            if br["when"] == OTHERWISE and not last:
                problems.append(f"{bw}: 'otherwise' must be the last branch")
            if last and br["when"] != OTHERWISE:
                problems.append(f"{bw}: last branch must be 'otherwise'")
            if br["when"] != OTHERWISE:
                cond = CONDITIONS.get(br["when"])
                if cond is None:
                    problems.append(f"{bw}: condition {br['when']!r} is not registered")
                else:
                    for k in sorted(cond.payload - decl.payload):
                        problems.append(f"{bw}: condition reads payload {k!r} not declared on {ev!r}")
                    for k in sorted(cond.signals - decl.signals):
                        problems.append(f"{bw}: condition reads signal {k!r} not declared on {ev!r}")
            if br["to"] not in states:
                problems.append(f"{bw}: to-state {br['to']!r} is not declared")
            calls: list[Call] = []
            for k, call in enumerate(br["do"]):
                cw = f"{bw} do[{k}]"
                if not _keys(problems, cw, call, CALL_KEYS):
                    continue
                act = ACTIONS.get(call["action"])
                if act is None:
                    problems.append(f"{cw}: action {call['action']!r} is not registered")
                    continue
                if not isinstance(call["args"], dict) or set(call["args"]) != set(act.params):
                    problems.append(f"{cw}: args must be exactly {sorted(act.params)}")
                    continue
                for p, kind in act.params.items():
                    _check_arg(problems, f"{cw}.{p}", kind, call["args"][p], catalog)
                for p in sorted(act.payload - decl.payload):
                    problems.append(f"{cw}: action reads payload {p!r} not declared on {ev!r}")
                for p in sorted(act.signals - decl.signals):
                    problems.append(f"{cw}: action reads signal {p!r} not declared on {ev!r}")
                calls.append(Call(call["action"], dict(call["args"])))
            built.append(Branch(br["when"], br["to"], tuple(calls)))
        transitions[(src, ev)] = tuple(built)

    sources = {src for src, _ in transitions}
    for s in sorted(set(states) - terminal - sources):
        problems.append(f"state {s!r}: not terminal but has no outgoing transition")

    if raw["initial"] in states:
        seen, frontier = {raw["initial"]}, [raw["initial"]]
        while frontier:
            here = frontier.pop()
            for (src, _), branches in transitions.items():
                if src == here:
                    for br in branches:
                        if br.to in states and br.to not in seen:
                            seen.add(br.to)
                            frontier.append(br.to)
        for s in sorted(set(states) - seen):
            problems.append(f"state {s!r}: unreachable from {raw['initial']!r}")

    if problems:
        raise GraphError(name, problems)
    return Graph(
        name=raw["graph"],
        version=raw["version"],
        policy=raw["policy"],
        initial=raw["initial"],
        terminal=frozenset(terminal),
        events=events,
        states=dict(states),
        transitions=transitions,
    )


def load(name: str, catalog: Catalog, directory: Path = GRAPHS) -> Graph:
    with (directory / f"{name}.json").open(encoding="utf-8") as fh:
        raw = json.load(fh)
    graph = validate(raw, catalog)
    if graph.name != name:
        raise GraphError(name, [f"file {name}.json declares graph {graph.name!r}"])
    return graph


def names(directory: Path = GRAPHS) -> list[str]:
    return sorted(p.stem for p in directory.glob("*.json"))
