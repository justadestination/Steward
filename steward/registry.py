"""The closed sets of conditions and actions a graph may name.

Conditions answer one yes/no question from (event, context, policy).
Actions return context updates and outputs. Neither performs I/O; outputs
are instructions for whatever runs the graph (a web server, a CLI, a test).

Each entry declares exactly which event payload keys and signals it reads.
The validator checks those against every event the entry is used on, so a
condition can never be wired to an event that lacks what it needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .events import Event

OTHERWISE = "otherwise"

# Parameter types for actions. A tuple means "one of these literal values".
MESSAGE_ID = "message-id"   # must exist in data/messages.json
RULE_ID = "rule-id"         # must exist in policy/house_rules.json
QUESTION_ID = "question-id"  # free identifier naming what the reader was asked

# The only output kinds the engine will pass to the runner.
OUTPUT_KINDS = frozenset({
    # Steward (PWA)
    "say",                # Steward speaks to its own ward
    "deliver",            # Steward shows an incoming message to its ward
    "forward_to_house",   # Steward sends the ward's post on to the House
    "forward_to_operators",  # R8: Steward sends mail to @dontwastemytime
    "open_case",          # Steward has left; sends the strike evidence, nothing else
    "destroy_ward_data",  # Steward's sealed data is destroyed on the phone
    # House (server)
    "publish",            # House publishes a submission
    "return_to_sender",   # House sends a submission back, naming the rule
    "withhold",           # House keeps a submission out; never routed to the sender
    # Review (server)
    "notify_operators",   # shown in the operator panel
    "operator_mail",      # R8: a message filed in the operators' inbox
    "tell_steward",       # an event delivered to one Steward, by Steward id
    "record_mark",        # a mark on a Steward line (never on a person)
    "set_mark_weight",    # operator's penalty for a frivolous appeal (R7)
    "remove_mark",
    "issue_successor",    # a new Steward on the same line, starting over
    "retire_successor",   # departure overturned on appeal: the original returns
    "delete_evidence",    # the case's exchanges are deleted; only the mark remains
})


@dataclass(frozen=True)
class Output:
    kind: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, **self.data}


@dataclass(frozen=True)
class ActionResult:
    updates: dict[str, Any] = field(default_factory=dict)
    outputs: tuple[Output, ...] = ()


ConditionFn = Callable[[Event, Mapping[str, Any], Mapping[str, Any]], bool]
ActionFn = Callable[[Event, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], ActionResult]


@dataclass(frozen=True)
class Condition:
    name: str
    fn: ConditionFn
    payload: frozenset[str]
    signals: frozenset[str]


@dataclass(frozen=True)
class Action:
    name: str
    fn: ActionFn
    params: dict[str, Any]
    payload: frozenset[str]
    signals: frozenset[str]


CONDITIONS: dict[str, Condition] = {}
ACTIONS: dict[str, Action] = {}


def condition(name: str, *, payload: tuple[str, ...] = (), signals: tuple[str, ...] = ()):
    if name == OTHERWISE:
        raise ValueError(f"{OTHERWISE!r} is reserved")

    def register(fn: ConditionFn) -> ConditionFn:
        if name in CONDITIONS:
            raise ValueError(f"condition {name!r} registered twice")
        CONDITIONS[name] = Condition(name, fn, frozenset(payload), frozenset(signals))
        return fn

    return register


def action(
    name: str,
    *,
    params: dict[str, Any] | None = None,
    payload: tuple[str, ...] = (),
    signals: tuple[str, ...] = (),
):
    def register(fn: ActionFn) -> ActionFn:
        if name in ACTIONS:
            raise ValueError(f"action {name!r} registered twice")
        ACTIONS[name] = Action(name, fn, dict(params or {}), frozenset(payload), frozenset(signals))
        return fn

    return register
