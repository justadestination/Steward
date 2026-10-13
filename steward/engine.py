"""The engine: one pure function from (graph, instance, event, policy) to a step.

Given the same inputs it produces the same record, byte for byte. Branches
are tried in declared order; the first whose condition holds is taken, and
"otherwise" always holds.

Two kinds of "no":
  * An event type the graph never declared, or an event that does not match
    its declaration, is a caller error and raises EventError.
  * A declared event arriving in a state that has no transition for it is
    recorded with outcome "not_accepted". The instance stays put. It is
    logged rather than silently ignored.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from .events import Event, EventError
from .graph import Graph
from .registry import ACTIONS, CONDITIONS, OTHERWISE, OUTPUT_KINDS


class PolicyError(ValueError):
    """The policy passed in is not the kind this graph runs against."""


@dataclass(frozen=True)
class Instance:
    graph: str
    id: str
    state: str
    context: dict[str, Any]
    seq: int


@dataclass(frozen=True)
class Step:
    instance: Instance
    record: dict[str, Any]


def start(graph: Graph, instance_id: str, context: dict[str, Any] | None = None) -> Step:
    ctx = copy.deepcopy(context or {})
    inst = Instance(graph.name, instance_id, graph.initial, ctx, 0)
    record = {
        "record": "start",
        "graph": graph.name,
        "version": graph.version,
        "instance": instance_id,
        "seq": 0,
        "state": graph.initial,
        "context": copy.deepcopy(ctx),
    }
    return Step(inst, record)


def check_event(graph: Graph, event: Event, signal_values: dict[str, tuple[str, ...]]) -> None:
    decl = graph.events.get(event.type)
    if decl is None:
        raise EventError(f"graph {graph.name!r} has no event {event.type!r}")
    if set(event.payload) != decl.payload:
        raise EventError(
            f"{event.type}: payload keys must be exactly {sorted(decl.payload)}, got {sorted(event.payload)}"
        )
    if set(event.signals) != decl.signals:
        raise EventError(
            f"{event.type}: signals must be exactly {sorted(decl.signals)}, got {sorted(event.signals)}"
        )
    for name, value in event.signals.items():
        if value not in signal_values[name]:
            raise EventError(f"{event.type}: signal {name}={value!r} not in {list(signal_values[name])}")


def step(
    graph: Graph,
    instance: Instance,
    event: Event,
    policy: dict[str, Any],
    signal_values: dict[str, tuple[str, ...]],
) -> Step:
    if instance.graph != graph.name:
        raise ValueError(f"instance belongs to {instance.graph!r}, not {graph.name!r}")
    if policy.get("kind") != graph.policy:
        raise PolicyError(f"graph {graph.name!r} runs against {graph.policy!r}, got {policy.get('kind')!r}")
    check_event(graph, event, signal_values)

    seq = instance.seq + 1
    record: dict[str, Any] = {
        "record": "step",
        "graph": graph.name,
        "version": graph.version,
        "instance": instance.id,
        "seq": seq,
        "event": event.to_dict(),
        "from": instance.state,
    }

    branches = graph.transitions.get((instance.state, event.type))
    if branches is None:
        record.update(outcome="not_accepted", branch=None, when=None, to=instance.state, actions=[], outputs=[],
                      context=copy.deepcopy(instance.context))
        return Step(replace(instance, seq=seq), record)

    view = MappingProxyType(copy.deepcopy(instance.context))
    frozen_policy = MappingProxyType(policy)
    for index, branch in enumerate(branches):
        if branch.when == OTHERWISE:
            break
        result = CONDITIONS[branch.when].fn(event, view, frozen_policy)
        if type(result) is not bool:
            raise TypeError(f"condition {branch.when!r} returned {type(result).__name__}, not bool")
        if result:
            break

    context = copy.deepcopy(instance.context)
    outputs: list[dict[str, Any]] = []
    for call in branch.do:
        res = ACTIONS[call.action].fn(event, MappingProxyType(copy.deepcopy(context)), frozen_policy, call.args)
        context.update(copy.deepcopy(res.updates))
        for out in res.outputs:
            if out.kind not in OUTPUT_KINDS:
                raise ValueError(f"action {call.action!r} emitted unknown output {out.kind!r}")
            outputs.append(out.to_dict())

    record.update(
        outcome="taken",
        branch=index,
        when=branch.when,
        to=branch.to,
        actions=[{"action": c.action, "args": dict(c.args)} for c in branch.do],
        outputs=outputs,
        context=copy.deepcopy(context),
    )
    return Step(Instance(graph.name, instance.id, branch.to, context, seq), record)
