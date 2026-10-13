from __future__ import annotations

import copy
from typing import Any

import pytest

from steward import graph as graphs
from steward.catalog import HOUSE_RULES, ROOT, load_catalog, load_json
from steward.engine import Step, start, step
from steward.events import Event
from steward.policy import validate_house_rules, validate_reader_profile


@pytest.fixture(scope="session")
def catalog():
    return load_catalog()


@pytest.fixture(scope="session")
def house_rules():
    return validate_house_rules(load_json(HOUSE_RULES))


@pytest.fixture(scope="session")
def profile(catalog):
    return validate_reader_profile(load_json(ROOT / "policy" / "reader_profile.example.json"), catalog)


@pytest.fixture(scope="session")
def load(catalog):
    return lambda name: graphs.load(name, catalog)


def ev(type_: str, at: str = "2026-10-12T20:00:00Z", payload: dict | None = None, signals: dict | None = None) -> Event:
    return Event.from_dict({"type": type_, "at": at, "payload": payload or {}, "signals": signals or {}})


class Runner:
    """Drives one instance through a graph, keeping every record."""

    def __init__(self, graph, policy, catalog, context: dict[str, Any] | None = None, instance_id: str = "t1"):
        self.graph, self.policy, self.catalog = graph, policy, catalog
        s = start(graph, instance_id, context)
        self.instance = s.instance
        self.records = [s.record]

    def send(self, event: Event) -> Step:
        s = step(self.graph, self.instance, event, copy.deepcopy(self.policy), self.catalog.signals)
        self.instance = s.instance
        self.records.append(s.record)
        return s

    @property
    def state(self) -> str:
        return self.instance.state


@pytest.fixture
def runner(catalog):
    return lambda graph, policy, context=None: Runner(graph, policy, catalog, context)
