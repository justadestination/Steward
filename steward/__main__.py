"""Command line.

    python3 -m steward check
    python3 -m steward describe GRAPH
    python3 -m steward vectors [--write]
    python3 -m steward run GRAPH --events FILE.jsonl --policy FILE.json
                              [--context FILE.json] [--instance ID] [--ledger OUT.jsonl]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import graph as graphs
from .catalog import load_catalog, load_json
from .engine import start, step
from .events import Event
from .ledger import append
from .policy import load_policy, validate_house_rules
from .registry import OTHERWISE


def cmd_check(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    validate_house_rules(load_json(Path(args.house_rules)))
    failed = 0
    for name in graphs.names():
        try:
            g = graphs.load(name, catalog)
        except graphs.GraphError as exc:
            failed += 1
            print(exc)
            continue
        print(f"ok  {name} v{g.version}: {len(g.states)} states, {len(g.transitions)} transitions")
    return 1 if failed else 0


def cmd_describe(args: argparse.Namespace) -> int:
    g = graphs.load(args.graph, load_catalog())
    print("stateDiagram-v2")
    print(f"    [*] --> {g.initial}")
    for (src, ev), branches in g.transitions.items():
        for br in branches:
            label = ev if br.when == OTHERWISE else f"{ev} [{br.when}]"
            print(f"    {src} --> {br.to} : {label}")
    for t in sorted(g.terminal):
        print(f"    {t} --> [*]")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    g = graphs.load(args.graph, catalog)
    policy = load_policy(Path(args.policy), catalog)
    context = load_json(Path(args.context)) if args.context else {}
    ledger = Path(args.ledger) if args.ledger else None

    def emit(record: dict) -> None:
        print(json.dumps(record, sort_keys=True, ensure_ascii=False))
        if ledger:
            append(ledger, record)

    s = start(g, args.instance, context)
    emit(s.record)
    inst = s.instance
    with open(args.events, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                s = step(g, inst, Event.from_dict(json.loads(line)), policy, catalog.signals)
                emit(s.record)
                inst = s.instance
    return 0


def cmd_vectors(args: argparse.Namespace) -> int:
    from .vectors import check_all, files
    problems = check_all(load_catalog(), write=args.write)
    for p in problems:
        print(p)
    if not problems:
        print(f"ok  {len(files())} vectors" + (" (expected rewritten)" if args.write else ""))
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="steward")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="validate every graph and the posted house rules")
    c.add_argument("--house-rules", default=str(Path(__file__).resolve().parent.parent / "policy" / "house_rules.json"))
    d = sub.add_parser("describe", help="print a graph as a Mermaid state diagram")
    d.add_argument("graph")
    r = sub.add_parser("run", help="run events through a graph and print ledger records")
    r.add_argument("graph")
    r.add_argument("--events", required=True)
    r.add_argument("--policy", required=True)
    r.add_argument("--context")
    r.add_argument("--instance", default="cli")
    r.add_argument("--ledger")
    v = sub.add_parser("vectors", help="check shared engine vectors against the Python engine")
    v.add_argument("--write", action="store_true", help="rewrite expected records (review the diff)")
    args = p.parse_args(argv)
    return {"check": cmd_check, "describe": cmd_describe, "run": cmd_run, "vectors": cmd_vectors}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
