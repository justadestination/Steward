#!/usr/bin/env python3
"""Extract RFC 9474 Appendix A test vectors into vectors/blind/rfc9474.json.

Usage: python3 tools/rfc9474_vectors.py /path/to/rfc9474.txt
The RFC text is fetched by hand from https://www.rfc-editor.org/rfc/rfc9474.txt;
this tool only parses it, so the vectors are the RFC's own bytes.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "vectors" / "blind" / "rfc9474.json"
SECTION = re.compile(r"^A\.(\d)\.\s+(RSABSSA-\S+) Test Vector\s*$")
FIELD = re.compile(r"^\s{3}([a-z_]+) = ([0-9a-f]*)\s*$")
HEX = re.compile(r"^\s{3}([0-9a-f]+)\s*$")


def parse(text: str) -> list[dict]:
    vectors: list[dict] = []
    current: dict | None = None
    field: str | None = None
    in_appendix = False
    for line in text.splitlines():
        if line.startswith("Appendix A.  Test Vectors"):
            in_appendix = True
            continue
        if not in_appendix:
            continue
        m = SECTION.match(line)
        if m:
            current = {"name": m.group(2), "section": f"A.{m.group(1)}"}
            vectors.append(current)
            field = None
            continue
        if line.startswith("Acknowledgments") or line.startswith("Authors' Addresses"):
            break
        if current is None:
            continue
        m = FIELD.match(line)
        if m:
            field = m.group(1)
            current[field] = m.group(2)
            continue
        m = HEX.match(line)
        if m and field:
            current[field] += m.group(1)
            continue
        # page breaks, headers and blank lines end nothing; a prose line ends the field
        if line.strip() and not line.startswith(("RFC 9474", "Denis, et al.")):
            field = None
    return vectors


def main() -> int:
    vectors = parse(Path(sys.argv[1]).read_text())
    if len(vectors) != 4:
        print(f"expected 4 vectors, got {len(vectors)}", file=sys.stderr)
        return 1
    OUT.write_text(json.dumps({"source": "RFC 9474 Appendix A", "vectors": vectors}, indent=2) + "\n")
    for v in vectors:
        print(v["section"], v["name"], sorted(k for k in v if k not in ("name", "section")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
