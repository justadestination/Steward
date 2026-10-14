#!/usr/bin/env python3
"""Write vectors/blind/cross.json: fresh random inputs, every intermediate value.

Uses the RFC 9474 A.1 key with a new random prefix, salt and blinding factor,
so the Python and JS engines are checked against each other on values the
RFC does not cover. Regenerate only when blind.py changes on purpose.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from steward import blind  # noqa: E402

RFC = json.loads((ROOT / "vectors" / "blind" / "rfc9474.json").read_text())["vectors"][0]
OUT = ROOT / "vectors" / "blind" / "cross.json"


def main() -> int:
    n, e, d = int(RFC["n"], 16), int(RFC["e"], 16), int(RFC["d"], 16)
    cases = []
    for msg in (b"stw_cross-steward-one", b"stw_" + secrets.token_hex(16).encode()):
        prefix = secrets.token_bytes(blind.PREFIX_LEN)
        salt = secrets.token_bytes(blind.SALT_LEN)
        prepared = blind.prepare(msg, prefix=prefix)
        blinded_msg, inv = blind.blind(n, e, prepared, salt=salt)
        r = pow(int.from_bytes(inv, "big"), -1, n)
        blind_sig = blind.blind_sign(n, e, d, blinded_msg)
        sig = blind.finalize(n, e, prepared, blind_sig, inv)
        cases.append({
            "msg": msg.hex(), "msg_prefix": prefix.hex(), "prepared_msg": prepared.hex(), "salt": salt.hex(),
            "r": format(r, "x"), "inv": inv.hex(), "blinded_msg": blinded_msg.hex(),
            "blind_sig": blind_sig.hex(), "sig": sig.hex(),
        })
    OUT.write_text(json.dumps({"key": "RFC 9474 A.1", "cases": cases}, indent=2) + "\n")
    print(f"wrote {len(cases)} cases to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
