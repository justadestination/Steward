"""The Steward's character file: canonical bytes and fingerprint.

The House signs the character file (Ed25519, House key on the server). On
every connect the Steward sends the fingerprint of its own copy; if it
differs from the House's, the House returns the signed original and the
Steward restores it (graph `restore`, run on the phone; signature check in
pwa/character.js). The reader profile is never read or written here.

canonical(obj) must produce exactly the bytes of `canonical` in
pwa/engine.js, UTF-8 encoded: sorted keys, no spaces, non-ASCII kept as is.
vectors/character/fingerprint.json pins both sides to the same bytes.

Limits of that equality, enforced or noted:
  * floats are refused: Python writes 1.0 where JS writes 1;
  * keys are sorted by code point here and by UTF-16 unit in JS; the two
    agree unless keys mix characters above U+FFFF with ones from
    U+E000-U+FFFF. Keep keys out of that corner.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .catalog import DATA

CHARACTER = DATA / "character.json"


def _no_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("character values must not be floats (JS writes 1.0 as 1)")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("character keys must be strings")
            _no_floats(v)
    elif isinstance(value, list):
        for v in value:
            _no_floats(v)


def canonical(obj: Any) -> bytes:
    """JSON with sorted keys, separators (",", ":"), non-ASCII unescaped, UTF-8."""
    _no_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(obj: Any) -> str:
    """base64url, unpadded, of SHA-256 over canonical(obj)."""
    digest = hashlib.sha256(canonical(obj)).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def load(path: Path = CHARACTER) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)
