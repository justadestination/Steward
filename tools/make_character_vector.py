"""Writes vectors/character/fingerprint.json: canonical bytes (hex) and
fingerprint for the character skeleton and for one non-ASCII example.

    python3 tools/make_character_vector.py

Python writes the expected values; tests/test_character.py and
pwa/test/character.test.mjs must both reproduce them exactly.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from steward.character import canonical, fingerprint, load  # noqa: E402

OUT = ROOT / "vectors" / "character" / "fingerprint.json"

# Keys deliberately out of order; values cover accents, CJK, an emoji above
# U+FFFF, escapes JSON must write (quote, backslash, newline, tab, U+0001),
# nesting, integers, booleans and null. No floats (see steward/character.py).
NON_ASCII = {
    "version": 2,
    "voice": {"name": "Stéward", "greeting": "こんにちは — ça va? ✨🌙", "quiet": True},
    "rules": {"z_last": ["ä", "ß", "名前"], "a_first": None, "escapes": "quote\" back\\ nl\n tab\t ctl\u0001"},
    "source": "Ünïcödé test example, not a real character",
}


def case(name, obj):
    data = canonical(obj)
    return {"name": name, "character": obj, "canonical_hex": data.hex(), "fingerprint": fingerprint(obj)}


def main() -> int:
    vector = {
        "about": "canonical = JSON, sorted keys, separators (',', ':'), non-ASCII unescaped, UTF-8; "
                 "fingerprint = base64url unpadded SHA-256 of canonical bytes",
        "cases": [case("skeleton", load()), case("non_ascii", NON_ASCII)],
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
