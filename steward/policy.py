"""The two policy documents a graph can run against.

house_rules     the zone's posted rules. Public. The House acts only on these.
reader_profile  one reader's own settings. Belongs to the reader.

Both are checked for exact shape on load. A policy that does not validate
is refused, never patched with defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .catalog import Catalog, load_json
from .events import parse_instant


class PolicyDocError(ValueError):
    pass


def _exact(where: str, obj: Any, keys: set[str]) -> None:
    if not isinstance(obj, dict) or set(obj) != keys:
        got = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        raise PolicyDocError(f"{where}: keys must be exactly {sorted(keys)}, got {got}")


PARAMETERS = {
    "max_consecutive_posts", "cool_off_minutes", "strike_expiry_days",
    "review_wait_hours", "review_deadline_hours", "review_warning_hours",
    "appeal_window_days", "appeal_review_hours", "frivolous_max_weight",
    "operator_stamp_bits", "operator_stamp_max_age_minutes",
}
STAMP_BITS_RANGE = (8, 28)  # below 8 is no friction; above 28 is minutes on a phone
TERM_CATEGORIES = {"profanity", "insult", "bullying", "hate", "threat"}
TIME_OUT_RANGE = (60, 240)  # R5: one to four hours


def validate_house_rules(doc: Any) -> dict[str, Any]:
    _exact("house_rules", doc, {"kind", "version", "posted", "rules", "addresses", "parameters", "conduct", "terms"})
    if doc["kind"] != "house_rules":
        raise PolicyDocError("house_rules: kind must be 'house_rules'")
    parse_instant(doc["posted"])
    ids = []
    for i, rule in enumerate(doc["rules"]):
        _exact(f"rules[{i}]", rule, {"id", "text"})
        ids.append(rule["id"])
    if len(ids) != len(set(ids)):
        raise PolicyDocError("rules: ids must be unique")

    _exact("addresses", doc["addresses"], {"operators"})
    op = doc["addresses"]["operators"]
    if not isinstance(op, str) or not op.isascii() or not op.isalnum() or op != op.casefold():
        raise PolicyDocError("addresses.operators: a lowercase ASCII handle, without the @")

    params = doc["parameters"]
    _exact("parameters", params, PARAMETERS)
    for k, v in params.items():
        if type(v) is not int or v < 1:
            raise PolicyDocError(f"parameters.{k}: must be a positive integer")
    if not params["review_wait_hours"] < params["review_deadline_hours"]:
        raise PolicyDocError("parameters: review must open before its deadline")
    if not params["review_warning_hours"] < params["review_deadline_hours"] - params["review_wait_hours"]:
        raise PolicyDocError("parameters: the deadline warning must fall after review opens")

    conduct = doc["conduct"]
    lo_b, hi_b = STAMP_BITS_RANGE
    if not lo_b <= params["operator_stamp_bits"] <= hi_b:
        raise PolicyDocError(f"parameters.operator_stamp_bits: must be {lo_b}-{hi_b}")

    _exact("conduct", conduct, {"strike_categories", "time_out_minutes"})
    cats = conduct["strike_categories"]
    if not isinstance(cats, list) or not cats or len(cats) != len(set(cats)) or not set(cats) <= TERM_CATEGORIES - {"profanity"}:
        raise PolicyDocError("conduct.strike_categories: unique abuse categories; profanity is never a strike")
    _exact("conduct.time_out_minutes", conduct["time_out_minutes"], set(cats))
    lo, hi = TIME_OUT_RANGE
    for k, v in conduct["time_out_minutes"].items():
        if type(v) is not int or not lo <= v <= hi:
            raise PolicyDocError(f"conduct.time_out_minutes.{k}: must be {lo}-{hi}")

    _exact("terms", doc["terms"], TERM_CATEGORIES)
    for k, v in doc["terms"].items():
        if not isinstance(v, list) or not all(isinstance(t, str) and t == t.casefold() and t.isalnum() and t.isascii() for t in v):
            raise PolicyDocError(f"terms.{k}: must be a list of lowercase ASCII single words")
    return doc


def is_reserved_handle(handle: str, house_rules: dict[str, Any]) -> bool:
    """R8: no Steward or Flag may take the operators' address, in any spelling."""
    return handle.casefold().lstrip("@") == house_rules["addresses"]["operators"]


def validate_reader_profile(doc: Any, catalog: Catalog) -> dict[str, Any]:
    _exact("reader_profile", doc, {"kind", "handle", "inbox"})
    if doc["kind"] != "reader_profile":
        raise PolicyDocError("reader_profile: kind must be 'reader_profile'")
    if not isinstance(doc["handle"], str) or not doc["handle"]:
        raise PolicyDocError("reader_profile.handle: must be a non-empty string")
    _exact("inbox", doc["inbox"], {"hold_at"})
    allowed = catalog.signals["hostility"][1:]  # "none" would hold everything
    if doc["inbox"]["hold_at"] not in allowed:
        raise PolicyDocError(f"inbox.hold_at: must be one of {list(allowed)}")
    return doc


def load_policy(path: Path, catalog: Catalog) -> dict[str, Any]:
    doc = load_json(path)
    kind = doc.get("kind") if isinstance(doc, dict) else None
    if kind == "house_rules":
        return validate_house_rules(doc)
    if kind == "reader_profile":
        return validate_reader_profile(doc, catalog)
    raise PolicyDocError(f"{path}: unknown policy kind {kind!r}")
