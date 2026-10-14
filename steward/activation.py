"""The activation runner: one over-21 check, one blind signature, then scrub.

    run_activation(request, *, verify_presentation, signer, now, ledger=None)
        -> ("signed", blind_sig) or ("refused", None)

A request is exactly:
    {"blinded_msg": base64url str (unpadded) or bytes,
     "presentation": non-empty object (the issuer-signed "over 21" proof),
     "kind": non-empty str (presentation format, e.g. "mdl"),
     "challenge": non-empty str (the checker's nonce)}

The request never enters the graph. The runner holds it, feeds the
activation graph three events whose payloads are empty
(request -> verdict -> scrub), and the graph decides. Only the verdict's
two yes/no signals reach the ledger, so every ledger record is free of the
blinded message and of every presentation field.

`verify_presentation(request)` is injected (S2: the real mDL check). It
must return {"presentation_valid": "yes"|"no", "over_21": "yes"|"no"}.
Anything else, or any exception it raises, counts as refused.
`signer(blinded_msg: bytes) -> bytes` is injected (S2: the RSA private
key). It is called only when the graph reaches `signed`. If it raises, the
run is still scrubbed and the request cleared before the error propagates.

`now` is the instant stamped on every event ("2026-10-14T12:00:00Z").
`ledger`, if given, is a Path (records appended as JSON lines via
steward.ledger.append) or a list (records appended as dicts). Records come
from the engine only; this module never writes its own.

Scrubbing, and its limits. On return, whatever the outcome, the runner
clears the request dict (and the presentation dict inside it) and drops its
own references. In Python this is best effort: str and bytes are immutable
and cannot be overwritten in place, the injected callables may keep their
own copies, and the garbage collector decides when memory is reused. What
is guaranteed is that nothing from the request is written to the ledger
and that the caller's dict is empty afterwards.
"""

from __future__ import annotations

import base64
import binascii
import secrets
from pathlib import Path
from typing import Any, Callable

from . import graph as graphs
from . import ledger as ledgers
from .catalog import HOUSE_RULES, load_catalog, load_json
from .engine import start, step
from .events import Event
from .policy import validate_house_rules

REQUEST_KEYS = frozenset({"blinded_msg", "presentation", "kind", "challenge"})
VERDICT_KEYS = frozenset({"presentation_valid", "over_21"})
YES_NO = ("yes", "no")
REFUSED_SIGNALS = {"presentation_valid": "no", "over_21": "no"}

Ledger = Path | list | None


class _Malformed(ValueError):
    pass


def _b64url_decode(text: str) -> bytes:
    if not text or not text.isascii() or "=" in text:
        raise _Malformed("blinded_msg must be unpadded base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise _Malformed("blinded_msg must be unpadded base64url") from exc


def _blinded_bytes(request: Any) -> bytes:
    """The blinded message as bytes, or _Malformed if the request is not exactly right."""
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise _Malformed(f"request keys must be exactly {sorted(REQUEST_KEYS)}")
    if not isinstance(request["presentation"], dict) or not request["presentation"]:
        raise _Malformed("presentation must be a non-empty object")
    for key in ("kind", "challenge"):
        if not isinstance(request[key], str) or not request[key]:
            raise _Malformed(f"{key} must be a non-empty string")
    raw = request["blinded_msg"]
    if isinstance(raw, (bytes, bytearray)):
        msg = bytes(raw)
    elif isinstance(raw, str):
        msg = _b64url_decode(raw)
    else:
        raise _Malformed("blinded_msg must be base64url text or bytes")
    if not msg:
        raise _Malformed("blinded_msg must not be empty")
    return msg


def _verdict(request: dict, verify_presentation: Callable[[dict], Any]) -> dict[str, str]:
    """The checker's two signals; any surprise from the verifier is a refusal."""
    try:
        result = verify_presentation(request)
    except Exception:  # noqa: BLE001  any verifier failure is a refusal, never a pass
        return dict(REFUSED_SIGNALS)
    if not isinstance(result, dict) or set(result) != VERDICT_KEYS:
        return dict(REFUSED_SIGNALS)
    if any(result[k] not in YES_NO for k in VERDICT_KEYS):
        return dict(REFUSED_SIGNALS)
    return {k: result[k] for k in sorted(VERDICT_KEYS)}


def _scrub(request: Any) -> None:
    if isinstance(request, dict):
        presentation = request.get("presentation")
        if isinstance(presentation, dict):
            presentation.clear()
        request.clear()


def _record(ledger: Ledger, record: dict[str, Any]) -> None:
    if ledger is None:
        return
    if isinstance(ledger, list):
        ledger.append(record)
    else:
        ledgers.append(Path(ledger), record)


def run_activation(
    request: Any,
    *,
    verify_presentation: Callable[[dict], Any],
    signer: Callable[[bytes], bytes],
    now: str,
    ledger: Ledger = None,
) -> tuple[str, bytes | None]:
    catalog = load_catalog()
    g = graphs.load("activation", catalog)
    policy = validate_house_rules(load_json(HOUSE_RULES))

    def event(type_: str, signals: dict[str, str] | None = None) -> Event:
        return Event.from_dict({"type": type_, "at": now, "payload": {}, "signals": signals or {}})

    # Built before anything runs, so a bad `now` fails before a record exists.
    events = {t: event(t) for t in ("request", "scrub")}

    # A random instance id: nothing in the ledger is derived from the request.
    s = start(g, "activation-" + secrets.token_hex(8))
    _record(ledger, s.record)
    inst = s.instance
    blinded: bytes | None = None
    try:
        try:
            blinded = _blinded_bytes(request)
        except _Malformed:
            blinded = None

        s = step(g, inst, events["request"], policy, catalog.signals)
        _record(ledger, s.record)
        inst = s.instance

        signals = _verdict(request, verify_presentation) if blinded is not None else dict(REFUSED_SIGNALS)
        s = step(g, inst, event("verdict", signals), policy, catalog.signals)
        _record(ledger, s.record)
        inst = s.instance

        status = inst.state
        blind_sig: bytes | None = None
        try:
            if status == "signed":
                blind_sig = signer(blinded)
        finally:
            s = step(g, inst, events["scrub"], policy, catalog.signals)
            _record(ledger, s.record)
        return (status, blind_sig) if status == "signed" else ("refused", None)
    finally:
        blinded = None
        _scrub(request)
        del request
