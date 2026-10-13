"""Registered actions. Each returns context updates and outputs, nothing else.

Actions never perform I/O. An output is an instruction to the runner,
drawn from the closed set in registry.OUTPUT_KINDS.
"""

from __future__ import annotations

from typing import Any, Mapping

from .events import Event
from .registry import MESSAGE_ID, QUESTION_ID, RULE_ID, ActionResult, Output, action

# Events the server may send to a Steward. Each is declared on the conduct graph.
STEWARD_EVENTS_ABOUT_STRIKES = ("strike_overturned", "strike_upheld", "appeal_refused")


# ---- Shared -----------------------------------------------------------------

@action("say", params={"message": MESSAGE_ID})
def say(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("say", {"message": args["message"]}),))


# ---- Steward: introduction --------------------------------------------------

@action(
    "record_answer",
    params={"question": QUESTION_ID, "answer": ("yes", "no"), "channel": ("tap", "escape", "silence")},
)
def record_answer(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Append, never overwrite. A later answer to the same question names the
    entry it corrects, and the latest entry is the one in force."""
    answers = list(context.get("answers", []))
    previous = [i for i, a in enumerate(answers) if a["question"] == args["question"]]
    answers.append({
        "question": args["question"],
        "answer": args["answer"],
        "channel": args["channel"],
        "at": event.at,
        "corrects": previous[-1] if previous else None,
    })
    return ActionResult(updates={"answers": answers})


@action("forget_answers")
def forget_answers(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Erase the whole model of the ward. Different from changing an answer."""
    return ActionResult(updates={"answers": []})


# ---- Steward: outbox and inbox ----------------------------------------------

@action("forward_to_house", payload=("text",))
def forward_to_house(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("forward_to_house", {"text": event.payload["text"]}),))


@action("forward_to_operators", payload=("text", "case_id"))
def forward_to_operators(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """R8. No signals are read here: nothing about the text can stop it."""
    return ActionResult(outputs=(Output("forward_to_operators", {
        "text": event.payload["text"], "case_id": event.payload["case_id"],
    }),))


@action("deliver", payload=("message_id",))
def deliver(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("deliver", {"message_id": event.payload["message_id"]}),))


# ---- Steward: conduct (R5) --------------------------------------------------

@action("add_strike", payload=("exchange_id",), signals=("abuse",))
def add_strike(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """The strike's id is the exchange it came from, so evidence and strike
    can never be mismatched."""
    strikes = list(context.get("strikes", []))
    strikes.append({
        "id": event.payload["exchange_id"],
        "category": event.signals["abuse"],
        "at": event.at,
        "weight": 1,
    })
    return ActionResult(updates={"strikes": strikes})


@action("start_time_out", payload=("exchange_id",), signals=("abuse",))
def start_time_out(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Length is set by category in the posted rules, not chosen in the moment."""
    return ActionResult(updates={"time_out": {
        "strike_id": event.payload["exchange_id"],
        "started_at": event.at,
        "minutes": policy["conduct"]["time_out_minutes"][event.signals["abuse"]],
    }})


@action("end_time_out")
def end_time_out(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(updates={"time_out": None})


@action("seal_and_open_case", payload=("exchange_id",))
def seal_and_open_case(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """The Steward leaves. The ward's data is sealed on the phone, not sent
    and not destroyed. Only the strikes travel: what, never who."""
    case_id = "case-" + event.payload["exchange_id"]
    strikes = [dict(s) for s in context.get("strikes", [])]
    return ActionResult(
        updates={"sealed": True, "case_id": case_id, "time_out": None},
        outputs=(Output("open_case", {"case_id": case_id, "strikes": strikes}),),
    )


@action("remove_strike", payload=("strike_id",))
def remove_strike(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    sid = event.payload["strike_id"]
    return ActionResult(updates={"strikes": [s for s in context.get("strikes", []) if s["id"] != sid]})


@action("remove_strikes", payload=("overturned",))
def remove_strikes(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    gone = set(event.payload["overturned"])
    return ActionResult(updates={"strikes": [s for s in context.get("strikes", []) if s["id"] not in gone]})


@action("set_strike_weight", payload=("strike_id", "weight"))
def set_strike_weight(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """R7: the operator's penalty for a frivolous appeal. Bounds were checked
    on the server before this was sent."""
    sid, weight = event.payload["strike_id"], event.payload["weight"]
    return ActionResult(updates={"strikes": [
        dict(s, weight=weight) if s["id"] == sid else dict(s) for s in context.get("strikes", [])
    ]})


@action("unseal")
def unseal(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(updates={"sealed": False, "case_id": None})


@action("destroy_sealed")
def destroy_sealed(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Everything the ward and this Steward built together is destroyed.
    The mark lives on the server, on the Steward line."""
    case_id = context.get("case_id")
    return ActionResult(
        updates={"strikes": [], "time_out": None, "sealed": False, "case_id": None},
        outputs=(Output("destroy_ward_data", {"case_id": case_id}),),
    )


# ---- House --------------------------------------------------------------------

@action("publish", payload=("submission_id",))
def publish(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("publish", {"submission_id": event.payload["submission_id"]}),))


@action("return_to_sender", params={"rule": RULE_ID, "message": MESSAGE_ID}, payload=("submission_id",))
def return_to_sender(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("return_to_sender", {
        "submission_id": event.payload["submission_id"],
        "rule": args["rule"],
        "message": args["message"],
    }),))


@action("withhold", params={"rule": RULE_ID}, payload=("submission_id",))
def withhold(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Kept out without telling the sender. Recorded in the House ledger with
    the rule it rests on; the runner must never route this to the sender."""
    return ActionResult(outputs=(Output("withhold", {
        "submission_id": event.payload["submission_id"],
        "rule": args["rule"],
    }),))


# ---- The operators' inbox (R8, server) -----------------------------------------

@action("file_for_operators", payload=("mail_id", "steward_id", "case_id", "text"), signals=("abuse",))
def file_for_operators(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Always filed. The abuse signal is a label for the operator reading it,
    never a reason to stop it. steward_id is None when the sender has no Steward."""
    return ActionResult(outputs=(Output("operator_mail", {
        "mail_id": event.payload["mail_id"],
        "steward_id": event.payload["steward_id"],
        "case_id": event.payload["case_id"],
        "text": event.payload["text"],
        "label": event.signals["abuse"],
        "at": event.at,
    }),))


# ---- Review and appeals (server) ---------------------------------------------
#
# Review instances start with context:
#   {"case_id", "line_id", "steward_id", "strikes": [...]}
# Strike appeal instances start with context:
#   {"appeal_id", "line_id", "steward_id", "strike": {"id", "at", "category"}}
# line_id names a line of Stewards, never a person.

@action("stamp", params={"field": ("opened_at", "ruled_at", "appealed_at")})
def stamp(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(updates={args["field"]: event.at})


@action("mark_warned")
def mark_warned(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(updates={"warned": True})


@action("notify_operators", params={"message": MESSAGE_ID})
def notify_operators(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    subject = context.get("case_id") or context.get("appeal_id")
    return ActionResult(outputs=(Output("notify_operators", {"message": args["message"], "subject": subject}),))


@action("record_ruling", payload=("reviewer",))
def record_ruling(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """Which operator ruled is kept with the case. Operators are accountable;
    wards are anonymous."""
    rulings = list(context.get("rulings", []))
    rulings.append({"reviewer": event.payload["reviewer"], "event": event.type, "at": event.at})
    return ActionResult(updates={"rulings": rulings})


def _line(context: Mapping[str, Any]) -> dict[str, Any]:
    return {"line_id": context["line_id"], "case_id": context["case_id"]}


@action("record_mark")
def record_mark(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    categories = sorted({s["category"] for s in context["strikes"]})
    return ActionResult(outputs=(Output("record_mark", {**_line(context), "categories": categories, "at": event.at, "weight": 1}),))


@action("set_mark_weight", payload=("weight",))
def set_mark_weight(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("set_mark_weight", {**_line(context), "weight": event.payload["weight"]}),))


@action("remove_mark")
def remove_mark(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("remove_mark", _line(context)),))


@action("issue_successor")
def issue_successor(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(Output("issue_successor", _line(context)),))


@action("retire_successor")
def retire_successor(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """R6: a departure overturned on appeal. The original Steward returns
    with everything it knew; the successor issued in the meantime retires."""
    return ActionResult(outputs=(Output("retire_successor", _line(context)),))


@action("delete_evidence")
def delete_evidence(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(
        updates={"strikes": [{"id": s["id"], "category": s["category"]} for s in context["strikes"]]},
        outputs=(Output("delete_evidence", {"case_id": context["case_id"]}),),
    )


def _tell(context: Mapping[str, Any], type_: str, payload: dict[str, Any]) -> Output:
    return Output("tell_steward", {"steward_id": context["steward_id"], "event": {"type": type_, "payload": payload}})


@action("tell_case_final")
def tell_case_final(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(_tell(context, "case_final", {"case_id": context["case_id"]}),))


@action("tell_case_overturned_all")
def tell_case_overturned_all(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """The case lapsed, or an appeal against the departure succeeded."""
    ids = [s["id"] for s in context["strikes"]]
    return ActionResult(outputs=(_tell(context, "case_overturned", {"case_id": context["case_id"], "overturned": ids}),))


@action("tell_case_overturned_listed", payload=("overturned",))
def tell_case_overturned_listed(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    """An operator overturned specific strikes."""
    ids = list(event.payload["overturned"])
    return ActionResult(outputs=(_tell(context, "case_overturned", {"case_id": context["case_id"], "overturned": ids}),))


@action("tell_penalty_set", payload=("weight",))
def tell_penalty_set(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    payload = {"strike_id": context["strike"]["id"], "weight": event.payload["weight"]}
    return ActionResult(outputs=(_tell(context, "penalty_set", payload),))


@action("tell_about_strike", params={"event": STEWARD_EVENTS_ABOUT_STRIKES})
def tell_about_strike(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any], args: Mapping[str, Any]) -> ActionResult:
    return ActionResult(outputs=(_tell(context, args["event"], {"strike_id": context["strike"]["id"]}),))
