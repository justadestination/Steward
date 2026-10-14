"""Registered conditions. Each answers exactly one yes/no question.

A condition must return a real bool. It reads only what it declares at
registration, and it never consults anything outside its arguments.
Time always comes from event.at, never the clock.
"""

from __future__ import annotations

from typing import Any, Mapping

from .catalog import DATA, load_json
from .events import Event, minutes_between
from .registry import condition

# One source for value order: data/signals.json.
SIGNAL_ORDER: dict[str, tuple[str, ...]] = {
    k: tuple(v) for k, v in load_json(DATA / "signals.json").items()
}

MINUTES_PER_DAY = 1440


# ---- House: upholding the posted rules -------------------------------------

@condition("sender_lacks_steward", payload=("sender",))
def sender_lacks_steward(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """R1: posting goes through a Steward; everyone can read.
    `sender.via_steward` is set by the transport from how the submission
    arrived, never from anything the sender typed."""
    return event.payload["sender"]["via_steward"] is not True


@condition("abuse_is_hate", signals=("abuse",))
def abuse_is_hate(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return event.signals["abuse"] == "hate"


@condition("abuse_at_strike_level", signals=("abuse",))
def abuse_at_strike_level(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """Bullying, hate or threat, as posted. Swearing and a lone insult are not."""
    return event.signals["abuse"] in policy["conduct"]["strike_categories"]


@condition("in_cool_off", payload=("sender", "thread"))
def in_cool_off(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """R3: two posts in a row in one thread is the limit; it resets when
    someone else posts or 30 minutes after your last one.

    event.payload["thread"] lists prior posts oldest first, each
    {"author": str, "at": "...Z"}."""
    me = event.payload["sender"]["handle"]
    thread = event.payload["thread"]
    streak = 0
    for post in reversed(thread):  # newest first, stop at anyone else
        if post["author"] != me:
            break
        streak += 1
    limits = policy["parameters"]
    if streak < limits["max_consecutive_posts"]:
        return False
    return minutes_between(thread[-1]["at"], event.at) < limits["cool_off_minutes"]


# ---- Steward: working for its ward ------------------------------------------

@condition("hostile_toward_reader", signals=("hostility",))
def hostile_toward_reader(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """True when the incoming message reaches the ward's own hold level.
    The threshold is the ward's choice, stored in their profile."""
    order = SIGNAL_ORDER["hostility"]
    return order.index(event.signals["hostility"]) >= order.index(policy["inbox"]["hold_at"])


# ---- Steward: conduct toward the Steward (R5) -------------------------------

def active_strike_weight(context: Mapping[str, Any], at: str, policy: Mapping[str, Any]) -> int:
    """Sum of weights of strikes younger than the expiry period at `at`.
    A frivolous appeal can raise a strike's weight (R7)."""
    expiry = policy["parameters"]["strike_expiry_days"] * MINUTES_PER_DAY
    return sum(
        s["weight"] for s in context.get("strikes", [])
        if minutes_between(s["at"], at) < expiry
    )


@condition("not_a_strike", signals=("abuse",))
def not_a_strike(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return event.signals["abuse"] not in policy["conduct"]["strike_categories"]


@condition("no_active_strikes")
def no_active_strikes(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return active_strike_weight(context, event.at, policy) == 0


@condition("one_active_strike")
def one_active_strike(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return active_strike_weight(context, event.at, policy) == 1


@condition("time_out_over")
def time_out_over(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    t = context["time_out"]
    return minutes_between(t["started_at"], event.at) >= t["minutes"]


@condition("strike_holds_time_out", payload=("strike_id",))
def strike_holds_time_out(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    t = context.get("time_out")
    return t is not None and t["strike_id"] == event.payload["strike_id"]


# ---- Activation --------------------------------------------------------------

@condition("presentation_valid_and_over_21", signals=("over_21", "presentation_valid"))
def presentation_valid_and_over_21(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return event.signals["presentation_valid"] == "yes" and event.signals["over_21"] == "yes"


def _hours_since(context: Mapping[str, Any], key: str, at: str) -> float:
    return minutes_between(context[key], at) / 60


@condition("review_wait_over")
def review_wait_over(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return _hours_since(context, "opened_at", event.at) >= policy["parameters"]["review_wait_hours"]


@condition("review_deadline_passed")
def review_deadline_passed(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return _hours_since(context, "opened_at", event.at) >= policy["parameters"]["review_deadline_hours"]


@condition("deadline_warning_due")
def deadline_warning_due(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    p = policy["parameters"]
    due = p["review_deadline_hours"] - p["review_warning_hours"]
    return not context.get("warned", False) and _hours_since(context, "opened_at", event.at) >= due


@condition("case_appeal_window_over")
def case_appeal_window_over(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return _hours_since(context, "ruled_at", event.at) >= policy["parameters"]["appeal_window_days"] * 24


@condition("strike_appeal_window_over")
def strike_appeal_window_over(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return minutes_between(context["strike"]["at"], event.at) >= policy["parameters"]["appeal_window_days"] * MINUTES_PER_DAY


@condition("appeal_deadline_passed")
def appeal_deadline_passed(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return _hours_since(context, "appealed_at", event.at) >= policy["parameters"]["appeal_review_hours"]


@condition("penalty_out_of_bounds", payload=("weight",))
def penalty_out_of_bounds(event: Event, context: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """R7: the operator sets the penalty for a frivolous appeal, within the
    posted limit. Anything else is refused and the appeal stays open."""
    w = event.payload["weight"]
    return type(w) is not int or not 1 <= w <= policy["parameters"]["frivolous_max_weight"]
