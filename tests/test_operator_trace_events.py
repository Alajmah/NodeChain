"""Tests for operator trace-event discipline (v2.46.0 Phase 2.1).

The core invariant: every operator intervention must be traceable as an
operator action, NOT as node execution. This is enforced structurally by (a)
a distinct set of EventType values for operator actions and (b) a distinct
Actor.OPERATOR that can never be confused with Actor.NODE / RUNTIME / HUMAN.

These tests pin the enum additions before any code emits them.
"""

from __future__ import annotations

from nodechain.core.trace import Actor, EventType, TraceEvent


# --- the 13 operator event types exist --------------------------------------

def test_operator_console_opened_event_exists() -> None:
    assert EventType.OPERATOR_CONSOLE_OPENED.value == "operator_console_opened"


def test_recovery_snapshot_viewed_event_exists() -> None:
    assert EventType.RECOVERY_SNAPSHOT_VIEWED.value == "recovery_snapshot_viewed"


def test_recovery_action_requested_event_exists() -> None:
    assert EventType.RECOVERY_ACTION_REQUESTED.value == "recovery_action_requested"


def test_recovery_action_allowed_event_exists() -> None:
    assert EventType.RECOVERY_ACTION_ALLOWED.value == "recovery_action_allowed"


def test_recovery_action_blocked_event_exists() -> None:
    assert EventType.RECOVERY_ACTION_BLOCKED.value == "recovery_action_blocked"


def test_run_resumed_by_operator_event_exists() -> None:
    assert EventType.RUN_RESUMED_BY_OPERATOR.value == "run_resumed_by_operator"


def test_step_retried_by_operator_event_exists() -> None:
    assert EventType.STEP_RETRIED_BY_OPERATOR.value == "step_retried_by_operator"


def test_human_review_approved_by_operator_event_exists() -> None:
    assert (
        EventType.HUMAN_REVIEW_APPROVED_BY_OPERATOR.value
        == "human_review_approved_by_operator"
    )


def test_human_review_rejected_by_operator_event_exists() -> None:
    assert (
        EventType.HUMAN_REVIEW_REJECTED_BY_OPERATOR.value
        == "human_review_rejected_by_operator"
    )


def test_revision_requested_by_operator_event_exists() -> None:
    assert (
        EventType.REVISION_REQUESTED_BY_OPERATOR.value
        == "revision_requested_by_operator"
    )


def test_run_cancelled_by_operator_event_exists() -> None:
    assert EventType.RUN_CANCELLED_BY_OPERATOR.value == "run_cancelled_by_operator"


def test_run_failed_by_operator_event_exists() -> None:
    assert EventType.RUN_FAILED_BY_OPERATOR.value == "run_failed_by_operator"


def test_recovery_report_exported_event_exists() -> None:
    assert EventType.RECOVERY_REPORT_EXPORTED.value == "recovery_report_exported"


# --- Actor.OPERATOR exists and is distinct ----------------------------------

def test_operator_actor_exists_and_is_distinct_from_node_and_human() -> None:
    """The whole point: an operator action must never be representable as a
    node execution or a plain human action. OPERATOR is its own actor."""
    assert Actor.OPERATOR.value == "operator"
    assert Actor.OPERATOR is not Actor.NODE
    assert Actor.OPERATOR is not Actor.RUNTIME
    assert Actor.OPERATOR is not Actor.HUMAN
    assert Actor.OPERATOR is not Actor.POLICY_ENGINE


# --- operator events carry Actor.OPERATOR, never NODE ------------------------

def test_operator_event_uses_operator_actor_not_node() -> None:
    """An operator action trace event must be constructible with
    Actor.OPERATOR, and Actor.NODE must not equal Actor.OPERATOR — so a future
    bug that mislabels an operator action as a node event is detectable."""
    event = TraceEvent(
        run_id="r", chain_id="c", node_id="", step_id=0,
        event_type=EventType.RUN_RESUMED_BY_OPERATOR,
        actor=Actor.OPERATOR,
    )
    assert event.actor is Actor.OPERATOR
    assert event.actor is not Actor.NODE
    assert event.event_type is EventType.RUN_RESUMED_BY_OPERATOR


def test_operator_event_types_are_in_the_enum_closure() -> None:
    """All 13 operator events are real members of EventType — a closed enum,
    so unknown event types are rejected at construction time."""
    operator_events = {
        EventType.OPERATOR_CONSOLE_OPENED,
        EventType.RECOVERY_SNAPSHOT_VIEWED,
        EventType.RECOVERY_ACTION_REQUESTED,
        EventType.RECOVERY_ACTION_ALLOWED,
        EventType.RECOVERY_ACTION_BLOCKED,
        EventType.RUN_RESUMED_BY_OPERATOR,
        EventType.STEP_RETRIED_BY_OPERATOR,
        EventType.HUMAN_REVIEW_APPROVED_BY_OPERATOR,
        EventType.HUMAN_REVIEW_REJECTED_BY_OPERATOR,
        EventType.REVISION_REQUESTED_BY_OPERATOR,
        EventType.RUN_CANCELLED_BY_OPERATOR,
        EventType.RUN_FAILED_BY_OPERATOR,
        EventType.RECOVERY_REPORT_EXPORTED,
    }
    assert len(operator_events) == 13
    assert operator_events.issubset(set(EventType))
