"""Tests for PAUSED_FOR_BUDGET_APPROVAL runtime state (v2.47.0 / #14).

Budget-exceeded runs now PAUSE (awaiting operator budget-increase approval)
instead of failing immediately. The operator can approve a higher budget
(carried cost — absolute ceiling, no reset) and resume.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_classifier import RecoveryState, classify


# --- classifier: paused_for_budget → PAUSED_FOR_BUDGET_APPROVAL -------------

def test_paused_for_budget_status_classifies_correctly() -> None:
    """A run with status='paused_for_budget' classifies as
    PAUSED_FOR_BUDGET_APPROVAL, not FAILED_NON_RETRYABLE."""
    state = ChainState(
        run_id="r1", chain_id="c", status="paused_for_budget",
        metadata={"loop_budget_exceeded": "search"},
    )
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.PAUSED_FOR_BUDGET_APPROVAL
    assert "budget" in result.blocking_reason.lower()


def test_paused_for_budget_takes_priority_over_failure_fallback() -> None:
    """paused_for_budget must classify before the generic failure path — it's
    a distinct operator-actionable state, not a terminal failure."""
    state = ChainState(
        run_id="r1", chain_id="c", status="paused_for_budget",
        metadata={"last_failure": {"retryable": False}},
    )
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.PAUSED_FOR_BUDGET_APPROVAL


# --- policy: APPROVE_BUDGET_INCREASE ----------------------------------------

def _budget_snapshot(
    *, recovery_state="PAUSED_FOR_BUDGET_APPROVAL", status="paused_for_budget",
    loop_id="search", accumulated_cost=104.0, previous_budget=100.0,
) -> dict:
    return {
        "run_id": "r", "status": status, "recovery_state": recovery_state,
        "failed_step": None, "pending_review": None,
        "side_effects": [], "recovery_decisions": [],
        "last_failure_retryable": False, "last_failure_type": None,
        "last_failure_node_id": None, "last_failure_error": None,
        "prior_fallback_attempts": [], "governed_decision_receipt": None,
        "budget_loop_id": loop_id,
        "budget_accumulated_cost": accumulated_cost,
        "budget_previous": previous_budget,
    }


def test_policy_admits_budget_increase_for_paused_run() -> None:
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snapshot(),
        new_budget=150.0, operator_role="finance",
    )
    assert result.admitted is True


def test_policy_refuses_budget_increase_below_accumulated_cost() -> None:
    """new_budget must exceed accumulated cost — can't approve a ceiling below
    what's already spent. Use a value above previous (100) but below spent (104)
    so the accumulated-cost check fires, not the previous-budget check."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snapshot(previous_budget=100.0, accumulated_cost=104.0),
        new_budget=102.0, operator_role="finance",  # above previous, below spent
    )
    assert result.admitted is False
    assert "cost" in result.rejection_reason.lower() or "spent" in result.rejection_reason.lower()


def test_policy_refuses_budget_increase_not_above_previous() -> None:
    """new_budget must be strictly greater than the previous budget."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snapshot(previous_budget=100.0),
        new_budget=100.0, operator_role="finance",  # not higher
    )
    assert result.admitted is False
    assert "greater" in result.rejection_reason.lower() or "higher" in result.rejection_reason.lower()


def test_policy_refuses_budget_increase_for_non_paused_run() -> None:
    """APPROVE_BUDGET_INCREASE only applies to PAUSED_FOR_BUDGET_APPROVAL."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snapshot(recovery_state="FAILED_RETRYABLE", status="failed"),
        new_budget=150.0, operator_role="finance",
    )
    assert result.admitted is False
    assert "budget" in result.rejection_reason.lower()


def test_policy_refuses_budget_increase_without_new_budget() -> None:
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snapshot(),
        new_budget=None, operator_role="finance",
    )
    assert result.admitted is False
    assert "new_budget" in result.rejection_reason.lower()


# --- e2e: apply_action passes new_budget to delegate + audit fields -----------

@pytest.fixture()
def sm(tmp_path):
    from nodechain.core.state import StateManager
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path):
    import pathlib
    d = tmp_path / "traces"
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


@pytest.fixture()
def service(sm, trace_dir):
    from nodechain.runtime.recovery_service import RecoveryService
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed_paused(sm, run_id="r1", *, loop_id="search", accumulated=104.0,
                 previous=100.0):
    from nodechain.core.state import ChainState
    sm.save(ChainState(
        run_id=run_id, chain_id="c", status="paused_for_budget",
        metadata={
            "loop_budget_exceeded": loop_id,
            "budget_context": {
                "loop_id": loop_id, "accumulated_cost": accumulated,
                "previous_budget": previous, "reason": "budget exceeded",
            },
        },
    ))


def test_apply_action_threads_new_budget_to_delegate(service, sm) -> None:
    """#1 fix: new_budget reaches the delegate, not recovered from reason."""
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed_paused(sm)
    received = {}

    def delegate(action, run_id, **kw):
        received["new_budget"] = kw.get("new_budget")
        st = sm.load(run_id); st.status = "completed"; sm.save(st)
        return "completed"

    service.set_action_delegate(delegate)
    result = service.apply_action(
        "r1", RecoveryAction.APPROVE_BUDGET_INCREASE, operator_identity="op", operator_role="finance",
        new_budget=150.0, reason="approved budget increase",
    )
    assert result.admitted is True
    assert received["new_budget"] == 150.0  # threaded, not recovered from reason


def test_apply_action_budget_audit_fields_in_operator_log(service, sm) -> None:
    """#4 fix: operator_action_log carries previous/new budget + cost fields."""
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed_paused(sm, accumulated=104.0, previous=100.0)

    def delegate(action, run_id, **kw):
        st = sm.load(run_id); st.status = "completed"; sm.save(st)
        return "completed"

    service.set_action_delegate(delegate)
    service.apply_action(
        "r1", RecoveryAction.APPROVE_BUDGET_INCREASE, operator_identity="op", operator_role="finance",
        new_budget=150.0,
    )
    [row] = sm.get_operator_actions(run_id="r1")
    md = row["metadata"]
    assert md["new_budget"] == 150.0
    assert md["previous_budget"] == 100.0
    assert md["accumulated_cost_at_pause"] == 104.0
    assert md["remaining_budget_after_approval"] == 46.0
    assert md["loop_id"] == "search"


# --- e2e: LoopEnforcer uses budget_overrides --------------------------------

def test_loop_enforcer_uses_budget_override() -> None:
    """#2 fix: check_budget uses state.metadata['budget_overrides'] when present,
    not the static blueprint max_cost_usd."""
    from nodechain.runtime.loop_enforcer import LoopEnforcer
    from nodechain.core.blueprint import LoopDef
    from nodechain.core.state import ChainState

    loop = LoopDef(
        loop_id="search", entry_condition="True", exit_condition="False",
        max_iterations=10, max_cost_usd=100.0, path=["s", "e"],
    )
    enforcer = LoopEnforcer(blueprint=type("B", (), {"loops": {"search": loop}})())

    # Without override: 104 > 100 → blocked.
    state = ChainState(run_id="r", chain_id="c", status="running")
    result = enforcer.check_budget(loop, state, cost_usd=104.0)
    assert not result.allowed

    # With override: 104 <= 150 → allowed.
    state = ChainState(
        run_id="r", chain_id="c", status="running",
        metadata={"budget_overrides": {"search": 150.0}},
    )
    result = enforcer.check_budget(loop, state, cost_usd=104.0)
    assert result.allowed
    assert result.context["max_cost_usd"] == 150.0  # reflects effective budget


def test_loop_enforcer_without_override_uses_blueprint() -> None:
    """Sanity: without an override, the static blueprint budget applies."""
    from nodechain.runtime.loop_enforcer import LoopEnforcer
    from nodechain.core.blueprint import LoopDef
    from nodechain.core.state import ChainState

    loop = LoopDef(
        loop_id="search", entry_condition="True", exit_condition="False",
        max_iterations=10, max_cost_usd=100.0, path=["s", "e"],
    )
    enforcer = LoopEnforcer(blueprint=type("B", (), {"loops": {"search": loop}})())
    state = ChainState(run_id="r", chain_id="c", status="running")
    result = enforcer.check_budget(loop, state, cost_usd=50.0)
    assert result.allowed
    assert result.context["max_cost_usd"] == 100.0  # blueprint value


# --- e2e: pending_loop_back persisted on pause -------------------------------

def test_pause_for_budget_persists_pending_loop_back(sm) -> None:
    """#3 fix: _pause_for_budget records the loop target so resume re-enters it."""
    from nodechain.core.state import ChainState
    from nodechain.runtime.orchestrator import Orchestrator

    state = ChainState(
        run_id="r1", chain_id="c", status="running",
        current_node="loop_end",
    )
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self, st, mgr):
            self.state = st
            self.state_manager = mgr

    stub = _StubOrch(state, sm)
    stub._pause_for_budget(
        "search", 104.0, 100.0, "budget exceeded",
        target_node="loop_start", source_node="loop_end",
    )

    saved = sm.load("r1")
    assert saved.status == "paused_for_budget"
    plb = saved.metadata["pending_loop_back"]
    assert plb["target_node"] == "loop_start"
    assert plb["source_node"] == "loop_end"
    assert plb["accumulated_cost"] == 104.0


# --- e2e: resume uses _build_loop_payload for the loop target -----------------

def test_resume_pending_loop_back_builds_target_payload(sm) -> None:
    """#3 residual fix: the resume path doesn't just set the cursor to the loop
    target — it builds the target-specific payload via _build_loop_payload, the
    same path the live loop uses. This verifies the payload construction
    includes target-specific context, not the generic pre-computed payload."""
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.core.state import ChainState

    state = ChainState(
        run_id="r1", chain_id="c", status="running",
        current_node="loop_end",
        outputs={"loop_end": {"result": "search results", "step": 3}},
    )
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self):
            pass

    orch = _StubOrch()
    orch.state = state

    # _build_loop_payload should produce a target-specific payload.
    payload = orch._build_loop_payload("loop_start", state.outputs["loop_end"])
    assert payload is not None
    assert isinstance(payload, dict)


# --- #19: hardened _build_loop_payload semantic tests ------------------------

def test_build_loop_payload_context_selector_gets_normalized_goal(sm) -> None:
    """context_selector target receives normalized_goal from goal_interpreter
    output + prior search results from the source node — not raw source output."""
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.core.state import ChainState

    state = ChainState(
        run_id="r1", chain_id="c", status="running",
        outputs={
            "goal_interpreter": {"normalized_goal": {"objective": "test"}},
            "task_planner": {"plan": ["step1", "step2"]},
            "search_node": {"search_results": ["r1", "r2"], "cost": 0.5},
        },
    )
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self):
            pass

    orch = _StubOrch()
    orch.state = state

    payload = orch._build_loop_payload("context_selector", state.outputs["search_node"])
    # Must receive the structured context fields, not the raw search output
    assert "normalized_goal" in payload
    assert payload["normalized_goal"] == {"objective": "test"}
    assert "task_plan" in payload
    assert "prior_search_results" in payload
    assert payload["prior_search_results"] == ["r1", "r2"]
    # Must NOT be the raw search output (no "cost" or "search_results" keys)
    assert "cost" not in payload


def test_build_loop_payload_task_planner_gets_revision_context(sm) -> None:
    """task_planner target receives normalized_goal + revision_context from
    source output — the source's full output becomes the revision context."""
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.core.state import ChainState

    state = ChainState(
        run_id="r1", chain_id="c", status="running",
        outputs={
            "goal_interpreter": {"normalized_goal": {"objective": "revise"}},
            "risk_classifier": {"risk": "high", "needs_revision": True},
        },
    )
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self):
            pass

    orch = _StubOrch()
    orch.state = state

    payload = orch._build_loop_payload("task_planner", state.outputs["risk_classifier"])
    assert "normalized_goal" in payload
    assert payload["normalized_goal"] == {"objective": "revise"}
    assert "revision_context" in payload
    assert payload["revision_context"] == {"risk": "high", "needs_revision": True}


def test_build_loop_payload_default_passes_current_output(sm) -> None:
    """Unknown target node: payload is the current output, unmodified."""
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.core.state import ChainState

    state = ChainState(
        run_id="r1", chain_id="c", status="running",
        outputs={"some_node": {"key": "value"}},
    )
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self):
            pass

    orch = _StubOrch()
    orch.state = state

    payload = orch._build_loop_payload("unknown_target", {"key": "value"})
    assert payload == {"key": "value"}


def test_build_loop_payload_context_selector_handles_missing_outputs(sm) -> None:
    """context_selector with no prior goal_interpreter output: produces empty
    normalized_goal/task_plan but still carries prior_search_results."""
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.core.state import ChainState

    state = ChainState(
        run_id="r1", chain_id="c", status="running",
        outputs={"search_node": {"search_results": ["r1"]}},
    )
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self):
            pass

    orch = _StubOrch()
    orch.state = state

    payload = orch._build_loop_payload("context_selector", state.outputs["search_node"])
    assert payload["normalized_goal"] == {}
    assert payload["task_plan"] == {}
    assert payload["prior_search_results"] == ["r1"]
