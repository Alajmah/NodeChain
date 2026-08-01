"""Tests for FailureManager operator-fallback API (#13 ROUTE_FALLBACK delegation).

The fallback allowlist: only true fallback-capable failure types are
operator-routable. Initially just SEARCH_API_UNAVAILABLE. Retries/skips
(MODEL_TIMEOUT, SCHEMA_VALIDATION, etc.) are NOT fallbacks and must be refused.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.failure_manager import FailureManager, FailureType


def test_supports_operator_fallback_true_for_search_api_unavailable() -> None:
    assert FailureManager.supports_operator_fallback(
        FailureType.SEARCH_API_UNAVAILABLE
    ) is True


@pytest.mark.parametrize("ft", [
    FailureType.MODEL_TIMEOUT,
    FailureType.NODE_SCHEMA_VALIDATION,
    FailureType.TRACE_WRITE_FAILURE,
    FailureType.MEMORY_WRITE_POLICY_REJECTION,
    FailureType.UNKNOWN,
])
def test_supports_operator_fallback_false_for_non_fallback_types(ft) -> None:
    """Retry/skip/unknown strategies are NOT operator fallbacks."""
    assert FailureManager.supports_operator_fallback(ft) is False


def test_operator_fallback_types_is_a_closed_allowlist() -> None:
    """The allowlist must be explicit and small — not 'every handler'."""
    assert FailureManager.OPERATOR_FALLBACK_TYPES == {FailureType.SEARCH_API_UNAVAILABLE}


@pytest.mark.asyncio
async def test_route_fallback_refuses_non_fallback_type() -> None:
    """route_fallback on a non-fallback type returns recovered=False with a
    clear action — does NOT call the handler."""
    fm = FailureManager()
    result = await fm.route_fallback(
        FailureType.MODEL_TIMEOUT, node=None, envelope=None,
        error="x", state={}, invoke_fn=None,
    )
    assert result.recovered is False
    assert "no_operator_fallback" in result.action


@pytest.mark.asyncio
async def test_route_fallback_for_search_unavailable_calls_handler() -> None:
    """route_fallback for SEARCH_API_UNAVAILABLE delegates to the existing
    _handle_search_unavailable handler. With no invoke_fn the handler returns
    exhausted/no_invoke_fn, proving the dispatch wired through to the real
    fallback handler (not the refusal path)."""

    class _StubManifest:
        node_id = "search_node"

    class _StubNode:
        manifest = _StubManifest()

    class _StubEnvelope:
        payload = {"query": "test"}
        run_id = "r1"
        chain_id = "c"
        step_id = 1
        context = {}

    fm = FailureManager()
    result = await fm.route_fallback(
        FailureType.SEARCH_API_UNAVAILABLE, node=_StubNode(),
        envelope=_StubEnvelope(),
        error="search down", state={}, invoke_fn=None,
    )
    assert result.recovered is False
    # The handler returns exhausted_search_fallback when it can't retry;
    # either way the action must show it routed through the search handler.
    assert result.action in (
        "exhausted_search_fallback", "search_fallback_local_store",
        "no_invoke_fn",
    )


# --- step 2: OperatorActionPolicy admits ROUTE_FALLBACK for fallback-capable failures

def _fallback_snapshot(
    *, recovery_state="FAILED_RETRYABLE", failed_step=4,
    failure_type="search_api_unavailable", node_id="search_node",
    prior_fallback_attempts=None,
) -> dict:
    return {
        "run_id": "r", "status": "failed", "recovery_state": recovery_state,
        "failed_step": failed_step,
        "pending_review": None, "side_effects": [], "recovery_decisions": [],
        "last_failure_retryable": True,
        "last_failure_type": failure_type,
        "last_failure_node_id": node_id,
        "last_failure_error": "search api down",
        "prior_fallback_attempts": prior_fallback_attempts or [],
        "governed_decision_receipt": None,
    }


def test_policy_admits_route_fallback_for_search_api_unavailable() -> None:
    """ROUTE_FALLBACK admitted for a fallback-capable failure type with matching step."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK, _fallback_snapshot(), target_step_id=4,
    )
    assert result.admitted is True


def test_policy_refuses_route_fallback_for_non_fallback_type() -> None:
    """MODEL_TIMEOUT is a retry, not a fallback — ROUTE_FALLBACK refused."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK,
        _fallback_snapshot(failure_type="model_timeout"),
        target_step_id=4,
    )
    assert result.admitted is False
    assert "fallback" in result.rejection_reason.lower()


def test_policy_refuses_route_fallback_missing_failure_type() -> None:
    """No durable failure_type → refuse (don't classify free-text errors)."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK,
        _fallback_snapshot(failure_type=None),
        target_step_id=4,
    )
    assert result.admitted is False
    assert "failure_type" in result.rejection_reason.lower()


def test_policy_refuses_route_fallback_mismatched_step() -> None:
    """target_step_id must match the durable failed step (same as RETRY_STEP)."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK, _fallback_snapshot(failed_step=4),
        target_step_id=999,
    )
    assert result.admitted is False
    assert "step" in result.rejection_reason.lower()


def test_policy_refuses_duplicate_route_fallback() -> None:
    """A prior admitted ROUTE_FALLBACK for the same step blocks a second one."""
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK,
        _fallback_snapshot(prior_fallback_attempts=[4]),
        target_step_id=4,
    )
    assert result.admitted is False
    assert "already" in result.rejection_reason.lower() or "prior" in result.rejection_reason.lower()


def test_policy_refuses_route_fallback_without_target_step() -> None:
    from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK, _fallback_snapshot(),
        target_step_id=None,
    )
    assert result.admitted is False
    assert "step" in result.rejection_reason.lower()


# --- step 8: apply_action integration (delegate success + blocked + trace) ---

@pytest.fixture()
def sm(tmp_path):
    from nodechain.core.state import StateManager
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path):
    return str(tmp_path / "traces")


@pytest.fixture()
def service(sm, trace_dir):
    import pathlib
    pathlib.Path(trace_dir).mkdir(parents=True, exist_ok=True)
    from nodechain.runtime.recovery_service import RecoveryService
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed_failed(sm, run_id="r1", *, failure_type="search_api_unavailable",
                 step_id=4, node_id="search_node"):
    from nodechain.core.state import ChainState
    sm.save(ChainState(
        run_id=run_id, chain_id="c", status="failed", step=step_id,
        current_node=node_id,
        metadata={
            "last_failure": {
                "failure_type": failure_type, "node_id": node_id,
                "step_id": step_id, "error": "search api down",
                "retryable": True,
            },
        },
    ))


def test_apply_action_route_fallback_admitted_with_delegate(service, sm) -> None:
    """An admitted ROUTE_FALLBACK invokes the delegate and records the result."""
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed_failed(sm)
    invoked = {}

    def delegate(action, run_id, **kw):
        invoked["action"] = action
        invoked["target_step_id"] = kw.get("target_step_id")
        st = sm.load(run_id); st.status = "running"; sm.save(st)
        return "running"

    service.set_action_delegate(delegate)
    result = service.apply_action(
        "r1", RecoveryAction.ROUTE_FALLBACK, operator_identity="op",
        target_step_id=4,
    )
    assert result.admitted is True
    assert result.resulting_state == "running"
    assert invoked["action"] is RecoveryAction.ROUTE_FALLBACK
    assert invoked["target_step_id"] == 4
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is True
    assert row["action"] == "route_fallback"
    assert row["target_step_id"] == 4


def test_apply_action_route_fallback_blocked_for_non_fallback_type(service, sm) -> None:
    """MODEL_TIMEOUT is refused at policy; delegate never invoked; BLOCKED emitted."""
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed_failed(sm, failure_type="model_timeout")
    invoked = []

    def delegate(action, run_id, **kw):
        invoked.append(action)
        return "running"

    service.set_action_delegate(delegate)
    result = service.apply_action(
        "r1", RecoveryAction.ROUTE_FALLBACK, operator_identity="op",
        target_step_id=4,
    )
    assert result.admitted is False
    assert invoked == []  # delegate never called
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is False
    assert "fallback" in row["rejection_reason"].lower()


def test_apply_action_route_fallback_duplicate_refused(service, sm) -> None:
    """A second ROUTE_FALLBACK for the same step is refused (prior-attempt guard)."""
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed_failed(sm)

    def delegate(action, run_id, **kw):
        st = sm.load(run_id); st.status = "running"; sm.save(st)
        return "running"

    service.set_action_delegate(delegate)
    # First fallback admitted.
    r1 = service.apply_action("r1", RecoveryAction.ROUTE_FALLBACK,
                              operator_identity="op", target_step_id=4)
    assert r1.admitted is True
    # Second fallback for the same step refused.
    r2 = service.apply_action("r1", RecoveryAction.ROUTE_FALLBACK,
                              operator_identity="op", target_step_id=4)
    assert r2.admitted is False
    assert "already" in r2.rejection_reason.lower() or "prior" in r2.rejection_reason.lower()
