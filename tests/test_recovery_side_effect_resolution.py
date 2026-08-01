"""RecoveryService.apply_action(RESOLVE_SIDE_EFFECT) — governed operator
resolution of an unknown side effect (v3.4.0 Task 3).

This is the governed write boundary: an operator resolves an unknown side
effect through ``RecoveryService.apply_action``. RBAC + the
OperatorActionPolicy admit the action, then ``_delegate_action`` routes it
directly to ``StateManager.resolve_side_effect_recovery_decision`` — the
ledger-layer atomic store method (no orchestrator re-execution).

Audit invariants re-used from the v2.46 apply_action contract:
  - every attempt emits RECOVERY_ACTION_REQUESTED
  - success emits RECOVERY_ACTION_ALLOWED and records an operator_action_log row
  - failure (delegation raised) emits RECOVERY_ACTION_BLOCKED and records a row
    with admitted=False whose rejection_reason mentions the error
"""

from __future__ import annotations

import json

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_policy import RecoveryAction
from nodechain.runtime.recovery_service import RecoveryService


# --- fixtures -------------------------------------------------------------

@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> str:
    d = tmp_path / "traces"
    d.mkdir(parents=True)
    return str(d)


@pytest.fixture()
def service(sm: StateManager, trace_dir: str) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


# --- helpers --------------------------------------------------------------

def _seed_run(sm: StateManager, run_id: str = "r1", *, status: str = "running") -> ChainState:
    """Seed a non-terminal run. RESOLVE_SIDE_EFFECT is admitted for any
    non-terminal recovery state."""
    state = ChainState(run_id=run_id, chain_id="c", status=status, step=1,
                       current_node="search_tool")
    sm.save(state)
    return state


def _seed_unknown_side_effect(sm: StateManager, *, run_id: str, key: str,
                              node_id: str = "search_tool") -> None:
    """Seed an unknown side-effect ledger row (the resolution precondition).

    Mirrors the helper in test_side_effect_recovery_decisions.py: record
    started, then transition to unknown."""
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id=node_id,
        side_effect_type="external_call",
        idempotency_key=key,
        status="started",
    )
    sm.update_side_effect_status(run_id, key, status="unknown")


def _payload(event: dict) -> dict:
    raw = event.get("payload")
    try:
        return json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return {}


def _event_types(sm: StateManager, run_id: str) -> list[str]:
    return [e["event_type"] for e in sm.get_events(run_id)]


# --- the governed resolution path ----------------------------------------

class TestResolveSideEffect:
    """v3.4.0: apply_action(RESOLVE_SIDE_EFFECT) routes through the governed
    boundary into the ledger-layer atomic resolution."""

    def test_operator_resolves_unknown_to_completed(self, service, sm):
        """verified_completed + external_reference → admitted=True and the
        ledger row transitions unknown→completed."""
        run_id, key = "r1", "se:resolve-1"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="op@x",
            side_effect_key=key,
            side_effect_decision="verified_completed",
            external_reference="ref-1",
            response_hash="resp-hash-1",
        )

        assert result.admitted is True
        assert result.resulting_state == "completed"
        # Ledger transitioned to completed.
        row = sm.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "completed"
        assert row["external_reference"] == "ref-1"
        assert row["response_hash"] == "resp-hash-1"

    def test_operator_resolves_unknown_to_failed(self, service, sm):
        """verified_failed + reason → admitted=True and ledger failed."""
        run_id, key = "r1", "se:resolve-2"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="op@x",
            side_effect_key=key,
            side_effect_decision="verified_failed",
            reason="confirmed dead via provider console",
        )

        assert result.admitted is True
        assert result.resulting_state == "failed"
        row = sm.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "failed"

    def test_non_operator_role_rejected(self, service, sm):
        """An unrecognized role ('viewer') is refused at RBAC before the
        delegate runs. 'viewer' is not in VALID_ROLES, so the denial is
        classified invalid_role and the ledger is untouched. (Note: finance
        and admin ARE valid roles but are rejected for RESOLVE_SIDE_EFFECT
        specifically — see TestResolveSideEffectRbac.)"""
        run_id, key = "r1", "se:resolve-3"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="viewer@x",
            operator_role="viewer",
            side_effect_key=key,
            side_effect_decision="verified_completed",
            external_reference="ref-3",
        )

        assert result.admitted is False
        # apply_action surfaces the RBAC denial through rejection_reason
        # (AuthorizationResult.denial_type is not threaded into ActionResult
        # for the BLOCKED path — a pre-existing apply_action limitation). The
        # role message is RBAC-specific, proving the role check fired before
        # the delegate.
        assert result.rejection_reason is not None
        assert "viewer" in result.rejection_reason
        assert "not authorized" in result.rejection_reason or "invalid operator role" in result.rejection_reason
        # Ledger untouched — delegate never ran.
        row = sm.get_side_effect_by_key(run_id, key)
        assert row["status"] == "unknown"

    def test_resolve_side_effect_traced_and_recorded(self, service, sm):
        """A successful resolution emits RECOVERY_ACTION_ALLOWED and records an
        operator_action_log row with action='resolve_side_effect'."""
        run_id, key = "r1", "se:resolve-4"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="op@x",
            side_effect_key=key,
            side_effect_decision="verified_completed",
            external_reference="ref-4",
        )

        assert result.admitted is True

        # RECOVERY_ACTION_ALLOWED trace event exists.
        types = _event_types(sm, run_id)
        assert "recovery_action_requested" in types
        assert "recovery_action_allowed" in types

        # operator_action_log row recorded with action='resolve_side_effect'.
        rows = sm.get_operator_actions(run_id=run_id)
        resolve_rows = [r for r in rows if r["action"] == "resolve_side_effect"]
        assert len(resolve_rows) == 1
        row = resolve_rows[0]
        assert row["admitted"] is True
        assert row["resulting_state"] == "completed"
        assert row["trace_event_id"] == result.trace_event_id
        assert row["actor_identity"] == "op@x"

        # The ALLOWED event payload carries the action.
        allowed = [e for e in sm.get_events(run_id)
                   if e["event_type"] == "recovery_action_allowed"]
        assert allowed
        assert _payload(allowed[-1]).get("action") == "resolve_side_effect"

    def test_resolve_missing_key_rejected(self, service, sm):
        """A side_effect_key with no matching ledger row: policy admits, but
        delegation raises (SIDE_EFFECT_NOT_FOUND). RecoveryService catches the
        error, emits BLOCKED, and records admitted=False with the error in
        rejection_reason."""
        run_id = "r1"
        _seed_run(sm, run_id)
        # No side effect seeded for 'se:nonexistent'.

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="op@x",
            side_effect_key="se:nonexistent",
            side_effect_decision="verified_completed",
            external_reference="ref-5",
        )

        assert result.admitted is False
        assert result.rejection_reason is not None
        # The delegation-failure wrap surfaces the underlying error text.
        assert "delegation failed" in result.rejection_reason.lower()
        assert result.trace_event_id is not None

        # A BLOCKED event was emitted for the failed delegation.
        types = _event_types(sm, run_id)
        assert "recovery_action_blocked" in types

        # Ledger row recorded with admitted=False, action recorded.
        rows = sm.get_operator_actions(run_id=run_id)
        resolve_rows = [r for r in rows if r["action"] == "resolve_side_effect"]
        assert len(resolve_rows) == 1
        assert resolve_rows[0]["admitted"] is False
        assert "delegation failed" in resolve_rows[0]["rejection_reason"].lower()

    def test_resolve_missing_required_kwargs_raises_value_error(self, service, sm):
        """side_effect_key/side_effect_decision missing entirely → the delegate
        branch raises ValueError BEFORE touching the ledger (programming error,
        not a governed denial). The service wraps it as a delegation failure."""
        run_id = "r1"
        _seed_run(sm, run_id)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="op@x",
            # no side_effect_key / side_effect_decision
        )

        assert result.admitted is False
        assert result.rejection_reason is not None
        assert "delegation failed" in result.rejection_reason.lower()


class TestResolveSideEffectRbac:
    """The RBAC matrix entry for RESOLVE_SIDE_EFFECT admits ONLY operator.

    v3.4.0 design decision: side-effect resolution is a truth-claim about
    external state (did this effect complete?), distinct from flow-control
    recovery actions (resume/retry/cancel). The approved design narrows
    authority to operator only. Finance/admin — valid recovery roles for
    other actions — are rejected for RESOLVE_SIDE_EFFECT specifically.
    """

    def test_operator_admitted(self, service, sm):
        run_id, key = "r-op", "se:op"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity="operator@x", operator_role="operator",
            side_effect_key=key,
            side_effect_decision="verified_completed",
            external_reference="ref-op",
        )
        assert result.admitted is True
        assert sm.get_side_effect_by_key(run_id, key)["status"] == "completed"

    @pytest.mark.parametrize("role", ["finance", "admin"])
    def test_non_operator_valid_roles_rejected(self, service, sm, role):
        """finance/admin are valid roles for other recovery actions, but NOT for
        RESOLVE_SIDE_EFFECT (operator-only by design). The denial is classified
        'rbac' (not 'invalid_role'), and the ledger is untouched."""
        run_id, key = f"r-{role}", f"se:{role}"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        result = service.apply_action(
            run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
            operator_identity=f"{role}@x", operator_role=role,
            side_effect_key=key,
            side_effect_decision="verified_completed",
            external_reference=f"ref-{role}",
        )
        assert result.admitted is False
        # The denial is rbac (role is valid, just not allowed for this action).
        assert "not authorized" in result.rejection_reason.lower()
        # Ledger untouched — the delegate never ran.
        assert sm.get_side_effect_by_key(run_id, key)["status"] == "unknown"
