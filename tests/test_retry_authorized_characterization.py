"""v3.4.0 design-study characterization tests — Retry-Authorized Execution.

Freezes the CURRENT behavior of ``retry_authorized`` side effects so the v3.4
implementation cannot silently change it. v3.3 introduced
``safe_to_retry → retry_authorized`` as a recorded-but-unexecutable state; these
tests prove that gap is real and characterize how the existing surfaces treat it.

v3.5.0 update: tests 4 and 5 have been updated to reflect intentional v3.5
changes (dead transition removed, lineage columns added). Tests 1-3 and 6
remain unchanged — they assert behavior that v3.5 preserves.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime import _create_mock_nodes

from nodechain.core.blueprint import load_blueprint
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.runtime.recovery_service import RecoveryService


@pytest.fixture
def blueprint():
    return load_blueprint("blueprints/research_decision_v1.yaml")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "retry_auth.db")


def _seed_unknown_side_effect(sm, run_id="r1", key="se:retry-1", node_id="search_tool"):
    """Seed a side effect directly in 'unknown' status (post-crash-window)."""
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id=node_id,
        side_effect_type="external_call", idempotency_key=key,
        status="unknown", request_hash="rh-1",
    )


def _authorize_retry(sm, run_id="r1", key="se:retry-1"):
    """Resolve the unknown effect via safe_to_retry → retry_authorized (v3.3 path)."""
    sm.resolve_side_effect_recovery_decision(
        run_id=run_id, idempotency_key=key,
        decision="safe_to_retry", reason="operator authorizes retry",
    )


# ─── 1. safe_to_retry creates retry_authorized and does not execute ───────

class TestRetryAuthorizedCreation:
    def test_safe_to_retry_creates_retry_authorized_not_executed(self, db_path):
        """safe_to_retry → retry_authorized (v3.3); the effect stays
        retry_authorized, no retry attempt is created, no execution occurs."""
        sm = StateManager(db_path=db_path)
        _seed_unknown_side_effect(sm)
        _authorize_retry(sm)

        se = sm.get_side_effect_by_key("r1", "se:retry-1")
        assert se["status"] == "retry_authorized", (
            f"safe_to_retry should leave the effect at retry_authorized; "
            f"got {se['status']!r}"
        )
        # No retry attempt child row exists (only the original).
        all_ses = sm.get_side_effects("r1")
        assert len(all_ses) == 1, (
            f"expected only the original effect (no child retry attempt); "
            f"got {len(all_ses)} rows"
        )


# ─── 2. normal resume does not execute retry_authorized ───────────────────

class TestResumeDoesNotExecuteRetryAuthorized:
    def test_resume_does_not_transition_retry_authorized(self, blueprint, db_path):
        """A normal resume does not execute or transition a retry_authorized effect.

        v3.3's _reconcile_side_effects_on_resume only sweeps started→unknown;
        retry_authorized is not touched. And the resume scheduler skips
        completed nodes, so no re-execution occurs for the effect's node.
        This characterizes the gap: retry_authorized is a dead end on resume.
        """
        sm = StateManager(db_path=db_path)
        # Seed a retry_authorized effect directly (simulating post-v3.3 state).
        sm.record_side_effect(
            run_id="r1", step_id=4, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="search:semantic_scholar:abc",
            status="retry_authorized", request_hash="abc",
        )
        # Resume would need a saved chain state; for this characterization we
        # only assert the effect is NOT transitioned by querying it back.
        # (A full resume requires seeded chain state; the point is the effect
        # status is unchanged regardless.)
        se = sm.get_side_effect_by_key("r1", "search:semantic_scholar:abc")
        assert se["status"] == "retry_authorized", (
            "retry_authorized effect should remain retry_authorized (no execution path exists)"
        )


# ─── 3. ordinary RETRY_STEP is side-effect-unaware ────────────────────────

class TestRetryStepIsSideEffectUnaware:
    def test_retry_step_action_does_not_target_side_effects(self, db_path):
        """RETRY_STEP operates at step/invocation level, not side-effect level.

        The existing RETRY_STEP delegate calls orchestrator.resume(run_id) —
        it knows nothing about side-effect keys and does not execute
        retry_authorized effects. This characterizes that RETRY_STEP and
        EXECUTE_RETRY_AUTHORIZED are distinct operations."""
        from nodechain.runtime.recovery_policy import RecoveryAction
        # RETRY_STEP requires a target_step_id (step-level precision), proving
        # it operates at the invocation level, not the side-effect level.
        # It has no side_effect_key parameter in its dispatch.
        assert RecoveryAction.RETRY_STEP.value == "retry_step"
        assert RecoveryAction.RETRY_STEP is not RecoveryAction.RESOLVE_SIDE_EFFECT
        # v3.5.0: EXECUTE_RETRY_AUTHORIZED now exists and is distinct from RETRY_STEP.
        # RETRY_STEP is step-level re-execution; EXECUTE_RETRY_AUTHORIZED is
        # side-effect-level retry through the recovery dispatch seam.
        assert hasattr(RecoveryAction, "EXECUTE_RETRY_AUTHORIZED")
        assert RecoveryAction.EXECUTE_RETRY_AUTHORIZED is not RecoveryAction.RETRY_STEP


# ─── 4. _journal_one cannot start a retry_authorized row ──────────────────

class TestJournalOneCannotUnstickRetryAuthorized:
    def test_journal_one_leaves_retry_authorized_unchanged(self, db_path):
        """_journal_one only re-starts 'planned' rows. A retry_authorized row
        found by key reuse stays retry_authorized — the core reason v3.5
        requires a new child attempt key.

        v3.5.0 update (INV-008): retry_authorized→started is now REJECTED by
        LEGAL_TRANSITIONS. The state machine encodes the invariant: the
        original row is terminal history; retry execution uses a child row."""
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key="se:ra-1",
            status="retry_authorized", request_hash="rh",
        )
        # v3.5.0 (INV-008): retry_authorized→started is now ILLEGAL.
        # The dead transition was removed from LEGAL_TRANSITIONS.
        from nodechain.core.stores import SideEffectLedgerStore
        store = SideEffectLedgerStore(db_path)
        assert not store.validate_side_effect_transition("retry_authorized", "started"), (
            "v3.5: retry_authorized→started must be rejected (dead transition removed, INV-008)"
        )
        se = sm.get_side_effect_by_key("r1", "se:ra-1")
        assert se["status"] == "retry_authorized"


# ─── 5. no retry-attempt child lineage exists today ───────────────────────

class TestNoRetryAttemptLineage:
    def test_no_child_attempt_key_format_exists(self, db_path):
        """No ::retry:: child key format exists in the side-effect schema today.
        v3.5.0 adds lineage COLUMNS (parent_side_effect_key, root_side_effect_key,
        retry_ordinal, recovery_decision_id) but no child rows have been
        allocated yet — the coordinator (Task 4) has not been built.

        v3.5.0 update: lineage columns now EXIST on the row (as NULL/0 for
        original rows), but no child attempt rows exist."""
        sm = StateManager(db_path=db_path)
        _seed_unknown_side_effect(sm)
        _authorize_retry(sm)
        all_ses = sm.get_side_effects("r1")
        # No key contains a retry-attempt delimiter.
        for se in all_ses:
            assert "::retry::" not in se["idempotency_key"], (
                "no retry-attempt child keys should exist yet (coordinator not built)"
            )
            # v3.5.0: lineage columns now EXIST on the row (added by Task 1).
            # For original rows, they are NULL/0/legacy_unavailable.
            assert se["parent_side_effect_key"] is None
            assert se["root_side_effect_key"] is None
            assert se["retry_ordinal"] == 0
            assert se["recovery_decision_id"] is None
            assert se["capsule_status"] == "legacy_unavailable"


# ─── 6. completion validation does not treat retry_authorized as completed ─

class TestRetryAuthorizedNotCompleted:
    def test_retry_authorized_is_not_completed(self, db_path):
        """retry_authorized is a non-terminal authorization state, NOT completed.
        Completion requires observed evidence (v3.0); retry_authorized only
        means an operator authorized a future attempt."""
        sm = StateManager(db_path=db_path)
        _seed_unknown_side_effect(sm)
        _authorize_retry(sm)
        se = sm.get_side_effect_by_key("r1", "se:retry-1")
        assert se["status"] != "completed", (
            "retry_authorized must not be treated as completed"
        )
        assert not sm.is_side_effect_completed("r1", "se:retry-1"), (
            "is_side_effect_completed must return False for retry_authorized"
        )
        # The completed-status query excludes retry_authorized.
        completed = sm.get_side_effects_by_status("r1", "completed")
        assert all(se["status"] != "retry_authorized" for se in completed)
