"""Side-Effect Recovery Decision + Transition Guard Tests (v2.39.0).

Proves:
  - Recovery decisions are durable (record + retrieve)
  - Legal transitions pass, illegal transitions fail
  - Reconciler SE-R3 detects illegal status
  - Reconciler SE-R4 detects recovery decision without ledger row
  - Reconciler SE-R5 detects recovery decision conflicting with ledger state
"""

from __future__ import annotations

import sqlite3

import pytest

from nodechain.core.state import (
    StateManager,
    ChainState,
    SideEffectIntegrityError,
    SideEffectRecoveryError,
    SideEffectTransitionError,
)
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler


@pytest.fixture
def state_manager(tmp_path):
    return StateManager(db_path=str(tmp_path / "recovery.db"))


@pytest.fixture
def reconciler(state_manager):
    return TraceReconciler(state_manager)


def _make_trace(run_id: str) -> ChainTrace:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    trace.finalize("completed")
    return trace


class TestRecoveryDecisionCRUD:
    """v2.39.0: recovery decisions are durable."""

    def test_record_and_retrieve(self, state_manager):
        state_manager.record_recovery_decision({
            "decision_id": "rd-1",
            "run_id": "r1",
            "idempotency_key": "se:key1",
            "node_id": "search_tool",
            "side_effect_type": "external_call",
            "prior_status": "unknown",
            "decision": "verified_completed",
            "actor": "operator",
            "reason": "confirmed via external API log",
        })
        decisions = state_manager.get_recovery_decisions(run_id="r1")
        assert len(decisions) == 1
        assert decisions[0]["decision"] == "verified_completed"
        assert decisions[0]["idempotency_key"] == "se:key1"

    def test_filter_by_decision_type(self, state_manager):
        for i, dec in enumerate(["verified_completed", "safe_to_retry", "mark_unrecoverable"]):
            state_manager.record_recovery_decision({
                "decision_id": f"rd-{i}",
                "run_id": "r1",
                "idempotency_key": f"se:key{i}",
                "node_id": "n",
                "prior_status": "unknown",
                "decision": dec,
            })
        retries = state_manager.get_recovery_decisions(run_id="r1", decision="safe_to_retry")
        assert len(retries) == 1
        assert retries[0]["decision_id"] == "rd-1"


class TestTransitionValidation:
    """v2.39.0: legal/illegal side-effect status transitions."""

    def test_legal_transitions(self, state_manager):
        assert state_manager.validate_side_effect_transition("planned", "started")
        assert state_manager.validate_side_effect_transition("started", "completed")
        assert state_manager.validate_side_effect_transition("started", "failed")
        assert state_manager.validate_side_effect_transition("started", "unknown")
        assert state_manager.validate_side_effect_transition("unknown", "completed")
        assert state_manager.validate_side_effect_transition("unknown", "failed")
        assert state_manager.validate_side_effect_transition("unknown", "retry_authorized")

    def test_illegal_transitions(self, state_manager):
        assert not state_manager.validate_side_effect_transition("completed", "started")
        assert not state_manager.validate_side_effect_transition("completed", "failed")
        assert not state_manager.validate_side_effect_transition("failed", "completed")
        assert not state_manager.validate_side_effect_transition("planned", "unknown")
        assert not state_manager.validate_side_effect_transition("unknown", "started")
        # v3.5.0 (INV-008): retry_authorized→started removed. Retry execution
        # uses a child attempt, not same-row transition.
        assert not state_manager.validate_side_effect_transition("retry_authorized", "started")

    def test_terminal_states_locked(self, state_manager):
        """Completed and failed are terminal — no transitions out."""
        for terminal in ("completed", "failed"):
            for target in ("started", "completed", "failed", "unknown", "planned"):
                assert not state_manager.validate_side_effect_transition(terminal, target), \
                    f"{terminal}→{target} should be illegal"


class TestReconcilerRecoveryChecks:
    """v2.39.0: reconciler SE-R3/R4/R5."""

    @pytest.mark.asyncio
    async def test_se_r3_illegal_status_detected(self, reconciler, state_manager):
        """A ledger row with an unrecognized status is flagged."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        # Insert a row with a bogus status directly
        with __import__("sqlite3").connect(state_manager.db_path) as conn:
            conn.execute(
                "INSERT INTO side_effect_ledger "
                "(run_id, step_id, node_id, side_effect_type, idempotency_key, "
                "status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (state.run_id, 1, "n", "external_call", "k1", "bogus_status", "2026-01-01"),
            )

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        illegal = [i for i in report.issues
                   if i.check == "side_effect_illegal_transition"]
        assert len(illegal) >= 1

    @pytest.mark.asyncio
    async def test_se_r4_recovery_decision_missing_ledger(self, reconciler, state_manager):
        """Recovery decision referencing a non-existent ledger row = ERROR."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_recovery_decision({
            "decision_id": "rd-orphan",
            "run_id": state.run_id,
            "idempotency_key": "se:nonexistent",
            "node_id": "n",
            "prior_status": "unknown",
            "decision": "verified_completed",
        })

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        missing = [i for i in report.issues
                   if i.check == "side_effect_recovery_missing_ledger"]
        assert len(missing) >= 1

    @pytest.mark.asyncio
    async def test_se_r5_recovery_conflicts_with_ledger(self, reconciler, state_manager):
        """Recovery decision says verified_completed but ledger says failed."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        # Ledger row in failed state
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="se:conflict",
            status="failed",
        )

        # Recovery decision says it was completed
        state_manager.record_recovery_decision({
            "decision_id": "rd-conflict",
            "run_id": state.run_id,
            "idempotency_key": "se:conflict",
            "node_id": "n",
            "prior_status": "unknown",
            "decision": "verified_completed",
        })

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        conflicts = [i for i in report.issues
                     if i.check == "side_effect_recovery_conflict"]
        assert len(conflicts) >= 1

    @pytest.mark.asyncio
    async def test_clean_recovery_no_issues(self, reconciler, state_manager):
        """Valid recovery decision matching ledger state — no conflicts."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="se:clean",
            status="completed",
        )
        state_manager.record_recovery_decision({
            "decision_id": "rd-clean",
            "run_id": state.run_id,
            "idempotency_key": "se:clean",
            "node_id": "n",
            "prior_status": "unknown",
            "decision": "verified_completed",
        })

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        conflicts = [i for i in report.issues
                     if i.check in ("side_effect_recovery_conflict",
                                    "side_effect_recovery_missing_ledger",
                                    "side_effect_illegal_transition")]
        assert len(conflicts) == 0


def _count_decisions(state_manager: StateManager, run_id: str) -> int:
    """Count rows in side_effect_recovery_decisions for a run (atomicity check)."""
    with sqlite3.connect(state_manager.db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM side_effect_recovery_decisions WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    return row[0] if row else 0


def _seed_unknown_side_effect(state_manager: StateManager, *, run_id: str, key: str) -> None:
    """Seed an unknown side-effect ledger row (the resolution precondition)."""
    state_manager.record_side_effect(
        run_id=run_id, step_id=1, node_id="search_tool",
        side_effect_type="external_call",
        idempotency_key=key,
        status="started",
    )
    state_manager.update_side_effect_status(run_id, key, status="unknown")


def _base_decision(decision_id: str, run_id: str, key: str, decision: str) -> dict:
    """Build a recovery decision dict of the same shape record_recovery_decision takes."""
    return {
        "decision_id": decision_id,
        "run_id": run_id,
        "idempotency_key": key,
        "node_id": "search_tool",
        "side_effect_type": "external_call",
        "prior_status": "unknown",
        "decision": decision,
        "actor": "operator",
        "reason": "operator-verified resolution",
    }


class TestAtomicRecoveryResolution:
    """v3.4.0: resolve_side_effect_recovery_decision_transactional atomically
    inserts a recovery decision AND transitions the ledger out of 'unknown'
    on ONE connection. Tests mirror the spec in the v3.3 plan Task 1."""

    def test_atomic_unknown_to_completed(self, state_manager):
        run_id, key = "r-atomic-1", "se:atomic-1"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
            run_id=run_id,
            idempotency_key=key,
            decision=_base_decision("rd-1", run_id, key, "verified_completed"),
            target_status="completed",
            response_hash="resp-hash-1",
        )

        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "completed"
        assert row["response_hash"] == "resp-hash-1"
        assert _count_decisions(state_manager, run_id) == 1

    def test_atomic_unknown_to_failed_verified_failed(self, state_manager):
        run_id, key = "r-atomic-2", "se:atomic-2"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
            run_id=run_id,
            idempotency_key=key,
            decision=_base_decision("rd-2", run_id, key, "verified_failed"),
            target_status="failed",
        )

        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "failed"

    def test_atomic_unknown_to_failed_mark_unrecoverable(self, state_manager):
        run_id, key = "r-atomic-3", "se:atomic-3"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
            run_id=run_id,
            idempotency_key=key,
            decision=_base_decision("rd-3", run_id, key, "mark_unrecoverable"),
            target_status="failed",
        )

        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "failed"

    def test_atomic_unknown_to_retry_authorized(self, state_manager):
        run_id, key = "r-atomic-4", "se:atomic-4"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
            run_id=run_id,
            idempotency_key=key,
            decision=_base_decision("rd-4", run_id, key, "safe_to_retry"),
            target_status="retry_authorized",
        )

        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "retry_authorized"

    def test_atomic_duplicate_decision_id_rejected(self, state_manager):
        run_id, key = "r-atomic-5", "se:atomic-5"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        # First call completes; second call reuses decision_id on a fresh
        # unknown side effect (separate key so the ledger gate would otherwise pass).
        state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
            run_id=run_id,
            idempotency_key=key,
            decision=_base_decision("rd-dup", run_id, key, "verified_completed"),
            target_status="completed",
        )
        key2 = "se:atomic-5b"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key2)
        with pytest.raises(SideEffectIntegrityError):
            state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
                run_id=run_id,
                idempotency_key=key2,
                decision=_base_decision("rd-dup", run_id, key2, "verified_completed"),
                target_status="completed",
            )

    def test_atomic_empty_decision_id_rejected(self, state_manager):
        run_id, key = "r-atomic-6", "se:atomic-6"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        with pytest.raises(SideEffectTransitionError):
            state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
                run_id=run_id,
                idempotency_key=key,
                decision=_base_decision("", run_id, key, "verified_completed"),
                target_status="completed",
            )
        # Empty id must raise BEFORE any write — no partial state.
        assert _count_decisions(state_manager, run_id) == 0
        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row["status"] == "unknown"

    def test_atomic_wrong_decision_for_target_rejected(self, state_manager):
        run_id, key = "r-atomic-7", "se:atomic-7"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        # verified_completed cannot authorize unknown→failed.
        with pytest.raises(SideEffectTransitionError):
            state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
                run_id=run_id,
                idempotency_key=key,
                decision=_base_decision("rd-7", run_id, key, "verified_completed"),
                target_status="failed",
            )
        # Gate failure rolls back the INSERT — atomicity proof for this case.
        assert _count_decisions(state_manager, run_id) == 0
        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row["status"] == "unknown"

    def test_atomic_non_unknown_status_rejected(self, state_manager):
        run_id, key = "r-atomic-8", "se:atomic-8"
        # Seed a started effect (NOT unknown).
        state_manager.record_side_effect(
            run_id=run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key=key, status="started",
        )

        with pytest.raises(SideEffectTransitionError):
            state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
                run_id=run_id,
                idempotency_key=key,
                decision=_base_decision("rd-8", run_id, key, "verified_completed"),
                target_status="completed",
            )
        # INSERT rolled back — no decision row leaked.
        assert _count_decisions(state_manager, run_id) == 0

    def test_atomic_missing_ledger_row_rejected(self, state_manager):
        """Atomicity proof: when the ledger row is missing, the decision
        INSERT must be rolled back by the transaction — no partial state
        where a decision exists but the ledger is still unresolved."""
        run_id = "r-atomic-9"
        key = "se:nonexistent"

        with pytest.raises(SideEffectTransitionError):
            state_manager._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
                run_id=run_id,
                idempotency_key=key,
                decision=_base_decision("rd-9", run_id, key, "verified_completed"),
                target_status="completed",
            )
        # The atomicity proof: the decision INSERT was rolled back.
        assert _count_decisions(state_manager, run_id) == 0


class TestStateManagerRecoveryFacade:
    """v3.4.0: StateManager.resolve_side_effect_recovery_decision — the
    validated facade over the atomic store method. Maps decision→status,
    validates evidence, pre-checks unknown status, generates a decision_id,
    and delegates to resolve_side_effect_recovery_decision_transactional."""

    def test_facade_resolves_unknown_to_completed(self, state_manager):
        run_id, key = "r-facade-1", "se:facade-1"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        result = state_manager.resolve_side_effect_recovery_decision(
            run_id=run_id,
            idempotency_key=key,
            decision="verified_completed",
            external_reference="ext-ref-1",
        )

        assert result == "completed"
        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "completed"
        assert row["external_reference"] == "ext-ref-1"
        # Decision was recorded atomically alongside the transition.
        assert _count_decisions(state_manager, run_id) == 1

    def test_facade_verified_completed_without_evidence_rejected(self, state_manager):
        run_id, key = "r-facade-2", "se:facade-2"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="verified_completed",
            )
        assert exc_info.value.code == "MISSING_REQUIRED_EVIDENCE"
        # No partial state — nothing recorded, status unchanged.
        assert _count_decisions(state_manager, run_id) == 0
        row = state_manager.get_side_effect_by_key(run_id, key)
        assert row["status"] == "unknown"

    def test_facade_verified_failed_requires_reason(self, state_manager):
        run_id, key = "r-facade-3", "se:facade-3"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="verified_failed",
                reason="",
            )
        assert exc_info.value.code == "MISSING_REQUIRED_EVIDENCE"

    def test_facade_mark_unrecoverable_requires_reason(self, state_manager):
        run_id, key = "r-facade-4", "se:facade-4"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="mark_unrecoverable",
                reason="",
            )
        assert exc_info.value.code == "MISSING_REQUIRED_EVIDENCE"

    def test_facade_safe_to_retry_requires_reason(self, state_manager):
        run_id, key = "r-facade-5", "se:facade-5"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="safe_to_retry",
                reason="",
            )
        assert exc_info.value.code == "MISSING_REQUIRED_EVIDENCE"

    def test_facade_invalid_decision_rejected(self, state_manager):
        run_id, key = "r-facade-6", "se:facade-6"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key)

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="bogus",
                reason="whatever",
            )
        assert exc_info.value.code == "INVALID_RECOVERY_DECISION"

    def test_facade_not_found_rejected(self, state_manager):
        run_id, key = "r-facade-7", "se:nonexistent"

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="verified_completed",
                external_reference="ext-ref-7",
            )
        assert exc_info.value.code == "SIDE_EFFECT_NOT_FOUND"

    def test_facade_already_resolved_rejected(self, state_manager):
        run_id, key = "r-facade-8", "se:facade-8"
        # Seed a terminal completed effect (not via _seed_unknown).
        state_manager.record_side_effect(
            run_id=run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key=key, status="started",
        )
        state_manager.update_side_effect_status(run_id, key, status="completed")

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="verified_completed",
                external_reference="ext-ref-8",
            )
        assert exc_info.value.code == "SIDE_EFFECT_ALREADY_RESOLVED"

    def test_facade_not_unknown_rejected(self, state_manager):
        run_id, key = "r-facade-9", "se:facade-9"
        # Seed a started effect (not unknown, not terminal).
        state_manager.record_side_effect(
            run_id=run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key=key, status="started",
        )

        with pytest.raises(SideEffectRecoveryError) as exc_info:
            state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=key,
                decision="verified_completed",
                external_reference="ext-ref-9",
            )
        assert exc_info.value.code == "SIDE_EFFECT_NOT_UNKNOWN"

    def test_facade_generates_unique_decision_id(self, state_manager):
        """Two resolutions (different keys) get different decision_ids, and the
        decision_ids follow the 'rec:' prefix convention."""
        run_id = "r-facade-10"
        key_a, key_b = "se:facade-10a", "se:facade-10b"
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key_a)
        _seed_unknown_side_effect(state_manager, run_id=run_id, key=key_b)

        state_manager.resolve_side_effect_recovery_decision(
            run_id=run_id, idempotency_key=key_a,
            decision="verified_failed", reason="confirmed dead",
        )
        state_manager.resolve_side_effect_recovery_decision(
            run_id=run_id, idempotency_key=key_b,
            decision="mark_unrecoverable", reason="confirmed unrecoverable",
        )

        decisions = state_manager.get_recovery_decisions(run_id=run_id)
        assert len(decisions) == 2
        ids = {d["decision_id"] for d in decisions}
        assert len(ids) == 2  # distinct
        assert all(did.startswith("rec:") for did in ids), ids
