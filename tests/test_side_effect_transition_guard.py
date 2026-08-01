"""Side-Effect Runtime Transition Guard Tests (v2.39.1 + v2.39.2).

Proves that update_side_effect_status enforces legal transitions at write
time, not just post-hoc via reconciler. Unknown→terminal requires a
durable recovery decision with the correct semantic type (v2.39.2).
"""

from __future__ import annotations

import pytest

from nodechain.core.state import (
    StateManager,
    SideEffectTransitionError,
    SideEffectIntegrityError,
)


@pytest.fixture
def sm(tmp_path):
    return StateManager(db_path=str(tmp_path / "guard.db"))


def _create_started(sm, run_id="r1", key="k1"):
    """Helper: create a started side-effect row."""
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id="n",
        side_effect_type="external_call",
        idempotency_key=key, status="started",
    )


class TestIllegalTransitionsBlocked:
    """update_side_effect_status raises on illegal transitions."""

    def test_planned_to_unknown_blocked(self, sm):
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k1", status="planned",
        )
        with pytest.raises(SideEffectTransitionError, match="planned → unknown"):
            sm.update_side_effect_status("r1", "k1", "unknown")

    def test_completed_to_started_blocked(self, sm):
        _create_started(sm, "r1", "k2")
        sm.update_side_effect_status("r1", "k2", "completed", response_hash="r")
        with pytest.raises(SideEffectTransitionError, match="completed → started"):
            sm.update_side_effect_status("r1", "k2", "started")

    def test_failed_to_completed_blocked(self, sm):
        _create_started(sm, "r1", "k3")
        sm.update_side_effect_status("r1", "k3", "failed")
        with pytest.raises(SideEffectTransitionError, match="failed → completed"):
            sm.update_side_effect_status("r1", "k3", "completed")

    def test_unknown_to_started_blocked(self, sm):
        _create_started(sm, "r1", "k4")
        sm.update_side_effect_status("r1", "k4", "unknown")
        with pytest.raises(SideEffectTransitionError, match="unknown → started"):
            sm.update_side_effect_status("r1", "k4", "started")


class TestUnknownTerminalRequiresRecovery:
    """unknown→terminal requires a matching recovery decision."""

    def test_unknown_to_completed_without_recovery_raises(self, sm):
        _create_started(sm, "r1", "k5")
        sm.update_side_effect_status("r1", "k5", "unknown")
        with pytest.raises(SideEffectTransitionError, match="recovery decision"):
            sm.update_side_effect_status("r1", "k5", "completed")

    def test_unknown_to_failed_without_recovery_raises(self, sm):
        _create_started(sm, "r1", "k6")
        sm.update_side_effect_status("r1", "k6", "unknown")
        with pytest.raises(SideEffectTransitionError, match="recovery decision"):
            sm.update_side_effect_status("r1", "k6", "failed")

    def test_unknown_to_retry_without_recovery_raises(self, sm):
        _create_started(sm, "r1", "k7")
        sm.update_side_effect_status("r1", "k7", "unknown")
        with pytest.raises(SideEffectTransitionError, match="recovery decision"):
            sm.update_side_effect_status("r1", "k7", "retry_authorized")

    def test_unknown_to_completed_with_recovery_passes(self, sm):
        _create_started(sm, "r1", "k8")
        sm.update_side_effect_status("r1", "k8", "unknown")
        sm.record_recovery_decision({
            "decision_id": "rd-1", "run_id": "r1",
            "idempotency_key": "k8", "node_id": "n",
            "prior_status": "unknown", "decision": "verified_completed",
        })
        # Now the transition should succeed
        sm.update_side_effect_status("r1", "k8", "completed", response_hash="resp")
        row = sm.get_side_effect_by_key("r1", "k8")
        assert row["status"] == "completed"

    def test_unknown_to_failed_with_recovery_passes(self, sm):
        _create_started(sm, "r1", "k9")
        sm.update_side_effect_status("r1", "k9", "unknown")
        sm.record_recovery_decision({
            "decision_id": "rd-2", "run_id": "r1",
            "idempotency_key": "k9", "node_id": "n",
            "prior_status": "unknown", "decision": "verified_failed",
        })
        sm.update_side_effect_status("r1", "k9", "failed")
        row = sm.get_side_effect_by_key("r1", "k9")
        assert row["status"] == "failed"

    def test_unknown_to_retry_with_recovery_passes(self, sm):
        _create_started(sm, "r1", "k10")
        sm.update_side_effect_status("r1", "k10", "unknown")
        sm.record_recovery_decision({
            "decision_id": "rd-3", "run_id": "r1",
            "idempotency_key": "k10", "node_id": "n",
            "prior_status": "unknown", "decision": "safe_to_retry",
        })
        sm.update_side_effect_status("r1", "k10", "retry_authorized")
        row = sm.get_side_effect_by_key("r1", "k10")
        assert row["status"] == "retry_authorized"


class TestLegalTransitionsPass:
    """Legal transitions work correctly."""

    def test_started_to_completed(self, sm):
        _create_started(sm, "r1", "k11")
        sm.update_side_effect_status("r1", "k11", "completed", response_hash="r")
        assert sm.get_side_effect_by_key("r1", "k11")["status"] == "completed"

    def test_started_to_failed(self, sm):
        _create_started(sm, "r1", "k12")
        sm.update_side_effect_status("r1", "k12", "failed")
        assert sm.get_side_effect_by_key("r1", "k12")["status"] == "failed"

    def test_started_to_unknown(self, sm):
        _create_started(sm, "r1", "k13")
        sm.update_side_effect_status("r1", "k13", "unknown")
        assert sm.get_side_effect_by_key("r1", "k13")["status"] == "unknown"

    def test_retry_authorized_is_terminal(self, sm):
        """v3.5.0 (INV-008): retry_authorized→started is ILLEGAL.
        The dead transition was removed. Retry execution uses a child attempt
        via the SideEffectRetryCoordinator, not same-row transition."""
        _create_started(sm, "r1", "k14")
        sm.update_side_effect_status("r1", "k14", "unknown")
        sm.record_recovery_decision({
            "decision_id": "rd-4", "run_id": "r1",
            "idempotency_key": "k14", "node_id": "n",
            "prior_status": "unknown", "decision": "safe_to_retry",
        })
        sm.update_side_effect_status("r1", "k14", "retry_authorized")
        # v3.5.0: retry_authorized → started now rejected
        from nodechain.core.state import SideEffectTransitionError
        with pytest.raises(SideEffectTransitionError):
            sm.update_side_effect_status("r1", "k14", "started")
        assert sm.get_side_effect_by_key("r1", "k14")["status"] == "retry_authorized"


class TestTerminalDedupPreserved:
    """v2.38.1 terminal dedup behavior still works after v2.39.1 guard."""

    def test_completed_same_response_is_noop(self, sm):
        _create_started(sm, "r1", "k15")
        sm.update_side_effect_status("r1", "k15", "completed", response_hash="same")
        # Replay — no error
        sm.update_side_effect_status("r1", "k15", "completed", response_hash="same")
        assert sm.get_side_effect_by_key("r1", "k15")["status"] == "completed"

    def test_completed_different_response_raises(self, sm):
        _create_started(sm, "r1", "k16")
        sm.update_side_effect_status("r1", "k16", "completed", response_hash="a")
        with pytest.raises(SideEffectIntegrityError):
            sm.update_side_effect_status("r1", "k16", "completed", response_hash="b")


class TestMissingRowNoOp:
    """update on a non-existent row is a no-op (no crash, no phantom row)."""

    def test_missing_row_returns_silently(self, sm):
        sm.update_side_effect_status("r1", "nonexistent", "completed")
        # No crash, no row created
        assert sm.get_side_effect_by_key("r1", "nonexistent") is None


class TestRecoveryDecisionSemanticBinding:
    """v2.39.2: recovery decision must semantically match the target transition."""

    def _make_unknown(self, sm, key):
        _create_started(sm, "r1", key)
        sm.update_side_effect_status("r1", key, "unknown")

    def _add_recovery(self, sm, key, decision):
        sm.record_recovery_decision({
            "decision_id": f"rd-{key}", "run_id": "r1",
            "idempotency_key": key, "node_id": "n",
            "prior_status": "unknown", "decision": decision,
        })

    # Mismatch negatives
    def test_safe_to_retry_must_not_authorize_completed(self, sm):
        self._make_unknown(sm, "sem1")
        self._add_recovery(sm, "sem1", "safe_to_retry")
        with pytest.raises(SideEffectTransitionError, match="verified_completed"):
            sm.update_side_effect_status("r1", "sem1", "completed")

    def test_verified_completed_must_not_authorize_retry(self, sm):
        self._make_unknown(sm, "sem2")
        self._add_recovery(sm, "sem2", "verified_completed")
        with pytest.raises(SideEffectTransitionError, match="safe_to_retry"):
            sm.update_side_effect_status("r1", "sem2", "retry_authorized")

    def test_verified_failed_must_not_authorize_completed(self, sm):
        self._make_unknown(sm, "sem3")
        self._add_recovery(sm, "sem3", "verified_failed")
        with pytest.raises(SideEffectTransitionError, match="verified_completed"):
            sm.update_side_effect_status("r1", "sem3", "completed")

    def test_verified_completed_must_not_authorize_failed(self, sm):
        self._make_unknown(sm, "sem4")
        self._add_recovery(sm, "sem4", "verified_completed")
        with pytest.raises(SideEffectTransitionError, match="verified_failed|mark_unrecoverable"):
            sm.update_side_effect_status("r1", "sem4", "failed")

    # Correct pairings pass
    def test_mark_unrecoverable_authorizes_failed(self, sm):
        self._make_unknown(sm, "sem5")
        self._add_recovery(sm, "sem5", "mark_unrecoverable")
        sm.update_side_effect_status("r1", "sem5", "failed")
        assert sm.get_side_effect_by_key("r1", "sem5")["status"] == "failed"

    def test_operator_acknowledged_alone_does_not_authorize(self, sm):
        """operator_acknowledged is informational, not a terminal authorization."""
        self._make_unknown(sm, "sem6")
        self._add_recovery(sm, "sem6", "operator_acknowledged")
        with pytest.raises(SideEffectTransitionError):
            sm.update_side_effect_status("r1", "sem6", "completed")


class TestFailedSameStatusReplay:
    """v2.39.2: failed→failed behavior is explicitly defined."""

    def test_failed_to_failed_is_blocked(self, sm):
        """failed→failed is not in LEGAL_TRANSITIONS (failed is terminal)."""
        _create_started(sm, "r1", "ff1")
        sm.update_side_effect_status("r1", "ff1", "failed")
        with pytest.raises(SideEffectTransitionError, match="failed → failed"):
            sm.update_side_effect_status("r1", "ff1", "failed")

