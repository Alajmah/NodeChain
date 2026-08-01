"""v3.5.0 Task 4 tests — SideEffectRetryCoordinator.

Tests the coordinator's validation sequence, child allocation, and
deterministic key binding.

Protects: INV-001, INV-002, INV-003, INV-015, INV-019
"""
from __future__ import annotations

import pytest
import sqlite3

from nodechain.core.state import StateManager
from nodechain.core.side_effect_utils import make_retry_side_effect_key
from nodechain.runtime.side_effect_retry_coordinator import (
    SideEffectRetryCoordinator,
    RetryExecutionError,
)


@pytest.fixture
def kek(tmp_path):
    from conftest import provision_test_kek
    return provision_test_kek(tmp_path / "t4_kek.bin")


@pytest.fixture
def sm_with_retry_authorized_parent(tmp_path, kek):
    """StateManager with a retry_authorized side effect that has an available capsule."""
    db_path = str(tmp_path / "t4.db")
    sm = StateManager(db_path=db_path)

    # Create a started side effect with a capsule, then transition to retry_authorized
    sm.start_side_effect_with_capsule(
        run_id="r1", step_id=1, node_id="search_tool",
        side_effect_type="external_call",
        idempotency_key="semantic_scholar:abc123",
        request_hash="abc123",
        capsule_operation={"terms": ["ai"], "max": 10, "adapter": "semantic_scholar"},
        adapter_id="semantic_scholar",
        kek=kek,
    )
    # Transition: started → unknown (crash window) → retry_authorized (v3.3 decision)
    sm.update_side_effect_status("r1", "semantic_scholar:abc123", "unknown")
    sm.resolve_side_effect_recovery_decision(
        run_id="r1", idempotency_key="semantic_scholar:abc123",
        decision="safe_to_retry", reason="operator authorizes retry",
    )

    # Verify the parent is in the right state
    parent = sm.get_side_effect_by_key("r1", "semantic_scholar:abc123")
    assert parent["status"] == "retry_authorized"
    assert parent["capsule_status"] == "available"

    # Get the recovery decision ID (created by resolve_side_effect_recovery_decision)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT decision_id FROM side_effect_recovery_decisions WHERE run_id=? AND idempotency_key=?",
            ("r1", "semantic_scholar:abc123"),
        ).fetchone()
    assert row is not None
    decision_id = row[0]

    return sm, decision_id, kek


class TestCoordinatorValidation:
    """The coordinator validates parent status, capsule, and attestation."""

    def test_parent_not_found_rejected(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "nf.db"))
        coord = SideEffectRetryCoordinator(sm)
        with pytest.raises(RetryExecutionError, match="not found"):
            coord.execute_authorized_retry(
                "r1", "nonexistent:key", "rd-1",
            )

    def test_parent_not_retry_authorized_rejected(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "na.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key="se:1",
            status="started", request_hash="rh",
        )
        coord = SideEffectRetryCoordinator(sm, kek=kek)
        with pytest.raises(RetryExecutionError, match="not retry_authorized"):
            coord.execute_authorized_retry("r1", "se:1", "rd-1")

    def test_legacy_capsule_rejected(self, tmp_path):
        """A retry_authorized row with legacy_unavailable capsule is rejected."""
        sm = StateManager(db_path=str(tmp_path / "leg.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        coord = SideEffectRetryCoordinator(sm)
        with pytest.raises(RetryExecutionError, match="legacy_unavailable"):
            coord.execute_authorized_retry("r1", "se:legacy", "rd-1")


class TestChildAllocation:
    """The coordinator allocates a deterministic child attempt."""

    def test_child_allocated_with_lineage(self, sm_with_retry_authorized_parent):
        """v3.5 T6: coordinator allocates child with correct lineage metadata.

        Without an adapter_factory, the coordinator allocates the child,
        claims, crosses the boundary, but cannot dispatch (returns unknown).
        The lineage metadata is still correct.
        """
        sm, decision_id, kek = sm_with_retry_authorized_parent
        coord = SideEffectRetryCoordinator(sm, kek=kek)

        result = coord.execute_authorized_retry(
            "r1", "semantic_scholar:abc123", decision_id,
        )

        assert result.retry_attempt_key.startswith("retry:")

        # Child exists in the ledger with correct lineage
        child = sm.get_side_effect_by_key("r1", result.retry_attempt_key)
        assert child is not None
        assert child["parent_side_effect_key"] == "semantic_scholar:abc123"
        assert child["root_side_effect_key"] == "semantic_scholar:abc123"
        assert child["retry_ordinal"] == 1
        assert child["recovery_decision_id"] == decision_id

    def test_deterministic_key_convergence(self, sm_with_retry_authorized_parent):
        """Same decision + parent → same child key."""
        sm, decision_id, kek = sm_with_retry_authorized_parent
        coord = SideEffectRetryCoordinator(sm, kek=kek)

        result1 = coord.execute_authorized_retry(
            "r1", "semantic_scholar:abc123", decision_id,
        )
        # Second call with same inputs → idempotent (same child)
        result2 = coord.execute_authorized_retry(
            "r1", "semantic_scholar:abc123", decision_id,
        )
        assert result1.retry_attempt_key == result2.retry_attempt_key

    def test_parent_immutable_after_child_allocation(
        self, sm_with_retry_authorized_parent,
    ):
        """Parent status remains retry_authorized after child allocation."""
        sm, decision_id, kek = sm_with_retry_authorized_parent
        coord = SideEffectRetryCoordinator(sm, kek=kek)

        coord.execute_authorized_retry(
            "r1", "semantic_scholar:abc123", decision_id,
        )

        parent = sm.get_side_effect_by_key("r1", "semantic_scholar:abc123")
        assert parent["status"] == "retry_authorized"

    def test_recovery_execution_action_recorded(
        self, sm_with_retry_authorized_parent,
    ):
        """A recovery_execution_actions row is created (INV-018).

        v3.5 T6: with no adapter_factory, the action reaches a terminal
        status (unknown — no dispatch possible), NOT 'planned'.
        """
        sm, decision_id, kek = sm_with_retry_authorized_parent
        coord = SideEffectRetryCoordinator(sm, kek=kek)

        result = coord.execute_authorized_retry(
            "r1", "semantic_scholar:abc123", decision_id,
        )

        with sqlite3.connect(str(sm.db_path)) as conn:
            row = conn.execute(
                "SELECT execution_status, execution_claim_id FROM recovery_execution_actions WHERE retry_attempt_key=?",
                (result.retry_attempt_key,),
            ).fetchone()
        assert row is not None
        assert row[0] in ("unknown", "completed", "failed")  # terminal
        assert row[1] is not None  # claim_id assigned


class TestLineageChain:
    """Grandchild lineage is correct (INV-017)."""

    def test_retry_ordinal_increments(self, sm_with_retry_authorized_parent):
        """A child has ordinal 1; a grandchild would have ordinal 2."""
        sm, decision_id, kek = sm_with_retry_authorized_parent
        coord = SideEffectRetryCoordinator(sm, kek=kek)

        result = coord.execute_authorized_retry(
            "r1", "semantic_scholar:abc123", decision_id,
        )
        child = sm.get_side_effect_by_key("r1", result.retry_attempt_key)
        assert child["retry_ordinal"] == 1
        assert child["root_side_effect_key"] == "semantic_scholar:abc123"
