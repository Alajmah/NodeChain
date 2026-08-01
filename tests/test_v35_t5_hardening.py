"""v3.5.0 T5 hardening tests — generic child bypass guard + fenced dispatch marker.

ChatGPT T5 hold conditions:
1. Recovery children must be rejected by ordinary update_side_effect_status
2. mark_recovery_dispatch_attempted: fenced one-shot boundary CAS

Required adversarial coverage:
- Generic child planned→started rejected
- Generic child started→completed/failed/unknown rejected
- Ordinary non-lineage rows remain unaffected
- Dispatch marker: correct token + valid lease → True (one-shot)
- Dispatch marker: duplicate call → False
- Dispatch marker: stale token → False
- Dispatch marker: expired lease → False
"""
from __future__ import annotations

import sqlite3
import pytest
from datetime import datetime, timezone, timedelta

from nodechain.core.state import StateManager, SideEffectRecoveryError
from nodechain.core.stores import SideEffectLedgerStore
from nodechain.runtime.side_effect_retry_coordinator import SideEffectRetryCoordinator


@pytest.fixture
def kek(tmp_path):
    from conftest import provision_test_kek
    return provision_test_kek(tmp_path / "t5h_kek.bin")


@pytest.fixture
def setup_with_child_started(tmp_path, kek):
    """Full setup with child allocated and claimed (at started)."""
    db_path = str(tmp_path / "t5h.db")
    sm = StateManager(db_path=db_path)
    store = SideEffectLedgerStore(db_path)

    # Parent: started → unknown → retry_authorized
    sm.start_side_effect_with_capsule(
        run_id="r1", step_id=1, node_id="search_tool",
        side_effect_type="external_call",
        idempotency_key="semantic_scholar:abc",
        request_hash="abc",
        capsule_operation={"terms": ["ai"], "max": 10, "adapter": "semantic_scholar"},
        adapter_id="semantic_scholar",
        kek=kek,
    )
    sm.update_side_effect_status("r1", "semantic_scholar:abc", "unknown")
    sm.resolve_side_effect_recovery_decision(
        run_id="r1", idempotency_key="semantic_scholar:abc",
        decision="safe_to_retry", reason="auth",
    )

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT decision_id FROM side_effect_recovery_decisions WHERE run_id=? AND idempotency_key=?",
            ("r1", "semantic_scholar:abc"),
        ).fetchone()
    decision_id = row[0]

    # v3.5 T6: the coordinator now runs the full execution path. For T5
    # hardening tests that test store-level primitives, allocate the child
    # directly at planned via SQL (bypassing the coordinator).
    from nodechain.core.side_effect_utils import make_retry_side_effect_key
    child_key = make_retry_side_effect_key("semantic_scholar:abc", decision_id)

    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO side_effect_ledger
               (run_id, step_id, node_id, side_effect_type, idempotency_key,
                status, request_hash, retryable, timestamp,
                parent_side_effect_key, root_side_effect_key,
                retry_ordinal, recovery_decision_id, capsule_status)
               VALUES (?, 1, 'search_tool', 'external_call', ?, 'planned', 'abc', 1, ?,
                       'semantic_scholar:abc', 'semantic_scholar:abc', 1, ?, 'available')""",
            ("r1", child_key, now, decision_id),
        )

    # Create an action row for the claim to transition
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO recovery_execution_actions
               (action_id, operator_action_id, run_id, retry_attempt_key,
                execution_status, execution_claim_id, started_at,
                finished_at, outcome_code, metadata_json)
               VALUES ('test-action', NULL, 'r1', ?, 'created', 'claim-1',
                       NULL, NULL, NULL, '{}')""",
            (child_key,),
        )

    # Claim the child (planned → started)
    token = store.claim_recovery_attempt("r1", child_key, "claim-1", "test-action")

    return {
        "sm": sm, "store": store, "db_path": db_path,
        "parent_key": "semantic_scholar:abc",
        "child_key": child_key,
        "token": token,
        "kek": kek,
    }


# ── Fix 1: Generic child bypass guard ──────────────────────────────────


class TestGenericChildBypassGuard:
    """ChatGPT T5 hardening #1: recovery children rejected by ordinary API."""

    def test_generic_started_to_completed_rejected(self, setup_with_child_started):
        """Ordinary update_side_effect_status cannot complete a recovery child."""
        s = setup_with_child_started
        with pytest.raises(SideEffectRecoveryError, match="RECOVERY_CHILD_REQUIRES_FENCED_TRANSITION"):
            s["sm"].update_side_effect_status("r1", s["child_key"], "completed")

    def test_generic_started_to_failed_rejected(self, setup_with_child_started):
        s = setup_with_child_started
        with pytest.raises(SideEffectRecoveryError, match="RECOVERY_CHILD_REQUIRES_FENCED_TRANSITION"):
            s["sm"].update_side_effect_status("r1", s["child_key"], "failed")

    def test_generic_started_to_unknown_rejected(self, setup_with_child_started):
        s = setup_with_child_started
        with pytest.raises(SideEffectRecoveryError, match="RECOVERY_CHILD_REQUIRES_FENCED_TRANSITION"):
            s["sm"].update_side_effect_status("r1", s["child_key"], "unknown")

    def test_ordinary_non_lineage_rows_unaffected(self, tmp_path, kek):
        """Ordinary (non-recovery) rows still work through the generic API."""
        sm = StateManager(db_path=str(tmp_path / "t5n.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:normal",
            status="started", request_hash="rh",
        )
        # Should work fine — no parent_side_effect_key
        sm.update_side_effect_status("r1", "se:normal", "completed", response_hash="rh-result")
        se = sm.get_side_effect_by_key("r1", "se:normal")
        assert se["status"] == "completed"


# ── Fix 2: mark_recovery_dispatch_attempted fenced one-shot CAS ────────


class TestDispatchBoundaryMarker:
    """ChatGPT T5 hardening #2: fenced one-shot dispatch boundary CAS."""

    def test_correct_token_marks_boundary(self, setup_with_child_started):
        """Correct fencing token + valid lease → boundary marked."""
        s = setup_with_child_started
        result = s["store"].mark_recovery_dispatch_attempted(
            "r1", s["child_key"], s["token"],
        )
        assert result is True

        # Verify dispatch_attempted_at is set
        child = s["sm"].get_side_effect_by_key("r1", s["child_key"])
        assert child["dispatch_attempted_at"] is not None

    def test_duplicate_call_rejected(self, setup_with_child_started):
        """Second call with same token → False (one-shot)."""
        s = setup_with_child_started
        assert s["store"].mark_recovery_dispatch_attempted("r1", s["child_key"], s["token"])
        # Second call → False (already marked)
        assert not s["store"].mark_recovery_dispatch_attempted("r1", s["child_key"], s["token"])

    def test_stale_token_rejected(self, setup_with_child_started):
        """Wrong fencing token → False."""
        s = setup_with_child_started
        result = s["store"].mark_recovery_dispatch_attempted(
            "r1", s["child_key"], "WRONG_TOKEN",
        )
        assert result is False

    def test_expired_lease_rejected(self, setup_with_child_started):
        """Expired lease → False."""
        s = setup_with_child_started
        # Expire the lease
        with sqlite3.connect(s["db_path"]) as conn:
            conn.execute(
                """UPDATE side_effect_ledger SET claim_expires_at = ?
                   WHERE run_id = ? AND idempotency_key = ?""",
                ("2020-01-01T00:00:00+00:00", "r1", s["child_key"]),
            )
        result = s["store"].mark_recovery_dispatch_attempted(
            "r1", s["child_key"], s["token"],
        )
        assert result is False

    def test_stale_fence_cannot_cross_after_reclaim(self, setup_with_child_started):
        """ChatGPT race: worker A lease expires, worker B reclaims, A tries to cross."""
        s = setup_with_child_started
        token_a = s["token"]

        # Expire lease without dispatch
        with sqlite3.connect(s["db_path"]) as conn:
            conn.execute(
                """UPDATE side_effect_ledger SET claim_expires_at = ?
                   WHERE run_id = ? AND idempotency_key = ?""",
                ("2020-01-01T00:00:00+00:00", "r1", s["child_key"]),
            )

        # Worker B reclaims (no dispatch → safe)
        token_b = s["store"].reclaim_expired_recovery_attempt("r1", s["child_key"])
        assert token_b is not None  # Got new token

        # Worker A tries to cross boundary with stale token → rejected
        result_a = s["store"].mark_recovery_dispatch_attempted(
            "r1", s["child_key"], token_a,
        )
        assert result_a is False

        # Worker B can cross with new token
        result_b = s["store"].mark_recovery_dispatch_attempted(
            "r1", s["child_key"], token_b,
        )
        assert result_b is True
