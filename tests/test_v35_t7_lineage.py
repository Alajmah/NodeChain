"""v3.5.0 Task 7 tests — lineage projection, classifier, reconciler.

Tests ChatGPT's T7 gate requirements:
1. Lineage projection is read-only (parent stays retry_authorized)
2. Boundary-aware classifier (8-row state table)
3. Reconciler cross-record checks (SE-R6)
4. Critical crash-window test (dispatch→die→expire→unknown, no redispatch)
5. Classifier precedence fails toward inconsistency

Protects: INV-011, INV-021
"""
from __future__ import annotations

import sqlite3
import pytest
from datetime import datetime, timezone, timedelta

from nodechain.core.state import StateManager, ChainState
from nodechain.runtime.recovery_classifier import (
    RecoveryState,
    classify,
    classify_retry_lineage,
)
from nodechain.runtime.trace_reconciler import TraceReconciler


@pytest.fixture
def kek(tmp_path):
    from nodechain.core.capsule_crypto import KekManager, CapsuleEncryptionError
    path = tmp_path / "t7_kek.bin"
    # Caller-level retry for OS write anomalies (manager hard-fails post-
    # publication; operator removes corrupt file and retries).
    for _ in range(8):
        try:
            return KekManager(kek_path=path, local_dev=True).get_kek()
        except CapsuleEncryptionError:
            if path.exists():
                path.unlink(missing_ok=True)
    pytest.fail("could not provision KEK fixture after 8 attempts")


@pytest.fixture
def setup_parent_with_child(tmp_path, kek):
    """StateManager with a retry_authorized parent and configurable child state.

    Returns (sm, run_id, parent_key, child_key, kek) with child at 'planned'.
    Tests modify the child's state via direct SQL to test each classification.
    """
    db_path = str(tmp_path / "t7.db")
    sm = StateManager(db_path=db_path)
    run_id = "r1"
    parent_key = "semantic_scholar:abc123"

    # Create parent with capsule
    sm.start_side_effect_with_capsule(
        run_id=run_id, step_id=1, node_id="search_tool",
        side_effect_type="external_call",
        idempotency_key=parent_key,
        request_hash="abc123",
        capsule_operation={"terms": ["ai"], "max": 10, "filters": {}},
        operation_name="search",
        adapter_id="semantic_scholar", adapter_version="1.0.0",
        node_version="1.0", contract_id="c", contract_version="1.0",
        kek=kek,
    )
    sm.update_side_effect_status(run_id, parent_key, "unknown")
    sm.resolve_side_effect_recovery_decision(
        run_id=run_id, idempotency_key=parent_key,
        decision="safe_to_retry", reason="test",
    )

    # Create a child at planned via SQL
    from nodechain.core.side_effect_utils import make_retry_side_effect_key
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT decision_id FROM side_effect_recovery_decisions "
            "WHERE run_id=? AND idempotency_key=?",
            (run_id, parent_key),
        ).fetchone()
    decision_id = row[0]
    child_key = make_retry_side_effect_key(parent_key, decision_id)
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO side_effect_ledger
               (run_id, step_id, node_id, side_effect_type, idempotency_key,
                status, request_hash, retryable, timestamp,
                parent_side_effect_key, root_side_effect_key,
                retry_ordinal, recovery_decision_id, capsule_status)
               VALUES (?, 1, 'search_tool', 'external_call', ?, 'planned', 'abc', 1, ?,
                       ?, ?, 1, ?, 'available')""",
            (run_id, child_key, now, parent_key, parent_key, decision_id),
        )

    # Initialize chain state
    cs = ChainState(
        run_id=run_id, chain_id="c1", revision=0, status="crashed",
        step=1, current_node="search_tool",
    )
    sm.save(cs)

    return sm, run_id, parent_key, child_key, kek


def _set_child_status(sm, run_id, child_key, status, **extra):
    """Directly update child status and optional fields via SQL."""
    sets = ["status = ?"]
    params = [status]
    for k, v in extra.items():
        sets.append(f"{k} = ?")
        params.append(v)
    params.extend([run_id, child_key])
    with sqlite3.connect(str(sm.db_path)) as conn:
        conn.execute(
            f"""UPDATE side_effect_ledger
                SET {", ".join(sets)}
                WHERE run_id = ? AND idempotency_key = ?""",
            params,
        )


# ── 1. Boundary-aware classifier (ChatGPT 8-row state table) ──────────


class TestBoundaryAwareClassifier:
    """ChatGPT T7 gate #2: classifier must be boundary-aware."""

    def test_pending_execution_no_child(self, tmp_path, kek):
        """Parent retry_authorized, no child → RETRY_AUTHORIZED_PENDING_EXECUTION."""
        sm = StateManager(db_path=str(tmp_path / "t7a.db"))
        run_id = "r1"
        parent_key = "se:k1"
        sm.start_side_effect_with_capsule(
            run_id=run_id, step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key=parent_key,
            request_hash="rh", capsule_operation={"terms": ["a"], "max": 1, "filters": {}},
            operation_name="search", adapter_id="ss", adapter_version="1.0.0",
            node_version="1", contract_id="c", contract_version="1",
            kek=kek,
        )
        sm.update_side_effect_status(run_id, parent_key, "unknown")
        sm.resolve_side_effect_recovery_decision(
            run_id=run_id, idempotency_key=parent_key,
            decision="safe_to_retry", reason="t",
        )
        cs = ChainState(run_id=run_id, chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)

        side_effects = sm.get_side_effects(run_id)
        decisions = sm.get_recovery_decisions(run_id=run_id)

        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, decisions,
        )
        assert result is not None
        assert result.state == RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION

    def test_child_completed(self, setup_parent_with_child):
        """Child completed → RETRY_COMPLETED."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        _set_child_status(sm, run_id, child_key, "completed")

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )
        assert result.state == RecoveryState.RETRY_COMPLETED

    def test_child_failed(self, setup_parent_with_child):
        """Child failed → RETRY_FAILED."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        _set_child_status(sm, run_id, child_key, "failed")

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )
        assert result.state == RecoveryState.RETRY_FAILED

    def test_child_unknown(self, setup_parent_with_child):
        """Child unknown → RETRY_UNKNOWN."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        _set_child_status(sm, run_id, child_key, "unknown")

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )
        assert result.state == RecoveryState.RETRY_UNKNOWN

    def test_child_planned(self, setup_parent_with_child):
        """Child planned → RETRY_AUTHORIZED_PENDING_EXECUTION."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )
        assert result.state == RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION

    def test_legacy_not_replayable(self, tmp_path):
        """Parent retry_authorized with legacy capsule → LEGACY_NOT_REPLAYABLE."""
        sm = StateManager(db_path=str(tmp_path / "t7l.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        side_effects = sm.get_side_effects("r1")
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )
        assert result.state == RecoveryState.LEGACY_NOT_REPLAYABLE


# ── 2. Parent stays immutable (ChatGPT T7 gate #1) ─────────────────────


class TestParentImmutabilityInProjection:
    """The projection is read-only — parent stays retry_authorized."""

    def test_parent_unchanged_after_completed_child(self, setup_parent_with_child):
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        _set_child_status(sm, run_id, child_key, "completed")

        # Run the classifier
        side_effects = sm.get_side_effects(run_id)
        classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )

        # Parent is STILL retry_authorized
        parent = sm.get_side_effect_by_key(run_id, parent_key)
        assert parent["status"] == "retry_authorized"


# ── 3. Critical crash-window test (ChatGPT T7 gate #5) ─────────────────


class TestCrashWindowProjection:
    """ChatGPT T7 gate #5: the most important adversarial scenario.

    claim → mark dispatch → dispatch → worker dies → lease expires
    Expected: unknown, never auto-redispatched, operator intervention required.
    """

    def test_dispatched_then_expired_unknown(self, setup_parent_with_child):
        """Child started + dispatch_attempted_at set + lease expired → RETRY_UNKNOWN."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        _set_child_status(
            sm, run_id, child_key, "started",
            dispatch_attempted_at=past,
            claim_expires_at=past,  # expired
        )

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )

        assert result.state == RecoveryState.RETRY_UNKNOWN
        assert "uncertain" in result.blocking_reason.lower()

    def test_not_dispatched_then_expired_reclaimable(self, setup_parent_with_child):
        """Child started + NO dispatch_attempted_at + lease expired → IN_FLIGHT (reclaimable)."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        _set_child_status(
            sm, run_id, child_key, "started",
            dispatch_attempted_at=None,
            claim_expires_at=past,  # expired
        )

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )

        assert result.state == RecoveryState.RETRY_ATTEMPT_IN_FLIGHT
        assert "reclaimable" in result.blocking_reason.lower()

    def test_lease_valid_in_flight(self, setup_parent_with_child):
        """Child started + lease valid → RETRY_ATTEMPT_IN_FLIGHT."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        _set_child_status(
            sm, run_id, child_key, "started",
            claim_expires_at=future,
        )

        side_effects = sm.get_side_effects(run_id)
        result = classify_retry_lineage(
            [se for se in side_effects if se["status"] == "retry_authorized"],
            side_effects, None,
        )

        assert result.state == RecoveryState.RETRY_ATTEMPT_IN_FLIGHT


# ── 4. Reconciler SE-R6 cross-record checks ────────────────────────────


class TestReconcilerSER6:
    """ChatGPT T7 gate #3: cross-record consistency checks."""

    def test_orphan_child_detected(self, setup_parent_with_child):
        """SE-R6a: child referencing a missing parent → error."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        # Delete the parent row
        with sqlite3.connect(str(sm.db_path)) as conn:
            conn.execute(
                "DELETE FROM side_effect_ledger WHERE idempotency_key=?",
                (parent_key,),
            )

        reconciler = TraceReconciler(sm)
        side_effects = sm.get_side_effects(run_id)
        report = reconciler.reconcile.__wrapped__ if hasattr(
            reconciler.reconcile, "__wrapped__"
        ) else None

        # Directly call the side-effect check method
        from nodechain.runtime.trace_reconciler import ReconciliationIssue, ReconciliationReport
        rep = ReconciliationReport(run_id=run_id)
        reconciler._check_side_effect_trace_ledger([], [], [], [], side_effects, rep)

        orphan_issues = [i for i in rep.issues if i.check == "side_effect_retry_orphan_child"]
        assert len(orphan_issues) >= 1

    def test_missing_action_warning(self, setup_parent_with_child):
        """SE-R6c: child without an execution action → warning."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child

        from nodechain.runtime.trace_reconciler import ReconciliationReport
        rep = ReconciliationReport(run_id=run_id)
        side_effects = sm.get_side_effects(run_id)
        reconciler = TraceReconciler(sm)
        reconciler._check_side_effect_trace_ledger([], [], [], [], side_effects, rep)

        action_issues = [i for i in rep.issues if i.check == "side_effect_retry_missing_action"]
        assert len(action_issues) >= 1

    def test_premature_dispatch_error(self, setup_parent_with_child):
        """SE-R6d: dispatch_attempted_at on a planned child → error."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        now = datetime.now(timezone.utc).isoformat()
        _set_child_status(
            sm, run_id, child_key, "planned",
            dispatch_attempted_at=now,
        )

        from nodechain.runtime.trace_reconciler import ReconciliationReport
        rep = ReconciliationReport(run_id=run_id)
        side_effects = sm.get_side_effects(run_id)
        reconciler = TraceReconciler(sm)
        reconciler._check_side_effect_trace_ledger([], [], [], [], side_effects, rep)

        premature = [i for i in rep.issues if i.check == "side_effect_retry_premature_dispatch"]
        assert len(premature) >= 1
        assert premature[0].severity == "error"


# ── 5. classify() integration (full classification path) ──────────────


class TestClassifyIntegration:
    """Verify classify() picks up the retry lineage states."""

    def test_classify_returns_retry_completed(self, setup_parent_with_child):
        """Full classify() returns RETRY_COMPLETED when child is completed."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        _set_child_status(sm, run_id, child_key, "completed")

        state = sm.load(run_id)
        side_effects = sm.get_side_effects(run_id)
        decisions = sm.get_recovery_decisions(run_id=run_id)

        result = classify(state, side_effects, None, [], recovery_decisions=decisions)
        assert result.state == RecoveryState.RETRY_COMPLETED

    def test_classify_returns_retry_unknown(self, setup_parent_with_child):
        """Full classify() returns RETRY_UNKNOWN when child is unknown."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        _set_child_status(sm, run_id, child_key, "unknown")

        state = sm.load(run_id)
        side_effects = sm.get_side_effects(run_id)
        decisions = sm.get_recovery_decisions(run_id=run_id)

        result = classify(state, side_effects, None, [], recovery_decisions=decisions)
        assert result.state == RecoveryState.RETRY_UNKNOWN


# ── 6. Multi-parent severity (ChatGPT fix 3) ───────────────────────────


class TestMultiParentSeverity:
    """ChatGPT T7 fix 3: unresolved uncertainty wins over successful closure."""

    def test_unknown_outranks_completed(self, setup_parent_with_child, tmp_path, kek):
        """Two parents: one RETRY_UNKNOWN, one RETRY_COMPLETED → RETRY_UNKNOWN wins."""
        sm, run_id, parent_key1, child_key1, _ = setup_parent_with_child

        # Set child1 to unknown
        _set_child_status(sm, run_id, child_key1, "unknown")

        # Create a second parent with a completed child
        parent_key2 = "arxiv:def"
        sm.start_side_effect_with_capsule(
            run_id=run_id, step_id=2, node_id="n",
            side_effect_type="external_call", idempotency_key=parent_key2,
            request_hash="rh2",
            capsule_operation={"terms": ["b"], "max": 5, "filters": {}},
            operation_name="search", adapter_id="arxiv", adapter_version="1.0.0",
            node_version="1", contract_id="c", contract_version="1",
            kek=kek,
        )
        sm.update_side_effect_status(run_id, parent_key2, "unknown")
        sm.resolve_side_effect_recovery_decision(
            run_id=run_id, idempotency_key=parent_key2,
            decision="safe_to_retry", reason="t",
        )
        from nodechain.core.side_effect_utils import make_retry_side_effect_key
        import sqlite3 as _sql
        with _sql.connect(str(sm.db_path)) as conn:
            row = conn.execute(
                "SELECT decision_id FROM side_effect_recovery_decisions WHERE idempotency_key=?",
                (parent_key2,),
            ).fetchone()
        child_key2 = make_retry_side_effect_key(parent_key2, row[0])
        now = datetime.now(timezone.utc).isoformat()
        with _sql.connect(str(sm.db_path)) as conn:
            conn.execute(
                """INSERT INTO side_effect_ledger
                   (run_id, step_id, node_id, side_effect_type, idempotency_key,
                    status, request_hash, retryable, timestamp,
                    parent_side_effect_key, root_side_effect_key,
                    retry_ordinal, recovery_decision_id, capsule_status)
                   VALUES (?, 2, 'n', 'external_call', ?, 'completed', 'rh2', 1, ?,
                           ?, ?, 1, ?, 'available')""",
                (run_id, child_key2, now, parent_key2, parent_key2, row[0]),
            )

        side_effects = sm.get_side_effects(run_id)
        retry_parents = [se for se in side_effects if se["status"] == "retry_authorized"]
        result = classify_retry_lineage(retry_parents, side_effects, None)

        assert result.state == RecoveryState.RETRY_UNKNOWN


# ── 7. Durable expiry reconciliation (ChatGPT fix 1) ────────────────────


class TestDurableExpiryReconciliation:
    """ChatGPT T7 fix 1: reconciler must durably mutate expired children."""

    def test_dispatched_expired_goes_unknown(self, setup_parent_with_child):
        """Started + dispatch_attempted_at + expired → durably transitioned to unknown."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        _set_child_status(
            sm, run_id, child_key, "started",
            dispatch_attempted_at=past,
            claim_expires_at=past,
            execution_claim_id="test-fence-1",
        )

        results = sm.reconcile_expired_recovery_children(run_id)

        assert len(results) == 1
        assert results[0]["action"] == "unknown"

        # Verify the child is now unknown in the ledger
        child = sm.get_side_effect_by_key(run_id, child_key)
        assert child["status"] == "unknown"

    def test_not_dispatched_expired_requeued(self, setup_parent_with_child):
        """Started + no dispatch + expired → durably requeued to planned."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        _set_child_status(
            sm, run_id, child_key, "started",
            dispatch_attempted_at=None,
            claim_expires_at=past,
            execution_claim_id="test-fence-2",
        )

        results = sm.reconcile_expired_recovery_children(run_id)

        assert len(results) == 1
        assert results[0]["action"] == "requeued"

        # Verify the child is now planned with cleared ownership
        child = sm.get_side_effect_by_key(run_id, child_key)
        assert child["status"] == "planned"
        assert child["execution_claim_id"] is None

    def test_unexpired_not_changed(self, setup_parent_with_child):
        """Started + lease valid → NOT changed by reconciliation."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        _set_child_status(
            sm, run_id, child_key, "started",
            claim_expires_at=future,
        )

        results = sm.reconcile_expired_recovery_children(run_id)

        assert len(results) == 0  # nothing reconciled

        child = sm.get_side_effect_by_key(run_id, child_key)
        assert child["status"] == "started"  # unchanged


# ── 8. Pre-boundary failure accepted by SE-R6 (ChatGPT fix 4) ──────────


class TestPreBoundaryFailureAccepted:
    """ChatGPT T7 fix 4: pre-boundary 'failed' without boundary marker is valid."""

    def test_pre_boundary_failure_no_ser6e_error(self, setup_parent_with_child):
        """Child failed from pre-boundary validation → no dispatch_without_boundary error."""
        sm, run_id, parent_key, child_key, _ = setup_parent_with_child

        # Create an execution action with pre-boundary failure
        action_id = "test-action-1"
        now = datetime.now(timezone.utc).isoformat()
        import sqlite3 as _sql
        with _sql.connect(str(sm.db_path)) as conn:
            conn.execute(
                """INSERT INTO recovery_execution_actions
                   (action_id, operator_action_id, run_id, retry_attempt_key,
                    execution_status, execution_claim_id, started_at,
                    finished_at, outcome_code, metadata_json)
                   VALUES (?, NULL, ?, ?, 'failed', NULL, ?, ?,
                           'ENVELOPE_VALIDATION_FAILED', '{}')""",
                (action_id, run_id, child_key, now, now),
            )

        # Set child to failed (no dispatch_attempted_at)
        _set_child_status(sm, run_id, child_key, "failed")

        from nodechain.runtime.trace_reconciler import ReconciliationReport
        rep = ReconciliationReport(run_id=run_id)
        side_effects = sm.get_side_effects(run_id)
        reconciler = TraceReconciler(sm)
        reconciler._check_side_effect_trace_ledger([], [], [], [], side_effects, rep)

        boundary_errors = [
            i for i in rep.issues
            if i.check == "side_effect_retry_action_dispatch_without_boundary"
        ]
        assert len(boundary_errors) == 0  # pre-boundary failure is OK
