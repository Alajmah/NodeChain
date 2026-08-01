"""v3.5.0 Task 9 tests — metrics + deletion/purge gate.

Two surfaces consuming T7's lineage projection:
- operational retry metrics (DB-backed, three producers)
- deletion/purge gate with locked recheck + atomic purge + key tombstone

Protects: INV-016 (Capsule Retention Tied to Lineage Closure)
"""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone

import pytest

from nodechain.core.state import StateManager, ChainState
from nodechain.runtime.recovery_policy import RecoveryAction


@pytest.fixture
def kek(tmp_path):
    from nodechain.core.capsule_crypto import KekManager, CapsuleEncryptionError
    path = tmp_path / "t9_kek.bin"
    # Caller-level retry for OS write anomalies (manager hard-fails post-
    # publication; operator removes corrupt file and retries).
    for _ in range(8):
        try:
            return KekManager(kek_path=path, local_dev=True).get_kek()
        except CapsuleEncryptionError:
            if path.exists():
                path.unlink(missing_ok=True)
    pytest.fail("could not provision KEK fixture after 8 attempts")


# ── T9.1: lineage projection + exhaustive state partition ───────────────


class TestLineageProjection:
    """classify_retry_lineages() public per-parent projection."""

    def test_exhaustive_state_partition(self):
        """Every v3.5 retry-lineage state is in exactly one of CLOSED/OPEN.

        A future unclassified state must fail closed (not silently deletable).
        """
        from nodechain.runtime.recovery_classifier import (
            CLOSED_RETRY_LINEAGE_STATES,
            OPEN_RETRY_LINEAGE_STATES,
            RecoveryState,
        )

        retry_states = {
            RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION,
            RecoveryState.RETRY_ATTEMPT_IN_FLIGHT,
            RecoveryState.RETRY_COMPLETED,
            RecoveryState.RETRY_FAILED,
            RecoveryState.RETRY_UNKNOWN,
            RecoveryState.LEGACY_NOT_REPLAYABLE,
        }
        # No overlap
        assert CLOSED_RETRY_LINEAGE_STATES & OPEN_RETRY_LINEAGE_STATES == set()
        # Every retry state is in exactly one set
        assert retry_states == CLOSED_RETRY_LINEAGE_STATES | OPEN_RETRY_LINEAGE_STATES

    def test_projection_per_parent(self):
        """classify_retry_lineages returns one projection per parent."""
        from nodechain.runtime.recovery_classifier import (
            classify_retry_lineages, RetryLineageProjection,
        )

        parents = [
            {"idempotency_key": "se:a", "capsule_status": "available"},
            {"idempotency_key": "se:b", "capsule_status": "legacy_unavailable"},
        ]
        projections = classify_retry_lineages(parents, [], None)
        assert len(projections) == 2
        assert all(isinstance(p, RetryLineageProjection) for p in projections)
        keys = {p.parent_side_effect_key for p in projections}
        assert keys == {"se:a", "se:b"}
        # Parent with no capsule → legacy
        legacy = next(p for p in projections if p.parent_side_effect_key == "se:b")
        from nodechain.runtime.recovery_classifier import RecoveryState
        assert legacy.state is RecoveryState.LEGACY_NOT_REPLAYABLE
        assert legacy.capsule_status == "legacy_unavailable"

    def test_worst_parent_rule(self):
        """One open parent among closed parents → aggregate is open."""
        from nodechain.runtime.recovery_classifier import (
            classify_retry_lineage, RecoveryState,
        )

        # Parent A: completed child (closed). Parent B: no child (open).
        parents = [
            {"idempotency_key": "se:closed", "capsule_status": "available"},
            {"idempotency_key": "se:open", "capsule_status": "available"},
        ]
        children = [
            {"parent_side_effect_key": "se:closed", "retry_ordinal": 1,
             "status": "completed", "idempotency_key": "retry:1",
             "dispatch_attempted_at": None, "claim_expires_at": None},
            # se:open has NO child → pending execution
        ]
        worst = classify_retry_lineage(parents, children, None)
        assert worst is not None
        assert worst.state is RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION

    def test_aggregate_none_for_empty_parents(self):
        """classify_retry_lineage returns None when no retry_authorized parents."""
        from nodechain.runtime.recovery_classifier import classify_retry_lineage
        assert classify_retry_lineage([], [], None) is None

    def test_projection_carries_latest_child_key(self):
        """Projection includes latest_child_key for audit linking."""
        from nodechain.runtime.recovery_classifier import classify_retry_lineages

        parents = [{"idempotency_key": "se:p", "capsule_status": "available"}]
        children = [
            {"parent_side_effect_key": "se:p", "retry_ordinal": 1,
             "status": "completed", "idempotency_key": "retry:first",
             "dispatch_attempted_at": None, "claim_expires_at": None},
            {"parent_side_effect_key": "se:p", "retry_ordinal": 2,
             "status": "failed", "idempotency_key": "retry:second",
             "dispatch_attempted_at": None, "claim_expires_at": None},
        ]
        projections = classify_retry_lineages(parents, children, None)
        assert len(projections) == 1
        # Latest child (highest retry_ordinal) is retry:second
        assert projections[0].latest_child_key == "retry:second"


# ── T9.3 + T9.4: metric store + emitter ─────────────────────────────────


@pytest.fixture
def t9_db(tmp_path):
    """A StateManager DB with T9 tables."""
    return StateManager(db_path=str(tmp_path / "t9.db"))


class TestRecoveryMetricStore:
    """RecoveryMetricStore: strict idempotency + resurrection guard."""

    def _emit(self, store, **overrides):
        """Helper: emit a baseline metric event."""
        from datetime import datetime, timezone
        defaults = dict(
            metric_event_id="rme-1",
            emitted_at=datetime.now(timezone.utc).isoformat(),
            metric_name="retry_outcome_completed",
            metric_kind="count",
            value=1.0,
            run_id="run1",
            retry_attempt_key=None,
            recovery_action_id="act-1",
            labels_json="{}",
            source_event_key="retry:act-1:outcome:completed",
        )
        defaults.update(overrides)
        return store.insert(**defaults)

    def test_insert_and_idempotent_reemit(self, t9_db):
        from nodechain.core.stores import RecoveryMetricStore
        store = RecoveryMetricStore(t9_db.db_path)
        assert self._emit(store) is True         # inserted
        assert self._emit(store) is False        # identical → idempotent no-op

    def test_conflict_on_different_payload(self, t9_db):
        from nodechain.core.stores import RecoveryMetricStore
        store = RecoveryMetricStore(t9_db.db_path)
        self._emit(store, value=1.0)
        # Same source_event_key, different value → conflict
        with pytest.raises(RecoveryMetricStore.MetricSourceKeyConflict):
            self._emit(store, value=99.0)

    def test_resurrection_guard_after_purge(self, t9_db):
        """A run with a tombstone cannot receive new metrics."""
        from nodechain.core.stores import RecoveryMetricStore
        import sqlite3
        from datetime import datetime, timezone
        store = RecoveryMetricStore(t9_db.db_path)
        # Insert a tombstone manually (delete_run will do this in T9.5)
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(t9_db.db_path) as conn:
            conn.execute(
                "INSERT INTO run_purge_audit (purge_id, run_id, actor_identity, "
                "reason, requested_at, completed_at, key_purged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("p1", "run1", "operator", "cleanup", now, now, 1),
            )
            conn.commit()
        with pytest.raises(RecoveryMetricStore.MetricRunPurged):
            self._emit(store, run_id="run1")

    def test_no_run_id_bypasses_resurrection_guard(self, t9_db):
        """A metric without run_id is not subject to the purge guard."""
        from nodechain.core.stores import RecoveryMetricStore
        store = RecoveryMetricStore(t9_db.db_path)
        # No tombstone, no run_id — should insert fine
        assert self._emit(store, run_id=None,
                          source_event_key="retry:act-2:outcome:completed") is True


class TestRecoveryMetricsEmitter:
    """Emitter validation: allowlist, label bounding, canonicalization."""

    def _emitter(self, t9_db):
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        return RecoveryMetricsEmitter(RecoveryMetricStore(t9_db.db_path))

    def test_unknown_metric_name_rejected(self, t9_db):
        em = self._emitter(t9_db)
        with pytest.raises(ValueError, match="unknown metric name"):
            em.emit(metric_name="not_a_real_metric",
                    source_event_key="retry:x:y")

    def test_disallowed_label_key_rejected(self, t9_db):
        em = self._emitter(t9_db)
        with pytest.raises(ValueError, match="label key"):
            em.emit(metric_name="retry_outcome_completed",
                    source_event_key="retry:x:y",
                    labels={"free_text_field": "evil"})

    def test_outcome_label_must_be_finite(self, t9_db):
        em = self._emitter(t9_db)
        with pytest.raises(ValueError, match="outcome label"):
            em.emit(metric_name="retry_outcome_completed",
                    source_event_key="retry:x:y",
                    labels={"outcome": "bogus"})

    def test_labels_canonicalized_sorted(self, t9_db):
        """Label JSON is sorted-keys canonical, regardless of input order."""
        from nodechain.core.stores import RecoveryMetricStore
        import sqlite3, json
        em = self._emitter(t9_db)
        em.emit(metric_name="retry_outcome_completed",
                source_event_key="retry:x:y",
                labels={"adapter_id": "a", "side_effect_type": "b"})
        with sqlite3.connect(t9_db.db_path) as conn:
            row = conn.execute(
                "SELECT labels_json FROM recovery_metric_events").fetchone()
        labels = json.loads(row[0])
        # Canonical: sorted keys, fixed separators
        assert json.dumps(labels, sort_keys=True, separators=(",", ":")) == row[0]

    def test_failure_isolated_swallows_errors(self, t9_db):
        """failure_isolated never raises — metrics never break execution."""
        em = self._emitter(t9_db)
        # Invalid metric name → would raise, but failure_isolated swallows it
        em.failure_isolated(metric_name="bogus", source_event_key="x")
        # Unknown name → also swallowed
        em.failure_isolated(metric_name="also_bogus", source_event_key="y")


# ── T9.5: RunDeletionService — gates + locked purge ─────────────────────


def _save_run(t9_db, run_id, status):
    """Helper: save a chain state with a given status."""
    cs = ChainState(run_id=run_id, chain_id="c", revision=0, status=status, step=1)
    t9_db.save(cs)


class TestRunDeletionGate:
    """Deletion assessment: three independent gates."""

    def test_unknown_run_blocked(self, t9_db):
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, RUN_NOT_FOUND,
        )
        svc = RunDeletionService(t9_db.db_path)
        assessment = svc.can_delete("nonexistent")
        assert assessment.allowed is False
        assert RUN_NOT_FOUND in assessment.blocking_reasons
        assert assessment.run_exists is False

    def test_running_run_blocked_non_terminal(self, t9_db):
        """A running run with no retry lineage is NOT deletable on empty lineage."""
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, RUN_DELETION_BLOCKED_NON_TERMINAL,
        )
        _save_run(t9_db, "r1", "running")
        svc = RunDeletionService(t9_db.db_path)
        assessment = svc.can_delete("r1")
        assert assessment.allowed is False
        assert RUN_DELETION_BLOCKED_NON_TERMINAL in assessment.blocking_reasons
        # Lineage is vacuously closed (no retry parents) but deletion still blocked
        assert assessment.retry_lineage_closed is True

    def test_terminal_run_no_lineage_allowed(self, t9_db):
        """Completed run with no retry lineage → deletable."""
        from nodechain.runtime.run_deletion_service import RunDeletionService
        _save_run(t9_db, "r1", "completed")
        svc = RunDeletionService(t9_db.db_path)
        assessment = svc.can_delete("r1")
        assert assessment.allowed is True
        assert assessment.run_terminal is True

    def test_open_lineage_blocks(self, t9_db):
        """retry_authorized parent with no child → open lineage → blocked."""
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, RUN_DELETION_BLOCKED_OPEN_LINEAGE,
        )
        import sqlite3
        _save_run(t9_db, "r1", "completed")
        t9_db.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:a",
            status="retry_authorized", request_hash="rh",
        )
        # Mark capsule available so it's not classified as legacy
        with sqlite3.connect(t9_db.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status = 'available' "
                "WHERE run_id = ? AND idempotency_key = ?",
                ("r1", "se:a"),
            )
            conn.commit()
        svc = RunDeletionService(t9_db.db_path)
        assessment = svc.can_delete("r1")
        assert assessment.allowed is False
        assert RUN_DELETION_BLOCKED_OPEN_LINEAGE in assessment.blocking_reasons

    def test_legacy_lineage_closed_with_warning(self, t9_db):
        """Legacy (no capsule) parent → closed + warning, NOT blocked."""
        from nodechain.runtime.run_deletion_service import RunDeletionService
        _save_run(t9_db, "r1", "completed")
        t9_db.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        svc = RunDeletionService(t9_db.db_path)
        assessment = svc.can_delete("r1")
        assert assessment.allowed is True
        assert assessment.legacy_not_replayable_count == 1
        assert any("legacy" in w for w in assessment.warnings)


class TestRunPurge:
    """delete_run(): locked transaction + tombstone + key invalidation."""

    def test_delete_clears_all_tables_and_inserts_tombstone(self, t9_db):
        from nodechain.runtime.run_deletion_service import RunDeletionService
        _save_run(t9_db, "r1", "completed")
        t9_db.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        svc = RunDeletionService(t9_db.db_path)
        record = svc.delete_run("r1", actor_identity="operator", reason="cleanup")

        # Chain state gone
        assert t9_db.load("r1") is None
        # Side effects gone
        assert t9_db.get_side_effects("r1") == []
        # Tombstone present
        import sqlite3
        with sqlite3.connect(t9_db.db_path) as conn:
            row = conn.execute(
                "SELECT run_id, actor_identity, reason, key_purged, "
                "deleted_row_counts_json FROM run_purge_audit WHERE run_id = ?",
                ("r1",),
            ).fetchone()
        assert row is not None
        assert row[0] == "r1"
        assert row[1] == "operator"
        assert row[2] == "cleanup"
        assert row[3] == 0  # no key existed for this run
        import json
        counts = json.loads(row[4])
        assert counts["chain_states"] == 1
        assert counts["side_effect_ledger"] == 1

    def test_delete_blocked_raises_and_preserves_data(self, t9_db):
        """Open lineage → DeletionBlocked raised, data untouched."""
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, DeletionBlocked,
        )
        import sqlite3
        _save_run(t9_db, "r1", "completed")
        t9_db.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:a",
            status="retry_authorized", request_hash="rh",
        )
        with sqlite3.connect(t9_db.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status = 'available' "
                "WHERE run_id = ? AND idempotency_key = ?",
                ("r1", "se:a"),
            )
            conn.commit()
        svc = RunDeletionService(t9_db.db_path)
        with pytest.raises(DeletionBlocked):
            svc.delete_run("r1", actor_identity="op", reason="r")
        # Data preserved — run still exists
        assert t9_db.load("r1") is not None

    def test_key_invalidated_not_hard_deleted(self, tmp_path, kek):
        """Key row survives as tombstone with cleared material (X'')."""
        from nodechain.runtime.run_deletion_service import RunDeletionService
        import sqlite3
        db_path = str(tmp_path / "keytest.db")
        sm = StateManager(db_path=db_path)
        _save_run(sm, "r1", "completed")
        # Create a run key
        sm._run_key_store.get_or_create_run_dek("r1", kek)
        svc = RunDeletionService(db_path)
        svc.delete_run("r1", actor_identity="op", reason="done")
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT encrypted_dek, nonce, purged_at FROM run_encryption_keys "
                "WHERE run_id = ?", ("r1",),
            ).fetchone()
        assert row is not None              # tombstone survives
        assert row[0] == b""                # encrypted_dek cleared (X'')
        assert row[1] == b""                # nonce cleared (X'')
        assert row[2] is not None           # purged_at set

    def test_requires_actor_and_reason(self, t9_db):
        from nodechain.runtime.run_deletion_service import RunDeletionService
        _save_run(t9_db, "r1", "completed")
        svc = RunDeletionService(t9_db.db_path)
        with pytest.raises(ValueError, match="actor_identity"):
            svc.delete_run("r1", actor_identity="", reason="ok")
        with pytest.raises(ValueError, match="reason"):
            svc.delete_run("r1", actor_identity="op", reason="")

    def test_existing_delete_unchanged_narrow(self, t9_db):
        """StateManager.delete() still only clears chain_states (no widening)."""
        _save_run(t9_db, "r1", "completed")
        t9_db.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        t9_db.delete("r1")  # narrow delete — chain_states only
        assert t9_db.load("r1") is None
        # Side effects SURVIVE the narrow delete (only full purge clears them)
        assert len(t9_db.get_side_effects("r1")) == 1


# ── T9.11: Producer integration tests ────────────────────────────────────


@pytest.fixture
def setup_retry_with_metrics(tmp_path, kek):
    """Set up a retry_authorized parent + coordinator with a metrics emitter."""
    db_path = str(tmp_path / "t9int.db")
    trace_dir = str(tmp_path / "traces")
    sm = StateManager(db_path=db_path)
    run_id = "r1"
    parent_key = "semantic_scholar:abc123"

    sm.start_side_effect_with_capsule(
        run_id=run_id, step_id=1, node_id="search_tool",
        side_effect_type="external_call",
        idempotency_key=parent_key,
        request_hash="abc123",
        capsule_operation={"terms": ["ai"], "max": 10, "filters": {}},
        operation_name="search",
        adapter_id="semantic_scholar", adapter_version="1.0.0",
        node_version="1.0", contract_id="c", contract_version="1",
        kek=kek,
    )
    sm.update_side_effect_status(run_id, parent_key, "unknown")
    sm.resolve_side_effect_recovery_decision(
        run_id=run_id, idempotency_key=parent_key,
        decision="safe_to_retry", reason="test",
    )
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT decision_id FROM side_effect_recovery_decisions "
            "WHERE run_id=? AND idempotency_key=?", (run_id, parent_key),
        ).fetchone()
    decision_id = row[0]
    cs = ChainState(run_id=run_id, chain_id="c1", revision=0, status="crashed",
                    step=1, current_node="search_tool")
    sm.save(cs)

    from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
    from nodechain.core.stores import RecoveryMetricStore
    emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))

    return db_path, trace_dir, run_id, parent_key, decision_id, kek, sm, emitter


class TestCoordinatorMetricsEmission:
    """Coordinator emits lifecycle + authoritative outcome metrics."""

    def test_completed_retry_emits_outcome_metrics(self, setup_retry_with_metrics):
        """A completed retry emits retry_outcome_completed + claim + latency."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        result = coord.execute_authorized_retry(
            run_id, parent_key, decision_id,
            operator_action_id="oal-1",
        )
        assert result.child_status == "completed"

        # Verify metrics emitted
        events = emitter._store.query_recent(run_id=run_id)
        names = {e["metric_name"] for e in events}
        assert "retry_claim_acquired" in names
        assert "retry_dispatch_boundary_crossed_total" in names
        assert "retry_outcome_completed" in names
        assert "retry_attempt_latency_ms" in names

    def test_no_operation_metric_on_convergence(self, setup_retry_with_metrics):
        """A second call on an already-completed child emits no-operation."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        # First call completes
        coord.execute_authorized_retry(run_id, parent_key, decision_id)
        # Second call converges (child already exists)
        coord.execute_authorized_retry(run_id, parent_key, decision_id)

        events = emitter._store.query_recent(
            metric_name="retry_no_operation_total", run_id=run_id,
        )
        assert len(events) == 1  # exactly one no-operation

    def test_metrics_failure_does_not_break_execution(self, setup_retry_with_metrics):
        """A broken emitter never changes the retry result."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics

        # Break the emitter's store so emit raises
        emitter._store.db_path = "/nonexistent/path/db.db"

        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        # Retry must still complete despite broken metrics
        result = coord.execute_authorized_retry(run_id, parent_key, decision_id)
        assert result.child_status == "completed"


class TestPolicyDenialMetrics:
    """RecoveryService emits policy_denied on governed refusal."""

    def test_policy_denial_emits_metrics(self, setup_retry_with_metrics):
        """A non-operator role triggers policy denial + emits metrics."""
        from nodechain.runtime.recovery_service import RecoveryService
        from nodechain.runtime.recovery_policy import RecoveryAction

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
        service.set_metrics_emitter(emitter)

        result = service.apply_action(
            run_id, RecoveryAction.EXECUTE_RETRY_AUTHORIZED,
            operator_identity="viewer", operator_role="viewer",
            side_effect_key=parent_key, recovery_decision_id=decision_id,
        )
        assert result.admitted is False  # viewer role denied

        events = emitter._store.query_recent(
            metric_name="retry_policy_denied_total", run_id=run_id,
        )
        assert len(events) == 1
        rejected_events = emitter._store.query_recent(
            metric_name="retry_rejected_total", run_id=run_id,
        )
        assert len(rejected_events) == 1


class TestDashboardMetricsRendering:
    """Dashboard collector aggregates metrics correctly."""

    def test_empty_metrics_table_returns_n_a_success_rate(self, tmp_path):
        """No samples → success_rate is None (rendered as 'n/a')."""
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        # Point to a nonexistent DB — collector must fail-soft
        import os
        os.environ["NODECHAIN_DB_PATH"] = str(tmp_path / "nonexistent.db")
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        assert result["success_rate"] is None
        assert result["samples"] == 0

    def test_metrics_aggregation(self, setup_retry_with_metrics):
        """After a completed retry, dashboard shows the outcome."""
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter
        import os

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        coord.execute_authorized_retry(run_id, parent_key, decision_id)

        os.environ["NODECHAIN_DB_PATH"] = db_path
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        assert result["outcomes"]["completed"] == 1
        assert result["success_rate"] == 1.0
        assert result["samples"] == 1


class TestPostPurgeResurrectionGuard:
    """Metrics cannot be re-emitted for a purged run."""

    def test_metric_rejected_after_purge(self, setup_retry_with_metrics):
        """After delete_run, a late metric emission is rejected."""
        from nodechain.runtime.run_deletion_service import RunDeletionService
        from nodechain.core.stores import RecoveryMetricStore
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        # Execute the retry to create a completed child (closes the lineage)
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        coord.execute_authorized_retry(run_id, parent_key, decision_id)
        # Terminalize the run so it's deletable
        state = sm.load(run_id)
        state.status = "completed"
        sm.save(state)
        svc = RunDeletionService(db_path)
        svc.delete_run(run_id, actor_identity="op", reason="cleanup")

        # A late metric emission for the purged run must be rejected
        store = RecoveryMetricStore(db_path)
        from datetime import datetime, timezone
        with pytest.raises(RecoveryMetricStore.MetricRunPurged):
            store.insert(
                metric_event_id="late-1",
                emitted_at=datetime.now(timezone.utc).isoformat(),
                metric_name="retry_outcome_completed",
                metric_kind="count", value=1.0,
                run_id=run_id, retry_attempt_key=None,
                recovery_action_id=None, labels_json="{}",
                source_event_key="retry:late:outcome",
            )


# ── T9 re-review: blocker fixes + hardening ─────────────────────────────


class TestFailClosedDeletion:
    """Blocker 1: unclassified lineage states must block deletion."""

    def test_unclassified_state_blocks_deletion(self, t9_db):
        """A projection with a state in NEITHER CLOSED nor OPEN set blocks.

        We can't easily produce an unclassified state from the real classifier
        (all six states are partitioned), so we monkeypatch the partition to
        remove one state from both sets, then verify the gate blocks.
        """
        from nodechain.runtime import run_deletion_service as rds_mod
        from nodechain.runtime.recovery_classifier import RecoveryState
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, RUN_DELETION_BLOCKED_UNCLASSIFIED_LINEAGE,
        )
        import sqlite3

        _save_run(t9_db, "r1", "completed")
        t9_db.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:a",
            status="retry_authorized", request_hash="rh",
        )
        with sqlite3.connect(t9_db.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available' "
                "WHERE run_id='r1' AND idempotency_key='se:a'")
            conn.commit()

        # Temporarily remove RETRY_AUTHORIZED_PENDING_EXECUTION from both sets.
        # The parent (no child) classifies to this state → it becomes unclassified.
        orig_closed = rds_mod.CLOSED_RETRY_LINEAGE_STATES
        orig_open = rds_mod.OPEN_RETRY_LINEAGE_STATES
        rds_mod.CLOSED_RETRY_LINEAGE_STATES = orig_closed  # unchanged
        rds_mod.OPEN_RETRY_LINEAGE_STATES = frozenset(
            s for s in orig_open
            if s != RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION
        )
        try:
            svc = RunDeletionService(t9_db.db_path)
            assessment = svc.can_delete("r1")
            assert assessment.allowed is False
            assert RUN_DELETION_BLOCKED_UNCLASSIFIED_LINEAGE in assessment.blocking_reasons
        finally:
            rds_mod.OPEN_RETRY_LINEAGE_STATES = orig_open


class TestNearestRankPercentile:
    """Blocker 2: nearest-rank uses ceil(p*n)-1, not int(p*n)-1."""

    def test_percentile_small_samples(self):
        """Verify ceil-based indexing for n=2 and n=3."""
        from math import ceil

        # n=3: p50 → rank ceil(0.5*3)=2 → index 1; p95 → rank ceil(0.95*3)=3 → index 2
        vals3 = [10.0, 20.0, 30.0]
        assert vals3[ceil(0.50 * 3) - 1] == 20.0
        assert vals3[ceil(0.95 * 3) - 1] == 30.0

        # n=2: p50 → rank ceil(0.5*2)=1 → index 0; p95 → rank ceil(0.95*2)=2 → index 1
        vals2 = [10.0, 20.0]
        assert vals2[ceil(0.50 * 2) - 1] == 10.0
        assert vals2[ceil(0.95 * 2) - 1] == 20.0

    def test_collector_percentiles_correct(self, tmp_path):
        """End-to-end: emit 3 latency values, verify p50 selects rank 2."""
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os

        db_path = str(tmp_path / "pct.db")
        StateManager(db_path=db_path)  # init schema
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))
        for v in [10.0, 20.0, 30.0]:
            emitter.emit(
                metric_name="retry_command_latency_ms",
                value=v, run_id="r1",
                source_event_key=f"retry:r1:cmd:{v}",
            )
        os.environ["NODECHAIN_DB_PATH"] = db_path
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        lat = result["latencies"]["retry_command_latency_ms"]
        assert lat["count"] == 3
        assert lat["p50"] == 20.0   # ceil(0.5*3)=2 → index 1 → 20.0
        assert lat["p95"] == 30.0   # ceil(0.95*3)=3 → index 2 → 30.0


class TestAdapterTop20:
    """Blocker 3: adapter top-20 aggregation with deterministic ordering."""

    def test_adapter_aggregation_count_desc_id_asc(self, tmp_path):
        """Adapters sorted by count DESC, adapter_id ASC for ties."""
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os

        db_path = str(tmp_path / "adapt.db")
        StateManager(db_path=db_path)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))
        # adapter "zebra": 3 completions; adapter "alpha": 3 completions (tie);
        # adapter "mid": 1 completion
        for _ in range(3):
            emitter.emit(metric_name="retry_outcome_completed", run_id="r1",
                         source_event_key=f"retry:r1:z:{_}",
                         labels={"adapter_id": "zebra"})
        for _ in range(3):
            emitter.emit(metric_name="retry_outcome_completed", run_id="r1",
                         source_event_key=f"retry:r1:a:{_}",
                         labels={"adapter_id": "alpha"})
        emitter.emit(metric_name="retry_outcome_completed", run_id="r1",
                     source_event_key="retry:r1:m:0",
                     labels={"adapter_id": "mid"})

        os.environ["NODECHAIN_DB_PATH"] = db_path
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        top = result["adapter_top20"]
        assert len(top) == 3
        # alpha and zebra both have count 3 — tie broken by adapter_id ASC
        assert top[0] == {"adapter_id": "alpha", "count": 3}
        assert top[1] == {"adapter_id": "zebra", "count": 3}
        assert top[2] == {"adapter_id": "mid", "count": 1}

    def test_top20_truncation(self, tmp_path):
        """More than 20 adapters → top 20 + 'other' bucket = 21 entries."""
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os

        db_path = str(tmp_path / "trunc.db")
        StateManager(db_path=db_path)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))
        for i in range(25):
            emitter.emit(metric_name="retry_outcome_completed", run_id="r1",
                         source_event_key=f"retry:r1:a{i}",
                         labels={"adapter_id": f"adapter_{i:02d}"})
        os.environ["NODECHAIN_DB_PATH"] = db_path
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        top = result["adapter_top20"]
        # 20 named adapters + 1 "other" bucket
        assert len(top) == 21
        other = [a for a in top if a["adapter_id"] == "other"]
        assert len(other) == 1
        assert other[0]["count"] == 5  # 25 - 20 = 5 in "other"


class TestNaNRejection:
    """Hardening: NaN and infinity must be rejected."""

    def test_nan_rejected(self, t9_db):
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        em = RecoveryMetricsEmitter(RecoveryMetricStore(t9_db.db_path))
        with pytest.raises(ValueError, match="finite"):
            em.emit(metric_name="retry_outcome_completed",
                    value=float("nan"),
                    source_event_key="retry:x:nan")

    def test_infinity_rejected(self, t9_db):
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        em = RecoveryMetricsEmitter(RecoveryMetricStore(t9_db.db_path))
        with pytest.raises(ValueError, match="finite"):
            em.emit(metric_name="retry_attempt_latency_ms",
                    value=float("inf"),
                    source_event_key="retry:x:inf")


class TestSourceKeyConflictVariants:
    """Hardening: conflict detection across all payload fields, not just value."""

    def test_conflict_on_different_run_id(self, t9_db):
        from nodechain.core.stores import RecoveryMetricStore
        from datetime import datetime, timezone
        store = RecoveryMetricStore(t9_db.db_path)
        now = datetime.now(timezone.utc).isoformat()
        store.insert(metric_event_id="rme-1", emitted_at=now,
                     metric_name="retry_outcome_completed", metric_kind="count",
                     value=1.0, run_id="run_a", retry_attempt_key=None,
                     recovery_action_id=None, labels_json="{}",
                     source_event_key="retry:act:outcome")
        with pytest.raises(RecoveryMetricStore.MetricSourceKeyConflict):
            store.insert(metric_event_id="rme-2", emitted_at=now,
                         metric_name="retry_outcome_completed", metric_kind="count",
                         value=1.0, run_id="run_b", retry_attempt_key=None,
                         recovery_action_id=None, labels_json="{}",
                         source_event_key="retry:act:outcome")

    def test_conflict_on_different_labels(self, t9_db):
        from nodechain.core.stores import RecoveryMetricStore
        from datetime import datetime, timezone
        store = RecoveryMetricStore(t9_db.db_path)
        now = datetime.now(timezone.utc).isoformat()
        store.insert(metric_event_id="rme-1", emitted_at=now,
                     metric_name="retry_outcome_completed", metric_kind="count",
                     value=1.0, run_id="r1", retry_attempt_key=None,
                     recovery_action_id=None,
                     labels_json='{"adapter_id":"a"}',
                     source_event_key="retry:act:outcome")
        with pytest.raises(RecoveryMetricStore.MetricSourceKeyConflict):
            store.insert(metric_event_id="rme-2", emitted_at=now,
                         metric_name="retry_outcome_completed", metric_kind="count",
                         value=1.0, run_id="r1", retry_attempt_key=None,
                         recovery_action_id=None,
                         labels_json='{"adapter_id":"b"}',
                         source_event_key="retry:act:outcome")


class TestCollectorSchemaConsistency:
    """Hardening: all collector return paths have identical schema."""

    def test_missing_db_schema_has_all_keys(self, tmp_path):
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os
        os.environ["NODECHAIN_DB_PATH"] = str(tmp_path / "nope.db")
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        expected_keys = {"outcomes", "total_outcomes", "success_rate",
                         "rejections", "latencies", "adapter_top20", "samples"}
        assert set(result.keys()) == expected_keys
        assert result["adapter_top20"] == []

    def test_empty_db_schema_has_all_keys(self, t9_db):
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os
        os.environ["NODECHAIN_DB_PATH"] = str(t9_db.db_path)
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        expected_keys = {"outcomes", "total_outcomes", "success_rate",
                         "rejections", "latencies", "adapter_top20", "samples"}
        assert set(result.keys()) == expected_keys
        assert result["adapter_top20"] == []


class TestRollbackBehavior:
    """Fault-injection: rollback restores all data on purge failure."""

    def test_tombstone_failure_rolls_back_purge(self, tmp_path, kek):
        """If tombstone insertion fails, all deleted rows are restored."""
        from nodechain.runtime.run_deletion_service import RunDeletionService
        import sqlite3

        db_path = str(tmp_path / "rb.db")
        sm = StateManager(db_path=db_path)
        _save_run(sm, "r1", "completed")
        sm.record_side_effect(run_id="r1", step_id=1, node_id="n",
                              side_effect_type="external_call",
                              idempotency_key="se:1", status="completed",
                              request_hash="rh")
        # Pre-insert a tombstone so the UNIQUE(run_id) constraint will fail
        # when delete_run tries to insert a second one.
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO run_purge_audit (purge_id, run_id, actor_identity, "
                "reason, requested_at, completed_at, key_purged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("pre-existing", "r1", "someone", "earlier", now, now, 0),
            )
            conn.commit()

        svc = RunDeletionService(db_path)
        # The second tombstone insert will violate UNIQUE(run_id) → rollback
        with pytest.raises(Exception):
            svc.delete_run("r1", actor_identity="op", reason="cleanup")

        # Data must be restored — run still exists, side effect still exists
        assert sm.load("r1") is not None
        assert len(sm.get_side_effects("r1")) == 1


class TestDashboardHealthNonDegradation:
    """Metrics section must not degrade overall dashboard health."""

    def test_empty_metrics_does_not_affect_health(self, tmp_path):
        from nodechain.cli.dashboard import collect_dashboard
        import os
        os.environ["NODECHAIN_DB_PATH"] = str(tmp_path / "empty.db")
        try:
            dashboard = collect_dashboard()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        # recovery_metrics section exists but is empty
        assert "recovery_metrics" in dashboard["sections"]
        # Overall health is not critical/degraded due to metrics (lowercase)
        assert dashboard["overall_health"] not in ("critical", "degraded")


# ── T9 2nd re-review: end-to-end lifecycle wiring tests ─────────────────


class TestEndToEndLifecycleMetrics:
    """Verify every declared producer metric fires at its authoritative point."""

    def test_completed_retry_emits_full_lifecycle(self, setup_retry_with_metrics):
        """A completed retry emits: attempt_created, claim_acquired, boundary,
        outcome_completed, command_latency, attempt_latency."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        coord.execute_authorized_retry(
            run_id, parent_key, decision_id, operator_action_id="oal-life",
        )
        names = {e["metric_name"] for e in emitter._store.query_recent(run_id=run_id)}
        # All lifecycle metrics must be present
        assert "retry_attempt_created" in names
        assert "retry_claim_acquired" in names
        assert "retry_dispatch_boundary_crossed_total" in names
        assert "retry_outcome_completed" in names
        assert "retry_command_latency_ms" in names
        assert "retry_attempt_latency_ms" in names

    def test_coordinator_outcome_includes_adapter_id(self, setup_retry_with_metrics):
        """Real coordinator outcome metrics carry adapter_id for the dashboard."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter
        import json

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        coord.execute_authorized_retry(run_id, parent_key, decision_id)
        outcome_events = emitter._store.query_recent(
            metric_name="retry_outcome_completed", run_id=run_id,
        )
        assert len(outcome_events) == 1
        labels = json.loads(outcome_events[0]["labels_json"])
        assert labels.get("adapter_id") == "semantic_scholar"

    def test_coordinator_execution_appears_in_adapter_top20(
        self, setup_retry_with_metrics,
    ):
        """End-to-end: actual coordinator retry → dashboard adapter_top20."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os

        (db_path, trace_dir, run_id, parent_key, decision_id,
         kek, sm, emitter) = setup_retry_with_metrics
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
            metrics_emitter=emitter,
        )
        coord.execute_authorized_retry(run_id, parent_key, decision_id)

        os.environ["NODECHAIN_DB_PATH"] = db_path
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        top = result["adapter_top20"]
        assert len(top) >= 1
        assert any(a["adapter_id"] == "semantic_scholar" for a in top)

    def test_material_unavailable_emitted_on_legacy_row(self, tmp_path, kek):
        """A legacy (no capsule) parent emits material_unavailable + legacy_ineligible."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator, RetryExecutionError,
        )
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore

        db_path = str(tmp_path / "legacy.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: None,
            metrics_emitter=emitter,
        )
        with pytest.raises(RetryExecutionError):
            coord.execute_authorized_retry("r1", "se:legacy", "fake-decision")
        names = {e["metric_name"] for e in emitter._store.query_recent(run_id="r1")}
        assert "retry_material_unavailable_total" in names
        assert "retry_legacy_ineligible_total" in names


class TestReconciliationRequeueMetric:
    """v3.5.1 (#4): retry_requeued is emitted ONLY by the EXPLICIT mutating
    reconciliation path, never by a read (build_trace_health / build_snapshot).
    """

    def _setup_expired_child(self, db_path, kek):
        """Shared setup: run with an expired-started recovery child."""
        import sqlite3 as _sqlite3
        from datetime import datetime, timezone, timedelta
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:parent",
            status="retry_authorized", request_hash="rh",
        )
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(hours=1)).isoformat()
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="retry:child1",
            status="started", request_hash="rh",
        )
        with _sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available', "
                "parent_side_effect_key='se:parent', "
                "root_side_effect_key='se:parent', retry_ordinal=1, "
                "execution_claim_id='claim-1', claim_expires_at=? "
                "WHERE run_id='r1' AND idempotency_key='retry:child1'",
                (expired,),
            )
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available' "
                "WHERE run_id='r1' AND idempotency_key='se:parent'"
            )
            conn.commit()
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)
        return sm

    def test_read_path_does_not_requeue_or_emit_metric(self, tmp_path, kek):
        """v3.5.1 (#4): build_trace_health must NOT requeue or emit a metric.

        The read reports the expired child via a repair-required warning but
        leaves the child at 'started' and emits no retry_requeued metric.
        """
        from nodechain.runtime.recovery_service import RecoveryService
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore

        db_path = str(tmp_path / "req.db")
        sm = self._setup_expired_child(db_path, kek)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))

        service = RecoveryService(
            state_manager=sm, trace_dir=str(tmp_path / "traces"),
        )
        service.set_metrics_emitter(emitter)

        service.build_trace_health("r1")

        requeue_events = emitter._store.query_recent(metric_name="retry_requeued")
        assert len(requeue_events) == 0  # read path emits nothing
        # Child must remain started — the read did not repair it.
        child = sm.get_side_effect_by_key("r1", "retry:child1")
        assert child["status"] == "started"

    def test_read_path_reports_repair_required_warning(self, tmp_path, kek):
        """v3.5.1 (#4): the read surfaces a side_effect_retry_repair_required
        warning so the operator knows explicit reconciliation is needed."""
        from nodechain.runtime.recovery_service import RecoveryService

        db_path = str(tmp_path / "warn.db")
        sm = self._setup_expired_child(db_path, kek)
        service = RecoveryService(
            state_manager=sm, trace_dir=str(tmp_path / "traces"),
        )

        report = service.build_trace_health("r1")
        repair_required = [
            i for i in report.issues
            if i.check == "side_effect_retry_repair_required"
        ]
        assert len(repair_required) == 1
        assert repair_required[0].severity == "warning"

    def test_explicit_reconcile_requeues_and_emits_metric(self, tmp_path, kek):
        """v3.5.1 (#4): the explicit mutating reconcile is the metric owner.

        reconcile_expired_recovery_children repairs the child and the caller
        (reconcile command) emits retry_requeued. This pins that the repair
        path survives the purity split.
        """
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore

        db_path = str(tmp_path / "expl.db")
        sm = self._setup_expired_child(db_path, kek)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))

        results = sm.reconcile_expired_recovery_children("r1")
        assert len(results) == 1
        assert results[0]["action"] == "requeued"
        # The explicit owner emits the metric (mirrors reconcile command wiring).
        for rec in results:
            if rec.get("action") == "requeued":
                emitter.failure_isolated(
                    metric_name="retry_requeued",
                    run_id="r1", retry_attempt_key=rec.get("child_key", ""),
                    source_event_key=f"retry:r1:{rec.get('child_key', '')}:requeued",
                )
        requeue_events = emitter._store.query_recent(metric_name="retry_requeued")
        assert len(requeue_events) == 1
        child = sm.get_side_effect_by_key("r1", "retry:child1")
        assert child["status"] == "planned"


# ── T9 4th re-review: build_snapshot ordering + repair failure surfacing ─


class TestBuildSnapshotReconciliationOrdering:
    """v3.5.1 (#4): build_snapshot is PURE — it does not repair.

    The snapshot reflects current durable truth. An expired-started child
    remains 'started' (in-flight) until an EXPLICIT reconcile repairs it.
    The snapshot surfaces the need via a side_effect_retry_repair_required
    warning in trace_warnings.
    """

    def _setup_expired_child(self, db_path, kek):
        import sqlite3 as _sqlite3
        from datetime import datetime, timezone, timedelta
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:parent",
            status="retry_authorized", request_hash="rh",
        )
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(hours=1)).isoformat()
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="retry:child1",
            status="started", request_hash="rh",
        )
        with _sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available', "
                "parent_side_effect_key='se:parent', "
                "root_side_effect_key='se:parent', retry_ordinal=1, "
                "execution_claim_id='claim-1', claim_expires_at=? "
                "WHERE run_id='r1' AND idempotency_key='retry:child1'",
                (expired,),
            )
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available' "
                "WHERE run_id='r1' AND idempotency_key='se:parent'"
            )
            conn.commit()
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)
        return sm

    def test_snapshot_missing_trace_does_not_repair_but_reports_needed(
        self, tmp_path, kek,
    ):
        """v3.5.1 (#4): snapshot leaves child 'started', reports repair needed,
        emits no metric."""
        from nodechain.runtime.recovery_service import RecoveryService
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore

        db_path = str(tmp_path / "snap.db")
        sm = self._setup_expired_child(db_path, kek)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))

        service = RecoveryService(
            state_manager=sm, trace_dir=str(tmp_path / "traces"),
        )
        service.set_metrics_emitter(emitter)

        snapshot = service.build_snapshot("r1")
        assert snapshot is not None

        # Child must REMAIN started — a read does not repair.
        child = sm.get_side_effect_by_key("r1", "retry:child1")
        assert child["status"] == "started"

        # No requeue metric from a read.
        requeue_events = emitter._store.query_recent(metric_name="retry_requeued")
        assert len(requeue_events) == 0

        # The snapshot must surface that repair is required.
        assert any("repair_required" in w or "reconcile" in w.lower()
                   for w in snapshot.trace_warnings)

    def test_snapshot_corrupt_trace_does_not_repair_but_reports_needed(
        self, tmp_path, kek,
    ):
        """v3.5.1 (#4): corrupt-trace path is equally pure."""
        from nodechain.runtime.recovery_service import RecoveryService
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore

        db_path = str(tmp_path / "snap2.db")
        sm = self._setup_expired_child(db_path, kek)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))

        trace_dir = tmp_path / "traces"
        trace_dir.mkdir(parents=True)
        (trace_dir / "r1.json").write_text("{ INVALID JSON }")

        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))
        service.set_metrics_emitter(emitter)

        snapshot = service.build_snapshot("r1")
        assert snapshot is not None
        child = sm.get_side_effect_by_key("r1", "retry:child1")
        assert child["status"] == "started"
        requeue_events = emitter._store.query_recent(metric_name="retry_requeued")
        assert len(requeue_events) == 0


class TestRepairFailureSurfacing:
    """v3.5.1 (#4): detection failures must appear in the report, not silenced.

    The read path now calls scan_expired_recovery_children (pure detection).
    A detection failure surfaces as side_effect_retry_repair_failed.
    """

    def test_repair_failure_surfaces_in_missing_trace_report(self, tmp_path, kek):
        """When scan_expired_recovery_children raises, the error appears in the
        report even on the missing-trace early-return path."""
        from nodechain.runtime.recovery_service import RecoveryService
        from unittest.mock import patch

        db_path = str(tmp_path / "rf.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)

        service = RecoveryService(
            state_manager=sm, trace_dir=str(tmp_path / "traces"),
        )

        # Force the pure detection scan to raise
        with patch.object(
            sm, "scan_expired_recovery_children",
            side_effect=RuntimeError("simulated DB corruption"),
        ):
            report = service.build_trace_health("r1")

        # The report must contain the detection failure
        repair_issues = [
            i for i in report.issues
            if i.check == "side_effect_retry_repair_failed"
        ]
        assert len(repair_issues) == 1
        assert repair_issues[0].severity == "error"
        assert "simulated DB corruption" in repair_issues[0].actual


# ── T9 5th re-review: snapshot error projection + single-owner repair ────


class TestSnapshotErrorProjection:
    """v3.5.1 (#4): detection errors must appear in the snapshot, not dropped."""

    def test_snapshot_contains_repair_error_in_trace_errors(self, tmp_path, kek):
        """build_snapshot with a forced detection failure surfaces the error
        in snapshot.trace_errors."""
        from nodechain.runtime.recovery_service import RecoveryService
        from unittest.mock import patch

        db_path = str(tmp_path / "se.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)
        service = RecoveryService(
            state_manager=sm, trace_dir=str(tmp_path / "traces"),
        )

        with patch.object(
            sm, "scan_expired_recovery_children",
            side_effect=RuntimeError("DB lock contention"),
        ):
            snapshot = service.build_snapshot("r1")

        assert snapshot is not None
        # The detection error must appear in trace_errors
        assert len(snapshot.trace_errors) >= 1
        assert any("DB lock contention" in e for e in snapshot.trace_errors)


class TestSingleOwnerRepair:
    """v3.5.1 (#4): the read path calls scan (detection) once and never calls
    the mutating reconcile. Exactly one detection-failed error surfaces."""

    def test_read_calls_scan_once_and_never_mutating_reconcile(
        self, tmp_path, kek,
    ):
        """With a valid trace, a persistent detection failure produces exactly
        one side_effect_retry_repair_failed issue, and the mutating reconcile
        is never invoked by the read."""
        from nodechain.runtime.recovery_service import RecoveryService
        from datetime import datetime, timezone
        from unittest.mock import patch
        import json

        db_path = str(tmp_path / "so.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="completed", step=1)
        sm.save(cs)

        # Write a valid trace file so the trace-present path is taken
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir(parents=True)
        now = datetime.now(timezone.utc).isoformat()
        trace_data = {
            "trace_id": "t1", "run_id": "r1", "chain_id": "c",
            "started_at": now, "events": [
                {"event_id": "e1", "event_type": "chain_started",
                 "run_id": "r1", "revision": 1, "timestamp": now},
            ],
        }
        (trace_dir / "r1.json").write_text(json.dumps(trace_data))

        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))

        # Force the pure detection scan to ALWAYS fail
        scan_count = [0]
        def failing_scan(run_id):
            scan_count[0] += 1
            raise RuntimeError("persistent DB failure")

        reconcile_called = [False]
        def spy_reconcile(run_id):
            reconcile_called[0] = True
            return []

        with patch.object(sm, "scan_expired_recovery_children", side_effect=failing_scan), \
             patch.object(sm, "reconcile_expired_recovery_children", side_effect=spy_reconcile):
            report = service.build_trace_health("r1")

        # The scan should have been called exactly once.
        assert scan_count[0] == 1
        # The mutating reconcile must NEVER be called by a read.
        assert reconcile_called[0] is False

        # Exactly one detection-failed error
        repair_errors = [
            i for i in report.issues
            if i.check == "side_effect_retry_repair_failed"
        ]
        assert len(repair_errors) == 1
        assert "persistent DB failure" in repair_errors[0].actual


# ── T9 6th re-review: CLI rendering of trace errors ─────────────────────


class TestCLIRenderingOfTraceErrors:
    """trace_errors must be visible in recover inspect AND recover list."""

    def test_inspect_shows_trace_errors(self, tmp_path, capsys):
        """recover inspect renders the repair failure in trace_errors."""
        from nodechain.cli.recover import recover_inspect
        from unittest.mock import patch

        db_path = str(tmp_path / "cli.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="completed", step=1)
        sm.save(cs)

        # Patch at class level — recover_inspect creates its own StateManager.
        # v3.5.1 (#4): the read path calls scan_expired_recovery_children.
        with patch.object(
            StateManager, "scan_expired_recovery_children",
            side_effect=RuntimeError("CLI-visible repair failure"),
        ):
            recover_inspect("r1", db_path, str(tmp_path / "traces"))

        captured = capsys.readouterr()
        # The trace error must appear in the inspect output
        assert "Trace Errors" in captured.out
        assert "CLI-visible repair failure" in captured.out

    def test_list_shows_trace_health_error_for_completed_run(self, tmp_path, capsys):
        """recover list visibly marks a completed run with a trace error.

        The classifier returns COMPLETED before inspecting reconciler errors,
        so the trace health must be independent of recovery_state.
        """
        from nodechain.cli.recover import recover_list
        from unittest.mock import patch
        from rich.console import Console
        import nodechain.cli.recover as rec_mod

        db_path = str(tmp_path / "clist.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="completed", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="completed", step=1)
        sm.save(cs)

        # Use a wide console so the Trace Health column isn't truncated
        orig_console = rec_mod.console
        rec_mod.console = Console(width=300, force_terminal=False)
        try:
            with patch.object(
                StateManager, "scan_expired_recovery_children",
                side_effect=RuntimeError("list-visible failure"),
            ):
                recover_list(db_path, str(tmp_path / "traces"))
        finally:
            rec_mod.console = orig_console

        captured = capsys.readouterr()
        # The list must show a Trace Health column with ERROR
        assert "Trace Health" in captured.out
        assert "ERROR" in captured.out






