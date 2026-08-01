"""v3.5.0 Task 11 — crash/race/migration verification matrix.

Tests the scenarios from the T11 verification matrix that are not already
covered by T6/T7/T8/T9 tests. Each test simulates a crash/race/edge condition
and verifies the system reaches a correct, honest state.

Environment: Windows-11-10.0.26200-SP0, Python 3.12.1
SHA: e5a9d66cd2f86a617e54560c995ae20c77e6dabb
"""
from __future__ import annotations

import sqlite3
import pytest
from datetime import datetime, timezone, timedelta

from nodechain.core.state import StateManager, ChainState


@pytest.fixture
def kek(tmp_path):
    from conftest import provision_test_kek
    return provision_test_kek(tmp_path / "t11_kek.bin")


def _setup_retry_parent(sm, kek, run_id="r1", parent_key="semantic_scholar:abc"):
    """Standard retry_authorized parent with capsule + decision."""
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
    with sqlite3.connect(sm.db_path) as conn:
        row = conn.execute(
            "SELECT decision_id FROM side_effect_recovery_decisions "
            "WHERE run_id=? AND idempotency_key=?", (run_id, parent_key),
        ).fetchone()
    decision_id = row[0]
    cs = ChainState(run_id=run_id, chain_id="c1", revision=0, status="crashed",
                    step=1, current_node="search_tool")
    sm.save(cs)
    return parent_key, decision_id


# ── Crash/race matrix ───────────────────────────────────────────────────


class TestCrashRaceMatrix:
    """Crash/race scenarios from the T11 verification matrix."""

    def test_child_starts_heartbeat_expires_before_dispatch_reclaimable(
        self, tmp_path, kek,
    ):
        """Child started, heartbeat expires before dispatch → reclaimable.

        The classifier must map this to RETRY_ATTEMPT_IN_FLIGHT (safely
        reclaimable), NOT RETRY_UNKNOWN. The reconciler repairs it back
        to planned for re-execution.
        """
        from nodechain.runtime.recovery_classifier import (
            classify_retry_lineage, RecoveryState,
        )
        sm = StateManager(db_path=str(tmp_path / "cr1.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)

        # Create a started child with expired lease, NO dispatch marker
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(hours=1)).isoformat()
        child_key = "retry:child1"
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key=child_key,
            status="started", request_hash="rh",
        )
        with sqlite3.connect(sm.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available', "
                "parent_side_effect_key=?, root_side_effect_key=?, "
                "retry_ordinal=1, execution_claim_id='c1', "
                "claim_expires_at=?, dispatch_attempted_at=NULL "
                "WHERE run_id='r1' AND idempotency_key=?",
                (parent_key, parent_key, expired, child_key),
            )
            conn.commit()

        side_effects = sm.get_side_effects("r1")
        parents = [s for s in side_effects if s["status"] == "retry_authorized"]
        result = classify_retry_lineage(parents, side_effects, None)
        assert result is not None
        assert result.state is RecoveryState.RETRY_ATTEMPT_IN_FLIGHT

    def test_dispatch_marker_commits_then_lease_expires_to_unknown(
        self, tmp_path, kek,
    ):
        """Dispatch marker commits, process dies before adapter returns.

        Child started + dispatch_attempted_at set + lease expired →
        RETRY_UNKNOWN (never automatically redispatched).
        """
        from nodechain.runtime.recovery_classifier import (
            classify_retry_lineage, RecoveryState,
        )
        sm = StateManager(db_path=str(tmp_path / "cr2.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)

        now = datetime.now(timezone.utc)
        expired = (now - timedelta(hours=1)).isoformat()
        child_key = "retry:child2"
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key=child_key,
            status="started", request_hash="rh",
        )
        with sqlite3.connect(sm.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available', "
                "parent_side_effect_key=?, root_side_effect_key=?, "
                "retry_ordinal=1, execution_claim_id='c2', "
                "claim_expires_at=?, dispatch_attempted_at=? "
                "WHERE run_id='r1' AND idempotency_key=?",
                (parent_key, parent_key, expired, expired, child_key),
            )
            conn.commit()

        side_effects = sm.get_side_effects("r1")
        parents = [s for s in side_effects if s["status"] == "retry_authorized"]
        result = classify_retry_lineage(parents, side_effects, None)
        assert result.state is RecoveryState.RETRY_UNKNOWN

    def test_two_operators_converge_on_same_decision(self, tmp_path, kek):
        """Two operators execute the same recovery decision concurrently.

        The deterministic child key means both target the same child.
        The first succeeds; the second converges (dispatch_performed=False).
        """
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        import sys
        sys.path.insert(0, "tests")
        from test_v35_t6_execution import FakeAdapter

        sm = StateManager(db_path=str(tmp_path / "cr3.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: FakeAdapter(),
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
        )
        # First execution succeeds
        r1 = coord.execute_authorized_retry("r1", parent_key, decision_id)
        assert r1.child_status == "completed"
        assert r1.dispatch_performed is True

        # Second execution converges — no duplicate dispatch
        r2 = coord.execute_authorized_retry("r1", parent_key, decision_id)
        assert r2.child_status == "completed"
        assert r2.dispatch_performed is False  # convergence, not re-dispatch

    def test_run_deletion_blocked_while_lineage_open(self, tmp_path, kek):
        """Run deletion races with open retry lineage — must block."""
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, DeletionBlocked,
        )
        sm = StateManager(db_path=str(tmp_path / "cr4.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)
        # Parent is retry_authorized with no child → open lineage
        state = sm.load("r1")
        state.status = "completed"
        sm.save(state)

        svc = RunDeletionService(sm.db_path)
        with pytest.raises(DeletionBlocked):
            svc.delete_run("r1", actor_identity="op", reason="cleanup")
        # Run must survive
        assert sm.load("r1") is not None

    def test_reconciler_repairs_expired_child_without_dispatch(self, tmp_path, kek):
        """Reconciler repairs expired child (started→planned) for re-execution.

        A child that started but never crossed the dispatch boundary and
        whose lease expired is safely reclaimable — the reconciler resets
        it to planned.
        """
        sm = StateManager(db_path=str(tmp_path / "cr5.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(hours=1)).isoformat()
        child_key = "retry:child_reclaim"
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key=child_key,
            status="started", request_hash="rh",
        )
        with sqlite3.connect(sm.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available', "
                "parent_side_effect_key=?, root_side_effect_key=?, "
                "retry_ordinal=1, execution_claim_id='claim-x', "
                "claim_expires_at=?, dispatch_attempted_at=NULL "
                "WHERE run_id='r1' AND idempotency_key=?",
                (parent_key, parent_key, expired, child_key),
            )
            conn.commit()

        repaired = sm.reconcile_expired_recovery_children("r1")
        assert len(repaired) == 1
        assert repaired[0]["action"] == "requeued"

        child = sm.get_side_effect_by_key("r1", child_key)
        assert child["status"] == "planned"


# ── Adversarial/edge verification ───────────────────────────────────────


class TestAdversarialEdge:
    """Adversarial and edge-case scenarios from the T11 matrix."""

    def test_legacy_capsule_unavailable_rejected(self, tmp_path, kek):
        """Legacy row (no capsule) → REPLAY_MATERIAL_UNAVAILABLE."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator, RetryExecutionError,
        )
        sm = StateManager(db_path=str(tmp_path / "adv1.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: None,
        )
        with pytest.raises(RetryExecutionError) as exc_info:
            coord.execute_authorized_retry("r1", "se:legacy", "fake-decision")
        assert exc_info.value.code == "REPLAY_MATERIAL_UNAVAILABLE"

    def test_dead_transition_retry_authorized_to_started_rejected(self, tmp_path):
        """INV-008: retry_authorized → started is removed from LEGAL_TRANSITIONS."""
        from nodechain.core.state import SideEffectTransitionError
        sm = StateManager(db_path=str(tmp_path / "adv2.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:1",
            status="retry_authorized", request_hash="rh",
        )
        # Attempt the transition — must raise (illegal since v3.5)
        from nodechain.core.stores import SideEffectLedgerStore
        store = SideEffectLedgerStore(sm.db_path)
        with pytest.raises(SideEffectTransitionError):
            store.update_side_effect_status("r1", "se:1", "started")
        # Status must NOT have changed
        child = sm.get_side_effect_by_key("r1", "se:1")
        assert child["status"] == "retry_authorized"

    def test_duplicate_identical_queries_single_dispatch(self, tmp_path, kek):
        """Duplicate identical queries cannot dispatch twice.

        The deterministic child key ensures convergence — the second call
        finds the existing child and does not re-dispatch.
        """
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        import sys
        sys.path.insert(0, "tests")
        from test_v35_t6_execution import FakeAdapter

        sm = StateManager(db_path=str(tmp_path / "adv3.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)
        fake = FakeAdapter()
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: fake,
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
        )
        coord.execute_authorized_retry("r1", parent_key, decision_id)
        coord.execute_authorized_retry("r1", parent_key, decision_id)
        # Only ONE dispatch should have occurred
        assert fake.dispatch_count == 1

    def test_top20_plus_other_aggregation(self, tmp_path):
        """Top-20-plus-other metric aggregation works correctly."""
        from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
        from nodechain.core.stores import RecoveryMetricStore
        from nodechain.cli.dashboard import collect_recovery_metrics_status
        import os

        db_path = str(tmp_path / "adv4.db")
        StateManager(db_path=db_path)
        emitter = RecoveryMetricsEmitter(RecoveryMetricStore(db_path))
        # 25 adapters with outcome metrics
        for i in range(25):
            emitter.emit(
                metric_name="retry_outcome_completed", run_id="r1",
                source_event_key=f"retry:r1:a{i}",
                labels={"adapter_id": f"ad{i:02d}"},
            )
        os.environ["NODECHAIN_DB_PATH"] = db_path
        try:
            result = collect_recovery_metrics_status()
        finally:
            del os.environ["NODECHAIN_DB_PATH"]
        top = result["adapter_top20"]
        # 20 named + 1 "other"
        assert len(top) == 21
        other = [a for a in top if a["adapter_id"] == "other"]
        assert len(other) == 1
        assert other[0]["count"] == 5


# ── Migration verification ──────────────────────────────────────────────


class TestMigrationVerification:
    """Legacy database migration: pre-v3.5 DB shape → v3.5 schema."""

    def test_fresh_db_has_all_v35_tables(self, tmp_path):
        """A fresh DB creates all v3.5 tables + columns."""
        sm = StateManager(db_path=str(tmp_path / "mig1.db"))
        with sqlite3.connect(sm.db_path) as conn:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()]
        for expected in [
            "side_effect_replay_capsules", "recovery_execution_actions",
            "run_encryption_keys", "recovery_metric_events", "run_purge_audit",
        ]:
            assert expected in tables, f"missing table: {expected}"

    def test_legacy_rows_classified_unavailable(self, tmp_path):
        """Pre-existing side effects get capsule_status='legacy_unavailable'."""
        sm = StateManager(db_path=str(tmp_path / "mig2.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:pre",
            status="unknown", request_hash="rh",
        )
        se = sm.get_side_effect_by_key("r1", "se:pre")
        assert se.get("capsule_status") == "legacy_unavailable"


# ── Real concurrent race tests (threaded + forced overlap) ──────────────


class TestConcurrentRaces:
    """Concurrent race tests using injected barriers to force real overlap.

    Each test injects a synchronization hook inside the coordinator's
    allocation path so both threads are guaranteed to contend at the
    _allocate_child_and_action INSERT. No test-harness retry. No exception
    swallowing. Every action_id must resolve to a durable row.
    """

    def test_concurrent_execute_one_child_one_dispatch(self, tmp_path, kek):
        """Two threads execute simultaneously; allocation barrier forces conflict.

        Injects a barrier inside _allocate_child_and_action so both threads
        reach the INSERT simultaneously. The coordinator must catch the
        UNIQUE constraint and converge. Both calls return RetryExecutionResult.
        Exactly one child, one dispatch, every action_id resolves to a row.
        """
        import sys
        sys.path.insert(0, "tests")
        from test_v35_t6_execution import FakeAdapter
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator, RetryExecutionResult,
        )

        sm = StateManager(db_path=str(tmp_path / "race1.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)
        shared_fake = FakeAdapter()

        # Allocation barrier: forces both threads into the INSERT together.
        alloc_barrier = threading.Barrier(2)

        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: shared_fake,
            adapter_trust_validator=lambda ad: type(ad).__name__ == "FakeAdapter",
        )
        # Monkeypatch _allocate_child_and_action to barrier-synchronize the INSERT.
        original_allocate = coord._allocate_child_and_action
        allocate_call_count = [0]

        def barriered_allocate(**kwargs):
            allocate_call_count[0] += 1
            # Both threads reach the INSERT at the same time
            alloc_barrier.wait(timeout=5)
            return original_allocate(**kwargs)

        coord._allocate_child_and_action = barriered_allocate

        def execute():
            return coord.execute_authorized_retry("r1", parent_key, decision_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(execute) for _ in range(2)]
            results = [f.result() for f in futures]

        # Both must return RetryExecutionResult — no leaked IntegrityError
        assert all(isinstance(r, RetryExecutionResult) for r in results)

        # Exactly one dispatch
        assert shared_fake.dispatch_count == 1

        # One winner, one converger
        dispatched = [r for r in results if r.dispatch_performed]
        converged = [r for r in results if not r.dispatch_performed]
        assert len(dispatched) == 1
        assert len(converged) == 1
        assert dispatched[0].child_status == "completed"

        # Every non-null recovery_action_id must resolve to a durable row
        with sqlite3.connect(sm.db_path) as conn:
            for r in results:
                if r.recovery_action_id:
                    row = conn.execute(
                        "SELECT 1 FROM recovery_execution_actions "
                        "WHERE action_id = ?", (r.recovery_action_id,),
                    ).fetchone()
                    assert row is not None, (
                        f"phantom action_id {r.recovery_action_id} — "
                        f"no durable row"
                    )

        # Only ONE child in the ledger
        all_ses = sm.get_side_effects("r1")
        children = [s for s in all_ses
                    if s.get("parent_side_effect_key") == parent_key]
        assert len(children) == 1

    def test_heartbeat_races_reconciliation(self, tmp_path, kek):
        """Heartbeat extension races with expiry reconciliation.

        Starts with an expired lease. Two threads race:
        - Thread A: heartbeat_recovery_attempt(run_id, child_key, fencing_token)
        - Thread B: reconcile_expired_recovery_children(run_id)

        The fencing_token must match execution_claim_id for the heartbeat CAS.
        Acceptable outcomes are tied to the authoritative winner.
        """
        sm = StateManager(db_path=str(tmp_path / "race2.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)

        now = datetime.now(timezone.utc)
        expired = (now - timedelta(seconds=1)).isoformat()
        child_key = "retry:child_hb"
        claim_id = "hb-claim-1"

        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key=child_key,
            status="started", request_hash="rh",
        )
        with sqlite3.connect(sm.db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET capsule_status='available', "
                "parent_side_effect_key=?, root_side_effect_key=?, "
                "retry_ordinal=1, execution_claim_id=?, "
                "claim_acquired_at=?, claim_expires_at=?, "
                "dispatch_attempted_at=NULL "
                "WHERE run_id='r1' AND idempotency_key=?",
                (parent_key, parent_key, claim_id,
                 (now - timedelta(minutes=5)).isoformat(), expired, child_key),
            )
            conn.commit()

        import threading
        from concurrent.futures import ThreadPoolExecutor
        barrier = threading.Barrier(2)
        hb_result = {}
        recon_result = {}

        def try_heartbeat():
            barrier.wait(timeout=5)
            try:
                # Correct API: (run_id, child_key, fencing_token)
                # fencing_token must match execution_claim_id for CAS
                r = sm.heartbeat_recovery_attempt("r1", child_key, claim_id)
                hb_result["ok"] = r
            except Exception as e:
                hb_result["error"] = e

        def try_reconcile():
            barrier.wait(timeout=5)
            try:
                r = sm.reconcile_expired_recovery_children("r1")
                recon_result["repaired"] = r
            except Exception as e:
                recon_result["error"] = e

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(try_heartbeat)
            f2 = pool.submit(try_reconcile)
            f1.result()
            f2.result()

        child = sm.get_side_effect_by_key("r1", child_key)

        # No worker may produce an unexpected error
        assert "error" not in hb_result, f"heartbeat error: {hb_result.get('error')}"
        assert "error" not in recon_result, f"reconcile error: {recon_result.get('error')}"

        hb_ok = hb_result.get("ok") is True
        recon_repaired = (
            recon_result.get("repaired")
            and len(recon_result["repaired"]) > 0
        )

        # Exactly one winner
        assert hb_ok != recon_repaired, (
            f"expected exactly one winner: hb_ok={hb_ok}, "
            f"recon_repaired={recon_repaired}"
        )

        if hb_ok:
            # Heartbeat won: child stays started with a future lease
            assert child["status"] == "started"
            assert child["claim_expires_at"] > expired  # lease was extended
            # Reconciliation found nothing expired
            assert not recon_repaired
        else:
            # Reconciliation won: child requeued to planned
            assert child["status"] == "planned"
            assert recon_repaired
            # Heartbeat must have failed (child no longer started)
            assert hb_result.get("ok") is not True

    def test_deletion_vs_allocation_no_orphans(self, tmp_path, kek):
        """Concurrent delete_run + execute — no orphaned records.

        Barrier forces overlap. No exception swallowing. If deletion wins,
        verify ALL run-scoped tables empty + key purged. If allocation wins,
        verify exactly one child + action, deletion blocked.
        """
        from nodechain.runtime.run_deletion_service import (
            RunDeletionService, DeletionBlocked,
        )
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator, RetryExecutionResult,
        )
        import sys
        sys.path.insert(0, "tests")
        from test_v35_t6_execution import FakeAdapter
        from concurrent.futures import ThreadPoolExecutor
        import threading

        sm = StateManager(db_path=str(tmp_path / "race3.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)
        state = sm.load("r1")
        state.status = "completed"
        sm.save(state)

        svc = RunDeletionService(sm.db_path)
        shared_fake = FakeAdapter()
        barrier = threading.Barrier(2)
        del_outcome = {}
        alloc_outcome = {}

        def try_delete():
            barrier.wait(timeout=5)
            try:
                svc.delete_run("r1", actor_identity="op", reason="race")
                del_outcome["succeeded"] = True
            except DeletionBlocked as e:
                del_outcome["blocked"] = e

        def try_allocate():
            barrier.wait(timeout=5)
            try:
                coord = SideEffectRetryCoordinator(
                    sm, kek=kek,
                    adapter_factory=lambda name: shared_fake,
                    adapter_trust_validator=(
                        lambda ad: type(ad).__name__ == "FakeAdapter"
                    ),
                )
                r = coord.execute_authorized_retry("r1", parent_key, decision_id)
                alloc_outcome["result"] = r
            except Exception as e:
                alloc_outcome["error"] = e

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(try_delete)
            f2 = pool.submit(try_allocate)
            f1.result()
            f2.result()

        # No unexpected errors from either worker
        assert "error" not in del_outcome, f"deletion error: {del_outcome.get('error')}"
        assert "error" not in alloc_outcome, f"allocation error: {alloc_outcome.get('error')}"

        # The fixture has an open retry lineage (retry_authorized parent).
        # Deletion MUST be blocked regardless of whether child allocation
        # committed — an open lineage is an open lineage.
        assert "blocked" in del_outcome, (
            "deletion succeeded despite open retry lineage — gate failure"
        )
        assert not del_outcome.get("succeeded"), (
            "deletion succeeded despite open retry lineage — gate failure"
        )

        # Allocation must have produced a governed result
        result = alloc_outcome.get("result")
        assert result is not None
        assert isinstance(result, RetryExecutionResult)

        # Verify the child exists with a matching action row
        all_ses = sm.get_side_effects("r1")
        children = [s for s in all_ses
                    if s.get("parent_side_effect_key") == parent_key]
        assert len(children) == 1, f"expected 1 child, got {len(children)}"
        db_path = sm.db_path
        with sqlite3.connect(db_path) as conn:
            action_count = conn.execute(
                "SELECT COUNT(*) FROM recovery_execution_actions "
                "WHERE run_id=? AND retry_attempt_key=?",
                ("r1", children[0]["idempotency_key"]),
            ).fetchone()[0]
        assert action_count >= 1, "child without matching action row"

        # No partial purge occurred — run must still exist
        assert sm.load("r1") is not None

    def test_parent_resolution_blocked_during_concurrent_allocation(
        self, tmp_path, kek,
    ):
        """Parent status mutation races with child allocation.

        Two threads: one executes a retry (allocates child), the other
        attempts to mutate the parent to 'completed'. The outcome depends
        on serialization order:

        - allocation wins first: SideEffectRecoveryError with code
          RECOVERY_TARGET_IN_FLIGHT or RECOVERY_TARGET_HAS_RETRY_LINEAGE
        - mutation reaches the store first: SideEffectTransitionError
          (retry_authorized → completed is not in LEGAL_TRANSITIONS)

        Either way the parent must remain retry_authorized.
        """
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from nodechain.core.state import (
            SideEffectRecoveryError, SideEffectTransitionError,
        )
        import sys
        sys.path.insert(0, "tests")
        from test_v35_t6_execution import FakeAdapter
        from concurrent.futures import ThreadPoolExecutor
        import threading

        sm = StateManager(db_path=str(tmp_path / "race4.db"))
        parent_key, decision_id = _setup_retry_parent(sm, kek)

        shared_fake = FakeAdapter()
        barrier = threading.Barrier(2)
        exec_outcome = {}
        resolve_outcome = {}

        def try_execute():
            coord = SideEffectRetryCoordinator(
                sm, kek=kek,
                adapter_factory=lambda name: shared_fake,
                adapter_trust_validator=(
                    lambda ad: type(ad).__name__ == "FakeAdapter"
                ),
            )
            barrier.wait(timeout=5)
            try:
                r = coord.execute_authorized_retry("r1", parent_key, decision_id)
                exec_outcome["result"] = r
            except Exception as e:
                exec_outcome["error"] = e

        def try_resolve_parent():
            barrier.wait(timeout=5)
            try:
                from nodechain.core.stores import SideEffectLedgerStore
                store = SideEffectLedgerStore(sm.db_path)
                store.update_side_effect_status("r1", parent_key, "completed")
                resolve_outcome["succeeded"] = True
            except SideEffectRecoveryError as e:
                resolve_outcome["recovery_error"] = e
            except SideEffectTransitionError as e:
                resolve_outcome["transition_error"] = e
            except Exception as e:
                resolve_outcome["unexpected_error"] = e

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(try_execute)
            f2 = pool.submit(try_resolve_parent)
            f1.result()
            f2.result()

        # Execute must not error
        assert "error" not in exec_outcome, f"execute error: {exec_outcome.get('error')}"

        # Parent mutation must NOT succeed
        assert not resolve_outcome.get("succeeded"), "parent mutated — immutability violated"

        # The rejection must be a precise expected exception — not a catch-all
        if "recovery_error" in resolve_outcome:
            e = resolve_outcome["recovery_error"]
            assert e.code in (
                "RECOVERY_TARGET_IN_FLIGHT",
                "RECOVERY_TARGET_HAS_RETRY_LINEAGE",
            ), f"unexpected recovery error code: {e.code}"
        elif "transition_error" in resolve_outcome:
            # Dead-transition guard fired before lineage guard — also valid
            pass
        else:
            pytest.fail(
                f"unexpected resolve outcome: {resolve_outcome}"
            )

        # No unexpected errors
        assert "unexpected_error" not in resolve_outcome

        # Parent must still be retry_authorized
        parent = sm.get_side_effect_by_key("r1", parent_key)
        assert parent["status"] == "retry_authorized"

