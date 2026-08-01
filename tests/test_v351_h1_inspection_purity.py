"""v3.5.1 H1 — Fix #4: inspection must be pure (read-only).

The v3.5.0 build_snapshot / build_trace_health path performed durable
expiry reconciliation (started -> planned child transitions, action-row
updates, state_events inserts, metric emissions) as a side effect of a
read. This file pins the v3.5.1 contract:

* build_snapshot and build_trace_health perform ZERO durable mutation.
* GET /runs/{id}, recovery list, and inspect are equally pure.
* An expired pre-dispatch child is NOT repaired by a snapshot; the
  snapshot REPORTS that repair is required instead.
* An explicit reconciliation operation (reconcile_expired_recovery_children
  driven by the reconcile command / an explicit service call) DOES repair.

These tests are written FIRST (RED) and watch the current code fail before
the purity fix lands.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_service import RecoveryService
from nodechain.runtime.recovery_metrics import RecoveryMetricsEmitter
from nodechain.core.stores import RecoveryMetricStore


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> Path:
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture()
def service(sm: StateManager, trace_dir: Path) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=str(trace_dir))


@pytest.fixture()
def kek(monkeypatch, tmp_path) -> bytes:
    """Deterministic in-memory KEK so capsule bookkeeping doesn't need files."""
    return b"\x00" * 32


def _save_run(sm: StateManager, run_id: str, **kw) -> ChainState:
    state = ChainState(run_id=run_id, chain_id="c", **kw)
    sm.save(state)
    return state


def _setup_expired_child(db_path, kek) -> StateManager:
    """Run with one expired-started pre-dispatch recovery child.

    This is exactly the state that the v3.5.0 snapshot used to silently
    repair. Under v3.5.1 the snapshot must leave it untouched.
    """
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
    with sqlite3.connect(str(db_path)) as conn:
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


def _event_count(db_path, run_id="r1") -> int:
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM state_events WHERE run_id = ?", (run_id,)
        ).fetchone()
        return row[0]


def _metric_count(store: RecoveryMetricStore, name: str) -> int:
    return len(store.query_recent(metric_name=name))


# ── build_snapshot purity ─────────────────────────────────────────────────


class TestBuildSnapshotIsPure:
    """build_snapshot must perform zero durable mutation.

    The v3.5.0 test_build_snapshot_is_read_only only checked chain_states
    .revision. That is the one field the defective reconciliation happens
    NOT to touch, so the test passed while children, action rows, events,
    and metrics were mutated. These tests close every gap.
    """

    def test_snapshot_does_not_modify_child_status(self, tmp_path, kek):
        db_path = str(tmp_path / "child.db")
        sm = _setup_expired_child(db_path, kek)
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))

        before = sm.get_side_effect_by_key("r1", "retry:child1")["status"]
        service.build_snapshot("r1")
        after = sm.get_side_effect_by_key("r1", "retry:child1")["status"]

        assert before == "started"
        assert after == "started", (
            f"build_snapshot mutated expired child status {before!r} -> {after!r}; "
            "a read must not repair."
        )

    def test_snapshot_emits_no_state_event(self, tmp_path, kek):
        db_path = str(tmp_path / "evt.db")
        sm = _setup_expired_child(db_path, kek)
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))

        before = _event_count(db_path)
        service.build_snapshot("r1")
        after = _event_count(db_path)

        assert after == before, (
            f"build_snapshot emitted {after - before} state_events; "
            "a read must not append durable events."
        )

    def test_snapshot_emits_no_metric(self, tmp_path, kek):
        db_path = str(tmp_path / "met.db")
        sm = _setup_expired_child(db_path, kek)
        store = RecoveryMetricStore(db_path)
        emitter = RecoveryMetricsEmitter(store)
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))
        service.set_metrics_emitter(emitter)

        before = _metric_count(store, "retry_requeued")
        service.build_snapshot("r1")
        after = _metric_count(store, "retry_requeued")

        assert after == before, (
            f"build_snapshot emitted {after - before} retry_requeued metrics; "
            "a read must not emit metrics."
        )

    def test_snapshot_does_not_modify_recovery_action_status(self, tmp_path, kek):
        db_path = str(tmp_path / "act.db")
        sm = _setup_expired_child(db_path, kek)
        # Create the matching recovery execution action, then set it to an
        # active status the reconciler would finalize if it ran.
        sm.create_recovery_execution_action(
            action_id="act-1", operator_action_id="oal-1", run_id="r1",
            retry_attempt_key="retry:child1", execution_claim_id="claim-1",
        )
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE recovery_execution_actions SET execution_status='dispatch_started' "
                "WHERE action_id = ?", ("act-1",)
            )
            conn.commit()
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))

        service.build_snapshot("r1")
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT execution_status FROM recovery_execution_actions "
                "WHERE action_id = ?", ("act-1",)
            ).fetchone()
        assert row is not None
        assert row[0] == "dispatch_started", (
            f"build_snapshot finalized the action to {row[0]!r}; "
            "a read must not mutate recovery-action status."
        )


# ── build_trace_health purity ──────────────────────────────────────────────


class TestBuildTraceHealthIsPure:
    """build_trace_health is the other read path that used to repair."""

    def test_trace_health_does_not_modify_child_status(self, tmp_path, kek):
        db_path = str(tmp_path / "th.db")
        sm = _setup_expired_child(db_path, kek)
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))

        service.build_trace_health("r1")
        after = sm.get_side_effect_by_key("r1", "retry:child1")["status"]
        assert after == "started", (
            f"build_trace_health mutated child -> {after!r}; a read must not repair."
        )

    def test_trace_health_emits_no_event_no_metric(self, tmp_path, kek):
        db_path = str(tmp_path / "th2.db")
        sm = _setup_expired_child(db_path, kek)
        store = RecoveryMetricStore(db_path)
        emitter = RecoveryMetricsEmitter(store)
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        service = RecoveryService(state_manager=sm, trace_dir=str(trace_dir))
        service.set_metrics_emitter(emitter)

        ev_before = _event_count(db_path)
        met_before = _metric_count(store, "retry_requeued")
        service.build_trace_health("r1")
        ev_after = _event_count(db_path)
        met_after = _metric_count(store, "retry_requeued")

        assert ev_after == ev_before, "build_trace_health emitted an event"
        assert met_after == met_before, "build_trace_health emitted a metric"


# ── explicit reconciliation DOES repair ────────────────────────────────────


class TestExplicitReconciliationRepairs:
    """The repair must still exist — just behind an explicit mutating call.

    After the purity fix, the owner is a direct
    reconcile_expired_recovery_children() call (driven by the reconcile
    command), NOT a snapshot. This pins that the repair path survives.
    """

    def test_direct_reconcile_repairs_expired_child(self, tmp_path, kek):
        db_path = str(tmp_path / "rep.db")
        sm = _setup_expired_child(db_path, kek)

        results = sm.reconcile_expired_recovery_children("r1")

        assert len(results) == 1
        assert results[0]["action"] == "requeued"
        child = sm.get_side_effect_by_key("r1", "retry:child1")
        assert child["status"] == "planned"
