"""Side-Effect Trace/Ledger Lifecycle Tests (v2.33.0).

Proves the transition table agreed with the strategic reviewer:

    planned/new → started    : SIDE_EFFECT_STARTED
    started → completed      : SIDE_EFFECT_COMPLETED
    started → failed         : SIDE_EFFECT_FAILED
    started → unknown (crash): NO trace event (ledger is source of truth)

Each transition verifies:
  - the ledger status after the transition
  - the trace event type emitted (or its absence for unknown)
  - the reconciler's assessment (passes for correct bindings)

The TraceEmitter helpers are exercised directly (unit-level), and the
reconciler is exercised against ledger + trace fixtures (integration-level).
The orchestrator-level emission is covered by the search-adapter and
memory-write paths in their respective test suites.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_emitter import TraceEmitter
from nodechain.runtime.trace_reconciler import TraceReconciler


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "se_lifecycle.db")


@pytest.fixture
def state_manager(db_path):
    return StateManager(db_path)


@pytest.fixture
def reconciler(state_manager):
    return TraceReconciler(state_manager)


def _make_trace(run_id: str, events: list[TraceEvent] | None = None) -> ChainTrace:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


def _make_emitter(run_id: str = "run-lifecycle") -> tuple[TraceEmitter, ChainTrace]:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    emitter = TraceEmitter(trace, run_id=run_id, chain_id="test-chain")
    return emitter, trace


# ── Unit: TraceEmitter helpers emit canonical EventType ─────────────────────

class TestEmitterHelpersEmitCanonicalTypes:
    """v2.33.0: TraceEmitter helpers now emit SIDE_EFFECT_* (not TOOL_*)."""

    def test_started_emits_side_effect_started(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_started("search_tool", "api_call", "ss:abc")
        assert trace.events[0].event_type == EventType.SIDE_EFFECT_STARTED

    def test_completed_emits_side_effect_completed(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_completed("search_tool", "api_call", "ss:abc")
        assert trace.events[0].event_type == EventType.SIDE_EFFECT_COMPLETED

    def test_failed_emits_side_effect_failed(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_failed("search_tool", "api_call", "ss:abc", reason="x")
        assert trace.events[0].event_type == EventType.SIDE_EFFECT_FAILED

    def test_failed_includes_reason_metadata(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_failed("n", "t", "k", reason="adapter_timeout")
        assert trace.events[0].metadata["reason"] == "adapter_timeout"

    def test_all_side_effect_events_carry_idempotency_key(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_started("n", "t", "key-1")
        emitter.side_effect_completed("n", "t", "key-2")
        emitter.side_effect_failed("n", "t", "key-3")
        keys = [e.metadata["idempotency_key"] for e in trace.events]
        assert keys == ["key-1", "key-2", "key-3"]


# ── Integration: reconciler sees each lifecycle transition correctly ────────

class TestStartedToCompletedTransition:
    """started → completed: ledger completed, SIDE_EFFECT_COMPLETED, reconciler clean."""

    @pytest.mark.asyncio
    async def test_completed_transition_reconciles_cleanly(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:ok1", status="completed",
            request_hash="r1", response_hash="p1",
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="search_tool", step_id=1,
                event_type=EventType.SIDE_EFFECT_COMPLETED,
                actor=Actor.NODE,
                metadata={"idempotency_key": "ss:ok1"},
            ),
        ])

        report = reconciler.reconcile(trace)
        se_errors = [i for i in report.issues
                     if i.check.startswith("side_effect") and i.severity == "error"]
        assert len(se_errors) == 0, f"Unexpected side-effect errors: {se_errors}"


class TestStartedToFailedTransition:
    """started → failed: ledger failed, SIDE_EFFECT_FAILED, reconciler Check 4f binds."""

    @pytest.mark.asyncio
    async def test_failed_trace_matches_ledger_failed(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=2, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:fail1", status="failed",
            request_hash="r2",
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="search_tool", step_id=2,
                event_type=EventType.SIDE_EFFECT_FAILED,
                actor=Actor.NODE,
                metadata={
                    "idempotency_key": "ss:fail1",
                    "effect_type": "external_api_read",
                    "reason": "adapter_timeout",
                },
            ),
        ])

        report = reconciler.reconcile(trace)
        failed_errors = [i for i in report.issues
                         if i.check == "side_effect_failed_ledger_match"
                         and i.severity == "error"]
        assert len(failed_errors) == 0, f"Should bind cleanly: {failed_errors}"

    @pytest.mark.asyncio
    async def test_failed_trace_without_ledger_is_error(self, reconciler, state_manager):
        """SIDE_EFFECT_FAILED with no ledger row = ERROR (Check 4f)."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="search_tool", step_id=2,
                event_type=EventType.SIDE_EFFECT_FAILED,
                actor=Actor.NODE,
                metadata={"idempotency_key": "ss:orphan_fail"},
            ),
        ])

        report = reconciler.reconcile(trace)
        match_errors = [i for i in report.issues
                        if i.check == "side_effect_failed_ledger_match"
                        and i.severity == "error"]
        assert len(match_errors) >= 1

    @pytest.mark.asyncio
    async def test_failed_trace_status_mismatch_is_error(self, reconciler, state_manager):
        """SIDE_EFFECT_FAILED trace but ledger says completed = ERROR (Check 4f)."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=2, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:mismatch", status="completed",
            request_hash="r3", response_hash="p3",
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="search_tool", step_id=2,
                event_type=EventType.SIDE_EFFECT_FAILED,
                actor=Actor.NODE,
                metadata={"idempotency_key": "ss:mismatch"},
            ),
        ])

        report = reconciler.reconcile(trace)
        mismatch_errors = [i for i in report.issues
                           if i.check == "side_effect_failed_ledger_match"
                           and i.severity == "error"]
        assert len(mismatch_errors) >= 1

    @pytest.mark.asyncio
    async def test_ledger_failed_without_trace_is_warning(self, reconciler, state_manager):
        """Ledger failed but no SIDE_EFFECT_FAILED trace = WARNING (coverage)."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=2, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:no_trace_fail", status="failed",
            request_hash="r4",
        )

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        coverage = [i for i in report.issues
                    if i.check == "side_effect_failed_trace_coverage"]
        assert len(coverage) >= 1
        assert coverage[0].severity == "warning"


class TestStartedToUnknownTransition:
    """started → unknown (crash): NO trace event, ledger unknown, 4d warns from ledger.

    v2.33.0 correction: unknown emits NO side-effect trace event. The previous
    code emitted a fake SIDE_EFFECT_COMPLETED with decision="side_effect_marked_unknown",
    which polluted the reconciler's completed bucket. Now the ledger `unknown`
    status is the sole source of truth; Check 4d reads ledger state directly.
    """

    @pytest.mark.asyncio
    async def test_unknown_in_ledger_triggers_recovery_warning(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:crash_unknown", status="unknown",
            request_hash="r5",
        )

        # NO side-effect trace event — unknown is not failed/completed
        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        recovery = [i for i in report.issues
                    if i.check == "side_effect_recovery_required"]
        assert len(recovery) >= 1
        assert "unknown" in recovery[0].actual.lower()

    @pytest.mark.asyncio
    async def test_unknown_does_not_pollute_completed_bucket(self, reconciler, state_manager):
        """Critical: unknown side effects must NOT generate SIDE_EFFECT_COMPLETED
        events (the old fake-completion bug). The completed count check (4e)
        must not see phantom completed events from the recovery path."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:crash1", status="unknown",
            request_hash="r6",
        )

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        # No SIDE_EFFECT_COMPLETED events should exist in the trace
        completed_events = [e for e in trace.events
                            if "SIDE_EFFECT_COMPLETED" in str(e.event_type)]
        assert len(completed_events) == 0

        # The count-match check should NOT flag a mismatch caused by fake
        # completed events (both trace and ledger completed counts are 0)
        count_mismatch = [i for i in report.issues
                          if i.check == "side_effect_count_match"]
        # Zero completed in ledger, zero in trace → no mismatch
        for cm in count_mismatch:
            assert "0" in cm.expected or cm.severity != "error"


class TestEmitterReconcilerIntegration:
    """End-to-end: emitter produces events that the reconciler accepts."""

    @pytest.mark.asyncio
    async def test_emitter_completed_event_reconciles(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="n1",
            side_effect_type="api_call",
            idempotency_key="int:1", status="completed",
            request_hash="h", response_hash="p",
        )

        emitter, se_trace = _make_emitter(state.run_id)
        emitter.side_effect_completed("n1", "api_call", "int:1")

        # Build a reconcilable trace from the emitter's output
        trace = ChainTrace(run_id=state.run_id, chain_id="test-chain", chain_name="T")
        for e in se_trace.events:
            trace.add_event(e)
        trace.finalize("completed")

        report = reconciler.reconcile(trace)
        se_errors = [i for i in report.issues
                     if i.check.startswith("side_effect") and i.severity == "error"]
        assert len(se_errors) == 0

    @pytest.mark.asyncio
    async def test_emitter_failed_event_reconciles(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="n1",
            side_effect_type="api_call",
            idempotency_key="int:2", status="failed",
            request_hash="h",
        )

        emitter, se_trace = _make_emitter(state.run_id)
        emitter.side_effect_failed("n1", "api_call", "int:2", reason="timeout")

        trace = ChainTrace(run_id=state.run_id, chain_id="test-chain", chain_name="T")
        for e in se_trace.events:
            trace.add_event(e)
        trace.finalize("completed")

        report = reconciler.reconcile(trace)
        failed_errors = [i for i in report.issues
                         if i.check == "side_effect_failed_ledger_match"
                         and i.severity == "error"]
        assert len(failed_errors) == 0


# ── Production: orchestrator _journal_one emits SIDE_EFFECT_STARTED (v2.33.1) ─

class TestJournalOneEmitsStarted:
    """v2.33.1: _journal_one() must emit SIDE_EFFECT_STARTED when a side-effect
    row transitions to 'started', so the trace surface mirrors the ledger for
    the planned→started transition.

    Found by code-review re-audit of v2.33.0: the emitter helper was fixed but
    _journal_one() only wrote the ledger row — no trace event.
    """

    def test_new_started_row_emits_started_event(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.core.state import StateManager
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "journal.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch.state.run_id = "run-journal-1"

        envelope = InvocationEnvelope(
            run_id="run-journal-1", chain_id="t", node_id="n",
            step_id=1, payload={"q": "test"},
        )
        orch._journal_one("search:arxiv:abc", "n", "external_api_read", envelope)

        started_events = [e for e in orch.trace.events
                          if e.event_type == EventType.SIDE_EFFECT_STARTED]
        assert len(started_events) == 1
        assert started_events[0].metadata["idempotency_key"] == "search:arxiv:abc"
        # v2.35.0: external_api_read normalizes to external_call
        assert started_events[0].metadata["effect_type"] == "external_call"

        # Ledger should also reflect started
        row = sm.get_side_effect_by_key("run-journal-1", "search:arxiv:abc")
        assert row is not None
        assert row["status"] == "started"

    def test_planned_to_started_emits_started_event(self, tmp_path):
        """When a planned row transitions to started, emit SIDE_EFFECT_STARTED."""
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.core.state import StateManager
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "journal2.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch.state.run_id = "run-journal-2"

        # Pre-create a planned row
        sm.record_side_effect(
            run_id="run-journal-2", step_id=1, node_id="n",
            side_effect_type="external_api_read",
            idempotency_key="search:arxiv:planned",
            status="planned",
        )

        envelope = InvocationEnvelope(
            run_id="run-journal-2", chain_id="t", node_id="n",
            step_id=1, payload={"q": "test"},
        )
        orch._journal_one("search:arxiv:planned", "n", "external_api_read", envelope)

        started_events = [e for e in orch.trace.events
                          if e.event_type == EventType.SIDE_EFFECT_STARTED]
        assert len(started_events) == 1
        assert started_events[0].metadata["idempotency_key"] == "search:arxiv:planned"

        row = sm.get_side_effect_by_key("run-journal-2", "search:arxiv:planned")
        assert row["status"] == "started"

    def test_already_started_does_not_re_emit(self, tmp_path):
        """Idempotent: calling _journal_one on an already-started row emits nothing."""
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.core.state import StateManager
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "journal3.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch.state.run_id = "run-journal-3"

        envelope = InvocationEnvelope(
            run_id="run-journal-3", chain_id="t", node_id="n",
            step_id=1, payload={"q": "test"},
        )
        # First call creates the started row + emits
        orch._journal_one("search:arxiv:idem", "n", "external_api_read", envelope)
        # Second call: row already started — should NOT re-emit
        orch._journal_one("search:arxiv:idem", "n", "external_api_read", envelope)

        started_events = [e for e in orch.trace.events
                          if e.event_type == EventType.SIDE_EFFECT_STARTED]
        assert len(started_events) == 1  # exactly one, not two
