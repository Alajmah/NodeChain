"""H0.4 adversarial proof: singular trace-emission authority.

Tests the frozen acceptance criteria:
  - one logical event → one event_id → one durable trace row → one in-memory
    event → shared identity
  - durable-first: persistence failure leaves NO in-memory acknowledgement
  - stable ordering: durable trace-row sequence matches in-memory sequence
  - projection fidelity: durable row reconstructs a field-equal TraceEvent
  - mixed-journal isolation: internal journal rows (trace_event_id NULL) do
    not participate in trace identity/count assertions
  - no duplicate: each logical event appears exactly once in both representations
"""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from nodechain.core.trace import Actor, ChainTrace, EventType, TraceEvent


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_orchestrator(tmp_path: Path):
    """Construct a minimal Orchestrator with a real temp-db StateManager."""
    from nodechain.core.blueprint import ChainBlueprint, NodeDef
    from nodechain.core.state import StateManager
    from nodechain.core.capsule_crypto import KekManager
    from nodechain.runtime.orchestrator import Orchestrator

    db_path = str(tmp_path / "test.db")
    kek_path = str(tmp_path / ".kek")
    sm = StateManager(db_path, kek_manager=KekManager(local_dev=True, kek_path=kek_path))

    blueprint = ChainBlueprint(
        chain_id="test-chain",
        name="Test",
        version="1.0.0",
        goal="test",
        nodes=[NodeDef(node_id="goal_interpreter", node_type="model", config={}, position=1)],
        connections=[],
    )
    orch = Orchestrator(
        blueprint=blueprint,
        nodes={},
        state_manager=sm,
    )
    return orch, sm


# --------------------------------------------------------------------------- #
# 1. Identity invariant — shared event_id between in-memory and durable
# --------------------------------------------------------------------------- #


def test_identity_invariant_shared_event_id(tmp_path: Path) -> None:
    """An event emitted through _emit has the same event_id in both the
    in-memory ChainTrace and the durable state_events trace row."""
    orch, sm = _make_orchestrator(tmp_path)

    orch._emit(EventType.NODE_INVOKED, node_id="test_node", step_id=1)

    # In-memory event
    in_memory = orch.trace.events
    assert len(in_memory) == 1
    live_event = in_memory[0]
    assert live_event.event_type == EventType.NODE_INVOKED

    # Durable trace row
    durable = sm.get_trace_events(orch.state.run_id)
    assert len(durable) == 1
    durable_row = durable[0]

    # Shared identity
    assert durable_row["trace_event_id"] == live_event.event_id, (
        "durable trace_event_id does not match in-memory event_id"
    )
    # Shared timestamp (not a fresh datetime.now)
    assert durable_row["timestamp"] == live_event.timestamp, (
        "durable timestamp does not match in-memory timestamp"
    )


# --------------------------------------------------------------------------- #
# 2. Persistence failure — no in-memory acknowledgement
# --------------------------------------------------------------------------- #


def test_persistence_failure_leaves_no_inmemory_event(tmp_path: Path) -> None:
    """If the durable write fails, the event must NOT appear in ChainTrace.

    This is the durable-first guarantee: no authoritative acknowledgement
    before persistence succeeds.
    """
    orch, sm = _make_orchestrator(tmp_path)
    cost_before = orch.trace.total_cost_usd
    count_before = len(orch.trace.events)

    # Inject a persistence failure
    with patch.object(
        orch.persistence, "append_trace_event",
        side_effect=RuntimeError("injected DB failure"),
    ):
        with pytest.raises(RuntimeError, match="injected DB failure"):
            orch._emit(
                EventType.NODE_SUCCEEDED,
                node_id="test_node",
                cost_usd=0.05,
            )

    # The event was NOT acknowledged in-memory
    assert len(orch.trace.events) == count_before, (
        "event was appended to ChainTrace despite persistence failure"
    )
    assert orch.trace.total_cost_usd == cost_before, (
        "cost total changed despite persistence failure"
    )


# --------------------------------------------------------------------------- #
# 3. Ordering — durable sequence matches in-memory sequence
# --------------------------------------------------------------------------- #


def test_ordering_durable_matches_inmemory(tmp_path: Path) -> None:
    """The ordered trace_event_id sequence from ChainTrace.events equals the
    ordered durable trace-row sequence."""
    orch, sm = _make_orchestrator(tmp_path)

    orch._emit(EventType.CHAIN_STARTED, node_id="runtime", step_id=0)
    orch._emit(EventType.NODE_INVOKED, node_id="node_a", step_id=1)
    orch._emit(EventType.NODE_SUCCEEDED, node_id="node_a", step_id=1)
    orch._emit(EventType.CHAIN_COMPLETED, node_id="runtime")

    in_memory_ids = [e.event_id for e in orch.trace.events]
    durable_ids = [r["trace_event_id"] for r in sm.get_trace_events(orch.state.run_id)]

    assert in_memory_ids == durable_ids, (
        f"ordering mismatch:\n  in-memory: {in_memory_ids}\n  durable:   {durable_ids}"
    )


# --------------------------------------------------------------------------- #
# 4. Projection fidelity — durable row reconstructs field-equal TraceEvent
# --------------------------------------------------------------------------- #


def test_projection_fidelity_durable_reconstructs_event(tmp_path: Path) -> None:
    """The durable trace row carries enough to reconstruct a TraceEvent equal
    in all trace-relevant fields to the live event."""
    import json
    orch, sm = _make_orchestrator(tmp_path)

    orch._emit(
        EventType.NODE_FAILED,
        node_id="failed_node",
        step_id=3,
        actor=Actor.NODE,
        decision="node_error",
        reason_codes=["timeout", "unresponsive"],
        cost_usd=0.02,
        latency_ms=500,
        metadata={"attempt": 2, "adapter": "fixture"},
    )

    live = orch.trace.events[0]
    durable = sm.get_trace_events(orch.state.run_id)[0]
    payload = json.loads(durable["payload"]) if durable["payload"] else {}

    # All trace-relevant fields must be reconstructable
    assert payload["chain_id"] == live.chain_id
    assert payload["actor"] == live.actor.value
    assert payload["decision"] == live.decision
    assert payload["reason_codes"] == live.reason_codes
    assert payload["cost_usd"] == live.cost_usd
    assert payload["latency_ms"] == live.latency_ms
    assert payload["metadata"] == live.metadata
    assert durable["event_type"] == live.event_type.value
    assert durable["node_id"] == live.node_id
    assert durable["step_id"] == live.step_id
    assert durable["timestamp"] == live.timestamp
    assert durable["trace_event_id"] == live.event_id


# --------------------------------------------------------------------------- #
# 5. Mixed-journal isolation — trace rows vs internal journal rows
# --------------------------------------------------------------------------- #


def test_mixed_journal_isolation(tmp_path: Path) -> None:
    """Internal state_events rows (trace_event_id NULL) do not appear in
    get_trace_events; trace rows do not inflate get_events incorrectly."""
    orch, sm = _make_orchestrator(tmp_path)

    # Write a trace event through the authority
    orch._emit(EventType.NODE_INVOKED, node_id="trace_node", step_id=1)

    # Write an internal journal event through the old append_event path
    sm.append_event(
        run_id=orch.state.run_id,
        revision=0,
        event_type="node_completed",
        node_id="internal_node",
        step_id=1,
        payload={"source": "save_with_invocation"},
    )

    # get_trace_events returns ONLY the trace row
    trace_rows = sm.get_trace_events(orch.state.run_id)
    assert len(trace_rows) == 1
    assert trace_rows[0]["trace_event_id"] is not None
    assert trace_rows[0]["event_type"] == "node_invoked"

    # get_events returns BOTH (mixed journal)
    all_rows = sm.get_events(orch.state.run_id)
    assert len(all_rows) == 2

    # trace_event_id is NOT in get_events output (explicit column list)
    assert "trace_event_id" not in all_rows[0]


# --------------------------------------------------------------------------- #
# 6. No duplicate — each logical event appears exactly once
# --------------------------------------------------------------------------- #


def test_no_duplicate_append(tmp_path: Path) -> None:
    """Each _emit call produces exactly one in-memory event and exactly one
    durable trace row — no double-append from the authority boundary."""
    orch, sm = _make_orchestrator(tmp_path)

    orch._emit(EventType.NODE_INVOKED, node_id="dup_test", step_id=1)
    orch._emit(EventType.NODE_SUCCEEDED, node_id="dup_test", step_id=1)

    assert len(orch.trace.events) == 2
    durable = sm.get_trace_events(orch.state.run_id)
    assert len(durable) == 2

    # All event_ids must be unique
    in_memory_ids = [e.event_id for e in orch.trace.events]
    durable_ids = [r["trace_event_id"] for r in durable]
    assert len(set(in_memory_ids)) == 2
    assert len(set(durable_ids)) == 2


# --------------------------------------------------------------------------- #
# 7. Unique constraint — duplicate trace_event_id rejected
# --------------------------------------------------------------------------- #


def test_unique_constraint_rejects_duplicate_trace_event_id(tmp_path: Path) -> None:
    """The partial unique index prevents two durable trace rows with the same
    trace_event_id for the same run."""
    orch, sm = _make_orchestrator(tmp_path)

    orch._emit(EventType.NODE_INVOKED, node_id="uniq_test", step_id=1)
    live = orch.trace.events[0]

    # Attempt to insert a second row with the same trace_event_id
    with pytest.raises(Exception):
        sm.append_trace_event(
            run_id=orch.state.run_id,
            revision=0,
            event_type="node_succeeded",
            node_id="uniq_test",
            step_id=1,
            trace_event_id=live.event_id,  # duplicate
            timestamp=live.timestamp,
            payload={},
        )


# --------------------------------------------------------------------------- #
# 8. TraceEmitter without authority → cannot construct
# --------------------------------------------------------------------------- #


def test_trace_emitter_requires_record_fn() -> None:
    """H0.4: TraceEmitter cannot be constructed without the singular emission
    authority. No in-memory-only fallback exists."""
    from nodechain.runtime.trace_emitter import TraceEmitter
    trace = ChainTrace(run_id="test", chain_id="test")
    with pytest.raises(TypeError):
        TraceEmitter(trace=trace, run_id="test", chain_id="test")


# --------------------------------------------------------------------------- #
# 9. ContractPreflightController without authority → cannot construct
# --------------------------------------------------------------------------- #


def test_contract_preflight_requires_emit_fn() -> None:
    """H0.4: ContractPreflightController cannot be constructed without the
    emission authority. No in-memory-only fallback exists."""
    from nodechain.core.blueprint import ChainBlueprint, NodeDef
    from nodechain.core.contract import ContractRegistry
    from nodechain.runtime.contract_preflight_controller import (
        ContractPreflightController,
    )
    blueprint = ChainBlueprint(
        chain_id="test", name="T", version="1", goal="g",
        nodes=[NodeDef(node_id="n", node_type="model", config={}, position=1)],
        connections=[],
    )
    trace = ChainTrace(run_id="test", chain_id="test")
    with pytest.raises(TypeError):
        ContractPreflightController(
            blueprint=blueprint,
            contract_registry=ContractRegistry(),
            trace=trace,
        )


# --------------------------------------------------------------------------- #
# 10. Operator trace event visible in authoritative trace query
# --------------------------------------------------------------------------- #


def test_operator_trace_event_visible_in_authoritative_query(
    tmp_path: Path,
) -> None:
    """H0.4: operator recovery actions produce durable trace rows with
    first-class trace_event_id, visible in get_trace_events()."""
    from nodechain.core.state import StateManager
    from nodechain.core.capsule_crypto import KekManager
    from nodechain.runtime.recovery_service import RecoveryService
    from nodechain.core.trace import EventType

    db_path = str(tmp_path / "test.db")
    kek_path = str(tmp_path / ".kek")
    sm = StateManager(db_path, kek_manager=KekManager(local_dev=True, kek_path=kek_path))
    rs = RecoveryService(state_manager=sm, trace_dir=str(tmp_path / "traces"))

    run_id = "test-operator-run"
    tev_id = rs._emit_operator_event(
        run_id=run_id,
        revision=1,
        event_type=EventType.RUN_CANCELLED_BY_OPERATOR,
        action=type("A", (), {"value": "cancel"})(),
        operator_identity="admin@example.com",
        reason="test cancellation",
    )

    assert tev_id, "operator event did not return a trace_event_id"

    trace_events = sm.get_trace_events(run_id)
    assert len(trace_events) == 1, (
        f"expected 1 operator trace event, got {len(trace_events)}"
    )
    assert trace_events[0]["trace_event_id"] == tev_id
    assert trace_events[0]["trace_event_id"] is not None


# --------------------------------------------------------------------------- #
# 11. Resume-review singular — exactly one HUMAN_REVIEW_COMPLETED trace row
# --------------------------------------------------------------------------- #


def test_resume_review_singular_completed_trace_row(tmp_path: Path) -> None:
    """H0.4: after a full pause → approve → resume cycle, exactly one
    HUMAN_REVIEW_COMPLETED trace event exists in the durable trace query."""
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner
    from nodechain.research.run_descriptor import load_descriptor

    CORPUS = (
        Path(__file__).parent.parent.parent
        / "tests" / "fixtures" / "research"
        / "corpus_conflicting_evidence.yaml"
    )
    ws = str(tmp_path / "ws")

    # Initial run → pauses
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=ws,
    )
    result = runner.run()
    assert result.paused

    # Approve → resume
    desc = load_descriptor(ws, result.run_id)
    reconstructed = WorkspaceRunner.from_descriptor(desc)
    reconstructed.compose_for_resume(result.run_id)
    reconstructed.apply_review("approve", "ok", "reviewer1")
    result2 = reconstructed.resume(run_id=result.run_id)

    # Check durable trace events for exactly one HUMAN_REVIEW_COMPLETED
    from nodechain.core.state import StateManager
    from nodechain.core.capsule_crypto import KekManager
    sm = StateManager(desc.db_path, kek_manager=KekManager(local_dev=True, kek_path=desc.kek_path))
    trace_events = sm.get_trace_events(result.run_id)
    completed = [
        e for e in trace_events
        if e["event_type"] == "human_review_completed"
    ]
    assert len(completed) == 1, (
        f"expected exactly 1 HUMAN_REVIEW_COMPLETED trace row, "
        f"got {len(completed)}"
    )


# --------------------------------------------------------------------------- #
# 12. Terminal operator actions carry first-class trace_event_id in the atomic
# save_with_event transaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("event_type,tev_prefix", [
    ("run_cancelled_by_operator", "tev-cancel"),
    ("run_failed_by_operator", "tev-fail"),
])
def test_terminal_operator_events_visible_in_authoritative_query(
    tmp_path: Path, event_type: str, tev_prefix: str
) -> None:
    """H0.4: CANCEL_RUN and FAIL_RUN outcome rows written through the atomic
    save_with_event transaction carry a first-class trace_event_id and appear
    exactly once in get_trace_events().

    This exercises the save_with_event(trace_event_id=...) path that
    RecoveryService uses for terminal operator actions, proving the atomic
    state+event transaction enriches the event row without producing a
    second legacy write.
    """
    from nodechain.core.state import StateManager, ChainState
    from nodechain.core.capsule_crypto import KekManager

    db_path = str(tmp_path / "test.db")
    kek_path = str(tmp_path / ".kek")
    sm = StateManager(db_path, kek_manager=KekManager(local_dev=True, kek_path=kek_path))

    run_id = f"test-{tev_prefix}"
    state = ChainState(run_id=run_id, chain_id="test-chain", status="paused")
    sm.save(state)

    tev_id = f"{tev_prefix}-{uuid.uuid4().hex[:8]}"
    sm.save_with_event(
        state,
        event_type,
        event_payload={"actor": "operator", "reason": "test", "trace_event_id": tev_id},
        trace_event_id=tev_id,
    )

    # The terminal operator outcome must be visible in the authoritative
    # trace projection (trace_event_id IS NOT NULL).
    trace_rows = sm.get_trace_events(run_id)
    matching = [r for r in trace_rows if r["event_type"] == event_type]
    assert len(matching) == 1, (
        f"expected exactly 1 {event_type} trace row, got {len(matching)}"
    )
    assert matching[0]["trace_event_id"] == tev_id
    assert matching[0]["trace_event_id"] is not None

    # No duplicate — the mixed journal also shows it, but only once per event.
    all_rows = sm.get_events(run_id)
    typed = [r for r in all_rows if r["event_type"] == event_type]
    assert len(typed) == 1, (
        f"expected exactly 1 {event_type} in get_events, got {len(typed)}"
    )
