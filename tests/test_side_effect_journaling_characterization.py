"""v2.97 — Orchestrator Side-Effect Journaling Characterization Harness.

Freezes the orchestrator-integrated side-effect journaling path. The
StateManager characterization tests (test_state_manager_characterization.py)
freeze the store directly; these tests freeze what actually happens when the
orchestrator runs a chain that has declared side effects — the
``_journal_planned_side_effects`` → ``_journal_one`` →
``record_side_effect`` / ``update_side_effect_status`` lifecycle as exercised
by a real orchestrator run against the mock 12-node research chain.

Asserts CURRENT OBSERVED BEHAVIOR, not ideal behavior. Notable findings
captured by these tests:

* The mock chain journals side effects as ``started`` pre-call and NEVER
  advances them to ``completed`` (the mock does not perform real external
  calls, and the success path does not call ``update_side_effect_status``
  with ``"completed"``). So "completed" side effects are NOT observable
  after a successful mock run — only ``started`` is.
* ``SIDE_EFFECT_STARTED`` is emitted during pre-call journaling, which runs
  BEFORE ``_invoke_node`` emits ``NODE_INVOKED``. So ``SIDE_EFFECT_STARTED``
  precedes ``NODE_INVOKED`` (the reverse of a naive "started after invoked"
  guess).
* On node failure after a side effect is started, the side effect stays
  ``started`` (no transition to ``failed`` or ``completed``).

If a future orchestrator extraction changes any of this, these tests fail —
which makes the extraction safe without audit drift.

Test style: temp StateManager via tmp_path; ``asyncio.run()`` (not
``get_event_loop()``, which breaks in full-suite context — learned in v2.91).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

# Reuse the canonical mock chain from test_runtime
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime import MockNode, _create_mock_nodes

from nodechain.core.blueprint import load_blueprint
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator


# ─── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def blueprint():
    return load_blueprint("blueprints/research_decision_v1.yaml")


@pytest.fixture
def nodes():
    return _create_mock_nodes()


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "se_journal.db")


@pytest.fixture
def orchestrator(blueprint, nodes, db_path):
    sm = StateManager(db_path=db_path)
    return Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)


def _run(orch: Orchestrator, query: str = "test query"):
    """Helper: run the orchestrator synchronously via asyncio.run."""
    return asyncio.run(orch.run(query))


def _event_types(trace):
    """Extract ordered list of event_type strings from a trace."""
    return [e.event_type for e in trace.events]


def _index_of(trace, event_type):
    """Return the index of the first event with the given event_type, or -1."""
    for i, e in enumerate(trace.events):
        if e.event_type == event_type:
            return i
    return -1


def _search_side_effects(sm: StateManager, run_id: str):
    """Return ledger rows whose node_id is the search node."""
    return [se for se in sm.get_side_effects(run_id) if se.get("node_id") == "search_tool"]


# ─── 1. Declared side-effect lifecycle (planned → started → completed) ─────

class TestDeclaredSideEffectLifecycle:
    """After running the mock chain, the search node's side effects are in the ledger."""

    def test_search_node_records_at_least_one_side_effect(self, orchestrator, db_path):
        """The search_tool node declares external_call; at least one row is recorded."""
        trace = _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1, (
            f"expected >=1 side effect for search_tool, got {len(search_ses)}; "
            f"all side effects: {sm.get_side_effects(run_id)}"
        )

    def test_side_effects_have_valid_status(self, orchestrator, db_path):
        """Recorded side effects must be in a known lifecycle status.

        Observed: the mock chain journals as 'started' pre-call and never
        advances to 'completed' (the mock doesn't perform real external calls
        and the success path doesn't call update_side_effect_status with
        'completed'). So 'started' is the expected observable status.
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1

        valid_statuses = {"planned", "started", "completed", "failed", "unknown"}
        for se in search_ses:
            assert se["status"] in valid_statuses, (
                f"side effect {se.get('idempotency_key')} has invalid status "
                f"{se['status']!r}"
            )
            # v3.4.0: the canonical mock search_tool now reports observed
            # completion, so search side effects are 'completed'. (Previously
            # v2.97 characterized the gap as 'started'.) Memory_write effects
            # remain 'started' — they have no completion report in v3.0.
            assert se["status"] == "completed", (
                f"expected 'completed' (canonical mock reports completion in v3.0), "
                f"got {se['status']!r} for key {se.get('idempotency_key')}"
            )

    def test_search_side_effect_idempotency_key_format(self, orchestrator, db_path):
        """Search-type side effects use the canonical ``search:<adapter>:<hash>`` key.

        Derived in ``_journal_search_operations`` from the envelope's
        ``search_queries`` payload. The mock context_selector emits one query
        targeting ``semantic_scholar``, so the key starts with ``search:``.
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1

        for se in search_ses:
            key = se["idempotency_key"]
            assert key.startswith("search:"), (
                f"search side-effect key should start with 'search:', got {key!r}"
            )

    def test_side_effect_type_is_canonical_external_call(self, orchestrator, db_path):
        """The declared ``external_call`` is normalized to canonical form in the ledger.

        ``normalize_side_effect_type`` maps both ``external_call`` and
        ``external_api_read`` to the canonical ``external_call``.
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1

        for se in search_ses:
            assert se["side_effect_type"] == "external_call", (
                f"expected canonical 'external_call', got "
                f"{se['side_effect_type']!r}"
            )

    def test_side_effect_records_step_id_and_request_hash(self, orchestrator, db_path):
        """Each journaled side effect carries step_id and a non-empty request_hash."""
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1

        for se in search_ses:
            assert se["step_id"] is not None
            assert isinstance(se["step_id"], int)
            assert se["step_id"] >= 1
            # request_hash is derived from the operation dict (terms/max/filters)
            assert se.get("request_hash"), (
                f"expected non-empty request_hash for key {se['idempotency_key']}"
            )


# ─── 2. Failure-path lifecycle ─────────────────────────────────────────────

class TestFailurePathLifecycle:
    """When a node fails after a side effect is planned/started."""

    def test_failing_search_node_returns_trace_not_exception(self, blueprint, db_path):
        """A chain where search_tool raises must return a trace, never raise."""
        nodes = _create_mock_nodes()
        bad_node = nodes.get("search_tool")
        assert bad_node is not None
        bad_node._output_transform = lambda payload, envelope: (_ for _ in ()).throw(
            RuntimeError("intentional side-effect failure-path characterization")
        )

        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = _run(orch)
        assert trace is not None
        # Trace is always returned, never raises. Final status is failed or
        # (rarely) completed if the failure manager recovers — assert both
        # are acceptable observable outcomes; the key assertion is "no raise".
        assert trace.final_status in ("failed", "completed")

    def test_failing_search_node_side_effect_not_completed(self, blueprint, db_path):
        """On search_tool failure, its side effect stays 'started' (not 'completed').

        The failure path calls ``_fail_chain`` without invoking
        ``update_side_effect_status(..., "completed")``, so the pre-call
        journaled side effect remains in its post-journal state.
        """
        nodes = _create_mock_nodes()
        bad_node = nodes.get("search_tool")
        assert bad_node is not None
        bad_node._output_transform = lambda payload, envelope: (_ for _ in ()).throw(
            RuntimeError("intentional side-effect failure-path characterization")
        )

        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = _run(orch)
        run_id = orch.state.run_id

        # The side effect must have been journaled pre-call before the failure.
        search_ses = _search_side_effects(sm, run_id)
        if len(search_ses) == 0:
            # If the failure manager short-circuited before journaling, there's
            # nothing to assert about completion. Skip gracefully.
            pytest.skip("no side effects were journaled before failure (short-circuit)")

        for se in search_ses:
            assert se["status"] != "completed", (
                f"side effect {se['idempotency_key']} should NOT be 'completed' "
                f"after node failure; got {se['status']!r}"
            )
            # Observed: stays 'started' (the pre-call journal status).
            assert se["status"] in ("started", "planned", "failed", "unknown"), (
                f"unexpected status {se['status']!r}"
            )

    def test_failing_downstream_node_leaves_upstream_side_effects_started(
        self, blueprint, db_path,
    ):
        """When a node AFTER search_tool fails, search_tool's side effects stay 'started'.

        search_tool succeeds (side effects journaled 'started'), then a
        downstream node (evidence_synthesizer) fails. The search side effects
        are never advanced to 'completed'.
        """
        nodes = _create_mock_nodes()
        bad_node = nodes.get("evidence_synthesizer")
        assert bad_node is not None
        bad_node._output_transform = lambda payload, envelope: (_ for _ in ()).throw(
            RuntimeError("intentional downstream failure characterization")
        )

        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = _run(orch)
        run_id = orch.state.run_id

        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1, (
            "search_tool ran successfully before the downstream failure; "
            "its side effects must be in the ledger"
        )
        for se in search_ses:
            # v3.4.0: search_tool succeeds and reports observed completion
            # BEFORE the downstream (evidence_synthesizer) failure, so its
            # side effects are 'completed'. The downstream failure does not
            # unwind the already-observed completion.
            assert se["status"] == "completed", (
                f"search side effect should be 'completed' after search_tool "
                f"reports, even with a later downstream failure; got {se['status']!r}"
            )


# ─── 3. Trace event ordering ───────────────────────────────────────────────

class TestTraceEventOrdering:
    """Side-effect trace events appear in the correct order relative to node events."""

    def test_side_effect_started_precedes_node_invoked(self, orchestrator):
        """SIDE_EFFECT_STARTED is emitted during pre-call journaling, BEFORE NODE_INVOKED.

        ``_journal_planned_side_effects`` runs before ``_invoke_node`` (which
        emits NODE_INVOKED). So SIDE_EFFECT_STARTED precedes NODE_INVOKED for
        the search_tool node. This is the ACTUAL observed ordering — the
        reverse of a naive "started after invoked" guess.
        """
        trace = _run(orchestrator)
        types = _event_types(trace)

        assert "side_effect_started" in types, (
            f"no side_effect_started in trace; event types: {types[:15]}"
        )

        # Find the SIDE_EFFECT_STARTED event for the search_tool node.
        se_started_idx = None
        node_invoked_search_idx = None
        for i, e in enumerate(trace.events):
            if (e.event_type == "side_effect_started"
                    and e.node_id == "search_tool"
                    and se_started_idx is None):
                se_started_idx = i
            if (e.event_type == "node_invoked"
                    and e.node_id == "search_tool"
                    and node_invoked_search_idx is None):
                node_invoked_search_idx = i

        assert se_started_idx is not None, (
            "no SIDE_EFFECT_STARTED event for search_tool in trace"
        )
        assert node_invoked_search_idx is not None, (
            "no NODE_INVOKED event for search_tool in trace"
        )
        # Observed: pre-call journaling emits SIDE_EFFECT_STARTED before
        # _invoke_node emits NODE_INVOKED.
        assert se_started_idx < node_invoked_search_idx, (
            f"SIDE_EFFECT_STARTED (idx {se_started_idx}) must precede "
            f"NODE_INVOKED for search_tool (idx {node_invoked_search_idx})"
        )

    def test_node_succeeded_precedes_chain_completed(self, orchestrator):
        """NODE_SUCCEEDED for search_tool comes before CHAIN_COMPLETED."""
        trace = _run(orchestrator)

        node_succeeded_search_idx = None
        chain_completed_idx = None
        for i, e in enumerate(trace.events):
            if (e.event_type == "node_succeeded"
                    and e.node_id == "search_tool"
                    and node_succeeded_search_idx is None):
                node_succeeded_search_idx = i
            if (e.event_type == "chain_completed"
                    and chain_completed_idx is None):
                chain_completed_idx = i

        assert node_succeeded_search_idx is not None
        assert chain_completed_idx is not None
        assert node_succeeded_search_idx < chain_completed_idx

    def test_side_effect_started_precedes_node_succeeded(self, orchestrator):
        """SIDE_EFFECT_STARTED (pre-call) comes before NODE_SUCCEEDED for search_tool.

        Since the mock never emits SIDE_EFFECT_COMPLETED, the only side-effect
        event is SIDE_EFFECT_STARTED, which must precede NODE_SUCCEEDED.
        """
        trace = _run(orchestrator)

        se_started_idx = None
        node_succeeded_search_idx = None
        for i, e in enumerate(trace.events):
            if (e.event_type == "side_effect_started"
                    and e.node_id == "search_tool"
                    and se_started_idx is None):
                se_started_idx = i
            if (e.event_type == "node_succeeded"
                    and e.node_id == "search_tool"
                    and node_succeeded_search_idx is None):
                node_succeeded_search_idx = i

        assert se_started_idx is not None
        assert node_succeeded_search_idx is not None
        assert se_started_idx < node_succeeded_search_idx

    def test_chain_completed_is_last_event(self, orchestrator):
        """CHAIN_COMPLETED is the final event in the trace."""
        trace = _run(orchestrator)
        types = _event_types(trace)
        assert len(types) > 0
        assert types[-1] == "chain_completed", (
            f"expected 'chain_completed' as last event, got {types[-1]!r}; "
            f"tail: {types[-5:]}"
        )

    def test_side_effect_completed_emitted_in_mock_chain(self, orchestrator):
        """v3.4.0: the canonical mock chain DOES emit SIDE_EFFECT_COMPLETED.

        The canonical mock search_tool now reports observed completion via
        output["side_effect_records"], so SIDE_EFFECT_COMPLETED is emitted.
        (v2.97 characterized the gap as absent; v3.0 closes it for search.)
        """
        trace = _run(orchestrator)
        types = _event_types(trace)
        assert "side_effect_completed" in types, (
            "canonical mock chain should emit side_effect_completed in v3.0 "
            f"(search reports observed completion); got {set(types)}"
        )


# ─── 4. Resume-visible ledger state ────────────────────────────────────────

class TestResumeVisibleLedgerState:
    """The side-effect ledger is queryable for resume/recovery after a run."""

    def test_started_side_effects_visible_by_status(self, orchestrator, db_path):
        """``get_side_effects_by_status(run_id, "started")`` returns search side effects.

        After a successful mock run, search side effects remain 'started'
        (see TestDeclaredSideEffectLifecycle), so they're visible via this
        query — which is the resume/recovery entry point for detecting
        started-but-not-completed effects.
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        started = sm.get_side_effects_by_status(run_id, "started")
        # v3.4.0: search_tool effects are now completed; memory_write has no
        # completion report and remains started. Assert memory_write is the
        # node that stays visible under the 'started' query.
        memory_started = [se for se in started if se.get("node_id") == "memory_write_decision"]
        assert len(memory_started) >= 1, (
            "expected >=1 started side effect for memory_write_decision (no report in v3.0); "
            f"got {len(memory_started)}"
        )

    def test_search_completed_side_effects_present_after_mock_run(self, orchestrator, db_path):
        """v3.4.0: after a successful mock run, search side effects ARE completed.

        The canonical mock search_tool reports observed completion, so the
        completed set is non-empty for search_tool. memory_write effects
        remain 'started' (no report in v3.0).
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        completed = sm.get_side_effects_by_status(run_id, "completed")
        search_completed = [se for se in completed if se.get("node_id") == "search_tool"]
        assert len(search_completed) >= 1, (
            "expected >=1 completed search side effect in v3.0; "
            f"got {len(search_completed)} (all completed: {completed})"
        )

    def test_ledger_rows_have_consistent_fields(self, orchestrator, db_path):
        """Every ledger row has node_id, step_id, status, idempotency_key, type."""
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        all_ses = sm.get_side_effects(run_id)
        assert len(all_ses) >= 1, "no side effects in ledger after run"

        for se in all_ses:
            for field in ("node_id", "step_id", "status", "idempotency_key",
                          "side_effect_type"):
                assert field in se, (
                    f"ledger row missing required field {field!r}: {se}"
                )
                assert se[field] is not None, (
                    f"ledger row field {field!r} is None: {se}"
                )
            assert se["status"] in ("planned", "started", "completed",
                                    "failed", "unknown")
            assert isinstance(se["step_id"], int)
            assert se["step_id"] >= 1

    def test_ledger_includes_memory_write_side_effect(self, orchestrator, db_path):
        """The memory_write_decision node also journals a side effect.

        Its key format is ``memory_write_decision:memory_write:<step_id>``
        (the reservation key), also journaled as 'started'.
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        all_ses = sm.get_side_effects(run_id)
        memory_ses = [se for se in all_ses
                      if se.get("node_id") == "memory_write_decision"]
        assert len(memory_ses) >= 1, (
            "expected >=1 side effect for memory_write_decision"
        )
        for se in memory_ses:
            assert se["idempotency_key"].startswith("memory_write_decision:"), (
                f"memory write key should start with 'memory_write_decision:', "
                f"got {se['idempotency_key']!r}"
            )
            assert se["side_effect_type"] == "memory_write"
            # v3.4.0: still 'started' — memory_write has no completion report
            # path in v3.0 (deferred). Only external_call (search) reports.
            assert se["status"] == "started"
