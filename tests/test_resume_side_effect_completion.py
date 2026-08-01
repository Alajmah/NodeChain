"""v3.4.0 — Resume-path observed side-effect completion tests.

v3.0 wired observed completion into run()'s post-call seam only. v3.1 wires
the same controller into resume()'s post-call seam for freshly re-executed
nodes (Case A1: a node whose side-effect key is genuinely new because the
crash happened before it ever journaled).

Case A2 (crash-window ``unknown`` effects) is OUT OF SCOPE for v3.1: those
effects cannot reach ``completed`` without a recovery-decision write path
that does not exist yet. See TestResumeUnknownEffectCharacterization.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime import MockNode, _create_mock_nodes

from nodechain.core.blueprint import load_blueprint
from nodechain.core.side_effect_utils import (
    compute_side_effect_request_hash, make_canonical_search_key,
)
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator


# ─── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def blueprint():
    return load_blueprint("blueprints/research_decision_v1.yaml")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "se_resume.db")


def _run(orch, query="test query"):
    return asyncio.run(orch.run(query))


def _resume(orch, run_id):
    return asyncio.run(orch.resume(run_id))


def _search_side_effects(sm, run_id):
    return [se for se in sm.get_side_effects(run_id) if se.get("node_id") == "search_tool"]


class _FatalFailureManager:
    """Test-only FailureManager stand-in that never recovers a failure.

    The production FailureManager._handle_unknown returns
    ``FailureResult(recovered=True, ...)`` after a retry EVEN WHEN the retry
    response itself failed (response.success == False) — a pre-existing
    quirk where the retry's failure envelope is treated as a recovered
    result. That swallowing behavior lets execution proceed PAST the crashed
    node (e.g. context_selector) into search_tool, which then journals its
    side effect pre-crash and defeats the A1 setup.

    For the A1 scenario we need the crash to be genuinely fatal so that
    search_tool NEVER executes pre-crash (its side-effect key must be
    fresh on resume). This stand-in expresses that test intent directly:
    every failure is terminal, the chain fails at the crashed node, and
    nothing downstream runs. The real orchestrator code path
    (classify_failure → handle → _fail_chain on recovered=False) is still
    exercised; only the recovery decision is overridden.
    """

    def __init__(self, real):
        self._real = real
        # Several orchestrator paths read/write _retry_counts; mirror the
        # real attribute so attribute access does not AttributeError.
        self._retry_counts = {}

    def classify_failure(self, error, context):
        return self._real.classify_failure(error, context)

    async def handle(self, failure_type, node, envelope, error, state, invoke_fn=None):
        from nodechain.runtime.failure_manager import FailureResult
        return FailureResult(recovered=False, action="test_fatal_no_recovery")

    async def route_fallback(self, *args, **kwargs):
        from nodechain.runtime.failure_manager import FailureResult
        return FailureResult(recovered=False, action="test_fatal_no_recovery")


def _crash_after_predecessor_of_search(db_path, blueprint):
    """Build a run where search_tool NEVER executes (fatal crash in context_selector).

    context_selector runs BEFORE search_tool (positions 3 and 4 in
    ``blueprints/research_decision_v1.yaml``), so a fatal crash in
    context_selector guarantees search_tool never journals its side effect
    pre-crash. On resume (with context_selector restored), search_tool
    executes fresh → its side-effect key is genuinely new (A1).

    The crash is made fatal by replacing ``orch.failure_manager`` with a
    ``_FatalFailureManager`` stand-in (see its docstring for why the
    production FailureManager cannot be used here).

    Returns (orch_failed_trace, run_id, nodes). The caller reuses the SAME
    nodes dict (with context_selector restored) and constructs a fresh
    Orchestrator pointing at the same db_path for resume.
    """
    nodes = _create_mock_nodes()
    cs_node = nodes["context_selector"]
    real_transform = cs_node._output_transform
    cs_node._output_transform = lambda payload: (_ for _ in ()).throw(
        RuntimeError("intentional crash-before-search for v3.1 resume test")
    )
    sm = StateManager(db_path=db_path)
    orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
    # Make the crash genuinely fatal so search_tool never runs pre-crash.
    # (See _FatalFailureManager docstring.) Restored implicitly by using a
    # fresh Orchestrator for resume — the production FailureManager handles
    # the resume path, where no crash occurs.
    orch.failure_manager = _FatalFailureManager(orch.failure_manager)
    trace = _run(orch)
    run_id = orch.state.run_id
    cs_node._output_transform = real_transform
    return trace, run_id, nodes


# ─── 1. Resume-path completion (A1: fresh key) ────────────────────────────

class TestResumePathCompletion:
    def test_fresh_resumed_node_valid_report_marks_completed(self, blueprint, db_path):
        """A1: resume re-executes search_tool (never ran pre-crash).

        search_tool's side effect is genuinely fresh. Resume journals it
        ``started``, the node reports completion, and the resume post-call
        seam marks it ``completed`` — identical to v3.0's run() path.
        """
        trace, run_id, nodes = _crash_after_predecessor_of_search(db_path, blueprint)
        assert trace.final_status == "failed"  # the crash failed the run

        # Harness precondition: search_tool journaled NOTHING pre-crash.
        sm_pre = StateManager(db_path=db_path)
        pre_search = _search_side_effects(sm_pre, run_id)
        assert pre_search == [], (
            f"harness precondition violated: search_tool side effects existed "
            f"pre-crash ({pre_search!r}); the crash-before-search construction "
            f"did not produce the intended A1 state."
        )

        sm = StateManager(db_path=db_path)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace2 = _resume(orch2, run_id)

        sm2 = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm2, run_id)
        assert len(search_ses) >= 1, (
            f"expected search side effects after resume; got {sm2.get_side_effects(run_id)}"
        )
        completed = [se for se in search_ses if se["status"] == "completed"]
        assert len(completed) >= 1, (
            f"v3.1: fresh resumed search effect should be completed; got statuses "
            f"{[se['status'] for se in search_ses]}"
        )

    def test_resume_node_absent_report_leaves_effect_started(self, blueprint, db_path):
        """Resume node with NO completion report ⇒ effect stays started.

        Uses a NON-reporting search transform during resume (the legacy mock).
        Proves the resume seam preserves the v3.0 legacy invariant: no report
        ⇒ no completion, no inference.
        """
        from test_observed_side_effect_completion import _legacy_search_transform
        trace, run_id, nodes = _crash_after_predecessor_of_search(db_path, blueprint)
        assert trace.final_status == "failed"

        nodes["search_tool"]._output_transform = _legacy_search_transform

        sm = StateManager(db_path=db_path)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        _resume(orch2, run_id)

        sm2 = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm2, run_id)
        assert len(search_ses) >= 1
        for se in search_ses:
            assert se["status"] == "started", (
                f"resume: absent report should leave effect 'started'; got {se['status']!r}"
            )

    def test_resume_node_invalid_report_fails_cleanly(self, blueprint, db_path):
        """Resume node with an INVALID completion report ⇒ failed trace, no raise.

        The report references a key that doesn't match any ledger row. The resume
        post-call seam must fail the chain via the existing soft-fail path
        (CONTRACT_VIOLATION + _fail_chain), not raise an exception.
        """
        trace, run_id, nodes = _crash_after_predecessor_of_search(db_path, blueprint)
        assert trace.final_status == "failed"

        nodes["search_tool"]._output_transform = lambda payload: {
            "results": [],
            "total_found": 0,
            "adapters_called": ["semantic_scholar"],
            "adapters_failed": [],
            "side_effect_records": [{
                "side_effect_key": "search:semantic_scholar:nonexistent0001",
                "side_effect_type": "external_call",
                "status": "completed",
                "observed_by": "node",
                "observed_at": "2026-07-08T00:00:00Z",
                "response_hash": "rh-bad",
            }],
        }

        sm = StateManager(db_path=db_path)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace2 = _resume(orch2, run_id)  # must not raise
        assert trace2 is not None
        assert trace2.final_status == "failed"

    def test_resume_node_success_does_not_imply_completion(self, blueprint, db_path):
        """Node success during resume does NOT imply side-effect completion.

        Uses the legacy (non-reporting) transform: search_tool succeeds, but
        without a completion report its effect stays 'started'.
        """
        from test_observed_side_effect_completion import _legacy_search_transform
        trace, run_id, nodes = _crash_after_predecessor_of_search(db_path, blueprint)
        assert trace.final_status == "failed"

        nodes["search_tool"]._output_transform = _legacy_search_transform
        sm = StateManager(db_path=db_path)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace2 = _resume(orch2, run_id)

        sm2 = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm2, run_id)
        if search_ses:
            assert all(se["status"] != "completed" for se in search_ses), (
                "resume: node success must not imply completion without a report"
            )


# ─── 2. Crash-window unknown-effect characterization (Case A2) ────────────

def _crash_during_search_then_resume(db_path, blueprint):
    """A2: search journaled 'started' in run(), crashed, now 'unknown'.

    run() with search_tool's _output_transform throwing AFTER pre-call
    journaling. The run fails. On resume, _reconcile_side_effects_on_resume
    marks the 'started' effect 'unknown'. Resume re-executes search_tool
    (fixed), journals the SAME key — _journal_one finds the existing 'unknown'
    row and leaves it. The completion report is rejected
    (reason="completion_requires_started_status").

    Returns (run_id, nodes).
    """
    nodes = _create_mock_nodes()
    search_node = nodes["search_tool"]
    real_transform = search_node._output_transform
    search_node._output_transform = lambda payload: (_ for _ in ()).throw(
        RuntimeError("intentional crash-during-search for v3.1 A2 characterization")
    )
    sm = StateManager(db_path=db_path)
    orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
    trace = _run(orch)
    run_id = orch.state.run_id
    search_node._output_transform = real_transform
    return run_id, nodes


class TestResumeUnknownEffectCharacterization:
    """v3.1 OUT-OF-SCOPE characterization: crash-window unknown effects.

    Documents the CURRENT rejected/unchanged behavior: crash-window ``unknown``
    side effects do NOT reach ``completed`` in v3.1. This is a known limitation,
    not a bug. Completing an ``unknown`` effect requires a recovery-decision
    write path that does not exist yet (no production caller of
    record_recovery_decision). v3.2 will address the recovery-decision design.

    The assertion is CURRENT behavior (rejected/unchanged), NOT an ideal future
    behavior. Do not write this test as if unknown→completed should work.
    """

    def test_unknown_effect_not_silently_completed_after_resume(self, blueprint, db_path):
        """A2: a crash-window 'unknown' effect is NOT completed by resume.

        Current-behavior claim: when a side effect crossed the crash window as
        'unknown', resume re-execution + a normal completion report does NOT
        transition it to 'completed'. The v3.0 validation rule rejects
        completion of non-'started' effects. Deferred to v3.2.
        """
        run_id, nodes = _crash_during_search_then_resume(db_path, blueprint)

        sm = StateManager(db_path=db_path)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace2 = _resume(orch2, run_id)

        sm2 = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm2, run_id)
        # CURRENT behavior: NO effect that was 'unknown' silently became
        # 'completed' via the resume completion path. Either:
        #   (a) the unknown row is still 'unknown'/'started' (re-execution
        #       collided on key, completion report rejected), or
        #   (b) the run failed on the rejected report.
        unknown_or_unresolved = [
            se for se in search_ses if se["status"] in ("unknown", "started")
        ]
        assert len(unknown_or_unresolved) >= 1 or trace2.final_status == "failed", (
            "v3.1 characterization: expected either an unresolved (unknown/started) "
            f"search effect or a failed resume trace; got statuses "
            f"{[se['status'] for se in search_ses]}, trace={trace2.final_status}"
        )
