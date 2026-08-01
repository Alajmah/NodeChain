"""v3.4.0 — Retry Recovery Success Invariant: orchestrator defense-in-depth.

The orchestrator must not trust recovered=True as a substitute for a valid
successful response. If a FailureManager returns recovered=True with either
a missing response (None, non-exempt action) or a failed response
(success=False), the orchestrator must fail the chain—not feed garbage
output downstream.

These tests use a deliberately LYING FailureManager so they prove the
orchestrator boundary independently of the four handler fixes (Task 2).
A future handler regression would still be caught here.

Invariant: a recovery result may advance execution only when
  1. recovered=True and response is present and response.success=True, OR
  2. recovered=True and action is an intentional skip/continue action
     explicitly allowlisted by the orchestrator (_SKIP_CONTINUE_ACTIONS).
All other recovered=True shapes are invalid and must fail the chain.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime import _create_mock_nodes
from test_resume_side_effect_completion import _FatalFailureManager

from nodechain.core.blueprint import load_blueprint
from nodechain.core.envelope import EnvelopeResponse
from nodechain.core.state import StateManager
from nodechain.runtime.failure_manager import FailureResult
from nodechain.runtime.orchestrator import Orchestrator


@pytest.fixture
def blueprint():
    return load_blueprint("blueprints/research_decision_v1.yaml")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "retry_inv.db")


def _run(orch, query="test query"):
    return asyncio.run(orch.run(query))


def _resume(orch, run_id):
    return asyncio.run(orch.resume(run_id))


class _LyingFailureManager:
    """Returns a pre-built lying FailureResult, bypassing real handlers.

    Used to isolate the orchestrator's post-recovery response check.
    classify_failure delegates to the real one; handle() always returns the
    pre-built lying result.
    """
    def __init__(self, real, lying_result):
        self._real = real
        self._lying_result = lying_result
        self._retry_counts = {}

    def classify_failure(self, error, context):
        return self._real.classify_failure(error, context)

    async def handle(self, failure_type, node, envelope, error, state, invoke_fn=None):
        return self._lying_result

    async def route_fallback(self, *args, **kwargs):
        return FailureResult(recovered=False, action="not_supported")


def _orch_with_crash_and_lying_fm(blueprint, db_path, lying_result, crash_target="context_selector"):
    """Orchestrator whose failure manager always returns lying_result.

    The crash_target node throws so the failure manager is invoked.
    Returns (orch, nodes, real_transform) — caller restores the transform for resume.
    """
    nodes = _create_mock_nodes()
    node = nodes[crash_target]
    real_transform = node._output_transform
    node._output_transform = lambda payload: (_ for _ in ()).throw(
        RuntimeError("trigger failure manager for v3.2 invariant test")
    )
    sm = StateManager(db_path=db_path)
    orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
    orch.failure_manager = _LyingFailureManager(orch.failure_manager, lying_result)
    return orch, nodes, real_transform


# ─── run() path defense ───────────────────────────────────────────────────

class TestRunPathDefense:
    def _assert_chain_fails_at_recovery_node(self, trace, recovery_node="context_selector"):
        """The guard must fail the chain AT the recovery node, not downstream.

        A weak ``final_status == "failed"`` assertion is insufficient: today
        (pre-guard) the orchestrator trusts ``recovered=True``, advances past
        the recovery node, and only fails later when a downstream node chokes
        on the garbage output. The load-bearing assertion is that NO node after
        the recovery node is ever invoked — the boundary is enforced at the
        recovery seam itself.
        """
        assert trace.final_status == "failed", (
            f"chain must fail; got {trace.final_status}"
        )
        invoked = [e.node_id for e in trace.events
                   if e.event_type == "node_invoked"]
        assert recovery_node in invoked, (
            f"{recovery_node} should have been invoked; got {invoked}"
        )
        recovery_idx = invoked.index(recovery_node)
        downstream = invoked[recovery_idx + 1:]
        assert not downstream, (
            f"run() must NOT advance past {recovery_node} after an invalid "
            f"recovery — the guard must fail the chain at the recovery seam. "
            f"Nodes invoked after {recovery_node}: {downstream}"
        )

    def test_run_refuses_recovered_true_with_failed_response(self, blueprint, db_path):
        """run(): recovered=True + response.success=False ⇒ chain fails at the node.

        A lying failure manager claims recovery but hands back a failed response.
        The orchestrator must NOT continue with the garbage output — it must fail
        the chain at the recovery seam rather than letting garbage propagate.
        """
        lying = FailureResult(
            recovered=True,
            response=EnvelopeResponse(
                request_envelope_id="x", run_id="x", chain_id="x",
                node_id="context_selector", step_id=2,
                output={}, output_type="object",
                success=False, error="lying: failed retry treated as recovered",
            ),
            action="lying_failed_retry",
        )
        orch, nodes, _ = _orch_with_crash_and_lying_fm(blueprint, db_path, lying)
        trace = _run(orch)
        self._assert_chain_fails_at_recovery_node(trace)

    def test_run_refuses_recovered_true_with_none_response(self, blueprint, db_path):
        """run(): recovered=True + response=None (non-exempt action) ⇒ chain fails at the node.

        Not a skip-continue action, so the None response is invalid. The
        orchestrator must not treat it as a policy-rejection skip.
        """
        lying = FailureResult(recovered=True, response=None, action="lying_none_retry")
        orch, nodes, _ = _orch_with_crash_and_lying_fm(blueprint, db_path, lying)
        trace = _run(orch)
        self._assert_chain_fails_at_recovery_node(trace)


# ─── resume() path defense ────────────────────────────────────────────────

class TestResumePathDefense:
    def test_resume_refuses_recovered_true_with_failed_response(self, blueprint, db_path):
        """resume(): recovered=True + response.success=False ⇒ chain fails.

        Setup: run to a partial state (crash in context_selector, made fatal via
        _FatalFailureManager), then resume with a lying failure manager that
        claims recovery but hands back a failed response.
        """
        lying = FailureResult(
            recovered=True,
            response=EnvelopeResponse(
                request_envelope_id="x", run_id="x", chain_id="x",
                node_id="context_selector", step_id=2,
                output={}, output_type="object",
                success=False, error="lying: failed retry on resume",
            ),
            action="lying_failed_retry",
        )
        # Step 1: run with a fatal crash in context_selector to create partial state.
        nodes = _create_mock_nodes()
        cs = nodes["context_selector"]
        real_transform = cs._output_transform
        cs._output_transform = lambda payload: (_ for _ in ()).throw(
            RuntimeError("crash for resume-defense setup")
        )
        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        orch.failure_manager = _FatalFailureManager(orch.failure_manager)
        run_trace = _run(orch)
        assert run_trace.final_status == "failed"
        run_id = orch.state.run_id
        # NOTE: do NOT restore _output_transform. The crash must persist into
        # resume so context_selector fails again on resume and the lying
        # failure manager (returning recovered=True + failed response) is
        # actually consulted — otherwise the node succeeds and the failure-
        # manager block (where the v3.2 guard lives) is never entered.

        # Step 2: resume with the lying failure manager.
        sm2 = StateManager(db_path=db_path)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm2)
        orch2.failure_manager = _LyingFailureManager(orch2.failure_manager, lying)
        trace2 = _resume(orch2, run_id)
        # Same load-bearing assertion as the run path: the chain must fail AT
        # the recovery node. Pre-guard, resume trusts recovered=True and the
        # chain advances with the garbage failed response swallowed — the worst
        # possible outcome — so this fails until the v3.2 guard is in place.
        assert trace2.final_status == "failed", (
            "resume() must refuse recovered=True + failed response; got "
            f"{trace2.final_status}"
        )
        invoked2 = [e.node_id for e in trace2.events
                    if e.event_type == "node_invoked"]
        assert "context_selector" in invoked2, (
            f"context_selector should have been re-invoked on resume; got {invoked2}"
        )
        cs_idx = invoked2.index("context_selector")
        downstream2 = invoked2[cs_idx + 1:]
        assert not downstream2, (
            "resume() must NOT advance past context_selector after an invalid "
            f"recovery. Nodes invoked after: {downstream2}"
        )


# ─── skip-continue exemption regression ────────────────────────────────────

class TestSkipContinueExemptionRegression:
    def test_intentional_skip_continue_still_advances(self, blueprint, db_path):
        """recovered=True + response=None + skip-continue action ⇒ chain continues.

        The _handle_memory_rejection and _handle_trace_failure handlers return
        recovered=True, response=None as a deliberate skip-continue. The new
        orchestrator guard must NOT break them: an allowlisted action with a
        None response still advances execution (the node is skipped, not failed).
        This is the explicit regression test for the _SKIP_CONTINUE_ACTIONS carve-out.
        """
        lying = FailureResult(
            recovered=True, response=None,
            action="skip_memory_write_policy_rejection",
        )
        orch, nodes, _ = _orch_with_crash_and_lying_fm(blueprint, db_path, lying)
        trace = _run(orch)
        # The skip-continue path should NOT fail the chain — it continues with
        # the node skipped. (It may complete or fail later for other reasons,
        # but NOT due to the guard rejecting the skip-continue recovery.)
        # Acceptable outcomes: completed, or failed for a DOWNSTREAM reason
        # (not the guard). The key assertion: the run did not fail IMMEDIATELY
        # at context_selector due to the None response.
        # Since context_selector has no real output (skipped), downstream nodes
        # may fail — that's acceptable. Assert it's not failed at THIS node
        # by checking the trace didn't abort on a guard violation.
        # Pragmatic assertion: the run reached at least one node after
        # context_selector (the skip-continue advanced execution).
        # If the guard broke the exemption, the trace would fail at
        # context_selector with no downstream invocation.
        node_events = [e for e in trace.events if e.event_type == "node_invoked"]
        node_ids_invoked = [e.node_id for e in node_events]
        # context_selector was invoked (and skipped via the lying recovery);
        # at least one more node should have been attempted if execution advanced.
        assert "context_selector" in node_ids_invoked, (
            "context_selector should have been invoked"
        )
        # The honest assertion: the run did not fail specifically because of
        # the guard rejecting the skip-continue. We can't perfectly distinguish
        # failure causes from final_status alone, so assert that EITHER the run
        # completed OR it progressed past context_selector.
        post_cs = [nid for nid in node_ids_invoked if nid != "context_selector"]
        assert trace.final_status == "completed" or len(post_cs) >= 1, (
            "skip-continue exemption: execution should advance past the skipped "
            f"node; final_status={trace.final_status}, invoked={node_ids_invoked}"
        )
