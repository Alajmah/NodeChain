"""Tests for review-resume control flow refactoring.

AC1: Review-resume no longer depends on double-break control flow.
AC2: approve resumes from the correct post-review node.
AC3: reject creates terminal failed state with trace continuity.
AC4: request_revision routes through GraphScheduler, not custom logic.
AC5: revision target is explicit and validated.
AC6: review timeout is represented as a decision, not an implicit default.
AC7: resume after review preserves run_id, step allocation, and trace consistency.
AC8: Existing 443 tests remain green.
"""

import os
import pytest
from unittest.mock import MagicMock

from nodechain.core.blueprint import ChainBlueprint, NodeDef, ConnectionDef
from nodechain.core.state import ChainState
from nodechain.core.trace import EventType, Actor
from nodechain.runtime.scheduler import GraphScheduler, SchedulingDecision


def _make_linear_blueprint() -> ChainBlueprint:
    """Simple linear blueprint for review tests."""
    return ChainBlueprint(
        chain_id="review_test_v1", name="Review Test", version="1.0.0",
        goal="Test review flow",
        nodes=[
            NodeDef(node_id="goal_interpreter", node_type="model", position=1),
            NodeDef(node_id="task_planner", node_type="model", position=2),
            NodeDef(node_id="search_tool", node_type="deterministic", position=3),
            NodeDef(node_id="risk_classifier", node_type="deterministic", position=4),
            NodeDef(node_id="response_generator", node_type="model", position=5),
            NodeDef(node_id="trace_collector", node_type="deterministic", position=6),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="task_planner", to_port="input"),
            ConnectionDef(from_node="task_planner", from_port="output", to_node="search_tool", to_port="input"),
            ConnectionDef(from_node="search_tool", from_port="output", to_node="risk_classifier", to_port="input"),
            ConnectionDef(from_node="risk_classifier", from_port="output", to_node="response_generator", to_port="input"),
            ConnectionDef(from_node="response_generator", from_port="output", to_node="trace_collector", to_port="input"),
        ],
    )


class TestSchedulerReviewTransitions:
    """AC4/AC5: Review decisions are scheduler transitions."""

    def test_approve_is_scheduling_decision(self):
        scheduler = GraphScheduler(_make_linear_blueprint())
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("approve", order, "risk_classifier")

        assert isinstance(transition, SchedulingDecision)
        assert transition.action == SchedulingDecision.REVIEW_APPROVE

    def test_revision_target_is_from_scheduler(self):
        """AC5: Revision target is computed by scheduler, not hardcoded."""
        scheduler = GraphScheduler(_make_linear_blueprint())
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision(
            "request_revision", order, "risk_classifier",
        )

        # Scheduler should find the closest model node before risk_classifier
        assert transition.revision_target == "task_planner"
        assert transition.action == SchedulingDecision.REVIEW_REVISION

    def test_explicit_revision_target_overrides_default(self):
        scheduler = GraphScheduler(_make_linear_blueprint())
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision(
            "request_revision", order, "risk_classifier",
            revision_target="goal_interpreter",
        )

        assert transition.revision_target == "goal_interpreter"

    def test_reject_is_terminal(self):
        scheduler = GraphScheduler(_make_linear_blueprint())
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("reject", order, "risk_classifier")
        assert transition.action == SchedulingDecision.REVIEW_REJECT

    def test_timeout_is_explicit_decision(self):
        """AC6: Timeout is a named decision, not an implicit default."""
        scheduler = GraphScheduler(_make_linear_blueprint())
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("timeout", order, "risk_classifier")
        assert transition.action == SchedulingDecision.REVIEW_TIMEOUT
        assert transition.review_decision == "timeout"

    def test_continuation_after_approve(self):
        """AC2: Approve continues from the node after risk_classifier."""
        scheduler = GraphScheduler(_make_linear_blueprint())
        order = scheduler.resolve_execution_order()
        idx = scheduler.find_continuation_point(order, "risk_classifier")
        assert order[idx] == "response_generator"


class TestReviewResumeIntegration:
    """AC1/AC7: Review-resume delegates to resume() without duplication."""

    @pytest.mark.asyncio
    async def test_resume_after_approve_preserves_run_id(self):
        """AC7: Resume after review approval preserves run_id."""
        import asyncio
        import sys
        sys.path.insert(0, "tests")
        from test_runtime import MockNode

        transforms = {
            "goal_interpreter": lambda p: {"primary_question": "q", "research_domain": "general", "success_criteria": ["t"], "domain_classification": []},
            "task_planner": lambda p: {"plan_id": "p", "tasks": [{"task_id": "t1", "description": "t", "query_terms": ["t"], "priority": 1}], "source_routing": {"primary": ["ss"], "secondary": []}},
            "search_tool": lambda p: {"results": [{"origin_api": "ss", "raw_data": {"title": "T"}, "query_used": "t", "retrieved_at": "2026"}], "total_found": 1, "adapters_called": ["ss"], "adapters_failed": []},
            "risk_classifier": lambda p: {"risk_level": "HIGH", "confidence": 0.9, "review_required": True, "risk_factors": [], "uncertainty_disclosures": []},
            "response_generator": lambda p: {"recommendation": "R", "executive_summary": "S", "key_findings": ["F"], "confidence_statement": {"level": "HIGH", "numeric": 0.9}, "citations": []},
            "trace_collector": lambda p: {"trace_id": "t", "events_summary": []},
        }

        blueprint = _make_linear_blueprint()
        from nodechain.core.contract import SideEffect
        _se = {"search_tool": [SideEffect(effect_type="external_call", target="search_apis")]}
        nodes = {nid: MockNode(nid, "any", "any", transforms[nid], side_effects=_se.get(nid, [])) for nid in transforms}

        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        try:
            from nodechain.runtime.orchestrator import Orchestrator
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test review")

            assert trace.final_status == "completed"
            assert trace.run_id == orch.state.run_id

            # Verify review events are present
            review_events = [e for e in trace.events
                             if e.event_type in (EventType.HUMAN_REVIEW_REQUESTED, EventType.HUMAN_REVIEW_COMPLETED)]
            assert len(review_events) >= 1

            # Verify step IDs are monotonic
            step_ids = [e.step_id for e in trace.events if e.step_id > 0]
            if len(step_ids) > 1:
                assert step_ids == sorted(step_ids), f"Non-monotonic steps: {step_ids}"

        finally:
            os.environ.pop("NODECHAIN_REVIEW_MODE", None)

    @pytest.mark.asyncio
    async def test_reject_creates_terminal_state(self):
        """AC3: Reject creates failed terminal state with trace continuity."""
        import sys
        sys.path.insert(0, "tests")
        from test_runtime import MockNode

        transforms = {
            "goal_interpreter": lambda p: {"primary_question": "q", "research_domain": "general", "success_criteria": ["t"], "domain_classification": []},
            "task_planner": lambda p: {"plan_id": "p", "tasks": [{"task_id": "t1", "description": "t", "query_terms": ["t"], "priority": 1}], "source_routing": {"primary": ["ss"], "secondary": []}},
            "search_tool": lambda p: {"results": [{"origin_api": "ss", "raw_data": {"title": "T"}, "query_used": "t", "retrieved_at": "2026"}], "total_found": 1, "adapters_called": ["ss"], "adapters_failed": []},
            "risk_classifier": lambda p: {"risk_level": "HIGH", "confidence": 0.9, "review_required": True, "risk_factors": [], "uncertainty_disclosures": []},
            "response_generator": lambda p: {"recommendation": "R"},
            "trace_collector": lambda p: {"trace_id": "t", "events_summary": []},
        }

        blueprint = _make_linear_blueprint()
        from nodechain.core.contract import SideEffect
        _se = {"search_tool": [SideEffect(effect_type="external_call", target="search_apis")]}
        nodes = {nid: MockNode(nid, "any", "any", transforms[nid], side_effects=_se.get(nid, [])) for nid in transforms}

        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
        try:
            from nodechain.runtime.orchestrator import Orchestrator
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test rejection")

            assert trace.final_status == "failed"

            # Trace continuity: should have started, reviewed, and failed
            event_types = [e.event_type for e in trace.events]
            assert EventType.CHAIN_STARTED in event_types
            assert EventType.CHAIN_FAILED in event_types

            # Review events present
            review_events = [e for e in trace.events
                             if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
            assert len(review_events) >= 1
            assert review_events[0].decision == "reject"

        finally:
            os.environ.pop("NODECHAIN_REVIEW_MODE", None)

    @pytest.mark.asyncio
    async def test_revision_routes_through_scheduler(self):
        """AC4: Revision routes through scheduler transition, not custom logic."""
        import sys
        sys.path.insert(0, "tests")
        from test_runtime import MockNode

        call_count = {"risk": 0}

        def risk_transform(p):
            call_count["risk"] += 1
            if call_count["risk"] == 1:
                # First time: trigger review
                return {"risk_level": "HIGH", "confidence": 0.9, "review_required": True, "risk_factors": [], "uncertainty_disclosures": []}
            else:
                # Second time: pass review
                return {"risk_level": "LOW", "confidence": 0.95, "review_required": False, "risk_factors": [], "uncertainty_disclosures": []}

        transforms = {
            "goal_interpreter": lambda p: {"primary_question": "q", "research_domain": "general", "success_criteria": ["t"], "domain_classification": []},
            "task_planner": lambda p: {"plan_id": "p", "tasks": [{"task_id": "t1", "description": "t", "query_terms": ["t"], "priority": 1}], "source_routing": {"primary": ["ss"], "secondary": []}},
            "search_tool": lambda p: {"results": [{"origin_api": "ss", "raw_data": {"title": "T"}, "query_used": "t", "retrieved_at": "2026"}], "total_found": 1, "adapters_called": ["ss"], "adapters_failed": []},
            "risk_classifier": risk_transform,
            "response_generator": lambda p: {"recommendation": "R", "executive_summary": "S", "key_findings": ["F"], "confidence_statement": {"level": "HIGH", "numeric": 0.9}, "citations": []},
            "trace_collector": lambda p: {"trace_id": "t", "events_summary": []},
        }

        blueprint = _make_linear_blueprint()
        from nodechain.core.contract import SideEffect
        _se = {"search_tool": [SideEffect(effect_type="external_call", target="search_apis")]}
        nodes = {nid: MockNode(nid, "any", "any", transforms[nid], side_effects=_se.get(nid, [])) for nid in transforms}

        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-revision"
        try:
            from nodechain.runtime.orchestrator import Orchestrator
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test revision")

            # Should complete (revision loops back and re-runs with LOW risk)
            assert trace.final_status == "completed"

            # Should have review events
            review_events = [e for e in trace.events
                             if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
            assert len(review_events) >= 1
            assert any(e.decision == "request_revision" for e in review_events)

        finally:
            os.environ.pop("NODECHAIN_REVIEW_MODE", None)
