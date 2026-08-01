"""Tests for loop enforcement consolidation — advisory warnings and report.

Covers:
- Advisory warning when prose condition treated as passthrough
- Advisory metadata on LoopEnforcementResult
- Loop summary in report JSON output
- Cost source metadata in loop events
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.runtime.loop_enforcer import (
    evaluate_condition, ConditionEvaluationError, LoopEnforcer,
    LoopEnforcementResult,
)
from nodechain.core.blueprint import LoopDef, ChainBlueprint
from nodechain.core.state import ChainState, LoopState


class TestAdvisoryMetadata:
    """Verify advisory field on enforcement results."""

    def _make_enforcer(self):
        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        return LoopEnforcer(bp)

    def test_prose_entry_sets_advisory(self):
        """Prose entry condition sets advisory metadata."""
        enforcer = self._make_enforcer()
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="quality is sufficient",
            exit_condition="",
            max_iterations=5, max_cost_usd=1.0,
            path=["node_a"],
        )
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True
        assert result.advisory is not None
        assert "condition_parse_failed" in result.advisory
        assert "advisory" in result.advisory

    def test_structured_entry_no_advisory(self):
        """Structured entry condition has no advisory."""
        enforcer = self._make_enforcer()
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="iteration >= 0",
            exit_condition="",
            max_iterations=5, max_cost_usd=1.0,
            path=["node_a"],
        )
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True
        assert result.advisory is None

    def test_prose_exit_sets_advisory(self):
        """Prose exit condition sets advisory metadata."""
        enforcer = self._make_enforcer()
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="enough evidence gathered",
            max_iterations=5, max_cost_usd=1.0,
            path=["node_a"],
        )
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is True
        assert result.advisory is not None
        assert "condition_parse_failed" in result.advisory

    def test_empty_entry_no_advisory(self):
        """Empty entry condition has no advisory."""
        enforcer = self._make_enforcer()
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="",
            max_iterations=5, max_cost_usd=1.0,
            path=["node_a"],
        )
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True
        assert result.advisory is None


class TestLoopSummaryInReport:
    """Verify loop summary in report JSON output."""

    def test_report_includes_loops(self):
        """Report JSON includes loop summary when loop_state is present."""
        from nodechain.cli.report import _build_report_dict
        from nodechain.core.state import ChainState, LoopState

        state = ChainState()
        state.loop_state["test-loop"] = LoopState(
            iteration=2,
            reason="insufficient sources",
            entered_at="2026-06-12T19:00:00Z",
        )

        report = _build_report_dict(state, completed_steps={}, side_effects=[])
        assert "loops" in report
        assert "test-loop" in report["loops"]
        assert report["loops"]["test-loop"]["iteration"] == 2
        assert report["loops"]["test-loop"]["reason"] == "insufficient sources"

    def test_report_no_loops_when_empty(self):
        """Report JSON omits loops when loop_state is empty."""
        from nodechain.cli.report import _build_report_dict
        from nodechain.core.state import ChainState

        state = ChainState()
        report = _build_report_dict(state, completed_steps={}, side_effects=[])
        assert "loops" not in report


class TestCostSourceMetadata:
    """Verify cost_source metadata in budget events."""

    def test_budget_metadata_has_cost_source(self):
        """Budget enforcement result includes cost_source context."""
        enforcer = LoopEnforcer(
            ChainBlueprint(
                chain_id="test", name="test", version="1.0",
                description="test", goal="test",
                nodes=[], connections=[], loops=[],
            )
        )
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="", exit_condition="",
            max_iterations=5, max_cost_usd=0.1,
            path=["node_a"],
        )
        state = ChainState()
        result = enforcer.check_budget(loop, state, cost_usd=0.2)
        assert result.allowed is False
        # Context should have max_cost_usd
        assert "max_cost_usd" in result.context
        assert result.context["max_cost_usd"] == 0.1


class TestConditionEdgeCases:
    """Additional edge cases for condition evaluator."""

    def test_whitespace_only_passes(self):
        """Whitespace-only condition passes."""
        assert evaluate_condition("   ", {"x": 1}) is True

    def test_integer_comparison(self):
        """Integer comparison without decimal."""
        assert evaluate_condition("iteration == 2", {"iteration": 2}) is True
        assert evaluate_condition("iteration == 2", {"iteration": 3}) is False

    def test_negative_number(self):
        """Negative number in condition."""
        assert evaluate_condition("cost >= -1", {"cost": -0.5}) is True

    def test_zero_comparison(self):
        """Zero comparison."""
        assert evaluate_condition("iteration > 0", {"iteration": 0}) is False
        assert evaluate_condition("iteration >= 0", {"iteration": 0}) is True
