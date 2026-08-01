"""Tests for loop enforcement — entry/exit conditions and budget.

AC1: loop max_cost_usd stops loop execution when exceeded.
AC2: entry_condition=false skips/blocks loop entry.
AC3: exit_condition=true terminates loop early.
AC4: condition evaluation is safe and declarative, not arbitrary eval.
AC5: escalation message/policy is emitted when loop exits due to budget/limit.
AC6: trace records loop_entered, loop_exited, loop_blocked, and reason.
AC7: 580 tests remain green.
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


# ═══════════════════════════════════════════════════════════════════
# AC4: Safe condition evaluation
# ═══════════════════════════════════════════════════════════════════

class TestConditionEvaluator:
    """Verify the declarative condition evaluator."""

    def test_empty_condition_passes(self):
        """Empty condition always passes."""
        assert evaluate_condition("", {}) is True
        assert evaluate_condition("  ", {}) is True

    def test_numeric_gt(self):
        """Numeric greater-than comparison."""
        assert evaluate_condition("iteration > 0", {"iteration": 1}) is True
        assert evaluate_condition("iteration > 0", {"iteration": 0}) is False

    def test_numeric_gte(self):
        """Numeric greater-than-or-equal."""
        assert evaluate_condition("iteration >= 1", {"iteration": 1}) is True
        assert evaluate_condition("iteration >= 2", {"iteration": 1}) is False

    def test_numeric_lt(self):
        """Numeric less-than."""
        assert evaluate_condition("cost < 0.5", {"cost": 0.3}) is True
        assert evaluate_condition("cost < 0.5", {"cost": 0.7}) is False

    def test_numeric_lte(self):
        """Numeric less-than-or-equal."""
        assert evaluate_condition("cost <= 0.5", {"cost": 0.5}) is True
        assert evaluate_condition("cost <= 0.5", {"cost": 0.6}) is False

    def test_equality(self):
        """Equality comparison."""
        assert evaluate_condition("iteration == 0", {"iteration": 0}) is True
        assert evaluate_condition("iteration == 1", {"iteration": 0}) is False

    def test_inequality(self):
        """Inequality comparison."""
        assert evaluate_condition("iteration != 0", {"iteration": 1}) is True
        assert evaluate_condition("iteration != 0", {"iteration": 0}) is False

    def test_boolean_true(self):
        """Boolean true comparison."""
        assert evaluate_condition("active == true", {"active": True}) is True

    def test_boolean_false(self):
        """Boolean false comparison."""
        assert evaluate_condition("active == false", {"active": False}) is True

    def test_float_comparison(self):
        """Float comparison."""
        assert evaluate_condition("cost >= 0.25", {"cost": 0.3}) is True
        assert evaluate_condition("cost >= 0.25", {"cost": 0.1}) is False

    def test_unknown_variable_raises(self):
        """Unknown variable raises ConditionEvaluationError."""
        with pytest.raises(ConditionEvaluationError, match="Unknown variable"):
            evaluate_condition("foo > 0", {"iteration": 1})

    def test_invalid_syntax_raises(self):
        """Invalid syntax raises ConditionEvaluationError."""
        with pytest.raises(ConditionEvaluationError, match="Invalid condition"):
            evaluate_condition("just a string", {"iteration": 1})

    def test_no_arbitrary_eval(self):
        """Conditions must not allow arbitrary code execution."""
        with pytest.raises(ConditionEvaluationError):
            evaluate_condition("__import__('os')", {})


# ═══════════════════════════════════════════════════════════════════
# AC2: Entry condition
# ═══════════════════════════════════════════════════════════════════

class TestLoopEntryCondition:
    """Verify entry_condition enforcement."""

    def _make_enforcer(self):
        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        return LoopEnforcer(bp)

    def _make_loop(self, entry_condition="", exit_condition=""):
        return LoopDef(
            loop_id="test-loop",
            entry_condition=entry_condition,
            exit_condition=exit_condition,
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a", "node_b"],
        )

    def test_empty_entry_allows(self):
        """Empty entry condition allows entry."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(entry_condition="")
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True

    def test_entry_condition_passes(self):
        """Entry condition that passes allows entry."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(entry_condition="iteration >= 0")
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True

    def test_entry_condition_blocks(self):
        """AC2: Entry condition that fails blocks loop entry."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(entry_condition="iteration >= 1")
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is False
        assert "entry" in result.check_type
        assert result.reason is not None

    def test_entry_with_existing_iteration_passes(self):
        """Entry condition with iteration > 0 can pass."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(entry_condition="iteration >= 1")
        state = ChainState()
        state.loop_state["test-loop"] = LoopState(iteration=1)
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True

    def test_unparseable_entry_passes_through(self):
        """Prose conditions pass through without blocking."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(entry_condition="source quality is sufficient")
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True


# ═══════════════════════════════════════════════════════════════════
# AC1: Budget enforcement
# ═══════════════════════════════════════════════════════════════════

class TestLoopBudget:
    """Verify max_cost_usd enforcement."""

    def _make_enforcer(self):
        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        return LoopEnforcer(bp)

    def _make_loop(self, max_cost_usd=0.5):
        return LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=max_cost_usd,
            path=["node_a", "node_b"],
        )

    def test_within_budget_allows(self):
        """Cost within budget allows continuation."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(max_cost_usd=0.5)
        state = ChainState()
        result = enforcer.check_budget(loop, state, cost_usd=0.3)
        assert result.allowed is True

    def test_exactly_at_budget_allows(self):
        """Cost exactly at budget is still allowed."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(max_cost_usd=0.5)
        state = ChainState()
        result = enforcer.check_budget(loop, state, cost_usd=0.5)
        assert result.allowed is True

    def test_over_budget_blocks(self):
        """AC1: Cost over budget blocks loop execution."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(max_cost_usd=0.5)
        state = ChainState()
        result = enforcer.check_budget(loop, state, cost_usd=0.6)
        assert result.allowed is False
        assert "budget" in result.check_type
        assert "exceeded" in result.reason.lower()

    def test_zero_budget_blocks_any_cost(self):
        """Zero budget blocks any positive cost."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(max_cost_usd=0.0)
        state = ChainState()
        result = enforcer.check_budget(loop, state, cost_usd=0.001)
        assert result.allowed is False


# ═══════════════════════════════════════════════════════════════════
# AC3: Exit condition
# ═══════════════════════════════════════════════════════════════════

class TestLoopExitCondition:
    """Verify exit_condition enforcement."""

    def _make_enforcer(self):
        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        return LoopEnforcer(bp)

    def _make_loop(self, exit_condition=""):
        return LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition=exit_condition,
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a", "node_b"],
        )

    def test_empty_exit_allows(self):
        """Empty exit condition means loop continues normally."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(exit_condition="")
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is True

    def test_exit_condition_not_met_allows(self):
        """Exit condition not met means loop continues."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(exit_condition="iteration >= 5")
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is True

    def test_exit_condition_met_blocks(self):
        """AC3: Exit condition met terminates loop early."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(exit_condition="iteration >= 3")
        state = ChainState()
        state.loop_state["test-loop"] = LoopState(iteration=3)
        result = enforcer.check_exit(loop, state)
        assert result.allowed is False
        assert "exit" in result.check_type
        assert result.reason is not None

    def test_cost_based_exit(self):
        """Exit condition based on cost."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(exit_condition="cost >= 0.25")
        state = ChainState()
        result = enforcer.check_exit(loop, state, cost_usd=0.3)
        assert result.allowed is False

    def test_unparseable_exit_passes(self):
        """Prose exit conditions pass through."""
        enforcer = self._make_enforcer()
        loop = self._make_loop(exit_condition="quality is acceptable")
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is True


# ═══════════════════════════════════════════════════════════════════
# AC5: Escalation messages
# ═══════════════════════════════════════════════════════════════════

class TestLoopEscalation:
    """Verify escalation message generation."""

    def _make_enforcer(self):
        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        return LoopEnforcer(bp)

    def test_escalation_with_message(self):
        """AC5: Escalation message from loop definition."""
        enforcer = self._make_enforcer()
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a"],
            escalation="Request human review",
        )
        msg = enforcer.get_escalation(loop, "Budget exceeded")
        assert "Request human review" in msg
        assert "Budget exceeded" in msg

    def test_escalation_without_message(self):
        """No escalation message returns just the reason."""
        enforcer = self._make_enforcer()
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a"],
        )
        msg = enforcer.get_escalation(loop, "Budget exceeded")
        assert msg == "Budget exceeded"


# ═══════════════════════════════════════════════════════════════════
# Integration: loop enforcement via scheduler
# ═══════════════════════════════════════════════════════════════════

class TestLoopEnforcementIntegration:
    """Verify loop enforcement through the scheduler."""

    def _make_scheduler(self, loops=None):
        from nodechain.runtime.scheduler import GraphScheduler
        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            loops=loops or [],
        )
        return GraphScheduler(bp)

    def test_entry_blocked_for_first_node(self):
        """Entry condition blocks loop on first node in path."""
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="iteration >= 1",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a", "node_b"],
        )
        scheduler = self._make_scheduler(loops=[loop])
        state = ChainState()
        result = scheduler.check_loop_entry("node_a", state)
        assert result is not None
        assert result.allowed is False

    def test_entry_not_checked_for_middle_node(self):
        """Entry condition only checked for first node in path."""
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="iteration >= 1",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a", "node_b"],
        )
        scheduler = self._make_scheduler(loops=[loop])
        state = ChainState()
        result = scheduler.check_loop_entry("node_b", state)
        assert result is None  # Not the first node

    def test_budget_check_exceeds(self):
        """Budget check returns violation when exceeded."""
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=0.1,
            path=["node_a"],
        )
        scheduler = self._make_scheduler(loops=[loop])
        state = ChainState()
        result = scheduler.check_loop_budget("test-loop", state, cost_usd=0.2)
        assert result is not None
        assert result.allowed is False

    def test_exit_condition_met(self):
        """Exit condition met returns violation."""
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="iteration >= 2",
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a"],
        )
        scheduler = self._make_scheduler(loops=[loop])
        state = ChainState()
        state.loop_state["test-loop"] = LoopState(iteration=2)
        result = scheduler.check_loop_exit("test-loop", state)
        assert result is not None
        assert result.allowed is False

    def test_escalation_message(self):
        """Scheduler returns escalation message."""
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="",
            exit_condition="",
            max_iterations=5,
            max_cost_usd=1.0,
            path=["node_a"],
            escalation="Please review",
        )
        scheduler = self._make_scheduler(loops=[loop])
        msg = scheduler.get_escalation_message("test-loop", "Budget exceeded")
        assert "Please review" in msg
