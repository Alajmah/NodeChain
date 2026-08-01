"""Tests for strict-mode loop advisory escalation.

AC1: Non-strict mode: prose loop condition passes with LOOP_ESCALATION advisory.
AC2: Strict mode: unparseable entry_condition blocks execution.
AC3: Strict mode: unparseable exit_condition blocks execution.
AC4: Strict mode error includes loop_id, condition field, condition text.
AC5: Structured conditions continue to evaluate normally in both modes.
AC6: 625 tests remain green.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.runtime.loop_enforcer import (
    evaluate_condition, LoopEnforcer, LoopEnforcementResult,
)
from nodechain.core.blueprint import LoopDef, ChainBlueprint
from nodechain.core.state import ChainState, LoopState


def _make_enforcer():
    bp = ChainBlueprint(
        chain_id="test", name="test", version="1.0",
        description="test", goal="test",
        nodes=[], connections=[], loops=[],
    )
    return LoopEnforcer(bp)


def _prose_entry_loop():
    return LoopDef(
        loop_id="test-loop",
        entry_condition="quality is sufficient",
        exit_condition="",
        max_iterations=5, max_cost_usd=1.0,
        path=["node_a"],
    )


def _prose_exit_loop():
    return LoopDef(
        loop_id="test-loop",
        entry_condition="",
        exit_condition="enough evidence gathered",
        max_iterations=5, max_cost_usd=1.0,
        path=["node_a"],
    )


def _structured_entry_loop():
    return LoopDef(
        loop_id="test-loop",
        entry_condition="iteration >= 0",
        exit_condition="",
        max_iterations=5, max_cost_usd=1.0,
        path=["node_a"],
    )


def _structured_exit_loop():
    return LoopDef(
        loop_id="test-loop",
        entry_condition="",
        exit_condition="iteration >= 5",
        max_iterations=5, max_cost_usd=1.0,
        path=["node_a"],
    )


# ═══════════════════════════════════════════════════════════════════
# AC1: Non-strict mode passthrough
# ═══════════════════════════════════════════════════════════════════

class TestNonStrictPassthrough:
    """Verify non-strict mode treats prose as advisory."""

    def setup_method(self):
        os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)

    def test_prose_entry_passes_non_strict(self):
        """AC1: Prose entry condition passes in non-strict mode."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True
        assert result.advisory is not None
        assert "condition_parse_failed" in result.advisory

    def test_prose_exit_passes_non_strict(self):
        """AC1: Prose exit condition passes in non-strict mode."""
        enforcer = _make_enforcer()
        loop = _prose_exit_loop()
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is True
        assert result.advisory is not None

    def test_prose_entry_no_strict_env(self):
        """AC1: Without NODECHAIN_GOVERNANCE_STRICT set, passes."""
        os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True


# ═══════════════════════════════════════════════════════════════════
# AC2 + AC3: Strict mode blocks
# ═══════════════════════════════════════════════════════════════════

class TestStrictModeBlocks:
    """Verify strict mode blocks unparseable conditions."""

    def setup_method(self):
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"

    def teardown_method(self):
        os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)

    def test_strict_prose_entry_blocked(self):
        """AC2: Strict mode blocks unparseable entry_condition."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is False

    def test_strict_prose_exit_blocked(self):
        """AC3: Strict mode blocks unparseable exit_condition."""
        enforcer = _make_enforcer()
        loop = _prose_exit_loop()
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is False

    def test_strict_entry_with_env_true(self):
        """AC2: NODECHAIN_GOVERNANCE_STRICT=true blocks."""
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "true"
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is False

    def test_strict_entry_with_env_yes(self):
        """AC2: NODECHAIN_GOVERNANCE_STRICT=yes blocks."""
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "yes"
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is False

    def test_strict_entry_with_env_0_passes(self):
        """NODECHAIN_GOVERNANCE_STRICT=0 passes."""
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "0"
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True


# ═══════════════════════════════════════════════════════════════════
# AC4: Error message content
# ═══════════════════════════════════════════════════════════════════

class TestStrictErrorMessage:
    """Verify strict mode error messages include required fields."""

    def setup_method(self):
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"

    def teardown_method(self):
        os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)

    def test_entry_error_includes_loop_id(self):
        """AC4: Error includes loop_id."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.loop_id == "test-loop"

    def test_entry_error_includes_condition_text(self):
        """AC4: Error includes condition text."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert "quality is sufficient" in result.reason

    def test_entry_error_includes_condition_field(self):
        """AC4: Error identifies which field failed."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert "entry_condition" in result.reason

    def test_exit_error_includes_condition_field(self):
        """AC4: Exit error identifies exit_condition field."""
        enforcer = _make_enforcer()
        loop = _prose_exit_loop()
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert "exit_condition" in result.reason

    def test_error_mentions_structured_syntax(self):
        """AC4: Error mentions required syntax."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert "structured expression" in result.reason
        assert "variable operator value" in result.reason

    def test_no_advisory_in_strict_mode(self):
        """Strict mode errors don't have advisory (they're hard errors)."""
        enforcer = _make_enforcer()
        loop = _prose_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.advisory is None


# ═══════════════════════════════════════════════════════════════════
# AC5: Structured conditions work in both modes
# ═══════════════════════════════════════════════════════════════════

class TestStructuredConditionsBothModes:
    """Structured conditions evaluate normally regardless of strict mode."""

    def test_structured_entry_non_strict(self):
        """AC5: Structured entry works in non-strict mode."""
        os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)
        enforcer = _make_enforcer()
        loop = _structured_entry_loop()
        state = ChainState()
        result = enforcer.check_entry(loop, state)
        assert result.allowed is True
        assert result.advisory is None

    def test_structured_entry_strict(self):
        """AC5: Structured entry works in strict mode."""
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"
        try:
            enforcer = _make_enforcer()
            loop = _structured_entry_loop()
            state = ChainState()
            result = enforcer.check_entry(loop, state)
            assert result.allowed is True
            assert result.advisory is None
        finally:
            os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)

    def test_structured_exit_non_strict(self):
        """AC5: Structured exit works in non-strict mode."""
        os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)
        enforcer = _make_enforcer()
        loop = _structured_exit_loop()
        state = ChainState()
        result = enforcer.check_exit(loop, state)
        assert result.allowed is True
        assert result.advisory is None

    def test_structured_exit_strict(self):
        """AC5: Structured exit works in strict mode."""
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"
        try:
            enforcer = _make_enforcer()
            loop = _structured_exit_loop()
            state = ChainState()
            result = enforcer.check_exit(loop, state)
            assert result.allowed is True
            assert result.advisory is None
        finally:
            os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)

    def test_structured_exit_met_blocks_in_strict(self):
        """AC5: Structured exit condition met blocks in strict mode."""
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"
        try:
            enforcer = _make_enforcer()
            loop = _structured_exit_loop()
            state = ChainState()
            state.loop_state["test-loop"] = LoopState(iteration=5)
            result = enforcer.check_exit(loop, state)
            assert result.allowed is False
            assert result.advisory is None
        finally:
            os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)
