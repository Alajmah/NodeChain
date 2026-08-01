"""Loop Enforcer — declarative loop policy enforcement.

Evaluates entry/exit conditions and budget constraints for loop definitions.
Conditions are evaluated against a safe, declarative context — no arbitrary eval.

Supported condition syntax:
  - Simple comparisons: iteration >= 1, cost < 0.5
  - Boolean checks: loop_required == true
  - Empty string: always passes (no condition)

Context variables available:
  - iteration: current loop iteration count
  - cost: cumulative cost in USD for this loop
  - max_iterations: declared max
  - max_cost_usd: declared budget
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from nodechain.core.blueprint import ChainBlueprint, LoopDef
from nodechain.core.state import ChainState


def _governance_strict() -> bool:
    """Read NODECHAIN_GOVERNANCE_STRICT from environment."""
    import os
    return os.environ.get("NODECHAIN_GOVERNANCE_STRICT", "").strip() in ("1", "true", "yes")


# ── Safe condition evaluator ──

# Allowed comparison operators
_COMPARE_RE = re.compile(
    r'^\s*(\w+)\s*(>=|<=|!=|==|>|<)\s*(.+?)\s*$'
)

# Allowed value types
_BOOL_VALUES = {"true", "false", "yes", "no"}
_NUMERIC_RE = re.compile(r'^-?\d+(?:\.\d+)?$')


class ConditionEvaluationError(Exception):
    """Raised when a condition cannot be evaluated safely."""
    pass


def evaluate_condition(
    condition: str,
    context: dict[str, Any],
) -> bool:
    """Evaluate a declarative condition against a context.

    Returns True if the condition passes, False if it fails.
    Empty conditions always pass.

    Supported syntax:
        variable operator value
        - variable: alphanumeric + underscore
        - operator: >=, <=, !=, ==, >, <
        - value: number, string (unquoted), boolean (true/false)

    Safety: No eval(), no exec(), no imports, no function calls.
    """
    if not condition or not condition.strip():
        return True

    condition = condition.strip()
    match = _COMPARE_RE.match(condition)
    if not match:
        raise ConditionEvaluationError(
            f"Invalid condition syntax: '{condition}'. "
            f"Expected: <variable> <operator> <value>"
        )

    var_name, operator, raw_value = match.groups()

    # Resolve variable from context
    if var_name not in context:
        raise ConditionEvaluationError(
            f"Unknown variable '{var_name}' in condition. "
            f"Available: {list(context.keys())}"
        )
    left = context[var_name]

    # Parse value
    raw_value = raw_value.strip()
    if raw_value.lower() in _BOOL_VALUES:
        right = raw_value.lower() in ("true", "yes")
    elif _NUMERIC_RE.match(raw_value):
        right = float(raw_value) if '.' in raw_value else int(raw_value)
    else:
        right = raw_value  # string comparison

    # Type coercion for comparison
    if isinstance(left, (int, float)) and isinstance(right, str):
        try:
            right = float(right)
        except ValueError:
            pass
    elif isinstance(left, bool) and isinstance(right, str):
        right = right.lower() in ("true", "yes")

    # Evaluate
    try:
        if operator == '>=':
            return left >= right
        elif operator == '<=':
            return left <= right
        elif operator == '>':
            return left > right
        elif operator == '<':
            return left < right
        elif operator == '==':
            return left == right
        elif operator == '!=':
            return left != right
        else:
            raise ConditionEvaluationError(f"Unknown operator: {operator}")
    except TypeError as e:
        raise ConditionEvaluationError(
            f"Cannot compare {type(left).__name__} {operator} {type(right).__name__}: {e}"
        )


# ── Loop enforcement result ──

@dataclass
class LoopEnforcementResult:
    """Result from a loop policy check."""
    allowed: bool = True
    reason: str | None = None
    check_type: str = ""  # "entry", "exit", "budget", "max_iterations"
    loop_id: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    advisory: str | None = None  # Set when condition is unparseable (treated as advisory)


# ── Loop enforcer ──

class LoopEnforcer:
    """Enforces declarative loop policies from LoopDef declarations.

    Three enforcement points:
    1. Entry: Can the loop be entered? (entry_condition)
    2. Budget: Has the loop exceeded max_cost_usd?
    3. Exit: Should the loop terminate early? (exit_condition)

    Cost tracking is derived from trace events for nodes in the loop path.
    """

    def __init__(self, blueprint: ChainBlueprint):
        self._blueprint = blueprint

    def check_entry(
        self,
        loop: LoopDef,
        state: ChainState,
        cost_usd: float = 0.0,
    ) -> LoopEnforcementResult:
        """Check if a loop can be entered.

        Evaluates entry_condition against loop context.
        Returns allowed=False if entry should be blocked.
        """
        context = self._build_context(loop, state, cost_usd)

        try:
            passes = evaluate_condition(loop.entry_condition, context)
        except ConditionEvaluationError:
            # Condition cannot be parsed (e.g. prose description).
            if _governance_strict():
                # Strict mode: unparseable condition is an error
                return LoopEnforcementResult(
                    allowed=False,
                    reason=(
                        f"Strict mode: entry_condition '{loop.entry_condition}' "
                        f"is not a structured expression — must use 'variable operator value' syntax"
                    ),
                    check_type="entry",
                    loop_id=loop.loop_id,
                    context=context,
                )
            # Non-strict: treat as passthrough with advisory
            return LoopEnforcementResult(
                allowed=True,
                check_type="entry",
                loop_id=loop.loop_id,
                context=context,
                advisory=(
                    f"condition_parse_failed: entry_condition '{loop.entry_condition}' "
                    f"is not a structured expression — treated as advisory"
                ),
            )

        if not passes:
            return LoopEnforcementResult(
                allowed=False,
                reason=f"Entry condition not met: '{loop.entry_condition}'",
                check_type="entry",
                loop_id=loop.loop_id,
                context=context,
            )

        return LoopEnforcementResult(
            allowed=True,
            check_type="entry",
            loop_id=loop.loop_id,
            context=context,
        )

    def check_budget(
        self,
        loop: LoopDef,
        state: ChainState,
        cost_usd: float = 0.0,
    ) -> LoopEnforcementResult:
        """Check if loop has exceeded its budget.

        Returns allowed=False if max_cost_usd is exceeded. The effective budget
        is the operator-approved override (v2.47.0 state.metadata['budget_overrides'])
        if present, otherwise the static blueprint max_cost_usd.
        """
        context = self._build_context(loop, state, cost_usd)

        # v2.47.0: effective budget accounts for operator-approved overrides.
        # The override is an absolute ceiling (carried cost); accumulated spend
        # is preserved, not reset.
        overrides = {}
        if hasattr(state, "metadata") and state.metadata:
            overrides = (state.metadata or {}).get("budget_overrides") or {}
        effective_budget = overrides.get(loop.loop_id, loop.max_cost_usd)
        context["max_cost_usd"] = effective_budget  # reflect what was actually enforced

        if cost_usd > effective_budget:
            return LoopEnforcementResult(
                allowed=False,
                reason=(
                    f"Loop '{loop.loop_id}' budget exceeded: "
                    f"${cost_usd:.4f} > ${effective_budget:.4f}"
                ),
                check_type="budget",
                loop_id=loop.loop_id,
                context=context,
            )

        return LoopEnforcementResult(
            allowed=True,
            check_type="budget",
            loop_id=loop.loop_id,
            context=context,
        )

    def check_exit(
        self,
        loop: LoopDef,
        state: ChainState,
        cost_usd: float = 0.0,
    ) -> LoopEnforcementResult:
        """Check if exit_condition is met (early termination).

        Returns allowed=False if the loop should exit early.
        Note: this is the INVERSE of entry — exit_condition being True
        means the loop SHOULD exit.
        """
        # Empty condition means no exit restriction
        if not loop.exit_condition or not loop.exit_condition.strip():
            return LoopEnforcementResult(
                allowed=True,
                check_type="exit",
                loop_id=loop.loop_id,
            )

        context = self._build_context(loop, state, cost_usd)

        try:
            should_exit = evaluate_condition(loop.exit_condition, context)
        except ConditionEvaluationError as e:
            if _governance_strict():
                # Strict mode: unparseable condition is an error
                return LoopEnforcementResult(
                    allowed=False,
                    reason=(
                        f"Strict mode: exit_condition '{loop.exit_condition}' "
                        f"is not a structured expression — must use 'variable operator value' syntax"
                    ),
                    check_type="exit",
                    loop_id=loop.loop_id,
                    context=context,
                )
            # Non-strict: passthrough with advisory
            return LoopEnforcementResult(
                allowed=True,
                reason=f"Exit condition evaluation error: {e}",
                check_type="exit",
                loop_id=loop.loop_id,
                context=context,
                advisory=(
                    f"condition_parse_failed: exit_condition '{loop.exit_condition}' "
                    f"is not a structured expression — treated as advisory"
                ),
            )

        if should_exit:
            return LoopEnforcementResult(
                allowed=False,
                reason=f"Exit condition met: '{loop.exit_condition}'",
                check_type="exit",
                loop_id=loop.loop_id,
                context=context,
            )

        return LoopEnforcementResult(
            allowed=True,
            check_type="exit",
            loop_id=loop.loop_id,
            context=context,
        )

    def get_escalation(
        self,
        loop: LoopDef,
        reason: str,
    ) -> str | None:
        """Get escalation message for a loop policy violation."""
        if loop.escalation:
            return f"{loop.escalation}: {reason}"
        return reason

    def _build_context(
        self,
        loop: LoopDef,
        state: ChainState,
        cost_usd: float = 0.0,
    ) -> dict[str, Any]:
        """Build the condition evaluation context."""
        loop_id = loop.loop_id
        iteration = 0
        if loop_id in state.loop_state:
            iteration = state.loop_state[loop_id].iteration

        return {
            "iteration": iteration,
            "cost": cost_usd,
            "max_iterations": loop.max_iterations,
            "max_cost_usd": loop.max_cost_usd,
            "loop_id": loop.loop_id,
        }
