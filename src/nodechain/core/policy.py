"""Policy model — declarative rules governing node behavior."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PolicyType(str, Enum):
    INPUT_VALIDATION = "input_validation"
    OUTPUT_VALIDATION = "output_validation"
    TOOL_ACCESS = "tool_access"           # External API/adapter access
    MODEL_ACCESS = "model_access"         # LLM inference access
    MEMORY_ACCESS = "memory_access"       # Deprecated: use MEMORY_READ or MEMORY_WRITE
    MEMORY_WRITE = "memory_write"         # Memory write access (v2.31.0)
    MEMORY_READ = "memory_read"           # Memory read access (v2.31.0)
    COST_LIMIT = "cost_limit"
    RATE_LIMIT = "rate_limit"
    CONTENT_FILTER = "content_filter"
    TRUST_LEVEL = "trust_level"
    RETRY = "retry"
    TIMEOUT = "timeout"
    FALLBACK = "fallback"
    AUDIT = "audit"
    MEMORY_RETENTION = "memory_retention"
    SENSITIVITY = "sensitivity"
    SIDE_EFFECT = "side_effect"           # Declared side-effect gating
    ADAPTER_ACCESS = "adapter_access"     # v2.43.0: specific backend/adapter grants


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    TRANSFORM = "transform"
    RETRY = "retry"
    ESCALATE = "escalate"
    LOG = "log"


class PolicyRule(BaseModel):
    """A single policy rule with condition and action."""

    rule_id: str
    condition: str
    action: PolicyAction
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: int = 0


class Policy(BaseModel):
    """A declarative policy governing node behavior."""

    policy_id: str
    policy_type: PolicyType
    target: str  # node_id or '*' for all
    rules: list[PolicyRule]
    description: str = ""
    version: str = "1.0.0"


class PolicyDecision(BaseModel):
    """Result of evaluating a policy against a context."""

    policy_id: str
    rule_id: str
    action: PolicyAction
    reason: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyEngine:
    """Evaluates policies against invocation contexts."""

    def __init__(self, policies: list[Policy] | None = None) -> None:
        self._policies: dict[str, Policy] = {}
        if policies:
            for p in policies:
                self._policies[p.policy_id] = p

    def register(self, policy: Policy) -> None:
        self._policies[policy.policy_id] = policy

    def evaluate(
        self,
        policy_type: PolicyType,
        node_id: str,
        context: dict[str, Any],
    ) -> list[PolicyDecision]:
        """
        Evaluate all matching policies for a given context.
        Returns decisions sorted by rule priority (highest first).
        """
        decisions: list[PolicyDecision] = []

        for policy in self._policies.values():
            # Check if policy applies to this node
            if policy.target != "*" and policy.target != node_id:
                continue

            if policy.policy_type != policy_type:
                continue

            # Evaluate rules by priority
            sorted_rules = sorted(
                policy.rules, key=lambda r: r.priority, reverse=True
            )
            for rule in sorted_rules:
                if self._evaluate_condition(rule.condition, context):
                    decisions.append(
                        PolicyDecision(
                            policy_id=policy.policy_id,
                            rule_id=rule.rule_id,
                            action=rule.action,
                            parameters=rule.parameters,
                        )
                    )
                    break  # First matching rule wins per policy

        return decisions

    def _evaluate_condition(
        self, condition: str, context: dict[str, Any]
    ) -> bool:
        """
        Condition evaluator.
        Supports: field comparisons (>, <, >=, <=, ==, !=), 'in' checks,
        existence checks, field-to-field comparisons.
        """
        if condition == "always":
            return True
        if condition == "never":
            return False

        # field > value, field < value, field == value
        for op in [">=", "<=", "!=", ">", "<", "=="]:
            if op in condition:
                field, value = condition.split(op, 1)
                field = field.strip()
                value = value.strip()

                actual = context.get(field)
                if actual is None:
                    return False

                # Try field-to-field: if value is a key in context, use that
                resolved = context.get(value, value)

                try:
                    if op == ">=":
                        return float(actual) >= float(resolved)
                    elif op == "<=":
                        return float(actual) <= float(resolved)
                    elif op == ">":
                        return float(actual) > float(resolved)
                    elif op == "<":
                        return float(actual) < float(resolved)
                    elif op == "!=":
                        return str(actual) != str(resolved)
                    elif op == "==":
                        return str(actual) == str(resolved)
                except (ValueError, TypeError):
                    return False

        # field in [a, b, c]
        if " in " in condition:
            field, values_str = condition.split(" in ", 1)
            field = field.strip()
            actual = context.get(field)
            if actual is None:
                return False
            # Parse [a, b, c]
            values_str = values_str.strip().strip("[]")
            values = [v.strip().strip("'\"") for v in values_str.split(",")]
            # v2.34.1: list-aware. If actual is a list, check if ANY of its
            # members are in values (e.g. side_effect_types in ["external_call"]
            # matches when side_effect_types=["external_call", "memory_write"]).
            # Otherwise scalar check via string comparison.
            if isinstance(actual, (list, tuple, set)):
                actual_strs = [str(a) for a in actual]
                return any(a in values for a in actual_strs)
            return str(actual) in values

        # Existence check
        return condition.strip() in context
