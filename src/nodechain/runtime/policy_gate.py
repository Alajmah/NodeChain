"""Policy Gate — authorization checks before node invocation.

Evaluates policy engine rules for tool access, model access,
memory access, trust level, and cost budget.

Owns:
- Policy evaluation for all policy types
- Denial/approval extraction from decisions
- Policy context construction

Does NOT own:
- Node invocation
- Scheduling
- State persistence
- Trace emission (returns decisions for caller to emit)
- Human review handling
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from nodechain.core.policy import PolicyEngine, PolicyType, PolicyAction
from nodechain.nodes.base_node import BaseNode


@dataclass
class PolicyCheckResult:
    """Result of evaluating all policy gates for a node."""

    node_id: str
    allowed: bool
    denial_reason: str | None = None
    approval_required: str | None = None
    evaluated_policies: list[dict[str, Any]] = field(default_factory=list)


class PolicyGate:
    """Evaluates authorization policies before node invocation.

    The gate checks five policy dimensions:
    1. TOOL_ACCESS — external API calls
    2. MODEL_ACCESS — LLM/model invocation
    3. MEMORY_ACCESS — read/write to memory store
    4. TRUST_LEVEL — node trust requirements
    5. COST_LIMIT — accumulated cost budget
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        *,
        get_capabilities: Callable[[str], Any] | None = None,
        get_trace_events: Callable[[], list[Any]] | None = None,
        get_step: Callable[[], int] | None = None,
    ) -> None:
        self.engine = policy_engine
        self._get_capabilities = get_capabilities
        self._get_trace_events = get_trace_events
        self._get_step = get_step

    def has_policies(self) -> bool:
        """Check if policy engine has any registered policies."""
        return len(self.engine._policies) > 0

    def check(
        self,
        node_id: str,
        node: BaseNode,
    ) -> PolicyCheckResult:
        """Evaluate all applicable policies for a node.

        Returns PolicyCheckResult with allowed=True if all gates pass,
        or allowed=False with denial_reason if any gate blocks.
        """
        req = node.manifest.contract.requirements
        context = self._build_context(node_id, node)
        evaluated: list[dict[str, Any]] = []

        # 0. Package trust (v2.44.0: FIRST gate for privileged nodes)
        # Uses observed trust from BaseNode attributes, not self-declared.
        # Fail-closed. Only evaluates for privileged nodes.
        # v2.44.4: explicit built-in boundary — inherited BaseNode defaults
        # are treated as "unknown" for privileged nodes that aren't proven
        # built-in by module namespace.
        from nodechain.core.contract import is_privileged_node
        import inspect as _inspect
        is_privileged = is_privileged_node(node.manifest.contract)
        raw_trust = getattr(node, '_trust_level', '')
        raw_origin = getattr(node, '_node_origin', '')

        # v2.44.4: verify built-in trust claim
        if is_privileged:
            if raw_trust == 'built_in' or raw_origin == 'built_in':
                # Must be proven built-in: node module under nodechain.nodes.*
                try:
                    node_mod = _inspect.getmodule(type(node))
                    mod_name = node_mod.__name__ if node_mod else ''
                except Exception:
                    mod_name = ''
                is_known_builtin = mod_name.startswith('nodechain.nodes.')
                if not is_known_builtin:
                    # Inherited BaseNode defaults, not proven built-in
                    observed_trust = 'unknown'
                    origin = 'unknown'
                else:
                    observed_trust = raw_trust
                    origin = raw_origin
            else:
                # Loader-set trust (local_trusted, local_untrusted, etc.)
                observed_trust = raw_trust
                origin = raw_origin
        else:
            observed_trust = raw_trust or 'built_in'
            origin = raw_origin or 'built_in'

        required_trust = req.trust_level or "trusted"
        context["observed_trust_level"] = observed_trust
        context["origin"] = origin
        context["required_trust_level"] = required_trust

        if is_privileged:
            decisions = self.engine.evaluate(PolicyType.TRUST_LEVEL, node_id, context)
            deny = self._get_denial(decisions)
            if not decisions:
                deny = "No trust-level policy decision for privileged node"

            trust_eval = {
                "type": "package_trust",
                "policy_type": PolicyType.TRUST_LEVEL.value,
                "observed_trust_level": observed_trust,
                "required_trust_level": required_trust,
                "origin": origin,
                "is_privileged": True,
                "decision": "denied" if deny else "allowed",
                "rule_ids": [d.rule_id for d in decisions],
                "policy_ids": [d.policy_id for d in decisions],
            }
            if decisions:
                blocking = next(
                    (d for d in decisions if d.action == PolicyAction.DENY), None,
                ) or decisions[0]
                trust_eval["policy_id"] = blocking.policy_id
                trust_eval["rule_id"] = blocking.rule_id
            evaluated.append(trust_eval)
            if deny:
                return PolicyCheckResult(
                    node_id, False, denial_reason=deny,
                    evaluated_policies=evaluated,
                )

        # 1. Tool access gate (v2.42.0: contract-driven, not hardcoded node_id)
        # Triggers on Requirements.tools_required. Fail-closed when no
        # TOOL_ACCESS policy decision exists.
        if req.tools_required:
            # v2.42.0: compute grant context fields for policy evaluation
            declared = set(req.tools_required)
            runtime_allowed = set(context.get("allowed_tools", []))
            ungranted = declared - runtime_allowed
            context["tools_required"] = list(declared)
            context["tools_required_count"] = len(declared)
            context["allowed_tools"] = list(runtime_allowed)
            context["ungranted_tools"] = list(ungranted)
            context["ungranted_tool_count"] = len(ungranted)
            context["has_ungranted_tools"] = len(ungranted) > 0

            decisions = self.engine.evaluate(PolicyType.TOOL_ACCESS, node_id, context)
            deny = self._get_denial(decisions)
            # v2.42.0: fail-closed when no TOOL_ACCESS decision exists
            if not decisions:
                deny = "No tool-access policy decision for declared tool requirement"

            ta_eval = {
                "type": "tool_access",
                "policy_type": PolicyType.TOOL_ACCESS.value,
                "tools_required": list(declared),
                "allowed_tools": list(runtime_allowed),
                "ungranted_tools": list(ungranted),
                "decision": "denied" if deny else "allowed",
                "rule_ids": [d.rule_id for d in decisions],
                "policy_ids": [d.policy_id for d in decisions],
            }
            if decisions:
                blocking = next(
                    (d for d in decisions if d.action == PolicyAction.DENY), None,
                ) or decisions[0]
                ta_eval["policy_id"] = blocking.policy_id
                ta_eval["rule_id"] = blocking.rule_id
            evaluated.append(ta_eval)
            if deny:
                return PolicyCheckResult(
                    node_id, False, denial_reason=deny,
                    evaluated_policies=evaluated,
                )

        # 2. Model access (for model-backed nodes)
        if req.model_required:
            decisions = self.engine.evaluate(PolicyType.MODEL_ACCESS, node_id, context)
            deny = self._get_denial(decisions)
            evaluated.append({
                "type": "model_access",
                "decision": "denied" if deny else "allowed",
                "rule_ids": [d.rule_id for d in decisions],
            })
            if deny:
                return PolicyCheckResult(node_id, False, denial_reason=deny, evaluated_policies=evaluated)

        # 1b. Adapter access gate (v2.43.0)
        # Separate from TOOL_ACCESS: tool capability ≠ specific backend grant.
        # Triggers on Requirements.adapters_required (supported adapters).
        # v2.43.1: subset grants are allowed — the node declares what it
        # *supports*, the gate checks that at least some adapters are granted.
        # A node declaring 5 adapters with only 3 granted is ALLOWED.
        # A node with 0 granted adapters is DENIED.
        # The hard upper-bound (can't call ungranted adapters) is enforced
        # in search_tool.py via capabilities.allowed_adapters.
        if req.adapters_required:
            declared_adapters = set(req.adapters_required)
            runtime_adapters = set(context.get("allowed_adapters", []))
            granted_adapters = declared_adapters & runtime_adapters
            ungranted_adapters = declared_adapters - runtime_adapters
            context["adapters_required"] = list(declared_adapters)
            context["adapters_required_count"] = len(declared_adapters)
            context["allowed_adapters"] = list(runtime_adapters)
            context["granted_adapters"] = list(granted_adapters)
            context["granted_adapter_count"] = len(granted_adapters)
            context["ungranted_adapters"] = list(ungranted_adapters)
            context["ungranted_adapter_count"] = len(ungranted_adapters)
            context["has_ungranted_adapters"] = len(ungranted_adapters) > 0
            # v2.43.1: deny only when NO adapters are granted (not when subset)
            context["has_no_granted_adapters"] = len(granted_adapters) == 0

            decisions = self.engine.evaluate(PolicyType.ADAPTER_ACCESS, node_id, context)
            deny = self._get_denial(decisions)
            if not decisions:
                deny = "No adapter-access policy decision for declared adapter requirement"

            aa_eval = {
                "type": "adapter_access",
                "policy_type": PolicyType.ADAPTER_ACCESS.value,
                "adapters_required": list(declared_adapters),
                "allowed_adapters": list(runtime_adapters),
                "granted_adapters": list(granted_adapters),
                "ungranted_adapters": list(ungranted_adapters),
                "decision": "denied" if deny else "allowed",
                "rule_ids": [d.rule_id for d in decisions],
                "policy_ids": [d.policy_id for d in decisions],
            }
            if decisions:
                blocking = next(
                    (d for d in decisions if d.action == PolicyAction.DENY), None,
                ) or decisions[0]
                aa_eval["policy_id"] = blocking.policy_id
                aa_eval["rule_id"] = blocking.rule_id
            evaluated.append(aa_eval)
            if deny:
                return PolicyCheckResult(
                    node_id, False, denial_reason=deny,
                    evaluated_policies=evaluated,
                )

        # 3. Memory write access
        if req.memory_access == "write":
            decisions = self.engine.evaluate(PolicyType.MEMORY_WRITE, node_id, context)
            deny = self._get_denial(decisions)
            approval = self._get_approval_required(decisions)
            evaluated.append({
                "type": "memory_access",
                "decision": "denied" if deny else ("requires_approval" if approval else "allowed"),
                "rule_ids": [d.rule_id for d in decisions],
            })
            if deny:
                return PolicyCheckResult(node_id, False, denial_reason=deny, evaluated_policies=evaluated)

        # 3a. Memory read gate (v2.40.0)
        # Evaluates PolicyType.MEMORY_READ for nodes that declare memory read
        # access. DENY blocks the node before _build_context(). ALLOW carries
        # a decision_id so _build_context can authorize memory exposure.
        # The _build_context sanitizer (Part D) handles undeclared nodes.
        if req.memory_access in ("read", "read_write"):
            decisions = self.engine.evaluate(PolicyType.MEMORY_READ, node_id, context)
            deny = self._get_denial(decisions)
            approval = self._get_approval_required(decisions)
            # v2.40.1: fail closed when no MEMORY_READ decision exists
            # (same pattern as SIDE_EFFECT gate — declared access but no
            # policy coverage = deny, not silent allow)
            if not decisions:
                deny = "No memory-read policy decision for declared memory access"
            # Structured evaluation data (mirrors side-effect pattern)
            mr_eval = {
                "type": "memory_read",
                "policy_type": PolicyType.MEMORY_READ.value,
                "memory_access": req.memory_access,
                "decision": (
                    "denied" if deny
                    else ("requires_approval" if approval else "allowed")
                ),
                "rule_ids": [d.rule_id for d in decisions],
                "policy_ids": [d.policy_id for d in decisions],
                "actions": [d.action.value for d in decisions],
            }
            if decisions:
                # Bind to the actual decision (DENY preferred, then approval)
                blocking = next(
                    (d for d in decisions if d.action == PolicyAction.DENY), None,
                ) or next(
                    (d for d in decisions if d.action == PolicyAction.REQUIRE_APPROVAL), None,
                ) or decisions[0]
                mr_eval["policy_id"] = blocking.policy_id
                mr_eval["rule_id"] = blocking.rule_id
            evaluated.append(mr_eval)
            if deny or approval:
                return PolicyCheckResult(
                    node_id, False,
                    denial_reason=deny or approval,
                    evaluated_policies=evaluated,
                )

        # 3b. Side-effect gate (v2.34.0)
        # Evaluates PolicyType.SIDE_EFFECT for nodes with declared side effects.
        # ALLOW-by-default (via SIDE_EFFECT_POLICY); operators install DENY/
        # REQUIRE_APPROVAL rules to block. No matching decision fails closed.
        side_effects = node.manifest.contract.side_effects
        if side_effects:
            # v2.35.1: normalize declared types to canonical form so policy
            # rules written against canonical types match legacy declarations.
            from nodechain.core.contract import normalize_side_effect_type
            se_types = []
            for se in side_effects:
                canon = normalize_side_effect_type(se.effect_type)
                if canon and canon not in se_types:
                    se_types.append(canon)
            context["side_effect_types"] = se_types
            decisions = self.engine.evaluate(
                PolicyType.SIDE_EFFECT, node_id, context,
            )
            deny = self._get_denial(decisions)
            approval = self._get_approval_required(decisions)
            # Fail closed if no SIDE_EFFECT decision was returned at all
            if not decisions:
                deny = "No side-effect policy decision for declared side effects"
            # Structured evaluation data (correction 3: no string parsing)
            se_eval = {
                "type": "side_effect",
                "policy_type": PolicyType.SIDE_EFFECT.value,
                "side_effect_types": se_types,
                "decision": (
                    "denied" if deny
                    else ("requires_approval" if approval else "allowed")
                ),
                "rule_ids": [d.rule_id for d in decisions],
                "policy_ids": [d.policy_id for d in decisions],
                "actions": [d.action.value for d in decisions],
            }
            if decisions:
                # v2.34.1: bind to the actual blocking decision. Prefer DENY
                # over REQUIRE_APPROVAL when both are present (a deny is a
                # stronger cause than an approval requirement). Falls back to
                # decisions[0] if neither is present (shouldn't happen since we
                # only reach here when deny or approval is truthy).
                denying = next(
                    (d for d in decisions if d.action == PolicyAction.DENY),
                    None,
                ) or next(
                    (d for d in decisions if d.action == PolicyAction.REQUIRE_APPROVAL),
                    None,
                ) or decisions[0]
                se_eval["policy_id"] = denying.policy_id
                se_eval["rule_id"] = denying.rule_id
            evaluated.append(se_eval)
            if deny or approval:
                return PolicyCheckResult(
                    node_id, False,
                    denial_reason=deny or approval,
                    evaluated_policies=evaluated,
                )

        # 4. Cost budget (for model-backed nodes)
        if req.model_required:
            cost_so_far = self._get_accumulated_cost(node_id)
            context["accumulated_cost"] = cost_so_far
            context["max_cost_usd"] = context.get("max_cost_usd", 1.0)
            decisions = self.engine.evaluate(PolicyType.COST_LIMIT, node_id, context)
            deny = self._get_denial(decisions)
            evaluated.append({
                "type": "cost_limit",
                "accumulated": cost_so_far,
                "budget": context.get("max_cost_usd"),
                "decision": "denied" if deny else "ok",
                "rule_ids": [d.rule_id for d in decisions],
            })
            if deny:
                return PolicyCheckResult(node_id, False, denial_reason=deny, evaluated_policies=evaluated)

        return PolicyCheckResult(node_id, True, evaluated_policies=evaluated)

    def _build_context(self, node_id: str, node: BaseNode) -> dict[str, Any]:
        """Build policy evaluation context."""
        req = node.manifest.contract.requirements
        caps = self._get_capabilities(node_id) if self._get_capabilities else None

        return {
            "node_id": node_id,
            "memory_access": req.memory_access or "none",
            "model_required": req.model_required,
            # v2.44.0: context has self-declared trust as "trust_level" for
            # backward compat, but package_trust gate uses "observed_trust_level"
            # from BaseNode._trust_level (set in the gate section, not here).
            "trust_level": req.trust_level or "trusted",
            "can_call_tools": caps.can_call_tools if caps else False,
            "can_read_memory": caps.can_read_memory if caps else False,
            "can_write_memory": caps.can_write_memory if caps else False,
            "allowed_tools": caps.allowed_tools if caps else [],
            "allowed_adapters": caps.allowed_adapters if caps else [],
            "max_cost_usd": caps.max_cost_usd if caps else 1.0,
            "accumulated_cost": self._get_accumulated_cost(node_id),
            "step": self._get_step() if self._get_step else 0,
        }

    def _get_accumulated_cost(self, node_id: str) -> float:
        """Get accumulated cost for a node from trace events."""
        if not self._get_trace_events:
            return 0.0
        events = self._get_trace_events()
        return sum(e.cost_usd for e in events if e.node_id == node_id)

    @staticmethod
    def _get_denial(decisions: list) -> str | None:
        """Extract denial reason from policy decisions."""
        for d in decisions:
            if d.action == PolicyAction.DENY:
                return d.parameters.get("reason", d.reason or f"Denied by rule {d.rule_id}")
        return None

    @staticmethod
    def _get_approval_required(decisions: list) -> str | None:
        """Extract approval requirement from policy decisions."""
        for d in decisions:
            if d.action == PolicyAction.REQUIRE_APPROVAL:
                return d.parameters.get("reason", d.reason or f"Approval required by rule {d.rule_id}")
        return None
