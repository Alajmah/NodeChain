"""Default policies for the Research & Decision Assistant chain.

These policies are loaded into the PolicyEngine and enforced as runtime
gates before tool access and memory writes.
"""

from nodechain.core.policy import (
    Policy,
    PolicyAction,
    PolicyRule,
    PolicyType,
)

# ── Tool Access Policies ──────────────────────────────────────────

TOOL_ACCESS_POLICY = Policy(
    policy_id="research.tool_access.v1",
    policy_type=PolicyType.TOOL_ACCESS,
    target="*",  # v2.42.0: all nodes, not just search_tool
    description="Controls tool access based on contract declarations and runtime grants.",
    rules=[
        # v2.42.0: deny-first if ungranted tools exist (higher priority)
        PolicyRule(
            rule_id="tool.deny_ungranted",
            condition="has_ungranted_tools == True",
            action=PolicyAction.DENY,
            parameters={"reason": "Node requests tools not in its capability grants"},
            priority=20,
        ),
        # Allow when all required tools are granted
        PolicyRule(
            rule_id="tool.allow_granted",
            condition="tools_required_count > 0",
            action=PolicyAction.ALLOW,
            priority=10,
        ),
    ],
)

# ── Adapter Access Policy (v2.43.0) ───────────────────────────────

ADAPTER_ACCESS_POLICY = Policy(
    policy_id="runtime.adapter_access.v1",
    policy_type=PolicyType.ADAPTER_ACCESS,
    target="*",
    description="Governs specific adapter/backend grants, separate from tool capability. Subset grants are allowed.",
    rules=[
        # v2.43.1: deny only when NO adapters are granted (not when subset)
        PolicyRule(
            rule_id="adapter.deny_no_grants",
            condition="has_no_granted_adapters == True",
            action=PolicyAction.DENY,
            parameters={"reason": "Node declares adapters but none are granted in capabilities"},
            priority=20,
        ),
        # Allow when at least one adapter is granted (subset is fine)
        PolicyRule(
            rule_id="adapter.allow_subset_grant",
            condition="adapters_required_count > 0",
            action=PolicyAction.ALLOW,
            priority=10,
        ),
    ],
)

# ── Memory Access Policies ────────────────────────────────────────

MEMORY_WRITE_POLICY = Policy(
    policy_id="research.memory_write.v1",
    policy_type=PolicyType.MEMORY_WRITE,
    target="memory_write_decision",
    description="Governs memory write access. Blocks writes below confidence threshold or with HIGH sensitivity.",
    rules=[
        PolicyRule(
            rule_id="memory.block_low_confidence",
            condition="confidence < 0.7",
            action=PolicyAction.DENY,
            parameters={"reason": "Confidence below write threshold (0.7)"},
            priority=20,
        ),
        PolicyRule(
            rule_id="memory.block_high_sensitivity",
            condition="sensitivity == HIGH",
            action=PolicyAction.REQUIRE_APPROVAL,
            parameters={"reason": "HIGH sensitivity requires explicit approval"},
            priority=15,
        ),
        PolicyRule(
            rule_id="memory.allow_write",
            condition="always",
            action=PolicyAction.ALLOW,
            priority=0,
        ),
    ],
)

MEMORY_READ_POLICY = Policy(
    policy_id="research.memory_read.v1",
    policy_type=PolicyType.MEMORY_READ,
    target="*",
    description="Governs memory read access. Only nodes with declared memory read access can read.",
    rules=[
        PolicyRule(
            rule_id="memory.allow_read_with_access",
            # v2.40.0: fixed condition — actual values are read/write/read_write, not readonly
            condition="memory_access in [read, write, read_write]",
            action=PolicyAction.ALLOW,
            priority=10,
        ),
        PolicyRule(
            rule_id="memory.deny_read_without_access",
            condition="always",
            action=PolicyAction.DENY,
            parameters={"reason": "Node does not have memory read access"},
            priority=0,
        ),
    ],
)

# ── Cost Limit Policy ─────────────────────────────────────────────

COST_LIMIT_POLICY = Policy(
    policy_id="research.cost_limit.v1",
    policy_type=PolicyType.COST_LIMIT,
    target="*",
    description="Prevents any single node from exceeding its cost budget.",
    rules=[
        PolicyRule(
            rule_id="cost.block_over_budget",
            condition="accumulated_cost > max_cost_usd",
            action=PolicyAction.DENY,
            parameters={"reason": "Node exceeded cost budget"},
            priority=10,
        ),
        PolicyRule(
            rule_id="cost.allow_under_budget",
            condition="always",
            action=PolicyAction.ALLOW,
            priority=0,
        ),
    ],
)

# ── Trust Level Policy ────────────────────────────────────────────

TRUST_LEVEL_POLICY = Policy(
    policy_id="runtime.trust.v1",
    policy_type=PolicyType.TRUST_LEVEL,
    target="*",
    description="v2.44.0: Package trust based on runtime-observed trust level (not self-declared).",
    rules=[
        # Deny untrusted/unknown observed trust levels for privileged nodes
        PolicyRule(
            rule_id="trust.deny_untrusted_privileged",
            condition="observed_trust_level in [local_untrusted, remote_untrusted, unknown]",
            action=PolicyAction.DENY,
            parameters={"reason": "Untrusted package cannot execute privileged capabilities"},
            priority=20,
        ),
        # Allow built_in and local_trusted
        PolicyRule(
            rule_id="trust.allow_trusted",
            condition="observed_trust_level in [built_in, local_trusted]",
            action=PolicyAction.ALLOW,
            priority=10,
        ),
    ],
)

# ── Model Access Policy ─────────────────────────────────────────────

MODEL_ACCESS_POLICY = Policy(
    policy_id="research.model_access.v1",
    policy_type=PolicyType.MODEL_ACCESS,
    target="*",
    description="Controls LLM inference access. Only model-backed nodes may call the LLM.",
    rules=[
        PolicyRule(
            rule_id="model.allow_model_required",
            condition="model_required == True",
            action=PolicyAction.ALLOW,
            priority=10,
        ),
        PolicyRule(
            rule_id="model.deny_non_model",
            condition="always",
            action=PolicyAction.DENY,
            parameters={"reason": "Node is not model-backed and cannot call LLM"},
            priority=0,
        ),
    ],
)

# ── Side-Effect Policy (v2.34.0) ──────────────────────────────────

SIDE_EFFECT_POLICY = Policy(
    policy_id="runtime.side_effect.v1",
    policy_type=PolicyType.SIDE_EFFECT,
    target="*",
    description=(
        "Governs declared side effects. Allow-by-default so the enforcement "
        "path is exercised without breaking existing chains. Operators install "
        "DENY/REQUIRE_APPROVAL rules to block specific effect types. A node "
        "that declares side effects but matches no SIDE_EFFECT policy decision "
        "fails closed."
    ),
    rules=[
        PolicyRule(
            rule_id="side_effect.allow",
            condition="always",
            action=PolicyAction.ALLOW,
            priority=0,
        ),
    ],
)

# ── All default policies ──────────────────────────────────────────

DEFAULT_POLICIES = [
    TOOL_ACCESS_POLICY,
    MODEL_ACCESS_POLICY,
    MEMORY_WRITE_POLICY,
    MEMORY_READ_POLICY,
    COST_LIMIT_POLICY,
    TRUST_LEVEL_POLICY,
    SIDE_EFFECT_POLICY,
    ADAPTER_ACCESS_POLICY,
]
