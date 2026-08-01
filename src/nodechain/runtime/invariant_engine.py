"""Invariant Engine — declarative blueprint and runtime invariant enforcement.

Operates at two levels:
- Load time: Blueprint structure invariants (edges, branches, joins, loops exist)
- Runtime: Governance invariants (policy coverage, side-effect declarations, trace audit)

Strict governance mode (NODECHAIN_GOVERNANCE_STRICT=1):
  - Missing policy coverage for capability-bearing nodes becomes ERROR (not warning)
  - Side-effect declaration violations become ERROR
  - Missing cancellation_policy for wait_for=any becomes ERROR
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from nodechain.core.blueprint import ChainBlueprint


# ── Cancellation policy enum ──

CANCEL_ALLOW_ALL = "allow_all"
CANCEL_ON_FIRST = "cancel_on_first"
CANCEL_IGNORE_LATE = "ignore_late"
CANCEL_FIRST_SUCCESS_ONLY = "first_success_only"
CANCEL_QUORUM = "quorum"

VALID_CANCELLATION_POLICIES = frozenset({
    CANCEL_ALLOW_ALL, CANCEL_ON_FIRST, CANCEL_IGNORE_LATE,
    CANCEL_FIRST_SUCCESS_ONLY, CANCEL_QUORUM,
})


# ── Governance strict mode ──

def _governance_strict() -> bool:
    """Read NODECHAIN_GOVERNANCE_STRICT from environment."""
    return os.environ.get("NODECHAIN_GOVERNANCE_STRICT", "").strip() in ("1", "true", "yes")


@dataclass
class InvariantViolation:
    """A single invariant failure."""

    invariant_id: str
    severity: str       # "error" or "warning"
    message: str
    node_id: str = ""   # Affected node (if applicable)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class InvariantReport:
    """Full invariant check result."""

    checks_run: int = 0
    violations: list[InvariantViolation] = field(default_factory=list)

    @property
    def errors(self) -> list[InvariantViolation]:
        return [v for v in self.violations if v.severity == "error"]

    @property
    def warnings(self) -> list[InvariantViolation]:
        return [v for v in self.violations if v.severity == "warning"]

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        parts = [f"Invariant Check: {self.checks_run} checks"]
        if self.violations:
            parts.append(f"{len(self.errors)} errors, {len(self.warnings)} warnings")
            for v in self.violations:
                icon = "✗" if v.severity == "error" else "⚠"
                parts.append(f"  {icon} [{v.invariant_id}] {v.message}")
        else:
            parts.append("All invariants satisfied")
        return "\n".join(parts)


class InvariantEngine:
    """Enforces blueprint and runtime invariants.

    Usage:
        engine = InvariantEngine()
        report = engine.check_blueprint(blueprint)
        if not report.is_valid:
            print(report.summary())
            raise ValueError("Blueprint invariant violations")
    """

    def __init__(self, strict_governance: bool | None = None):
        """Initialize invariant engine.

        Args:
            strict_governance: If set, overrides NODECHAIN_GOVERNANCE_STRICT env var.
                None = read from env, True = always strict, False = always warning.
        """
        if strict_governance is not None:
            self._strict = strict_governance
        else:
            self._strict = _governance_strict()

    @property
    def governance_severity(self) -> str:
        """Severity to use for governance violations in current mode."""
        return "error" if self._strict else "warning"

    def check_blueprint(self, blueprint: ChainBlueprint) -> InvariantReport:
        """Check structural invariants at blueprint load time.

        Verifies:
        - All node IDs referenced in connections exist
        - All branch targets exist
        - All join sources exist
        - All loop targets exist
        - Loop paths don't redundantly repeat nodes
        - Merge strategies are supported
        - No orphan nodes (unreachable from connections)
        """
        report = InvariantReport()
        node_ids = set(blueprint.node_ids())
        node_set = node_ids  # For clarity

        # ── 1. Connection target existence ──
        for conn in blueprint.connections:
            report.checks_run += 1
            if conn.from_node not in node_set:
                report.violations.append(InvariantViolation(
                    invariant_id="connection_source_exists",
                    severity="error",
                    message=f"Connection from_node '{conn.from_node}' not in node definitions",
                    node_id=conn.from_node,
                    details={"from": conn.from_node, "to": conn.to_node},
                ))
            if conn.to_node not in node_set:
                report.violations.append(InvariantViolation(
                    invariant_id="connection_target_exists",
                    severity="error",
                    message=f"Connection to_node '{conn.to_node}' not in node definitions",
                    node_id=conn.to_node,
                    details={"from": conn.from_node, "to": conn.to_node},
                ))

        # ── 2. Branch target existence ──
        for branch in blueprint.branches:
            report.checks_run += 1
            if branch.from_node not in node_set:
                report.violations.append(InvariantViolation(
                    invariant_id="branch_source_exists",
                    severity="error",
                    message=f"Branch '{branch.branch_id}' from_node '{branch.from_node}' not in nodes",
                    node_id=branch.from_node,
                ))

            for branch_name, path_nodes in branch.branches.items():
                for nid in path_nodes:
                    report.checks_run += 1
                    if nid not in node_set:
                        report.violations.append(InvariantViolation(
                            invariant_id="branch_target_exists",
                            severity="error",
                            message=f"Branch '{branch.branch_id}/{branch_name}' references non-existent node '{nid}'",
                            node_id=nid,
                        ))

            if branch.default_branch and branch.default_branch not in branch.branches:
                report.checks_run += 1
                report.violations.append(InvariantViolation(
                    invariant_id="branch_default_exists",
                    severity="warning",
                    message=f"Branch '{branch.branch_id}' default_branch '{branch.default_branch}' not in branches",
                    details={"available": list(branch.branches.keys())},
                ))

        # ── 3. Join source existence ──
        for join in blueprint.joins:
            report.checks_run += 1
            if join.to_node not in node_set:
                report.violations.append(InvariantViolation(
                    invariant_id="join_target_exists",
                    severity="error",
                    message=f"Join '{join.join_id}' to_node '{join.to_node}' not in nodes",
                    node_id=join.to_node,
                ))

            for from_branch in join.from_branches:
                report.checks_run += 1
                # Check that the branch name exists in some BranchDef
                branch_exists = any(
                    from_branch in bd.branches for bd in blueprint.branches
                )
                if not branch_exists:
                    report.violations.append(InvariantViolation(
                        invariant_id="join_source_exists",
                        severity="error",
                        message=f"Join '{join.join_id}' references non-existent branch '{from_branch}'",
                        details={"from_branch": from_branch},
                    ))

        # ── 4. Loop target existence ──
        for loop in blueprint.loops:
            report.checks_run += 1
            for nid in loop.path:
                if nid not in node_set:
                    report.violations.append(InvariantViolation(
                        invariant_id="loop_target_exists",
                        severity="error",
                        message=f"Loop '{loop.loop_id}' references non-existent node '{nid}'",
                        node_id=nid,
                    ))

            # Check max_iterations is positive
            report.checks_run += 1
            if loop.max_iterations < 1:
                report.violations.append(InvariantViolation(
                    invariant_id="loop_max_iterations_positive",
                    severity="error",
                    message=f"Loop '{loop.loop_id}' max_iterations={loop.max_iterations} must be >= 1",
                ))

        # ── 5. Merge strategy support ──
        supported_strategies = {"merge", "append", "latest", "concat"}
        for join in blueprint.joins:
            report.checks_run += 1
            if join.merge_strategy not in supported_strategies:
                # Unsupported merge strategy is execution semantics —
                # warning in default mode, error in strict governance
                report.violations.append(InvariantViolation(
                    invariant_id="merge_strategy_supported",
                    severity=self.governance_severity,
                    message=f"Join '{join.join_id}' merge_strategy '{join.merge_strategy}' not in {supported_strategies}",
                    details={"strategy": join.merge_strategy, "supported": list(supported_strategies)},
                ))

        # ── 6. wait_for policy support ──
        supported_wait = {"all", "any", "first", "quorum"}
        for join in blueprint.joins:
            report.checks_run += 1
            if join.wait_for not in supported_wait:
                report.violations.append(InvariantViolation(
                    invariant_id="wait_for_supported",
                    severity="warning",
                    message=f"Join '{join.join_id}' wait_for '{join.wait_for}' not in {supported_wait}",
                ))

            # Quorum-specific validation
            if join.wait_for == "quorum":
                has_count = join.quorum_count is not None
                has_ratio = join.quorum_ratio is not None
                if not has_count and not has_ratio:
                    sev = "error" if _governance_strict() else "warning"
                    report.violations.append(InvariantViolation(
                        invariant_id="quorum_config_required",
                        severity=sev,
                        message=(
                            f"Join '{join.join_id}' uses wait_for=quorum "
                            f"without quorum_count or quorum_ratio"
                        ),
                    ))
                if has_ratio and (join.quorum_ratio <= 0 or join.quorum_ratio > 1):
                    report.violations.append(InvariantViolation(
                        invariant_id="quorum_ratio_range",
                        severity="error",
                        message=(
                            f"Join '{join.join_id}' quorum_ratio "
                            f"{join.quorum_ratio} must be in (0, 1]"
                        ),
                    ))
                if has_count and join.quorum_count < 1:
                    report.violations.append(InvariantViolation(
                        invariant_id="quorum_count_minimum",
                        severity="error",
                        message=(
                            f"Join '{join.join_id}' quorum_count "
                            f"{join.quorum_count} must be >= 1"
                        ),
                    ))

        # ── 7. No orphan nodes ──
        connected_nodes = set()
        for conn in blueprint.connections:
            connected_nodes.add(conn.from_node)
            connected_nodes.add(conn.to_node)
        # Branch/join nodes are also reachable
        for branch in blueprint.branches:
            connected_nodes.add(branch.from_node)
            for path in branch.branches.values():
                connected_nodes.update(path)
        for join in blueprint.joins:
            connected_nodes.add(join.to_node)
        # Loop nodes are reachable
        for loop in blueprint.loops:
            connected_nodes.update(loop.path)

        for nid in node_set:
            report.checks_run += 1
            if nid not in connected_nodes:
                report.violations.append(InvariantViolation(
                    invariant_id="no_orphan_nodes",
                    severity="warning",
                    message=f"Node '{nid}' is not reachable from any connection, branch, join, or loop",
                    node_id=nid,
                ))

        return report

    def check_runtime(
        self,
        blueprint: ChainBlueprint,
        node_configs: dict[str, dict[str, Any]],
        policies: list[dict[str, Any]] | None = None,
        cancellation_policies: dict[str, str] | None = None,
    ) -> InvariantReport:
        """Check runtime/governance invariants before execution.

        Verifies:
        - model_required nodes have model_access policy coverage
        - External adapter nodes have tool_access policy coverage
        - Memory write nodes have memory governance
        - Side-effecting nodes declare side_effects in config
        - Declared side_effects have matching policy coverage
        - Human-review chains have review policy or explicit disabled mode
        - wait_for=any has explicit cancellation_policy
        - Loop paths are not trivially redundant
        - trace_required chains have terminal audit/trace path
        """
        report = self.check_blueprint(blueprint)
        sev = self.governance_severity

        node_ids = set(blueprint.node_ids())
        policy_types = set()
        if policies:
            for p in policies:
                pt = p.get("type", p.get("policy_type", ""))
                if pt:
                    policy_types.add(pt)

        for nid in node_ids:
            config = node_configs.get(nid, {})

            # ── Model-backed nodes should have model_access policy ──
            report.checks_run += 1
            if config.get("model_required"):
                if policies is not None and "model_access" not in policy_types:
                    report.violations.append(InvariantViolation(
                        invariant_id="model_access_policy_coverage",
                        severity=sev,
                        message=f"Node '{nid}' requires model but no model_access policy registered",
                        node_id=nid,
                    ))

            # ── Nodes that call external tools should have tool_access policy ──
            report.checks_run += 1
            if config.get("can_call_tools"):
                if policies is not None and "tool_access" not in policy_types:
                    report.violations.append(InvariantViolation(
                        invariant_id="tool_access_policy_coverage",
                        severity=sev,
                        message=f"Node '{nid}' calls external tools but no tool_access policy registered",
                        node_id=nid,
                    ))

            # ── Memory write nodes should have memory governance ──
            report.checks_run += 1
            if config.get("can_write_memory"):
                if policies is not None and "memory_access" not in policy_types:
                    report.violations.append(InvariantViolation(
                        invariant_id="memory_governance_coverage",
                        severity=sev,
                        message=f"Node '{nid}' writes memory but no memory_access policy registered",
                        node_id=nid,
                    ))

                # ── Memory write nodes must also declare side_effects ──
                report.checks_run += 1
                declared_effects = config.get("side_effects", [])
                if "memory_write" not in declared_effects:
                    report.violations.append(InvariantViolation(
                        invariant_id="memory_write_side_effect_declaration",
                        severity=sev,
                        message=f"Node '{nid}' can_write_memory but does not declare 'memory_write' in side_effects",
                        node_id=nid,
                        details={"declared": declared_effects},
                    ))

            # ── Side-effecting nodes should declare side_effects ──
            report.checks_run += 1
            if config.get("has_side_effects") and not config.get("side_effects"):
                report.violations.append(InvariantViolation(
                    invariant_id="side_effect_declaration_required",
                    severity=sev,
                    message=f"Node '{nid}' has_side_effects=true but no side_effects declared in config",
                    node_id=nid,
                ))

            # ── Declared side_effects should have policy coverage ──
            report.checks_run += 1
            declared_effects = config.get("side_effects", [])
            if declared_effects and policies is not None:
                uncovered = []
                for effect in declared_effects:
                    # v2.35.0: canonical taxonomy. external_call covers all
                    # outbound API/network/search effects (was api_call/search/
                    # external_read/external_write/external_api_read).
                    from nodechain.core.contract import normalize_side_effect_type
                    canonical = normalize_side_effect_type(effect) or effect
                    if canonical == "external_call":
                        if "tool_access" not in policy_types:
                            uncovered.append(effect)
                    # Memory effects need memory_access
                    elif canonical == "memory_write":
                        if "memory_access" not in policy_types:
                            uncovered.append(effect)
                    elif canonical == "memory_read":
                        if "memory_access" not in policy_types:
                            uncovered.append(effect)
                if uncovered:
                    report.violations.append(InvariantViolation(
                        invariant_id="side_effect_policy_coverage",
                        severity=sev,
                        message=f"Node '{nid}' declares side_effects {uncovered} without required policy coverage",
                        node_id=nid,
                        details={"uncovered": uncovered, "policy_types": list(policy_types)},
                    ))

        # ── Human-review chains should have review policy or disabled mode ──
        report.checks_run += 1
        has_review_gate = len(blueprint.gates) > 0
        has_review_policy = policies is not None and (
            "trust_level" in policy_types or "review" in policy_types
        )
        if has_review_gate and not has_review_policy and policies is not None:
            report.violations.append(InvariantViolation(
                invariant_id="review_gate_policy_coverage",
                severity=sev,
                message=f"Blueprint has {len(blueprint.gates)} review gate(s) but no trust_level or review policy",
            ))

        # ── wait_for=any requires explicit cancellation_policy ──
        for join in blueprint.joins:
            report.checks_run += 1
            if join.wait_for == "any":
                has_policy = (
                    cancellation_policies is not None
                    and join.join_id in cancellation_policies
                )
                if not has_policy:
                    report.violations.append(InvariantViolation(
                        invariant_id="wait_for_any_cancellation_policy",
                        severity=sev,
                        message=f"Join '{join.join_id}' uses wait_for=any without explicit cancellation_policy",
                        details={
                            "join_id": join.join_id,
                            "wait_for": join.wait_for,
                            "available": list(cancellation_policies.keys()) if cancellation_policies else [],
                            "valid_policies": sorted(VALID_CANCELLATION_POLICIES),
                        },
                    ))
                elif has_policy:
                    # Validate cancellation policy value
                    policy_val = cancellation_policies[join.join_id]
                    report.checks_run += 1
                    if policy_val not in VALID_CANCELLATION_POLICIES:
                        report.violations.append(InvariantViolation(
                            invariant_id="cancellation_policy_value_invalid",
                            severity="warning",
                            message=f"Join '{join.join_id}' cancellation_policy '{policy_val}' not in valid set",
                            details={
                                "value": policy_val,
                                "valid": sorted(VALID_CANCELLATION_POLICIES),
                            },
                        ))

        # ── trace_required implies terminal audit/trace path ──
        report.checks_run += 1
        trace_config = getattr(blueprint, 'trace', {}) or {}
        trace_required = trace_config.get('required', False)
        if not trace_required:
            # Fallback: check invariants for backward compatibility
            for inv in blueprint.invariants:
                if "trace" in inv.invariant_id.lower() and inv.enforcement in ("runtime", "both"):
                    trace_required = True
                    break
        if trace_required:
            # Check that a trace/audit/reconciler node exists
            has_trace_node = any(
                any(kw in nid.lower() for kw in ("trace", "audit", "reconciler"))
                for nid in node_ids
            )
            if not has_trace_node:
                trace_sev = sev if self._strict else "warning"
                report.violations.append(InvariantViolation(
                    invariant_id="trace_required_terminal_audit",
                    severity=trace_sev,
                    message="Blueprint requires traceability but no trace/audit/reconciler node found",
                    details={"node_ids": list(node_ids), "trace_config": trace_config},
                ))

        # ── Loop path redundancy ──
        for loop in blueprint.loops:
            report.checks_run += 1
            if len(loop.path) < 2:
                report.violations.append(InvariantViolation(
                    invariant_id="loop_path_minimum_length",
                    severity="warning",
                    message=f"Loop '{loop.loop_id}' path has only {len(loop.path)} nodes — minimum 2 recommended",
                ))

            # Check if loop path starts and ends with the same node
            if len(loop.path) >= 2 and loop.path[0] == loop.path[-1]:
                report.checks_run += 1
                report.violations.append(InvariantViolation(
                    invariant_id="loop_path_redundant_bookend",
                    severity="warning",
                    message=f"Loop '{loop.loop_id}' path starts and ends with '{loop.path[0]}' — "
                            f"consider starting from the next node to avoid redundant re-evaluation",
                    node_id=loop.path[0],
                ))

        return report
