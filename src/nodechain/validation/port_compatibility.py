"""Port Compatibility — connection-level port/schema validation.

Validates that:
1. Connection source port exists on upstream node's exit contract.
2. Connection target port exists on downstream node's entry contract.
3. Source output type is compatible with target input type.
4. Required target fields are satisfied by source guaranteed fields.
5. Type mismatch blocks blueprint load in strict mode.
6. Branch/join fan-in port compatibility is checked.
7. Port mapping errors include source node, source port, target node, target port.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nodechain.core.blueprint import ChainBlueprint, ConnectionDef, BranchDef, JoinDef
from nodechain.core.contract import NodeContract, check_compatibility


@dataclass
class PortIssue:
    """A single port compatibility issue."""

    severity: str  # "error" or "warning"
    source_node: str
    source_port: str
    target_node: str
    target_port: str
    issue_type: str  # "type_mismatch", "missing_required_field", "missing_port", "schema_ref_mismatch", "fan_in_mismatch"
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PortCompatibilityReport:
    """Full port compatibility report."""

    checks_run: int = 0
    issues: list[PortIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[PortIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[PortIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        parts = [f"Port Compatibility: {self.checks_run} checks"]
        if self.issues:
            parts.append(f"{len(self.errors)} errors, {len(self.warnings)} warnings")
            for issue in self.issues:
                parts.append(
                    f"  [{issue.severity.upper()}] {issue.source_node}:{issue.source_port} "
                    f"→ {issue.target_node}:{issue.target_port} — {issue.message}"
                )
        else:
            parts.append("All connections valid")
        return "\n".join(parts)


def validate_port_compatibility(
    blueprint: ChainBlueprint,
    contracts: dict[str, NodeContract],
    strict: bool = False,
) -> PortCompatibilityReport:
    """Validate all port connections in a blueprint.

    Checks:
    - Backbone connections (from connections list)
    - Branch fan-out (from branch definitions)
    - Join fan-in (from join definitions)

    Args:
        blueprint: The chain blueprint to validate
        contracts: Node contracts keyed by node_id
        strict: If True, warnings become errors

    Returns:
        PortCompatibilityReport with all issues found.
    """
    report = PortCompatibilityReport()

    # ── 1. Backbone connections ──
    for conn in blueprint.connections:
        _check_connection(conn, contracts, report, strict)

    # ── 2. Branch fan-out ──
    for branch_def in blueprint.branches:
        _check_branch_fan_out(branch_def, blueprint, contracts, report, strict)

    # ── 3. Join fan-in ──
    for join_def in blueprint.joins:
        _check_join_fan_in(join_def, blueprint, contracts, report, strict)

    return report


def _check_connection(
    conn: ConnectionDef,
    contracts: dict[str, NodeContract],
    report: PortCompatibilityReport,
    strict: bool,
) -> None:
    """Check a single backbone connection."""
    source_id = conn.from_node
    target_id = conn.to_node
    source_port = conn.from_port
    target_port = conn.to_port

    report.checks_run += 1

    source_contract = contracts.get(source_id)
    target_contract = contracts.get(target_id)

    if source_contract is None:
        report.issues.append(PortIssue(
            severity="error",
            source_node=source_id, source_port=source_port,
            target_node=target_id, target_port=target_port,
            issue_type="missing_port",
            message=f"Source node '{source_id}' has no registered contract",
            details={"missing": "source_contract"},
        ))
        return

    if target_contract is None:
        report.issues.append(PortIssue(
            severity="error",
            source_node=source_id, source_port=source_port,
            target_node=target_id, target_port=target_port,
            issue_type="missing_port",
            message=f"Target node '{target_id}' has no registered contract",
            details={"missing": "target_contract"},
        ))
        return

    # Check type compatibility
    source_exit = source_contract.exit
    target_entry = target_contract.entry

    if source_exit.output_type != target_entry.input_type:
        sev = "error"
        report.issues.append(PortIssue(
            severity=sev,
            source_node=source_id, source_port=source_port,
            target_node=target_id, target_port=target_port,
            issue_type="type_mismatch",
            message=(
                f"Type mismatch: {source_id} produces '{source_exit.output_type}' "
                f"but {target_id} expects '{target_entry.input_type}'"
            ),
            details={
                "source_output_type": source_exit.output_type,
                "target_input_type": target_entry.input_type,
            },
        ))

    # Check required field coverage
    if target_entry.required_fields:
        missing = set(target_entry.required_fields) - set(source_exit.guaranteed_fields)
        if missing:
            report.issues.append(PortIssue(
                severity="error",
                source_node=source_id, source_port=source_port,
                target_node=target_id, target_port=target_port,
                issue_type="missing_required_field",
                message=(
                    f"Missing required fields: {sorted(missing)}. "
                    f"{source_id} guarantees {source_exit.guaranteed_fields}, "
                    f"{target_id} requires {target_entry.required_fields}"
                ),
                details={
                    "missing_fields": sorted(missing),
                    "source_guaranteed": source_exit.guaranteed_fields,
                    "target_required": target_entry.required_fields,
                },
            ))

    # Check schema ref compatibility
    if source_exit.schema_ref and target_entry.schema_ref:
        if source_exit.schema_ref != target_entry.schema_ref:
            # Schema refs differ — warning in non-strict, error in strict
            sev = "error" if strict else "warning"
            report.issues.append(PortIssue(
                severity=sev,
                source_node=source_id, source_port=source_port,
                target_node=target_id, target_port=target_port,
                issue_type="schema_ref_mismatch",
                message=(
                    f"Schema ref mismatch: {source_id} produces '{source_exit.schema_ref}' "
                    f"but {target_id} expects '{target_entry.schema_ref}'"
                ),
                details={
                    "source_schema": source_exit.schema_ref,
                    "target_schema": target_entry.schema_ref,
                },
            ))

    # Check optional field coverage (always warning)
    if target_entry.optional_fields:
        available = set(source_exit.guaranteed_fields) | set(source_exit.possible_fields)
        missing_optional = set(target_entry.optional_fields) - available
        if missing_optional:
            report.issues.append(PortIssue(
                severity="warning",
                source_node=source_id, source_port=source_port,
                target_node=target_id, target_port=target_port,
                issue_type="optional_field_gap",
                message=f"Optional fields not available: {sorted(missing_optional)}",
                details={"missing_optional": sorted(missing_optional)},
            ))


def _check_branch_fan_out(
    branch_def: BranchDef,
    blueprint: ChainBlueprint,
    contracts: dict[str, NodeContract],
    report: PortCompatibilityReport,
    strict: bool,
) -> None:
    """Check that the branch source node's output is compatible with
    each branch's first node's input."""
    source_id = branch_def.from_node
    source_contract = contracts.get(source_id)
    if source_contract is None:
        return

    for branch_name, node_ids in branch_def.branches.items():
        if not node_ids:
            continue

        first_node_id = node_ids[0]
        target_contract = contracts.get(first_node_id)
        if target_contract is None:
            continue

        report.checks_run += 1

        # Check type compatibility between source and first branch node
        if source_contract.exit.output_type != target_contract.entry.input_type:
            report.issues.append(PortIssue(
                severity="error",
                source_node=source_id, source_port="output",
                target_node=first_node_id, target_port="input",
                issue_type="type_mismatch",
                message=(
                    f"Branch '{branch_name}': {source_id} produces "
                    f"'{source_contract.exit.output_type}' but {first_node_id} "
                    f"expects '{target_contract.entry.input_type}'"
                ),
                details={
                    "branch": branch_name,
                    "source_output_type": source_contract.exit.output_type,
                    "target_input_type": target_contract.entry.input_type,
                },
            ))


def _check_join_fan_in(
    join_def: JoinDef,
    blueprint: ChainBlueprint,
    contracts: dict[str, NodeContract],
    report: PortCompatibilityReport,
    strict: bool,
) -> None:
    """Check that each branch's last node output is compatible with
    the join target node's input."""
    join_node_id = join_def.to_node
    join_contract = contracts.get(join_node_id)
    if join_contract is None:
        return

    # Find which branches feed into this join
    for branch_def in blueprint.branches:
        for branch_name in join_def.from_branches:
            if branch_name not in branch_def.branches:
                continue

            node_ids = branch_def.branches[branch_name]
            if not node_ids:
                continue

            last_node_id = node_ids[-1]
            last_contract = contracts.get(last_node_id)
            if last_contract is None:
                continue

            report.checks_run += 1

            # Check type compatibility between last branch node and join target
            if last_contract.exit.output_type != join_contract.entry.input_type:
                report.issues.append(PortIssue(
                    severity="error",
                    source_node=last_node_id, source_port="output",
                    target_node=join_node_id, target_port="input",
                    issue_type="fan_in_mismatch",
                    message=(
                        f"Join fan-in mismatch: branch '{branch_name}' last node "
                        f"{last_node_id} produces '{last_contract.exit.output_type}' "
                        f"but join target {join_node_id} expects "
                        f"'{join_contract.entry.input_type}'"
                    ),
                    details={
                        "branch": branch_name,
                        "join_id": join_def.join_id,
                        "source_output_type": last_contract.exit.output_type,
                        "target_input_type": join_contract.entry.input_type,
                    },
                ))
