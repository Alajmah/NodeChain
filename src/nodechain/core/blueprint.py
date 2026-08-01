"""Chain Blueprint — declarative chain definition loader and validator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class NodeDef(BaseModel):
    """Node definition within a blueprint."""

    node_id: str
    node_type: str
    config: dict[str, Any] = Field(default_factory=dict)
    position: int = 0


class ConnectionDef(BaseModel):
    """Connection between two nodes in a blueprint."""

    from_node: str
    from_port: str
    to_node: str
    to_port: str
    condition: str | None = None
    label: str | None = None


class BranchDef(BaseModel):
    """Branch definition — fan-out from one node to multiple candidate paths."""

    branch_id: str
    from_node: str  # Node that decides which branches to take
    branches: dict[str, list[str]]  # branch_name → list of node_ids in that branch
    default_branch: str | None = None  # Branch to take if no condition matches


class JoinDef(BaseModel):
    """Join definition — fan-in from multiple branches to one node."""

    join_id: str
    to_node: str  # Node that receives merged outputs
    from_branches: list[str]  # Branch names that feed into this join
    wait_for: str = "all"  # "all" | "any" | "first" | "quorum"
    merge_strategy: str = "merge"  # "merge" | "append" | "latest" | "concat"
    quorum_count: int | None = None  # Minimum number of successful branches
    quorum_ratio: float | None = None  # Minimum ratio of successful branches (0.0–1.0)
    cancellation_after_quorum: str = "cancel"  # "cancel" | "ignore_late" | "allow_all"


class LoopDef(BaseModel):
    """Bounded loop definition."""

    loop_id: str
    entry_condition: str
    exit_condition: str
    max_iterations: int = 2
    max_cost_usd: float = 0.5
    path: list[str]
    escalation: str | None = None


class GateDef(BaseModel):
    """Human review gate definition."""

    gate_id: str
    trigger: str
    allowed_decisions: list[str]
    timeout_minutes: int = 30
    approver_role: str = "chain_operator"


class InvariantDef(BaseModel):
    """Chain invariant — enforced at load time, runtime, or both."""

    invariant_id: str
    description: str
    enforcement: str = "both"  # load_time, runtime, both


class ChainBlueprint(BaseModel):
    """
    Declarative chain definition. Loaded from YAML, validated at chain start.
    This is the single source of truth for chain structure.
    """

    chain_id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    goal: str
    nodes: list[NodeDef]
    connections: list[ConnectionDef]
    loops: list[LoopDef] = Field(default_factory=list)
    branches: list[BranchDef] = Field(default_factory=list)
    joins: list[JoinDef] = Field(default_factory=list)
    gates: list[GateDef] = Field(default_factory=list)
    invariants: list[InvariantDef] = Field(default_factory=list)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    trace: dict[str, Any] = Field(default_factory=dict)
    """Trace metadata: required, terminal_audit_required, reconciler_required."""
    governance: dict[str, Any] = Field(default_factory=dict)
    """Governance metadata: strict_policy_coverage, cancellation_policies."""
    policy_preset: str = ""  # v1.3.5: minimal|standard_untrusted|production_untrusted
    """Policy preset for sandbox/resource governance. v1.3.5 additive."""

    model_config = {"extra": "forbid"}

    def node_ids(self) -> list[str]:
        return [n.node_id for n in self.nodes]

    def get_node(self, node_id: str) -> NodeDef | None:
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        return None

    def get_connections_from(self, node_id: str) -> list[ConnectionDef]:
        return [c for c in self.connections if c.from_node == node_id]

    def get_connections_to(self, node_id: str) -> list[ConnectionDef]:
        return [c for c in self.connections if c.to_node == node_id]

    def get_loop(self, loop_id: str) -> LoopDef | None:
        for loop in self.loops:
            if loop.loop_id == loop_id:
                return loop
        return None

    def get_branch(self, branch_id: str) -> BranchDef | None:
        for b in self.branches:
            if b.branch_id == branch_id:
                return b
        return None

    def get_branches_from(self, node_id: str) -> list[BranchDef]:
        return [b for b in self.branches if b.from_node == node_id]

    def get_join_for(self, node_id: str) -> JoinDef | None:
        for j in self.joins:
            if j.to_node == node_id:
                return j
        return None

    def is_branch_node(self, node_id: str) -> bool:
        return any(b.from_node == node_id for b in self.branches)

    def is_join_node(self, node_id: str) -> bool:
        return any(j.to_node == node_id for j in self.joins)


def load_blueprint(path: str | Path) -> ChainBlueprint:
    """Load and parse a chain blueprint from YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Blueprint not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    return ChainBlueprint(**raw)
