"""Composition plan model and legacy composition surfaces (H0.3 fail-closed).

This module previously hosted a lightweight parallel executor that constructed
its own ``InvocationEnvelope`` and called ``await node.execute(envelope)``
directly, bypassing the canonical ``Orchestrator`` and every governed
authority (policy, trust admission, side-effect journal, invocation ledger,
durable state, trace, recovery, review, validation, containment).

H0.3 removes that bypass. The module now retains only the pure data/model
utilities that composition planning and validation need:

  * :class:`SubChainSpec`
  * :class:`CompositionPlan`
  * :class:`SubChainResult`
  * :func:`CompositionPlan.topological_order`
  * :func:`CompositionPlan.compute_digest`
  * :func:`_aggregate_results`

The execution surfaces are retained as import-compatible symbols so callers
that referenced them get an explicit, stable failure rather than an import
error:

  * :func:`execute_sub_chain` — raises :class:`GovernedCompositionRequired`
  * :func:`orchestrate_composition` — raises :class:`GovernedCompositionRequired`
  * :class:`SubChainStep` — ``execute()`` returns an unsuccessful
    ``EnvelopeResponse`` with ``error = governed_composition_backend_required``

There is no escape hatch, ``_unsafe`` flag, environment override, or private
back door in ``src/nodechain`` that re-enables the legacy executor. Governed
composition — when it becomes a real product requirement — must be designed
from first principles around a canonical child ``Orchestrator``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest
from nodechain.nodes.base_node import BaseNode


#: Stable reason code returned/raised by every legacy composition execution
#: surface. The CLI maps this to ``EXIT_VALIDATION`` (10).
GOVERNED_COMPOSITION_BACKEND_REQUIRED = "governed_composition_backend_required"


class GovernedCompositionRequired(Exception):
    """Raised when legacy composition execution is invoked.

    The legacy ``execute_sub_chain`` / ``orchestrate_composition`` paths have
    been retired in H0.3 because they executed Harness Nodes outside the
    canonical ``Orchestrator``, bypassing every governed authority. This
    exception is raised at the boundary so callers fail fast with a stable
    reason code rather than silently running an ungoverned executor.
    """

    #: Stable reason code for programmatic consumers.
    code: str = GOVERNED_COMPOSITION_BACKEND_REQUIRED

    def __init__(self, message: str = GOVERNED_COMPOSITION_BACKEND_REQUIRED) -> None:
        super().__init__(message)


# ── Composition Plan ────────────────────────────────────────────────────────

class SubChainSpec:
    """Specification for a sub-chain within a composed orchestration.

    Attributes:
        chain_id: Identifier for this sub-chain within the composition
        blueprint_path: Path to the sub-chain's blueprint YAML
        inputs: Mapping of input field → source (literal value or "@chain_id.field")
        depends_on: List of chain_ids that must complete before this one
        failure_mode: What to do if this sub-chain fails
            (propagate, skip, continue, default)
        default_output: Default output if chain fails and mode is "default"
    """

    def __init__(
        self,
        chain_id: str,
        blueprint_path: str = "",
        inputs: dict[str, Any] | None = None,
        depends_on: list[str] | None = None,
        failure_mode: str = "propagate",
        default_output: dict[str, Any] | None = None,
    ):
        self.chain_id = chain_id
        self.blueprint_path = blueprint_path
        self.inputs = inputs or {}
        self.depends_on = depends_on or []
        self.failure_mode = failure_mode
        self.default_output = default_output or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "blueprint_path": self.blueprint_path,
            "inputs": self.inputs,
            "depends_on": self.depends_on,
            "failure_mode": self.failure_mode,
            "default_output": self.default_output,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubChainSpec:
        return cls(
            chain_id=data["chain_id"],
            blueprint_path=data.get("blueprint_path", ""),
            inputs=data.get("inputs", {}),
            depends_on=data.get("depends_on", []),
            failure_mode=data.get("failure_mode", "propagate"),
            default_output=data.get("default_output", {}),
        )


class CompositionPlan:
    """A plan for composing multiple sub-chains.

    Defines the sub-chains, their dependencies, and the aggregation strategy.
    """

    AGGREGATION_STRATEGIES = frozenset({"merge_all", "last_only", "collect_list", "scored_best"})

    def __init__(
        self,
        plan_id: str = "",
        sub_chains: list[SubChainSpec] | None = None,
        aggregation_strategy: str = "merge_all",
        description: str = "",
    ):
        self.plan_id = plan_id or str(uuid.uuid4())
        self.sub_chains = sub_chains or []
        self.aggregation_strategy = aggregation_strategy
        self.description = description

    def topological_order(self) -> list[str]:
        """Return chain_ids in dependency order (topological sort).

        Raises ValueError if there's a cycle.
        """
        # Build dependency graph
        deps: dict[str, set[str]] = {}
        all_ids = set()
        for sc in self.sub_chains:
            all_ids.add(sc.chain_id)
            deps[sc.chain_id] = set(sc.depends_on)

        # Kahn's algorithm
        order: list[str] = []
        no_deps = {cid for cid in all_ids if not deps[cid]}

        while no_deps:
            cid = no_deps.pop()
            order.append(cid)
            # Remove this chain from others' dependencies
            for other in deps:
                if cid in deps[other]:
                    deps[other].discard(cid)
                    if not deps[other] and other not in order and other not in no_deps:
                        no_deps.add(other)

        if len(order) != len(all_ids):
            remaining = all_ids - set(order)
            raise ValueError(f"Circular dependency detected among: {remaining}")

        return order

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "type": "composition_plan",
            "sub_chains": [sc.to_dict() for sc in self.sub_chains],
            "aggregation_strategy": self.aggregation_strategy,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompositionPlan:
        return cls(
            plan_id=data.get("plan_id", ""),
            sub_chains=[SubChainSpec.from_dict(sc) for sc in data.get("sub_chains", [])],
            aggregation_strategy=data.get("aggregation_strategy", "merge_all"),
            description=data.get("description", ""),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> CompositionPlan:
        """Load a composition plan from YAML."""
        path = Path(path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls.from_dict(raw)

    def compute_digest(self) -> str:
        """SHA-256 digest of the plan (for trace lineage)."""
        content = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode()).hexdigest()


# ── Sub-Chain Execution ─────────────────────────────────────────────────────

class SubChainResult:
    """Result of executing a single sub-chain within a composition."""

    def __init__(
        self,
        chain_id: str,
        status: str,  # completed, failed, skipped, defaulted
        output: dict[str, Any] | None = None,
        error: str = "",
        duration_ms: float = 0.0,
        blueprint_path: str = "",
    ):
        self.chain_id = chain_id
        self.status = status
        self.output = output or {}
        self.error = error
        self.duration_ms = duration_ms
        self.blueprint_path = blueprint_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "status": self.status,
            "output": self.output,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "blueprint_path": self.blueprint_path,
        }


async def execute_sub_chain(
    spec: SubChainSpec,
    upstream_outputs: dict[str, dict[str, Any]] | None = None,
    node_registry: dict[str, BaseNode] | None = None,
) -> SubChainResult:
    """Fail-closed legacy composition entry point (H0.3).

    This function previously resolved a ``BaseNode`` from ``node_registry``,
    constructed a fresh ``InvocationEnvelope`` with synthesized run/chain/step
    identity, and called ``await node.execute(envelope)`` directly — bypassing
    the canonical ``Orchestrator`` and every governed authority.

    H0.3 retires that path. The symbol is retained for import compatibility
    only. Calling it now raises :class:`GovernedCompositionRequired` before
    any node resolution, envelope construction, or execution occurs.

    Raises:
        GovernedCompositionRequired: always. There is no escape hatch.
    """
    raise GovernedCompositionRequired()


async def orchestrate_composition(
    plan: CompositionPlan,
    node_registry: dict[str, BaseNode] | None = None,
    initial_input: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fail-closed legacy composition entry point (H0.3).

    This function previously drove a parallel mini-runtime: it ran sub-chains
    in topological order, calling :func:`execute_sub_chain` for each, which
    in turn called ``await node.execute(envelope)`` outside the canonical
    ``Orchestrator``.

    H0.3 retires that path. The symbol is retained for import compatibility
    only. Calling it now raises :class:`GovernedCompositionRequired` before
    any sub-chain execution, dependency resolution, or aggregation occurs.

    Raises:
        GovernedCompositionRequired: always. There is no escape hatch.
    """
    raise GovernedCompositionRequired()


def _aggregate_results(
    outputs: dict[str, dict[str, Any]],
    strategy: str,
) -> dict[str, Any]:
    """Aggregate sub-chain outputs using the specified strategy.

    Strategies:
        merge_all: Merge all outputs into one dict (later chains override)
        last_only: Return only the last chain's output
        collect_list: Collect all outputs into a list
        scored_best: Return the output with the highest 'audit_score' or 'score'
    """
    valid_outputs = {
        k: v for k, v in outputs.items()
        if v.get("_status") not in ("failed",)
    }

    if not valid_outputs:
        return {}

    if strategy == "merge_all":
        result: dict[str, Any] = {}
        for output in valid_outputs.values():
            result.update(output)
        return result

    elif strategy == "last_only":
        last_key = list(valid_outputs.keys())[-1]
        return valid_outputs[last_key]

    elif strategy == "collect_list":
        return {"chains": list(valid_outputs.values())}

    elif strategy == "scored_best":
        best_score = -1
        best_output: dict[str, Any] = {}
        for output in valid_outputs.values():
            score = output.get("audit_score", output.get("score", 0))
            if score > best_score:
                best_score = score
                best_output = output
        return best_output

    return {}


# ── SubChainStep Node ───────────────────────────────────────────────────────

class SubChainStep(BaseNode):
    """Legacy sub-chain invocation node (H0.3 fail-closed).

    Previously, ``execute()`` built a node registry by scanning the package
    registry, constructed child nodes, and called
    :func:`orchestrate_composition` — re-entering the ungoverned executor.

    H0.3 retires that path. The class is retained so existing imports and
    node registries that reference it keep working, but ``execute()`` now
    returns an unsuccessful ``EnvelopeResponse`` with
    ``error = governed_composition_backend_required`` and ``success = False``
    **before** any registry access, child-node construction, or composition
    invocation occurs. This ensures a ``SubChainStep`` running inside the
    real ``Orchestrator`` cannot become a tunnel back into the legacy bypass.
    """

    def __init__(self, plan: CompositionPlan | None = None) -> None:
        self._plan = plan

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="sub_chain_step",
            node_type="deterministic",
            name="Sub-Chain Step",
            description="Legacy sub-chain step (governed composition backend required)",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="composition.subchain.v1",
            node_id="sub_chain_step",
            version="1.0.0",
            entry={
                "schema_ref": "",
                "input_type": "composition_input",
                "required_fields": [],
                "optional_fields": ["plan", "blueprint_path", "inputs"],
            },
            exit={
                "schema_ref": "",
                "output_type": "orchestration_result",
                "guaranteed_fields": [
                    "orchestration_id", "plan_digest", "status",
                    "aggregated_result", "timestamp",
                ],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        """Return a governed-backend-required response; never execute.

        Fails closed before registry access, package loading, child-node
        construction, or any call to :func:`orchestrate_composition`.
        """
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="sub_chain_step",
            step_id=envelope.step_id,
            output={
                "orchestration_id": "",
                "plan_digest": "",
                "status": "failed",
                "error": GOVERNED_COMPOSITION_BACKEND_REQUIRED,
                "aggregated_result": {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
            success=False,
            error=GOVERNED_COMPOSITION_BACKEND_REQUIRED,
        )
