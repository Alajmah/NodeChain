"""Multi-Chain Orchestrator (v1.22.0).

Enables chain-of-chains composition: a meta-chain that invokes multiple
sub-chains, manages dependencies between them, and aggregates results.

Capabilities:
  1. SubChainStep — a node that invokes another chain blueprint
  2. ChainOrchestrator — coordinates multiple sub-chains with dependencies
  3. Dependency graph — chains can depend on other chains' outputs
  4. Result aggregation — collects and merges sub-chain outputs
  5. Failure propagation — configurable failure handling per sub-chain
  6. Composed trace — full trace including sub-chain executions

Design principles:
  - Each sub-chain executes independently with its own state
  - Dependencies are data-flow edges (output → input mapping)
  - The orchestrator is itself a chain node (composable recursively)
  - No mutation of sub-chain blueprints (read-only composition)
  - Full trace lineage preserved
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest
from nodechain.nodes.base_node import BaseNode


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
    upstream_outputs: dict[str, dict[str, Any]],
    node_registry: dict[str, BaseNode] | None = None,
) -> SubChainResult:
    """Execute a single sub-chain node directly (no full Orchestrator).

    For full chain execution, use the Orchestrator. This lightweight executor
    runs a single node from the node registry, suitable for composition.

    Args:
        spec: Sub-chain specification.
        upstream_outputs: Outputs from dependency chains.
        node_registry: Registry of available nodes.

    Returns:
        SubChainResult with output or error.
    """
    start_ts = time.time()

    if node_registry is None:
        node_registry = {}

    # Resolve inputs from upstream outputs
    resolved_inputs: dict[str, Any] = {}
    for key, value in spec.inputs.items():
        if isinstance(value, str) and value.startswith("@"):
            # Reference: @chain_id.field
            parts = value[1:].split(".", 1)
            if len(parts) == 2:
                src_chain, src_field = parts
                src_data = upstream_outputs.get(src_chain, {})
                resolved_inputs[key] = src_data.get(src_field, "")
            else:
                resolved_inputs[key] = value
        else:
            resolved_inputs[key] = value

    # Try to find and execute a node with chain_id
    node = node_registry.get(spec.chain_id)
    if node is None:
        return SubChainResult(
            chain_id=spec.chain_id,
            status="failed",
            error=f"Node '{spec.chain_id}' not found in registry",
            duration_ms=(time.time() - start_ts) * 1000,
            blueprint_path=spec.blueprint_path,
        )

    try:
        envelope = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()),
            run_id=str(uuid.uuid4()),
            chain_id=f"composed:{spec.chain_id}",
            node_id=spec.chain_id,
            step_id=1,
            payload=resolved_inputs,
        )
        response = await node.execute(envelope)
        return SubChainResult(
            chain_id=spec.chain_id,
            status="completed",
            output=response.output,
            duration_ms=(time.time() - start_ts) * 1000,
            blueprint_path=spec.blueprint_path,
        )
    except Exception as e:
        return SubChainResult(
            chain_id=spec.chain_id,
            status="failed",
            error=str(e),
            duration_ms=(time.time() - start_ts) * 1000,
            blueprint_path=spec.blueprint_path,
        )


async def orchestrate_composition(
    plan: CompositionPlan,
    node_registry: dict[str, BaseNode],
    initial_input: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a composition plan: run all sub-chains in dependency order.

    Args:
        plan: The composition plan.
        node_registry: Available nodes for execution.
        initial_input: Initial payload passed to root chains.

    Returns:
        Orchestration result with all sub-chain outputs, aggregated result,
        and lineage metadata.
    """
    orchestration_id = str(uuid.uuid4())
    start_ts = time.time()

    # Get execution order
    order = plan.topological_order()

    # Track outputs
    outputs: dict[str, dict[str, Any]] = {}
    results: list[SubChainResult] = []
    skipped: list[str] = []

    for chain_id in order:
        spec = next(s for s in plan.sub_chains if s.chain_id == chain_id)

        # Check if any dependency failed
        dep_failed = False
        for dep in spec.depends_on:
            if dep in skipped or outputs.get(dep, {}).get("_status") == "failed":
                dep_failed = True
                break

        if dep_failed:
            if spec.failure_mode == "skip":
                skipped.append(chain_id)
                results.append(SubChainResult(
                    chain_id=chain_id,
                    status="skipped",
                    error="Dependency failed",
                    blueprint_path=spec.blueprint_path,
                ))
                continue
            elif spec.failure_mode == "default":
                outputs[chain_id] = {**spec.default_output, "_status": "defaulted"}
                results.append(SubChainResult(
                    chain_id=chain_id,
                    status="defaulted",
                    output=spec.default_output,
                    blueprint_path=spec.blueprint_path,
                ))
                continue

        # Execute sub-chain
        # Merge initial_input for root chains (no dependencies)
        if not spec.depends_on and initial_input:
            merged_inputs = {**initial_input, **spec.inputs}
            temp_spec = SubChainSpec(
                chain_id=spec.chain_id,
                blueprint_path=spec.blueprint_path,
                inputs=merged_inputs,
                depends_on=spec.depends_on,
                failure_mode=spec.failure_mode,
                default_output=spec.default_output,
            )
            result = await execute_sub_chain(temp_spec, outputs, node_registry)
        else:
            result = await execute_sub_chain(spec, outputs, node_registry)

        results.append(result)

        if result.status == "completed":
            outputs[chain_id] = result.output
        elif result.status == "failed":
            outputs[chain_id] = {"_status": "failed", "_error": result.error}
            if spec.failure_mode == "propagate":
                # Mark all downstream chains as skipped
                for downstream in order[order.index(chain_id)+1:]:
                    skipped.append(downstream)
                    ds = next(s for s in plan.sub_chains if s.chain_id == downstream)
                    results.append(SubChainResult(
                        chain_id=downstream,
                        status="skipped",
                        error=f"Upstream '{chain_id}' failed (propagate)",
                        blueprint_path=ds.blueprint_path,
                    ))
                break
            elif spec.failure_mode == "default":
                outputs[chain_id] = {**spec.default_output, "_status": "defaulted"}
            # "continue" mode: just proceed

    # Aggregate results
    aggregated = _aggregate_results(outputs, plan.aggregation_strategy)

    duration_ms = (time.time() - start_ts) * 1000

    return {
        "type": "orchestration_result",
        "orchestration_id": orchestration_id,
        "plan_id": plan.plan_id,
        "plan_digest": plan.compute_digest(),
        "status": "completed" if not skipped or all(r.status in ("completed", "defaulted") for r in results) else "partial",
        "execution_order": order,
        "sub_chain_results": [r.to_dict() for r in results],
        "outputs": outputs,
        "aggregated_result": aggregated,
        "aggregation_strategy": plan.aggregation_strategy,
        "skipped": skipped,
        "duration_ms": round(duration_ms, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nodechain_version": "1.22.0",
    }


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
    """A node that represents a sub-chain invocation within a composition.

    This node can be used in a regular chain blueprint to invoke
    another chain. When executed, it runs the composition plan
    and returns the aggregated result.
    """

    def __init__(self, plan: CompositionPlan | None = None) -> None:
        self._plan = plan

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="sub_chain_step",
            node_type="deterministic",
            name="Sub-Chain Step",
            description="Invokes a sub-chain composition plan",
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
        payload = envelope.payload

        # Resolve plan
        plan = self._plan
        if plan is None:
            plan_data = payload.get("plan", {})
            if plan_data:
                plan = CompositionPlan.from_dict(plan_data)
            else:
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
                        "error": "No composition plan provided",
                        "aggregated_result": {},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    output_type="dict",
                )

        # Build node registry from available nodes
        from nodechain.registry.local_registry import RegistryIndex
        registry = RegistryIndex()
        registry.scan()

        node_registry: dict[str, BaseNode] = {}
        for spec in plan.sub_chains:
            pkg = registry.get_package(spec.chain_id)
            if pkg:
                try:
                    node_cls = pkg.load()
                    if isinstance(node_cls, list):
                        for cls in node_cls:
                            instance = cls()
                            node_registry[instance.manifest().node_id] = instance
                    else:
                        instance = node_cls()
                        node_registry[instance.manifest().node_id] = instance
                except Exception:
                    pass

        # Also add built-in nodes
        from nodechain.nodes.goal_interpreter import GoalInterpreterNode as GoalInterpreter
        from nodechain.nodes.task_planner import TaskPlannerNode as TaskPlanner
        from nodechain.nodes.evidence_synthesizer import EvidenceSynthesizerNode as EvidenceSynthesizer
        from nodechain.nodes.response_generator import ResponseGeneratorNode as ResponseGenerator
        for cls in [GoalInterpreter, TaskPlanner, EvidenceSynthesizer, ResponseGenerator]:
            try:
                instance = cls()
                node_registry[instance.manifest().node_id] = instance
            except Exception:
                pass

        # Execute composition
        initial_input = {k: v for k, v in payload.items() if k != "plan"}
        result = await orchestrate_composition(plan, node_registry, initial_input)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="sub_chain_step",
            step_id=envelope.step_id,
            output=result,
            output_type="dict",
        )
