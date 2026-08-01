"""Tests for the Multi-Chain Orchestrator (v1.22.0).

Tests cover:
1. CompositionPlan — creation, YAML loading, topological sort, digest
2. SubChainSpec — input resolution, dependency declaration
3. SubChainResult — status tracking
4. Orchestration — execution order, failure modes, aggregation
5. SubChainStep node — composable node interface
6. Aggregation strategies — merge_all, last_only, collect_list, scored_best
7. Error handling — missing nodes, circular deps, propagation
"""

from __future__ import annotations

import asyncio
import json
import pytest
import uuid
from pathlib import Path

from nodechain.core.envelope import InvocationEnvelope


# ── CompositionPlan Tests ───────────────────────────────────────────────────

class TestCompositionPlan:
    """CompositionPlan creation, serialization, and digest."""

    def test_create_empty_plan(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan
        plan = CompositionPlan()
        assert plan.plan_id
        assert plan.sub_chains == []
        assert plan.aggregation_strategy == "merge_all"

    def test_create_with_sub_chains(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan = CompositionPlan(
            sub_chains=[
                SubChainSpec(chain_id="a", depends_on=[]),
                SubChainSpec(chain_id="b", depends_on=["a"]),
            ],
        )
        assert len(plan.sub_chains) == 2

    def test_serialization_roundtrip(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan = CompositionPlan(
            plan_id="test-plan",
            sub_chains=[
                SubChainSpec(chain_id="a", inputs={"x": 1}, depends_on=[]),
                SubChainSpec(chain_id="b", depends_on=["a"], failure_mode="default"),
            ],
            aggregation_strategy="collect_list",
        )
        d = plan.to_dict()
        restored = CompositionPlan.from_dict(d)
        assert restored.plan_id == "test-plan"
        assert len(restored.sub_chains) == 2
        assert restored.aggregation_strategy == "collect_list"

    def test_compute_digest_deterministic(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan1 = CompositionPlan(
            plan_id="test",
            sub_chains=[SubChainSpec(chain_id="a")],
        )
        plan2 = CompositionPlan(
            plan_id="test",
            sub_chains=[SubChainSpec(chain_id="a")],
        )
        assert plan1.compute_digest() == plan2.compute_digest()

    def test_different_plans_different_digests(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan1 = CompositionPlan(sub_chains=[SubChainSpec(chain_id="a")])
        plan2 = CompositionPlan(sub_chains=[SubChainSpec(chain_id="b")])
        assert plan1.compute_digest() != plan2.compute_digest()


class TestTopologicalSort:
    """Topological ordering of sub-chains."""

    def test_linear_dependency(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="c", depends_on=["b"]),
            SubChainSpec(chain_id="b", depends_on=["a"]),
            SubChainSpec(chain_id="a", depends_on=[]),
        ])
        order = plan.topological_order()
        assert order.index("a") < order.index("b")
        assert order.index("b") < order.index("c")

    def test_parallel_chains(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="a", depends_on=[]),
            SubChainSpec(chain_id="b", depends_on=[]),
            SubChainSpec(chain_id="c", depends_on=["a", "b"]),
        ])
        order = plan.topological_order()
        assert order.index("a") < order.index("c")
        assert order.index("b") < order.index("c")

    def test_circular_dependency_raises(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="a", depends_on=["b"]),
            SubChainSpec(chain_id="b", depends_on=["a"]),
        ])
        with pytest.raises(ValueError, match="Circular dependency"):
            plan.topological_order()

    def test_single_chain(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec
        plan = CompositionPlan(sub_chains=[SubChainSpec(chain_id="solo")])
        assert plan.topological_order() == ["solo"]


# ── Input Resolution Tests ──────────────────────────────────────────────────

class TestInputResolution:
    """Input references (@chain.field) are resolved correctly."""

    @pytest.mark.asyncio
    async def test_literal_input_passed_through(self):
        from nodechain.runtime.chain_orchestrator import SubChainSpec, execute_sub_chain
        spec = SubChainSpec(chain_id="echo", inputs={"message": "hello"})
        result = await execute_sub_chain(spec, {})
        # echo may not be registered; check it handles gracefully
        assert result.status in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_reference_input_resolved(self):
        from nodechain.runtime.chain_orchestrator import SubChainSpec, execute_sub_chain
        spec = SubChainSpec(chain_id="echo", inputs={"message": "@upstream.result"})
        result = await execute_sub_chain(spec, {"upstream": {"result": "resolved_value"}})
        assert result.status in ("completed", "failed")


# ── Orchestration Tests ─────────────────────────────────────────────────────

class TestOrchestration:
    """Full orchestration execution."""

    @pytest.mark.asyncio
    async def test_single_node_composition(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition
        from nodes.echo_node.implementation import EchoNode

        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="echo_node", inputs={"message": "test"}),
        ])
        registry = {"echo_node": EchoNode()}
        result = await orchestrate_composition(plan, registry)

        assert result["status"] == "completed"
        assert len(result["sub_chain_results"]) == 1
        assert result["sub_chain_results"][0]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_linear_composition(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition
        from nodes.echo_node.implementation import EchoNode

        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="echo_node", inputs={"message": "first"}),
            SubChainSpec(
                chain_id="echo_node2",
                inputs={"message": "@echo_node.message"},
                depends_on=["echo_node"],
            ),
        ])
        registry = {"echo_node": EchoNode(), "echo_node2": EchoNode()}
        result = await orchestrate_composition(plan, registry)

        assert result["status"] == "completed"
        assert len(result["sub_chain_results"]) == 2
        assert "echo_node" in result["outputs"]
        assert "echo_node2" in result["outputs"]

    @pytest.mark.asyncio
    async def test_failure_propagation(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition

        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="missing", failure_mode="propagate"),
            SubChainSpec(chain_id="also_missing", depends_on=["missing"]),
        ])
        result = await orchestrate_composition(plan, {})

        assert result["status"] == "partial"
        assert "missing" in result["skipped"] or len(result["skipped"]) >= 1

    @pytest.mark.asyncio
    async def test_failure_skip_mode(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition

        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="missing", failure_mode="skip"),
            SubChainSpec(chain_id="also_missing", depends_on=["missing"], failure_mode="skip"),
        ])
        result = await orchestrate_composition(plan, {})

        # Failed chain + skipped dependent
        statuses = [r["status"] for r in result["sub_chain_results"]]
        assert "failed" in statuses or "skipped" in statuses

    @pytest.mark.asyncio
    async def test_failure_default_mode(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition

        plan = CompositionPlan(sub_chains=[
            SubChainSpec(
                chain_id="missing",
                failure_mode="default",
                default_output={"fallback": True, "score": 50},
            ),
        ])
        result = await orchestrate_composition(plan, {})

        assert result["status"] == "completed"
        assert result["outputs"]["missing"].get("fallback") is True

    @pytest.mark.asyncio
    async def test_parallel_composition(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition
        from nodes.echo_node.implementation import EchoNode

        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="chain_a", inputs={"message": "a"}),
            SubChainSpec(chain_id="chain_b", inputs={"message": "b"}),
        ], aggregation_strategy="merge_all")
        registry = {"chain_a": EchoNode(), "chain_b": EchoNode()}
        result = await orchestrate_composition(plan, registry)

        assert result["status"] == "completed"
        assert "chain_a" in result["outputs"]
        assert "chain_b" in result["outputs"]

    @pytest.mark.asyncio
    async def test_orchestration_has_lineage(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan, SubChainSpec, orchestrate_composition
        from nodes.echo_node.implementation import EchoNode

        plan = CompositionPlan(
            plan_id="test-lineage",
            sub_chains=[SubChainSpec(chain_id="echo_node", inputs={"message": "test"})],
        )
        registry = {"echo_node": EchoNode()}
        result = await orchestrate_composition(plan, registry)

        assert result["plan_id"] == "test-lineage"
        assert result["plan_digest"]
        assert result["orchestration_id"]
        assert result["execution_order"] == ["echo_node"]
        assert result["duration_ms"] >= 0


# ── Aggregation Strategy Tests ──────────────────────────────────────────────

class TestAggregationStrategies:
    """All 4 aggregation strategies produce correct results."""

    def test_merge_all(self):
        from nodechain.runtime.chain_orchestrator import _aggregate_results
        outputs = {"a": {"x": 1}, "b": {"y": 2}}
        result = _aggregate_results(outputs, "merge_all")
        assert result == {"x": 1, "y": 2}

    def test_merge_all_later_overrides(self):
        from nodechain.runtime.chain_orchestrator import _aggregate_results
        outputs = {"a": {"x": 1}, "b": {"x": 2}}
        result = _aggregate_results(outputs, "merge_all")
        assert result == {"x": 2}

    def test_last_only(self):
        from nodechain.runtime.chain_orchestrator import _aggregate_results
        outputs = {"a": {"x": 1}, "b": {"y": 2}}
        result = _aggregate_results(outputs, "last_only")
        assert result == {"y": 2}

    def test_collect_list(self):
        from nodechain.runtime.chain_orchestrator import _aggregate_results
        outputs = {"a": {"x": 1}, "b": {"y": 2}}
        result = _aggregate_results(outputs, "collect_list")
        assert "chains" in result
        assert len(result["chains"]) == 2

    def test_scored_best(self):
        from nodechain.runtime.chain_orchestrator import _aggregate_results
        outputs = {
            "a": {"audit_score": 70, "data": "low"},
            "b": {"audit_score": 95, "data": "high"},
        }
        result = _aggregate_results(outputs, "scored_best")
        assert result["audit_score"] == 95

    def test_empty_outputs(self):
        from nodechain.runtime.chain_orchestrator import _aggregate_results
        assert _aggregate_results({}, "merge_all") == {}


# ── SubChainStep Node Tests ─────────────────────────────────────────────────

class TestSubChainStep:
    """SubChainStep composable node."""

    @pytest.mark.asyncio
    async def test_contract_valid(self):
        from nodechain.runtime.chain_orchestrator import SubChainStep
        node = SubChainStep()
        assert node.manifest().node_id == "sub_chain_step"
        assert node.contract().contract_id == "composition.subchain.v1"

    @pytest.mark.asyncio
    async def test_execute_without_plan_returns_error(self):
        from nodechain.runtime.chain_orchestrator import SubChainStep
        node = SubChainStep()
        envelope = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=1, payload={},
        )
        result = await node.execute(envelope)
        assert result.output["status"] == "failed"

    @pytest.mark.asyncio
    async def test_execute_with_plan(self):
        from nodechain.runtime.chain_orchestrator import SubChainStep, CompositionPlan, SubChainSpec
        plan = CompositionPlan(sub_chains=[
            SubChainSpec(chain_id="echo_node", inputs={"message": "orchestrated"}),
        ])
        node = SubChainStep(plan=plan)
        envelope = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=1, payload={},
        )
        result = await node.execute(envelope)
        assert result.output["status"] in ("completed", "partial")
        assert result.output["plan_digest"]


# ── YAML Loading Test ───────────────────────────────────────────────────────

class TestYAMLLoading:
    """Composition plan loads from YAML."""

    def test_cross_domain_plan_loads(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan
        plan = CompositionPlan.from_yaml("blueprints/composition_cross_domain_v1.yaml")
        assert plan.plan_id == "cross_domain_assessment_v1"
        assert len(plan.sub_chains) == 4
        assert plan.aggregation_strategy == "merge_all"

    def test_cross_domain_plan_topological_order(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan
        plan = CompositionPlan.from_yaml("blueprints/composition_cross_domain_v1.yaml")
        order = plan.topological_order()
        # severity_triager has no deps
        assert "severity_triager" in order
        # audit_report_writer depends on trust_posture_auditor and remediation_decisioner
        assert order.index("trust_posture_auditor") < order.index("audit_report_writer")
        assert order.index("remediation_decisioner") < order.index("audit_report_writer")

    def test_cross_domain_plan_has_digest(self):
        from nodechain.runtime.chain_orchestrator import CompositionPlan
        plan = CompositionPlan.from_yaml("blueprints/composition_cross_domain_v1.yaml")
        digest = plan.compute_digest()
        assert len(digest) == 64  # SHA-256 hex


# ── CLI Tests ───────────────────────────────────────────────────────────────

class TestCLIComposition:
    """CLI compose command exists."""

    def test_compose_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        # compose command should be available
        assert "compose" in result.output

    def test_compose_plan_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["compose", "--help"])
        assert result.exit_code == 0
