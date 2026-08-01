"""Tests for contract validation and compatibility checking."""

import pytest

from nodechain.core.contract import (
    EntryContract,
    ExitContract,
    NodeContract,
    ContractRegistry,
    check_compatibility,
    Requirements,
)
from nodechain.core.port import PortType


class TestContractModel:
    """Test NodeContract model creation and validation."""

    def test_create_contract(self):
        contract = NodeContract(
            contract_id="test.v1",
            node_id="test_node",
            entry=EntryContract(
                input_type=PortType.RAW_QUERY,
                schema_ref="nodechain://schemas/semantic_types/raw_user_query",
                required_fields=["query"],
            ),
            exit=ExitContract(
                output_type=PortType.RESEARCH_GOAL,
                schema_ref="nodechain://schemas/semantic_types/normalized_research_goal",
                guaranteed_fields=["primary_question"],
            ),
        )
        assert contract.node_id == "test_node"
        assert contract.entry.input_type == PortType.RAW_QUERY
        assert contract.exit.output_type == PortType.RESEARCH_GOAL


class TestCompatibility:
    """Test contract compatibility between connected nodes."""

    def test_compatible_contracts(self):
        source = NodeContract(
            contract_id="source.v1",
            node_id="source",
            entry=EntryContract(
                input_type=PortType.RAW_QUERY,
                schema_ref="nodechain://schemas/semantic_types/raw_user_query",
            ),
            exit=ExitContract(
                output_type=PortType.RESEARCH_GOAL,
                schema_ref="nodechain://schemas/semantic_types/normalized_research_goal",
                guaranteed_fields=["primary_question", "research_domain"],
            ),
        )

        target = NodeContract(
            contract_id="target.v1",
            node_id="target",
            entry=EntryContract(
                input_type=PortType.RESEARCH_GOAL,
                schema_ref="nodechain://schemas/semantic_types/normalized_research_goal",
                required_fields=["primary_question"],
            ),
            exit=ExitContract(
                output_type=PortType.TASK_PLAN,
                schema_ref="nodechain://schemas/semantic_types/task_plan",
            ),
        )

        result = check_compatibility(source, target)
        assert result.compatible is True
        assert len(result.issues) == 0

    def test_incompatible_types(self):
        source = NodeContract(
            contract_id="s.v1",
            node_id="source",
            entry=EntryContract(
                input_type=PortType.RAW_QUERY,
                schema_ref="raw",
            ),
            exit=ExitContract(
                output_type=PortType.RAW_QUERY,
                schema_ref="raw",
            ),
        )

        target = NodeContract(
            contract_id="t.v1",
            node_id="target",
            entry=EntryContract(
                input_type=PortType.RESEARCH_GOAL,
                schema_ref="goal",
            ),
            exit=ExitContract(
                output_type=PortType.TASK_PLAN,
                schema_ref="plan",
            ),
        )

        result = check_compatibility(source, target)
        assert result.compatible is False
        assert any("Type mismatch" in i for i in result.issues)

    def test_missing_required_fields(self):
        source = NodeContract(
            contract_id="s.v1",
            node_id="source",
            entry=EntryContract(input_type="a", schema_ref="a"),
            exit=ExitContract(
                output_type="b",
                schema_ref="b",
                guaranteed_fields=["field_a"],
            ),
        )

        target = NodeContract(
            contract_id="t.v1",
            node_id="target",
            entry=EntryContract(
                input_type="b",
                schema_ref="b",
                required_fields=["field_a", "field_b"],
            ),
            exit=ExitContract(output_type="c", schema_ref="c"),
        )

        result = check_compatibility(source, target)
        assert result.compatible is False
        assert any("field_b" in i for i in result.issues)


class TestContractRegistry:
    """Test contract registry with blueprint connection validation."""

    def test_registry_validate_all_connections(self):
        from nodechain.core.blueprint import load_blueprint

        registry = ContractRegistry()
        # Register the 12 node contracts
        from nodechain.nodes.goal_interpreter import GOAL_INTERPRETER_CONTRACT
        from nodechain.nodes.task_planner import TASK_PLANNER_CONTRACT
        from nodechain.nodes.context_selector import CONTEXT_SELECTOR_CONTRACT
        from nodechain.nodes.source_ingestion import SOURCE_INGESTION_CONTRACT
        from nodechain.nodes.search_tool import SEARCH_TOOL_CONTRACT
        from nodechain.nodes.source_quality import SOURCE_QUALITY_CONTRACT
        from nodechain.nodes.evidence_synthesizer import EVIDENCE_SYNTHESIZER_CONTRACT
        from nodechain.nodes.claim_validator import CLAIM_VALIDATOR_CONTRACT
        from nodechain.nodes.risk_classifier import RISK_CLASSIFIER_CONTRACT
        from nodechain.nodes.response_generator import RESPONSE_GENERATOR_CONTRACT
        from nodechain.nodes.memory_write import MEMORY_WRITE_CONTRACT
        from nodechain.nodes.trace_collector import TRACE_COLLECTOR_CONTRACT

        for contract in [
            GOAL_INTERPRETER_CONTRACT,
            TASK_PLANNER_CONTRACT,
            CONTEXT_SELECTOR_CONTRACT,
            SEARCH_TOOL_CONTRACT,
            SOURCE_INGESTION_CONTRACT,
            SOURCE_QUALITY_CONTRACT,
            EVIDENCE_SYNTHESIZER_CONTRACT,
            CLAIM_VALIDATOR_CONTRACT,
            RISK_CLASSIFIER_CONTRACT,
            RESPONSE_GENERATOR_CONTRACT,
            MEMORY_WRITE_CONTRACT,
            TRACE_COLLECTOR_CONTRACT,
        ]:
            registry.register(contract)

        # Load blueprint and validate connections
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        connections = [
            {"from_node": c.from_node, "to_node": c.to_node}
            for c in blueprint.connections
        ]

        results = registry.validate_connections(connections)

        # All connections should be compatible
        incompatible = [r for r in results if not r.compatible]
        assert len(incompatible) == 0, (
            f"Incompatible connections: {[(r.source_node, r.target_node, r.issues) for r in incompatible]}"
        )
