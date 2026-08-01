"""Tests for port compatibility validation.

AC1: Connection source port must exist on upstream node contract.
AC2: Connection target port must exist on downstream node contract.
AC3: Source output schema must be compatible with target input schema.
AC4: Required target fields must be satisfied by source schema or mapping.
AC5: Type mismatch blocks blueprint load in strict mode.
AC6: Port mapping errors include source node, source port, target node, target port.
AC7: Branch/join fan-in port compatibility is checked.
AC8: Existing 460 tests remain green.
"""

import pytest

from nodechain.core.blueprint import (
    ChainBlueprint, NodeDef, ConnectionDef, BranchDef, JoinDef,
)
from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.port import PortType
from nodechain.validation.port_compatibility import (
    validate_port_compatibility,
    PortCompatibilityReport,
    PortIssue,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_contract(
    node_id: str,
    input_type: str = PortType.TASK_PLAN,
    output_type: str = PortType.RAW_SEARCH_RESULTS,
    input_schema: str = "test://input",
    output_schema: str = "test://output",
    required_fields: list[str] | None = None,
    guaranteed_fields: list[str] | None = None,
    optional_fields: list[str] | None = None,
) -> NodeContract:
    return NodeContract(
        contract_id=f"test.{node_id}.v1",
        node_id=node_id,
        version="1.0.0",
        entry=EntryContract(
            input_type=input_type,
            schema_ref=input_schema,
            required_fields=required_fields or [],
            optional_fields=optional_fields or [],
        ),
        exit=ExitContract(
            output_type=output_type,
            schema_ref=output_schema,
            guaranteed_fields=guaranteed_fields or [],
        ),
        requirements=Requirements(model_required=False),
    )


def _make_linear_blueprint() -> tuple[ChainBlueprint, dict[str, NodeContract]]:
    bp = ChainBlueprint(
        chain_id="port_test_v1", name="Port Test", version="1.0.0", goal="Test ports",
        nodes=[
            NodeDef(node_id="source", node_type="model", position=1),
            NodeDef(node_id="middle", node_type="deterministic", position=2),
            NodeDef(node_id="sink", node_type="model", position=3),
        ],
        connections=[
            ConnectionDef(from_node="source", from_port="output", to_node="middle", to_port="input"),
            ConnectionDef(from_node="middle", from_port="output", to_node="sink", to_port="input"),
        ],
    )

    contracts = {
        "source": _make_contract(
            "source",
            input_type=PortType.RAW_QUERY,
            output_type=PortType.RESEARCH_GOAL,
            output_schema="nodechain://schemas/semantic_types/normalized_research_goal",
        ),
        "middle": _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            output_type=PortType.TASK_PLAN,
            input_schema="nodechain://schemas/semantic_types/normalized_research_goal",
            output_schema="nodechain://schemas/semantic_types/task_plan",
        ),
        "sink": _make_contract(
            "sink",
            input_type=PortType.TASK_PLAN,
            output_type=PortType.FINAL_RESPONSE,
            input_schema="nodechain://schemas/semantic_types/task_plan",
            output_schema="nodechain://schemas/semantic_types/final_response",
        ),
    }

    return bp, contracts


# ── AC1/AC2: Source/target port existence ────────────────────────────────

class TestPortExistence:

    def test_missing_source_contract(self):
        """AC1: Source node with no contract produces error."""
        bp, contracts = _make_linear_blueprint()
        del contracts["source"]

        report = validate_port_compatibility(bp, contracts)
        assert not report.is_valid
        assert any(
            i.issue_type == "missing_port" and i.source_node == "source"
            for i in report.errors
        )

    def test_missing_target_contract(self):
        """AC2: Target node with no contract produces error."""
        bp, contracts = _make_linear_blueprint()
        del contracts["middle"]

        report = validate_port_compatibility(bp, contracts)
        assert not report.is_valid
        assert any(
            i.issue_type == "missing_port" and i.target_node == "middle"
            for i in report.errors
        )


# ── AC3: Type compatibility ─────────────────────────────────────────────

class TestTypeCompatibility:

    def test_matching_types_pass(self):
        """Correct type chain should pass."""
        bp, contracts = _make_linear_blueprint()
        report = validate_port_compatibility(bp, contracts)
        assert report.is_valid, report.summary()
        assert report.checks_run >= 2

    def test_type_mismatch_detected(self):
        """AC3: Type mismatch between source output and target input."""
        bp, contracts = _make_linear_blueprint()
        # Make source produce wrong type
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.FINAL_RESPONSE,  # Wrong — middle expects RESEARCH_GOAL
        )

        report = validate_port_compatibility(bp, contracts)
        assert not report.is_valid
        type_errors = [i for i in report.errors if i.issue_type == "type_mismatch"]
        assert len(type_errors) >= 1
        assert "source" in type_errors[0].source_node
        assert "middle" in type_errors[0].target_node


# ── AC4: Required field coverage ─────────────────────────────────────────

class TestRequiredFields:

    def test_all_required_fields_present(self):
        """When source guarantees all required fields, pass."""
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.RESEARCH_GOAL,
            guaranteed_fields=["primary_question", "research_domain"],
        )
        contracts["middle"] = _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            required_fields=["primary_question", "research_domain"],
        )

        report = validate_port_compatibility(bp, contracts)
        field_errors = [i for i in report.errors if i.issue_type == "missing_required_field"]
        assert len(field_errors) == 0

    def test_missing_required_fields(self):
        """AC4: Missing required fields produce error."""
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.RESEARCH_GOAL,
            guaranteed_fields=["primary_question"],  # Missing research_domain
        )
        contracts["middle"] = _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            required_fields=["primary_question", "research_domain"],
        )

        report = validate_port_compatibility(bp, contracts)
        field_errors = [i for i in report.errors if i.issue_type == "missing_required_field"]
        assert len(field_errors) >= 1
        assert "research_domain" in str(field_errors[0].details.get("missing_fields", []))


# ── AC5: Strict mode ─────────────────────────────────────────────────────

class TestStrictMode:

    def test_schema_mismatch_warning_in_default_mode(self):
        """Schema ref mismatch is warning in non-strict mode."""
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.RESEARCH_GOAL,
            output_schema="schema_a",
        )
        contracts["middle"] = _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            output_type=PortType.TASK_PLAN,  # Preserve correct type
            input_schema="schema_b",
        )

        report = validate_port_compatibility(bp, contracts, strict=False)
        schema_warnings = [i for i in report.warnings if i.issue_type == "schema_ref_mismatch"]
        assert len(schema_warnings) >= 1
        assert report.is_valid  # Warnings don't block

    def test_schema_mismatch_error_in_strict_mode(self):
        """AC5: Schema ref mismatch is error in strict mode."""
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.RESEARCH_GOAL,
            output_schema="schema_a",
        )
        contracts["middle"] = _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            output_type=PortType.TASK_PLAN,  # Preserve correct type
            input_schema="schema_b",
        )

        report = validate_port_compatibility(bp, contracts, strict=True)
        schema_errors = [i for i in report.errors if i.issue_type == "schema_ref_mismatch"]
        assert len(schema_errors) >= 1
        assert not report.is_valid  # Errors block in strict mode


# ── AC6: Port mapping error detail ───────────────────────────────────────

class TestPortMappingDetail:

    def test_error_includes_all_four_fields(self):
        """AC6: Port mapping errors include source node/port and target node/port."""
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.FINAL_RESPONSE,  # Mismatch
        )

        report = validate_port_compatibility(bp, contracts)
        assert not report.is_valid
        error = report.errors[0]
        assert error.source_node == "source"
        assert error.source_port == "output"
        assert error.target_node == "middle"
        assert error.target_port == "input"
        assert error.issue_type == "type_mismatch"
        assert error.message  # Non-empty message


# ── AC7: Branch/join fan-in compatibility ────────────────────────────────

class TestBranchJoinCompatibility:

    def _make_branch_blueprint(self) -> tuple[ChainBlueprint, dict[str, NodeContract]]:
        bp = ChainBlueprint(
            chain_id="branch_port_v1", name="Branch Port Test",
            version="1.0.0", goal="Test branch ports",
            nodes=[
                NodeDef(node_id="router", node_type="deterministic", position=1),
                NodeDef(node_id="alpha_search", node_type="deterministic", position=2),
                NodeDef(node_id="beta_search", node_type="deterministic", position=3),
                NodeDef(node_id="joiner", node_type="deterministic", position=4),
            ],
            connections=[
            ],
            branches=[
                BranchDef(
                    branch_id="b1", from_node="router",
                    branches={"alpha": ["alpha_search"], "beta": ["beta_search"]},
                    default_branch="alpha",
                ),
            ],
            joins=[
                JoinDef(join_id="j1", to_node="joiner", from_branches=["alpha", "beta"]),
            ],
        )

        contracts = {
            "router": _make_contract(
                "router",
                input_type=PortType.RAW_QUERY,
                output_type=PortType.TASK_PLAN,
            ),
            "alpha_search": _make_contract(
                "alpha_search",
                input_type=PortType.TASK_PLAN,
                output_type=PortType.RAW_SEARCH_RESULTS,
            ),
            "beta_search": _make_contract(
                "beta_search",
                input_type=PortType.TASK_PLAN,
                output_type=PortType.RAW_SEARCH_RESULTS,
            ),
            "joiner": _make_contract(
                "joiner",
                input_type=PortType.RAW_SEARCH_RESULTS,
                output_type=PortType.EVIDENCE_BASE,
            ),
        }

        return bp, contracts

    def test_branch_fan_out_compatible(self):
        """Branch source output matches branch node inputs."""
        bp, contracts = self._make_branch_blueprint()
        report = validate_port_compatibility(bp, contracts)
        assert report.is_valid, report.summary()

    def test_branch_fan_out_type_mismatch(self):
        """AC7: Branch node input type mismatch detected."""
        bp, contracts = self._make_branch_blueprint()
        # Make alpha_search expect wrong type
        contracts["alpha_search"] = _make_contract(
            "alpha_search",
            input_type=PortType.FINAL_RESPONSE,  # Wrong — router outputs TASK_PLAN
            output_type=PortType.RAW_SEARCH_RESULTS,
        )

        report = validate_port_compatibility(bp, contracts)
        branch_errors = [i for i in report.errors if i.issue_type == "type_mismatch"]
        assert len(branch_errors) >= 1
        assert any("alpha_search" in e.target_node for e in branch_errors)

    def test_join_fan_in_compatible(self):
        """Branch last nodes output type matches join target input."""
        bp, contracts = self._make_branch_blueprint()
        report = validate_port_compatibility(bp, contracts)
        fan_in_errors = [i for i in report.errors if i.issue_type == "fan_in_mismatch"]
        assert len(fan_in_errors) == 0

    def test_join_fan_in_type_mismatch(self):
        """AC7: Join fan-in type mismatch detected."""
        bp, contracts = self._make_branch_blueprint()
        # Make alpha_search produce wrong type for join
        contracts["alpha_search"] = _make_contract(
            "alpha_search",
            input_type=PortType.TASK_PLAN,
            output_type=PortType.FINAL_RESPONSE,  # Wrong — joiner expects RAW_SEARCH_RESULTS
        )

        report = validate_port_compatibility(bp, contracts)
        fan_in_errors = [i for i in report.errors if i.issue_type == "fan_in_mismatch"]
        assert len(fan_in_errors) >= 1
        assert "alpha" in fan_in_errors[0].details.get("branch", "")

    def test_join_fan_in_both_branches_checked(self):
        """Both branches' last nodes are checked against join target."""
        bp, contracts = self._make_branch_blueprint()
        # Both branches produce wrong type
        contracts["alpha_search"] = _make_contract(
            "alpha_search",
            output_type=PortType.FINAL_RESPONSE,
        )
        contracts["beta_search"] = _make_contract(
            "beta_search",
            output_type=PortType.FINAL_RESPONSE,
        )

        report = validate_port_compatibility(bp, contracts)
        fan_in_errors = [i for i in report.errors if i.issue_type == "fan_in_mismatch"]
        assert len(fan_in_errors) == 2


# ── Optional fields ──────────────────────────────────────────────────────

class TestOptionalFields:

    def test_optional_field_gap_is_warning(self):
        """Missing optional fields produce warnings, never errors."""
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.RESEARCH_GOAL,
            guaranteed_fields=["primary_question"],
        )
        contracts["middle"] = _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            output_type=PortType.TASK_PLAN,  # Preserve correct type for sink
            optional_fields=["sub_questions", "constraints"],
        )

        report = validate_port_compatibility(bp, contracts)
        opt_warnings = [i for i in report.warnings if i.issue_type == "optional_field_gap"]
        assert len(opt_warnings) >= 1
        assert report.is_valid  # Warnings don't block


# ── Report structure ─────────────────────────────────────────────────────

class TestReportStructure:

    def test_empty_blueprint_is_valid(self):
        bp = ChainBlueprint(
            chain_id="empty", name="Empty", version="1.0.0", goal="Empty",
            nodes=[], connections=[],
        )
        report = validate_port_compatibility(bp, {})
        assert report.is_valid

    def test_summary_format(self):
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract("source", output_type=PortType.FINAL_RESPONSE)
        report = validate_port_compatibility(bp, contracts)
        summary = report.summary()
        assert "error" in summary.lower()
        assert "type_mismatch" in summary or "Type mismatch" in summary

    def test_errors_and_warnings_separated(self):
        bp, contracts = _make_linear_blueprint()
        contracts["source"] = _make_contract(
            "source",
            output_type=PortType.RESEARCH_GOAL,
            output_schema="schema_a",
        )
        contracts["middle"] = _make_contract(
            "middle",
            input_type=PortType.RESEARCH_GOAL,
            output_type=PortType.TASK_PLAN,  # Preserve correct type
            input_schema="schema_b",
            optional_fields=["missing_field"],
        )

        report = validate_port_compatibility(bp, contracts, strict=False)
        # Schema mismatch → warning, optional gap → warning
        assert len(report.warnings) >= 1
        assert len(report.errors) == 0
        assert report.is_valid
