"""Typed Port — model for port connections and compatibility."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PortType:
    """Well-known port types for typed-port composition.

    Research chain types cover the Research & Decision Assistant flow.
    Cross-domain types (v2.61.0) enable reusable shared nodes across
    different autonomous-system domains.
    """

    # Research & Decision Assistant chain
    RAW_QUERY = "raw_user_query"
    RESEARCH_GOAL = "normalized_research_goal"
    TASK_PLAN = "task_plan"
    CONTEXT_BUNDLE = "context_bundle"
    RAW_SEARCH_RESULTS = "raw_search_results"
    SOURCE_SET = "source_set"
    QUALIFIED_SOURCE_SET = "qualified_source_set"
    EVIDENCE_BASE = "evidence_base"
    VALIDATED_EVIDENCE = "validated_evidence_base"
    RISK_ASSESSMENT = "risk_assessment"
    FINAL_RESPONSE = "final_response"
    MEMORY_WRITE_DECISION = "memory_write_decision"
    CHAIN_TRACE_OUTPUT = "chain_trace_output"

    # Cross-domain reusable node types (v2.61.0)
    RISK_CONTEXT = "risk_context"
    TRACE_INPUT = "trace_input"

    # Code Review Assistant chain (v2.71.0)
    CODE_REVIEW_GOAL = "code_review_goal"
    CODE_ARTIFACTS = "code_artifacts"
    REVIEW_FINDINGS = "review_findings"
    CLASSIFIED_FINDINGS = "classified_findings"
    FINAL_REVIEW = "final_review"

    # Code Review patch proposal path (v2.72.0)
    PATCH_PROPOSALS = "patch_proposals"
    VALIDATED_PATCHES = "validated_patches"
    CLASSIFIED_PATCHES = "classified_patches"
    FINAL_PATCH_REPORT = "final_patch_report"

    # Code Review sandbox test execution (v2.73.0)
    SANDBOX_TEST_RESULTS = "sandbox_test_results"
    CLASSIFIED_TEST_RESULTS = "classified_test_results"
    FINAL_TEST_REPORT = "final_test_report"


class Port(BaseModel):
    """A typed port on a node — either input or output."""

    name: str
    port_type: str
    schema_ref: str
    required: bool = True
    description: str = ""

    model_config = {"extra": "forbid"}


class PortConnection(BaseModel):
    """A typed connection between an output port and an input port."""

    from_node: str
    from_port: str
    to_node: str
    to_port: str
    condition: str | None = None
    label: str | None = None

    model_config = {"extra": "forbid"}


def ports_compatible(source: Port, target: Port) -> bool:
    """Check if source output port type matches target input port type."""
    return source.port_type == target.port_type
