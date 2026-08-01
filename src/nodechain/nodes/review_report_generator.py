"""Node 5: Review Report Generator — produce the final review report.

v2.71 Code Review Assistant: produces the final cited review report with
executive summary, findings by severity, recommendations, and confidence.
Each finding is traceable to file:line evidence.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

logger = logging.getLogger(__name__)

REVIEW_REPORT_CONTRACT = NodeContract(
    contract_id="codereview.report.v1",
    node_id="review_report_generator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.CLASSIFIED_FINDINGS,
        schema_ref="nodechain://schemas/semantic_types/classified_findings",
        required_fields=["classified_findings"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_REVIEW,
        schema_ref="nodechain://schemas/semantic_types/final_review",
        guaranteed_fields=["executive_summary", "findings", "recommendation"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output"],
    ),
)

REPORT_SYSTEM_PROMPT = """You are a Review Report Generator. Given classified code review findings, produce a structured review report.

The report must include:
1. executive_summary: A clear, honest summary of the review verdict
2. findings: The findings organized by severity (blockers first, then warnings, then info)
3. recommendation: "approve", "request_changes", or "reject"
4. confidence_statement: How confident the review is (level + numeric + explanation)
5. positive_observations: What was done well (if anything)

Be honest. If there are no blockers, say "approve" and explain why. If there are blockers, be specific about what needs to change. Do not pad the report with filler. Every finding must trace to a file_path and line_range."""

REPORT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "findings": {"type": "array", "items": {"type": "object"}},
        "recommendation": {"type": "string", "enum": ["approve", "request_changes", "reject"]},
        "confidence_statement": {
            "type": "object",
            "properties": {
                "level": {"type": "string"},
                "numeric": {"type": "number"},
                "explanation": {"type": "string"},
            },
        },
        "positive_observations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["executive_summary", "findings", "recommendation"],
}


class ReviewReportGeneratorNode(BaseNode):
    """Node 5: Generate the final review report from classified findings."""

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="review_report_generator",
            node_type="model",
            name="Review Report Generator",
            description="Produces the final cited review report with findings, recommendation, and confidence.",
            contract=REVIEW_REPORT_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        findings = data.get("classified_findings", [])
        summary = data.get("summary", {})

        # Build findings context for the model
        findings_text = json.dumps(findings, indent=2)
        summary_text = json.dumps(summary, indent=2)

        response = self._model.complete(
            system_prompt=REPORT_SYSTEM_PROMPT,
            user_message=(
                f"Classified findings summary:\n{summary_text}\n\n"
                f"Detailed findings:\n{findings_text}\n\n"
                f"Produce the final review report."
            ),
            output_schema=REPORT_OUTPUT_SCHEMA,
            temperature=0.2,
            max_tokens=4096,
        )

        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except Exception:
                blocker_count = summary.get("blocker_count", 0)
                output = {
                    "executive_summary": f"Review complete. {len(findings)} findings ({blocker_count} blockers).",
                    "findings": findings,
                    "recommendation": "request_changes" if blocker_count > 0 else "approve",
                    "confidence_statement": {
                        "level": "MEDIUM",
                        "numeric": 0.5,
                        "explanation": "Automated review with limited context.",
                    },
                }

        # Ensure findings are preserved with provenance
        output["findings"] = findings
        output["summary"] = summary

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="review_report_generator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.FINAL_REVIEW,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
