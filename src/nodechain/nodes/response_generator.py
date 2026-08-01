"""Node 10: Response Generator — produce cited recommendation with confidence statement."""

from __future__ import annotations

import json
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


RESPONSE_GENERATOR_CONTRACT = NodeContract(
    contract_id="research.response-generator.v1",
    node_id="response_generator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RISK_ASSESSMENT,
        schema_ref="nodechain://schemas/semantic_types/risk_assessment",
        required_fields=["risk_level", "confidence"],
        optional_fields=["human_review_decision"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        guaranteed_fields=[
            "recommendation", "confidence_statement", "citations",
            "uncertainty_disclosures",
        ],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "writing"],
    ),
)

RESPONSE_SYSTEM_PROMPT = """You are a Research Response Generator. Given validated evidence, risk assessment, and optionally a human review decision, produce a comprehensive research response.

Return ONLY valid JSON matching the provided schema. Do NOT include fields not in the schema.

Your response must include:
1. recommendation: A clear, actionable recommendation answering the research question
2. executive_summary: 2-3 sentence summary for quick reading
3. key_findings: The most important findings from the evidence
4. confidence_statement: Level (HIGH/MEDIUM/LOW), numeric score (0.0-1.0), and explanation
5. alternative_perspectives: Other viewpoints the reader should consider
6. methodology_notes: Brief note on how the research was conducted

IMPORTANT: Do NOT include citations or uncertainty_disclosures in your JSON output. These are added programmatically.

Be precise, cite sources, and be honest about limitations. Do not overstate confidence."""


class ResponseGeneratorNode(BaseNode):
    """
    Node 10: Produces the final cited recommendation.
    Consumes optional human review decision. Validates optional port handling.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="response_generator",
            node_type="model",
            name="Response Generator",
            description="Produces final cited recommendation with confidence statement.",
            contract=RESPONSE_GENERATOR_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        risk_assessment = envelope.payload

        # Get evidence data from risk classifier's pass-through (port isolation)
        # instead of peeking into chain_state["outputs"]
        validated_claims = risk_assessment.get("validated_claims", [])
        sources = risk_assessment.get("sources", [])
        synthesis = risk_assessment.get("synthesis", {})

        # Check for human review decision
        review_decision = risk_assessment.get("human_review_decision", "not_required")

        # Build source map for citations
        source_map = {s.get("source_id", ""): s for s in sources}

        # Build citations from validated claims.
        # v2.69: Previously this only included claims with status in
        # ("confirmed", "partially_confirmed"), which on the v2.68 real run
        # excluded every claim (all were "unconfirmed" or "insufficient_evidence")
        # and produced an empty citations list — even though every claim had
        # valid, traceable supporting_sources. The status field is a confidence
        # classification, not a citation-integrity signal. Per agreement with
        # strategic reviewer: aggregate citations from any validated claim that
        # has supporting_sources. The per-claim status is preserved for honesty.
        citations = []
        seen_refs: set[str] = set()
        for claim in validated_claims:
            for src_ref in claim.get("supporting_sources", []):
                if not src_ref or src_ref in seen_refs:
                    continue
                source = source_map.get(src_ref, {})
                if source:
                    seen_refs.add(src_ref)
                    citations.append({
                        "source_ref": src_ref,
                        "citation_text": f"{source.get('title', 'Unknown')} ({source.get('publication_date', 'n.d.')})",
                        "claim_supported": claim.get("statement", ""),
                        "claim_status": claim.get("status", "unknown"),
                    })

        output_schema = {
            "type": "object",
            "properties": {
                "recommendation": {"type": "string"},
                "executive_summary": {"type": "string"},
                "key_findings": {"type": "array", "items": {"type": "string"}},
                "confidence_statement": {
                    "type": "object",
                    "properties": {
                        "level": {"type": "string"},
                        "numeric": {"type": "number"},
                        "explanation": {"type": "string"},
                    },
                },
                "alternative_perspectives": {"type": "array", "items": {"type": "string"}},
                "methodology_notes": {"type": "string"},
            },
        }

        # Early exit: if no synthesis and no validated claims, return deterministic response
        has_evidence = bool(validated_claims) or bool(synthesis.get('summary', ''))
        if not has_evidence:
            return EnvelopeResponse(
                request_envelope_id=envelope.envelope_id,
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id="response_generator",
                step_id=envelope.step_id,
                output={
                    "recommendation": "No actionable recommendation can be made due to insufficient evidence.",
                    "executive_summary": "The research pipeline was unable to gather sufficient evidence to form a conclusion.",
                    "key_findings": ["No validated evidence was available for analysis."],
                    "confidence_statement": {
                        "level": "LOW",
                        "numeric": 0.0,
                        "explanation": "No evidence was available for analysis.",
                    },
                    "alternative_perspectives": ["Consider refining the research question or expanding search parameters."],
                    "methodology_notes": "Automated search returned no usable sources.",
                    "citations": [],
                    "uncertainty_disclosures": ["Entire analysis is uncertain due to lack of data."],
                    "human_review_decision": review_decision,
                },
                output_type=PortType.FINAL_RESPONSE,
            )

        response = self._model.complete(
            system_prompt=RESPONSE_SYSTEM_PROMPT,
            user_message=(
                f"Generate a research response based on:\n\n"
                f"Synthesis: {json.dumps(synthesis, indent=2)}\n\n"
                f"Validated Claims: {json.dumps(validated_claims[:10], indent=2)}\n\n"
                f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}\n"
                f"Confidence: {risk_assessment.get('confidence', 0)}\n"
                f"Review Decision: {review_decision}"
            ),
            output_schema=output_schema,
            temperature=0.3,
            max_tokens=8192,
        )

        model_output = response.structured_output or {}
        if not model_output:
            try:
                model_output = json.loads(response.content)
            except json.JSONDecodeError:
                model_output = {
                    "recommendation": synthesis.get("summary", "Unable to generate recommendation."),
                    "executive_summary": synthesis.get("summary", ""),
                    "key_findings": synthesis.get("key_findings", []),
                }

        output = {
            **model_output,
            "confidence_statement": model_output.get("confidence_statement", {
                "level": risk_assessment.get("risk_level", "MEDIUM"),
                "numeric": risk_assessment.get("confidence", 0.5),
                "explanation": "Based on automated evidence assessment",
            }),
            "citations": citations,
            "uncertainty_disclosures": [
                ud.get("area", "") + ": " + ud.get("nature", "")
                for ud in risk_assessment.get("uncertainty_disclosures", [])
            ],
            "human_review_decision": review_decision,
            "methodology_notes": model_output.get(
                "methodology_notes",
                "Research conducted using automated academic search and evidence synthesis.",
            ),
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="response_generator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.FINAL_RESPONSE,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
