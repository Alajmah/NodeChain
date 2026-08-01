"""Branch Response Generator — simplified response generator for branch chains."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.contract import (
    EntryContract, ExitContract, Requirements, NodeContract,
)
from nodechain.nodes.base_node import BaseNode


BRANCH_RESPONSE_CONTRACT = NodeContract(
    contract_id="branch.response-generator.v1",
    node_id="response_generator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.VALIDATED_EVIDENCE,
        schema_ref="nodechain://schemas/semantic_types/validated_evidence_base",
        required_fields=["claims"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        guaranteed_fields=["recommendation", "confidence_statement"],
    ),
    requirements=Requirements(model_required=True),
)


class BranchResponseGeneratorNode(BaseNode):
    """Simplified response generator for branch chains.
    
    Takes validated evidence and produces a recommendation.
    Uses the same model-backed generation as the research chain.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="response_generator",
            node_type="model",
            name="Branch Response Generator",
            description="Generates response from branch-joined evidence.",
            contract=BRANCH_RESPONSE_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        import json
        payload = envelope.payload
        claims = payload.get("claims", [])
        sources = payload.get("sources", [])
        conflict_report = payload.get("conflict_report", {})
        
        system = """You are a Research Response Generator. Given evidence claims and sources,
produce a clear, actionable recommendation.

Return ONLY valid JSON:
{
  "recommendation": "Clear answer to the research question",
  "confidence_statement": {"level": "HIGH|MEDIUM|LOW", "numeric": 0.0-1.0, "explanation": "..."},
  "key_findings": ["finding1", "finding2"],
  "methodology_notes": "Brief note on methodology"
}"""

        evidence_summary = json.dumps({
            "claim_count": len(claims),
            "source_count": len(sources),
            "conflicts": conflict_report.get("conflicts_found", 0),
            "claims": [{"statement": c.get("statement",""), "confidence": c.get("confidence",0)} for c in claims[:10]],
        }, indent=2)[:3000]

        response = self._model.complete(
            system_prompt=system,
            user_message=f"Evidence:\n{evidence_summary}",
            max_tokens=2048,
            temperature=0.3,
        )
        
        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except json.JSONDecodeError:
                output = {
                    "recommendation": "Unable to generate recommendation.",
                    "confidence_statement": {"level": "LOW", "numeric": 0.1},
                    "key_findings": [],
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
