"""Node 8: Claim Validator — two-pass validation (structural + consistency)."""

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


CLAIM_VALIDATOR_CONTRACT = NodeContract(
    contract_id="research.claim-validator.v1",
    node_id="claim_validator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.EVIDENCE_BASE,
        schema_ref="nodechain://schemas/semantic_types/evidence_base",
        required_fields=["claims", "synthesis"],
    ),
    exit=ExitContract(
        output_type=PortType.VALIDATED_EVIDENCE,
        schema_ref="nodechain://schemas/semantic_types/validated_evidence_base",
        guaranteed_fields=["validated_claims", "validation_summary"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "reasoning", "validation"],
    ),
)

CONSISTENCY_SYSTEM_PROMPT = """You are a Claim Consistency Validator. Given a set of evidence claims with source references, validate each claim for internal consistency and source agreement.

For each claim, evaluate:
- internal_consistency: 0.0-1.0 — Does the claim logically follow from its supporting sources?
- source_agreement: 0.0-1.0 — How well do the sources agree on this claim?
- issues: List of any consistency problems found

Then classify each claim:
- confirmed: Well-supported, consistent, good source agreement
- partially_confirmed: Mostly supported but with caveats
- unconfirmed: Insufficient support or significant uncertainty
- contradicted: Sources actively contradict the claim
- insufficient_evidence: Not enough sources to evaluate

Be rigorous. A claim is only confirmed if the evidence genuinely supports it."""


class ClaimValidatorNode(BaseNode):
    """
    Node 8: Hybrid two-pass validation.
    Pass 1: Structural (deterministic) — source count, attribution completeness
    Pass 2: Consistency (model-backed) — internal logic, source agreement
    Each pass produces separate trace events.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="claim_validator",
            node_type="hybrid",
            name="Claim Validator",
            description="Two-pass validation: structural (deterministic) + consistency (model-backed).",
            contract=CLAIM_VALIDATOR_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        claims = envelope.payload.get("claims", [])
        synthesis = envelope.payload.get("synthesis", {})

        # Pass 1: Structural validation (deterministic)
        structurally_validated = self._structural_validation(claims)

        # Pass 2: Consistency validation (model-backed)
        consistency_results = self._consistency_validation(structurally_validated)

        # Merge results
        validated_claims = self._merge_validation_results(
            structurally_validated, consistency_results
        )

        # Build validation summary
        status_counts: dict[str, int] = {}
        for vc in validated_claims:
            status = vc.get("status", "unconfirmed")
            status_counts[status] = status_counts.get(status, 0) + 1

        output = {
            "validated_claims": validated_claims,
            "validation_summary": {
                "total_claims": len(validated_claims),
                **status_counts,
                "synthesis_preserved": bool(synthesis),
            },
            # Pass through for downstream nodes (port isolation)
            "sources": envelope.payload.get("sources", []),
            "synthesis": synthesis,
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="claim_validator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.VALIDATED_EVIDENCE,
        )

    def _structural_validation(
        self, claims: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Pass 1: Deterministic structural checks.
        - Does the claim have supporting sources?
        - Is attribution complete?
        - Is source count adequate?
        """
        validated = []
        for claim in claims:
            supporting = claim.get("supporting_sources", [])
            has_sources = len(supporting) > 0
            adequate_count = len(supporting) >= 2

            issues = []
            if not has_sources:
                issues.append("No supporting sources")
            if not adequate_count:
                issues.append("Fewer than 2 supporting sources")
            if not claim.get("statement"):
                issues.append("Missing claim statement")

            validated.append({
                **claim,
                "structural_validation": {
                    "passed": len(issues) == 0,
                    "source_count_adequate": adequate_count,
                    "attribution_complete": has_sources,
                    "issues": issues,
                },
            })

        return validated

    def _consistency_validation(
        self, claims: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Pass 2: Model-backed consistency check.
        Sends claims to model for deep reasoning about internal consistency.
        """
        claims_summary = []
        for c in claims:
            claims_summary.append({
                "claim_id": c.get("claim_id", ""),
                "statement": c.get("statement", ""),
                "confidence": c.get("confidence", 0),
                "supporting_sources": c.get("supporting_sources", []),
                "contradicting_sources": c.get("contradicting_sources", []),
            })

        output_schema = {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "claim_id": {"type": "string"},
                            "internal_consistency": {"type": "number"},
                            "source_agreement": {"type": "number"},
                            "status": {"type": "string"},
                            "issues": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
            },
        }

        response = self._model.complete(
            system_prompt=CONSISTENCY_SYSTEM_PROMPT,
            user_message=f"Validate these {len(claims_summary)} claims:\n\n{json.dumps(claims_summary, indent=2)}",
            output_schema=output_schema,
            temperature=0.2,
        )

        if response.structured_output:
            return response.structured_output.get("results", [])

        try:
            parsed = json.loads(response.content)
            return parsed.get("results", [])
        except json.JSONDecodeError:
            return []

    def _merge_validation_results(
        self,
        structural: list[dict[str, Any]],
        consistency: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Merge Pass 1 and Pass 2 results into final validated claims."""
        consistency_map = {
            c.get("claim_id"): c for c in consistency
        }

        merged = []
        for claim in structural:
            claim_id = claim.get("claim_id", "")
            consistency_result = consistency_map.get(claim_id, {})

            structural_passed = claim.get("structural_validation", {}).get("passed", False)
            consistency_passed = consistency_result.get("internal_consistency", 0) >= 0.5

            # Determine final status
            if structural_passed and consistency_passed:
                if consistency_result.get("source_agreement", 0) >= 0.7:
                    status = "confirmed"
                else:
                    status = "partially_confirmed"
            elif not structural_passed:
                status = "insufficient_evidence"
            else:
                status = "unconfirmed"

            # Adjust confidence using bounded additive adjustment
            # This preserves the meaning of the original confidence score
            # instead of compressing it multiplicatively.
            original_confidence = claim.get("confidence", 0.5)
            validation_adjustment = (
                0.0   if status == "confirmed"         # no penalty
                else -0.05 if status == "partially_confirmed"  # minor penalty
                else -0.10 if status == "unconfirmed"        # moderate penalty
                else -0.20                               # insufficient/contradicted
            )
            adjusted_confidence = round(max(0.05, original_confidence + validation_adjustment), 2)

            merged.append({
                "claim_id": claim_id,
                "statement": claim.get("statement", ""),
                "raw_confidence": original_confidence,  # preserve original
                "status": status,
                "structural_validation": claim.get("structural_validation", {}),
                "consistency_validation": {
                    "passed": consistency_passed,
                    "internal_consistency": consistency_result.get("internal_consistency", 0),
                    "source_agreement": consistency_result.get("source_agreement", 0),
                    "issues": consistency_result.get("issues", []),
                },
                "adjusted_confidence": adjusted_confidence,
                "supporting_sources": claim.get("supporting_sources", []),
                "contradicting_sources": claim.get("contradicting_sources", []),
                "validation_notes": ", ".join(
                    claim.get("structural_validation", {}).get("issues", [])
                    + consistency_result.get("issues", [])
                ),
            })

        return merged
