"""Conflict Detector Node — detects conflicts in merged evidence."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
from nodechain.nodes.base_node import BaseNode


class ConflictDetectorNode(BaseNode):
    """Analyzes merged evidence for conflicts, contradictions, and disagreements.
    
    Produces a conflict report and adjusts confidence for conflicting claims.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="conflict_detector",
            node_type="deterministic",
            name="Conflict Detector",
            description="Detects conflicts and contradictions in merged evidence.",
            contract=NodeContract(
                contract_id="branch.conflict-detector.v1",
                node_id="conflict_detector",
                version="1.0.0",
                entry=EntryContract(
                    input_type=PortType.EVIDENCE_BASE,
                    schema_ref="nodechain://schemas/semantic_types/evidence_base",
                    required_fields=["claims"],
                ),
                exit=ExitContract(
                    output_type=PortType.VALIDATED_EVIDENCE,
                    schema_ref="nodechain://schemas/semantic_types/validated_evidence_base",
                    guaranteed_fields=["claims", "conflict_report"],
                ),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload
        claims = payload.get("claims", [])
        sources = payload.get("sources", [])
        conflicts = payload.get("conflicts", [])
        
        # Analyze conflicts
        conflict_report = {
            "total_claims": len(claims),
            "total_sources": len(sources),
            "conflicts_found": len(conflicts),
            "conflict_details": conflicts,
            "cross_branch_agreement": self._assess_agreement(claims),
        }
        
        # Flag claims involved in conflicts
        conflict_claim_ids = set()
        for c in conflicts:
            conflict_claim_ids.add(c.get("claim_1", ""))
            conflict_claim_ids.add(c.get("claim_2", ""))
        
        adjusted_claims = []
        for claim in claims:
            if not isinstance(claim, dict):
                adjusted_claims.append(claim)
                continue
            cid = claim.get("claim_id", "")
            if cid in conflict_claim_ids:
                adjusted = {**claim}
                adjusted["conflict_flagged"] = True
                # Reduce confidence for conflicting claims
                raw_conf = claim.get("raw_confidence", claim.get("confidence", 0.5))
                adjusted["confidence"] = min(raw_conf * 0.8, claim.get("confidence", raw_conf))
                adjusted_claims.append(adjusted)
            else:
                adjusted_claims.append({**claim, "conflict_flagged": False})
        
        output = {
            "claims": adjusted_claims,
            "sources": sources,
            "conflict_report": conflict_report,
            "merge_summary": payload.get("merge_summary", {}),
        }
        
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="conflict_detector",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.VALIDATED_EVIDENCE,
        )
    
    def _assess_agreement(self, claims: list[dict]) -> str:
        """Assess overall agreement level across claims."""
        if not claims:
            return "unknown"
        
        flagged = sum(
            1 for c in claims 
            if isinstance(c, dict) and c.get("conflict_flagged", False)
        )
        
        ratio = flagged / len(claims) if claims else 0
        if ratio > 0.3:
            return "low"
        elif ratio > 0.1:
            return "moderate"
        return "high"
