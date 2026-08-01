"""Node 9: Risk / Confidence Classifier — scoring + review routing."""

from __future__ import annotations

import json
import statistics
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


RISK_CLASSIFIER_CONTRACT = NodeContract(
    contract_id="research.risk-classifier.v1",
    node_id="risk_classifier",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.VALIDATED_EVIDENCE,
        schema_ref="nodechain://schemas/semantic_types/validated_evidence_base",
        required_fields=["validated_claims", "validation_summary"],
    ),
    exit=ExitContract(
        output_type=PortType.RISK_ASSESSMENT,
        schema_ref="nodechain://schemas/semantic_types/risk_assessment",
        guaranteed_fields=["risk_level", "confidence", "review_required", "uncertainty_disclosures", "validated_claims", "sources"],
    ),
    requirements=Requirements(
        model_required=False,
    ),
)


class RiskClassifierNode(BaseNode):
    """
    Node 9: Hybrid (rules + model) risk/confidence scoring.
    First routing branch — determines if human review is needed.
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="risk_classifier",
            node_type="hybrid",
            name="Risk / Confidence Classifier",
            description="Classifies risk level and confidence. Routes to human review for HIGH risk.",
            contract=RISK_CLASSIFIER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        validated_claims = envelope.payload.get("validated_claims", [])
        validation_summary = envelope.payload.get("validation_summary", {})
        sources = envelope.payload.get("sources", [])
        total_claims = validation_summary.get("total_claims", len(validated_claims))

        if total_claims == 0:
            return EnvelopeResponse(
                request_envelope_id=envelope.envelope_id,
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id="risk_classifier",
                step_id=envelope.step_id,
                output={
                    "risk_level": "HIGH",
                    "confidence": 0.0,
                    "review_required": True,
                    "review_reason": "No validated claims to assess",
                    "uncertainty_disclosures": [
                        {"area": "overall", "nature": "no_evidence", "impact": "high"}
                    ],
                    "risk_factors": ["zero_validated_claims"],
                    "confidence_factors": {
                        "claim_validation_rate": 0.0,
                    },
                    "validated_claims": validated_claims,
                    "sources": sources,
                    "synthesis": envelope.payload.get("synthesis", {}),
                },
                output_type=PortType.RISK_ASSESSMENT,
            )

        # Calculate metrics
        confirmed = sum(1 for c in validated_claims if c.get("status") == "confirmed")
        contradicted = sum(1 for c in validated_claims if c.get("status") == "contradicted")
        unconfirmed = sum(1 for c in validated_claims if c.get("status") == "unconfirmed")
        insufficient = sum(1 for c in validated_claims if c.get("status") == "insufficient_evidence")

        confidences = [c.get("adjusted_confidence", c.get("confidence", 0.5)) for c in validated_claims]
        mean_confidence = statistics.mean(confidences) if confidences else 0.0

        claim_validation_rate = confirmed / total_claims if total_claims > 0 else 0.0
        contradiction_rate = contradicted / total_claims if total_claims > 0 else 0.0

        # Risk classification rules
        risk_factors = []
        uncertainty_disclosures = []

        if contradiction_rate > 0.3:
            risk_factors.append("high_contradiction_rate")
            uncertainty_disclosures.append({
                "area": "evidence_consistency",
                "nature": "significant_contradictions",
                "impact": "high",
            })

        if claim_validation_rate < 0.4:
            risk_factors.append("low_validation_rate")
            uncertainty_disclosures.append({
                "area": "evidence_quality",
                "nature": "few_confirmed_claims",
                "impact": "medium",
            })

        if mean_confidence < 0.4:
            risk_factors.append("low_confidence")
            uncertainty_disclosures.append({
                "area": "overall_confidence",
                "nature": "below_threshold",
                "impact": "medium",
            })

        if insufficient > total_claims * 0.5:
            risk_factors.append("insufficient_evidence")
            uncertainty_disclosures.append({
                "area": "evidence_coverage",
                "nature": "majority_insufficient",
                "impact": "high",
            })

        # Determine risk level
        if len(risk_factors) >= 2 or contradiction_rate > 0.3 or mean_confidence < 0.3:
            risk_level = "HIGH"
        elif len(risk_factors) >= 1 or mean_confidence < 0.5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Build risk_factor_evidence for audit
        risk_factor_evidence = {
            "high_contradiction_rate": {
                "threshold": 0.3,
                "actual": round(contradiction_rate, 2),
                "triggered": "high_contradiction_rate" in risk_factors,
            },
            "low_validation_rate": {
                "threshold": 0.4,
                "actual": round(claim_validation_rate, 2),
                "triggered": "low_validation_rate" in risk_factors,
            },
            "low_confidence": {
                "threshold": 0.4,
                "actual": round(mean_confidence, 2),
                "triggered": "low_confidence" in risk_factors,
            },
            "insufficient_evidence": {
                "threshold": round(total_claims * 0.5, 0),
                "actual": insufficient,
                "triggered": "insufficient_evidence" in risk_factors,
            },
        }

        review_required = risk_level == "HIGH"

        output = {
            "risk_level": risk_level,
            "confidence": round(mean_confidence, 2),
            "confidence_factors": {
                "claim_validation_rate": round(claim_validation_rate, 2),
                "source_quality_mean": 0.0,
                "evidence_coverage": round(1.0 - (insufficient / total_claims), 2) if total_claims > 0 else 0.0,
            },
            "review_required": review_required,
            "review_reason": f"Risk level: {risk_level}. Factors: {', '.join(risk_factors)}" if review_required else "",
            "uncertainty_disclosures": uncertainty_disclosures,
            "risk_factors": risk_factors,
            "risk_factor_evidence": risk_factor_evidence,
            # Explicit threshold documentation for audit
            "thresholds_applied": {
                "low_confidence_threshold": 0.4,
                "high_risk_trigger": "2+ risk factors OR contradiction_rate > 0.3 OR mean_confidence < 0.3",
                "medium_risk_trigger": "1+ risk factor OR mean_confidence < 0.5",
                "actual_risk_factor_count": len(risk_factors),
                "actual_contradiction_rate": round(contradiction_rate, 2),
                "actual_mean_confidence": round(mean_confidence, 2),
            },
            # Pass through evidence for downstream nodes (port isolation fix)
            "validated_claims": validated_claims,
            "sources": envelope.payload.get("sources", []),
            "synthesis": envelope.payload.get("synthesis", {}),
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="risk_classifier",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.RISK_ASSESSMENT,
        )
