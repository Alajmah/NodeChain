"""Shared Risk Classifier — domain-neutral reusable node (v2.61.0).

Accepts a canonical RISK_CONTEXT and produces a RISK_ASSESSMENT.
This node is intentionally domain-neutral: it does not know whether
the risk context comes from research, incident response, security audit,
or any other domain. Domain adaptation happens upstream via adapters.

Build a node once. Govern it forever. Reuse it everywhere.
"""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


SHARED_RISK_CLASSIFIER_CONTRACT = NodeContract(
    contract_id="shared.risk-classifier.v1",
    node_id="shared_risk_classifier",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RISK_CONTEXT,
        schema_ref="nodechain://schemas/semantic_types/risk_context",
        required_fields=["domain", "subject", "severity_signals"],
    ),
    exit=ExitContract(
        output_type=PortType.RISK_ASSESSMENT,
        schema_ref="nodechain://schemas/semantic_types/risk_assessment",
        guaranteed_fields=["risk_level", "confidence", "review_required"],
    ),
    requirements=Requirements(
        model_required=False,
    ),
)


class SharedRiskClassifierNode(BaseNode):
    """Domain-neutral risk classifier.

    Accepts a canonical RISK_CONTEXT with severity signals, confidence
    signals, and uncertainty factors, then produces a RISK_ASSESSMENT
    with risk level, confidence score, and review recommendation.

    This node is reusable across any autonomous-system domain that
    can normalize its data into a RISK_CONTEXT.
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter  # Not required — deterministic

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="shared_risk_classifier",
            node_type="deterministic",
            name="Shared Risk Classifier",
            description="Domain-neutral risk classifier. Reusable across chains.",
            contract=SHARED_RISK_CLASSIFIER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        ctx = envelope.payload

        domain = ctx.get("domain", "unknown")
        subject = ctx.get("subject", "")
        severity_signals = ctx.get("severity_signals", [])
        confidence_signals = ctx.get("confidence_signals", [])
        uncertainty_factors = ctx.get("uncertainty_factors", [])
        evidence_refs = ctx.get("evidence_refs", [])

        # Count signals
        high_severity = sum(1 for s in severity_signals if isinstance(s, dict) and s.get("level") in ("high", "critical"))
        medium_severity = sum(1 for s in severity_signals if isinstance(s, dict) and s.get("level") == "medium")
        low_severity = sum(1 for s in severity_signals if isinstance(s, dict) and s.get("level") in ("low", "info"))

        # Confidence: average of confidence signals (0.0-1.0)
        if confidence_signals:
            conf_values = [s.get("score", 0.5) if isinstance(s, dict) else 0.5 for s in confidence_signals]
            mean_confidence = sum(conf_values) / len(conf_values)
        else:
            mean_confidence = 0.5

        # Risk classification rules (domain-neutral)
        risk_factors = []
        uncertainty_disclosures = []

        if high_severity > 0:
            risk_factors.append("high_severity_signals")
            uncertainty_disclosures.append({
                "area": "severity",
                "nature": "high_severity_present",
                "impact": "high",
            })

        if len(uncertainty_factors) >= 3:
            risk_factors.append("high_uncertainty_count")
            uncertainty_disclosures.append({
                "area": "uncertainty",
                "nature": "multiple_uncertainty_factors",
                "impact": "medium",
            })

        if mean_confidence < 0.4:
            risk_factors.append("low_confidence")
            uncertainty_disclosures.append({
                "area": "confidence",
                "nature": "below_threshold",
                "impact": "medium",
            })

        if len(evidence_refs) == 0:
            risk_factors.append("no_evidence_refs")
            uncertainty_disclosures.append({
                "area": "evidence",
                "nature": "no_evidence_cited",
                "impact": "high",
            })

        # Determine risk level
        if len(risk_factors) >= 2 or high_severity >= 2:
            risk_level = "HIGH"
        elif len(risk_factors) >= 1 or mean_confidence < 0.5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        review_required = risk_level == "HIGH"

        output = {
            "risk_level": risk_level,
            "confidence": round(mean_confidence, 2),
            "review_required": review_required,
            "review_reason": f"Risk level: {risk_level}. Factors: {', '.join(risk_factors)}" if review_required else "",
            "risk_factors": risk_factors,
            "uncertainty_disclosures": uncertainty_disclosures,
            "domain": domain,
            "subject": subject,
            "signal_counts": {
                "high_severity": high_severity,
                "medium_severity": medium_severity,
                "low_severity": low_severity,
            },
            "confidence_factors": {
                "mean_confidence": round(mean_confidence, 2),
                "signal_count": len(confidence_signals),
                "evidence_count": len(evidence_refs),
            },
            "thresholds_applied": {
                "high_risk_trigger": "2+ risk factors OR 2+ high severity signals",
                "medium_risk_trigger": "1+ risk factor OR confidence < 0.5",
                "low_confidence_threshold": 0.4,
            },
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="shared_risk_classifier",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.RISK_ASSESSMENT,
        )
