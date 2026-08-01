"""Severity Triager — classifies incident severity and impact.

Input: incident report from IncidentDetector
Output: severity assessment with recommended urgency and blast radius
"""

from __future__ import annotations

from datetime import datetime, timezone

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class SeverityTriager(BaseNode):
    """Triages incident severity based on anomalies and context."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="severity_triager",
            node_type="hybrid",
            name="Severity Triager",
            description="Classifies incident severity and blast radius",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="incident.triager.v1",
            node_id="severity_triager",
            version="1.0.0",
            entry={
                "input_type": "incident_report",
                "schema_ref": "",
                "required_fields": ["detected", "anomalies"],
                "optional_fields": ["severity_hint", "incident_id"],
            },
            exit={
                "output_type": "severity_assessment",
                "schema_ref": "",
                "guaranteed_fields": ["severity", "urgency", "blast_radius", "requires_remediation"],
            },
            side_effects=[],
            requirements={
                "model_required": False,
                "memory_access": "none",
                "trust_level": "trusted",
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload
        anomalies = payload.get("anomalies", [])
        hint = payload.get("severity_hint", "info")

        # Severity scoring
        score = 0
        blast_radius: list[str] = []

        for anomaly in anomalies:
            atype = anomaly.get("type", "")
            source = anomaly.get("source", "")

            if atype == "configuration_drift":
                score += 30
                blast_radius.append(f"drift:{source}")
            elif atype == "critical_alerts":
                score += 50
                blast_radius.append(f"alerts:{anomaly.get('count', 0)}")
            elif "cpu" in atype.lower() or "memory" in atype.lower():
                score += 25
                blast_radius.append(f"resource:{atype}")
            else:
                score += 10
                blast_radius.append(f"metric:{atype}")

        # Determine severity
        if score >= 70 or hint == "critical":
            severity = "critical"
            urgency = "immediate"
        elif score >= 40 or hint == "warning":
            severity = "high"
            urgency = "urgent"
        elif score >= 15:
            severity = "medium"
            urgency = "normal"
        else:
            severity = "low"
            urgency = "low"

        requires_remediation = severity in ("critical", "high", "medium")
        requires_human_review = severity == "critical"

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="severity_triager",
            step_id=envelope.step_id,
            output={
                "severity": severity,
                "urgency": urgency,
                "blast_radius": list(set(blast_radius)),
                "severity_score": score,
                "anomaly_count": len(anomalies),
                "requires_remediation": requires_remediation,
                "requires_human_review": requires_human_review,
                "incident_id": payload.get("incident_id", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
