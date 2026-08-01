"""Incident Detector — detects anomalies from monitoring signals.

Input: monitoring signals (metrics, alerts, drift reports)
Output: incident report with detected anomalies and initial assessment
"""

from __future__ import annotations

from datetime import datetime, timezone

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class IncidentDetector(BaseNode):
    """Detects incidents from monitoring signals."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="incident_detector",
            node_type="deterministic",
            name="Incident Detector",
            description="Detects anomalies from monitoring signals",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="incident.detector.v1",
            node_id="incident_detector",
            version="1.0.0",
            entry={
                "input_type": "monitoring_signals",
                "schema_ref": "",
                "required_fields": ["signals"],
                "optional_fields": ["drift_report", "alert_history"],
            },
            exit={
                "output_type": "incident_report",
                "schema_ref": "",
                "guaranteed_fields": ["incident_id", "detected", "anomalies", "severity_hint"],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        signals = envelope.payload.get("signals", [])
        drift_report = envelope.payload.get("drift_report", {})
        alert_history = envelope.payload.get("alert_history", [])

        anomalies: list[dict] = []
        severity_hint = "info"

        # Check for drift-detected incidents
        if drift_report and drift_report.get("drift_detected", False):
            anomalies.append({
                "type": "configuration_drift",
                "source": "drift_detection",
                "detail": drift_report.get("drift_summary", "Configuration drift detected"),
                "fields": drift_report.get("drift_fields", []),
                "evidence_strength": drift_report.get("evidence_strength", "observed"),
            })
            severity_hint = "warning"

        # Check metric-based signals
        for signal in signals:
            if signal.get("status") == "critical" or signal.get("value", 0) > signal.get("threshold", float("inf")):
                anomalies.append({
                    "type": signal.get("metric", "unknown"),
                    "source": signal.get("source", "monitoring"),
                    "detail": f"{signal.get('metric', 'metric')}: {signal.get('value', 'N/A')} exceeds threshold {signal.get('threshold', 'N/A')}",
                    "value": signal.get("value"),
                    "threshold": signal.get("threshold"),
                })
                if severity_hint != "critical":
                    severity_hint = "warning"

        # Check alert patterns
        critical_alerts = [a for a in alert_history if a.get("severity") == "critical"]
        if critical_alerts:
            anomalies.append({
                "type": "critical_alerts",
                "source": "alerting",
                "detail": f"{len(critical_alerts)} critical alerts in history",
                "count": len(critical_alerts),
            })
            severity_hint = "critical"

        detected = len(anomalies) > 0
        incident_id = f"INC-{envelope.run_id[:8]}" if detected else ""

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="incident_detector",
            step_id=envelope.step_id,
            output={
                "incident_id": incident_id,
                "detected": detected,
                "anomalies": anomalies,
                "severity_hint": severity_hint,
                "signal_count": len(signals),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
