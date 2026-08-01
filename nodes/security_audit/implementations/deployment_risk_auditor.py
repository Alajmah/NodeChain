"""Deployment Risk Auditor — audits deployment and operations posture.

Node 6 of the Security Audit Chain.
Checks: drift, failed remediations, release history gaps.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class DeploymentRiskAuditor(BaseNode):
    """Audits deployment risk posture."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="deployment_risk_auditor",
            node_type="deterministic",
            name="Deployment Risk Auditor",
            description="Audits deployment and operations risk",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.deployment.v1",
            node_id="deployment_risk_auditor",
            version="1.0.0",
            entry={
                "schema_ref": "",
                "input_type": "asset_inventory",
                "required_fields": [],
                "optional_fields": ["dashboard"],
            },
            exit={
                "schema_ref": "",
                "output_type": "deployment_audit",
                "guaranteed_fields": ["findings", "finding_count", "deployment_score", "timestamp"],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        from nodechain.cli.dashboard import collect_operations_status

        ops_status = collect_operations_status()
        findings: list[dict[str, Any]] = []

        # Check 1: Unresolved drift
        drift = ops_status.get("drift_detected", 0)
        remediations = ops_status.get("remediations", 0)
        if drift > remediations:
            unresolved = drift - remediations
            findings.append({
                "control": "DEPLOY-001",
                "severity": "warning",
                "title": f"{unresolved} unresolved drift(s)",
                "description": f"{drift} drift detected, {remediations} remediated. {unresolved} remaining.",
                "evidence_ref": f"operations:{unresolved}_unresolved_drift",
                "recommendation": "Review drift reports and apply remediation",
            })

        # Check 2: No known-good releases
        known_good = ops_status.get("known_good_releases", 0)
        if known_good == 0:
            findings.append({
                "control": "DEPLOY-002",
                "severity": "warning",
                "title": "No known-good releases in history",
                "description": "No verified deployment releases recorded.",
                "evidence_ref": "operations:no_known_good",
                "recommendation": "Execute deployment and create release records",
            })

        # Check 3: Failed remediations
        import json
        from pathlib import Path
        data_dir = Path("data")
        failed_count = 0
        if data_dir.exists():
            for f in data_dir.glob("remediation_receipt*.json"):
                try:
                    receipt = json.loads(f.read_text(encoding="utf-8"))
                    if receipt.get("remediation_status") in ("failed", "unknown"):
                        failed_count += 1
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        if failed_count > 0:
            findings.append({
                "control": "DEPLOY-003",
                "severity": "degraded",
                "title": f"{failed_count} failed remediation(s)",
                "description": "Remediation receipts show failures.",
                "evidence_ref": f"operations:{failed_count}_failed_remediation",
                "recommendation": "Review failed remediation receipts and re-attempt",
            })

        # Compute deployment score
        degraded_count = sum(1 for f in findings if f["severity"] == "degraded")
        warning_count = sum(1 for f in findings if f["severity"] == "warning")
        deployment_score = max(0, 100 - degraded_count * 25 - warning_count * 10)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="deployment_risk_auditor",
            step_id=envelope.step_id,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "deployment_score": deployment_score,
                "drift_detected": drift,
                "remediations": remediations,
                "known_good_releases": known_good,
                "failed_remediations": failed_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
