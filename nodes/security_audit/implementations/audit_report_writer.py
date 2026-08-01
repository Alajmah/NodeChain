"""Audit Report Writer — aggregates all audit findings into a signed report.

Node 7 of the Security Audit Chain.
Computes overall audit score, ranks findings by severity, and produces
a structured audit report artifact.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


SEVERITY_ORDER = {"critical": 0, "degraded": 1, "warning": 2, "info": 3}


class AuditReportWriter(BaseNode):
    """Aggregates audit findings into a final report."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="audit_report_writer",
            node_type="deterministic",
            name="Audit Report Writer",
            description="Aggregates audit findings and produces audit report",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.report.v1",
            node_id="audit_report_writer",
            version="1.0.0",
            entry={
                "input_type": "aggregated_audit_findings",
                "required_fields": [],
                "optional_fields": [
                    "trust_audit", "registry_audit", "evidence_audit",
                    "sandbox_audit", "deployment_audit",
                ],
            },
            exit={
                "output_type": "security_audit_report",
                "guaranteed_fields": [
                    "audit_score", "overall_grade", "findings", "finding_count",
                    "report_digest", "timestamp",
                ],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload

        # Collect findings from all auditors
        all_findings: list[dict[str, Any]] = []
        scores: dict[str, int] = {}

        for auditor_name, audit_key in [
            ("trust", "trust_audit"),
            ("registry", "registry_audit"),
            ("evidence", "evidence_audit"),
            ("sandbox", "sandbox_audit"),
            ("deployment", "deployment_audit"),
        ]:
            audit_data = payload.get(audit_key, {})
            findings = audit_data.get("findings", [])
            for f in findings:
                f["auditor"] = auditor_name
                all_findings.append(f)
            scores[auditor_name] = audit_data.get(f"{auditor_name}_score", 100)

        # Sort by severity (most severe first)
        all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 3))

        # Compute overall audit score
        audit_score = sum(scores.values()) // len(scores) if scores else 100

        # Determine grade
        if audit_score >= 90:
            grade = "A"
        elif audit_score >= 80:
            grade = "B"
        elif audit_score >= 70:
            grade = "C"
        elif audit_score >= 60:
            grade = "D"
        else:
            grade = "F"

        # Build report
        report = {
            "type": "security_audit_report",
            "audit_id": envelope.run_id,
            "audit_score": audit_score,
            "overall_grade": grade,
            "findings": all_findings,
            "finding_count": len(all_findings),
            "scores_by_domain": scores,
            "critical_count": sum(1 for f in all_findings if f.get("severity") == "critical"),
            "degraded_count": sum(1 for f in all_findings if f.get("severity") == "degraded"),
            "warning_count": sum(1 for f in all_findings if f.get("severity") == "warning"),
            "recommendations": [f["recommendation"] for f in all_findings if "recommendation" in f],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nodechain_version": "1.21.0",
        }

        # Compute report digest
        digest_content = json.dumps(
            {k: v for k, v in report.items() if k != "report_digest"},
            sort_keys=True, separators=(",", ":"),
        )
        report["report_digest"] = hashlib.sha256(digest_content.encode()).hexdigest()

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="audit_report_writer",
            step_id=envelope.step_id,
            output=report,
            output_type="dict",
        )
