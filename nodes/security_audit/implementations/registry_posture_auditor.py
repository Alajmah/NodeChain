"""Registry Posture Auditor — audits certified registry health.

Node 3 of the Security Audit Chain.
Checks: revoked entries, denied entries, uncertified active packages.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class RegistryPostureAuditor(BaseNode):
    """Audits certified registry posture."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="registry_posture_auditor",
            node_type="deterministic",
            name="Registry Posture Auditor",
            description="Audits certified registry for security issues",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.registry.v1",
            node_id="registry_posture_auditor",
            version="1.0.0",
            entry={
                "schema_ref": "",
                "input_type": "asset_inventory",
                "required_fields": [],
                "optional_fields": ["dashboard"],
            },
            exit={
                "schema_ref": "",
                "output_type": "registry_audit",
                "guaranteed_fields": ["findings", "finding_count", "registry_score", "timestamp"],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        from nodechain.cli.dashboard import collect_registry_status

        reg_status = collect_registry_status()
        findings: list[dict[str, Any]] = []

        # Check 1: Revoked entries
        revoked = reg_status.get("revoked", 0)
        if revoked > 0:
            findings.append({
                "control": "REG-001",
                "severity": "warning",
                "title": f"{revoked} revoked registry entries",
                "description": "Registry contains revoked packages that may have been consumed before revocation.",
                "evidence_ref": f"registry:{revoked}_revoked",
                "recommendation": "Verify no active deployments use revoked packages",
            })

        # Check 2: Denied entries (publication failures)
        denied = reg_status.get("denied", 0)
        if denied > 0:
            findings.append({
                "control": "REG-002",
                "severity": "degraded",
                "title": f"{denied} denied registry entries",
                "description": "Registry has entries that failed publication (certification or digest mismatch).",
                "evidence_ref": f"registry:{denied}_denied",
                "recommendation": "Review denied entries and fix certification issues",
            })

        # Check 3: Active but not certified
        active = reg_status.get("active", 0)
        certified = reg_status.get("certified", 0)
        uncertified = active - certified if active > certified else 0
        if uncertified > 0:
            findings.append({
                "control": "REG-003",
                "severity": "warning",
                "title": f"{uncertified} active packages without certification",
                "description": "Active registry entries lack certification status.",
                "evidence_ref": f"registry:{uncertified}_uncertified",
                "recommendation": "Run evaluation suites and create certifications",
            })

        # Compute registry score
        degraded_count = sum(1 for f in findings if f["severity"] == "degraded")
        warning_count = sum(1 for f in findings if f["severity"] == "warning")
        registry_score = max(0, 100 - degraded_count * 25 - warning_count * 10)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="registry_posture_auditor",
            step_id=envelope.step_id,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "registry_score": registry_score,
                "active": active,
                "certified": certified,
                "revoked": revoked,
                "denied": denied,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
