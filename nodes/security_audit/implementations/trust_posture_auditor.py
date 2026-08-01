"""Trust Posture Auditor — audits trust store health.

Node 2 of the Security Audit Chain.
Checks: unsigned snapshots, legacy keys, missing purposes, empty store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class TrustPostureAuditor(BaseNode):
    """Audits trust store posture."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="trust_posture_auditor",
            node_type="deterministic",
            name="Trust Posture Auditor",
            description="Audits trust store for security issues",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.trust.v1",
            node_id="trust_posture_auditor",
            version="1.0.0",
            entry={
                "schema_ref": "",
                "input_type": "asset_inventory",
                "required_fields": [],
                "optional_fields": ["dashboard"],
            },
            exit={
                "schema_ref": "",
                "output_type": "trust_audit",
                "guaranteed_fields": ["findings", "finding_count", "trust_score", "timestamp"],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        from nodechain.cli.dashboard import collect_trust_status

        trust_status = collect_trust_status()
        findings: list[dict[str, Any]] = []

        # Check 1: Store doesn't exist
        if not trust_status.get("trust_store_exists"):
            findings.append({
                "control": "TRUST-001",
                "severity": "critical",
                "title": "Trust store not initialized",
                "description": "No trust store found. All trust operations are unverified.",
                "evidence_ref": "trust_store:missing",
                "recommendation": "Initialize trust store with nodechain trust-store init",
            })

        # Check 2: Unsigned snapshot
        if trust_status.get("trust_store_exists") and not trust_status.get("snapshot_signed"):
            findings.append({
                "control": "TRUST-002",
                "severity": "warning",
                "title": "Trust store snapshot not signed",
                "description": "Trust store has no signed snapshot. Integrity cannot be verified offline.",
                "evidence_ref": "trust_store:unsigned_snapshot",
                "recommendation": "Create signed snapshot with nodechain trust-store snapshot",
            })

        # Check 3: Legacy keys
        legacy = trust_status.get("legacy_keys", 0)
        if legacy > 0:
            findings.append({
                "control": "TRUST-003",
                "severity": "warning",
                "title": f"{legacy} legacy keys without purpose",
                "description": "Trust store contains keys without purpose constraints.",
                "evidence_ref": f"trust_store:{legacy}_legacy_keys",
                "recommendation": "Migrate legacy keys to purpose-scoped entries",
            })

        # Check 4: Zero keys
        if trust_status.get("trust_store_exists") and trust_status.get("total_keys", 0) == 0:
            findings.append({
                "control": "TRUST-004",
                "severity": "warning",
                "title": "Trust store has zero trusted keys",
                "description": "No keys in trust store. No signatures can be verified.",
                "evidence_ref": "trust_store:empty",
                "recommendation": "Add keys for required purposes (attestation, receipt, etc.)",
            })

        # Compute trust score (0-100)
        critical_count = sum(1 for f in findings if f["severity"] == "critical")
        warning_count = sum(1 for f in findings if f["severity"] == "warning")
        trust_score = max(0, 100 - critical_count * 40 - warning_count * 10)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="trust_posture_auditor",
            step_id=envelope.step_id,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "trust_score": trust_score,
                "total_keys": trust_status.get("total_keys", 0),
                "legacy_keys": legacy,
                "snapshot_signed": trust_status.get("snapshot_signed", False),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
