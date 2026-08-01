"""Evidence Chain Auditor — audits evidence chain integrity.

Node 4 of the Security Audit Chain.
Checks: broken chains, missing digests, incomplete evidence links.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class EvidenceChainAuditor(BaseNode):
    """Audits evidence chain integrity."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="evidence_chain_auditor",
            node_type="deterministic",
            name="Evidence Chain Auditor",
            description="Audits evidence chain integrity",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.evidence.v1",
            node_id="evidence_chain_auditor",
            version="1.0.0",
            entry={
                "schema_ref": "",
                "input_type": "asset_inventory",
                "required_fields": [],
                "optional_fields": ["dashboard"],
            },
            exit={
                "schema_ref": "",
                "output_type": "evidence_audit",
                "guaranteed_fields": ["findings", "finding_count", "evidence_score", "timestamp"],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        from nodechain.cli.dashboard import collect_evidence_status

        ev_status = collect_evidence_status()
        findings: list[dict[str, Any]] = []

        # Check 1: Broken evidence chains
        broken = ev_status.get("broken_chains", 0)
        if broken > 0:
            findings.append({
                "control": "EVID-001",
                "severity": "warning",
                "title": f"{broken} broken evidence chain(s)",
                "description": "Evidence chains with missing or invalid links detected.",
                "evidence_ref": f"evidence:{broken}_broken_chains",
                "recommendation": "Re-index evidence artifacts",
            })

        # Check 2: Replay failures
        replay_failures = ev_status.get("replay_failures", 0)
        if replay_failures > 0:
            findings.append({
                "control": "EVID-002",
                "severity": "warning",
                "title": f"{replay_failures} trace replay failure(s)",
                "description": "Trace replay verification has failed for some chains.",
                "evidence_ref": f"evidence:{replay_failures}_replay_failures",
                "recommendation": "Investigate trace integrity for failed replays",
            })

        # Check 3: Zero indexed artifacts
        indexed = ev_status.get("indexed_artifacts", 0)
        if indexed == 0:
            findings.append({
                "control": "EVID-003",
                "severity": "warning",
                "title": "No evidence artifacts indexed",
                "description": "No evidence artifacts found. Audit trail is empty.",
                "evidence_ref": "evidence:empty",
                "recommendation": "Generate evidence by running chains and creating audit bundles",
            })

        # Compute evidence score
        warning_count = len(findings)
        evidence_score = max(0, 100 - warning_count * 15)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="evidence_chain_auditor",
            step_id=envelope.step_id,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "evidence_score": evidence_score,
                "indexed_artifacts": indexed,
                "broken_chains": broken,
                "replay_failures": replay_failures,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
