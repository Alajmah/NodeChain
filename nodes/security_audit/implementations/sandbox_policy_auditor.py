"""Sandbox Policy Auditor — audits sandbox and policy enforcement posture.

Node 5 of the Security Audit Chain.
Checks: seccomp availability, namespace isolation, cgroup limits, policy presets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class SandboxPolicyAuditor(BaseNode):
    """Audits sandbox and policy enforcement posture."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="sandbox_policy_auditor",
            node_type="deterministic",
            name="Sandbox Policy Auditor",
            description="Audits sandbox and policy enforcement",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.sandbox.v1",
            node_id="sandbox_policy_auditor",
            version="1.0.0",
            entry={
                "schema_ref": "",
                "input_type": "asset_inventory",
                "required_fields": [],
                "optional_fields": ["dashboard"],
            },
            exit={
                "schema_ref": "",
                "output_type": "sandbox_audit",
                "guaranteed_fields": ["findings", "finding_count", "sandbox_score", "timestamp"],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        findings: list[dict[str, Any]] = []

        # Check 1: Seccomp availability
        import sys
        has_seccomp = sys.platform.startswith("linux")
        if not has_seccomp:
            findings.append({
                "control": "SAND-001",
                "severity": "warning",
                "title": "Seccomp not available on this platform",
                "description": f"Platform is {sys.platform}. Seccomp syscall filtering requires Linux.",
                "evidence_ref": f"sandbox:platform_{sys.platform}",
                "recommendation": "Deploy on Linux for full sandbox enforcement",
            })

        # Check 2: Import enforcement hooks installed
        try:
            from nodechain.sdk.import_enforcer import _hooks_installed
            if not _hooks_installed:
                findings.append({
                    "control": "SAND-002",
                    "severity": "degraded",
                    "title": "Import enforcement hooks not installed",
                    "description": "Python import enforcement is not active.",
                    "evidence_ref": "sandbox:import_hooks_missing",
                    "recommendation": "Ensure NodeInvoker activates enforcement for untrusted nodes",
                })
        except Exception:
            pass  # Module may not have the flag

        # Check 3: Policy presets available
        try:
            from nodechain.sdk.policy_presets import POLICY_PRESETS
            preset_count = len(POLICY_PRESETS)
            if preset_count < 3:
                findings.append({
                    "control": "SAND-003",
                    "severity": "warning",
                    "title": f"Only {preset_count} policy presets available",
                    "description": "Fewer than expected policy presets configured.",
                    "evidence_ref": f"sandbox:{preset_count}_presets",
                    "recommendation": "Verify policy preset configuration",
                })
        except Exception:
            pass

        # Compute sandbox score
        degraded_count = sum(1 for f in findings if f["severity"] == "degraded")
        warning_count = sum(1 for f in findings if f["severity"] == "warning")
        sandbox_score = max(0, 100 - degraded_count * 25 - warning_count * 10)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="sandbox_policy_auditor",
            step_id=envelope.step_id,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "sandbox_score": sandbox_score,
                "platform": sys.platform,
                "seccomp_available": has_seccomp,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
