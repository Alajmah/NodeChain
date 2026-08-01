"""Remediation Decisioner — decides remediation mode based on severity and policy.

Input: severity assessment from SeverityTriager
Output: remediation decision with mode, policy, and authorization
"""

from __future__ import annotations

from datetime import datetime, timezone

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class RemediationDecisioner(BaseNode):
    """Decides remediation mode based on severity and governance policy."""

    # Mode hierarchy: manual < recommend < auto_rollback
    SEVERITY_MODE_MAP = {
        "critical": "manual",  # Critical incidents require human approval
        "high": "recommend",   # High incidents get rollback recommendation
        "medium": "recommend",
        "low": "manual",       # Low incidents are alert-only
    }

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="remediation_decisioner",
            node_type="deterministic",
            name="Remediation Decisioner",
            description="Decides remediation mode based on severity and policy",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="incident.decisioner.v1",
            node_id="remediation_decisioner",
            version="1.0.0",
            entry={
                "input_type": "severity_assessment",
                "schema_ref": "",
                "required_fields": ["severity", "requires_remediation"],
                "optional_fields": ["urgency", "blast_radius"],
            },
            exit={
                "output_type": "remediation_decision",
                "schema_ref": "",
                "guaranteed_fields": ["remediation_mode", "authorized", "policy_digest", "selected_action"],
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
        severity = payload.get("severity", "low")
        requires_remediation = payload.get("requires_remediation", False)

        if not requires_remediation:
            return EnvelopeResponse(
                request_envelope_id=envelope.envelope_id,
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id="remediation_decisioner",
                step_id=envelope.step_id,
                output={
                    "remediation_mode": "manual",
                    "authorized": False,
                    "policy_digest": "",
                    "selected_action": "no_action",
                    "reason": "Remediation not required for this severity",
                    "incident_id": payload.get("incident_id", ""),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                output_type="dict",
            )

        mode = self.SEVERITY_MODE_MAP.get(severity, "manual")
        selected_action = "alert" if mode == "manual" else "rollback_artifact"
        # Manual mode is always authorized to produce an alert,
        # just not authorized to execute rollback.
        authorized = True  # All modes are authorized at their level

        # Compute a policy digest (simulated — real impl signs the policy)
        import hashlib
        import json
        policy_doc = {
            "remediation_mode": mode,
            "severity": severity,
            "selected_action": selected_action,
        }
        policy_digest = hashlib.sha256(
            json.dumps(policy_doc, sort_keys=True).encode()
        ).hexdigest()

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="remediation_decisioner",
            step_id=envelope.step_id,
            output={
                "remediation_mode": mode,
                "authorized": authorized,
                "policy_digest": policy_digest,
                "selected_action": selected_action,
                "reason": f"Mode '{mode}' selected for severity '{severity}'",
                "incident_id": payload.get("incident_id", ""),
                "severity": severity,
                "urgency": payload.get("urgency", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
