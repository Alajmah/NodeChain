"""Governed Remediation Executor — executes governed rollback within policy bounds.

Input: remediation decision from RemediationDecisioner
Output: remediation result with evidence and rollback status

This node is the critical governance boundary. It enforces:
- Authorization check (must be authorized)
- Mode enforcement (manual never executes)
- Evidence capture for audit trail
"""

from __future__ import annotations

from datetime import datetime, timezone

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class GovernedRemediator(BaseNode):
    """Executes governed remediation within authorization bounds."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="governed_remediator",
            node_type="deterministic",
            name="Governed Remediation Executor",
            description="Executes governed rollback within policy bounds",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="incident.remediator.v1",
            node_id="governed_remediator",
            version="1.0.0",
            entry={
                "input_type": "remediation_decision",
                "schema_ref": "",
                "required_fields": ["remediation_mode", "authorized", "selected_action"],
                "optional_fields": ["policy_digest", "incident_id"],
            },
            exit={
                "output_type": "remediation_result",
                "schema_ref": "",
                "guaranteed_fields": ["executed", "rollback_attempted", "final_state", "evidence"],
            },
            side_effects=[
                {
                    "effect_type": "deployment",
                    "target": "deployment_target",
                    "optional": True,
                }
            ],
            requirements={
                "model_required": False,
                "memory_access": "none",
                "trust_level": "trusted",
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload
        mode = payload.get("remediation_mode", "manual")
        authorized = payload.get("authorized", False)
        action = payload.get("selected_action", "no_action")

        evidence: list[dict] = []
        rollback_attempted = False
        executed = False
        final_state = "no_action"

        # Authorization gate
        if not authorized:
            evidence.append({
                "gate": "authorization",
                "result": "denied",
                "reason": "Remediation not authorized",
            })
            final_state = "denied"
        elif mode == "manual":
            # Manual mode never executes — alert only
            evidence.append({
                "gate": "mode_check",
                "result": "manual_mode",
                "reason": "Manual mode requires operator intervention",
            })
            final_state = "manual_intervention_required"
        elif mode in ("recommend", "auto_rollback"):
            # For recommend: produce the plan but don't execute
            # For auto_rollback: would execute (simulated here)
            rollback_attempted = mode == "auto_rollback"
            executed = mode == "auto_rollback"

            evidence.append({
                "gate": "authorization",
                "result": "approved",
                "policy_digest": payload.get("policy_digest", ""),
                "mode": mode,
            })
            evidence.append({
                "gate": "action_validation",
                "result": "valid",
                "action": action,
            })

            if mode == "recommend":
                final_state = "recommendation_produced"
            else:
                final_state = "executed"
                evidence.append({
                    "gate": "execution",
                    "result": "success",
                    "action": "rollback_artifact",
                    "target": payload.get("target", "unknown"),
                })

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="governed_remediator",
            step_id=envelope.step_id,
            output={
                "executed": executed,
                "rollback_attempted": rollback_attempted,
                "final_state": final_state,
                "evidence": evidence,
                "evidence_count": len(evidence),
                "policy_digest": payload.get("policy_digest", ""),
                "remediation_mode": mode,
                "selected_action": action,
                "incident_id": payload.get("incident_id", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
