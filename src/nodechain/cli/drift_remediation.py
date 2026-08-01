"""Drift Remediation (v1.15.0).

When drift is detected, NodeChain can perform a governed remediation decision.
This module handles the decision logic: should we remediate? How? To what?

The actual rollback execution is delegated to the deployment adapter's
existing rollback_artifact action.

Remediation modes:
  manual     — operator decides, no automatic action
  recommend   — produce a remediation plan but do not mutate target
  auto_rollback — execute governed rollback to latest known-good
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.cli.drift_detection import (
    DriftPolicy,
    check_drift,
    create_drift_report,
    verify_drift_policy_signature,
)
from nodechain.cli.release_history import ReleaseHistory


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


#: Valid remediation modes
REMEDIATION_MODES = frozenset({"manual", "recommend", "auto_rollback"})

#: Valid remediation actions
REMEDIATION_ACTIONS = frozenset({"rollback_artifact", "redeploy", "alert", "no_action"})


class RemediationPolicy:
    """Policy governing drift remediation behavior.

    Fields:
        remediation_mode: manual | recommend | auto_rollback
        allowed_remediation_actions: Subset of REMEDIATION_ACTIONS
        require_signed_drift_policy: Require the drift policy to be signed
        require_signed_drift_report: Require the drift report to be signed
        require_release_history_snapshot: Verify release history snapshot
        require_latest_known_good: Must resolve a known-good release
        require_previous_assurance_chain: Verify prior release assurance chain
        target: Target identifier for this remediation policy
    """

    def __init__(
        self,
        remediation_mode: str = "recommend",
        allowed_remediation_actions: list[str] | None = None,
        require_signed_drift_policy: bool = False,
        require_signed_drift_report: bool = False,
        require_release_history_snapshot: bool = False,
        require_latest_known_good: bool = True,
        require_previous_assurance_chain: bool = False,
        target: str = "",
    ):
        self.remediation_mode = remediation_mode
        self.allowed_remediation_actions = (
            list(allowed_remediation_actions)
            if allowed_remediation_actions
            else ["rollback_artifact"]
        )
        self.require_signed_drift_policy = require_signed_drift_policy
        self.require_signed_drift_report = require_signed_drift_report
        self.require_release_history_snapshot = require_release_history_snapshot
        self.require_latest_known_good = require_latest_known_good
        self.require_previous_assurance_chain = require_previous_assurance_chain
        self.target = target

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemediationPolicy:
        return cls(
            remediation_mode=data.get("remediation_mode", "recommend"),
            allowed_remediation_actions=data.get("allowed_remediation_actions"),
            require_signed_drift_policy=data.get("require_signed_drift_policy", False),
            require_signed_drift_report=data.get("require_signed_drift_report", False),
            require_release_history_snapshot=data.get("require_release_history_snapshot", False),
            require_latest_known_good=data.get("require_latest_known_good", True),
            require_previous_assurance_chain=data.get("require_previous_assurance_chain", False),
            target=data.get("target", ""),
        )

    @classmethod
    def from_file(cls, path: str) -> RemediationPolicy:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "remediation_mode": self.remediation_mode,
            "allowed_remediation_actions": self.allowed_remediation_actions,
            "require_signed_drift_policy": self.require_signed_drift_policy,
            "require_signed_drift_report": self.require_signed_drift_report,
            "require_release_history_snapshot": self.require_release_history_snapshot,
            "require_latest_known_good": self.require_latest_known_good,
            "require_previous_assurance_chain": self.require_previous_assurance_chain,
            "target": self.target,
        }

    def digest(self) -> str:
        return _sha256_dict(self.to_dict())

    def is_action_allowed(self, action: str) -> bool:
        return action in self.allowed_remediation_actions


def remediate_drift(
    target: str,
    drift_report: dict[str, Any] | None = None,
    drift_report_path: str = "",
    remediation_policy: RemediationPolicy | str | None = None,
    release_history_path: str = "",
    release_history_snapshot_path: str = "",
    trust_store_path: str = "",
    # For auto_rollback execution
    deployment_manifest: Any = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Perform governed drift remediation.

    Args:
        target: Target identifier (e.g., "pve1/801").
        drift_report: Drift report dict (from check_drift/create_drift_report).
        drift_report_path: Path to drift report JSON (alternative to dict).
        remediation_policy: RemediationPolicy or path to JSON.
        release_history_path: Path to release history.
        release_history_snapshot_path: Path to release history snapshot.
        trust_store_path: Path to trust store.
        deployment_manifest: AdapterManifest for executing rollback (auto_rollback mode).
        strict: Strict mode — failures become hard errors.

    Returns:
        Remediation receipt dict.
    """
    remediation_id = str(uuid.uuid4())
    started = _now_iso()

    # Normalize policy
    if isinstance(remediation_policy, str):
        remediation_policy = RemediationPolicy.from_file(remediation_policy)
    elif remediation_policy is None:
        remediation_policy = RemediationPolicy(target=target)
        remediation_policy.remediation_mode = "recommend"

    # Load drift report
    if drift_report is None and drift_report_path:
        drift_report = json.loads(Path(drift_report_path).read_text(encoding="utf-8"))
    elif drift_report is None:
        drift_report = {}

    # Base receipt fields
    receipt: dict[str, Any] = {
        "type": "remediation_receipt",
        "remediation_id": remediation_id,
        "target": target,
        "checked_at": started,
        "remediation_mode": remediation_policy.remediation_mode,
        "drift_report_digest": "",
        "remediation_policy_digest": remediation_policy.digest(),
        "selected_action": "no_action",
        "selected_release_id": "",
        "selected_artifact_digest": "",
        "rollback_attempted": False,
        "rollback_result": "",
        "final_state": "no_remediation_needed",
        "denial_reason": "",
        "valid": True,
    }

    # Compute drift report digest
    if drift_report:
        report_for_digest = {
            k: v for k, v in drift_report.items()
            if k not in {"report_signature", "report_signature_algorithm", "report_signer_fingerprint"}
        }
        receipt["drift_report_digest"] = _sha256_dict(report_for_digest)

    # ── Decision: is remediation needed? ──
    drift_detected = drift_report.get("drift_detected", False)

    if not drift_detected:
        receipt["final_state"] = "no_remediation_needed"
        receipt["selected_action"] = "no_action"
        return receipt

    # ── Drift detected — decide remediation ──
    receipt["final_state"] = "drift_detected"

    # Validate drift policy signature if required
    if remediation_policy.require_signed_drift_policy:
        policy_status = drift_report.get("policy_signature_status", "unsigned")
        if policy_status == "unsigned":
            receipt["denial_reason"] = "Drift policy is unsigned but signature required"
            receipt["final_state"] = "denied"
            receipt["valid"] = not strict
            return receipt
        if policy_status not in ("valid", "signed_unverified"):
            receipt["denial_reason"] = f"Drift policy signature status: {policy_status}"
            receipt["final_state"] = "denied"
            receipt["valid"] = not strict
            return receipt

    # Validate drift report signature if required
    if remediation_policy.require_signed_drift_report:
        report_signed = "report_signature" in drift_report
        if not report_signed:
            receipt["denial_reason"] = "Drift report is unsigned but signature required"
            receipt["final_state"] = "denied"
            receipt["valid"] = not strict
            return receipt

    # ── Mode: manual ──
    if remediation_policy.remediation_mode == "manual":
        receipt["selected_action"] = "alert"
        receipt["final_state"] = "manual_intervention_required"
        receipt["denial_reason"] = "Manual remediation mode — operator action required"
        return receipt

    # ── Mode: recommend ──
    if remediation_policy.remediation_mode == "recommend":
        # Resolve latest known-good
        if remediation_policy.require_latest_known_good:
            history = ReleaseHistory(path=release_history_path)
            known_good = history.latest_known_good(target=target)
            if not known_good:
                receipt["denial_reason"] = "No latest known-good release found"
                receipt["final_state"] = "denied"
                receipt["valid"] = not strict
                return receipt
            receipt["selected_release_id"] = known_good.release_id
            receipt["selected_artifact_digest"] = known_good.artifact_digest

        receipt["selected_action"] = "rollback_artifact" if remediation_policy.is_action_allowed("rollback_artifact") else "alert"
        receipt["final_state"] = "recommendation_produced"
        receipt["rollback_attempted"] = False
        return receipt

    # ── Mode: auto_rollback ──
    if remediation_policy.remediation_mode == "auto_rollback":
        # Check action is allowed
        if not remediation_policy.is_action_allowed("rollback_artifact"):
            receipt["denial_reason"] = "rollback_artifact not in allowed_remediation_actions"
            receipt["final_state"] = "denied"
            receipt["valid"] = not strict
            return receipt

        # Resolve latest known-good
        history = ReleaseHistory(path=release_history_path)
        known_good = history.latest_known_good(target=target)
        if not known_good:
            receipt["denial_reason"] = "No latest known-good release found for rollback"
            receipt["final_state"] = "denied"
            receipt["valid"] = not strict
            return receipt

        receipt["selected_release_id"] = known_good.release_id
        receipt["selected_artifact_digest"] = known_good.artifact_digest

        # Verify release-history snapshot if required
        if remediation_policy.require_release_history_snapshot and release_history_snapshot_path:
            from nodechain.cli.release_history import verify_release_history_snapshot
            snap_result = verify_release_history_snapshot(
                snapshot_path=release_history_snapshot_path,
                check_live_history=True,
                history_path=release_history_path,
            )
            if not snap_result["valid"]:
                receipt["denial_reason"] = f"Release history snapshot invalid: {'; '.join(snap_result['errors'])}"
                receipt["final_state"] = "denied"
                receipt["valid"] = not strict
                return receipt

        # Verify previous assurance chain if required
        if remediation_policy.require_previous_assurance_chain:
            # Check if the known-good release has assurance chain evidence
            kg_receipt_digest = known_good.deployment_receipt_digest
            if not kg_receipt_digest:
                receipt["denial_reason"] = "Latest known-good has no deployment receipt digest"
                receipt["final_state"] = "denied"
                receipt["valid"] = not strict
                return receipt

        # Execute rollback if we have a deployment manifest
        if deployment_manifest is not None:
            receipt["selected_action"] = "rollback_artifact"
            receipt["rollback_attempted"] = True

            # Delegate to the deployment adapter
            from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
            adapter = ProxmoxApiAdapter(manifest=deployment_manifest)

            try:
                rollback_result = adapter.deploy(
                    target=target,
                    artifact_digest=receipt["selected_artifact_digest"],
                    policy_digest=remediation_policy.digest(),
                    assurance_receipt_id=remediation_id,
                )
                receipt["rollback_result"] = rollback_result.get("deploy_status", "unknown")
                receipt["final_state"] = rollback_result.get("final_deployment_state",
                    "rolled_back" if rollback_result.get("deploy_status") == "accepted" else "failed")
                # Merge relevant rollback evidence
                for k in ("rollback_status", "rollback_verified", "rollback_artifact_digest",
                          "failure_mode", "deploy_status"):
                    if k in rollback_result:
                        receipt[f"rollback_{k}"] = rollback_result[k] if not k.startswith("deploy") else rollback_result[k]
            except Exception as e:
                receipt["rollback_result"] = "exception"
                receipt["final_state"] = "failed"
                receipt["denial_reason"] = str(e)
                receipt["valid"] = not strict
        else:
            # No manifest — can't execute, downgrade to recommendation
            receipt["selected_action"] = "rollback_artifact"
            receipt["rollback_attempted"] = False
            receipt["final_state"] = "recommendation_produced"
            receipt["denial_reason"] = "No deployment manifest provided for auto_rollback execution"

    return receipt


def create_remediation_receipt(
    remediation_result: dict[str, Any],
    output_path: str = "",
    private_key_path: str = "",
) -> dict[str, Any]:
    """Create a signed remediation receipt from a remediation result.

    Args:
        remediation_result: Result from remediate_drift().
        output_path: Path to write receipt JSON.
        private_key_path: PEM private key for signing.

    Returns:
        Remediation receipt dict with optional signature.
    """
    import base64

    receipt: dict[str, Any] = dict(remediation_result)
    receipt["receipt_digest"] = _sha256_dict(
        {k: v for k, v in receipt.items()
         if k not in {"receipt_signature", "receipt_signature_algorithm",
                      "receipt_signer_fingerprint", "receipt_digest"}}
    )

    if private_key_path:
        from nodechain.cli.bundle_signing import _load_private_key
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization

        private_key = _load_private_key(private_key_path)
        signed_data = json.dumps(
            {k: v for k, v in receipt.items() if k not in {
                "receipt_signature", "receipt_signature_algorithm",
                "receipt_signer_fingerprint",
            }},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

        signature = private_key.sign(
            signed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )

        public_key = private_key.public_key()
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

        receipt["receipt_signature"] = base64.b64encode(signature).decode("ascii")
        receipt["receipt_signature_algorithm"] = "RSA-PSS-SHA256"
        receipt["receipt_signer_fingerprint"] = fingerprint

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

    return receipt
