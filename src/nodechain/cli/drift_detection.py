"""Deployment Drift Detection (v1.14.0–v1.14.1).

v1.14.0: Core drift detection — compares live target state against expected
state from release history.

v1.14.1: Policy-aware drift detection with evidence strength classification.
Each field records its evidence source, strength, and comparison status.
Strict mode enforces minimum evidence strength requirements.

Drift detection is read-only — it never mutates the target.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.cli.release_history import ReleaseHistory


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


#: Fields compared during drift detection
DRIFT_FIELDS = frozenset({
    "artifact_digest",
    "final_path",
    "service_state",
    "target_identity",
    "policy_digest",
    "deployment_receipt_digest",
})

#: Valid evidence strength levels, ordered weakest → strongest
EVIDENCE_STRENGTH_LEVELS = ("unavailable", "inferred", "observed", "verified")

#: Strength rank lookup (higher = stronger)
_STRENGTH_RANK = {s: i for i, s in enumerate(EVIDENCE_STRENGTH_LEVELS)}


def _strength_meets(minimum: str, actual: str) -> bool:
    """Check whether actual strength meets or exceeds the minimum required."""
    return _STRENGTH_RANK.get(actual, 0) >= _STRENGTH_RANK.get(minimum, 0)


#: Evidence sources considered "observed" (directly from live target)
_OBSERVED_SOURCES = frozenset({"proxmox_api", "agent", "manual", "direct"})

#: Evidence sources considered "inferred" (from configuration, not verified live)
_INFERRED_SOURCES = frozenset({"configuration", "manifest", "config", "release_record"})


def classify_evidence_strength(
    field: str,
    observed_value: str,
    evidence_source: str,
) -> str:
    """Classify the evidence strength of a single field observation.

    Returns one of: 'observed', 'inferred', 'verified', 'unavailable'.
    """
    if not observed_value:
        return "unavailable"
    if evidence_source in _INFERRED_SOURCES:
        return "inferred"
    # Default: if a value is provided and source is observed-type
    return "observed"


class DriftPolicy:
    """Policy profile governing drift detection behavior.

    Fields:
        required_fields: Fields that must be present and match.
        advisory_fields: Fields that produce warnings on mismatch.
        ignored_fields: Fields excluded from checking entirely.
        acceptable_drift: Map of field → list of acceptable observed values
            (drift allowed if observed value is in this list).
        evidence_strength_required: Map of field → minimum evidence strength
            (one of: observed, verified, inferred, unavailable).
        strict_mode: When True, required field failures are hard errors.
    """

    def __init__(
        self,
        required_fields: list[str] | None = None,
        advisory_fields: list[str] | None = None,
        ignored_fields: list[str] | None = None,
        acceptable_drift: dict[str, list[str]] | None = None,
        evidence_strength_required: dict[str, str] | None = None,
        strict_mode: bool = False,
        # v1.14.3: Lifecycle fields
        policy_id: str = "",
        policy_version: str = "",
        valid_from: str = "",
        valid_until: str = "",
        supersedes_policy_digest: str = "",
        policy_status: str = "active",
    ):
        self.required_fields = list(required_fields) if required_fields else list(DRIFT_FIELDS)
        self.advisory_fields = list(advisory_fields) if advisory_fields else []
        self.ignored_fields = list(ignored_fields) if ignored_fields else []
        self.acceptable_drift = dict(acceptable_drift) if acceptable_drift else {}
        self.evidence_strength_required = dict(evidence_strength_required) if evidence_strength_required else {}
        self.strict_mode = strict_mode
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.supersedes_policy_digest = supersedes_policy_digest
        self.policy_status = policy_status

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DriftPolicy:
        return cls(
            required_fields=data.get("required_fields"),
            advisory_fields=data.get("advisory_fields"),
            ignored_fields=data.get("ignored_fields"),
            acceptable_drift=data.get("acceptable_drift"),
            evidence_strength_required=data.get("evidence_strength_required"),
            strict_mode=data.get("strict_mode", False),
            policy_id=data.get("policy_id", ""),
            policy_version=data.get("policy_version", ""),
            valid_from=data.get("valid_from", ""),
            valid_until=data.get("valid_until", ""),
            supersedes_policy_digest=data.get("supersedes_policy_digest", ""),
            policy_status=data.get("policy_status", "active"),
        )

    @classmethod
    def from_file(cls, path: str) -> DriftPolicy:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_fields": self.required_fields,
            "advisory_fields": self.advisory_fields,
            "ignored_fields": self.ignored_fields,
            "acceptable_drift": self.acceptable_drift,
            "evidence_strength_required": self.evidence_strength_required,
            "strict_mode": self.strict_mode,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "supersedes_policy_digest": self.supersedes_policy_digest,
            "policy_status": self.policy_status,
        }

    def digest(self) -> str:
        """SHA-256 digest of the policy for binding to drift reports."""
        return _sha256_dict(self.to_dict())

    def is_ignored(self, field: str) -> bool:
        return field in self.ignored_fields

    def is_required(self, field: str) -> bool:
        return field in self.required_fields

    def is_advisory(self, field: str) -> bool:
        return field in self.advisory_fields

    def min_strength(self, field: str) -> str:
        return self.evidence_strength_required.get(field, "unavailable")

    def is_acceptable_drift(self, field: str, observed_value: str) -> bool:
        """Check whether an observed drift value is explicitly acceptable."""
        allowed = self.acceptable_drift.get(field)
        if allowed is None:
            return False
        return observed_value in allowed

    # v1.14.3: Lifecycle validation

    def is_active(self) -> bool:
        """Check if policy status is active (not deprecated/revoked)."""
        return self.policy_status == "active"

    def check_validity(self, now: str = "") -> dict[str, Any]:
        """Check time-based validity of the policy.

        Args:
            now: ISO timestamp. Defaults to current UTC time.

        Returns:
            {valid: bool, status: str, detail: str}
        """
        if not now:
            now = _now_iso()

        # Check status first
        if self.policy_status == "revoked":
            return {"valid": False, "status": "revoked",
                    "detail": "Policy has been revoked"}
        if self.policy_status == "deprecated":
            return {"valid": False, "status": "deprecated",
                    "detail": "Policy has been deprecated"}

        # Check valid_from
        if self.valid_from and now < self.valid_from:
            return {"valid": False, "status": "not_yet_valid",
                    "detail": f"Policy not valid until {self.valid_from}"}

        # Check valid_until
        if self.valid_until and now > self.valid_until:
            return {"valid": False, "status": "expired",
                    "detail": f"Policy expired at {self.valid_until}"}

        return {"valid": True, "status": "active",
                "detail": "Policy is within validity window"}


# ── v1.14.0 API (backward-compatible) ───────────────────────────────────────

def check_drift(
    target: str,
    release_id: str = "",
    release_history_path: str = "",
    # Live evidence from the target
    observed_artifact_digest: str = "",
    observed_final_path: str = "",
    observed_service_state: str = "",
    observed_target_identity: str = "",
    observed_policy_digest: str = "",
    observed_deployment_receipt_digest: str = "",
    evidence_source: str = "manual",
    # v1.14.1: Policy-aware drift detection
    policy: DriftPolicy | str | None = None,
    # v1.14.1: Per-field evidence sources
    field_evidence_sources: dict[str, str] | None = None,
    # v1.14.2: Policy signature verification
    require_policy_signature: bool = False,
    trust_store_path: str = "",
) -> dict[str, Any]:
    """Check for deployment drift against release history.

    When a policy is provided, each field records evidence_source,
    evidence_strength, and comparison_status. Strict mode enforces
    minimum evidence strength requirements.

    Args:
        target: Target identifier (e.g., "pve1/801").
        release_id: Release ID to check against. If empty, uses latest known-good.
        release_history_path: Path to release history file.
        observed_*: Live evidence from the target.
        evidence_source: How the evidence was collected ('manual', 'proxmox_api', etc.)
        policy: DriftPolicy instance, path to policy JSON, or None for default behavior.
        field_evidence_sources: Per-field evidence source overrides.

    Returns:
        Drift result dict with optional policy-aware fields.
    """
    # Normalize policy
    if isinstance(policy, str):
        # v1.14.2: Verify policy signature if required
        if require_policy_signature:
            sig_result = verify_drift_policy_signature(
                policy_path=policy,
                trust_store_path=trust_store_path,
            )
            if not sig_result["valid"]:
                return {
                    "drift_detected": False,
                    "drift_fields": [],
                    "expected_values": {},
                    "observed_values": {},
                    "checked_at": _now_iso(),
                    "target": target,
                    "release_id": release_id,
                    "evidence_source": evidence_source,
                    "report_id": str(uuid.uuid4()),
                    "valid": False,
                    "error": "Policy signature verification failed",
                    "policy_signature_errors": sig_result["errors"],
                    "policy_signature_status": sig_result["details"]["signature_status"],
                    "policy_signer_fingerprint": sig_result["details"]["signer_fingerprint"],
                    "policy_signer_trusted": sig_result["details"]["signer_trusted"],
                }
        policy = DriftPolicy.from_file(policy)
        # Preserve policy signature fields for drift report
        _policy_sig_status = ""
        _policy_sig_fp = ""
        _policy_sig_trusted = False
        if require_policy_signature:
            _policy_sig_status = sig_result["details"]["signature_status"]
            _policy_sig_fp = sig_result["details"]["signer_fingerprint"]
            _policy_sig_trusted = sig_result["details"]["signer_trusted"]
    elif policy is None:
        policy = DriftPolicy()  # Default: all fields required, no strength requirement
        _policy_sig_status = "unsigned"
        _policy_sig_fp = ""
        _policy_sig_trusted = False
    else:
        # DriftPolicy instance passed directly
        _policy_sig_status = "unsigned"
        _policy_sig_fp = ""
        _policy_sig_trusted = False

    # Resolve per-field evidence sources
    fes = field_evidence_sources or {}

    history = ReleaseHistory(path=release_history_path)

    # Resolve release record
    record = None
    if release_id:
        record = history.get(release_id)
    else:
        record = history.latest_known_good(target=target)

    if not record:
        return {
            "drift_detected": False,
            "drift_fields": [],
            "expected_values": {},
            "observed_values": {},
            "checked_at": _now_iso(),
            "target": target,
            "release_id": release_id,
            "evidence_source": evidence_source,
            "report_id": str(uuid.uuid4()),
            "error": f"Release not found: {release_id or 'latest_known_good'}",
            "valid": False,
        }

    expected_values: dict[str, Any] = {
        "artifact_digest": record.artifact_digest,
        "final_path": getattr(record, "artifact_path", ""),
        "service_state": "running" if record.final_deployment_state == "applied" else record.final_deployment_state,
        "target_identity": record.target,
        "policy_digest": getattr(record, "verifier_profile_digest", ""),
        "deployment_receipt_digest": record.deployment_receipt_digest,
    }

    observed_values: dict[str, Any] = {
        "artifact_digest": observed_artifact_digest,
        "final_path": observed_final_path,
        "service_state": observed_service_state,
        "target_identity": observed_target_identity or target,
        "policy_digest": observed_policy_digest,
        "deployment_receipt_digest": observed_deployment_receipt_digest,
    }

    # ── v1.14.0 comparison (backward-compatible) ──
    drift_fields: list[str] = []
    for field in DRIFT_FIELDS:
        if policy.is_ignored(field):
            continue
        expected = expected_values.get(field, "")
        observed = observed_values.get(field, "")
        if not observed:
            continue
        if not expected:
            continue
        # Check acceptable drift
        if expected != observed and policy.is_acceptable_drift(field, observed):
            continue
        if expected != observed:
            drift_fields.append(field)

    result: dict[str, Any] = {
        "drift_detected": len(drift_fields) > 0,
        "drift_fields": drift_fields,
        "expected_values": expected_values,
        "observed_values": observed_values,
        "checked_at": _now_iso(),
        "target": target,
        "release_id": record.release_id,
        "evidence_source": evidence_source,
        "report_id": str(uuid.uuid4()),
        "valid": True,
    }

    # ── v1.14.1: Policy-aware per-field evaluation ──
    field_details: dict[str, dict[str, Any]] = {}
    required_field_failures: list[dict[str, Any]] = []
    advisory_field_warnings: list[dict[str, Any]] = []
    evidence_strength_summary: dict[str, int] = {
        "observed": 0, "verified": 0, "inferred": 0, "unavailable": 0,
    }

    for field in DRIFT_FIELDS:
        if policy.is_ignored(field):
            field_details[field] = {
                "comparison_status": "ignored",
                "evidence_source": "",
                "evidence_strength": "unavailable",
            }
            continue

        expected = expected_values.get(field, "")
        observed = observed_values.get(field, "")
        src = fes.get(field, evidence_source)
        strength = classify_evidence_strength(field, observed, src)

        evidence_strength_summary[strength] = evidence_strength_summary.get(strength, 0) + 1

        # Determine comparison status
        if not observed:
            status = "unavailable"
        elif not expected:
            status = "expected_missing"
        elif expected == observed:
            status = "match"
        elif policy.is_acceptable_drift(field, observed):
            status = "acceptable_drift"
        else:
            status = "mismatch"

        detail = {
            "comparison_status": status,
            "evidence_source": src,
            "evidence_strength": strength,
        }
        field_details[field] = detail

        # Required field failures
        if policy.is_required(field):
            if status == "unavailable":
                required_field_failures.append({
                    "field": field,
                    "failure_type": "unavailable",
                    "detail": "Required field was not observed",
                })
            elif status == "mismatch":
                required_field_failures.append({
                    "field": field,
                    "failure_type": "mismatch",
                    "expected": expected,
                    "observed": observed,
                })
            elif status == "expected_missing":
                required_field_failures.append({
                    "field": field,
                    "failure_type": "expected_missing",
                    "detail": "No expected value in release record",
                })

            # Evidence strength enforcement
            min_str = policy.min_strength(field)
            if min_str != "unavailable" and not _strength_meets(min_str, strength):
                required_field_failures.append({
                    "field": field,
                    "failure_type": "insufficient_evidence",
                    "required_strength": min_str,
                    "actual_strength": strength,
                })

        # Advisory field warnings
        if policy.is_advisory(field) and status == "mismatch":
            advisory_field_warnings.append({
                "field": field,
                "expected": expected,
                "observed": observed,
            })

    # Compute policy-aware drift detection
    # In strict mode, required field failures count as drift even if
    # the mismatch wasn't caught by the simple v1.14.0 comparison
    policy_drift = len(required_field_failures) > 0 if policy.strict_mode else False

    result["field_details"] = field_details
    result["required_field_failures"] = required_field_failures
    result["advisory_field_warnings"] = advisory_field_warnings
    result["evidence_strength_summary"] = evidence_strength_summary
    result["policy_digest"] = policy.digest()
    result["policy_strict_mode"] = policy.strict_mode
    result["policy_required_failures_count"] = len(required_field_failures)

    # v1.14.2: Policy signature evidence
    result["policy_signature_status"] = _policy_sig_status
    result["policy_signer_fingerprint"] = _policy_sig_fp
    result["policy_signer_trusted"] = _policy_sig_trusted

    # v1.14.3: Policy lifecycle evidence
    validity = policy.check_validity()
    result["policy_id"] = policy.policy_id
    result["policy_version"] = policy.policy_version
    result["policy_status"] = policy.policy_status
    result["policy_validity_status"] = validity["status"]
    result["policy_validity_detail"] = validity["detail"]
    result["policy_supersedes"] = policy.supersedes_policy_digest

    # v1.14.3: Strict mode rejects expired/revoked policies
    if not validity["valid"] and policy.strict_mode:
        result["drift_detected"] = True
        result["valid"] = False
        result["error"] = f"Policy lifecycle violation: {validity['detail']}"
        result["drift_fields"].append("policy_lifecycle")

    # If strict mode and there are required failures, mark drift
    if policy_drift:
        result["drift_detected"] = True
        # Add any missing drift fields
        for failure in required_field_failures:
            f = failure["field"]
            if f not in result["drift_fields"]:
                result["drift_fields"].append(f)

    return result


def collect_proxmox_drift_evidence(
    manifest: Any,
    timeout: int = 30,
) -> dict[str, Any]:
    """Collect live drift evidence from a Proxmox API target.

    Read-only: queries the Proxmox API for current CT/VM state.

    Args:
        manifest: An AdapterManifest with Proxmox API connection info.
        timeout: Request timeout in seconds.

    Returns:
        {
            artifact_digest: str,
            final_path: str,
            service_state: str,
            target_identity: str,
            evidence_source: str,
        }
    """
    from nodechain.cli.deployment_adapter import ProxmoxApiAdapter

    adapter = ProxmoxApiAdapter(manifest=manifest)
    node = manifest.proxmox_node
    vmid = str(manifest.target_vmid)

    status_url = adapter._build_api_url("get_status")
    token_id, token_secret = adapter._resolve_token_id(), adapter._resolve_token_secret()
    headers = adapter._build_api_headers(token_id, token_secret)

    result = adapter._api_request(status_url, headers, timeout=timeout)

    service_state = "unknown"
    if result["status_code"] == 200 and result["body"].get("data"):
        data = result["body"]["data"]
        service_state = data.get("status", "unknown")

    return {
        "artifact_digest": "",
        "final_path": getattr(manifest, "final_path", ""),
        "service_state": service_state,
        "target_identity": f"{node}/{vmid}",
        "evidence_source": "proxmox_api",
    }


def create_drift_report(
    drift_result: dict[str, Any],
    output_path: str = "",
    private_key_path: str = "",
) -> dict[str, Any]:
    """Create a signed drift report from a drift check result.

    Includes v1.14.1 policy fields when available.
    """
    import base64

    report: dict[str, Any] = {
        "type": "drift_report",
        "report_id": drift_result.get("report_id", str(uuid.uuid4())),
        "drift_detected": drift_result.get("drift_detected", False),
        "drift_fields": drift_result.get("drift_fields", []),
        "expected_values": drift_result.get("expected_values", {}),
        "observed_values": drift_result.get("observed_values", {}),
        "checked_at": drift_result.get("checked_at", _now_iso()),
        "target": drift_result.get("target", ""),
        "release_id": drift_result.get("release_id", ""),
        "evidence_source": drift_result.get("evidence_source", ""),
        "report_digest": "",
    }

    # v1.14.1 policy fields
    if "field_details" in drift_result:
        report["field_details"] = drift_result["field_details"]
        report["required_field_failures"] = drift_result.get("required_field_failures", [])
        report["advisory_field_warnings"] = drift_result.get("advisory_field_warnings", [])
        report["evidence_strength_summary"] = drift_result.get("evidence_strength_summary", {})
        report["policy_digest"] = drift_result.get("policy_digest", "")
        report["policy_strict_mode"] = drift_result.get("policy_strict_mode", False)
        # v1.14.2
        report["policy_signature_status"] = drift_result.get("policy_signature_status", "unsigned")
        report["policy_signer_fingerprint"] = drift_result.get("policy_signer_fingerprint", "")
        report["policy_signer_trusted"] = drift_result.get("policy_signer_trusted", False)
        # v1.14.3: Lifecycle
        report["policy_id"] = drift_result.get("policy_id", "")
        report["policy_version"] = drift_result.get("policy_version", "")
        report["policy_status"] = drift_result.get("policy_status", "active")
        report["policy_validity_status"] = drift_result.get("policy_validity_status", "active")

    # Compute report digest
    report["report_digest"] = _sha256_dict(report)

    # Sign if requested
    if private_key_path:
        from nodechain.cli.bundle_signing import _load_private_key
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization

        private_key = _load_private_key(private_key_path)
        signed_data = json.dumps(
            {k: v for k, v in report.items() if k not in {
                "report_signature", "report_signature_algorithm",
                "report_signer_fingerprint",
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

        report["report_signature"] = base64.b64encode(signature).decode("ascii")
        report["report_signature_algorithm"] = "RSA-PSS-SHA256"
        report["report_signer_fingerprint"] = fingerprint

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    return report


# ── v1.14.2: Drift Policy Trust ───────────────────────────────────────────


def sign_drift_policy(
    policy_path: str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign a drift policy with RSA-PSS-SHA256 (v1.14.2).

    Produces a signed policy document containing:
      - The original policy fields
      - policy_digest
      - policy_signature
      - policy_signature_algorithm
      - policy_signer_fingerprint

    Args:
        policy_path: Path to drift policy JSON.
        private_key_path: Path to PEM private key.
        output_path: Where to write signed policy. Defaults to overwriting input.

    Returns:
        Signed policy dict.
    """
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    # Load and validate policy
    policy = DriftPolicy.from_file(policy_path)
    signed_policy = policy.to_dict()

    # Compute digest
    signed_policy["type"] = "signed_drift_policy"
    signed_policy["policy_digest"] = _sha256_dict(
        {k: v for k, v in signed_policy.items() if k != "type"}
    )

    # Sign canonical form
    canonical = json.dumps(
        {k: v for k, v in signed_policy.items() if k not in {
            "policy_signature", "policy_signature_algorithm",
            "policy_signer_fingerprint",
        }},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(
        canonical,
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

    signed_policy["policy_signature"] = base64.b64encode(signature).decode("ascii")
    signed_policy["policy_signature_algorithm"] = "RSA-PSS-SHA256"
    signed_policy["policy_signer_fingerprint"] = fingerprint

    out = output_path or policy_path
    Path(out).write_text(json.dumps(signed_policy, indent=2, sort_keys=True), encoding="utf-8")
    return signed_policy


def verify_drift_policy_signature(
    policy_path: str = "",
    policy_dict: dict[str, Any] | None = None,
    public_key_pem: str = "",
    trust_store_path: str = "",
) -> dict[str, Any]:
    """Verify a signed drift policy (v1.14.2).

    Checks:
      1. Policy has a signature field
      2. policy_digest matches the content
      3. Signature is valid for the signer's key
      4. Signer is in trust store (if trust_store_path given)
      5. Signer has drift_policy_signing purpose

    Args:
        policy_path: Path to signed drift policy JSON.
        policy_dict: Policy dict (alternative to path).
        public_key_pem: PEM public key for signature verification.
        trust_store_path: Path to trust store for signer lookup.

    Returns:
        {
            valid: bool,
            errors: list[str],
            warnings: list[str],
            details: {
                policy_digest: str,
                signature_status: str,  # valid|invalid|unsigned|signed_unverified
                signer_fingerprint: str,
                signer_trusted: bool,
                signer_purpose_ok: bool,
            }
        }
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    # Load policy
    if policy_dict is None:
        policy_dict = json.loads(Path(policy_path).read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "signature_status": "unsigned",
        "signer_fingerprint": "",
        "signer_trusted": False,
        "signer_purpose_ok": False,
    }

    sig = policy_dict.get("policy_signature", "")
    if not sig:
        return {
            "valid": False,
            "errors": ["Policy is not signed"],
            "warnings": [],
            "details": details,
        }

    # Verify digest
    stored_digest = policy_dict.get("policy_digest", "")
    if not stored_digest:
        errors.append("Missing policy_digest")
    else:
        recomputed = _sha256_dict(
            {k: v for k, v in policy_dict.items()
             if k not in {"policy_signature", "policy_signature_algorithm",
                          "policy_signer_fingerprint", "type", "policy_digest"}}
        )
        if stored_digest != recomputed:
            errors.append(
                f"Policy digest mismatch: expected {stored_digest[:16]}, got {recomputed[:16]}"
            )
    details["policy_digest"] = stored_digest

    signer_fp = policy_dict.get("policy_signer_fingerprint", "")
    details["signer_fingerprint"] = signer_fp

    # Resolve public key: try trust store first, then explicit PEM
    resolved_pem = ""
    signer_trusted = False
    signer_purpose_ok = False

    if trust_store_path:
        import os
        from nodechain.cli.trust_store import (
            load_trust_store as _load_ts,
            is_trusted_fingerprint,
        )

        # Set env var so trust store functions use the right path
        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path

        # Check if signer is trusted with drift_policy_signing purpose
        signer_trusted = is_trusted_fingerprint(
            signer_fp,
            purpose="drift_policy_signing",
            strict=False,
        )
        signer_purpose_ok = signer_trusted
        details["signer_trusted"] = signer_fp != "" and signer_trusted
        details["signer_purpose_ok"] = signer_purpose_ok

        if not signer_trusted:
            if signer_fp:
                errors.append(
                    f"Signer {signer_fp} not trusted for drift_policy_signing"
                )
            else:
                errors.append("No signer fingerprint in policy")

        # Try to get PEM from trust store
        store = _load_ts()
        for info in store["keys"].values():
            if info.get("fingerprint") == signer_fp:
                resolved_pem = info.get("public_key_pem", "")
                break

        # Restore env var
        if old_ts:
            os.environ["NODECHAIN_TRUST_STORE"] = old_ts
        elif "NODECHAIN_TRUST_STORE" in os.environ:
            del os.environ["NODECHAIN_TRUST_STORE"]

    if not resolved_pem and public_key_pem:
        resolved_pem = public_key_pem

    if not resolved_pem:
        if sig and not errors:
            warnings.append("Signed policy but no public key available for verification")
            details["signature_status"] = "signed_unverified"
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "details": details,
        }

    # Verify signature
    try:
        from cryptography.hazmat.primitives import serialization as ser
        pub_key = ser.load_pem_public_key(resolved_pem.encode("utf-8"))

        canonical = json.dumps(
            {k: v for k, v in policy_dict.items() if k not in {
                "policy_signature", "policy_signature_algorithm",
                "policy_signer_fingerprint",
            }},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

        pub_key.verify(
            base64.b64decode(sig),
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        details["signature_status"] = "valid"
    except InvalidSignature:
        details["signature_status"] = "invalid"
        errors.append("Policy signature verification failed")
    except Exception as e:
        details["signature_status"] = "invalid"
        errors.append(f"Signature verification error: {e}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "details": details,
    }
