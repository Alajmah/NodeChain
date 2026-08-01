"""Evidence Indexing, Querying, and Timeline (v1.17.0).

Indexes NodeChain artifacts into a queryable evidence graph, supports
filtering across all artifact types, and reconstructs operational timelines
for targets.

Evidence types supported:
  trace, audit_bundle, attestation, verifier_profile, gate_receipt,
  deployment_receipt, release_history_snapshot, drift_report,
  remediation_receipt, evaluation_report, certification
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


#: Supported artifact types for evidence indexing
EVIDENCE_TYPES = frozenset({
    "trace",
    "audit_bundle",
    "attestation",
    "verifier_profile",
    "gate_receipt",
    "deployment_receipt",
    "release_history_snapshot",
    "drift_report",
    "remediation_receipt",
    "evaluation_report",
    "certification",
    "signed_evaluation_suite",
    "registry_entry",
    "remote_install_receipt",  # v2.0.0
    "dependency_resolution_receipt",  # v2.2.0
    "transparency_log",  # v2.3.0
    "transparency_entry",  # v2.3.0
    "policy_profile_receipt",  # v2.4.0
    "federated_resolution_receipt",  # v2.5.0
    "registry_health_score_receipt",  # v2.6.0
    "registry_reputation_report",  # v2.6.0
    "discovery_index_receipt",  # v2.7.0
    "marketplace_registry_add_receipt",  # v2.7.0
    "supply_chain_attestation",  # v2.8.0
    "attestation_receipt",  # v2.8.0
    "retention_manifest",  # v2.9.0
    "garbage_collection_receipt",  # v2.9.0
    "evidence_checkpoint",  # v2.10.0
    "checkpoint_chain_receipt",  # v2.10.0
    "recovery_report",  # v2.10.0
})

#: Maps JSON type field to normalized evidence type
_TYPE_MAP = {
    "chain_trace": "trace",
    "audit_bundle": "audit_bundle",
    "deployment_attestation": "attestation",
    "verifier_profile": "verifier_profile",
    "gate_receipt": "gate_receipt",
    "deployment_system_receipt": "deployment_receipt",
    "deployment_receipt": "deployment_receipt",
    "release_history_snapshot": "release_history_snapshot",
    "drift_report": "drift_report",
    "remediation_receipt": "remediation_receipt",
    "evaluation_report": "evaluation_report",
    "evaluation_certification": "certification",
    "signed_evaluation_suite": "signed_evaluation_suite",
    "registry_entry": "registry_entry",
    "remote_install_receipt": "remote_install_receipt",
    "transparency_log": "transparency_log",
    "transparency_entry": "transparency_entry",
    "policy_profile_receipt": "policy_profile_receipt",
    "federated_resolution_receipt": "federated_resolution_receipt",
}


def _detect_artifact_type(data: dict[str, Any]) -> str:
    """Detect the artifact type from its JSON content."""
    # Check explicit type field
    raw_type = data.get("type", "")
    if raw_type in _TYPE_MAP:
        return _TYPE_MAP[raw_type]
    if raw_type in EVIDENCE_TYPES:
        return raw_type

    # Infer from field patterns
    if "chain_id" in data and "events" in data:
        return "trace"
    if "eval_id" in data and "suite_digest" in data:
        return "evaluation_report"
    if "certification_id" in data:
        return "certification"
    if "drift_detected" in data or "drift_report_digest" in data:
        if "remediation_mode" in data:
            return "remediation_receipt"
        return "drift_report"
    if "policy_id" in data and "required" in data:
        return "gate_receipt"
    if "target_type" in data and "adapter_name" in data:
        return "deployment_receipt"
    if "attestation_id" in data or "policy_id" in data and "target_digest" in data:
        return "attestation"
    if "release_history_digest" in data or "entries_digest" in data:
        return "release_history_snapshot"
    if "audit_id" in data or "bundle_digest" in data:
        return "audit_bundle"
    if "profile_id" in data and "trusted_keys" in data:
        return "verifier_profile"
    if "suite_signature" in data:
        return "signed_evaluation_suite"
    if "entry_id" in data and "package_digest" in data:
        return "registry_entry"
    if "receipt_id" in data and "remote_url" in data:
        if "graph_digest" in data:
            return "dependency_resolution_receipt"
        return "remote_install_receipt"

    return "unknown"


def _extract_common_fields(data: dict[str, Any], artifact_type: str) -> dict[str, Any]:
    """Extract common fields from an artifact for indexing."""
    return {
        "run_id": data.get("run_id", ""),
        "target_digest": data.get("target_digest", ""),
        "target_type": data.get("target_type", ""),
        "target_ref": data.get("target_ref", ""),
        "artifact_digest": (
            data.get("report_digest")
            or data.get("certification_digest")
            or data.get("drift_report_digest")
            or data.get("remediation_id", "")
            or data.get("bundle_digest")
            or data.get("attestation_digest")
            or data.get("receipt_digest")
            or data.get("suite_digest")
            or data.get("suite_digest", "")
            or data.get("release_history_digest")
            or data.get("entries_digest")
            or ""
        ),
        "policy_digest": data.get("policy_digest", ""),
        "suite_digest": data.get("suite_digest", ""),
        "certification_status": data.get("certification_status", ""),
        "final_deployment_state": data.get("final_state", data.get("final_deployment_state", "")),
        "drift_detected": data.get("drift_detected", data.get("has_drift", False)),
        "remediation_status": data.get("final_state", data.get("remediation_status", "")),
        "signer_fingerprint": (
            data.get("report_signer_fingerprint")
            or data.get("certifier_fingerprint")
            or data.get("suite_signer_fingerprint")
            or data.get("signer_fingerprint")
            or data.get("attestation_signer_fingerprint")
            or data.get("receipt_signer_fingerprint")
            or ""
        ),
        "timestamp": (
            data.get("issued_at")
            or data.get("finished_at")
            or data.get("started_at")
            or data.get("created_at")
            or data.get("timestamp")
            or data.get("generated_at")
            or data.get("detected_at")
            or ""
        ),
        "chain_id": data.get("chain_id", ""),
        "eval_id": data.get("eval_id", ""),
    }


def index_artifact(
    file_path: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Index a single artifact file.

    Args:
        file_path: Path to the artifact JSON file.
        data: Pre-parsed data dict (alternative to reading file).

    Returns:
        Evidence entry dict.
    """
    if data is None:
        data = json.loads(Path(file_path).read_text(encoding="utf-8"))

    artifact_type = _detect_artifact_type(data)
    common = _extract_common_fields(data, artifact_type)

    entry = {
        "file_path": str(file_path),
        "artifact_type": artifact_type,
        "indexed_at": _now_iso(),
        **common,
        "file_digest": hashlib.sha256(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }

    return entry


def index_directory(
    directory: str,
    recursive: bool = True,
) -> list[dict[str, Any]]:
    """Index all JSON artifacts in a directory.

    Args:
        directory: Path to directory containing artifact JSON files.
        recursive: Whether to search subdirectories.

    Returns:
        List of evidence entries.
    """
    entries: list[dict[str, Any]] = []
    base = Path(directory)

    pattern = "**/*.json" if recursive else "*.json"
    for path in sorted(base.glob(pattern)):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            entry = index_artifact(str(path), data)
            if entry["artifact_type"] != "unknown":
                entries.append(entry)
        except (json.JSONDecodeError, Exception):
            continue

    return entries


def build_evidence_index(
    input_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Build an evidence index from a file or directory.

    Args:
        input_path: Path to artifact file or directory.
        output_path: Where to write the evidence index JSON.

    Returns:
        Evidence index dict with entries, digest, and metadata.
    """
    p = Path(input_path)

    if p.is_file():
        entries = [index_artifact(input_path)]
    elif p.is_dir():
        entries = index_directory(input_path)
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")

    index = {
        "type": "evidence_index",
        "indexed_at": _now_iso(),
        "entry_count": len(entries),
        "artifact_types": sorted({e["artifact_type"] for e in entries}),
        "entries": entries,
        "evidence_index_digest": "",
    }

    # Compute digest (excluding the digest field itself)
    digest_content = {k: v for k, v in index.items() if k != "evidence_index_digest"}
    index["evidence_index_digest"] = _sha256_dict(digest_content)

    if output_path:
        Path(output_path).write_text(
            json.dumps(index, indent=2, sort_keys=True), encoding="utf-8",
        )

    return index


# ── Query Engine ───────────────────────────────────────────────────────────

#: Supported query filters
QUERY_FILTERS = frozenset({
    "run_id", "target_digest", "target_type", "artifact_digest",
    "policy_digest", "suite_digest", "certification_status",
    "final_deployment_state", "drift_detected", "remediation_status",
    "signer_fingerprint", "artifact_type",
})


def query_evidence(
    index: dict[str, Any] | str,
    filters: dict[str, Any] | None = None,
    time_from: str = "",
    time_until: str = "",
) -> list[dict[str, Any]]:
    """Query evidence index with filters.

    Args:
        index: Evidence index dict or path to JSON.
        filters: Dict of field → value filters. Supports partial string match.
        time_from: ISO timestamp lower bound (inclusive).
        time_until: ISO timestamp upper bound (inclusive).

    Returns:
        List of matching evidence entries.
    """
    if isinstance(index, str):
        index = json.loads(Path(index).read_text(encoding="utf-8"))

    entries = index.get("entries", [])
    filters = filters or {}

    results: list[dict[str, Any]] = []

    for entry in entries:
        match = True

        for key, value in filters.items():
            entry_val = entry.get(key, "")

            if key == "drift_detected":
                # Boolean comparison
                if bool(entry_val) != bool(value):
                    match = False
                    break
            elif isinstance(value, str):
                # Partial string match
                if value.lower() not in str(entry_val).lower():
                    match = False
                    break
            else:
                if entry_val != value:
                    match = False
                    break

        if match:
            # Time range filter
            ts = entry.get("timestamp", "")
            if time_from and ts and ts < time_from:
                match = False
            if time_until and ts and ts > time_until:
                match = False

        if match:
            results.append(entry)

    return results


# ── Timeline Reconstruction ────────────────────────────────────────────────

#: Timeline event ordering (by lifecycle phase)
TIMELINE_ORDER = {
    "evaluation_report": 1,
    "certification": 2,
    "audit_bundle": 3,
    "attestation": 4,
    "verifier_profile": 5,
    "gate_receipt": 6,
    "trace": 7,
    "deployment_receipt": 8,
    "release_history_snapshot": 9,
    "drift_report": 10,
    "remediation_receipt": 11,
    "signed_evaluation_suite": 12,
    "registry_entry": 13,
}


def build_timeline(
    index: dict[str, Any] | str,
    target: str = "",
    target_digest: str = "",
) -> dict[str, Any]:
    """Reconstruct an operational timeline for a target.

    Args:
        index: Evidence index dict or path to JSON.
        target: Target reference to filter by.
        target_digest: Target digest to filter by.

    Returns:
        Timeline dict with ordered events and digest.
    """
    if isinstance(index, str):
        index = json.loads(Path(index).read_text(encoding="utf-8"))

    entries = index.get("entries", [])

    # Filter by target
    if target:
        entries = [e for e in entries
                    if target.lower() in e.get("target_ref", "").lower()
                    or target.lower() in e.get("target_type", "").lower()]
    if target_digest:
        entries = [e for e in entries
                    if e.get("target_digest") == target_digest]

    # Sort by timestamp, then by lifecycle phase
    def sort_key(e: dict[str, Any]) -> tuple:
        ts = e.get("timestamp", "")
        phase = TIMELINE_ORDER.get(e.get("artifact_type", ""), 99)
        return (ts, phase)

    entries.sort(key=sort_key)

    # Build timeline events
    events: list[dict[str, Any]] = []
    for entry in entries:
        events.append({
            "artifact_type": entry["artifact_type"],
            "timestamp": entry.get("timestamp", ""),
            "target_ref": entry.get("target_ref", ""),
            "target_digest": entry.get("target_digest", "")[:16] + "..." if entry.get("target_digest") else "",
            "artifact_digest": entry.get("artifact_digest", "")[:16] + "..." if entry.get("artifact_digest") else "",
            "signer_fingerprint": entry.get("signer_fingerprint", ""),
            "summary": _summarize_event(entry),
            "file_path": entry.get("file_path", ""),
        })

    timeline = {
        "type": "evidence_timeline",
        "target": target,
        "target_digest": target_digest,
        "generated_at": _now_iso(),
        "event_count": len(events),
        "events": events,
        "timeline_digest": "",
    }

    digest_content = {k: v for k, v in timeline.items() if k != "timeline_digest"}
    timeline["timeline_digest"] = _sha256_dict(digest_content)

    return timeline


def _summarize_event(entry: dict[str, Any]) -> str:
    """Generate a human-readable summary for a timeline event."""
    at = entry.get("artifact_type", "unknown")
    if at == "evaluation_report":
        passed = "passed" if entry.get("eval_id") else "completed"
        return f"Evaluation {passed}"
    if at == "certification":
        status = entry.get("certification_status", "unknown")
        return f"Certification: {status}"
    if at == "deployment_receipt":
        state = entry.get("final_deployment_state", "")
        return f"Deployment: {state}" if state else "Deployment recorded"
    if at == "drift_report":
        detected = entry.get("drift_detected", False)
        return "Drift detected" if detected else "No drift"
    if at == "remediation_receipt":
        status = entry.get("remediation_status", "")
        return f"Remediation: {status}" if status else "Remediation recorded"
    if at == "release_history_snapshot":
        return "Release history snapshot"
    if at == "trace":
        return f"Chain execution (run: {entry.get('run_id', '')[:8]})"
    if at == "attestation":
        return "Deployment attestation"
    if at == "audit_bundle":
        return "Sandbox audit bundle"
    if at == "gate_receipt":
        return "Gate evaluation receipt"
    if at == "verifier_profile":
        return "Verifier profile"
    if at == "signed_evaluation_suite":
        return "Signed evaluation suite"
    if at == "registry_entry":
        pid = entry.get("package_id", entry.get("target_ref", ""))
        status = entry.get("certification_status", "")
        return f"Registry: {pid} ({status})" if status else f"Registry: {pid}"
    return at


# ── Evidence Report Signing ────────────────────────────────────────────────

def sign_evidence_report(
    report: dict[str, Any] | str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign an evidence report (index, timeline, or replay report).

    Args:
        report: Evidence report dict or path to JSON.
        private_key_path: Path to PEM private key.
        output_path: Where to write signed report JSON.

    Returns:
        Signed report dict.
    """
    import base64
    if isinstance(report, str):
        report = json.loads(Path(report).read_text(encoding="utf-8"))

    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    # Find the digest field
    digest_field = ""
    for candidate in ("evidence_index_digest", "timeline_digest", "replay_report_digest"):
        if candidate in report:
            digest_field = candidate
            break

    # Recompute digest if field exists
    if digest_field:
        digest_content = {k: v for k, v in report.items()
                          if k not in {digest_field, "evidence_signature",
                                       "evidence_signature_algorithm",
                                       "evidence_signer_fingerprint"}}
        report[digest_field] = _sha256_dict(digest_content)

    # Canonical form for signing (exclude signature fields)
    sig_excluded = {"evidence_signature", "evidence_signature_algorithm",
                    "evidence_signer_fingerprint"}
    canonical = json.dumps(
        {k: v for k, v in report.items() if k not in sig_excluded},
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

    report["evidence_signature"] = base64.b64encode(signature).decode("ascii")
    report["evidence_signature_algorithm"] = "RSA-PSS-SHA256"
    report["evidence_signer_fingerprint"] = fingerprint

    if output_path:
        Path(output_path).write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8",
        )

    return report


def verify_evidence_report(
    report: dict[str, Any] | str,
    public_key_pem: str = "",
    trust_store_path: str = "",
) -> dict[str, Any]:
    """Verify a signed evidence report.

    Returns:
        {valid, errors, warnings, details}
    """
    import base64
    if isinstance(report, str):
        report = json.loads(Path(report).read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "signature_status": "unsigned",
        "signer_fingerprint": "",
        "signer_trusted": False,
    }

    sig = report.get("evidence_signature", "")
    if not sig:
        return {"valid": False, "errors": ["Evidence report is not signed"],
                "warnings": [], "details": details}

    signer_fp = report.get("evidence_signer_fingerprint", "")
    details["signer_fingerprint"] = signer_fp

    resolved_pem = ""

    if trust_store_path:
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint, load_trust_store

        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path
        try:
            trusted = is_trusted_fingerprint(signer_fp, purpose="evidence_report_signing")
            details["signer_trusted"] = signer_fp != "" and trusted
            if not trusted:
                if signer_fp:
                    errors.append(f"Signer {signer_fp} not trusted for evidence_report_signing")
                else:
                    errors.append("No signer fingerprint")

            store = load_trust_store()
            for info in store["keys"].values():
                if info.get("fingerprint") == signer_fp:
                    resolved_pem = info.get("public_key_pem", "")
                    break
        finally:
            if old_ts:
                os.environ["NODECHAIN_TRUST_STORE"] = old_ts
            elif "NODECHAIN_TRUST_STORE" in os.environ:
                del os.environ["NODECHAIN_TRUST_STORE"]

    if not resolved_pem and public_key_pem:
        resolved_pem = public_key_pem

    if not resolved_pem:
        if sig and not errors:
            warnings.append("Signed but no public key for verification")
            details["signature_status"] = "signed_unverified"
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}

    try:
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        pub_key = ser.load_pem_public_key(resolved_pem.encode("utf-8"))
        sig_excluded = {"evidence_signature", "evidence_signature_algorithm",
                        "evidence_signer_fingerprint"}
        canonical = json.dumps(
            {k: v for k, v in report.items() if k not in sig_excluded},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        pub_key.verify(
            base64.b64decode(sig), canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        details["signature_status"] = "valid"
    except InvalidSignature:
        details["signature_status"] = "invalid"
        errors.append("Evidence report signature verification failed")
    except Exception as e:
        details["signature_status"] = "invalid"
        errors.append(f"Signature verification error: {e}")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}
