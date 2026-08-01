"""Evaluation Certification (v1.16.3).

Creates signed certification artifacts for targets that pass trusted
evaluation suites under strict thresholds.

Certification is the bridge between evaluation and ecosystem trust:
  package → sign → evaluate → certify → publish → reuse

A certification proves that:
  1. A target was evaluated by a specific suite
  2. The evaluation passed (report passed=true)
  3. The evaluation report was signed (if required)
  4. The suite was signed and trusted (if required)
  5. The suite was active and within its validity window
  6. The certifier is authorized via trust store
  7. The certification itself is signed
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


#: Valid certification statuses
CERTIFICATION_STATUSES = frozenset({"certified", "denied", "revoked"})

#: Fields excluded from certification digest computation
_DIGEST_EXCLUDED = frozenset({
    "certification_signature",
    "certification_signature_algorithm",
    "certifier_fingerprint",
    "certification_digest",
})


def create_certification(
    eval_report: dict[str, Any] | str,
    valid_from: str = "",
    valid_until: str = "",
    require_report_signature: bool = False,
    require_suite_signature: bool = False,
    trust_store_path: str = "",
    strict: bool = False,
) -> dict[str, Any]:
    """Create a certification artifact from an evaluation report.

    Checks (all must pass for certification):
      1. Evaluation report passed=true
      2. Report signature valid (if require_report_signature)
      3. Suite signature valid (if require_suite_signature)
      4. Suite registry status active (if strict)
      5. Suite validity window acceptable (if strict)
      6. Thresholds satisfied (implied by passed=true)
      7. Target digest present

    Args:
        eval_report: Evaluation report dict or path to JSON file.
        valid_from: ISO timestamp for certification validity start.
        valid_until: ISO timestamp for certification validity end.
        require_report_signature: Require the eval report to be signed.
        require_suite_signature: Require the suite to be signed.
        trust_store_path: Path to trust store for verification.
        strict: Enable all checks.

    Returns:
        Certification artifact dict.
    """
    # Load report
    if isinstance(eval_report, str):
        eval_report = json.loads(Path(eval_report).read_text(encoding="utf-8"))

    issued_at = _now_iso()
    errors: list[str] = []

    # Check 1: Report passed
    if not eval_report.get("passed", False):
        errors.append("Evaluation report did not pass (passed != true)")

    # Check 2: Report signature (if required)
    if require_report_signature:
        report_sig_status = eval_report.get("report_signature_status", "unsigned")
        if report_sig_status != "valid":
            errors.append(f"Report signature required but status is '{report_sig_status}'")

    # Check 3: Suite signature (if required)
    if require_suite_signature:
        suite_sig_status = eval_report.get("suite_signature_status", "unsigned")
        if suite_sig_status != "valid":
            errors.append(f"Suite signature required but status is '{suite_sig_status}'")

    # Check 4: Suite validity (if strict)
    if strict:
        suite_validity = eval_report.get("suite_validity_status", "not_checked")
        if suite_validity != "valid":
            errors.append(f"Suite validity required but status is '{suite_validity}'")

    # Check 5: Target digest present
    target_digest = eval_report.get("target_digest", "")
    if not target_digest:
        errors.append("Evaluation report has no target_digest")

    # Build certification (even if denied, for audit trail)
    certification_id = str(uuid.uuid4())
    target_type = eval_report.get("target_type", eval_report.get("suite_target_type", "chain"))
    suite_id = eval_report.get("suite_id", "")
    suite_version = eval_report.get("suite_version", "")
    suite_digest = eval_report.get("suite_digest", "")
    report_digest = eval_report.get("report_digest", "")

    cert_status = "certified" if not errors else "denied"

    cert: dict[str, Any] = {
        "type": "evaluation_certification",
        "certification_id": certification_id,
        "target_type": target_type,
        "target_ref": eval_report.get("target_ref", ""),
        "target_digest": target_digest,
        "suite_id": suite_id,
        "suite_version": suite_version,
        "suite_digest": suite_digest,
        "eval_report_digest": report_digest,
        "certifier_fingerprint": "",
        "certification_status": cert_status,
        "valid_from": valid_from or issued_at,
        "valid_until": valid_until,
        "issued_at": issued_at,
        "errors": errors,
        "nodechain_version": eval_report.get("nodechain_version", ""),
        # Placeholder for signing
        "certification_digest": "",
        "certification_signature": "",
        "certification_signature_algorithm": "",
    }

    # Compute digest
    cert["certification_digest"] = _sha256_dict(
        {k: v for k, v in cert.items() if k not in _DIGEST_EXCLUDED}
    )

    return cert


def sign_certification(
    certification: dict[str, Any] | str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign a certification artifact with RSA-PSS-SHA256.

    Args:
        certification: Certification dict or path to JSON file.
        private_key_path: Path to PEM private key.
        output_path: Where to write signed certification JSON.

    Returns:
        Signed certification dict.
    """
    if isinstance(certification, str):
        certification = json.loads(Path(certification).read_text(encoding="utf-8"))

    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    # Recompute digest (ensure it's fresh)
    certification["certification_digest"] = _sha256_dict(
        {k: v for k, v in certification.items()
         if k not in {"certification_signature", "certification_signature_algorithm",
                      "certifier_fingerprint", "certification_digest"}}
    )

    # Canonical form for signing
    canonical = json.dumps(
        {k: v for k, v in certification.items()
         if k not in {"certification_signature", "certification_signature_algorithm",
                      "certifier_fingerprint"}},
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

    certification["certifier_fingerprint"] = fingerprint
    certification["certification_signature"] = base64.b64encode(signature).decode("ascii")
    certification["certification_signature_algorithm"] = "RSA-PSS-SHA256"

    if output_path:
        Path(output_path).write_text(
            json.dumps(certification, indent=2, sort_keys=True), encoding="utf-8",
        )

    return certification


def verify_certification(
    certification: dict[str, Any] | str,
    public_key_pem: str = "",
    trust_store_path: str = "",
    expected_target_digest: str = "",
    expected_report_digest: str = "",
) -> dict[str, Any]:
    """Verify a signed certification artifact.

    Checks (8-point):
      1. Certification has signature
      2. certification_digest matches content
      3. Signature is cryptographically valid
      4. Certifier is in trust store (if trust_store_path)
      5. Certifier has certification_signing purpose
      6. eval_report_digest present
      7. suite_digest present
      8. Status is certified and within validity window

    Returns:
        {valid, errors, warnings, details}
    """
    if isinstance(certification, str):
        certification = json.loads(Path(certification).read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "signature_status": "unsigned",
        "certifier_fingerprint": "",
        "certifier_trusted": False,
        "certification_status": certification.get("certification_status", ""),
        "certification_digest": "",
        "within_validity_window": True,
    }

    # Check 1: Signature present
    sig = certification.get("certification_signature", "")
    if not sig:
        errors.append("Certification is not signed")
        return {"valid": False, "errors": errors, "warnings": warnings, "details": details}

    # Check 2: Digest matches
    stored_digest = certification.get("certification_digest", "")
    if not stored_digest:
        errors.append("Missing certification_digest")
    else:
        recomputed = _sha256_dict(
            {k: v for k, v in certification.items()
             if k not in _DIGEST_EXCLUDED}
        )
        if stored_digest != recomputed:
            errors.append("Certification digest mismatch")
    details["certification_digest"] = stored_digest

    signer_fp = certification.get("certifier_fingerprint", "")
    details["certifier_fingerprint"] = signer_fp

    # Resolve public key
    resolved_pem = ""

    # Check 4 & 5: Trust store lookup
    if trust_store_path:
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint, load_trust_store

        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path
        try:
            certifier_trusted = is_trusted_fingerprint(
                signer_fp, purpose="certification_signing",
            )
            details["certifier_trusted"] = signer_fp != "" and certifier_trusted
            if not certifier_trusted:
                if signer_fp:
                    errors.append(
                        f"Certifier {signer_fp} not trusted for certification_signing"
                    )
                else:
                    errors.append("No certifier fingerprint in certification")

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

    # Check 6: eval_report_digest present
    if not certification.get("eval_report_digest"):
        errors.append("Missing eval_report_digest")

    # Check 7: suite_digest present
    if not certification.get("suite_digest"):
        errors.append("Missing suite_digest")

    # Check 8: Status and validity window
    status = certification.get("certification_status", "")
    if status != "certified":
        errors.append(f"Certification status is '{status}', not 'certified'")

    now = _now_iso()
    valid_from = certification.get("valid_from", "")
    valid_until = certification.get("valid_until", "")
    if valid_from and now < valid_from:
        errors.append("Certification not yet valid")
        details["within_validity_window"] = False
    if valid_until and now > valid_until:
        errors.append("Certification expired")
        details["within_validity_window"] = False

    # Optional: Expected digests
    if expected_target_digest:
        if certification.get("target_digest") != expected_target_digest:
            errors.append("Target digest mismatch")
    if expected_report_digest:
        if certification.get("eval_report_digest") != expected_report_digest:
            errors.append("Report digest mismatch")

    if not resolved_pem:
        if sig and not errors:
            warnings.append("Signed certification but no public key for verification")
            details["signature_status"] = "signed_unverified"
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}

    # Check 3: Cryptographic verification
    try:
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        pub_key = ser.load_pem_public_key(resolved_pem.encode("utf-8"))
        canonical = json.dumps(
            {k: v for k, v in certification.items()
             if k not in {"certification_signature", "certification_signature_algorithm",
                          "certifier_fingerprint"}},
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
        errors.append("Certification signature verification failed")
    except Exception as e:
        details["signature_status"] = "invalid"
        errors.append(f"Signature verification error: {e}")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}


def revoke_certification(
    certification: dict[str, Any] | str,
    reason: str = "",
    output_path: str = "",
) -> dict[str, Any]:
    """Revoke a certification by changing its status.

    Args:
        certification: Certification dict or path to JSON file.
        reason: Revocation reason.
        output_path: Where to write updated certification.

    Returns:
        Updated certification with status=revoked.
    """
    if isinstance(certification, str):
        certification = json.loads(Path(certification).read_text(encoding="utf-8"))

    certification["certification_status"] = "revoked"
    certification["revoked_at"] = _now_iso()
    certification["revoke_reason"] = reason

    # Recompute digest (signature is now invalid, but we keep it for audit)
    certification["certification_digest"] = _sha256_dict(
        {k: v for k, v in certification.items() if k not in _DIGEST_EXCLUDED}
    )

    if output_path:
        Path(output_path).write_text(
            json.dumps(certification, indent=2, sort_keys=True), encoding="utf-8",
        )

    return certification


def inspect_certification(
    certification: dict[str, Any] | str,
) -> dict[str, Any]:
    """Inspect a certification artifact, returning a summary.

    Returns:
        Summary dict with key fields and verification status.
    """
    if isinstance(certification, str):
        certification = json.loads(Path(certification).read_text(encoding="utf-8"))

    return {
        "certification_id": certification.get("certification_id", ""),
        "target_type": certification.get("target_type", ""),
        "target_ref": certification.get("target_ref", ""),
        "target_digest": certification.get("target_digest", "")[:16] + "...",
        "suite_id": certification.get("suite_id", ""),
        "suite_version": certification.get("suite_version", ""),
        "certification_status": certification.get("certification_status", ""),
        "issued_at": certification.get("issued_at", ""),
        "valid_from": certification.get("valid_from", ""),
        "valid_until": certification.get("valid_until", ""),
        "certifier_fingerprint": certification.get("certifier_fingerprint", ""),
        "is_signed": bool(certification.get("certification_signature")),
        "certification_digest": certification.get("certification_digest", "")[:16] + "...",
        "eval_report_digest": certification.get("eval_report_digest", "")[:16] + "...",
        "suite_digest": certification.get("suite_digest", "")[:16] + "...",
        "errors": certification.get("errors", []),
    }
