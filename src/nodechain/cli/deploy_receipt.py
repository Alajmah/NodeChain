"""Deployment receipt (v1.9.0).

Records that a deployment gate evaluated a specific attestation under a
specific verifier profile and either accepted or rejected the deployment.

This closes the semantic gap:
  attestation says deployment is allowed
  → receipt says the gate actually evaluated and accepted it

Commands:
  nodechain deploy-receipt create --attestation a.json --profile p.json --output receipt.json
  nodechain deploy-receipt create ... --sign --key deploy-gate_private.pem
  nodechain deploy-receipt verify receipt.json --pubkey deploy-gate_public.pem

Exit codes:
  0  = valid receipt, deploy allowed
  10 = invalid receipt (validation failure)
  15 = strict deny (deploy_allowed=false under --strict)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

#: Schema version for the deployment receipt format.
DEPLOY_RECEIPT_SCHEMA_VERSION = "1"

#: Required fields in every receipt.
REQUIRED_RECEIPT_FIELDS = frozenset({
    "schema_version",
    "receipt_id",
    "type",
    "attestation_digest",
    "deploy_allowed",
    "verified_at",
})


def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file's content."""
    h = hashlib.sha256()
    h.update(Path(path).read_bytes())
    return h.hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    """Compute SHA-256 of canonical JSON of a dict."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def create_receipt(
    attestation_path: str,
    profile_path: str = "",
    output: str = "",
    sign_key: str = "",
    verifier_profile_path: str = "",
) -> dict[str, Any]:
    """Create a deployment receipt from an attestation.

    Runs full attestation verification (with profile if provided) and
    records the result as an immutable receipt.

    Args:
        attestation_path: Path to attestation JSON.
        profile_path: Path to verifier profile JSON (optional).
        output: Path to write receipt JSON.
        sign_key: Path to private key PEM for signing the receipt.
        verifier_profile_path: Alias for profile_path.

    Returns:
        Receipt dict.
    """
    from nodechain import __version__
    from nodechain.cli.attestation import verify_attestation

    # Use verifier_profile_path as alias
    effective_profile = profile_path or verifier_profile_path

    # Run verification
    verify_result = verify_attestation(
        attestation_path,
        profile_path=effective_profile,
    )

    # Load attestation for digest extraction
    attestation = json.loads(Path(attestation_path).read_text(encoding="utf-8"))

    # Compute attestation digest (SHA-256 of file content)
    attestation_digest = _sha256_file(attestation_path)

    # Get profile digest if profile provided
    profile_digest = ""
    profile_signer_fp = ""
    if effective_profile:
        from nodechain.cli.attestation import load_verifier_profile
        try:
            profile = load_verifier_profile(effective_profile)
            profile_digest = profile.get("profile_digest", "")
            profile_signer_fp = profile.get("profile_signer_fingerprint", "")
        except Exception:
            pass

    # Build receipt
    receipt: dict[str, Any] = {
        "schema_version": DEPLOY_RECEIPT_SCHEMA_VERSION,
        "type": "deployment_receipt",
        "receipt_id": str(uuid.uuid4()),
        "attestation_digest": attestation_digest,
        "attestation_run_id": attestation.get("run_id", ""),
        "verifier_profile_digest": profile_digest,
        "profile_signer_fingerprint": profile_signer_fp,
        "attestation_signer_fingerprint": attestation.get("signer_key_fingerprint", ""),
        "deploy_allowed": verify_result.get("deploy_allowed", False),
        "denial_reason": verify_result.get("denial_reason", ""),
        "target": attestation.get("deployment_target", ""),
        "artifact_digest": attestation.get("artifact_digest", ""),
        "lockfile_digest": attestation.get("lockfile_digest", ""),
        "policy_id": attestation.get("policy_id", ""),
        "policy_digest": attestation.get("policy_digest", ""),
        "verification_errors": verify_result.get("errors", []),
        "verification_warnings": verify_result.get("warnings", []),
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verifier_nodechain_version": __version__,
    }

    # Compute receipt digest (over receipt content, excluding signature fields)
    receipt["receipt_digest"] = _sha256_dict(
        {k: v for k, v in receipt.items()
         if k not in ("receipt_signature", "receipt_signature_algorithm",
                      "receipt_signer_fingerprint")}
    )

    # Sign receipt if requested
    if sign_key:
        receipt = _sign_receipt(receipt, sign_key)

    # Write output
    if output:
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

    return receipt


def _sign_receipt(receipt: dict[str, Any], private_key_path: str) -> dict[str, Any]:
    """Sign a deployment receipt with RSA-PSS-SHA256."""
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = _load_private_key(private_key_path)

    # Canonical signed data (everything except signature fields)
    signed_data = json.dumps(
        {k: v for k, v in receipt.items()
         if k not in ("receipt_signature", "receipt_signature_algorithm",
                      "receipt_signer_fingerprint")},
        sort_keys=True,
        separators=(",", ":"),
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

    enriched = dict(receipt)
    enriched["receipt_signature"] = base64.b64encode(signature).decode("ascii")
    enriched["receipt_signature_algorithm"] = "RSA-PSS-SHA256"
    enriched["receipt_signer_fingerprint"] = fingerprint

    return enriched


def verify_receipt(
    receipt_path: str,
    pubkey_path: str = "",
    strict: bool = False,
    expected_attestation_digest: str = "",
    expected_profile_digest: str = "",
    allowed_schema_versions: list[str] | None = None,
) -> dict[str, Any]:
    """Verify a deployment receipt.

    Args:
        receipt_path: Path to receipt JSON.
        pubkey_path: Path to public key PEM for signature verification.
        strict: If True, deploy_allowed=false is a hard error.
        expected_attestation_digest: Must match receipt's attestation_digest.
        expected_profile_digest: Must match receipt's verifier_profile_digest.
        allowed_schema_versions: If set, receipt schema_version must be in list.

    Returns:
        {valid: bool, errors: list, warnings: list, checks: dict}
    """
    result: dict[str, Any] = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "checks": {},
    }

    p = Path(receipt_path)
    if not p.exists():
        result["valid"] = False
        result["errors"].append(f"Receipt file not found: {receipt_path}")
        return result

    try:
        receipt = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        result["valid"] = False
        result["errors"].append(f"Cannot parse receipt JSON: {exc}")
        return result

    # Check type
    if receipt.get("type") != "deployment_receipt":
        result["warnings"].append(f"Unexpected type: {receipt.get('type', '')}")
    result["checks"]["type"] = receipt.get("type", "")

    # Check schema version
    sv = receipt.get("schema_version", "")
    result["checks"]["schema_version"] = sv
    if allowed_schema_versions and sv not in allowed_schema_versions:
        result["errors"].append(
            f"Receipt schema version {sv} not in allowed versions: {allowed_schema_versions}"
        )
        result["checks"]["schema_version_allowed"] = False
    else:
        result["checks"]["schema_version_allowed"] = True

    # Check required fields
    for field in REQUIRED_RECEIPT_FIELDS:
        if field not in receipt:
            result["errors"].append(f"Missing required field: {field}")

    # ── Attestation digest check ──
    result["checks"]["attestation_digest"] = receipt.get("attestation_digest", "")
    if expected_attestation_digest:
        if expected_attestation_digest != receipt.get("attestation_digest", ""):
            result["errors"].append(
                f"Attestation digest mismatch: expected {expected_attestation_digest[:16]}..., "
                f"receipt says {receipt.get('attestation_digest', '')[:16]}..."
            )
            result["checks"]["attestation_digest_match"] = False
        else:
            result["checks"]["attestation_digest_match"] = True

    # ── Profile digest check ──
    result["checks"]["verifier_profile_digest"] = receipt.get("verifier_profile_digest", "")
    if expected_profile_digest:
        if expected_profile_digest != receipt.get("verifier_profile_digest", ""):
            result["errors"].append(
                f"Profile digest mismatch: expected {expected_profile_digest[:16]}..., "
                f"receipt says {receipt.get('verifier_profile_digest', '')[:16]}..."
            )
            result["checks"]["profile_digest_match"] = False
        else:
            result["checks"]["profile_digest_match"] = True

    # ── Deploy/deny decision ──
    deploy_allowed = receipt.get("deploy_allowed", False)
    denial_reason = receipt.get("denial_reason", "")
    result["checks"]["deploy_allowed"] = deploy_allowed
    result["checks"]["denial_reason"] = denial_reason

    if strict and not deploy_allowed:
        result["errors"].append(
            f"Deployment denied in strict mode: {denial_reason}"
        )

    # ── Signature verification ──
    has_sig = bool(receipt.get("receipt_signature"))
    sig_status = "missing"

    if pubkey_path and has_sig:
        import base64
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization

        signature = base64.b64decode(receipt["receipt_signature"])
        algorithm = receipt.get("receipt_signature_algorithm", "")
        if algorithm != "RSA-PSS-SHA256":
            sig_status = "invalid"
            result["errors"].append(f"Unsupported signature algorithm: {algorithm}")
        else:
            try:
                pubkey_data = Path(pubkey_path).read_bytes()
                public_key = serialization.load_pem_public_key(pubkey_data)

                signed_data = json.dumps(
                    {k: v for k, v in receipt.items()
                     if k not in ("receipt_signature", "receipt_signature_algorithm",
                                  "receipt_signer_fingerprint")},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")

                public_key.verify(
                    signature,
                    signed_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hashes.SHA256(),
                )
                sig_status = "valid"
            except Exception as exc:
                sig_status = "invalid"
                result["errors"].append(f"Receipt signature verification failed: {exc}")
    elif has_sig:
        sig_status = "signed_not_verified"
        result["warnings"].append("Receipt is signed but no --pubkey provided")
    elif pubkey_path:
        sig_status = "missing"
        result["warnings"].append("--pubkey provided but receipt is not signed")

    result["checks"]["signature_status"] = sig_status

    # ── Receipt digest verification ──
    stored_digest = receipt.get("receipt_digest", "")
    if stored_digest:
        computed_digest = _sha256_dict(
            {k: v for k, v in receipt.items()
             if k not in ("receipt_signature", "receipt_signature_algorithm",
                          "receipt_signer_fingerprint", "receipt_digest")}
        )
        if stored_digest != computed_digest:
            result["errors"].append("Receipt digest mismatch — content may have been tampered")
            result["checks"]["receipt_digest_valid"] = False
        else:
            result["checks"]["receipt_digest_valid"] = True
    result["checks"]["receipt_digest"] = stored_digest

    # Final validity
    if result["errors"]:
        result["valid"] = False

    return result
