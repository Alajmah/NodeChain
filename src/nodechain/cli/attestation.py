"""Deployment attestation (v1.8.0).

Binds a signed audit bundle to a specific deployment artifact, environment,
policy preset, and runtime decision.

Commands:
  nodechain attest <run_id> --bundle audit.zip --output attestation.json
  nodechain attest ... --sign --key private.pem
  nodechain attest --verify attestation.json --pubkey public.pem
  nodechain attest --verify attestation.json --require-signature --strict
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform as platform_module
import subprocess
import sys
from pathlib import Path
from typing import Any

#: Schema version for the attestation format.
ATTESTATION_SCHEMA_VERSION = "1"

#: Required fields in every attestation.
REQUIRED_ATTESTATION_FIELDS = frozenset({
    "schema_version",
    "type",
    "run_id",
    "generated_at",
    "audit_bundle_sha256",
    "bundle_signature_status",
    "active_preset",
    "trust_verdict",
    "platform",
})


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _get_platform_summary() -> dict[str, str]:
    """Get deployment platform summary."""
    info = {
        "platform": platform_module.system(),
        "platform_release": platform_module.release(),
        "python_version": sys.version.split()[0],
        "machine": platform_module.machine(),
    }

    # Container detection
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
        if "docker" in cgroup or "lxc" in cgroup or "containerd" in cgroup:
            info["container_detected"] = "yes"
            if "lxc" in cgroup:
                info["container_type"] = "lxc"
            elif "docker" in cgroup:
                info["container_type"] = "docker"
        else:
            info["container_detected"] = "no"
    except Exception:
        info["container_detected"] = "unknown"

    return info


def _get_git_info() -> dict[str, str]:
    """Get git commit/tag info."""
    info = {"git_commit": "", "git_tag": "", "git_branch": ""}
    for key, cmd in [
        ("git_commit", ["git", "rev-parse", "--short", "HEAD"]),
        ("git_tag", ["git", "describe", "--tags", "--abbrev=0"]),
        ("git_branch", ["git", "rev-parse", "--abbrev-ref", "HEAD"]),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                info[key] = result.stdout.strip()
        except Exception:
            pass
    return info


def _read_bundle_info(bundle_path: str) -> dict[str, Any]:
    """Extract key information from an audit bundle ZIP.

    Returns:
        {audit_bundle_sha256, bundle_signature_status, signer_key_fingerprint,
         run_id, preset, trust_verdict, lockfile_digest, manifest}
    """
    import zipfile

    p = Path(bundle_path)
    if not p.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_path}")

    bundle_bytes = p.read_bytes()
    bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()

    info: dict[str, Any] = {
        "audit_bundle_sha256": bundle_sha256,
        "bundle_path": str(p),
        "bundle_size": len(bundle_bytes),
        "bundle_signature_status": "unknown",
        "signer_key_fingerprint": "",
    }

    with zipfile.ZipFile(p, "r") as zf:
        # Read bundle_meta
        try:
            meta_raw = zf.read("bundle_meta.json")
            meta = json.loads(meta_raw)

            has_sig = bool(meta.get("signature", ""))
            if has_sig:
                info["bundle_signature_status"] = "signed"
                info["signer_key_fingerprint"] = meta.get("signer_key_fingerprint", "")
            else:
                info["bundle_signature_status"] = "unsigned"

            info["run_id"] = meta.get("run_id", "")
            info["generated_at"] = meta.get("generated_at", "")
            info["nodechain_version"] = meta.get("nodechain_version", "")
        except Exception:
            pass

        # Read preset
        try:
            preset_data = json.loads(zf.read("preset.json"))
            info["active_preset"] = preset_data.get("preset", "none")
        except Exception:
            info["active_preset"] = os.environ.get("NODECHAIN_POLICY_PRESET", "none")

        # Read invariants for trust verdict
        try:
            inv_data = json.loads(zf.read("invariants.json"))
            errors = inv_data.get("errors", 0)
            total = inv_data.get("total", 0)
            if errors == 0 and total == 0:
                info["trust_verdict"] = "compliant"
            elif errors == 0:
                info["trust_verdict"] = "compliant_with_warnings"
            else:
                info["trust_verdict"] = "non_compliant"
            info["invariant_errors"] = errors
            info["invariant_total"] = total
        except Exception:
            info["trust_verdict"] = "unknown"

        # Read lockfile digest
        try:
            lockfile_data = json.loads(zf.read("lockfile.json"))
            info["lockfile_valid"] = lockfile_data.get("valid", False)
            info["lockfile_locked_count"] = lockfile_data.get("locked_count", 0)
        except Exception:
            info["lockfile_valid"] = False

        # Read enforcement layers
        try:
            layers_data = json.loads(zf.read("enforcement_layers.json"))
            info["enforced_layers"] = len(layers_data.get("enforced", []))
            info["unavailable_layers"] = len(layers_data.get("unavailable", []))
            info["required_layers"] = len(layers_data.get("required", []))
        except Exception:
            pass

    return info


def _compute_lockfile_digest() -> str:
    """Compute SHA-256 of the registry lockfile if present."""
    lockfile = Path("registry.lock.json")
    if not lockfile.exists():
        return ""
    return hashlib.sha256(lockfile.read_bytes()).hexdigest()


def generate_attestation(
    run_id: str,
    bundle_path: str,
    output_path: str = "",
    deployment_target: str = "",
    artifact_digest: str = "",
    sign_key: str = "",
    policy_id: str = "",
    policy_version: str = "",
) -> int:
    """Generate a deployment attestation.

    Returns exit code: 0 = ok, 2 = not found.
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_NOT_FOUND

    # Read bundle info
    try:
        bundle_info = _read_bundle_info(bundle_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return EXIT_NOT_FOUND

    # Gather additional info
    platform_info = _get_platform_summary()
    git_info = _get_git_info()
    lockfile_digest = _compute_lockfile_digest()

    # Build attestation
    # Compute policy digest if policy_id provided
    policy_digest = ""
    if policy_id:
        policy_data = f"{policy_id}:{policy_version or '1'}".encode("utf-8")
        policy_digest = hashlib.sha256(policy_data).hexdigest()

    # Determine deploy_allowed
    trust_verdict = bundle_info.get("trust_verdict", "unknown")
    deploy_allowed = trust_verdict in ("compliant", "compliant_with_warnings")
    denial_reason = "" if deploy_allowed else f"trust_verdict={trust_verdict}"

    attestation: dict[str, Any] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "type": "deployment_attestation",
        "run_id": run_id,
        "generated_at": _utc_now(),
        "audit_bundle_sha256": bundle_info["audit_bundle_sha256"],
        "audit_bundle_path": bundle_info.get("bundle_path", ""),
        "bundle_signature_status": bundle_info["bundle_signature_status"],
        "signer_key_fingerprint": bundle_info["signer_key_fingerprint"],
        "active_preset": bundle_info.get("active_preset", "none"),
        "trust_verdict": trust_verdict,
        "deploy_allowed": deploy_allowed,
        "denial_reason": denial_reason,
        "invariant_errors": bundle_info.get("invariant_errors", 0),
        "invariant_total": bundle_info.get("invariant_total", 0),
        "deployment_target": deployment_target,
        "artifact_digest": artifact_digest,
        "lockfile_digest": lockfile_digest,
        "lockfile_valid": bundle_info.get("lockfile_valid", False),
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "enforced_layers": bundle_info.get("enforced_layers", 0),
        "unavailable_layers": bundle_info.get("unavailable_layers", 0),
        "required_layers": bundle_info.get("required_layers", 0),
        "nodechain_version": bundle_info.get("nodechain_version", ""),
        "git": git_info,
        "platform": platform_info,
    }

    # Sign if requested
    signature_status = "unsigned"
    signer_fingerprint = ""
    if sign_key:
        try:
            from nodechain.cli.bundle_signing import sign_bundle_meta
            # Sign the core attestation fields
            signed = sign_bundle_meta(attestation, sign_key)
            attestation.update(signed)
            signature_status = "signed"
            signer_fingerprint = attestation.get("signer_key_fingerprint", "")
        except Exception as e:
            print(f"WARNING: Signing failed: {e}")
            signature_status = "signing_failed"

    # Determine output path
    if not output_path:
        output_path = f"attestation_{run_id}.json"
    output = Path(output_path)

    # Write attestation
    output.write_text(json.dumps(attestation, indent=2, default=str), encoding="utf-8")

    # Compute attestation digest
    attestation_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()

    print(f"Attestation written to: {output}")
    print(f"  Attestation SHA-256: {attestation_sha256}")
    print(f"  Audit bundle SHA-256: {bundle_info['audit_bundle_sha256'][:16]}...")
    print(f"  Trust verdict: {trust_verdict}")
    print(f"  Deploy allowed: {deploy_allowed}")
    if not deploy_allowed:
        print(f"  Denial reason: {denial_reason}")
    print(f"  Bundle signature: {bundle_info['bundle_signature_status']}")
    print(f"  Attestation signature: {signature_status}")
    if signer_fingerprint:
        print(f"  Signer fingerprint: {signer_fingerprint}")

    return EXIT_OK


#: Schema version for verifier profiles.
VERIFIER_PROFILE_SCHEMA_VERSION = "1"


def load_verifier_profile(profile_path: str) -> dict[str, Any]:
    """Load and validate a verifier profile JSON file.

    Returns:
        Parsed profile dict with profile_digest added.
    """
    p = Path(profile_path)
    if not p.exists():
        raise FileNotFoundError(f"Verifier profile not found: {profile_path}")

    profile = json.loads(p.read_text(encoding="utf-8"))

    # Compute profile digest
    profile_bytes = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
    profile["profile_digest"] = hashlib.sha256(profile_bytes).hexdigest()

    return profile


def verify_attestation(
    attestation_path: str,
    pubkey_path: str = "",
    require_signature: bool = False,
    strict: bool = False,
    expected_bundle_path: str = "",
    expected_artifact_digest: str = "",
    expected_lockfile_digest: str = "",
    expected_policy_digest: str = "",
    expected_target: str = "",
    profile_path: str = "",
    require_profile_signature: bool = False,
) -> dict[str, Any]:
    """Verify a deployment attestation.

    Returns:
        {valid: bool, errors: [...], warnings: [...], checks: {...},
         deploy_allowed: bool, denial_reason: str}
    """
    result: dict[str, Any] = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "checks": {},
    }

    p = Path(attestation_path)
    if not p.exists():
        result["valid"] = False
        result["errors"].append(f"Attestation file not found: {attestation_path}")
        return result

    try:
        attestation = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        result["valid"] = False
        result["errors"].append(f"Cannot parse attestation JSON: {exc}")
        return result

    # Check schema version
    sv = attestation.get("schema_version", "")
    if not sv:
        result["warnings"].append("Attestation missing schema_version")
    result["checks"]["schema_version"] = sv

    # Check type
    att_type = attestation.get("type", "")
    if att_type != "deployment_attestation":
        result["warnings"].append(f"Unexpected type: {att_type}")
    result["checks"]["type"] = att_type

    # ── v1.8.2: Load verifier profile if provided ──
    trusted_fingerprints: list[str] = []
    allowed_schemas: list[str] = []
    if profile_path:
        try:
            profile = load_verifier_profile(profile_path)
        except Exception as exc:
            result["valid"] = False
            result["errors"].append(f"Cannot load verifier profile: {exc}")
            return result

        result["checks"]["profile_digest"] = profile.get("profile_digest", "")
        result["checks"]["profile_schema_version"] = profile.get("schema_version", "")

        # ── v1.8.3: Profile signature verification against trust store ──
        profile_has_sig = bool(profile.get("profile_signature"))
        profile_sig_status = "missing"
        profile_signer_fp = profile.get("profile_signer_fingerprint", "")

        if require_profile_signature and not profile_has_sig:
            profile_sig_status = "missing"
            result["errors"].append(
                "--require-profile-signature: verifier profile is not signed"
            )
        elif profile_has_sig:
            # Look up signer in trust store
            from nodechain.cli.trust_store import lookup_by_fingerprint, is_trusted_fingerprint

            if is_trusted_fingerprint(profile_signer_fp):
                # Get the trusted public key PEM
                trusted_pem = lookup_by_fingerprint(profile_signer_fp)
                from nodechain.cli.trust_store import verify_profile_signature
                sig_result = verify_profile_signature(profile, trusted_pem)
                if sig_result["valid"]:
                    profile_sig_status = "valid"
                    result["checks"]["profile_signer_trusted"] = True
                else:
                    profile_sig_status = "invalid"
                    result["errors"].append(
                        f"Profile signature verification failed: {sig_result['reason']}"
                    )
                    result["checks"]["profile_signer_trusted"] = True  # trusted but bad sig
            else:
                profile_sig_status = "untrusted_signer"
                result["errors"].append(
                    f"Profile signer fingerprint {profile_signer_fp} not in trust store"
                )
                result["checks"]["profile_signer_trusted"] = False

        result["checks"]["profile_signature_status"] = profile_sig_status
        result["checks"]["profile_signer_fingerprint"] = profile_signer_fp

        # Profile fields override CLI flags if not already set
        if profile.get("require_signature") and not require_signature:
            require_signature = True
        if profile.get("strict_mode") and not strict:
            strict = True
        if profile.get("expected_policy_digest") and not expected_policy_digest:
            expected_policy_digest = profile["expected_policy_digest"]
        if profile.get("expected_target") and not expected_target:
            expected_target = profile["expected_target"]
        if profile.get("expected_artifact_digest") and not expected_artifact_digest:
            expected_artifact_digest = profile["expected_artifact_digest"]
        if profile.get("expected_lockfile_digest") and not expected_lockfile_digest:
            expected_lockfile_digest = profile["expected_lockfile_digest"]

        trusted_fingerprints = profile.get("trusted_signer_fingerprints", [])
        allowed_schemas = profile.get("allowed_attestation_schema_versions", [])

        # Check attestation schema against allowed versions
        if allowed_schemas and sv not in allowed_schemas:
            result["errors"].append(
                f"Attestation schema version {sv} not in allowed versions: {allowed_schemas}"
            )
            result["checks"]["schema_version_allowed"] = False
        else:
            result["checks"]["schema_version_allowed"] = True

    # Check required fields
    for field in REQUIRED_ATTESTATION_FIELDS:
        if field not in attestation:
            result["errors"].append(f"Missing required field: {field}")

    # ── Check 1: Audit bundle hash matches ──
    if expected_bundle_path:
        bundle_sha = hashlib.sha256(Path(expected_bundle_path).read_bytes()).hexdigest()
        att_bundle_sha = attestation.get("audit_bundle_sha256", "")
        if bundle_sha != att_bundle_sha:
            result["errors"].append(
                f"Audit bundle hash mismatch: expected {bundle_sha[:16]}..., "
                f"attestation says {att_bundle_sha[:16]}..."
            )
        result["checks"]["bundle_hash_match"] = (bundle_sha == att_bundle_sha)

    # ── Check 2: Artifact digest matches ──
    if expected_artifact_digest:
        att_artifact = attestation.get("artifact_digest", "")
        if expected_artifact_digest != att_artifact:
            result["errors"].append(
                f"Artifact digest mismatch: expected {expected_artifact_digest}, "
                f"attestation says {att_artifact}"
            )
        result["checks"]["artifact_digest_match"] = (expected_artifact_digest == att_artifact)

    # ── Check 2b: Lockfile digest matches (v1.8.1) ──
    if expected_lockfile_digest:
        att_lockfile = attestation.get("lockfile_digest", "")
        if expected_lockfile_digest != att_lockfile:
            result["errors"].append(
                f"Lockfile digest mismatch: expected {expected_lockfile_digest[:16]}..., "
                f"attestation says {att_lockfile[:16] if att_lockfile else '(empty)'}..."
            )
        result["checks"]["lockfile_digest_match"] = (expected_lockfile_digest == att_lockfile)

    # ── Check 2c: Policy digest matches (v1.8.1) ──
    if expected_policy_digest:
        att_policy = attestation.get("policy_digest", "")
        if not att_policy:
            result["errors"].append(
                "Expected policy digest but attestation has no policy binding"
            )
        elif expected_policy_digest != att_policy:
            result["errors"].append(
                f"Policy digest mismatch: expected {expected_policy_digest[:16]}..., "
                f"attestation says {att_policy[:16]}..."
            )
        result["checks"]["policy_digest_match"] = (expected_policy_digest == att_policy)

    # ── Check 2d: Deployment target matches (v1.8.1) ──
    if expected_target:
        att_target = attestation.get("deployment_target", "")
        if expected_target != att_target:
            result["errors"].append(
                f"Deployment target mismatch: expected {expected_target}, "
                f"attestation says {att_target}"
            )
        result["checks"]["target_match"] = (expected_target == att_target)

    # ── Check 2e: Policy present under strict mode (v1.8.1) ──
    if strict:
        policy_id = attestation.get("policy_id", "")
        if not policy_id:
            result["errors"].append(
                "Strict mode requires policy binding but attestation has no policy_id"
            )
        result["checks"]["policy_bound"] = bool(policy_id)

    # ── Check 3: Trust verdict compliance ──
    trust_verdict = attestation.get("trust_verdict", "unknown")
    result["checks"]["trust_verdict"] = trust_verdict
    if strict and trust_verdict == "non_compliant":
        result["errors"].append(
            "Trust verdict is non-compliant (strict mode requires compliant)"
        )

    # ── Check 4: Signature verification ──
    has_sig = bool(attestation.get("signature", ""))
    sig_status = "unsigned"

    if pubkey_path:
        if not has_sig:
            sig_status = "missing"
            if require_signature:
                result["errors"].append(
                    "--require-signature: attestation is not signed"
                )
            else:
                result["warnings"].append(
                    "Attestation is not signed but --pubkey was provided"
                )
        else:
            try:
                from nodechain.cli.bundle_signing import verify_bundle_signature
                sig_result = verify_bundle_signature(attestation, pubkey_path)
                sig_status = "valid" if sig_result["valid"] else "invalid"
                if not sig_result["valid"]:
                    result["errors"].append(
                        f"Signature verification failed: {sig_result['reason']}"
                    )
            except Exception as exc:
                sig_status = "error"
                result["errors"].append(f"Signature verification error: {exc}")
    elif has_sig:
        sig_status = "signed_not_verified"
        result["warnings"].append(
            "Attestation is signed but no --pubkey provided"
        )
        if require_signature:
            result["errors"].append(
                "--require-signature requires --pubkey for verification"
            )
    elif require_signature:
        sig_status = "missing"
        result["errors"].append(
            "--require-signature: attestation is not signed"
        )

    result["checks"]["signature_status"] = sig_status

    # ── v1.8.2: Trusted signer fingerprint check ──
    if trusted_fingerprints:
        att_fingerprint = attestation.get("signer_key_fingerprint", "")
        if att_fingerprint and att_fingerprint not in trusted_fingerprints:
            result["errors"].append(
                f"Signer fingerprint {att_fingerprint} not in trusted list"
            )
            result["checks"]["signer_trusted"] = False
        elif att_fingerprint:
            result["checks"]["signer_trusted"] = True
        else:
            result["checks"]["signer_trusted"] = False

    # ── Deploy/deny decision (v1.8.1) ──
    deploy_allowed = attestation.get("deploy_allowed", False)
    denial_reason = attestation.get("denial_reason", "")
    if not deploy_allowed and not denial_reason:
        denial_reason = "deploy_allowed is false"
    result["deploy_allowed"] = deploy_allowed
    result["denial_reason"] = denial_reason

    # Under strict mode, deploy_allowed=false is a denial
    if strict and not deploy_allowed:
        result["errors"].append(
            f"Deployment denied: {denial_reason}"
        )

    if result["errors"]:
        result["valid"] = False

    return result
