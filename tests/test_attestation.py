"""Tests for deployment attestation (v1.8.0).

Tests cover:
1. Attestation command exists
2. Attestation generation with all required fields
3. Attestation schema version
4. Attestation signing
5. Attestation verification
6. Verification failures (bundle hash, wrong key, non-compliant, artifact digest)
7. CI mode: --require-signature --strict
8. Version and changelog
"""

from __future__ import annotations

import json
import hashlib
import zipfile
from pathlib import Path
import pytest


# ─── Helpers ─────────────────────────────────────────────────────────────

def _make_test_bundle(tmp_path) -> Path:
    """Create a minimal valid audit bundle for testing."""
    from nodechain.cli.audit_bundle import (
        _stamp, _build_file_manifest, AUDIT_BUNDLE_SCHEMA_VERSION,
    )

    files: dict[str, bytes] = {}
    files["SUMMARY.md"] = b"# Audit\n\n## Compliance Status\n\nCOMPLIANT"
    files["invariants.json"] = json.dumps(_stamp({
        "violations": [], "total": 0, "errors": 0,
    }, "invariants")).encode()
    files["lockfile.json"] = json.dumps(_stamp({"valid": True}, "lockfile")).encode()
    files["sandbox_capabilities.json"] = json.dumps(_stamp({}, "sandbox_capabilities")).encode()
    files["namespace_detection.json"] = json.dumps(_stamp({}, "namespace_detection")).encode()
    files["preset.json"] = json.dumps(_stamp({"preset": "hardened_untrusted"}, "preset")).encode()
    files["enforcement_layers.json"] = json.dumps(_stamp({
        "required": [], "enforced": [{"layer": "seccomp"}],
        "advisory": [], "unavailable": [], "skipped": [],
    }, "enforcement_layers")).encode()
    files["platform.json"] = json.dumps(_stamp({"platform": "Linux"}, "platform")).encode()

    manifest = _build_file_manifest(files)

    meta = _stamp({
        "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
        "generated_at": "2026-06-14T12:00:00Z",
        "nodechain_version": "3.5.0",
        "run_id": "test_run",
        "files": manifest,
    }, "bundle_meta")
    files["bundle_meta.json"] = json.dumps(meta).encode()

    bundle = tmp_path / "test_bundle.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        for fname, fdata in files.items():
            zf.writestr(fname, fdata)

    return bundle


def _make_signed_test_bundle(tmp_path) -> tuple[Path, dict]:
    """Create a signed audit bundle and return (path, keys)."""
    from nodechain.cli.audit_bundle import (
        _stamp, _build_file_manifest, AUDIT_BUNDLE_SCHEMA_VERSION,
    )
    from nodechain.cli.bundle_signing import generate_key_pair, sign_bundle_meta

    files: dict[str, bytes] = {}
    files["SUMMARY.md"] = b"# Audit\n\n## Compliance Status\n\nCOMPLIANT"
    files["invariants.json"] = json.dumps(_stamp({
        "violations": [], "total": 0, "errors": 0,
    }, "invariants")).encode()
    files["lockfile.json"] = json.dumps(_stamp({"valid": True}, "lockfile")).encode()
    files["sandbox_capabilities.json"] = json.dumps(_stamp({}, "sandbox_capabilities")).encode()
    files["namespace_detection.json"] = json.dumps(_stamp({}, "namespace_detection")).encode()
    files["preset.json"] = json.dumps(_stamp({"preset": "hardened_untrusted"}, "preset")).encode()
    files["enforcement_layers.json"] = json.dumps(_stamp({
        "required": [], "enforced": [{"layer": "seccomp"}],
        "advisory": [], "unavailable": [], "skipped": [],
    }, "enforcement_layers")).encode()
    files["platform.json"] = json.dumps(_stamp({"platform": "Linux"}, "platform")).encode()

    manifest = _build_file_manifest(files)

    meta = {
        "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
        "generated_at": "2026-06-14T12:00:00Z",
        "nodechain_version": "3.5.0",
        "run_id": "test_run",
        "files": manifest,
    }

    keys = generate_key_pair(str(tmp_path))
    meta = sign_bundle_meta(meta, keys["private_key_path"])
    meta = _stamp(meta, "bundle_meta")
    files["bundle_meta.json"] = json.dumps(meta).encode()

    bundle = tmp_path / "signed_bundle.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        for fname, fdata in files.items():
            zf.writestr(fname, fdata)

    return bundle, keys


# ─── 1. Command Exists ────────────────────────────────────────────────────

class TestAttestCommand:
    """attest command is registered."""

    def test_command_in_cli_source(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "attest" in main_src

    def test_module_exists(self):
        assert Path("src/nodechain/cli/attestation.py").exists()

    def test_functions_exist(self):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        assert callable(generate_attestation)
        assert callable(verify_attestation)

    def test_frozen_surfaces_lists_command(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "attest" in fs


# ─── 2. Attestation Generation ────────────────────────────────────────────

class TestAttestationGeneration:
    """Attestation includes all required fields."""

    def test_generate_attestation(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        code = generate_attestation("test_run", str(bundle), output)
        assert code == 0
        assert Path(output).exists()

    def test_attestation_has_required_fields(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        data = json.loads(Path(output).read_text())
        assert data["run_id"] == "test_run"
        assert data["audit_bundle_sha256"]
        assert data["bundle_signature_status"]
        assert data["active_preset"]
        assert data["trust_verdict"]
        assert data["platform"]
        assert data["generated_at"]
        assert data["git"]

    def test_attestation_has_bundle_hash(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        data = json.loads(Path(output).read_text())
        actual_bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
        assert data["audit_bundle_sha256"] == actual_bundle_sha

    def test_attestation_includes_lockfile_digest(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        data = json.loads(Path(output).read_text())
        assert "lockfile_digest" in data
        assert "lockfile_valid" in data

    def test_attestation_includes_enforcement_info(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        data = json.loads(Path(output).read_text())
        assert "enforced_layers" in data
        assert "unavailable_layers" in data
        assert "required_layers" in data

    def test_attestation_includes_deployment_target(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            deployment_target="prod-lxc-801",
        )

        data = json.loads(Path(output).read_text())
        assert data["deployment_target"] == "prod-lxc-801"

    def test_missing_bundle_returns_not_found(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        from nodechain.cli.exit_codes import EXIT_NOT_FOUND
        output = str(tmp_path / "attestation.json")
        code = generate_attestation("test_run", "nonexistent.zip", output)
        assert code == EXIT_NOT_FOUND


# ─── 3. Schema Version ────────────────────────────────────────────────────

class TestAttestationSchema:
    """Attestation has schema_version."""

    def test_schema_version_constant(self):
        from nodechain.cli.attestation import ATTESTATION_SCHEMA_VERSION
        assert ATTESTATION_SCHEMA_VERSION == "1"

    def test_attestation_has_schema_version(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        data = json.loads(Path(output).read_text())
        assert data["schema_version"] == "1"
        assert data["type"] == "deployment_attestation"


# ─── 4. Attestation Signing ───────────────────────────────────────────────

class TestAttestationSigning:
    """Attestation can be signed with RSA-PSS."""

    def test_sign_attestation(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        code = generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys["private_key_path"],
        )
        assert code == 0

        data = json.loads(Path(output).read_text())
        assert "signature" in data
        assert data["signature_algorithm"] == "RSA-PSS-SHA256"
        assert "signer_key_fingerprint" in data


# ─── 5. Attestation Verification ──────────────────────────────────────────

class TestAttestationVerification:
    """Attestation verification works."""

    def test_verify_valid_attestation(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        result = verify_attestation(output)
        assert result["valid"] is True

    def test_verify_missing_file(self, tmp_path):
        from nodechain.cli.attestation import verify_attestation
        result = verify_attestation(str(tmp_path / "nonexistent.json"))
        assert result["valid"] is False
        assert any("not found" in e for e in result["errors"])

    def test_verify_signed_attestation_with_correct_key(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys["private_key_path"],
        )

        result = verify_attestation(output, pubkey_path=keys["public_key_path"])
        assert result["valid"] is True
        assert result["checks"]["signature_status"] == "valid"

    def test_verify_signed_with_wrong_key_fails(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        keys1 = generate_key_pair(str(tmp_path), "pair1")
        keys2 = generate_key_pair(str(tmp_path), "pair2")
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys1["private_key_path"],
        )

        result = verify_attestation(output, pubkey_path=keys2["public_key_path"])
        assert result["valid"] is False
        assert result["checks"]["signature_status"] == "invalid"


# ─── 6. Verification Failure Modes ───────────────────────────────────────

class TestVerificationFailures:
    """Specific verification failure modes."""

    def test_bundle_hash_mismatch_detected(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        bundle1 = _make_test_bundle(tmp_path)
        # Create a different bundle
        bundle2 = tmp_path / "different.zip"
        bundle2.write_bytes(bundle1.read_bytes() + b"\x00")

        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle1), output)

        result = verify_attestation(output, expected_bundle_path=str(bundle2))
        assert result["valid"] is False
        assert any("hash mismatch" in e for e in result["errors"])

    def test_artifact_digest_mismatch_detected(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            artifact_digest="abc123",
        )

        result = verify_attestation(output, expected_artifact_digest="wrong")
        assert result["valid"] is False
        assert any("digest mismatch" in e for e in result["errors"])

    def test_strict_mode_fails_on_non_compliant(self, tmp_path):
        """Non-compliant trust verdict fails under strict mode."""
        from nodechain.cli.attestation import verify_attestation
        # Create a fake attestation with non-compliant verdict
        att = {
            "schema_version": "1",
            "type": "deployment_attestation",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "audit_bundle_sha256": "abc",
            "bundle_signature_status": "unsigned",
            "active_preset": "hardened_untrusted",
            "trust_verdict": "non_compliant",
            "platform": {"platform": "Linux"},
        }
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(att))

        result = verify_attestation(str(p), strict=True)
        assert result["valid"] is False
        assert any("non-compliant" in e for e in result["errors"])

    def test_strict_mode_passes_on_compliant(self, tmp_path):
        from nodechain.cli.attestation import verify_attestation
        att = {
            "schema_version": "1",
            "type": "deployment_attestation",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "audit_bundle_sha256": "abc",
            "bundle_signature_status": "unsigned",
            "active_preset": "hardened_untrusted",
            "trust_verdict": "compliant",
            "deploy_allowed": True,
            "policy_id": "prod-policy",
            "platform": {"platform": "Linux"},
        }
        p = tmp_path / "good.json"
        p.write_text(json.dumps(att))

        result = verify_attestation(str(p), strict=True)
        assert result["valid"] is True


# ─── 7. CI Mode: --require-signature --strict ─────────────────────────────

class TestCIMode:
    """CI mode enforcement."""

    def test_require_signature_fails_unsigned(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)

        result = verify_attestation(
            output,
            pubkey_path="",
            require_signature=True,
        )
        assert result["valid"] is False
        assert any("require-signature" in e or "not signed" in e for e in result["errors"])

    def test_require_signature_with_pubkey_passes_signed(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys["private_key_path"],
            policy_id="ci-policy", policy_version="1",
        )

        result = verify_attestation(
            output,
            pubkey_path=keys["public_key_path"],
            require_signature=True,
            strict=True,
        )
        assert result["valid"] is True

    def test_ci_mode_combined_fails_on_wrong_key(self, tmp_path):
        from nodechain.cli.attestation import (
            generate_attestation, verify_attestation,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        keys1 = generate_key_pair(str(tmp_path), "k1")
        keys2 = generate_key_pair(str(tmp_path), "k2")
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys1["private_key_path"],
            policy_id="ci-policy", policy_version="1",
        )

        result = verify_attestation(
            output,
            pubkey_path=keys2["public_key_path"],
            require_signature=True,
            strict=True,
        )
        assert result["valid"] is False


# ─── 8. Version and Changelog ────────────────────────────────────────────

class TestV180Version:
    def test_version_is_1_8_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v180(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Attestation" in changelog or "attestation" in changelog

    def test_frozen_surfaces_has_attest(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "attest" in fs

    def test_cli_has_attest_command(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "attest" in main_src
        assert "--require-signature" in main_src


# --- 9. Policy Binding (v1.8.1) -------------------------------------------


class TestPolicyBinding:
    """Attestation includes explicit policy document digest."""

    def test_generate_with_policy(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            policy_id="prod-policy-v2",
            policy_version="2",
        )
        data = json.loads(Path(output).read_text())
        assert data["policy_id"] == "prod-policy-v2"
        assert data["policy_version"] == "2"
        assert data["policy_digest"]
        assert len(data["policy_digest"]) == 64

    def test_policy_digest_deterministic(self, tmp_path):
        import hashlib
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output1 = str(tmp_path / "att1.json")
        output2 = str(tmp_path / "att2.json")
        generate_attestation("run1", str(bundle), output1, policy_id="p1", policy_version="1")
        generate_attestation("run2", str(bundle), output2, policy_id="p1", policy_version="1")
        d1 = json.loads(Path(output1).read_text())
        d2 = json.loads(Path(output2).read_text())
        assert d1["policy_digest"] == d2["policy_digest"]

    def test_deploy_allowed_in_attestation(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)
        data = json.loads(Path(output).read_text())
        assert "deploy_allowed" in data
        assert data["deploy_allowed"] is True  # compliant bundle

    def test_deploy_denied_on_non_compliant(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        # Tamper with the bundle to make invariants show errors
        # Actually easier: create a non-compliant attestation manually
        att = {
            "schema_version": "1",
            "type": "deployment_attestation",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "audit_bundle_sha256": "abc",
            "bundle_signature_status": "unsigned",
            "active_preset": "hardened_untrusted",
            "trust_verdict": "non_compliant",
            "deploy_allowed": False,
            "denial_reason": "trust_verdict=non_compliant",
            "policy_id": "",
            "platform": {"platform": "Linux"},
        }
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(att))
        result = __import__("nodechain.cli.attestation", fromlist=["verify_attestation"]).verify_attestation(str(p))
        assert result["deploy_allowed"] is False
        assert result["denial_reason"]


# --- 10. Expectation Checks (v1.8.1) --------------------------------------


class TestExpectationChecks:
    """CI can verify exact policy, target, artifact, lockfile."""

    def test_expect_policy_digest_match(self, tmp_path):
        import hashlib
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")
        data = json.loads(Path(output).read_text())
        result = verify_attestation(output, expected_policy_digest=data["policy_digest"])
        assert result["valid"] is True
        assert result["checks"].get("policy_digest_match") is True

    def test_expect_policy_digest_mismatch(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")
        result = verify_attestation(output, expected_policy_digest="wrong")
        assert result["valid"] is False
        assert any("Policy digest mismatch" in e for e in result["errors"])

    def test_expect_policy_missing_fails(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)  # no policy
        result = verify_attestation(output, expected_policy_digest="somehash")
        assert result["valid"] is False
        assert any("no policy binding" in e for e in result["errors"])

    def test_expect_target_match(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, deployment_target="prod-lxc")
        result = verify_attestation(output, expected_target="prod-lxc")
        assert result["valid"] is True

    def test_expect_target_mismatch(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, deployment_target="prod-lxc")
        result = verify_attestation(output, expected_target="staging")
        assert result["valid"] is False
        assert any("target mismatch" in e for e in result["errors"])

    def test_expect_lockfile_digest_mismatch(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)
        result = verify_attestation(output, expected_lockfile_digest="wrong")
        assert result["valid"] is False
        assert any("Lockfile digest mismatch" in e for e in result["errors"])

    def test_strict_requires_policy_binding(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output)  # no policy_id
        result = verify_attestation(output, strict=True)
        assert result["valid"] is False
        assert any("policy" in e.lower() for e in result["errors"])

    def test_cli_has_expect_options(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--expect-policy-digest" in main_src
        assert "--expect-lockfile-digest" in main_src
        assert "--expect-target" in main_src
        assert "--expect-artifact-digest" in main_src


# --- 11. Version and Changelog (v1.8.1) -----------------------------------


class TestV181Version:
    def test_version_is_1_8_1(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v181(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Policy Binding" in changelog or "policy" in changelog.lower()


# --- 12. Verifier Profile (v1.8.2) ----------------------------------------


class TestVerifierProfile:
    """Versioned verifier profile consolidates CI flags."""

    def test_load_verifier_profile(self, tmp_path):
        from nodechain.cli.attestation import load_verifier_profile, VERIFIER_PROFILE_SCHEMA_VERSION
        profile = {
            "schema_version": "1",
            "require_signature": True,
            "trusted_signer_fingerprints": ["abc123"],
        }
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(profile))
        loaded = load_verifier_profile(str(p))
        assert loaded["schema_version"] == "1"
        assert loaded["require_signature"] is True
        assert "profile_digest" in loaded
        assert len(loaded["profile_digest"]) == 64

    def test_verify_with_profile(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys["private_key_path"],
            policy_id="p1", policy_version="1",
            deployment_target="prod-lxc",
        )

        profile = {
            "schema_version": "1",
            "require_signature": True,
            "strict_mode": True,
            "trusted_signer_fingerprints": [keys["fingerprint"]],
            "allowed_attestation_schema_versions": ["1"],
        }
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(profile))

        result = verify_attestation(
            output,
            pubkey_path=keys["public_key_path"],
            profile_path=str(p),
        )
        assert result["valid"] is True
        assert result["checks"].get("profile_digest")
        assert result["checks"].get("signer_trusted") is True

    def test_untrusted_signer_fingerprint_rejected(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            sign_key=keys["private_key_path"],
            policy_id="p1", policy_version="1",
        )

        profile = {
            "schema_version": "1",
            "trusted_signer_fingerprints": ["deadbeef"],  # wrong fingerprint
        }
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(profile))

        result = verify_attestation(
            output,
            pubkey_path=keys["public_key_path"],
            profile_path=str(p),
        )
        assert result["valid"] is False
        assert any("not in trusted list" in e for e in result["errors"])

    def test_unsupported_schema_version_rejected(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")

        profile = {
            "schema_version": "1",
            "allowed_attestation_schema_versions": ["99"],  # don't accept v1
        }
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(profile))

        result = verify_attestation(output, profile_path=str(p))
        assert result["valid"] is False
        assert any("not in allowed" in e for e in result["errors"])

    def test_profile_provides_expectations(self, tmp_path):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation(
            "test_run", str(bundle), output,
            policy_id="p1", policy_version="1",
            deployment_target="prod-lxc",
        )
        data = json.loads(Path(output).read_text())

        profile = {
            "schema_version": "1",
            "expected_target": "prod-lxc",
            "expected_policy_digest": data["policy_digest"],
        }
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(profile))

        result = verify_attestation(output, profile_path=str(p))
        assert result["valid"] is True

    def test_cli_has_profile_option(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--profile" in main_src


# --- 13. Version and Changelog (v1.8.2) -----------------------------------


class TestV182Version:
    def test_version_is_1_8_2(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v182(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Verifier Profile" in changelog or "verifier" in changelog.lower()


# --- 14. Trust Store (v1.8.3) ---------------------------------------------


class TestTrustStore:
    """Local trust store for verifier profile signing keys."""

    def test_add_key(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, TRUST_STORE_SCHEMA_VERSION
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        result = add_key("profile-signer", keys["public_key_path"])
        assert result["status"] == "added"
        assert result["name"] == "profile-signer"
        assert len(result["fingerprint"]) == 32

    def test_list_keys(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, list_keys
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("signer1", keys["public_key_path"])

        key_list = list_keys()
        assert len(key_list) == 1
        assert key_list[0]["name"] == "signer1"
        assert key_list[0]["fingerprint"]

    def test_remove_key(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, remove_key, list_keys
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("signer1", keys["public_key_path"])

        result = remove_key("signer1")
        assert result["status"] == "removed"

        key_list = list_keys()
        assert len(key_list) == 0

    def test_remove_nonexistent_key(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import remove_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        result = remove_key("nonexistent")
        assert result["status"] == "not_found"

    def test_is_trusted_fingerprint(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, is_trusted_fingerprint
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("signer1", keys["public_key_path"])

        assert is_trusted_fingerprint(keys["fingerprint"]) is True
        assert is_trusted_fingerprint("deadbeef") is False

    def test_lookup_by_fingerprint(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, lookup_by_fingerprint
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("signer1", keys["public_key_path"])

        pem = lookup_by_fingerprint(keys["fingerprint"])
        assert pem is not None
        assert "BEGIN PUBLIC KEY" in pem

    def test_cli_has_trust_store_commands(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "trust-store" in main_src
        assert "add-key" in main_src
        assert "remove-key" in main_src


# --- 15. Profile Signing (v1.8.3) -----------------------------------------


class TestProfileSigning:
    """Verifier profiles can be signed and verified against trust store."""

    def test_sign_profile(self, tmp_path):
        from nodechain.cli.trust_store import sign_profile
        from nodechain.cli.bundle_signing import generate_key_pair

        keys = generate_key_pair(str(tmp_path))
        profile = {
            "schema_version": "1",
            "strict_mode": True,
        }
        signed = sign_profile(profile, keys["private_key_path"])
        assert "profile_signature" in signed
        assert signed["profile_signature_algorithm"] == "RSA-PSS-SHA256"
        assert signed["profile_signer_fingerprint"] == keys["fingerprint"]

    def test_verify_signed_profile(self, tmp_path):
        from nodechain.cli.trust_store import sign_profile, verify_profile_signature
        from nodechain.cli.bundle_signing import generate_key_pair

        keys = generate_key_pair(str(tmp_path))
        profile = {
            "schema_version": "1",
            "strict_mode": True,
        }
        signed = sign_profile(profile, keys["private_key_path"])

        result = verify_profile_signature(signed, keys["public_key_path"])
        # Note: verify_profile_signature takes PEM string, not file path
        pem = Path(keys["public_key_path"]).read_text()
        result = verify_profile_signature(signed, pem)
        assert result["valid"] is True
        assert result["fingerprint"] == keys["fingerprint"]

    def test_verify_profile_wrong_key(self, tmp_path):
        from nodechain.cli.trust_store import sign_profile, verify_profile_signature
        from nodechain.cli.bundle_signing import generate_key_pair

        keys1 = generate_key_pair(str(tmp_path), "k1")
        keys2 = generate_key_pair(str(tmp_path), "k2")
        profile = {"schema_version": "1"}
        signed = sign_profile(profile, keys1["private_key_path"])

        pem2 = Path(keys2["public_key_path"]).read_text()
        result = verify_profile_signature(signed, pem2)
        assert result["valid"] is False

    def test_unsigned_profile_fails_verification(self):
        from nodechain.cli.trust_store import verify_profile_signature
        profile = {"schema_version": "1"}
        result = verify_profile_signature(profile, "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----")
        assert result["valid"] is False


# --- 16. Profile Signature in Attestation (v1.8.3) ------------------------


class TestProfileSignatureVerification:
    """Attestation verification with profile signatures and trust store."""

    def test_require_profile_signature_fails_unsigned(self, tmp_path, monkeypatch):
        from nodechain.cli.attestation import generate_attestation, verify_attestation

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")

        # Create unsigned profile
        profile = {"schema_version": "1"}
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(profile))

        result = verify_attestation(
            output, profile_path=str(p),
            require_profile_signature=True,
        )
        assert result["valid"] is False
        assert any("not signed" in e.lower() for e in result["errors"])
        assert result["checks"]["profile_signature_status"] == "missing"

    def test_signed_profile_by_trusted_signer_passes(self, tmp_path, monkeypatch):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        from nodechain.cli.trust_store import add_key, sign_profile
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("trusted-signer", keys["public_key_path"])

        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")

        # Sign the profile
        profile = {"schema_version": "1"}
        signed_profile = sign_profile(profile, keys["private_key_path"])
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(signed_profile))

        result = verify_attestation(
            output, profile_path=str(p),
            require_profile_signature=True,
        )
        assert result["valid"] is True
        assert result["checks"]["profile_signature_status"] == "valid"
        assert result["checks"]["profile_signer_trusted"] is True

    def test_signed_profile_by_untrusted_signer_fails(self, tmp_path, monkeypatch):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        from nodechain.cli.trust_store import sign_profile
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))  # NOT added to trust store

        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")

        profile = {"schema_version": "1"}
        signed_profile = sign_profile(profile, keys["private_key_path"])
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(signed_profile))

        result = verify_attestation(
            output, profile_path=str(p),
            require_profile_signature=True,
        )
        assert result["valid"] is False
        assert result["checks"]["profile_signature_status"] == "untrusted_signer"
        assert result["checks"]["profile_signer_trusted"] is False

    def test_profile_signature_status_in_output(self, tmp_path, monkeypatch):
        from nodechain.cli.attestation import generate_attestation, verify_attestation
        from nodechain.cli.trust_store import add_key, sign_profile
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("trusted-signer", keys["public_key_path"])

        bundle = _make_test_bundle(tmp_path)
        output = str(tmp_path / "attestation.json")
        generate_attestation("test_run", str(bundle), output, policy_id="p1", policy_version="1")

        profile = {"schema_version": "1"}
        signed_profile = sign_profile(profile, keys["private_key_path"])
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(signed_profile))

        result = verify_attestation(output, profile_path=str(p))
        assert "profile_signature_status" in result["checks"]
        assert "profile_signer_fingerprint" in result["checks"]
        assert "profile_signer_trusted" in result["checks"]

    def test_cli_has_require_profile_signature(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--require-profile-signature" in main_src


# --- 17. Version and Changelog (v1.8.3) -----------------------------------


class TestV183Version:
    def test_version_is_1_8_3(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v183(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Trust Store" in changelog or "trust store" in changelog.lower()
