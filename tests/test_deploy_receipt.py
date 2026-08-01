"""Tests for deployment receipts (v1.9.0)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ── Test Helpers ────────────────────────────────────────────────────────────


def _make_test_bundle(tmp_path: Path) -> Path:
    """Create a minimal audit bundle ZIP for testing."""
    import zipfile
    bundle_path = tmp_path / "audit_bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test_run",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        zf.writestr("bundle_meta.json", json.dumps(meta))
        zf.writestr("SUMMARY.md", "# Test Bundle\n\nCOMPLIANT")
        zf.writestr(
            "invariants.json",
            json.dumps({"invariants": [], "errors": 0, "warnings": 0}),
        )
    return bundle_path


def _make_test_attestation(tmp_path: Path) -> str:
    """Create a test attestation file."""
    from nodechain.cli.attestation import generate_attestation
    bundle = _make_test_bundle(tmp_path)
    output = str(tmp_path / "attestation.json")
    generate_attestation(
        "test_run", str(bundle), output,
        policy_id="p1", policy_version="1",
        deployment_target="prod-lxc",
    )
    return output


# ── 1. Receipt Creation ────────────────────────────────────────────────────


class TestReceiptCreation:
    """Receipts record gate evaluation results."""

    def test_create_receipt_basic(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, DEPLOY_RECEIPT_SCHEMA_VERSION
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        assert receipt["schema_version"] == DEPLOY_RECEIPT_SCHEMA_VERSION
        assert receipt["type"] == "deployment_receipt"
        assert "receipt_id" in receipt
        assert len(receipt["receipt_id"]) == 36  # UUID format
        assert receipt["deploy_allowed"] is True  # compliant attestation
        assert receipt["attestation_digest"]
        assert len(receipt["attestation_digest"]) == 64

    def test_receipt_has_all_required_fields(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, REQUIRED_RECEIPT_FIELDS
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        for field in REQUIRED_RECEIPT_FIELDS:
            assert field in receipt, f"Missing field: {field}"

    def test_receipt_includes_context_fields(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        assert receipt["target"] == "prod-lxc"
        assert receipt["policy_id"] == "p1"
        assert receipt["policy_digest"]
        assert "artifact_digest" in receipt
        assert "lockfile_digest" in receipt

    def test_receipt_has_verifier_version(self, tmp_path):
        import nodechain
        from nodechain.cli.deploy_receipt import create_receipt
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        assert receipt["verifier_nodechain_version"] == nodechain.__version__

    def test_receipt_has_timestamp(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        assert receipt["verified_at"]
        # ISO 8601 format
        assert "T" in receipt["verified_at"]

    def test_receipt_has_digest(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        assert receipt["receipt_digest"]
        assert len(receipt["receipt_digest"]) == 64

    def test_receipt_written_to_file(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output)
        data = json.loads(Path(output).read_text())
        assert data["type"] == "deployment_receipt"

    def test_receipt_for_non_compliant_attestation(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        # Create a non-compliant attestation
        att = {
            "schema_version": "1",
            "type": "deployment_attestation",
            "run_id": "bad_run",
            "generated_at": "2026-06-14T12:00:00Z",
            "audit_bundle_sha256": "abc",
            "bundle_signature_status": "unsigned",
            "trust_verdict": "non_compliant",
            "deploy_allowed": False,
            "denial_reason": "trust_verdict=non_compliant",
            "policy_id": "p1",
            "platform": {"platform": "Linux"},
        }
        p = tmp_path / "bad_att.json"
        p.write_text(json.dumps(att))

        receipt = create_receipt(attestation_path=str(p))
        assert receipt["deploy_allowed"] is False
        assert receipt["denial_reason"]
        assert "verification_errors" in receipt


# ── 2. Receipt Signing ────────────────────────────────────────────────────


class TestReceiptSigning:
    """Receipts can be cryptographically signed."""

    def test_sign_receipt(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(
            attestation_path=att_path,
            sign_key=keys["private_key_path"],
        )
        assert "receipt_signature" in receipt
        assert receipt["receipt_signature_algorithm"] == "RSA-PSS-SHA256"
        assert receipt["receipt_signer_fingerprint"] == keys["fingerprint"]

    def test_unsigned_receipt_has_no_signature(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        att_path = _make_test_attestation(tmp_path)
        receipt = create_receipt(attestation_path=att_path)
        assert "receipt_signature" not in receipt


# ── 3. Receipt Verification ───────────────────────────────────────────────


class TestReceiptVerification:
    """Receipts can be verified."""

    def test_verify_valid_unsigned_receipt(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output)

        result = verify_receipt(output)
        assert result["valid"] is True

    def test_verify_valid_signed_receipt(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output, sign_key=keys["private_key_path"])

        result = verify_receipt(output, pubkey_path=keys["public_key_path"])
        assert result["valid"] is True
        assert result["checks"]["signature_status"] == "valid"

    def test_verify_receipt_wrong_key(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        from nodechain.cli.bundle_signing import generate_key_pair
        keys1 = generate_key_pair(str(tmp_path), "k1")
        keys2 = generate_key_pair(str(tmp_path), "k2")
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output, sign_key=keys1["private_key_path"])

        result = verify_receipt(output, pubkey_path=keys2["public_key_path"])
        assert result["valid"] is False
        assert result["checks"]["signature_status"] == "invalid"

    def test_verify_tampered_receipt(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output)

        # Tamper with receipt content
        data = json.loads(Path(output).read_text())
        data["deploy_allowed"] = True  # change nothing semantically but alter content
        data["denial_reason"] = "tampered"
        Path(output).write_text(json.dumps(data))

        result = verify_receipt(output)
        assert result["valid"] is False
        assert any("digest mismatch" in e.lower() for e in result["errors"])

    def test_strict_mode_fails_on_denied(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        # Create denied attestation
        att = {
            "schema_version": "1",
            "type": "deployment_attestation",
            "run_id": "bad_run",
            "generated_at": "2026-06-14T12:00:00Z",
            "audit_bundle_sha256": "abc",
            "bundle_signature_status": "unsigned",
            "trust_verdict": "non_compliant",
            "deploy_allowed": False,
            "denial_reason": "trust_verdict=non_compliant",
            "policy_id": "p1",
            "platform": {"platform": "Linux"},
        }
        p = tmp_path / "bad_att.json"
        p.write_text(json.dumps(att))

        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=str(p), output=output)

        result = verify_receipt(output, strict=True)
        assert result["valid"] is False
        assert any("denied" in e.lower() for e in result["errors"])

    def test_expectation_attestation_digest_match(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output)
        data = json.loads(Path(output).read_text())

        result = verify_receipt(output, expected_attestation_digest=data["attestation_digest"])
        assert result["valid"] is True
        assert result["checks"]["attestation_digest_match"] is True

    def test_expectation_attestation_digest_mismatch(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output)

        result = verify_receipt(output, expected_attestation_digest="wrong")
        assert result["valid"] is False
        assert any("Attestation digest mismatch" in e for e in result["errors"])

    def test_unsupported_schema_version_rejected(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt, verify_receipt
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        create_receipt(attestation_path=att_path, output=output)

        result = verify_receipt(output, allowed_schema_versions=["99"])
        assert result["valid"] is False
        assert any("not in allowed" in e for e in result["errors"])

    def test_missing_required_field(self, tmp_path):
        from nodechain.cli.deploy_receipt import verify_receipt
        # Create receipt missing required field
        bad_receipt = {
            "schema_version": "1",
            "type": "deployment_receipt",
            # Missing: receipt_id, attestation_digest, deploy_allowed, verified_at
        }
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(bad_receipt))

        result = verify_receipt(str(p))
        assert result["valid"] is False
        assert any("Missing required field" in e for e in result["errors"])


# ── 4. CLI Surface ────────────────────────────────────────────────────────


class TestReceiptCLI:
    """CLI commands exist for deploy-receipt."""

    def test_cli_has_deploy_receipt_command(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "deploy-receipt" in main_src
        assert "deploy_receipt_create" in main_src
        assert "deploy_receipt_verify" in main_src

    def test_cli_create_has_options(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--attestation" in main_src
        assert "--profile" in main_src
        assert "--sign" in main_src

    def test_cli_verify_has_options(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--expect-attestation-digest" in main_src
        assert "--expect-profile-digest" in main_src

    def test_cli_invoke_create(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        runner = CliRunner()
        result = runner.invoke(cli, [
            "deploy-receipt", "create",
            "--attestation", att_path,
            "--output", output,
        ])
        assert result.exit_code == 0
        assert Path(output).exists()

    def test_cli_invoke_verify(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        att_path = _make_test_attestation(tmp_path)
        output = str(tmp_path / "receipt.json")
        runner = CliRunner()
        runner.invoke(cli, [
            "deploy-receipt", "create",
            "--attestation", att_path,
            "--output", output,
        ])
        result = runner.invoke(cli, [
            "deploy-receipt", "verify", output,
        ])
        assert result.exit_code == 0

    def test_cli_verify_strict_deny_exit_15(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        # Create denied attestation
        att = {
            "schema_version": "1",
            "type": "deployment_attestation",
            "run_id": "bad_run",
            "generated_at": "2026-06-14T12:00:00Z",
            "audit_bundle_sha256": "abc",
            "bundle_signature_status": "unsigned",
            "trust_verdict": "non_compliant",
            "deploy_allowed": False,
            "denial_reason": "trust_verdict=non_compliant",
            "policy_id": "p1",
            "platform": {"platform": "Linux"},
        }
        att_path = tmp_path / "bad_att.json"
        att_path.write_text(json.dumps(att))

        output = str(tmp_path / "receipt.json")
        runner = CliRunner()
        runner.invoke(cli, [
            "deploy-receipt", "create",
            "--attestation", str(att_path),
            "--output", output,
        ])
        result = runner.invoke(cli, [
            "deploy-receipt", "verify", output, "--strict",
        ])
        assert result.exit_code == 15

    def test_cli_verify_invalid_receipt_exit_10(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        bad_receipt = {"type": "not_a_receipt"}
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(bad_receipt))

        runner = CliRunner()
        result = runner.invoke(cli, [
            "deploy-receipt", "verify", str(p),
        ])
        assert result.exit_code == 10


# ── 5. Version and Changelog ──────────────────────────────────────────────


class TestV190Version:
    def test_version_is_1_9_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v190(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Deployment Receipt" in changelog or "receipt" in changelog.lower()

    def test_frozen_surfaces_has_deploy_receipt(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "deploy-receipt" in fs
