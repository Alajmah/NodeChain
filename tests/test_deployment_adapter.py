"""Tests for deployment system adapters and receipts (v1.10.0)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


# ── Test Helpers ────────────────────────────────────────────────────────────


def _make_test_bundle(tmp_path: Path) -> Path:
    """Create a valid audit bundle ZIP for testing."""
    import zipfile
    bundle_path = tmp_path / "audit_bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        for fname, content in [
            ("bundle_meta.json", json.dumps({
                "audit_bundle_schema_version": "1",
                "schema_version": "1",
                "type": "audit_bundle_meta",
                "run_id": "test_run",
                "generated_at": "2026-06-14T12:00:00Z",
                "files": [],
            })),
            ("invariants.json", json.dumps({
                "schema_version": "1", "type": "invariants_report",
                "invariants": [], "errors": 0, "warnings": 0,
            })),
            ("lockfile.json", json.dumps({
                "schema_version": "1", "type": "lockfile", "entries": [],
            })),
            ("sandbox_capabilities.json", json.dumps({
                "schema_version": "1", "type": "sandbox_capabilities", "capabilities": {},
            })),
            ("namespace_detection.json", json.dumps({
                "schema_version": "1", "type": "namespace_detection", "namespaces": {},
            })),
            ("preset.json", json.dumps({
                "schema_version": "1", "type": "preset", "preset": {},
            })),
            ("enforcement_layers.json", json.dumps({
                "schema_version": "1", "type": "enforcement_layers", "layers": [],
            })),
            ("platform.json", json.dumps({
                "schema_version": "1", "type": "platform_info", "platform": "Test",
            })),
        ]:
            zf.writestr(fname, content)
        zf.writestr("SUMMARY.md", "# Audit Bundle\n\n## Compliance Status\n\nCOMPLIANT\n")
    return bundle_path


def _make_gate_receipt(tmp_path: Path) -> str:
    """Create a gate receipt (deploy_allowed=true)."""
    from nodechain.cli.attestation import generate_attestation
    from nodechain.cli.deploy_receipt import create_receipt
    bundle = _make_test_bundle(tmp_path)
    att_path = str(tmp_path / "attestation.json")
    generate_attestation(
        "test_run", str(bundle), att_path,
        policy_id="p1", policy_version="1",
        deployment_target="prod-lxc",
    )
    receipt_path = str(tmp_path / "gate_receipt.json")
    create_receipt(attestation_path=att_path, output=receipt_path)
    return receipt_path


def _make_denied_gate_receipt(tmp_path: Path) -> str:
    """Create a denied gate receipt."""
    from nodechain.cli.deploy_receipt import create_receipt
    att = {
        "schema_version": "1", "type": "deployment_attestation",
        "run_id": "bad_run", "generated_at": "2026-06-14T12:00:00Z",
        "audit_bundle_sha256": "abc", "bundle_signature_status": "unsigned",
        "trust_verdict": "non_compliant",
        "deploy_allowed": False, "denial_reason": "trust_verdict=non_compliant",
        "policy_id": "p1", "platform": {"platform": "Linux"},
    }
    att_path = tmp_path / "bad_att.json"
    att_path.write_text(json.dumps(att))
    receipt_path = str(tmp_path / "denied_receipt.json")
    create_receipt(attestation_path=str(att_path), output=receipt_path)
    return receipt_path


# ── 1. Adapter Interface ───────────────────────────────────────────────────


class TestAdapterInterface:
    """Deployment adapter interface and registry."""

    def test_dry_run_adapter_exists(self):
        from nodechain.cli.deployment_adapter import DryRunAdapter
        adapter = DryRunAdapter()
        assert adapter.system_name == "dry_run"

    def test_local_shell_adapter_exists(self):
        from nodechain.cli.deployment_adapter import LocalShellAdapter
        adapter = LocalShellAdapter()
        assert adapter.system_name == "local_shell"

    def test_get_adapter_by_name(self):
        from nodechain.cli.deployment_adapter import get_adapter
        adapter = get_adapter("dry_run")
        assert adapter.system_name == "dry_run"

    def test_get_adapter_hyphen_alias(self):
        from nodechain.cli.deployment_adapter import get_adapter
        adapter = get_adapter("dry-run")
        assert adapter.system_name == "dry_run"

    def test_unknown_adapter_raises(self):
        from nodechain.cli.deployment_adapter import get_adapter
        with pytest.raises(ValueError, match="Unknown deployment adapter"):
            get_adapter("nonexistent")

    def test_list_adapters(self):
        from nodechain.cli.deployment_adapter import list_adapters
        adapters = list_adapters()
        assert "dry_run" in adapters
        assert "local_shell" in adapters

    def test_dry_run_adapter_deploy(self):
        from nodechain.cli.deployment_adapter import DryRunAdapter
        adapter = DryRunAdapter()
        result = adapter.deploy(
            target="prod-lxc",
            artifact_digest="abc123",
            policy_digest="def456",
            assurance_receipt_id="r-001",
        )
        assert result["deploy_status"] == "accepted"
        assert "deployer_identity" in result
        assert "deploy_started_at" in result
        assert "deploy_finished_at" in result


# ── 2. Deployment Receipt Creation ─────────────────────────────────────────


class TestDeploymentReceiptCreation:
    """Creating deployment-system receipts from gate receipts."""

    def test_create_dry_run_receipt(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
        )
        assert receipt["type"] == "deployment_system_receipt"
        assert receipt["deployment_system"] == "dry_run"
        assert receipt["deploy_status"] == "accepted"
        assert receipt["deployment_receipt_id"]  # UUID
        assert receipt["assurance_receipt_digest"]
        assert receipt["receipt_digest"]

    def test_receipt_has_all_required_fields(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, REQUIRED_DEPLOYMENT_RECEIPT_FIELDS,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(gate_receipt_path=gate_receipt)
        for field in REQUIRED_DEPLOYMENT_RECEIPT_FIELDS:
            assert field in receipt, f"Missing field: {field}"

    def test_receipt_has_timestamps(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(gate_receipt_path=gate_receipt)
        assert receipt["deploy_started_at"]
        assert receipt["deploy_finished_at"]
        assert "T" in receipt["deploy_started_at"]

    def test_receipt_has_deployer_identity(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(gate_receipt_path=gate_receipt)
        assert receipt["deployer_identity"]
        assert "dry-run" in receipt["deployer_identity"] or "@" in receipt["deployer_identity"]

    def test_receipt_has_target_and_digests(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(gate_receipt_path=gate_receipt)
        assert receipt["target"] == "prod-lxc"
        assert "artifact_digest" in receipt
        assert "assurance_receipt_digest" in receipt

    def test_receipt_written_to_file(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(gate_receipt_path=gate_receipt, output=output)
        data = json.loads(Path(output).read_text())
        assert data["type"] == "deployment_system_receipt"

    def test_denied_gate_receipt_raises(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        denied = _make_denied_gate_receipt(tmp_path)
        with pytest.raises(ValueError, match="denied"):
            create_deployment_receipt(gate_receipt_path=denied)


# ── 3. Receipt Signing ────────────────────────────────────────────────────


class TestDeploymentReceiptSigning:
    """Deployment receipts can be signed."""

    def test_sign_receipt(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            sign_key=keys["private_key_path"],
        )
        assert "receipt_signature" in receipt
        assert receipt["receipt_signature_algorithm"] == "RSA-PSS-SHA256"
        assert receipt["receipt_signer_fingerprint"] == keys["fingerprint"]


# ── 4. Receipt Verification ───────────────────────────────────────────────


class TestDeploymentReceiptVerification:
    """Deployment receipts can be verified."""

    def test_verify_valid_unsigned(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(gate_receipt_path=gate_receipt, output=output)

        result = verify_deployment_receipt(output)
        assert result["valid"] is True

    def test_verify_valid_signed(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            output=output,
            sign_key=keys["private_key_path"],
        )
        result = verify_deployment_receipt(output, pubkey_path=keys["public_key_path"])
        assert result["valid"] is True
        assert result["checks"]["signature_status"] == "valid"

    def test_verify_wrong_key(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        keys1 = generate_key_pair(str(tmp_path), "k1")
        keys2 = generate_key_pair(str(tmp_path), "k2")
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            output=output,
            sign_key=keys1["private_key_path"],
        )
        result = verify_deployment_receipt(output, pubkey_path=keys2["public_key_path"])
        assert result["valid"] is False
        assert result["checks"]["signature_status"] == "invalid"

    def test_verify_tampered_receipt(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(gate_receipt_path=gate_receipt, output=output)

        # Tamper
        data = json.loads(Path(output).read_text())
        data["deploy_detail"] = "TAMPERED"
        Path(output).write_text(json.dumps(data))

        result = verify_deployment_receipt(output)
        assert result["valid"] is False
        assert any("digest mismatch" in e.lower() for e in result["errors"])

    def test_gate_receipt_cross_check(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(gate_receipt_path=gate_receipt, output=output)

        result = verify_deployment_receipt(
            output,
            expected_gate_receipt_path=gate_receipt,
        )
        assert result["valid"] is True
        assert result["checks"]["gate_receipt_match"] is True

    def test_gate_receipt_cross_check_mismatch(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        gate1 = _make_gate_receipt(tmp_path)
        # Create a genuinely different gate receipt
        gate2_data = json.loads(Path(gate1).read_text())
        gate2_data["receipt_id"] = "different-receipt-id"
        gate2_path = str(tmp_path / "gate2.json")
        Path(gate2_path).write_text(json.dumps(gate2_data))

        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(gate_receipt_path=gate1, output=output)

        result = verify_deployment_receipt(
            output,
            expected_gate_receipt_path=gate2_path,
        )
        assert result["valid"] is False
        assert result["checks"]["gate_receipt_match"] is False

    def test_wrong_receipt_type_rejected(self, tmp_path):
        from nodechain.cli.deployment_adapter import verify_deployment_receipt
        gate_receipt = {"type": "deployment_receipt"}  # gate, not deployment-system
        p = tmp_path / "wrong.json"
        p.write_text(json.dumps(gate_receipt))

        result = verify_deployment_receipt(str(p))
        assert result["valid"] is False
        assert any("Expected type" in e for e in result["errors"])


# ── 5. Strict Mode ────────────────────────────────────────────────────────


class TestStrictMode:
    """Strict mode enforces deploy_status == accepted."""

    def test_strict_passes_on_accepted(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, verify_deployment_receipt,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        create_deployment_receipt(gate_receipt_path=gate_receipt, output=output)

        result = verify_deployment_receipt(output, strict=True)
        assert result["valid"] is True

    def test_strict_fails_on_rejected(self, tmp_path):
        from nodechain.cli.deployment_adapter import verify_deployment_receipt
        # Manually create a receipt with rejected status
        receipt = {
            "schema_version": "1",
            "type": "deployment_system_receipt",
            "deployment_receipt_id": "test-id",
            "gate_receipt_id": "gate-id",
            "deployment_system": "test",
            "target": "prod",
            "artifact_digest": "abc",
            "policy_digest": "",
            "deploy_status": "rejected",
            "deployer_identity": "test@host",
            "deploy_detail": "Command failed",
            "deploy_started_at": "2026-06-14T12:00:00+00:00",
            "deploy_finished_at": "2026-06-14T12:00:01+00:00",
            "assurance_receipt_id": "gate-id",
            "assurance_receipt_digest": "abc",
        }
        # Compute digest
        import hashlib
        from nodechain.cli.deployment_adapter import _sha256_dict
        receipt["receipt_digest"] = _sha256_dict(receipt)
        p = tmp_path / "rejected.json"
        p.write_text(json.dumps(receipt))

        result = verify_deployment_receipt(str(p), strict=True)
        assert result["valid"] is False
        assert any("not accepted" in e for e in result["errors"])


# ── 6. CLI Surface ─────────────────────────────────────────────────────────


class TestDeployCLI:
    """CLI command exists for deploy."""

    def test_cli_has_deploy_command(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "deploy" in main_src
        assert "deploy_cmd" in main_src

    def test_cli_has_deploy_options(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--adapter" in main_src
        assert "--gate-receipt" in main_src

    def test_cli_invoke_deploy_dry_run(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        gate_receipt = _make_gate_receipt(tmp_path)
        output = str(tmp_path / "deploy.json")
        runner = CliRunner()
        result = runner.invoke(cli, [
            "deploy",
            "--receipt", gate_receipt,
            "--adapter", "dry-run",
            "--output", output,
        ])
        assert result.exit_code == 0
        assert Path(output).exists()

    def test_cli_invoke_verify(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        gate_receipt = _make_gate_receipt(tmp_path)
        deploy_path = str(tmp_path / "deploy.json")
        runner = CliRunner()
        runner.invoke(cli, [
            "deploy",
            "--receipt", gate_receipt,
            "--adapter", "dry-run",
            "--output", deploy_path,
        ])
        result = runner.invoke(cli, [
            "deploy", "--verify", deploy_path,
        ])
        assert result.exit_code == 0

    def test_cli_verify_strict_exit_15(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        from nodechain.cli.deployment_adapter import _sha256_dict
        # Create receipt with rejected status
        receipt = {
            "schema_version": "1",
            "type": "deployment_system_receipt",
            "deployment_receipt_id": "test",
            "gate_receipt_id": "gate",
            "deployment_system": "test",
            "target": "prod",
            "artifact_digest": "",
            "policy_digest": "",
            "deploy_status": "rejected",
            "deployer_identity": "test",
            "deploy_detail": "failed",
            "deploy_started_at": "2026-06-14T12:00:00+00:00",
            "deploy_finished_at": "2026-06-14T12:00:01+00:00",
            "assurance_receipt_id": "gate",
            "assurance_receipt_digest": "abc",
        }
        receipt["receipt_digest"] = _sha256_dict(receipt)
        p = tmp_path / "rejected.json"
        p.write_text(json.dumps(receipt))

        runner = CliRunner()
        result = runner.invoke(cli, [
            "deploy", "--verify", str(p), "--strict",
        ])
        assert result.exit_code == 15


# ── 7. Receipt Type Distinction ───────────────────────────────────────────


class TestReceiptTypeDistinction:
    """Gate receipts vs deployment-system receipts are clearly distinguished."""

    def test_gate_receipt_type(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        from nodechain.cli.attestation import generate_attestation
        bundle = _make_test_bundle(tmp_path)
        att = str(tmp_path / "att.json")
        generate_attestation("test_run", str(bundle), att,
                             policy_id="p1", policy_version="1")
        gate_path = str(tmp_path / "gate.json")
        create_receipt(attestation_path=att, output=gate_path)
        data = json.loads(Path(gate_path).read_text())
        assert data["type"] == "deployment_receipt"

    def test_deployment_receipt_type(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        gate_receipt = _make_gate_receipt(tmp_path)
        deploy = create_deployment_receipt(gate_receipt_path=gate_receipt)
        assert deploy["type"] == "deployment_system_receipt"

    def test_types_are_different(self, tmp_path):
        from nodechain.cli.deploy_receipt import create_receipt
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        from nodechain.cli.attestation import generate_attestation

        bundle = _make_test_bundle(tmp_path)
        att = str(tmp_path / "att.json")
        generate_attestation("test_run", str(bundle), att,
                             policy_id="p1", policy_version="1")
        gate_path = str(tmp_path / "gate.json")
        create_receipt(attestation_path=att, output=gate_path)
        gate_data = json.loads(Path(gate_path).read_text())

        deploy = create_deployment_receipt(gate_receipt_path=gate_path)

        assert gate_data["type"] != deploy["type"]
        assert gate_data["type"] == "deployment_receipt"
        assert deploy["type"] == "deployment_system_receipt"


# ── 8. Version and Changelog ───────────────────────────────────────────────


class TestV1100Version:
    def test_version_is_1_10_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v1100(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Deployment System" in changelog or "deployment system" in changelog.lower()

    def test_frozen_surfaces_has_deploy(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "deploy" in fs


# ── 9. Adapter Manifest (v1.10.1) ─────────────────────────────────────────


class TestAdapterManifest:
    """Adapter manifest policy document."""

    def test_manifest_creation(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="prod-shell",
            adapter_type="local_shell",
            allowed_targets=["prod-lxc"],
            command_template="echo deploy {target}",
            timeout_seconds=10,
        )
        assert m.adapter_id == "prod-shell"
        assert m.adapter_type == "local_shell"
        assert m.command_template == "echo deploy {target}"

    def test_manifest_to_dict(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ADAPTER_MANIFEST_SCHEMA_VERSION
        m = AdapterManifest(adapter_id="test", adapter_type="dry_run")
        d = m.to_dict()
        assert d["schema_version"] == ADAPTER_MANIFEST_SCHEMA_VERSION
        assert d["type"] == "adapter_manifest"
        assert d["adapter_id"] == "test"

    def test_manifest_from_dict(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        d = {
            "schema_version": "1",
            "type": "adapter_manifest",
            "adapter_id": "test",
            "adapter_type": "local_shell",
            "command_template": "echo hi",
        }
        m = AdapterManifest.from_dict(d)
        assert m.adapter_id == "test"
        assert m.command_template == "echo hi"

    def test_manifest_digest(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="test", adapter_type="dry_run")
        assert len(m.digest()) == 64

    def test_manifest_from_file(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest
        d = {"adapter_id": "file-test", "adapter_type": "dry_run"}
        p = tmp_path / "manifest.json"
        p.write_text(json.dumps(d))
        m = AdapterManifest.from_file(str(p))
        assert m.adapter_id == "file-test"

    def test_validate_target_allowed(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="t", adapter_type="dry_run", allowed_targets=["prod-lxc"])
        assert m.validate_target("prod-lxc") is True
        assert m.validate_target("staging") is False

    def test_validate_target_wildcard(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="t", adapter_type="dry_run")
        assert m.validate_target("anything") is True

    def test_validate_policy_digest(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="t", adapter_type="dry_run", required_policy_digest="abc")
        assert m.validate_policy_digest("abc") is True
        assert m.validate_policy_digest("xyz") is False

    def test_validate_artifact_digest_wildcard(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="t", adapter_type="dry_run")
        assert m.validate_artifact_digest("anything") is True

    def test_validate_command_template_safe(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo deploy {target} {artifact_digest}",
            allow_shell=True,
        )
        issues = m.validate_command_template()
        assert len(issues) == 0

    def test_validate_command_template_missing(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="t", adapter_type="local_shell", execution_mode="shell", command_template="", allow_shell=True)
        issues = m.validate_command_template()
        assert any("missing" in i.lower() for i in issues)

    def test_validate_command_template_unsafe_substitution(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo $(whoami)",
            allow_shell=True,
        )
        issues = m.validate_command_template()
        assert len(issues) > 0
        assert any("unsafe" in i.lower() or "substitution" in i.lower() for i in issues)

    def test_validate_command_template_unsafe_pipe(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo hi | cat",
            allow_shell=True,
        )
        issues = m.validate_command_template()
        assert len(issues) > 0

    def test_validate_command_template_unsafe_chaining(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo hi && rm -rf /",
            allow_shell=True,
        )
        issues = m.validate_command_template()
        assert len(issues) > 0

    def test_command_template_digest(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="t", adapter_type="local_shell", command_template="echo deploy")
        assert len(m.command_template_digest()) == 64


# ── 10. Manifest-Governed Deployment (v1.10.1) ─────────────────────────────


class TestManifestGovernedDeployment:
    """Deployment with manifest validation and execution details."""

    def test_deploy_with_manifest(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="test-dry",
            adapter_type="dry_run",
            allowed_targets=["prod-lxc"],
            execution_mode="argv",
            argv_template=["echo", "deploy", "{target}"],
            allow_shell=False,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            manifest_path=manifest_path,
        )
        assert receipt["adapter_manifest_digest"]
        assert receipt["command_template_digest"]

    def test_deploy_target_not_allowed(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="strict",
            adapter_type="dry_run",
            allowed_targets=["staging-only"],  # doesn't include prod-lxc
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        with pytest.raises(ValueError, match="not in allowed"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                manifest_path=manifest_path,
            )

    def test_deploy_policy_digest_mismatch(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="strict",
            adapter_type="dry_run",
            required_policy_digest="wrong-digest",
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        with pytest.raises(ValueError, match="Policy digest mismatch"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                manifest_path=manifest_path,
            )

    def test_deploy_unsafe_command_template_rejected(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="unsafe",
            adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo $(whoami) && rm -rf /",
            allow_shell=True,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        with pytest.raises(ValueError, match="policy violations"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="local_shell",
                manifest_path=manifest_path,
            )

    def test_local_shell_with_safe_template(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="test-shell",
            adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo deploy {target}",
            allow_shell=True,
            timeout_seconds=10,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="local_shell",
            manifest_path=manifest_path,
        )
        assert receipt["deploy_status"] == "accepted"
        assert receipt["execution_exit_code"] == 0
        assert receipt["command_executed"]
        assert "stdout_digest" in receipt

    def test_strict_mode_rejects_nonzero_exit(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="fail-shell",
            adapter_type="local_shell",
            execution_mode="shell",
            command_template="exit 1",  # always fails
            allow_shell=True,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="local_shell",
            manifest_path=manifest_path,
            strict=True,
        )
        assert receipt["deploy_status"] == "rejected"
        assert receipt["execution_exit_code"] == 1

    def test_cli_has_manifest_option(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--manifest" in main_src


# ── 11. Argv Execution Mode (v1.10.2) ─────────────────────────────────────


class TestArgvExecution:
    """Non-shell argv-based process execution."""

    def test_manifest_supports_argv_template(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["echo", "deploy", "{target}"],
            allow_shell=False,
        )
        assert m.execution_mode == "argv"
        assert m.argv_template == ["echo", "deploy", "{target}"]
        assert m.allow_shell is False

    def test_argv_template_digest(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            argv_template=["echo", "{target}"],
        )
        assert len(m.argv_template_digest()) == 64

    def test_validate_argv_safe_placeholders(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["deploy-tool", "--target", "{target}", "--artifact", "{artifact_digest}"],
        )
        issues = m.validate_argv_template()
        assert len(issues) == 0

    def test_validate_argv_unsafe_placeholders(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["tool", "{evil_var}"],
        )
        issues = m.validate_argv_template()
        assert any("Unsafe template variables" in i for i in issues)

    def test_validate_argv_empty_executable(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["", "--target", "x"],
        )
        issues = m.validate_argv_template()
        assert any("empty" in i.lower() for i in issues)

    def test_validate_argv_executable_allowlist_passes(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["echo", "deploy"],
            allowed_executables=["echo", "deploy-tool"],
        )
        issues = m.validate_argv_template()
        assert len(issues) == 0

    def test_validate_argv_executable_allowlist_fails(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["rm", "-rf", "/"],
            allowed_executables=["echo", "deploy-tool"],
        )
        issues = m.validate_argv_template()
        assert any("not in allowlist" in i for i in issues)

    def test_shell_mode_blocked_without_allow_shell(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo deploy",
            allow_shell=False,
        )
        issues = m.validate_command_template()
        assert any("allow_shell=false" in i for i in issues)

    def test_shell_mode_allowed_with_allow_shell(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo deploy {target}",
            allow_shell=True,
        )
        issues = m.validate_command_template()
        assert len(issues) == 0

    def test_deploy_with_argv_mode(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="argv-test",
            adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["echo", "deploy", "{target}"],
            allow_shell=False,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="local_shell",
            manifest_path=manifest_path,
        )
        assert receipt["deploy_status"] == "accepted"
        assert receipt["execution_mode"] == "argv"
        assert receipt["shell_used"] is False
        assert receipt["argv_template_digest"]
        assert receipt["resolved_argv_digest"]
        assert receipt["execution_exit_code"] == 0

    def test_deploy_shell_mode_blocked_by_manifest(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="blocked",
            adapter_type="local_shell",
            execution_mode="shell",
            command_template="echo deploy",
            allow_shell=False,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        with pytest.raises(ValueError, match="policy violations"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="local_shell",
                manifest_path=manifest_path,
            )

    def test_manifest_serialization_roundtrip_with_argv(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="t", adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["echo", "{target}"],
            allow_shell=False,
            allowed_executables=["echo"],
        )
        d = m.to_dict()
        m2 = AdapterManifest.from_dict(d)
        assert m2.execution_mode == "argv"
        assert m2.argv_template == ["echo", "{target}"]
        assert m2.allow_shell is False
        assert m2.allowed_executables == ["echo"]

    def test_cli_invoke_argv_deploy(self, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        from nodechain.cli.deployment_adapter import AdapterManifest

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="cli-argv",
            adapter_type="local_shell",
            execution_mode="argv",
            argv_template=["echo", "deploy"],
            allow_shell=False,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        output = str(tmp_path / "deploy.json")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "deploy",
            "--receipt", gate_receipt,
            "--adapter", "local_shell",
            "--manifest", manifest_path,
            "--output", output,
        ])
        assert result.exit_code == 0
        data = json.loads(Path(output).read_text())
        assert data["execution_mode"] == "argv"
        assert data["shell_used"] is False


# ── 12. Manifest Signing and Trust (v1.10.3) ──────────────────────────────


class TestManifestSigning:
    """Adapter manifests can be signed and verified."""

    def test_sign_manifest(self, tmp_path):
        from nodechain.cli.deployment_adapter import sign_manifest
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        manifest = {"adapter_id": "t", "adapter_type": "dry_run", "schema_version": "1"}
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest))

        signed = sign_manifest(manifest_path, keys["private_key_path"])
        assert "manifest_signature" in signed
        assert signed["manifest_signature_algorithm"] == "RSA-PSS-SHA256"
        assert signed["manifest_signer_fingerprint"] == keys["fingerprint"]

    def test_verify_signed_manifest(self, tmp_path):
        from nodechain.cli.deployment_adapter import sign_manifest, verify_manifest_signature
        from nodechain.cli.bundle_signing import generate_key_pair
        keys = generate_key_pair(str(tmp_path))
        manifest = {"adapter_id": "t", "adapter_type": "dry_run", "schema_version": "1"}
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest))

        signed = sign_manifest(manifest_path, keys["private_key_path"])
        pem = Path(keys["public_key_path"]).read_text()
        result = verify_manifest_signature(signed, pem)
        assert result["valid"] is True
        assert result["fingerprint"] == keys["fingerprint"]

    def test_verify_manifest_wrong_key(self, tmp_path):
        from nodechain.cli.deployment_adapter import sign_manifest, verify_manifest_signature
        from nodechain.cli.bundle_signing import generate_key_pair
        keys1 = generate_key_pair(str(tmp_path), "k1")
        keys2 = generate_key_pair(str(tmp_path), "k2")
        manifest = {"adapter_id": "t", "adapter_type": "dry_run"}
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest))

        signed = sign_manifest(manifest_path, keys1["private_key_path"])
        pem2 = Path(keys2["public_key_path"]).read_text()
        result = verify_manifest_signature(signed, pem2)
        assert result["valid"] is False

    def test_unsigned_manifest_fails_verification(self):
        from nodechain.cli.deployment_adapter import verify_manifest_signature
        result = verify_manifest_signature(
            {"adapter_id": "t"}, "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----"
        )
        assert result["valid"] is False


class TestManifestTrustStoreIntegration:
    """Manifest signatures verified against trust store."""

    def test_require_manifest_signature_passes_trusted(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.trust_store import add_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("adapter-signer", keys["public_key_path"])

        gate_receipt = _make_gate_receipt(tmp_path)

        manifest = AdapterManifest(
            adapter_id="trusted-argv",
            adapter_type="dry_run",
            execution_mode="argv",
            argv_template=["echo", "deploy"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            manifest_path=manifest_path,
            require_manifest_signature=True,
        )
        assert receipt["adapter_manifest_signature_status"] == "valid"
        assert receipt["adapter_manifest_signer_trusted"] is True

    def test_require_manifest_signature_fails_unsigned(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(adapter_id="t", adapter_type="dry_run")
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        with pytest.raises(ValueError, match="not signed"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                manifest_path=manifest_path,
                require_manifest_signature=True,
            )

    def test_require_manifest_signature_fails_untrusted(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        # NOT added to trust store

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(adapter_id="t", adapter_type="dry_run")
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        with pytest.raises(ValueError, match="not in trust store"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                manifest_path=manifest_path,
                require_manifest_signature=True,
            )

    def test_receipt_records_manifest_signature_fields(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.trust_store import add_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("adapter-signer", keys["public_key_path"])

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="t", adapter_type="dry_run",
            execution_mode="argv", argv_template=["echo", "deploy"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            manifest_path=manifest_path,
            require_manifest_signature=True,
        )
        assert "adapter_manifest_signature_status" in receipt
        assert "adapter_manifest_signer_fingerprint" in receipt
        assert "adapter_manifest_signer_trusted" in receipt

    def test_cli_has_require_manifest_signature(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--require-adapter-manifest-signature" in main_src


# ── 13. Trust Store Key Purposes (v1.10.4) ────────────────────────────────


class TestTrustStoreKeyPurposes:
    """Trust store keys carry purpose constraints."""

    def test_add_key_with_purpose(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))

        result = add_key("manifest-signer", keys["public_key_path"],
                         purposes=["adapter_manifest_signing"])
        assert result["purposes"] == ["adapter_manifest_signing"]

    def test_add_key_multiple_purposes(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))

        result = add_key("dual-signer", keys["public_key_path"],
                         purposes=["adapter_manifest_signing", "receipt_signing"])
        assert "adapter_manifest_signing" in result["purposes"]
        assert "receipt_signing" in result["purposes"]

    def test_add_key_unknown_purpose_rejected(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))

        with pytest.raises(ValueError, match="Unknown purpose"):
            add_key("bad", keys["public_key_path"], purposes=["evil_purpose"])

    def test_add_key_no_purpose_defaults_all(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, ALL_PURPOSES
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))

        result = add_key("legacy", keys["public_key_path"])
        assert sorted(result["purposes"]) == sorted(ALL_PURPOSES)

    def test_check_purpose_allowed(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, check_purpose
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        result = check_purpose(keys["fingerprint"], "adapter_manifest_signing")
        assert result["allowed"] is True

    def test_check_purpose_denied(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, check_purpose
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        result = check_purpose(keys["fingerprint"], "verifier_profile_signing")
        assert result["allowed"] is False
        assert "verifier_profile_signing" in result["reason"]

    def test_check_purpose_legacy_key_allows_all(self, tmp_path, monkeypatch):
        import json
        from nodechain.cli.trust_store import check_purpose

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old-key": {
                    "fingerprint": "abc123",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                }
            }
        }))

        result = check_purpose("abc123", "adapter_manifest_signing")
        assert result["allowed"] is True
        assert "Legacy" in result["reason"]

    def test_list_keys_shows_purposes(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, list_keys
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing", "receipt_signing"])

        listed = list_keys()
        assert len(listed) == 1
        assert "adapter_manifest_signing" in listed[0]["allowed_purposes"]

    def test_manifest_deploy_fails_wrong_purpose(self, tmp_path, monkeypatch):
        """Key with verifier_profile_signing can't sign adapter manifests."""
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.trust_store import add_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("profile-only-signer", keys["public_key_path"],
                purposes=["verifier_profile_signing"])  # NOT adapter_manifest_signing

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="t", adapter_type="dry_run",
            execution_mode="argv", argv_template=["echo"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        with pytest.raises(ValueError, match="lacks purpose"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                manifest_path=manifest_path,
                require_manifest_signature=True,
            )

    def test_manifest_deploy_succeeds_correct_purpose(self, tmp_path, monkeypatch):
        """Key with adapter_manifest_signing can sign adapter manifests."""
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.trust_store import add_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        keys = generate_key_pair(str(tmp_path))
        add_key("manifest-signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="t", adapter_type="dry_run",
            execution_mode="argv", argv_template=["echo"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            manifest_path=manifest_path,
            require_manifest_signature=True,
        )
        assert receipt["adapter_manifest_signature_status"] == "valid"

    def test_cli_add_key_has_purpose_option(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--purpose" in main_src

    def test_backward_compat_old_trust_store(self, tmp_path, monkeypatch):
        """Old trust store without purposes loads without error."""
        import json
        from nodechain.cli.trust_store import load_trust_store, is_trusted_fingerprint

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "legacy-signer": {
                    "fingerprint": "legacy123",
                    "public_key_pem": "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
                    "added_at": "2024-01-01",
                }
            }
        }))

        store = load_trust_store()
        assert "legacy-signer" in store["keys"]
        # Old key trusted for any purpose
        assert is_trusted_fingerprint("legacy123") is True
        assert is_trusted_fingerprint("legacy123", "adapter_manifest_signing") is True


# ── 14. Strict Trust Store Mode (v1.10.5) ─────────────────────────────────


class TestStrictTrustStoreMode:
    """Strict mode rejects legacy keys without explicit purposes."""

    def test_strict_rejects_legacy_key(self, tmp_path, monkeypatch):
        """In strict mode, legacy keys are rejected."""
        import json as _json
        from nodechain.cli.trust_store import is_trusted_fingerprint

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old-key": {
                    "fingerprint": "abc123",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                }
            }
        }))

        # Non-strict: legacy key accepted
        assert is_trusted_fingerprint("abc123") is True
        # Strict: legacy key rejected
        assert is_trusted_fingerprint("abc123", strict=True) is False

    def test_strict_accepts_key_with_purposes(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, is_trusted_fingerprint
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        # Strict mode still works for keys with explicit purposes
        assert is_trusted_fingerprint(keys["fingerprint"], strict=True) is True
        assert is_trusted_fingerprint(
            keys["fingerprint"], "adapter_manifest_signing", strict=True
        ) is True

    def test_check_purpose_strict_rejects_legacy(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import check_purpose

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old-key": {
                    "fingerprint": "abc123",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                }
            }
        }))

        result = check_purpose("abc123", "adapter_manifest_signing", strict=True)
        assert result["allowed"] is False
        assert "Legacy" in result["reason"]

    def test_migrate_legacy_keys(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import migrate_legacy_keys, load_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                },
                "old2": {
                    "fingerprint": "fp2",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                },
                "new1": {
                    "fingerprint": "fp3",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["receipt_signing"],
                },
            }
        }))

        result = migrate_legacy_keys()
        assert result["migrated"] == 2
        assert "old1" in result["names"]
        assert "old2" in result["names"]
        assert "new1" not in result["names"]

        store = load_trust_store()
        assert store["keys"]["old1"]["allowed_purposes"] is not None
        assert store["keys"]["old2"]["allowed_purposes"] is not None

    def test_migrate_with_specific_purposes(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import migrate_legacy_keys, load_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                }
            }
        }))

        result = migrate_legacy_keys(purposes=["adapter_manifest_signing"])
        assert result["purposes"] == ["adapter_manifest_signing"]

        store = load_trust_store()
        assert store["keys"]["old1"]["allowed_purposes"] == ["adapter_manifest_signing"]

    def test_migrate_no_legacy_keys(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import migrate_legacy_keys, add_key
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        result = migrate_legacy_keys()
        assert result["migrated"] == 0

    def test_list_keys_marks_legacy(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import list_keys

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                },
                "new1": {
                    "fingerprint": "fp3",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["receipt_signing"],
                },
            }
        }))

        keys = list_keys()
        old_key = [k for k in keys if k["name"] == "old1"][0]
        new_key = [k for k in keys if k["name"] == "new1"][0]
        assert old_key["is_legacy"] is True
        assert new_key["is_legacy"] is False

    def test_receipt_has_trust_store_mode_standard(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.trust_store import add_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="t", adapter_type="dry_run",
            execution_mode="argv", argv_template=["echo"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            manifest_path=manifest_path,
            require_manifest_signature=True,
        )
        assert receipt["trust_store_mode"] == "standard"
        assert receipt["signer_required_purpose"] == "adapter_manifest_signing"
        assert receipt["purpose_authorized"] is True
        assert "adapter_manifest_signing" in receipt["signer_allowed_purposes"]

    def test_receipt_has_trust_store_mode_strict(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.trust_store import add_key

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="t", adapter_type="dry_run",
            execution_mode="argv", argv_template=["echo"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            manifest_path=manifest_path,
            require_manifest_signature=True,
            strict_trust_store=True,
        )
        assert receipt["trust_store_mode"] == "strict"
        assert receipt["purpose_authorized"] is True

    def test_strict_deploy_rejects_legacy_manifest_signer(self, tmp_path, monkeypatch):
        """Strict mode rejects a legacy key signing a manifest."""
        import json as _json
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, sign_manifest, AdapterManifest,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))

        # Add key as legacy (raw, no allowed_purposes)
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "legacy-signer": {
                    "fingerprint": keys["fingerprint"],
                    "public_key_pem": Path(keys["public_key_path"]).read_text(),
                    "added_at": "2024-01-01",
                }
            }
        }))

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="t", adapter_type="dry_run",
            execution_mode="argv", argv_template=["echo"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))
        sign_manifest(manifest_path, keys["private_key_path"])

        with pytest.raises(ValueError, match="legacy key"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                manifest_path=manifest_path,
                require_manifest_signature=True,
                strict_trust_store=True,
            )

    def test_cli_has_strict_trust_store_flag(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--strict-trust-store" in main_src

    def test_cli_has_migrate_command(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "trust_store_migrate" in main_src
        assert "migrate" in main_src


# ── 15. Trust Store Integrity and Audit (v1.10.6) ─────────────────────────


class TestTrustStoreIntegrity:
    """Trust store has integrity metadata, atomic writes, and audit log."""

    def test_store_has_trust_store_id(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        store = load_trust_store()
        assert "trust_store_id" in store
        assert len(store["trust_store_id"]) > 0

    def test_store_has_updated_at(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        store = load_trust_store()
        assert "updated_at" in store
        assert len(store["updated_at"]) > 0

    def test_store_has_entries_digest(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        store = load_trust_store()
        assert "entries_digest" in store
        assert len(store["entries_digest"]) == 64  # SHA-256 hex

    def test_entries_digest_changes_on_add(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys1 = generate_key_pair(str(tmp_path), "k1")
        add_key("signer1", keys1["public_key_path"])
        digest1 = load_trust_store()["entries_digest"]

        keys2 = generate_key_pair(str(tmp_path), "k2")
        add_key("signer2", keys2["public_key_path"])
        digest2 = load_trust_store()["entries_digest"]
        assert digest1 != digest2

    def test_atomic_write_no_tmp_file_left(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        # No .tmp file should exist after save
        assert not (tmp_path / "trust_store.tmp").exists()

    def test_audit_log_add_key(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        store = load_trust_store()
        audit = store.get("audit_log", [])
        assert len(audit) >= 1
        event = audit[-1]
        assert event["action"] == "add_key"
        assert event["key_id"] == "signer"
        assert event["fingerprint"] == keys["fingerprint"]
        assert "adapter_manifest_signing" in event["purposes_after"]

    def test_audit_log_remove_key(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, remove_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])
        remove_key("signer")

        store = load_trust_store()
        audit = store.get("audit_log", [])
        actions = [e["action"] for e in audit]
        assert "remove_key" in actions
        remove_event = [e for e in audit if e["action"] == "remove_key"][0]
        assert remove_event["key_id"] == "signer"
        assert "adapter_manifest_signing" in remove_event["purposes_before"]

    def test_audit_log_migrate_key(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import migrate_legacy_keys, load_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "old1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                }
            }
        }))
        migrate_legacy_keys(purposes=["adapter_manifest_signing"])

        store = load_trust_store()
        audit = store.get("audit_log", [])
        actions = [e["action"] for e in audit]
        assert "migrate_key" in actions
        migrate_event = [e for e in audit if e["action"] == "migrate_key"][0]
        assert migrate_event["key_id"] == "old1"
        assert "adapter_manifest_signing" in migrate_event["purposes_after"]

    def test_audit_event_has_timestamp(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, load_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        store = load_trust_store()
        event = store["audit_log"][-1]
        assert "timestamp" in event
        assert "T" in event["timestamp"]  # ISO 8601


class TestTrustStoreVerify:
    """trust-store verify validates integrity."""

    def test_verify_valid_store(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import add_key, verify_trust_store
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        result = verify_trust_store()
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_verify_detects_duplicate_fingerprints(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import verify_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "k1": {
                    "fingerprint": "same_fp",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["adapter_manifest_signing"],
                },
                "k2": {
                    "fingerprint": "same_fp",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["receipt_signing"],
                },
            }
        }))

        result = verify_trust_store()
        assert result["valid"] is False
        assert any("Duplicate" in e for e in result["errors"])

    def test_verify_detects_invalid_purposes(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import verify_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "k1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["evil_purpose"],
                },
            }
        }))

        result = verify_trust_store()
        assert result["valid"] is False
        assert any("Invalid purposes" in e for e in result["errors"])

    def test_verify_detects_malformed_pem(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import verify_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "k1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "not-a-real-key",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["adapter_manifest_signing"],
                },
            }
        }))

        result = verify_trust_store()
        assert result["valid"] is False
        assert any("Malformed PEM" in e for e in result["errors"])

    def test_verify_detects_tampered_entries_digest(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import verify_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "entries_digest": "deadbeef" * 8,
            "keys": {
                "k1": {
                    "fingerprint": "fp1",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["adapter_manifest_signing"],
                },
            }
        }))

        result = verify_trust_store(strict=True)
        assert result["valid"] is False
        assert any("digest mismatch" in e.lower() for e in result["errors"])

    def test_verify_nonexistent_store(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import verify_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))

        result = verify_trust_store()
        assert result["valid"] is False
        assert "does not exist" in result["errors"][0]

    def test_verify_missing_entries_digest_warning(self, tmp_path, monkeypatch):
        import json as _json
        from nodechain.cli.trust_store import verify_trust_store

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {},
        }))

        # Non-strict: warning
        result = verify_trust_store(strict=False)
        assert "entries_digest missing" in str(result["warnings"])

        # Strict: error
        result = verify_trust_store(strict=True)
        assert "entries_digest missing" in str(result["errors"])

    def test_cli_has_verify_command(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "trust_store_verify" in main_src

    def test_strict_mode_refuses_malformed_store(self, tmp_path, monkeypatch):
        """Strict is_trusted_fingerprint refuses unverifiable store."""
        import json as _json
        from nodechain.cli.trust_store import is_trusted_fingerprint

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        store_path.write_text(_json.dumps({
            "schema_version": "1",
            "type": "trust_store",
            "keys": {
                "k1": {
                    "fingerprint": "same_fp",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["evil"],
                },
                "k2": {
                    "fingerprint": "same_fp",
                    "public_key_pem": "fake",
                    "added_at": "2024-01-01",
                    "allowed_purposes": ["adapter_manifest_signing"],
                },
            }
        }))

        # Strict mode verifies store first, should reject
        assert is_trusted_fingerprint("same_fp", strict=True) is False


# ── 16. Trust Store Snapshots (v1.10.7) ───────────────────────────────────


class TestTrustStoreSnapshot:
    """Trust store snapshots freeze and attest the trust root state."""

    def test_create_snapshot(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        snap = create_trust_store_snapshot()
        assert snap["schema_version"] == "1"
        assert snap["type"] == "trust_store_snapshot"
        assert snap["key_count"] == 1
        assert "entries_digest" in snap
        assert "audit_log_digest" in snap
        assert "created_at" in snap
        assert "snapshot_digest" in snap

    def test_snapshot_has_purposes_summary(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys1 = generate_key_pair(str(tmp_path), "k1")
        add_key("s1", keys1["public_key_path"],
                purposes=["adapter_manifest_signing"])
        keys2 = generate_key_pair(str(tmp_path), "k2")
        add_key("s2", keys2["public_key_path"],
                purposes=["adapter_manifest_signing", "receipt_signing"])

        snap = create_trust_store_snapshot()
        ps = snap["purposes_summary"]
        assert ps["adapter_manifest_signing"] == 2
        assert ps["receipt_signing"] == 1

    def test_snapshot_write_to_file(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        out = str(tmp_path / "snapshot.json")
        create_trust_store_snapshot(output_path=out)
        snap = json.loads(Path(out).read_text())
        assert snap["type"] == "trust_store_snapshot"

    def test_snapshot_signed(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        snap = create_trust_store_snapshot(private_key_path=keys["private_key_path"])
        assert "snapshot_signature" in snap
        assert snap["snapshot_signature_algorithm"] == "RSA-PSS-SHA256"
        assert snap["snapshot_signer_fingerprint"] == keys["fingerprint"]

    def test_verify_snapshot_valid(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot, verify_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        out = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=out)

        result = verify_trust_store_snapshot(snapshot_path=out)
        assert result["valid"] is True

    def test_verify_snapshot_signed_valid(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot, verify_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        out = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=out, private_key_path=keys["private_key_path"])

        pubkey = Path(keys["public_key_path"]).read_text()
        result = verify_trust_store_snapshot(
            snapshot_path=out, public_key_pem=pubkey,
        )
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"

    def test_verify_snapshot_tampered(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot, verify_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"])

        out = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=out)

        # Tamper with snapshot
        snap = json.loads(Path(out).read_text())
        snap["key_count"] = 999
        Path(out).write_text(json.dumps(snap))

        result = verify_trust_store_snapshot(snapshot_path=out)
        assert result["valid"] is False
        assert any("digest mismatch" in e.lower() for e in result["errors"])

    def test_verify_snapshot_check_live_matches(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot, verify_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        out = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=out)

        result = verify_trust_store_snapshot(
            snapshot_path=out, check_live_store=True,
        )
        assert result["valid"] is True
        assert result["details"]["live_store_matches"] is True

    def test_verify_snapshot_check_live_mismatch(self, tmp_path, monkeypatch):
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot, verify_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys1 = generate_key_pair(str(tmp_path), "k1")
        add_key("s1", keys1["public_key_path"])

        out = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=out)

        # Add another key after snapshot
        keys2 = generate_key_pair(str(tmp_path), "k2")
        add_key("s2", keys2["public_key_path"])

        result = verify_trust_store_snapshot(
            snapshot_path=out, check_live_store=True,
        )
        assert result["valid"] is False
        assert result["details"]["live_store_matches"] is False

    def test_deploy_with_snapshot_requirement(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys = generate_key_pair(str(tmp_path))
        add_key("signer", keys["public_key_path"],
                purposes=["adapter_manifest_signing"])

        snap_path = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=snap_path)

        gate_receipt = _make_gate_receipt(tmp_path)
        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="dry_run",
            snapshot_path=snap_path,
        )
        assert "trust_store_snapshot_digest" in receipt
        assert "trust_store_snapshot_signature_status" in receipt

    def test_deploy_snapshot_mismatch_fails(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        from nodechain.cli.trust_store import (
            add_key, create_trust_store_snapshot,
        )
        from nodechain.cli.bundle_signing import generate_key_pair

        store_path = tmp_path / "trust_store.json"
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(store_path))
        keys1 = generate_key_pair(str(tmp_path), "k1")
        add_key("s1", keys1["public_key_path"])

        snap_path = str(tmp_path / "snap.json")
        create_trust_store_snapshot(output_path=snap_path)

        # Modify store after snapshot
        keys2 = generate_key_pair(str(tmp_path), "k2")
        add_key("s2", keys2["public_key_path"])

        gate_receipt = _make_gate_receipt(tmp_path)
        with pytest.raises(ValueError, match="snapshot verification failed"):
            create_deployment_receipt(
                gate_receipt_path=gate_receipt,
                adapter_name="dry_run",
                snapshot_path=snap_path,
            )

    def test_cli_has_snapshot_command(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "trust_store_snapshot" in main_src
        assert "verify-snapshot" in main_src

    def test_cli_deploy_has_snapshot_option(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "--require-trust-store-snapshot" in main_src


# ── 17. Proxmox Deployment Adapter (v1.11.0) ──────────────────────────────


class TestProxmoxAdapter:
    """ProxmoxAdapter performs narrow deployment actions against Proxmox VE."""

    def test_proxmox_adapter_registered(self):
        from nodechain.cli.deployment_adapter import get_adapter, list_adapters
        assert "proxmox" in list_adapters()
        adapter = get_adapter("proxmox")
        assert adapter.system_name == "proxmox"

    def test_proxmox_manifest_fields(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["validate_target"],
        )
        d = m.to_dict()
        assert d["proxmox_node"] == "pve1"
        assert d["target_vmid"] == "801"
        assert "validate_target" in d["allowed_actions"]

    def test_proxmox_manifest_roundtrip(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["validate_target", "execute_deploy"],
        )
        d = m.to_dict()
        m2 = AdapterManifest.from_dict(d)
        assert m2.proxmox_node == "pve1"
        assert m2.target_vmid == "801"
        assert "execute_deploy" in m2.allowed_actions

    def test_proxmox_validate_manifest_missing_node(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            target_vmid="801",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("proxmox_node" in i for i in issues)

    def test_proxmox_validate_manifest_missing_vmid(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("target_vmid" in i for i in issues)

    def test_proxmox_validate_manifest_wrong_type(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="local_shell",
            proxmox_node="pve1",
            target_vmid="801",
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("adapter_type" in i for i in issues)

    def test_proxmox_validate_manifest_unknown_action(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["destroy_everything"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("Unknown actions" in i for i in issues)

    def test_proxmox_validate_manifest_valid(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert len(issues) == 0

    def test_proxmox_deploy_rejected_on_missing_manifest(self):
        from nodechain.cli.deployment_adapter import ProxmoxAdapter
        adapter = ProxmoxAdapter(manifest=None)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"

    def test_proxmox_deploy_rejected_on_invalid_manifest(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            # Missing proxmox_node and target_vmid
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"
        assert "Manifest validation failed" in result["deploy_detail"]

    def test_proxmox_receipt_has_fields(self, tmp_path, monkeypatch):
        """Proxmox deploy receipt records all required fields."""
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            allowed_targets=["*"],
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv",
            argv_template=["echo"],
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        # Use upload_artifact so no SSH is needed
        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="proxmox",
            manifest_path=manifest_path,
        )
        assert receipt["proxmox_node"] == "pve1"
        assert receipt["vmid"] == "801"
        assert receipt["proxmox_action"] == "upload_artifact"
        assert "api_endpoint" in receipt

    @pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Proxmox integration requires Linux SSH access",
    )
    def test_proxmox_validate_target_live(self, tmp_path, monkeypatch):
        """Live integration test against CT 801."""
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        monkeypatch.setenv("NODECHAIN_PROXMOX_HOST", "192.0.2.100")

        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="px-live",
            adapter_type="proxmox",
            allowed_targets=["*"],
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["validate_target"],
            execution_mode="argv",
            argv_template=["echo"],
            timeout_seconds=15,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="proxmox",
            manifest_path=manifest_path,
        )
        assert receipt["proxmox_node"] == "pve1"
        assert receipt["vmid"] == "801"

    def test_proxmox_upload_artifact_action(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import ProxmoxAdapter, AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv",
            argv_template=["echo"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "abc123def456", "policy", "receipt-id")
        assert result["deploy_status"] == "accepted"
        assert result["action"] == "upload_artifact"
        assert result["proxmox_node"] == "pve1"
        assert result["vmid"] == "801"
        assert "upload" in result["api_endpoint"]

    def test_proxmox_execute_deploy_action(self, tmp_path, monkeypatch):
        """execute_deploy without SSH target should fail gracefully."""
        from nodechain.cli.deployment_adapter import ProxmoxAdapter, AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["execute_deploy"],
            execution_mode="argv",
            argv_template=["echo", "hello"],
            timeout_seconds=3,
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("nonexistent.invalid", "artifact", "policy", "receipt-id")
        assert result["action"] == "execute_deploy"
        assert result["proxmox_node"] == "pve1"
        assert result["vmid"] == "801"
        # Will fail since SSH target doesn't exist, but fields should be present
        assert result["deploy_status"] in ("failed", "rejected")

    def test_strict_mode_rejects_proxmox_failure(self, tmp_path):
        from nodechain.cli.deployment_adapter import (
            create_deployment_receipt, AdapterManifest,
        )
        gate_receipt = _make_gate_receipt(tmp_path)
        manifest = AdapterManifest(
            adapter_id="px-1",
            adapter_type="proxmox",
            allowed_targets=["*"],
            proxmox_node="pve1",
            target_vmid="801",
            allowed_actions=["execute_deploy"],
            execution_mode="argv",
            argv_template=["echo"],
            timeout_seconds=1,
        )
        manifest_path = str(tmp_path / "manifest.json")
        Path(manifest_path).write_text(json.dumps(manifest.to_dict()))

        # strict=True should escalate failure to rejected
        # Use shorter timeout for test
        receipt = create_deployment_receipt(
            gate_receipt_path=gate_receipt,
            adapter_name="proxmox",
            manifest_path=manifest_path,
            strict=True,
        )
        assert receipt["deploy_status"] in ("rejected", "failed")

    def test_proxmox_actions_constant(self):
        from nodechain.cli.deployment_adapter import PROXMOX_ACTIONS
        assert "validate_target" in PROXMOX_ACTIONS
        assert "upload_artifact" in PROXMOX_ACTIONS
        assert "execute_deploy" in PROXMOX_ACTIONS
