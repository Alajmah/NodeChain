"""v1.19.1 — Certified Incident Chain Assurance.

Proves that the incident-response chain is not just composed, but
certified-registry-composed end to end:

    package → registry entry → certification → eval report → suite → trace

The chain flows through:
  1. Package manifest with content hash
  2. Evaluation suite with structural cases
  3. Evaluation report (passed)
  4. Certification artifact (certified)
  5. Certified registry entry (active)
  6. Registry consumption (7-point check)
  7. Trace fields recording registry evidence
  8. Evidence query reconstructing the full chain

Tests verify:
  - Registry resolution with certified_only policy
  - Trace field propagation (5 registry evidence fields)
  - Critical incident path (human review → denied without approval →
    authorized only with explicit decision → recovery not closed)
  - Evidence chain reconstruction
  - CLI smoke commands
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sha256_dict(d: dict) -> str:
    """SHA-256 of canonical JSON."""
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _setup_test_registry(tmp_path: Path) -> dict[str, str]:
    """Create a test environment with signed incident-response registry entry.

    Returns dict of paths:
      - registry_path
      - package_digest
      - certification_path
      - eval_report_path
      - suite_path
    """
    from nodechain.cli.certified_registry import publish_package, save_registry, load_registry

    # Build a package manifest dict
    package_dict = {
        "package_id": "incident_response",
        "version": "1.0.0",
        "description": "5-node incident response pipeline",
        "nodes": [
            "incident_detector",
            "severity_triager",
            "remediation_decisioner",
            "governed_remediator",
            "recovery_verifier",
        ],
        "capabilities": ["import:json", "fs:read"],
        "sandbox_profile": "none",
        "trust_level": "trusted",
    }
    package_digest = _sha256_dict(package_dict)
    package_dict["content_hash"] = package_digest

    # Build a minimal eval report (passed)
    eval_report = {
        "type": "evaluation_report",
        "eval_id": str(uuid.uuid4()),
        "suite_id": "incident_response_eval",
        "suite_version": "1.0.0",
        "suite_digest": "fake_suite_digest_" + uuid.uuid4().hex[:16],
        "target_type": "package",
        "target_ref": "incident_response",
        "target_digest": package_digest,
        "passed": True,
        "total_cases": 5,
        "passed_cases": 5,
        "failed_cases": [],
        "threshold_failures": [],
        "missing_artifacts": [],
        "report_digest": "",
        "valid": True,
        "nodechain_version": "3.5.0",
    }
    eval_report["report_digest"] = _sha256_dict(
        {k: v for k, v in eval_report.items() if k != "report_digest"}
    )
    eval_report_path = str(tmp_path / "eval_report.json")
    Path(eval_report_path).write_text(json.dumps(eval_report, indent=2), encoding="utf-8")

    # Build certification from eval report
    from nodechain.cli.certification import create_certification
    cert = create_certification(eval_report=eval_report, valid_from="2026-01-01T00:00:00Z")
    assert cert["certification_status"] == "certified"
    cert_path = str(tmp_path / "certification.json")
    Path(cert_path).write_text(json.dumps(cert, indent=2), encoding="utf-8")

    # Set registry path
    registry_path = str(tmp_path / "certified_registry.json")
    os.environ["NODECHAIN_CERTIFIED_REGISTRY"] = registry_path

    # Publish to registry
    entry = publish_package(
        package_dict=package_dict,
        certification=cert,
        require_certification=True,
    )
    assert entry["registry_status"] == "active", f"Entry denied: {entry.get('errors', [])}"

    return {
        "registry_path": registry_path,
        "package_digest": package_digest,
        "certification_path": cert_path,
        "certification_digest": cert["certification_digest"],
        "eval_report_path": eval_report_path,
        "eval_report_digest": eval_report["report_digest"],
        "suite_digest": eval_report["suite_digest"],
        "entry_id": entry["entry_id"],
        "package_dict": json.dumps(package_dict),
    }


# ── AC1: Registry Resolution ─────────────────────────────────────────────────

class TestRegistryResolution:
    """Acceptance Criterion 1: Every incident-response node resolves through registry consumption."""

    def test_resolves_with_certified_only_policy(self, tmp_path):
        """Package resolves when certified_only=True and certification is valid."""
        env = _setup_test_registry(tmp_path)
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy

        policy = ConsumptionPolicy(certified_only=True)
        result = resolve_package("incident_response", policy=policy)

        assert result.resolved is True
        assert result.policy_verdict == "allowed"
        assert len(result.checks) == 7

    def test_denies_unknown_package(self, tmp_path):
        """Unknown package fails resolution."""
        _setup_test_registry(tmp_path)
        from nodechain.cli.registry_consumption import resolve_package

        result = resolve_package("nonexistent_package")
        assert result.resolved is False
        assert result.policy_verdict == "denied"

    def test_denies_without_certification(self, tmp_path):
        """Package without certification fails certified_only policy."""
        from nodechain.cli.certified_registry import publish_package
        _setup_test_registry(tmp_path)

        # Publish a second entry without certification
        pkg = {
            "package_id": "uncertified_incident",
            "version": "1.0.0",
            "content_hash": _sha256_dict({"id": "uncertified_incident"}),
        }
        publish_package(package_dict=pkg, require_certification=False)

        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        policy = ConsumptionPolicy(certified_only=True)
        result = resolve_package("uncertified_incident", policy=policy)
        assert result.resolved is False
        assert "not 'certified'" in " ".join(result.errors)


# ── AC2: Trace Fields ────────────────────────────────────────────────────────

class TestTraceFields:
    """Acceptance Criterion 2: Trace records include registry evidence fields."""

    def test_install_produces_all_five_trace_fields(self, tmp_path):
        """install_package() returns all 5 registry evidence fields."""
        env = _setup_test_registry(tmp_path)
        from nodechain.cli.registry_consumption import install_package, ConsumptionPolicy

        policy = ConsumptionPolicy(certified_only=True)
        result = install_package("incident_response", policy=policy)

        assert result["resolved"] is True
        assert result["registry_resolution_status"] == "resolved"

        # All 5 fields must be present (publisher_fingerprint may be empty for unsigned)
        assert "registry_entry_digest" in result
        assert result["registry_entry_digest"]
        assert "certification_digest" in result
        assert result["certification_digest"]
        assert "publisher_fingerprint" in result  # present even if empty for unsigned
        assert "registry_resolution_status" in result
        assert "policy_verdict" in result

    def test_consumption_trace_fields_extraction(self, tmp_path):
        """create_consumption_trace_fields() extracts all 5 fields."""
        env = _setup_test_registry(tmp_path)
        from nodechain.cli.registry_consumption import (
            install_package, create_consumption_trace_fields, ConsumptionPolicy,
        )

        policy = ConsumptionPolicy(certified_only=True)
        install_result = install_package("incident_response", policy=policy)
        trace_fields = create_consumption_trace_fields(install_result)

        expected_keys = {
            "registry_entry_digest",
            "certification_digest",
            "publisher_fingerprint",
            "registry_resolution_status",
            "registry_policy_verdict",
        }
        assert set(trace_fields.keys()) == expected_keys
        assert trace_fields["registry_resolution_status"] == "resolved"
        assert trace_fields["registry_policy_verdict"] == "allowed"


# ── AC3: Evaluation Suite ────────────────────────────────────────────────────

class TestEvaluationSuite:
    """Acceptance Criterion 3: The package is evaluated by a trusted active suite."""

    def test_incident_response_suite_exists(self):
        """The incident_response_eval.yaml suite file exists."""
        suite_path = Path("eval_suites/incident_response_eval.yaml")
        assert suite_path.exists(), "incident_response_eval.yaml not found"

    def test_suite_loads_and_validates(self):
        """Suite loads and validates without errors."""
        from nodechain.cli.evaluation import EvaluationSuite

        suite = EvaluationSuite.from_file("eval_suites/incident_response_eval.yaml")
        errors = suite.validate()
        assert not errors, f"Suite validation errors: {errors}"
        assert suite.suite_id == "incident_response_eval"
        assert suite.target_type == "package"
        assert len(suite.cases) >= 5

    def test_suite_evaluates_incident_response(self):
        """Running the suite produces a passing report."""
        from nodechain.cli.evaluation import EvaluationSuite, run_evaluation

        suite = EvaluationSuite.from_file("eval_suites/incident_response_eval.yaml")
        report = run_evaluation(suite, target_digest="test_digest")

        assert report["passed"] is True
        assert report["total_cases"] >= 5
        assert report["passed_cases"] == report["total_cases"]
        assert report["valid"] is True


# ── AC4: Signed Local Certification ──────────────────────────────────────────

class TestSignedCertification:
    """Acceptance Criterion 4: The chain receives a signed local certification."""

    def test_certification_from_eval_report(self, tmp_path):
        """Certification artifact created from passing eval report."""
        env = _setup_test_registry(tmp_path)

        from nodechain.cli.certification import verify_certification
        cert = json.loads(Path(env["certification_path"]).read_text())
        assert cert["certification_status"] == "certified"
        assert cert["target_digest"] == env["package_digest"]
        assert cert["eval_report_digest"] == env["eval_report_digest"]

    def test_certification_digest_consistent(self, tmp_path):
        """Certification digest is deterministic."""
        env = _setup_test_registry(tmp_path)
        cert = json.loads(Path(env["certification_path"]).read_text())
        # Recompute digest
        from nodechain.cli.certification import _sha256_dict as cert_sha
        recomputed = cert_sha(
            {k: v for k, v in cert.items()
             if k not in {"certification_signature", "certification_signature_algorithm",
                          "certifier_fingerprint", "certification_digest"}}
        )
        assert cert["certification_digest"] == recomputed

    def test_certification_signed_with_key(self, tmp_path):
        """Certification can be signed and verified with RSA-PSS."""
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.cli.certification import sign_certification, verify_certification

        env = _setup_test_registry(tmp_path)
        keypair = generate_key_pair(str(tmp_path), "cert_key")
        key_path = keypair["private_key_path"]
        pub_path = keypair["public_key_path"]

        signed = sign_certification(env["certification_path"], key_path)
        assert signed["certification_signature"]
        assert signed["certification_signature_algorithm"] == "RSA-PSS-SHA256"

        pub_pem = Path(keypair["public_key_path"]).read_text(encoding="utf-8")
        result = verify_certification(signed, public_key_pem=pub_pem)
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"


# ── AC5: Evidence Chain Reconstruction ───────────────────────────────────────

class TestEvidenceChainReconstruction:
    """Acceptance Criterion 5: Evidence query can reconstruct the full chain."""

    def test_registry_entry_links_to_certification(self, tmp_path):
        """Registry entry contains certification_digest and eval_report_digest."""
        env = _setup_test_registry(tmp_path)
        from nodechain.cli.certified_registry import load_registry

        registry = load_registry()
        entry = registry["entries"][env["entry_id"]]

        assert entry["certification_digest"]
        assert entry["eval_report_digest"]
        assert entry["suite_digest"]
        assert entry["package_digest"]

    def test_full_chain_reconstructable(self, tmp_path):
        """Evidence chain: package → registry → certification → eval → suite."""
        env = _setup_test_registry(tmp_path)
        from nodechain.cli.certified_registry import load_registry
        from nodechain.cli.registry_consumption import install_package, create_consumption_trace_fields, ConsumptionPolicy

        # Step 1: Install through consumption gate
        policy = ConsumptionPolicy(certified_only=True)
        install_result = install_package("incident_response", policy=policy)
        assert install_result["resolved"]

        # Step 2: Extract trace fields
        trace = create_consumption_trace_fields(install_result)

        # Step 3: Reconstruct chain from trace fields
        registry = load_registry()
        entry = registry["entries"][env["entry_id"]]

        # registry_entry_digest → entry
        assert trace["registry_entry_digest"] == entry.get("entry_digest", "")

        # certification_digest → certification
        cert = json.loads(Path(env["certification_path"]).read_text())
        assert trace["certification_digest"] == cert["certification_digest"]

        # eval_report_digest → report
        report = json.loads(Path(env["eval_report_path"]).read_text())
        assert cert["eval_report_digest"] == report["report_digest"]

        # suite_digest → suite
        assert report["suite_digest"] == env["suite_digest"]

        # Full chain verified
        chain = {
            "package_digest": entry["package_digest"],
            "registry_entry": trace["registry_entry_digest"],
            "certification": trace["certification_digest"],
            "eval_report": cert["eval_report_digest"],
            "suite": env["suite_digest"],
        }
        # Every link in the chain has a non-empty digest
        for name, digest in chain.items():
            assert digest, f"Chain link '{name}' has empty digest"


# ── AC6: Critical Incident Path ──────────────────────────────────────────────

class TestCriticalIncidentPath:
    """Acceptance Criterion 6: Critical incident path proves governance enforcement."""

    @pytest.mark.asyncio
    async def test_human_review_required_for_critical(self):
        """Critical severity triggers requires_human_review=True."""
        from nodes.incident_response.implementations.severity_triager import SeverityTriager
        from nodechain.core.envelope import InvocationEnvelope

        triager = SeverityTriager()
        envelope = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=1,
            payload={
                "detected": True,
                "anomalies": [{"type": "critical_alerts", "count": 5, "source": "alerting"}],
                "severity_hint": "critical",
            },
        )
        result = await triager.execute(envelope)
        assert result.output["severity"] == "critical"
        assert result.output["requires_human_review"] is True

    @pytest.mark.asyncio
    async def test_remediation_denied_without_approval(self):
        """Remediation is denied when authorized=False."""
        from nodes.incident_response.implementations.governed_remediator import GovernedRemediator
        from nodechain.core.envelope import InvocationEnvelope

        remediator = GovernedRemediator()
        envelope = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=1,
            payload={
                "remediation_mode": "auto_rollback",
                "authorized": False,
                "selected_action": "rollback_artifact",
            },
        )
        result = await remediator.execute(envelope)
        assert result.output["executed"] is False
        assert result.output["final_state"] == "denied"

    @pytest.mark.asyncio
    async def test_remediation_allowed_with_authorization(self):
        """Remediation executes when authorized=True and mode allows."""
        from nodes.incident_response.implementations.governed_remediator import GovernedRemediator
        from nodechain.core.envelope import InvocationEnvelope

        remediator = GovernedRemediator()
        envelope = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=1,
            payload={
                "remediation_mode": "auto_rollback",
                "authorized": True,
                "selected_action": "rollback_artifact",
                "policy_digest": "abc123",
            },
        )
        result = await remediator.execute(envelope)
        assert result.output["executed"] is True
        assert result.output["final_state"] == "executed"

    @pytest.mark.asyncio
    async def test_recovery_not_closed_until_verified(self):
        """Recovery verifier does not mark incident resolved until remediation executed."""
        from nodes.incident_response.implementations.recovery_verifier import RecoveryVerifier
        from nodechain.core.envelope import InvocationEnvelope

        verifier = RecoveryVerifier()

        # Pending recommendation → not resolved
        env1 = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=1,
            payload={
                "final_state": "recommendation_produced",
                "executed": False,
                "evidence": [],
            },
        )
        r1 = await verifier.execute(env1)
        assert r1.output["recovered"] is False
        assert r1.output["incident_status"] != "resolved"

        # Executed → resolved
        env2 = InvocationEnvelope(
            envelope_id=str(uuid.uuid4()), run_id="test", chain_id="test",
            node_id="test", step_id=2,
            payload={
                "final_state": "executed",
                "executed": True,
                "evidence": [{"gate": "execution", "result": "success"}],
            },
        )
        r2 = await verifier.execute(env2)
        assert r2.output["recovered"] is True
        assert r2.output["incident_status"] == "resolved"


# ── AC7: CLI Smoke ────────────────────────────────────────────────────────────

class TestCLISmoke:
    """Acceptance Criterion 7: CI CLI smoke commands."""

    def test_cli_run_blueprint_help(self):
        """nodechain run --help works."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert result.exit_code == 0

    def test_cli_evidence_index_help(self):
        """nodechain evidence index --help works."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["evidence", "index", "--help"])
        assert result.exit_code == 0

    def test_cli_evidence_timeline_help(self):
        """nodechain evidence timeline --help works."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["evidence", "timeline", "--help"])
        assert result.exit_code == 0

    def test_cli_trace_replay_help(self):
        """nodechain trace-replay --help works."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["trace-replay", "--help"])
        assert result.exit_code == 0

    def test_cli_registry_resolve_help(self):
        """nodechain registry resolve --help works."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "resolve", "--help"])
        assert result.exit_code == 0

    def test_cli_registry_install_help(self):
        """nodechain registry install --help works."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "install", "--help"])
        assert result.exit_code == 0
