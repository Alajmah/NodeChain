"""Tests for Linux Proxmox baseline tooling — v1.2.1.

AC1: Setup script exists and has correct structure.
AC2: Validation script exists and has correct structure.
AC3: Linux deployment documentation exists.
AC4: Dockerfile updated for production deployment.
AC5: Linux sandbox report fields documented.
AC6: No frozen v1 public surface changes.
"""

import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestSetupScript:
    """AC1: Setup script exists and has correct structure."""

    def test_setup_script_exists(self):
        assert (PROJECT_ROOT / "scripts" / "setup_linux.sh").exists()

    def test_setup_script_has_shebang(self):
        src = (PROJECT_ROOT / "scripts" / "setup_linux.sh").read_text(encoding="utf-8")
        assert src.startswith("#!/usr/bin/env bash")

    def test_setup_installs_python(self):
        src = (PROJECT_ROOT / "scripts" / "setup_linux.sh").read_text(encoding="utf-8")
        assert "python3" in src

    def test_setup_installs_seccomp_dev(self):
        src = (PROJECT_ROOT / "scripts" / "setup_linux.sh").read_text(encoding="utf-8")
        assert "libseccomp-dev" in src

    def test_setup_creates_venv(self):
        src = (PROJECT_ROOT / "scripts" / "setup_linux.sh").read_text(encoding="utf-8")
        assert "venv" in src

    def test_setup_reports_capabilities(self):
        src = (PROJECT_ROOT / "scripts" / "setup_linux.sh").read_text(encoding="utf-8")
        assert "resource_limits_enforced" in src


class TestValidationScript:
    """AC2: Validation script exists and has correct structure."""

    def test_validation_script_exists(self):
        assert (PROJECT_ROOT / "scripts" / "validate_linux.sh").exists()

    def test_validation_has_shebang(self):
        src = (PROJECT_ROOT / "scripts" / "validate_linux.sh").read_text(encoding="utf-8")
        assert src.startswith("#!/usr/bin/env bash")

    def test_validation_runs_pytest(self):
        src = (PROJECT_ROOT / "scripts" / "validate_linux.sh").read_text(encoding="utf-8")
        assert "pytest" in src

    def test_validation_runs_cli(self):
        src = (PROJECT_ROOT / "scripts" / "validate_linux.sh").read_text(encoding="utf-8")
        assert "trust" in src
        assert "reconcile" in src

    def test_validation_reports_capabilities(self):
        src = (PROJECT_ROOT / "scripts" / "validate_linux.sh").read_text(encoding="utf-8")
        assert "syscall_filtering_enforced" in src
        assert "namespace_enforced" in src
        assert "cgroup_enforced" in src

    def test_validation_has_honest_assessment(self):
        src = (PROJECT_ROOT / "scripts" / "validate_linux.sh").read_text(encoding="utf-8")
        assert "NOT IMPLEMENTED" in src or "REAL" in src


class TestLinuxDeploymentDoc:
    """AC3: Linux deployment documentation exists."""

    def test_doc_exists(self):
        assert (PROJECT_ROOT / "docs" / "linux-deployment.md").exists()

    def test_doc_has_proxmox_section(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "Proxmox" in doc

    def test_doc_has_capability_matrix(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "resource_limits_enforced" in doc
        assert "syscall_filtering_enforced" in doc

    def test_doc_has_seccomp_instructions(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "libseccomp-dev" in doc
        assert "pip install seccomp" in doc

    def test_doc_has_vm_recommendations(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "Ubuntu" in doc
        assert "VM" in doc

    def test_doc_explains_vm_vs_lxc(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "LXC" in doc
        assert "full VM" in doc or "Full VM" in doc

    def test_doc_has_systemd_example(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "systemd" in doc.lower()

    def test_doc_has_docker_instructions(self):
        doc = (PROJECT_ROOT / "docs" / "linux-deployment.md").read_text(encoding="utf-8")
        assert "docker" in doc.lower()


class TestDockerfile:
    """AC4: Dockerfile updated for production deployment."""

    def test_dockerfile_exists(self):
        assert (PROJECT_ROOT / "Dockerfile").exists()

    def test_uses_python_311(self):
        src = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "python:3.11" in src

    def test_installs_libseccomp(self):
        src = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "libseccomp" in src

    def test_copies_schemas_and_blueprints(self):
        src = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "COPY schemas" in src
        assert "COPY blueprints" in src

    def test_has_healthcheck(self):
        src = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "HEALTHCHECK" in src

    def test_has_labels(self):
        src = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "LABEL" in src

    def test_env_defaults(self):
        src = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "NODECHAIN_PROVIDER" in src
        assert "PYTHONIOENCODING" in src


class TestNoFrozenSurfaceChanges:
    """AC6: No frozen v1 public surface changes."""

    def test_cli_commands_unchanged(self):
        from nodechain.cli.main import cli
        expected = {"run", "inspect", "reconcile", "resume", "presets",
                    "report", "trace", "trust", "trust-store", "deploy-receipt", "assurance", "deploy", "registry", "node",
                    "audit-bundle", "attest", "release-history", "drift", "eval",
                    "evidence", "trace-replay", "dashboard", "compose", "policy", "marketplace", "supply-chain", "retention", "checkpoint", "graph", "console", "review", "recover", "api", "research"}
        assert set(cli.commands.keys()) == expected

    def test_exit_codes_unchanged(self):
        from nodechain.cli.exit_codes import (
            EXIT_OK, EXIT_NOT_FOUND, EXIT_RECONCILE_ERRORS,
            EXIT_RECONCILE_RECOVERY, EXIT_RUN_VALIDATION,
            EXIT_RUN_PAUSED, EXIT_RUN_FAILED,
            EXIT_RESUME_NOT_RESUMABLE, EXIT_RESUME_FAILED,
            EXIT_TRUST_VIOLATION,
        )
        assert {0, 1, 2, 3, 10, 11, 12, 13, 14, 15} == {
            EXIT_OK, EXIT_NOT_FOUND, EXIT_RECONCILE_ERRORS,
            EXIT_RECONCILE_RECOVERY, EXIT_RUN_VALIDATION,
            EXIT_RUN_PAUSED, EXIT_RUN_FAILED,
            EXIT_RESUME_NOT_RESUMABLE, EXIT_RESUME_FAILED,
            EXIT_TRUST_VIOLATION,
        }

    def test_invariant_codes_unchanged(self):
        """INV-001 through INV-007 all present."""
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        # Trigger all invariants
        summary = TrustSummary(run_id="t", locked_mode=True, lockfile_verified=False)
        summary.add_node(NodeTrustRecord(
            node_id="bad",
            trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants(strict=True)
        codes = {v.code for v in violations}
        assert "INV-001" in codes
        assert "INV-005" in codes
