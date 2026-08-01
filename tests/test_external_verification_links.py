"""v2.87 — External Verification Pack: doc-link + command-existence smoke test.

Validates that docs/external-verification.md does not rot:
- All referenced documents exist
- All referenced scripts/commands exist
- The claims-vs-evidence table references real test files
- The blueprint referenced exists

This is a structural check, not a behavioral test. It catches drift (deleted
docs, renamed scripts) without re-running the full quickstart.
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestExternalVerificationLinks:
    """Every reference in docs/external-verification.md must resolve."""

    def test_referenced_docs_exist(self):
        """All documents linked from external-verification.md must exist."""
        expected_docs = [
            "docs/5-minute-local-proof.md",
            "docs/ci.md",
            "docs/native_sandbox_verification.md",
            "docs/native_sandbox_test_runner.md",
            "VISION.md",
        ]
        for doc in expected_docs:
            assert (REPO_ROOT / doc).exists(), f"referenced doc missing: {doc}"

    def test_referenced_scripts_exist(self):
        """Scripts referenced in the verification commands must exist."""
        expected_scripts = [
            "scripts/validate_schemas.py",
            "scripts/run_full_suite_sharded.py",
        ]
        for script in expected_scripts:
            assert (REPO_ROOT / script).exists(), f"referenced script missing: {script}"

    def test_referenced_tests_exist(self):
        """Test files referenced in the claims-vs-evidence table must exist."""
        expected_tests = [
            "tests/test_quickstart_smoke.py",
            "tests/test_cli_characterization.py",
            "tests/test_state_manager_characterization.py",
            "tests/test_native_sandbox_enforcement.py",
            "tests/test_release_guard.py",
        ]
        for test in expected_tests:
            assert (REPO_ROOT / test).exists(), f"referenced test missing: {test}"

    def test_referenced_blueprint_exists(self):
        """The echo demo blueprint referenced in the quickstart must exist."""
        assert (REPO_ROOT / "blueprints/echo_demo_v1.yaml").exists()

    def test_external_verification_doc_exists(self):
        """The external verification doc itself must exist."""
        assert (REPO_ROOT / "docs/external-verification.md").exists()

    def test_external_verification_doc_mentions_key_sections(self):
        """The doc must contain the critical structural sections."""
        content = (REPO_ROOT / "docs/external-verification.md").read_text(encoding="utf-8")
        for required_section in [
            "Claims vs Evidence",
            "What this does NOT prove",
            "Verification commands",
            "Verification language",
        ]:
            assert required_section in content, (
                f"external-verification.md missing required section: {required_section}"
            )
