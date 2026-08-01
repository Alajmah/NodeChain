"""v2.90 — Release Evidence Index: doc-link + structural-section smoke test.

Validates that docs/release-evidence.md does not rot:
- All referenced documents, scripts, and tests exist
- The document contains the required structural sections
- The evidence-path table references real artifacts
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestReleaseEvidenceLinks:
    """Every reference in docs/release-evidence.md must resolve."""

    def test_release_evidence_doc_exists(self):
        assert (REPO_ROOT / "docs/release-evidence.md").exists()

    def test_referenced_docs_exist(self):
        expected_docs = [
            "docs/external-verification.md",
            "docs/5-minute-local-proof.md",
            "docs/ci.md",
            "docs/native_sandbox_verification.md",
            "docs/native_sandbox_test_runner.md",
        ]
        for doc in expected_docs:
            assert (REPO_ROOT / doc).exists(), f"referenced doc missing: {doc}"

    def test_referenced_scripts_exist(self):
        expected_scripts = [
            "scripts/run_external_verification.py",
            "scripts/run_sandbox_verification.py",
            "scripts/run_full_suite_sharded.py",
            "scripts/validate_schemas.py",
        ]
        for script in expected_scripts:
            assert (REPO_ROOT / script).exists(), f"referenced script missing: {script}"

    def test_referenced_tests_exist(self):
        expected_tests = [
            "tests/test_quickstart_smoke.py",
            "tests/test_state_manager_characterization.py",
            "tests/test_cli_characterization.py",
            "tests/test_external_verification_links.py",
            "tests/test_native_sandbox_enforcement.py",
        ]
        for test in expected_tests:
            assert (REPO_ROOT / test).exists(), f"referenced test missing: {test}"

    def test_required_sections_present(self):
        content = (REPO_ROOT / "docs/release-evidence.md").read_text(encoding="utf-8")
        for section in [
            "Evidence Paths",
            "Claims vs Evidence",
            "What this does NOT prove",
            "Verification language",
            "Regenerating all evidence",
        ]:
            assert section in content, (
                f"release-evidence.md missing required section: {section}"
            )
