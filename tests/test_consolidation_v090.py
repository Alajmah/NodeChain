"""Tests for v0.9.0 consolidation pass.

AC1: Final exit-code table consistent — no stale sys.exit(1) outside EXIT_RECONCILE_ERRORS.
AC2: Trust demo scripts exist.
AC3: README has Trust Model section.
AC4: Version is 0.9.0 everywhere.
AC5: 1146 tests remain green.
"""

import re
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestExitCodeConsistency:
    """AC1: All CLI exit codes use structured constants."""

    def test_no_stale_sys_exit_1_in_cli(self):
        """No raw sys.exit(1) except documented EXIT_RECONCILE_ERRORS in sdk_cli."""
        cli_dir = PROJECT_ROOT / "src" / "nodechain" / "cli"
        stale = []
        for py in cli_dir.glob("*.py"):
            src = py.read_text(encoding="utf-8")
            for i, line in enumerate(src.splitlines(), 1):
                if "sys.exit(1)" in line and "EXIT_RECONCILE_ERRORS" not in line:
                    stale.append(f"{py.name}:{i}: {line.strip()}")
        # Only sdk_cli.py line 139 is allowed (documented lockfile drift)
        stale = [s for s in stale if "Lockfile drift" not in s]
        assert len(stale) == 0, f"Stale sys.exit(1) found:\n{chr(10).join(stale)}"

    def test_exit_code_constants_defined(self):
        from nodechain.cli.exit_codes import (
            EXIT_OK, EXIT_NOT_FOUND, EXIT_RECONCILE_ERRORS,
            EXIT_RECONCILE_RECOVERY, EXIT_RUN_VALIDATION,
            EXIT_RUN_PAUSED, EXIT_RUN_FAILED,
            EXIT_RESUME_NOT_RESUMABLE, EXIT_RESUME_FAILED,
            EXIT_TRUST_VIOLATION,
        )
        assert EXIT_OK == 0
        assert EXIT_NOT_FOUND == 2
        assert EXIT_RECONCILE_ERRORS == 1
        assert EXIT_RECONCILE_RECOVERY == 3
        assert EXIT_RUN_VALIDATION == 10
        assert EXIT_RUN_PAUSED == 11
        assert EXIT_RUN_FAILED == 12
        assert EXIT_RESUME_NOT_RESUMABLE == 13
        assert EXIT_RESUME_FAILED == 14
        assert EXIT_TRUST_VIOLATION == 15

    def test_all_exit_codes_in_readme(self):
        """README exit code table includes all 10 codes."""
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        for code in [0, 1, 2, 3, 10, 11, 12, 13, 14, 15]:
            assert f"| {code} |" in readme, f"Exit code {code} missing from README table"


class TestDemoScript:
    """AC2: Trust demo scripts exist."""

    def test_demo_trust_sh_exists(self):
        assert (PROJECT_ROOT / "examples" / "demo_trust.sh").exists()

    def test_demo_trust_bat_exists(self):
        assert (PROJECT_ROOT / "examples" / "demo_trust.bat").exists()

    def test_demo_has_trust_check(self):
        src = (PROJECT_ROOT / "examples" / "demo_trust.sh").read_text(encoding="utf-8")
        assert "--trust-check" in src
        assert "--locked" in src
        assert "--strict" in src


class TestReadmeTrustModel:
    """AC3: README has Trust Model section."""

    def test_readme_has_trust_model(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        assert "## Trust Model" in readme

    def test_readme_has_trust_levels(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        assert "built_in" in readme
        assert "local_trusted" in readme
        assert "local_untrusted" in readme
        assert "remote_untrusted" in readme

    def test_readme_has_invariant_codes(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        assert "INV-001" in readme
        assert "INV-005" in readme

    def test_readme_has_honest_boundaries(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        assert "Honest Boundaries" in readme or "does NOT" in readme


class TestVersionConsistency:
    """AC4: Version is 0.9.0 everywhere."""

    def test_init_version(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_pyproject_version(self):
        toml = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert 'version = "3.6.0"' in toml

    def test_release_guard_version(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "test_release_guard",
            PROJECT_ROOT / "tests" / "test_release_guard.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.EXPECTED_VERSION == "3.6.0"
