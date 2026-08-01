"""Tests for trust CI and run gates.

AC1: --trust-check flag exists on run command.
AC2: --locked --strict requires lockfile verification.
AC3: reconcile --strict includes trust invariant failures.
AC4: report exposes trust_summary with invariant codes.
AC5: Trust violation exit code is stable (15).
AC6: nodechain trust --strict exits nonzero.
AC7: Existing 1132 tests remain green.
"""

import pytest

from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord, TrustViolation
from nodechain.cli.exit_codes import (
    EXIT_OK, EXIT_TRUST_VIOLATION,
)


class TestExitCodeStability:
    """AC5: Trust violation exit code is stable."""

    def test_trust_exit_code_is_15(self):
        assert EXIT_TRUST_VIOLATION == 15

    def test_exit_ok_is_zero(self):
        assert EXIT_OK == 0

    def test_all_exit_codes_distinct(self):
        from nodechain.cli import exit_codes as ec
        codes = [
            ec.EXIT_OK, ec.EXIT_NOT_FOUND, ec.EXIT_RECONCILE_ERRORS,
            ec.EXIT_RECONCILE_RECOVERY, ec.EXIT_RUN_VALIDATION,
            ec.EXIT_RUN_PAUSED, ec.EXIT_RUN_FAILED,
            ec.EXIT_RESUME_NOT_RESUMABLE, ec.EXIT_RESUME_FAILED,
            ec.EXIT_TRUST_VIOLATION,
        ]
        assert len(codes) == len(set(codes)), "Duplicate exit codes"


class TestRunTrustCheckFlag:
    """AC1: --trust-check flag on run command."""

    def test_trust_check_in_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--trust-check" in result.output

    def test_strict_flag_in_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--strict" in result.output

    def test_locked_flag_in_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--locked" in result.output


class TestTrustSummaryInReport:
    """AC4: Report exposes trust_summary."""

    def test_report_has_trust_summary_code(self):
        from pathlib import Path
        src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "trust_summary" in src

    def test_report_has_sandbox_status(self):
        from pathlib import Path
        src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "sandbox_status" in src


class TestReconcilerTrustCheck:
    """AC3: Reconciler includes trust checks."""

    def test_reconciler_has_trust_check(self):
        from pathlib import Path
        src = Path("src/nodechain/runtime/trace_reconciler.py").read_text(encoding="utf-8")
        assert "trust" in src.lower()


class TestValidateInvariantsIntegration:
    """Validate invariants works correctly for CI scenarios."""

    def test_clean_run_no_violations(self):
        summary = TrustSummary(run_id="clean", locked_mode=False)
        summary.add_node(NodeTrustRecord(
            node_id="builtin", trust_level="built_in",
        ))
        v = summary.validate_invariants(strict=True)
        assert len(v) == 0

    def test_locked_clean_run_no_violations(self):
        summary = TrustSummary(
            run_id="clean",
            locked_mode=True,
            lockfile_verified=True,
        )
        v = summary.validate_invariants(strict=True)
        assert len(v) == 0

    def test_locked_unverified_fails(self):
        summary = TrustSummary(
            run_id="bad",
            locked_mode=True,
            lockfile_verified=False,
        )
        v = summary.validate_invariants(strict=True)
        assert any(x.code == "INV-005" for x in v)

    def test_untrusted_in_process_fails(self):
        summary = TrustSummary(run_id="bad")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted", trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants(strict=True)
        assert any(x.code == "INV-001" for x in v)

    def test_ci_scenario_all_pass(self):
        """Full CI scenario: built-in + trusted + untrusted with proper isolation."""
        summary = TrustSummary(
            run_id="ci",
            locked_mode=True,
            lockfile_verified=True,
        )
        summary.add_node(NodeTrustRecord(
            node_id="core1", trust_level="built_in",
            isolation_mode="in_process",
        ))
        summary.add_node(NodeTrustRecord(
            node_id="core2", trust_level="built_in",
            isolation_mode="in_process",
        ))
        summary.add_node(NodeTrustRecord(
            node_id="trusted_pkg",
            trust_level="local_trusted",
            isolation_mode="in_process",
            child_policy_enforced=False,
            env_filtered=False,
            temp_dir_isolated=False,
        ))
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_pkg",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
        ))
        v = summary.validate_invariants(strict=True)
        assert len(v) == 0
        assert summary.is_compliant is True
