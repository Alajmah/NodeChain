"""Operator Workbench tests (v2.67.3).

Tests the enhanced operator CLI commands: profiles show (full governance),
preview (dry-run authorization), evidence browser, inspect evidence section,
and dashboard. Uses synthetic persisted runs — no real network or LLM.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    return CliRunner()


# ── profiles show — full governance display ───────────────────────────────

class TestProfilesShowFull:
    def test_team_default_shows_action_matrix(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "team-default"])
        assert result.exit_code == 0
        assert "Action Matrix" in result.output
        assert "resume" in result.output

    def test_break_glass_shows_admin_only(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "break-glass"])
        assert result.exit_code == 0
        # break-glass: operator and finance should be denied
        assert "✗" in result.output

    def test_shows_budget_governance(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "regulated"])
        assert result.exit_code == 0
        assert "Budget Governance" in result.output

    def test_shows_override_governance(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "break-glass"])
        assert result.exit_code == 0
        assert "Override Governance" in result.output

    def test_shows_audit_governance(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "regulated"])
        assert result.exit_code == 0
        assert "Audit Governance" in result.output

    def test_shows_batch_governance(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "team-default"])
        assert result.exit_code == 0
        assert "Batch Governance" in result.output

    def test_shows_per_action_requirements(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "regulated"])
        assert result.exit_code == 0
        assert "Per-Action Requirements" in result.output

    def test_unknown_profile_errors(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "profiles", "show", "nonexistent"])
        assert result.exit_code == 0  # Command exits 0 but prints error
        assert "nonexistent" in result.output.lower() or "unknown" in result.output.lower() or "Available" in result.output


# ── preview — dry-run authorization ───────────────────────────────────────

class TestPreviewCommand:
    def test_preview_help_exists(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "preview", "--help"])
        assert result.exit_code == 0
        assert "dry-run" in result.output.lower() or "preview" in result.output.lower()

    def test_preview_unknown_run_errors(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, [
            "recover", "preview", "nonexistent-run", "resume",
            "--db", "data/test_workbench.db",
        ])
        # Should report not found
        assert "No saved state" in result.output or result.exit_code != 0

    def test_preview_invalid_action(self, runner, tmp_path):
        """Preview with invalid action should fail cleanly, not crash."""
        from nodechain.cli.main import cli
        db = str(tmp_path / "test.db")
        # Create a minimal run so we get past the "not found" check
        from nodechain.core.state import StateManager, ChainState
        sm = StateManager(db_path=db)
        state = ChainState(run_id="test-run", chain_id="test-chain")
        state.status = "failed"
        sm.save(state)

        result = runner.invoke(cli, [
            "recover", "preview", "test-run", "not_a_real_action",
            "--db", db,
        ])
        assert "Unknown action" in result.output or "Allowed" in result.output

    def test_preview_resume_on_failed_run(self, runner, tmp_path):
        """Preview resume on a failed run should not crash and show a decision."""
        from nodechain.cli.main import cli
        db = str(tmp_path / "test.db")
        from nodechain.core.state import StateManager, ChainState
        sm = StateManager(db_path=db)
        state = ChainState(run_id="test-run", chain_id="test-chain")
        state.status = "failed"
        sm.save(state)

        result = runner.invoke(cli, [
            "recover", "preview", "test-run", "resume",
            "--db", db, "--role", "operator",
        ])
        assert result.exit_code == 0
        assert "ALLOWED" in result.output or "DENIED" in result.output

    def test_preview_budget_denied_for_operator(self, runner, tmp_path):
        """Operator role should be denied budget increase (RBAC)."""
        from nodechain.cli.main import cli
        db = str(tmp_path / "test.db")
        from nodechain.core.state import StateManager, ChainState
        sm = StateManager(db_path=db)
        state = ChainState(run_id="test-run", chain_id="test-chain")
        state.status = "failed"
        sm.save(state)

        result = runner.invoke(cli, [
            "recover", "preview", "test-run", "approve_budget_increase",
            "--db", db, "--role", "operator", "--new-budget", "100",
        ])
        assert result.exit_code == 0
        assert "DENIED" in result.output


# ── evidence — dedicated evidence browser ─────────────────────────────────

class TestEvidenceCommand:
    def test_evidence_help_exists(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "evidence", "--help"])
        assert result.exit_code == 0
        assert "evidence" in result.output.lower()

    def test_evidence_unknown_run_errors(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, [
            "recover", "evidence", "nonexistent-run",
            "--db", "data/test_workbench.db",
        ])
        assert "No saved state" in result.output or result.exit_code != 0

    def test_evidence_json_output_for_unknown_run(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, [
            "recover", "evidence", "nonexistent-run",
            "--db", "data/test_workbench.db", "--json",
        ])
        # Should report not found even in JSON mode
        assert "No saved state" in result.output or result.exit_code != 0


# ── dashboard — unified view ─────────────────────────────────────────────

class TestDashboardCommand:
    def test_dashboard_help_exists(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, ["recover", "dashboard", "--help"])
        assert result.exit_code == 0
        assert "dashboard" in result.output.lower()

    def test_dashboard_empty_db(self, runner, tmp_path):
        """Dashboard on a fresh DB with no runs should not crash."""
        from nodechain.cli.main import cli
        db = str(tmp_path / "empty.db")
        result = runner.invoke(cli, ["recover", "dashboard", "--db", db])
        assert result.exit_code == 0
        assert "No runs" in result.output or "Operator Dashboard" in result.output


# ── inspect — evidence section ────────────────────────────────────────────

class TestInspectEvidenceSection:
    def test_inspect_unknown_run(self, runner):
        from nodechain.cli.main import cli
        result = runner.invoke(cli, [
            "recover", "inspect", "nonexistent-run",
            "--db", "data/test_workbench.db",
        ])
        assert "No saved state" in result.output
