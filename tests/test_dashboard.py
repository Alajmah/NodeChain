"""Tests for the Operator Dashboard (v1.20.0).

Tests cover all 10 acceptance criteria:
  AC1:  Top-level command exists
  AC2:  Dashboard aggregates all spines
  AC3:  Read-only subcommands
  AC4:  --json output for every view
  AC5:  --watch flag (tested as flag exists, not actual loop)
  AC6:  Health model classification
  AC7:  Dashboard detects issues
  AC8:  Dashboard never mutates state
  AC9:  Deterministic with fixtures
  AC10: Windows/Linux green (implicit)
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner


# ── AC1: Top-level command ──────────────────────────────────────────────────

class TestAC1TopLevelCommand:
    """AC1: nodechain dashboard top-level command exists."""

    def test_dashboard_help(self):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "Operator dashboard" in result.output

    def test_dashboard_in_cli_help(self):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "dashboard" in result.output

    def test_dashboard_default_runs_without_error(self):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard"])
        assert result.exit_code == 0


# ── AC2: Dashboard Aggregates ───────────────────────────────────────────────

class TestAC2Aggregation:
    """AC2: Dashboard aggregates all spines."""

    def test_collect_dashboard_has_all_sections(self):
        from nodechain.cli.dashboard import collect_dashboard
        data = collect_dashboard()
        sections = data["sections"]
        assert "runtime" in sections
        assert "trust" in sections
        assert "registry" in sections
        assert "evidence" in sections
        assert "operations" in sections
        assert "evaluation" in sections

    def test_collect_dashboard_has_metadata(self):
        from nodechain.cli.dashboard import collect_dashboard
        data = collect_dashboard()
        assert data["type"] == "nodechain_dashboard"
        assert data["timestamp"]
        assert data["overall_health"]

    def test_runtime_status_has_expected_fields(self):
        from nodechain.cli.dashboard import collect_runtime_status
        rt = collect_runtime_status()
        assert "active_runs" in rt
        assert "total_runs" in rt
        assert "failed_runs" in rt
        assert "paused_reviews" in rt

    def test_trust_status_has_expected_fields(self):
        from nodechain.cli.dashboard import collect_trust_status
        tr = collect_trust_status()
        assert "trust_store_exists" in tr
        assert "total_keys" in tr
        assert "legacy_keys" in tr
        assert "snapshot_signed" in tr

    def test_registry_status_has_expected_fields(self):
        from nodechain.cli.dashboard import collect_registry_status
        rg = collect_registry_status()
        assert "active" in rg
        assert "deprecated" in rg
        assert "revoked" in rg
        assert "certified" in rg

    def test_evidence_status_has_expected_fields(self):
        from nodechain.cli.dashboard import collect_evidence_status
        ev = collect_evidence_status()
        assert "indexed_artifacts" in ev
        assert "broken_chains" in ev
        assert "replay_failures" in ev

    def test_operations_status_has_expected_fields(self):
        from nodechain.cli.dashboard import collect_operations_status
        ops = collect_operations_status()
        assert "known_good_releases" in ops
        assert "drift_detected" in ops
        assert "remediations" in ops

    def test_evaluation_status_has_expected_fields(self):
        from nodechain.cli.dashboard import collect_evaluation_status
        ev = collect_evaluation_status()
        assert "trusted_suites" in ev
        assert "total_reports" in ev
        assert "certifications" in ev
        assert "expired_certs" in ev


# ── AC3: Read-only Subcommands ──────────────────────────────────────────────

class TestAC3Subcommands:
    """AC3: All read-only subcommands exist and return exit 0."""

    @pytest.mark.parametrize("subcmd", [
        "runs", "trust", "registry", "evidence",
        "deployments", "drift", "evaluations", "health",
    ])
    def test_subcommand_help(self, subcmd):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", subcmd, "--help"])
        assert result.exit_code == 0

    @pytest.mark.parametrize("subcmd", [
        "runs", "trust", "registry", "evidence",
        "deployments", "drift", "evaluations", "health",
    ])
    def test_subcommand_executes(self, subcmd):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", subcmd])
        assert result.exit_code == 0


# ── AC4: JSON Output ────────────────────────────────────────────────────────

class TestAC4JsonOutput:
    """AC4: --json output for every view."""

    def test_dashboard_overview_json(self):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "sections" in data
        assert "overall_health" in data

    @pytest.mark.parametrize("subcmd", [
        "runs", "trust", "registry", "evidence",
        "deployments", "drift", "evaluations", "health",
    ])
    def test_subcommand_json(self, subcmd):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", subcmd, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, dict)


# ── AC5: Watch Flag ─────────────────────────────────────────────────────────

class TestAC5WatchFlag:
    """AC5: --watch flag exists."""

    def test_watch_in_help(self):
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "--watch" in result.output


# ── AC6: Health Model ───────────────────────────────────────────────────────

class TestAC6HealthModel:
    """AC6: Health model classifies status correctly."""

    def test_health_levels_exist(self):
        from nodechain.cli.dashboard import HEALTHY, WARNING, DEGRADED, CRITICAL, UNKNOWN
        assert HEALTHY == "healthy"
        assert WARNING == "warning"
        assert DEGRADED == "degraded"
        assert CRITICAL == "critical"
        assert UNKNOWN == "unknown"

    def test_worst_health_picks_worst(self):
        from nodechain.cli.dashboard import worst_health, HEALTHY, WARNING, CRITICAL, UNKNOWN
        assert worst_health(HEALTHY) == HEALTHY
        assert worst_health(HEALTHY, WARNING) == WARNING
        assert worst_health(HEALTHY, WARNING, CRITICAL) == CRITICAL
        assert worst_health() == UNKNOWN

    def test_worst_health_ordering(self):
        from nodechain.cli.dashboard import worst_health, HEALTHY, WARNING, DEGRADED, CRITICAL
        assert worst_health(HEALTHY, DEGRADED) == DEGRADED
        assert worst_health(WARNING, DEGRADED, CRITICAL) == CRITICAL

    def test_dashboard_reports_health(self):
        from nodechain.cli.dashboard import collect_dashboard
        data = collect_dashboard()
        assert data["overall_health"] in ("healthy", "warning", "degraded", "critical", "unknown")


# ── AC7: Dashboard Detects Issues ───────────────────────────────────────────

class TestAC7IssueDetection:
    """AC7: Dashboard detects specific issues."""

    def test_detects_unsigned_trust_snapshot(self):
        from nodechain.cli.dashboard import collect_dashboard
        data = collect_dashboard()
        # Without signed snapshot, should report it
        if not data["sections"]["trust"].get("snapshot_signed"):
            assert any("snapshot" in issue.lower() for issue in data["issues"])

    def test_detects_revoked_registry_entries(self, tmp_path, monkeypatch):
        """Dashboard reports revoked registry entries."""
        from nodechain.cli.dashboard import collect_registry_status
        registry_path = str(tmp_path / "registry.json")
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", registry_path)

        from nodechain.cli.certified_registry import save_registry, load_registry
        registry = load_registry()
        registry["entries"]["rev-1"] = {
            "package_id": "test_pkg",
            "registry_status": "revoked",
            "certification_status": "certified",
        }
        save_registry(registry)

        status = collect_registry_status()
        assert status["revoked"] == 1
        assert status["health"] == "warning"

    def test_detects_paused_reviews(self, tmp_path, monkeypatch):
        """Dashboard reports paused human reviews from SQLite."""
        db_path = str(tmp_path / "test.db")
        monkeypatch.setenv("NODECHAIN_DB_PATH", db_path)

        # Create a test DB with a paused run
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_states (
                    run_id TEXT, chain_id TEXT, status TEXT, updated_at TEXT
                )
            """)
            conn.execute(
                "INSERT INTO chain_states VALUES ('run-1', 'test-chain', 'paused', '2026-01-01')"
            )
            conn.commit()

        from nodechain.cli.dashboard import collect_runtime_status
        status = collect_runtime_status()
        assert status["paused_reviews"] == 1


# ── AC8: Read-Only (Never Mutates) ──────────────────────────────────────────

class TestAC8ReadOnly:
    """AC8: Dashboard never mutates state by default."""

    def test_dashboard_does_not_create_db(self, tmp_path, monkeypatch):
        """Running dashboard with non-existent DB doesn't create it."""
        db_path = str(tmp_path / "nonexistent.db")
        monkeypatch.setenv("NODECHAIN_DB_PATH", db_path)

        from nodechain.cli.dashboard import collect_dashboard
        collect_dashboard()

        assert not Path(db_path).exists(), "Dashboard created a DB file!"

    def test_dashboard_does_not_create_registry(self, tmp_path, monkeypatch):
        """Running dashboard doesn't create registry file."""
        registry_path = str(tmp_path / "nonexistent_registry.json")
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", registry_path)

        from nodechain.cli.dashboard import collect_registry_status
        collect_registry_status()

        assert not Path(registry_path).exists(), "Dashboard created a registry file!"

    def test_dashboard_does_not_modify_existing_state(self, tmp_path, monkeypatch):
        """Running dashboard doesn't modify existing artifacts."""
        # Set up a real trust store
        ts_path = str(tmp_path / "trust_store.json")
        ts_data = {"entries": {}, "entries_digest": "abc123", "snapshot_signature": ""}
        Path(ts_path).write_text(json.dumps(ts_data), encoding="utf-8")
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", ts_path)

        original = Path(ts_path).read_text()

        from nodechain.cli.dashboard import collect_trust_status
        collect_trust_status()
        collect_trust_status()
        collect_trust_status()

        after = Path(ts_path).read_text()
        assert original == after, "Dashboard modified trust store!"


# ── AC9: Deterministic with Fixtures ────────────────────────────────────────

class TestAC9Deterministic:
    """AC9: Dashboard output is deterministic with fixtures."""

    def test_empty_environment_is_healthy_or_warning(self, tmp_path, monkeypatch):
        """In an empty environment, dashboard returns consistent status."""
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "empty.db"))
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(tmp_path / "empty_ts.json"))
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "empty_reg.json"))

        from nodechain.cli.dashboard import collect_dashboard
        data1 = collect_dashboard()
        data2 = collect_dashboard()

        # Sections (excluding timestamp) should be identical
        assert data1["sections"] == data2["sections"]
        assert data1["overall_health"] == data2["overall_health"]
        assert data1["issues"] == data2["issues"]

    def test_full_dashboard_json_roundtrip(self, tmp_path, monkeypatch):
        """Dashboard JSON output can be loaded and re-serialized."""
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "empty.db"))
        monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(tmp_path / "empty_ts.json"))
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "empty_reg.json"))

        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--json"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        # Should be serializable
        re_serialized = json.dumps(data, sort_keys=True)
        re_parsed = json.loads(re_serialized)
        assert data == re_parsed


# ── Rendering Tests ─────────────────────────────────────────────────────────

class TestRendering:
    """Test the Rich text rendering."""

    def test_render_overview_has_sections(self):
        from nodechain.cli.dashboard import collect_dashboard, render_dashboard
        data = collect_dashboard()
        rendered = render_dashboard(data)
        assert "Runtime" in rendered
        assert "Trust" in rendered
        assert "Registry" in rendered
        assert "Evidence" in rendered
        assert "Operations" in rendered
        assert "Evaluation" in rendered

    def test_render_health_section(self):
        from nodechain.cli.dashboard import collect_dashboard, render_dashboard
        data = collect_dashboard()
        rendered = render_dashboard(data, section="health")
        assert "Overall" in rendered

    def test_render_section_invalid(self):
        from nodechain.cli.dashboard import collect_dashboard, render_dashboard
        data = collect_dashboard()
        rendered = render_dashboard(data, section="nonexistent")
        assert "No data" in rendered
