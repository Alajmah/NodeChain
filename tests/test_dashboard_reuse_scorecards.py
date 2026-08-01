"""Dashboard reuse + scorecards section tests (v2.67.3).

Tests the two new dashboard sections that make the v2.64-v2.65 proofs
operator-visible: registry-resolved reuse proof status and cached
deterministic node quality scorecards.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.cli.dashboard import (
    collect_reuse_status,
    collect_scorecards_status,
    collect_dashboard,
    render_dashboard,
)


# ── Reuse collector ───────────────────────────────────────────────────────


class TestReuseCollector:
    """collect_reuse_status() returns correct structure and health."""

    def test_returns_dict_with_required_keys(self):
        result = collect_reuse_status()
        assert "health" in result
        assert "shared_nodes" in result
        assert "nodes_resolved" in result
        assert "nodes" in result
        assert "lockfile" in result

    def test_shared_nodes_count(self):
        result = collect_reuse_status()
        assert result["shared_nodes"] == 2

    def test_nodes_have_provenance(self):
        result = collect_reuse_status()
        for node in result["nodes"]:
            assert "node_id" in node
            assert "resolved" in node
            assert "origin" in node
            assert "content_digest" in node

    def test_lockfile_structure(self):
        result = collect_reuse_status()
        lf = result["lockfile"]
        assert "exists" in lf
        assert "ok" in lf
        assert "errors" in lf

    def test_health_is_valid_constant(self):
        from nodechain.cli.dashboard import HEALTHY, WARNING, DEGRADED, UNKNOWN
        result = collect_reuse_status()
        assert result["health"] in (HEALTHY, WARNING, DEGRADED, UNKNOWN)


# ── Scorecards collector ──────────────────────────────────────────────────


class TestScorecardsCollector:
    """collect_scorecards_status() handles missing/invalid/present states."""

    def test_missing_cache_returns_unknown(self):
        """When cache file doesn't exist, status is 'missing' and health UNKNOWN."""
        from nodechain.runtime.node_quality_scorecard import DEFAULT_SCORECARD_CACHE_PATH
        # Ensure cache doesn't exist (test env may not have it)
        if DEFAULT_SCORECARD_CACHE_PATH.exists():
            pytest.skip("Cache exists in test env — cannot test missing state cleanly")
        result = collect_scorecards_status()
        assert result["cache_exists"] is False
        assert result["status"] == "missing"
        assert result["health"] == "unknown"

    def test_returns_dict_with_required_keys(self):
        result = collect_scorecards_status()
        assert "health" in result
        assert "cache_exists" in result
        assert "status" in result

    def test_health_is_valid_constant(self):
        from nodechain.cli.dashboard import HEALTHY, WARNING, DEGRADED, UNKNOWN
        result = collect_scorecards_status()
        assert result["health"] in (HEALTHY, WARNING, DEGRADED, UNKNOWN)


# ── Scorecard cache infrastructure ────────────────────────────────────────


class TestScorecardCache:
    """write/load roundtrip, atomic write, pure loader."""

    def test_write_load_roundtrip(self, tmp_path):
        from nodechain.runtime.node_quality_scorecard import (
            NodeScorecardReport, write_scorecard_cache, load_scorecard_cache,
        )
        reports = [
            NodeScorecardReport(node_id="test_node_1", passed=True),
            NodeScorecardReport(node_id="test_node_2", passed=True),
        ]
        cache_path = tmp_path / "latest.json"
        write_scorecard_cache(reports, path=cache_path)
        assert cache_path.exists()

        loaded = load_scorecard_cache(cache_path)
        assert loaded is not None
        assert loaded["schema_version"] == "nodechain.node_scorecard_cache.v1"
        assert loaded["summary"]["total"] == 2
        assert loaded["summary"]["passed"] == 2
        assert len(loaded["reports"]) == 2

    def test_load_missing_returns_none(self, tmp_path):
        from nodechain.runtime.node_quality_scorecard import load_scorecard_cache
        result = load_scorecard_cache(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_invalid_returns_none(self, tmp_path):
        from nodechain.runtime.node_quality_scorecard import load_scorecard_cache
        bad_path = tmp_path / "bad.json"
        bad_path.write_text('{"not_a_valid": "cache"}')
        result = load_scorecard_cache(bad_path)
        assert result is None

    def test_atomic_write_no_tmp_leftover(self, tmp_path):
        from nodechain.runtime.node_quality_scorecard import (
            NodeScorecardReport, write_scorecard_cache,
        )
        reports = [NodeScorecardReport(node_id="test", passed=True)]
        cache_path = tmp_path / "latest.json"
        write_scorecard_cache(reports, path=cache_path)
        # No .tmp file should remain
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert len(tmp_files) == 0


# ── Staleness check ───────────────────────────────────────────────────────


class TestStalenessCheck:
    """is_scorecard_cache_stale() detects digest/version changes."""

    def test_fresh_cache_not_stale(self, tmp_path):
        from nodechain.runtime.node_quality_scorecard import (
            run_registry_node_scorecard, write_scorecard_cache,
            load_scorecard_cache, is_scorecard_cache_stale,
        )
        from nodechain.registry.local_registry import RegistryIndex

        reports = [run_registry_node_scorecard(nid) for nid in ("shared_risk_classifier",)]
        cache_path = tmp_path / "latest.json"
        write_scorecard_cache(reports, path=cache_path)
        cache = load_scorecard_cache(cache_path)

        reg = RegistryIndex()
        reg.scan()
        stale, reasons = is_scorecard_cache_stale(cache, reg)
        assert stale is False
        assert reasons == []

    def test_tampered_digest_is_stale(self, tmp_path):
        from nodechain.runtime.node_quality_scorecard import (
            run_registry_node_scorecard, write_scorecard_cache,
            load_scorecard_cache, is_scorecard_cache_stale,
        )
        from nodechain.registry.local_registry import RegistryIndex

        reports = [run_registry_node_scorecard("shared_risk_classifier")]
        cache_path = tmp_path / "latest.json"
        write_scorecard_cache(reports, path=cache_path)

        # Tamper with the digest in the cache
        cache = load_scorecard_cache(cache_path)
        cache["reports"][0]["content_digest"] = "0" * 64

        reg = RegistryIndex()
        reg.scan()
        stale, reasons = is_scorecard_cache_stale(cache, reg)
        assert stale is True
        assert any("content_digest" in r for r in reasons)


# ── Target discovery parity ───────────────────────────────────────────────


class TestTargetDiscoveryParity:
    """get_shared_registry_node_ids() is the single source of truth."""

    def test_returns_both_shared_nodes(self):
        from nodechain.runtime.node_quality_scorecard import get_shared_registry_node_ids
        ids = get_shared_registry_node_ids()
        assert "shared_risk_classifier" in ids
        assert "shared_trace_collector" in ids
        assert len(ids) == 2


# ── Dashboard rendering ───────────────────────────────────────────────────


class TestDashboardRendering:
    """Dashboard includes compact summaries and renders new sections."""

    def test_dashboard_has_reuse_section(self):
        data = collect_dashboard()
        assert "reuse" in data["sections"]

    def test_dashboard_has_scorecards_section(self):
        data = collect_dashboard()
        assert "scorecards" in data["sections"]

    def test_render_includes_reuse_summary(self):
        data = collect_dashboard()
        rendered = render_dashboard(data)
        assert "Reuse" in rendered

    def test_render_includes_scorecards_summary(self):
        data = collect_dashboard()
        rendered = render_dashboard(data)
        assert "Scorecards" in rendered

    def test_render_reuse_section_detail(self):
        data = collect_dashboard()
        rendered = render_dashboard(data, section="reuse")
        assert "Node Details" in rendered or "Health" in rendered

    def test_render_scorecards_section_detail(self):
        data = collect_dashboard()
        rendered = render_dashboard(data, section="scorecards")
        assert "Cache" in rendered or "Status" in rendered


# ── Graceful degradation ──────────────────────────────────────────────────


class TestGracefulDegradation:
    """Missing artifacts produce visible operator states, not crashes."""

    def test_scorecards_missing_shows_state(self):
        from nodechain.runtime.node_quality_scorecard import DEFAULT_SCORECARD_CACHE_PATH
        if DEFAULT_SCORECARD_CACHE_PATH.exists():
            pytest.skip("Cache exists in test env")
        result = collect_scorecards_status()
        assert result["status"] == "missing"
        assert result["health"] == "unknown"

    def test_reuse_collector_never_crashes(self):
        result = collect_reuse_status()
        # Must always return a dict with health, never raise
        assert isinstance(result, dict)
        assert "health" in result

    def test_scorecards_collector_never_crashes(self):
        result = collect_scorecards_status()
        assert isinstance(result, dict)
        assert "health" in result


# ── CLI subcommand tests (v2.67.3: covers crash bug #1) ────────────────────


class TestCLISubcommands:
    """CLI subcommands work without crashing, including default scorecards path."""

    def test_dashboard_scorecards_no_refresh(self):
        """dashboard scorecards without --refresh must not crash (bug #1 fix)."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "scorecards"])
        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.exception}"
        assert "Scorecards" in result.output or "scorecards" in result.output.lower()

    def test_dashboard_scorecards_json(self):
        """dashboard scorecards --json emits valid JSON."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        import json as _json
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "scorecards", "--json"])
        assert result.exit_code == 0
        # Should be valid JSON
        parsed = _json.loads(result.output.strip())
        assert "cache_exists" in parsed
        assert "health" in parsed

    def test_dashboard_reuse(self):
        """dashboard reuse renders without crashing."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "reuse"])
        assert result.exit_code == 0
        assert "Reuse" in result.output or "reuse" in result.output.lower()

    def test_dashboard_reuse_json(self):
        """dashboard reuse --json emits valid JSON."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        import json as _json
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "reuse", "--json"])
        assert result.exit_code == 0
        parsed = _json.loads(result.output.strip())
        assert "health" in parsed
        assert "nodes" in parsed
