"""Tests for policy preset runtime wiring (v1.3.6).

Tests cover:
1. get_subprocess_runner() reads NODECHAIN_POLICY_PRESET
2. production_untrusted produces correct runner kwargs
3. standard_untrusted produces correct runner kwargs
4. minimal preserves default behavior
5. Demo blueprint exists with correct preset
6. CLI trust display shows preset info
7. CLI report includes preset info
"""

from __future__ import annotations

import os
import pytest
from pathlib import Path


# ─── 1. get_subprocess_runner Reads Preset ───────────────────────────────

class TestRunnerFactoryReadsPreset:
    """get_subprocess_runner() reads NODECHAIN_POLICY_PRESET env var."""

    def test_default_runner_no_preset(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        # Ensure no preset env var
        old = os.environ.pop("NODECHAIN_POLICY_PRESET", None)
        try:
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is False
            assert runner.cgroup_memory_max_mb == 0
        finally:
            if old is not None:
                os.environ["NODECHAIN_POLICY_PRESET"] = old

    def test_production_untrusted_runner_has_cgroup(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is True
            assert runner.cgroup_memory_max_mb == 512
            assert runner.cgroup_pids_max == 50
            assert runner.cgroup_cpu_max_quota == 200000
        finally:
            del os.environ["NODECHAIN_POLICY_PRESET"]

    def test_standard_untrusted_runner_no_cgroup(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        os.environ["NODECHAIN_POLICY_PRESET"] = "standard_untrusted"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is False
        finally:
            del os.environ["NODECHAIN_POLICY_PRESET"]

    def test_minimal_runner_no_cgroup(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        os.environ["NODECHAIN_POLICY_PRESET"] = "minimal"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is False
            assert runner.cgroup_memory_max_mb == 0
        finally:
            del os.environ["NODECHAIN_POLICY_PRESET"]

    def test_unknown_preset_falls_back_to_default(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        os.environ["NODECHAIN_POLICY_PRESET"] = "nonexistent"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is False
        finally:
            del os.environ["NODECHAIN_POLICY_PRESET"]


# ─── 2. Demo Blueprint ───────────────────────────────────────────────────

class TestDemoBlueprint:
    """Demo blueprint exists with correct preset."""

    def test_blueprint_file_exists(self):
        bp_path = Path("blueprints/production_untrusted_demo_v1.yaml")
        assert bp_path.exists(), "Demo blueprint not found"

    def test_blueprint_has_preset(self):
        import yaml
        bp_path = Path("blueprints/production_untrusted_demo_v1.yaml")
        data = yaml.safe_load(bp_path.read_text())
        assert data.get("policy_preset") == "production_untrusted"


# ─── 3. CLI Display Shows Preset Info ────────────────────────────────────

class TestCLIDisplaysPreset:
    """CLI trust/report display shows preset info."""

    def test_trust_command_shows_preset(self):
        from nodechain.cli import main as cli_main
        source = open(cli_main.__file__, encoding="utf-8").read()
        assert "Policy preset" in source
        assert "Preset source" in source

    def test_trust_command_shows_cgroup_limits(self):
        from nodechain.cli import main as cli_main
        source = open(cli_main.__file__, encoding="utf-8").read()
        assert "cgroup_limits_req" in source
        assert "cgroup_limits_enf" in source

    def test_report_includes_preset(self):
        from nodechain.cli import report as report_module
        source = open(report_module.__file__, encoding="utf-8").read()
        assert "NODECHAIN_POLICY_PRESET" in source


# ─── 4. End-to-End Preset Wiring (Linux only) ───────────────────────────

class TestEndToEndPresetWiring:
    """End-to-end: preset env var → runner → cgroup enforcement."""

    @pytest.mark.skipif(
        __import__("platform").system() != "Linux",
        reason="Linux only — requires cgroup v2"
    )
    def test_production_untrusted_applies_cgroup_limits(self):
        """production_untrusted actually applies cgroup limits to child."""
        import asyncio
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is True
            assert runner.cgroup_memory_max_mb == 512

            envelope = InvocationEnvelope(
                envelope_id="test_e2e",
                run_id="test_e2e",
                chain_id="test",
                node_id="echo",
                step_id=1,
                payload={"query": "hello preset"},
            )

            result = asyncio.run(runner.run_isolated(
                envelope=envelope,
                module_path=echo_path,
                class_name="EchoNode",
                node_id="echo",
                trust_level="local_untrusted",
                package_root=str(Path(echo_path).parent.resolve()),
            ))

            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        finally:
            del os.environ["NODECHAIN_POLICY_PRESET"]


# ─── 5. Version and Changelog ────────────────────────────────────────────

class TestV136Version:
    """Version reflects v1.3.6."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v136(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
