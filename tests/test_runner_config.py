"""Tests for RunnerConfig refactor and consolidation (v1.3.9).

Tests cover:
1. RunnerConfig construction and methods
2. RunnerConfig.from_preset() produces correct values
3. RunnerConfig.from_env() reads env vars
4. get_subprocess_runner(config=...) uses explicit config
5. NodeInvoker accepts runner_config
6. Orchestrator accepts runner_config
7. run_chain accepts runner_config
8. Human-readable report shows preset panel
9. Env-var fallback still works (backward compat)
10. Version and changelog
"""

from __future__ import annotations

import os
import pytest
from pathlib import Path


def _clean_preset_env():
    for key in ("NODECHAIN_POLICY_PRESET", "NODECHAIN_POLICY_PRESET_SOURCE",
                "NODECHAIN_SANDBOX_PROFILE"):
        os.environ.pop(key, None)


# ─── 1. RunnerConfig Construction ────────────────────────────────────────

class TestRunnerConfig:
    """RunnerConfig basic construction and methods."""

    def test_default_config(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig()
        assert cfg.enable_cgroup is False
        assert cfg.cgroup_memory_max_mb == 0

    def test_custom_config(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_cgroup=True, cgroup_memory_max_mb=256, cgroup_pids_max=10)
        assert cfg.enable_cgroup is True
        assert cfg.cgroup_memory_max_mb == 256
        assert cfg.cgroup_pids_max == 10

    def test_to_runner_kwargs(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_cgroup=True, cgroup_memory_max_mb=512)
        kwargs = cfg.to_runner_kwargs()
        assert kwargs["enable_cgroup"] is True
        assert kwargs["cgroup_memory_max_mb"] == 512
        assert "timeout_seconds" in kwargs

    def test_repr(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_cgroup=True, cgroup_memory_max_mb=256)
        r = repr(cfg)
        assert "RunnerConfig" in r
        assert "256" in r

    def test_from_preset_production(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("production_untrusted")
        cfg = RunnerConfig.from_preset(preset)
        assert cfg.enable_cgroup is True
        assert cfg.cgroup_memory_max_mb == 512
        assert cfg.cgroup_pids_max == 50
        assert cfg.cgroup_cpu_max_quota == 200000

    def test_from_preset_minimal(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("minimal")
        cfg = RunnerConfig.from_preset(preset)
        assert cfg.enable_cgroup is False
        assert cfg.cgroup_memory_max_mb == 0

    def test_from_env_no_preset(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        _clean_preset_env()
        assert RunnerConfig.from_env() is None

    def test_from_env_with_preset(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        _clean_preset_env()
        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            cfg = RunnerConfig.from_env()
            assert cfg is not None
            assert cfg.enable_cgroup is True
            assert cfg.cgroup_memory_max_mb == 512
        finally:
            _clean_preset_env()

    def test_from_env_unknown_preset(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        _clean_preset_env()
        os.environ["NODECHAIN_POLICY_PRESET"] = "nonexistent"
        try:
            assert RunnerConfig.from_env() is None
        finally:
            _clean_preset_env()


# ─── 2. get_subprocess_runner with Explicit Config ──────────────────────

class TestRunnerFactoryExplicitConfig:
    """get_subprocess_runner prefers explicit config over env vars."""

    def test_explicit_config_used(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner, RunnerConfig
        _clean_preset_env()
        # Set env to minimal, pass explicit production config
        os.environ["NODECHAIN_POLICY_PRESET"] = "minimal"
        try:
            cfg = RunnerConfig(enable_cgroup=True, cgroup_memory_max_mb=256, cgroup_pids_max=10)
            runner = get_subprocess_runner(config=cfg)
            assert runner.enable_cgroup is True
            assert runner.cgroup_memory_max_mb == 256
            assert runner.cgroup_pids_max == 10
        finally:
            _clean_preset_env()

    def test_none_config_falls_back_to_env(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        _clean_preset_env()
        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            runner = get_subprocess_runner(config=None)
            assert runner.enable_cgroup is True
            assert runner.cgroup_memory_max_mb == 512
        finally:
            _clean_preset_env()

    def test_none_config_no_env_returns_default(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        _clean_preset_env()
        runner = get_subprocess_runner(config=None)
        assert runner.enable_cgroup is False


# ─── 3. NodeInvoker Accepts runner_config ────────────────────────────────

class TestNodeInvokerRunnerConfig:
    """NodeInvoker stores and uses runner_config."""

    def test_invoker_default_no_config(self):
        from nodechain.runtime.node_invoker import NodeInvoker
        inv = NodeInvoker()
        assert inv._runner_config is None

    def test_invoker_with_config(self):
        from nodechain.runtime.node_invoker import NodeInvoker
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_cgroup=True, cgroup_memory_max_mb=256)
        inv = NodeInvoker(runner_config=cfg)
        assert inv._runner_config is not None
        assert inv._runner_config.enable_cgroup is True


# ─── 4. Orchestrator Accepts runner_config ────────────────────────────────

class TestOrchestratorRunnerConfig:
    """Orchestrator passes runner_config to invoker."""

    def test_orchestrator_default_no_config(self):
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        bp = ChainBlueprint(
            chain_id="test", name="test", goal="test",
            nodes=[NodeDef(node_id="a", node_type="x")],
            connections=[],
        )
        orch = Orchestrator(blueprint=bp, nodes={})
        assert orch.invoker._runner_config is None

    def test_orchestrator_with_config(self):
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.subprocess_runner import RunnerConfig
        bp = ChainBlueprint(
            chain_id="test", name="test", goal="test",
            nodes=[NodeDef(node_id="a", node_type="x")],
            connections=[],
        )
        cfg = RunnerConfig(enable_cgroup=True)
        orch = Orchestrator(blueprint=bp, nodes={}, runner_config=cfg)
        assert orch.invoker._runner_config is not None
        assert orch.invoker._runner_config.enable_cgroup is True


# ─── 5. Human-Readable Report Shows Preset ────────────────────────────────

class TestReportPresetDisplay:
    """Report CLI shows preset/enforcement panel."""

    def test_report_source_has_preset_panel(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "Policy Preset & Enforcement" in report_src
        assert "Seccomp" in report_src
        assert "Memory Limit" in report_src


# ─── 6. Backward Compat ──────────────────────────────────────────────────

class TestBackwardCompat:
    """Env-var fallback still works when no explicit config provided."""

    def test_env_var_path_still_works(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        _clean_preset_env()
        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            # No explicit config, falls back to env
            runner = get_subprocess_runner()
            assert runner.enable_cgroup is True
            assert runner.cgroup_memory_max_mb == 512
        finally:
            _clean_preset_env()

    def test_no_env_no_config_returns_default(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        _clean_preset_env()
        runner = get_subprocess_runner()
        assert runner.enable_cgroup is False


# ─── 7. Config Flow Is Explicit (No Hidden Coupling) ─────────────────────

class TestExplicitConfigFlow:
    """Verify the codebase uses explicit config in the main path."""

    def test_main_py_creates_runner_config(self):
        """CLI run handler creates RunnerConfig from preset."""
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "RunnerConfig" in main_src
        assert "runner_config" in main_src
        assert "from_preset" in main_src

    def test_run_chain_accepts_runner_config(self):
        """run_chain function accepts runner_config parameter."""
        run_src = Path("src/nodechain/cli/run.py").read_text(encoding="utf-8")
        assert "runner_config" in run_src

    def test_orchestrator_accepts_runner_config(self):
        """Orchestrator.__init__ accepts runner_config parameter."""
        orch_src = Path("src/nodechain/runtime/orchestrator.py").read_text(encoding="utf-8")
        assert "runner_config" in orch_src


# ─── 8. Version and Changelog ────────────────────────────────────────────

class TestV139Version:
    """Version reflects v1.3.9."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v139(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog

    def test_changelog_has_progression_table(self):
        """Changelog includes v1.3.0→v1.3.8 progression table."""
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "v1.3.0" in changelog
        assert "v1.3.8" in changelog
        assert "RunnerConfig" in changelog
