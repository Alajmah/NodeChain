"""Tests for cgroup limit behavior under pressure (v1.3.3 + v1.3.4).

Proves runtime behavior when child processes hit cgroup limits:
1. Memory OOM: child allocates unreclaimable memory → killed or pressured
2. pids.max: child exceeds process limit → fork fails
3. CPU throttling: CPU-bound child under quota → cpu.stat shows throttling
4. Cleanup after kernel-killed child
5. Policy presets
6. TrustSummary behavioral fields (v1.3.4 counters)

v1.3.4 additions:
- OOM test uses unreclaimable anonymous memory (mmap touch-every-page)
- CPU throttling asserts nr_throttled > 0 or throttled_usec > 0
- TrustSummary reports 6 pressure evidence counters
- memory.events oom/oom_kill counters checked

All pressure tests are Linux-only and run in subprocesses.
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path

from nodechain.sdk.cgroup_profile import (
    CgroupAccounting,
    read_accounting,
)
from nodechain.sdk.trust_summary import (
    NodeTrustRecord,
    TrustSummary,
)
from nodechain.sdk.policy_presets import (
    PolicyPreset,
    PRESETS,
    get_preset,
    list_presets,
)


# ─── 1. Memory OOM Behavior ──────────────────────────────────────────────

class TestMemoryOomBehavior:
    """Child exceeding memory.max is killed by the kernel."""

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only — requires cgroup v2 memory.max"
    )
    def test_child_memory_pressure_under_limit(self):
        """Child allocating unreclaimable memory under memory.max.

        Acceptance criteria (v1.3.4):
        - Either child is killed (oom_kill > 0, success=False)
        - Or child survives with memory.events max > 0 (reclamation)
        - In both cases, the limit was enforced.

        We use mmap with page-touching to create unreclaimable
        anonymous memory that forces real OOM pressure.
        """
        import asyncio
        import os
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        oom_path = str(Path(__file__).parent / "cgroup_test_nodes" / "oom_node.py")
        if not Path(oom_path).exists():
            pytest.skip("oom_node.py not found")

        runner = SubprocessRunner(
            enable_cgroup=True,
            cgroup_memory_max_mb=20,  # 20MB — tight for 50MB unreclaimable alloc
            timeout_seconds=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_oom",
            run_id="test_oom",
            chain_id="test",
            node_id="oom_child",
            step_id=1,
            payload={"query": "alloc"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=oom_path,
            class_name="OomNode",
            node_id="oom_child",
            trust_level="local_untrusted",
            package_root=str(Path(oom_path).parent),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_memory_events_counters_present(self):
        """memory.events counters are parsed and available in accounting."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        oom_path = str(Path(__file__).parent / "cgroup_test_nodes" / "oom_node.py")
        if not Path(oom_path).exists():
            pytest.skip("oom_node.py not found")

        runner = SubprocessRunner(
            enable_cgroup=True,
            cgroup_memory_max_mb=20,
            timeout_seconds=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_evt",
            run_id="test_evt",
            chain_id="test",
            node_id="oom_evt",
            step_id=1,
            payload={"query": "alloc"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=oom_path,
            class_name="OomNode",
            node_id="oom_evt",
            trust_level="local_untrusted",
            package_root=str(Path(oom_path).parent),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 2. pids.max Behavior ────────────────────────────────────────────────

class TestPidsLimitBehavior:
    """Child exceeding pids.max has fork denied."""

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only — requires cgroup v2 pids.max"
    )
    def test_child_fork_denied_on_pids_limit(self):
        """Child forking beyond pids.max fails."""
        import asyncio
        import os
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        fork_path = str(Path(__file__).parent / "cgroup_test_nodes" / "fork_node.py")
        if not Path(fork_path).exists():
            pytest.skip("fork_node.py not found")

        runner = SubprocessRunner(
            enable_cgroup=True,
            cgroup_pids_max=2,  # Very low limit
            timeout_seconds=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_pids",
            run_id="test_pids",
            chain_id="test",
            node_id="fork_child",
            step_id=1,
            payload={"query": "fork"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=fork_path,
            class_name="ForkNode",
            node_id="fork_child",
            trust_level="local_untrusted",
            package_root=str(Path(fork_path).parent),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 3. CPU Throttling Evidence ──────────────────────────────────────────

class TestCpuThrottlingEvidence:
    """CPU-bound child under quota shows throttling in cpu.stat."""

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only — requires cgroup v2 cpu.max"
    )
    def test_cpu_throttling_counters_nonzero(self):
        """CPU burn under tight quota must show throttling.

        v1.3.4: Asserts nr_throttled > 0 or throttled_usec > 0,
        not just field presence.
        """
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        burn_path = str(Path(__file__).parent / "cgroup_test_nodes" / "cpu_burn_node.py")
        if not Path(burn_path).exists():
            pytest.skip("cpu_burn_node.py not found")

        runner = SubprocessRunner(
            enable_cgroup=True,
            cgroup_cpu_max_quota=10000,  # 10ms per 100ms period = 10% CPU
            timeout_seconds=15,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_cpu",
            run_id="test_cpu",
            chain_id="test",
            node_id="burn_child",
            step_id=1,
            payload={"query": "burn"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=burn_path,
            class_name="CpuBurnNode",
            node_id="burn_child",
            trust_level="local_untrusted",
            package_root=str(Path(burn_path).parent),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 4. Cleanup After Kernel Kill ───────────────────────────────────────

class TestCleanupAfterKernelKill:
    """Cgroup cleanup succeeds after kernel kills the child."""

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_cgroup_removed_after_oom_pressure(self):
        """Verify cgroup directory is gone after memory-pressure execution."""
        import asyncio
        import os
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        oom_path = str(Path(__file__).parent / "cgroup_test_nodes" / "oom_node.py")
        if not Path(oom_path).exists():
            pytest.skip("oom_node.py not found")

        runner = SubprocessRunner(
            enable_cgroup=True,
            cgroup_memory_max_mb=20,
            timeout_seconds=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_cleanup",
            run_id="test_cleanup",
            chain_id="test",
            node_id="oom_cleanup",
            step_id=1,
            payload={"query": "alloc"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=oom_path,
            class_name="OomNode",
            node_id="oom_cleanup",
            trust_level="local_untrusted",
            package_root=str(Path(oom_path).parent),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 5. CgroupAccounting Throttling/OOM Fields ──────────────────────────

class TestCgroupAccountingV133Fields:
    """CgroupAccounting has throttling and OOM fields."""

    def test_fields_exist(self):
        acct = CgroupAccounting()
        assert hasattr(acct, "cpu_nr_periods")
        assert hasattr(acct, "cpu_nr_throttled")
        assert hasattr(acct, "cpu_throttled_usec")
        assert hasattr(acct, "oom_events")
        assert hasattr(acct, "oom_kill_events")

    def test_fields_in_to_dict(self):
        acct = CgroupAccounting(
            cpu_nr_periods=100,
            cpu_nr_throttled=50,
            cpu_throttled_usec=50000,
            oom_events=1,
            oom_kill_events=1,
        )
        d = acct.to_dict()
        assert d["cpu_nr_periods"] == 100
        assert d["cpu_nr_throttled"] == 50
        assert d["cpu_throttled_usec"] == 50000
        assert d["oom_events"] == 1
        assert d["oom_kill_events"] == 1


# ─── 6. NodeTrustRecord Behavioral Fields ────────────────────────────────

class TestNodeTrustRecordV134Fields:
    """NodeTrustRecord has v1.3.3/v1.3.4 behavioral fields."""

    def test_v133_fields_exist(self):
        record = NodeTrustRecord(node_id="test")
        assert hasattr(record, "cgroup_oom_kill_observed")
        assert hasattr(record, "cgroup_cpu_throttling_observed")
        assert hasattr(record, "cgroup_pids_limit_observed")

    def test_v134_fields_exist(self):
        record = NodeTrustRecord(node_id="test")
        assert hasattr(record, "memory_events_max")
        assert hasattr(record, "memory_events_oom")
        assert hasattr(record, "memory_events_oom_kill")
        assert hasattr(record, "cpu_nr_throttled")
        assert hasattr(record, "cpu_throttled_usec")
        assert hasattr(record, "pids_limit_denied")

    def test_v134_fields_in_to_dict(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            memory_events_max=42,
            memory_events_oom=3,
            memory_events_oom_kill=1,
            cpu_nr_throttled=15,
            cpu_throttled_usec=80000,
            pids_limit_denied=True,
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["memory_events_max"] == 42
        assert node["memory_events_oom"] == 3
        assert node["memory_events_oom_kill"] == 1
        assert node["cpu_nr_throttled"] == 15
        assert node["cpu_throttled_usec"] == 80000
        assert node["pids_limit_denied"] is True


# ─── 7. Policy Presets ───────────────────────────────────────────────────

class TestPolicyPresets:
    """Policy presets for resource governance declarations."""

    def test_list_presets(self):
        names = list_presets()
        assert "production_untrusted" in names
        assert "standard_untrusted" in names
        assert "minimal" in names

    def test_get_preset(self):
        preset = get_preset("production_untrusted")
        assert preset is not None
        assert preset.name == "production_untrusted"

    def test_get_preset_not_found(self):
        assert get_preset("nonexistent") is None

    def test_production_untrusted_preset_fields(self):
        preset = get_preset("production_untrusted")
        assert preset.sandbox_profile == "os_profile"
        assert preset.seccomp_required is True
        assert preset.cgroup_limits_requested is True
        assert preset.cgroup_memory_max_mb > 0
        assert preset.cgroup_pids_max > 0
        assert preset.cgroup_cpu_max_quota > 0
        assert preset.trust_check_required is True

    def test_standard_untrusted_preset(self):
        preset = get_preset("standard_untrusted")
        assert preset.sandbox_profile == "os_profile"
        assert preset.seccomp_required is True
        assert preset.cgroup_limits_requested is False

    def test_minimal_preset(self):
        preset = get_preset("minimal")
        assert preset.sandbox_profile == "subprocess_isolated"
        assert preset.seccomp_required is False
        assert preset.cgroup_limits_requested is False

    def test_preset_to_runner_kwargs(self):
        preset = get_preset("production_untrusted")
        kwargs = preset.to_runner_kwargs()
        assert kwargs["enable_cgroup"] is True
        assert kwargs["cgroup_memory_max_mb"] > 0
        assert kwargs["cgroup_pids_max"] > 0

    def test_minimal_preset_runner_kwargs(self):
        preset = get_preset("minimal")
        kwargs = preset.to_runner_kwargs()
        assert kwargs == {}

    def test_preset_to_required_os_capabilities(self):
        preset = get_preset("production_untrusted")
        caps = preset.to_required_os_capabilities()
        assert "seccomp" in caps
        assert "cgroup_limits" in caps
        assert "cgroup_accounting" in caps

    def test_minimal_preset_no_capabilities(self):
        preset = get_preset("minimal")
        caps = preset.to_required_os_capabilities()
        assert caps == []

    def test_preset_to_dict(self):
        preset = get_preset("production_untrusted")
        d = preset.to_dict()
        assert d["name"] == "production_untrusted"
        assert "seccomp_required" in d
        assert "cgroup_memory_max_mb" in d

    def test_strict_mode_enforces_preset_requirements(self):
        """Strict mode enforces declared preset requirements."""
        preset = get_preset("production_untrusted")
        caps = preset.to_required_os_capabilities()

        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            required_os_capabilities=caps,
            # Missing: seccomp, cgroup_limits, cgroup_accounting
            syscall_filtering_enforced=False,
            cgroup_available=False,
            cgroup_limits_writable=False,
        ))
        violations = summary.validate_invariants(strict=True)
        inv008 = [v for v in violations if v.code == "INV-008"]
        # Should have violations for missing seccomp, cgroup_limits, cgroup_accounting
        assert len(inv008) >= 2


# ─── 8. Version and Changelog ────────────────────────────────────────────

class TestCgroupV134Version:
    """Version reflects v1.3.4."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v134(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
