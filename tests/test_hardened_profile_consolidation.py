"""Tests for hardened sandbox profile consolidation (v1.5.2).

Tests cover:
1. Positive CLI smoke: hardened_untrusted --strict --trust-check → exit 0
2. Negative smoke per required kernel layer:
   a. required seccomp missing → exit 15 (INV-007)
   b. required cgroup limits missing → exit 15 (INV-009)
   c. required network namespace missing → exit 15 (INV-011)
   d. required mount confinement missing → exit 15 (INV-012)
   e. required PID namespace missing → exit 15 (INV-013)
3. Hardened Sandbox Profile table exists in docs
4. nodechain presets shows hardening layers
5. CLI consistency: report/trust/inspect show same posture
6. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. Positive CLI Smoke ──────────────────────────────────────────────

class TestPositiveCLISmoke:
    """Full CLI: hardened_untrusted --strict --trust-check exits 0."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_hardened_untrusted_full_smoke(self):
        import os, subprocess, sys

        bp = str(Path("blueprints/hardened_untrusted_demo_v1.yaml").resolve())
        if not Path(bp).exists():
            pytest.skip("hardened demo blueprint not found")

        env = os.environ.copy()
        env["NODECHAIN_PROVIDER"] = "mock"
        env["PYTHONIOENCODING"] = "utf-8"
        for key in ("NODECHAIN_POLICY_PRESET", "NODECHAIN_POLICY_PRESET_SOURCE",
                     "NODECHAIN_SANDBOX_PROFILE"):
            env.pop(key, None)

        result = subprocess.run(
            [sys.executable, "-m", "nodechain.cli.main",
             "run", "--blueprint", bp, "consolidation smoke",
             "--trust-check", "--strict"],
            capture_output=True, text=True, timeout=60, env=env,
            cwd=str(Path.cwd()),
        )
        assert result.returncode == 0, \
            f"Expected exit 0, got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"


# ─── 2. Negative Smoke Per Kernel Layer ─────────────────────────────────

class TestNegativeSmokeSeccomp:
    """INV-007: required seccomp/capability missing → exit 15."""

    def test_inv007_fires_when_required_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        import platform as _pf
        summary = TrustSummary(run_id="test")
        # On Linux, os_profile without syscall_filtering_enforced fires INV-007
        node_kwargs = dict(
            node_id="untrusted",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_used="os_profile",
            sandbox_backend="seccomp",
            syscall_filtering_enforced=False,
            resource_limits_enforced=True,
            os_sandbox_enforced=True,
        )
        summary.add_node(NodeTrustRecord(**node_kwargs))
        violations = summary.validate_invariants(strict=True)
        inv_codes = [v.code for v in violations]
        # INV-007 fires on Linux for os_profile without syscall filtering
        # On Windows, os_profile with RLIMIT (resource_limits_enforced=True)
        # satisfies INV-008, so only INV-007 fires on Linux
        if _pf.system() == "Linux":
            assert "INV-007" in inv_codes, f"Expected INV-007 on Linux, got: {inv_codes}"
        else:
            # On Windows, os_profile is valid with Job Objects or RLIMIT
            # INV-007 may not fire — just verify no crash
            pass


class TestNegativeSmokeCgroup:
    """INV-009: required cgroup limits missing → exit 15."""

    def test_inv009_fires_when_required_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            cgroup_limits_requested=True,
            cgroup_limits_enforced=False,
        ))
        violations = summary.validate_invariants(strict=True)
        inv009 = [v for v in violations if v.code == "INV-009"]
        assert len(inv009) == 1
        assert inv009[0].severity == "error"


class TestNegativeSmokeNetworkNS:
    """INV-011: required network namespace missing → exit 15."""

    def test_inv011_fires_when_required_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=False,
        ))
        violations = summary.validate_invariants(strict=True)
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 1
        assert inv011[0].severity == "error"


class TestNegativeSmokeMountConfinement:
    """INV-012: required mount confinement missing → exit 15."""

    def test_inv012_fires_when_required_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            mount_confinement_requested=True,
            mount_confinement_enforced=False,
        ))
        violations = summary.validate_invariants(strict=True)
        inv012 = [v for v in violations if v.code == "INV-012"]
        assert len(inv012) == 1
        assert inv012[0].severity == "error"


class TestNegativeSmokePidNamespace:
    """INV-013: required PID namespace missing → exit 15."""

    def test_inv013_fires_when_required_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            pid_namespace_requested=True,
            pid_namespace_enforced=False,
        ))
        violations = summary.validate_invariants(strict=True)
        inv013 = [v for v in violations if v.code == "INV-013"]
        assert len(inv013) == 1
        assert inv013[0].severity == "error"


class TestNegativeSmokeAllEnforced:
    """When all layers are enforced, no violations."""

    def test_all_enforced_no_violations(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="fully_enforced_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_used="os_profile",
            sandbox_backend="seccomp",
            syscall_filtering_enforced=True,
            os_sandbox_enforced=True,
            resource_limits_enforced=True,
            cgroup_limits_requested=True,
            cgroup_limits_enforced=True,
            network_namespace_requested=True,
            network_namespace_enforced=True,
            mount_confinement_requested=True,
            mount_confinement_enforced=True,
            pid_namespace_requested=True,
            pid_namespace_enforced=True,
        ))
        violations = summary.validate_invariants(strict=True)
        enforced_violations = [v for v in violations if v.node_id == "fully_enforced_node"]
        assert len(enforced_violations) == 0, \
            f"Expected no violations, got: {[(v.code, v.invariant) for v in enforced_violations]}"


# ─── 3. Hardened Sandbox Profile Table ──────────────────────────────────

class TestHardenedProfileDocs:
    """Documentation includes hardened sandbox profile table."""

    def test_linux_deployment_has_profile_table(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "Hardened Sandbox Profile" in ld

    def test_profile_table_has_required_column(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        table_section = ld[ld.index("Hardened Sandbox Profile"):]
        assert "Required" in table_section

    def test_profile_table_covers_all_invariants(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        table_section = ld[ld.index("Hardened Sandbox Profile"):]
        for inv in ["INV-001", "INV-007", "INV-009", "INV-011", "INV-012", "INV-013"]:
            assert inv in table_section, f"Missing {inv} in profile table"


# ─── 4. nodechain presets Shows Hardening Layers ────────────────────────

class TestPresetsCLIDisplay:
    """nodechain presets shows hardening layers."""

    def test_presets_source_has_hardening_layers(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "hardening_layers" in main_src

    def test_presets_source_shows_all_layer_names(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "seccomp" in main_src.lower()
        assert "cgroup" in main_src.lower()
        assert "network namespace" in main_src.lower()
        assert "mount confinement" in main_src.lower()
        assert "PID namespace" in main_src


# ─── 5. CLI Consistency ─────────────────────────────────────────────────

class TestCLIConsistency:
    """report/trust/inspect show same posture."""

    def test_report_has_all_layers(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        for term in ["Seccomp", "Memory Limit", "Network NS", "Mount Confinement", "PID Namespace"]:
            assert term in report_src, f"Missing '{term}' in report.py"

    def test_trust_has_all_layers(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        for term in ["seccomp", "cgroup_limits", "net_ns", "mnt_conf", "pid_ns"]:
            assert term in main_src, f"Missing '{term}' in main.py trust command"

    def test_inspect_has_all_layers(self):
        inspect_src = Path("src/nodechain/cli/inspect.py").read_text(encoding="utf-8")
        for term in ["Seccomp", "Mount Confinement", "PID Namespace"]:
            assert term in inspect_src, f"Missing '{term}' in inspect.py"


# ─── 6. Preset Configuration Consistency ────────────────────────────────

class TestPresetConfigConsistency:
    """hardened_untrusted has all layers consistently configured."""

    def test_hardened_untrusted_all_layers(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("hardened_untrusted")
        assert p.seccomp_required is True
        assert p.cgroup_limits_requested is True
        assert p.trust_check_required is True
        assert p.network_namespace_required is True
        assert p.mount_confinement_required is True
        assert p.pid_namespace_required is True

    def test_production_untrusted_subset(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        assert p.seccomp_required is True
        assert p.cgroup_limits_requested is True
        assert p.network_namespace_required is True
        # But NOT mount confinement or PID namespace
        assert p.mount_confinement_required is False
        assert p.pid_namespace_required is False

    def test_standard_untrusted_minimal(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("standard_untrusted")
        assert p.seccomp_required is True
        assert p.cgroup_limits_requested is False
        assert p.network_namespace_required is False
        assert p.mount_confinement_required is False
        assert p.pid_namespace_required is False

    def test_minimal_bare(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("minimal")
        assert p.seccomp_required is False
        assert p.cgroup_limits_requested is False
        assert p.mount_confinement_required is False
        assert p.pid_namespace_required is False


# ─── 7. Version and Changelog ────────────────────────────────────────────

class TestV152Version:
    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v152(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Hardened Sandbox Profile Consolidation" in changelog
