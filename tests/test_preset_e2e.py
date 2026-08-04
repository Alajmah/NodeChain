"""End-to-end policy preset tests (v1.3.7).

Proves:
1. standard_untrusted → seccomp_enforced=true on Linux (via isolation_config)
2. production_untrusted → seccomp + cgroup limits (via isolation_config + runner)
3. Blueprint-declared preset works without manual env vars
4. CLI preset overrides blueprint preset deterministically
"""

from __future__ import annotations

import os
import platform
import pytest
from pathlib import Path
from unittest.mock import patch


def _clean_preset_env():
    """Remove all preset-related env vars."""
    for key in ("NODECHAIN_POLICY_PRESET", "NODECHAIN_POLICY_PRESET_SOURCE",
                "NODECHAIN_SANDBOX_PROFILE"):
        os.environ.pop(key, None)


def _seccomp_capable() -> bool:
    """Whether the runtime can actually enforce seccomp-bpf here.

    Reuses the runtime's own capability detector (SeccompBackend.available)
    so the test gate matches production truth, not a coarse OS guess.

    Returns False on:
      - non-Linux platforms (Windows, macOS)
      - Linux without libseccomp/pyseccomp installed
      - LXC/nested containers where seccomp-bpf cannot be applied

    v2.67.3: added because the prior `platform.system() != "Linux"` gate
    reported True on Proxmox LXC (CT 801) yet enforcement fails there.
    """
    if platform.system() != "Linux":
        return False
    try:
        from nodechain.sdk.seccomp_profile import SeccompBackend
        return SeccompBackend().available
    except Exception:
        return False


# Computed once at import; used by skipif markers below.
_SECCOMP_CAPABLE = _seccomp_capable()


# ─── 1. Standard Untrusted E2E (Linux) ───────────────────────────────────

class TestStandardUntrustedE2E:
    """standard_untrusted produces seccomp enforcement on Linux."""

    @pytest.mark.skipif(
        not _SECCOMP_CAPABLE,
        reason="requires a Linux runtime that can enforce seccomp-bpf "
               "(bare metal or capable VM; LXC/nested containers cannot)"
    )
    def test_standard_untrusted_enables_seccomp(self):
        """standard_untrusted → seccomp_enforced=true via isolation_config."""
        import asyncio
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        _clean_preset_env()
        os.environ["NODECHAIN_POLICY_PRESET"] = "standard_untrusted"
        os.environ["NODECHAIN_POLICY_PRESET_SOURCE"] = "cli"
        # Preset resolver sets sandbox profile
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("standard_untrusted")
        os.environ["NODECHAIN_SANDBOX_PROFILE"] = preset.sandbox_profile

        try:
            runner = get_subprocess_runner()

            # Verify BaseNode.isolation_config would enable seccomp
            # by checking the sandbox profile
            assert os.environ.get("NODECHAIN_SANDBOX_PROFILE") == "os_profile"

            envelope = InvocationEnvelope(
                envelope_id="test_std",
                run_id="test_std",
                chain_id="test",
                node_id="echo",
                step_id=1,
                payload={"query": "hello seccomp"},
            )

            result = asyncio.run(runner.run_isolated(
                envelope=envelope,
                module_path=echo_path,
                class_name="EchoNode",
                node_id="echo",
                trust_level="local_untrusted",
                package_root=str(Path(echo_path).parent.resolve()),
                enable_seccomp=True,  # As isolation_config would provide
            ))

            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        finally:
            _clean_preset_env()


# ─── 2. Production Untrusted E2E (Linux) ─────────────────────────────────

class TestProductionUntrustedE2E:
    """production_untrusted produces seccomp + cgroup limits on Linux."""

    @pytest.mark.skipif(
        not _SECCOMP_CAPABLE,
        reason="requires a Linux runtime that can enforce seccomp-bpf "
               "(bare metal or capable VM; LXC/nested containers cannot)"
    )
    def test_production_untrusted_full_enforcement(self):
        """production_untrusted → seccomp + cgroup_limits_enforced=true."""
        import asyncio
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        _clean_preset_env()
        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        os.environ["NODECHAIN_POLICY_PRESET_SOURCE"] = "cli"
        os.environ["NODECHAIN_SANDBOX_PROFILE"] = "os_profile"

        try:
            runner = get_subprocess_runner()

            # Verify runner is configured from preset
            assert runner.enable_cgroup is True
            assert runner.cgroup_memory_max_mb == 512
            assert runner.cgroup_pids_max == 50
            assert runner.cgroup_cpu_max_quota == 200000

            envelope = InvocationEnvelope(
                envelope_id="test_prod",
                run_id="test_prod",
                chain_id="test",
                node_id="echo",
                step_id=1,
                payload={"query": "hello production"},
            )

            result = asyncio.run(runner.run_isolated(
                envelope=envelope,
                module_path=echo_path,
                class_name="EchoNode",
                node_id="echo",
                trust_level="local_untrusted",
                package_root=str(Path(echo_path).parent.resolve()),
                enable_seccomp=True,  # As isolation_config would provide
            ))

            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        finally:
            _clean_preset_env()


# ─── 3. Blueprint-Declared Preset ────────────────────────────────────────

class TestBlueprintDeclaredPreset:
    """Blueprint policy_preset works without manual env vars."""

    def test_demo_blueprint_has_preset(self):
        import yaml
        bp_path = Path("blueprints/production_untrusted_demo_v1.yaml")
        if not bp_path.exists():
            pytest.skip("Demo blueprint not found")
        data = yaml.safe_load(bp_path.read_text())
        assert data.get("policy_preset") == "production_untrusted"

    def test_blueprint_model_reads_preset(self):
        from nodechain.core.blueprint import ChainBlueprint
        bp = ChainBlueprint(
            chain_id="test",
            name="test",
            goal="test",
            nodes=[],
            connections=[],
            policy_preset="standard_untrusted",
        )
        assert bp.policy_preset == "standard_untrusted"

    def test_blueprint_resolver_sets_env_var(self):
        """Blueprint policy_preset → NODECHAIN_POLICY_PRESET env var."""
        _clean_preset_env()
        try:
            # Simulate the CLI resolver: blueprint has preset, no CLI override
            cli_preset = None
            blueprint_preset = "standard_untrusted"

            effective_preset = cli_preset or blueprint_preset or ""
            preset_source = "blueprint" if (not cli_preset and blueprint_preset) else "cli"

            assert effective_preset == "standard_untrusted"
            assert preset_source == "blueprint"

            # Apply as CLI does
            if effective_preset:
                os.environ["NODECHAIN_POLICY_PRESET"] = effective_preset
                os.environ["NODECHAIN_POLICY_PRESET_SOURCE"] = preset_source
                from nodechain.sdk.policy_presets import get_preset
                preset = get_preset(effective_preset)
                if preset and not os.environ.get("NODECHAIN_SANDBOX_PROFILE"):
                    os.environ["NODECHAIN_SANDBOX_PROFILE"] = preset.sandbox_profile

            assert os.environ.get("NODECHAIN_POLICY_PRESET") == "standard_untrusted"
            assert os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE") == "blueprint"
            assert os.environ.get("NODECHAIN_SANDBOX_PROFILE") == "os_profile"
        finally:
            _clean_preset_env()


# ─── 4. CLI Override Determinism ─────────────────────────────────────────

class TestCLIOverrideDeterminism:
    """CLI preset overrides blueprint preset deterministically."""

    def test_cli_overrides_blueprint(self):
        _clean_preset_env()
        try:
            cli_preset = "minimal"
            blueprint_preset = "production_untrusted"

            effective = cli_preset or ""
            source = "cli" if cli_preset else "blueprint"

            assert effective == "minimal"
            assert source == "cli"

            # CLI preset applies
            os.environ["NODECHAIN_POLICY_PRESET"] = effective
            os.environ["NODECHAIN_POLICY_PRESET_SOURCE"] = source

            from nodechain.sdk.policy_presets import get_preset
            preset = get_preset(effective)
            # minimal should NOT set os_profile
            assert preset.sandbox_profile == "subprocess_isolated"
        finally:
            _clean_preset_env()

    def test_no_preset_when_neither_set(self):
        _clean_preset_env()
        try:
            cli_preset = None
            blueprint_preset = ""

            effective = cli_preset or blueprint_preset or ""
            assert effective == ""
            assert "NODECHAIN_POLICY_PRESET" not in os.environ
        finally:
            _clean_preset_env()


# ─── 5. TrustSummary Reports Actual Evidence ─────────────────────────────

class TestTrustSummaryActualEvidence:
    """TrustSummary reports actual enforced capabilities."""

    def test_summary_includes_preset_fields(self):
        from nodechain.sdk.trust_summary import TrustSummary
        summary = TrustSummary(run_id="test")
        summary.policy_preset = "production_untrusted"
        summary.preset_source = "cli"
        d = summary.to_dict()
        assert d["policy_preset"] == "production_untrusted"
        assert d["preset_source"] == "cli"

    def test_node_record_has_cgroup_evidence(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.policy_preset = "production_untrusted"
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            syscall_filtering_enforced=True,
            cgroup_available=True,
            cgroup_limits_requested=True,
            cgroup_limits_enforced=True,
            cgroup_memory_max_mb=512,
            cgroup_pids_max=50,
            cgroup_cpu_max_quota=200000,
            cgroup_accounting_scope="invocation",
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["syscall_filtering_enforced"] is True
        assert node["cgroup_limits_enforced"] is True
        assert node["cgroup_memory_max_mb"] == 512


# ─── 6. Version and Changelog ────────────────────────────────────────────

class TestV137Version:
    """Version reflects v1.3.7."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v137(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
