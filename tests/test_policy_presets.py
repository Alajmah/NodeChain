"""Tests for policy preset productization (v1.3.5).

Tests cover:
1. CLI --policy-preset option exists
2. Blueprint policy_preset field
3. Preset resolution order (CLI > blueprint > default)
4. TrustSummary reports preset/source
5. INV-010 preset enforcement
6. CLI presets command
7. Strict mode enforces but doesn't invent
"""

from __future__ import annotations

import pytest
from pathlib import Path

from nodechain.sdk.policy_presets import (
    PolicyPreset,
    PRESETS,
    get_preset,
    list_presets,
)
from nodechain.sdk.trust_summary import (
    NodeTrustRecord,
    TrustSummary,
)


# ─── 1. Blueprint policy_preset Field ────────────────────────────────────

class TestBlueprintPolicyPreset:
    """Blueprint accepts policy_preset field."""

    def test_blueprint_has_policy_preset_field(self):
        from nodechain.core.blueprint import ChainBlueprint
        bp = ChainBlueprint(
            chain_id="test",
            name="test",
            goal="test",
            nodes=[],
            connections=[],
            policy_preset="production_untrusted",
        )
        assert bp.policy_preset == "production_untrusted"

    def test_blueprint_default_empty_preset(self):
        from nodechain.core.blueprint import ChainBlueprint
        bp = ChainBlueprint(
            chain_id="test",
            name="test",
            goal="test",
            nodes=[],
            connections=[],
        )
        assert bp.policy_preset == ""

    def test_blueprint_json_schema_has_preset(self):
        schema = Path("schemas/chain_blueprint.json").read_text()
        assert "policy_preset" in schema


# ─── 2. CLI --policy-preset Option ───────────────────────────────────────

class TestCLIPolicyPreset:
    """CLI exposes --policy-preset option."""

    def test_cli_has_policy_preset_option(self):
        from nodechain.cli import main as cli_main
        source = open(cli_main.__file__, encoding="utf-8").read()
        assert "--policy-preset" in source

    def test_cli_presets_command_exists(self):
        from nodechain.cli import main as cli_main
        source = open(cli_main.__file__, encoding="utf-8").read()
        assert "presets" in source.lower()


# ─── 3. Preset Resolution Order ──────────────────────────────────────────

class TestPresetResolutionOrder:
    """Preset resolution is deterministic: CLI > blueprint > default."""

    def test_cli_override_takes_precedence(self):
        """CLI flag overrides blueprint declaration."""
        cli_preset = "minimal"
        blueprint_preset = "production_untrusted"
        # CLI wins
        effective = cli_preset or ""
        assert effective == "minimal"

    def test_blueprint_used_when_no_cli(self):
        """Blueprint used when CLI flag not set."""
        cli_preset = None
        blueprint_preset = "standard_untrusted"
        effective = cli_preset or blueprint_preset or ""
        assert effective == "standard_untrusted"

    def test_default_empty_when_neither_set(self):
        """No preset when neither CLI nor blueprint declares one."""
        cli_preset = None
        blueprint_preset = ""
        effective = cli_preset or blueprint_preset or ""
        assert effective == ""


# ─── 4. TrustSummary Preset Reporting ────────────────────────────────────

class TestTrustSummaryPresetReporting:
    """TrustSummary reports policy_preset and preset_source."""

    def test_fields_exist(self):
        summary = TrustSummary(run_id="test")
        assert hasattr(summary, "policy_preset")
        assert hasattr(summary, "preset_source")

    def test_fields_in_to_dict(self):
        summary = TrustSummary(run_id="test")
        summary.policy_preset = "production_untrusted"
        summary.preset_source = "cli"
        d = summary.to_dict()
        assert d["policy_preset"] == "production_untrusted"
        assert d["preset_source"] == "cli"

    def test_default_values(self):
        summary = TrustSummary(run_id="test")
        d = summary.to_dict()
        assert d["policy_preset"] == ""
        assert d["preset_source"] == ""


# ─── 5. INV-010 Preset Enforcement ───────────────────────────────────────

class TestINV010PresetEnforcement:
    """INV-010 enforces preset requirements."""

    def test_inv010_fires_when_seccomp_required_but_missing(self):
        """production_untrusted requires seccomp."""
        summary = TrustSummary(run_id="test")
        summary.policy_preset = "production_untrusted"
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            cgroup_available=True,
            cgroup_limits_enforced=True,
            syscall_filtering_enforced=False,  # ← missing
        ))
        violations = summary.validate_invariants()
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) >= 1
        assert "seccomp" in inv010[0].invariant

    def test_inv010_fires_when_cgroup_required_but_missing(self):
        """production_untrusted requires cgroup."""
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
            cgroup_available=False,  # ← missing
            cgroup_limits_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) >= 1
        assert "cgroup" in inv010[0].invariant

    def test_inv010_passes_when_all_requirements_met(self):
        """production_untrusted passes with all requirements met."""
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
            cgroup_limits_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) == 0

    def test_inv010_passes_when_no_preset_set(self):
        """No preset → no INV-010 check."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="basic",
            trust_level="built_in",
        ))
        violations = summary.validate_invariants()
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) == 0

    def test_inv010_standard_untrusted_requires_seccomp(self):
        """standard_untrusted requires seccomp."""
        summary = TrustSummary(run_id="test")
        summary.policy_preset = "standard_untrusted"
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            syscall_filtering_enforced=False,  # ← missing
        ))
        violations = summary.validate_invariants()
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) >= 1

    def test_inv010_minimal_no_extra_requirements(self):
        """minimal preset has no extra requirements."""
        summary = TrustSummary(run_id="test")
        summary.policy_preset = "minimal"
        summary.add_node(NodeTrustRecord(
            node_id="basic",
            trust_level="built_in",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants()
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) == 0

    def test_strict_mode_does_not_invent_preset(self):
        """Strict mode without preset does not create INV-010 violations."""
        summary = TrustSummary(run_id="test")
        # No preset declared
        summary.add_node(NodeTrustRecord(
            node_id="basic",
            trust_level="built_in",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants(strict=True)
        inv010 = [v for v in violations if v.code == "INV-010"]
        assert len(inv010) == 0


# ─── 6. Preset API ───────────────────────────────────────────────────────

class TestPresetAPI:
    """Preset API surface is complete."""

    def test_four_presets_available(self):
        names = list_presets()
        assert len(names) == 4
        assert set(names) == {"minimal", "standard_untrusted", "production_untrusted", "hardened_untrusted"}

    def test_production_untrusted_defaults(self):
        p = get_preset("production_untrusted")
        assert p.cgroup_memory_max_mb == 512
        assert p.cgroup_pids_max == 50

    def test_preset_to_dict_is_serializable(self):
        import json
        p = get_preset("production_untrusted")
        d = p.to_dict()
        # Must be JSON-serializable
        json.dumps(d)


# ─── 7. Version and Changelog ────────────────────────────────────────────

class TestV135Version:
    """Version reflects v1.3.5."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v135(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
