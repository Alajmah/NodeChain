"""Multi-Registry Federation Tests (v2.5.0).

Tests all 10 acceptance criteria.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def _meta(pkg: str, ver: str, digest: str = "", pub: str = "pub_fp"):
    """Create metadata dict."""
    import hashlib
    return {
        "artifact_digest": digest or hashlib.sha256(f"{pkg}{ver}".encode()).hexdigest(),
        "metadata_digest": hashlib.sha256(f"meta-{pkg}{ver}".encode()).hexdigest(),
        "publisher_fingerprint": pub,
        "signer_fingerprint": "signer_fp",
        "metadata_signed": True,
    }


def _store_with(*registries):
    """Create a FederationConfigStore with registries."""
    from nodechain.sdk.federation import FederationConfigStore, FederatedRegistryConfig
    return FederationConfigStore(registries=list(registries))


# ── AC1: FederatedRegistryConfig ─────────────────────────────────────────────

class TestAC1Config:
    """AC1: FederatedRegistryConfig model."""

    def test_config_creation(self):
        from nodechain.sdk.federation import FederatedRegistryConfig
        c = FederatedRegistryConfig(
            registry_id="reg-a",
            base_url="https://reg-a.example.com",
        )
        assert c.registry_id == "reg-a"
        assert c.priority == 100
        assert c.enabled is True
        assert c.trust_level == "remote_untrusted"

    def test_config_serialization(self):
        from nodechain.sdk.federation import FederatedRegistryConfig
        c = FederatedRegistryConfig(
            registry_id="reg-a",
            base_url="https://reg-a.example.com",
            priority=50,
            allowed_publishers=["pub1"],
        )
        d = c.to_dict()
        c2 = FederatedRegistryConfig.from_dict(d)
        assert c2.registry_id == c.registry_id
        assert c2.priority == 50
        assert c2.allowed_publishers == ["pub1"]

    def test_publisher_filtering(self):
        from nodechain.sdk.federation import FederatedRegistryConfig
        c = FederatedRegistryConfig(
            registry_id="reg",
            base_url="https://r",
            allowed_publishers=["good_pub"],
        )
        assert c.is_publisher_allowed("good_pub")
        assert not c.is_publisher_allowed("bad_pub")

    def test_package_filtering(self):
        from nodechain.sdk.federation import FederatedRegistryConfig
        c = FederatedRegistryConfig(
            registry_id="reg",
            base_url="https://r",
            allowed_packages=["pkg_a"],
        )
        assert c.is_package_allowed("pkg_a")
        assert not c.is_package_allowed("pkg_b")

    def test_empty_lists_allow_all(self):
        from nodechain.sdk.federation import FederatedRegistryConfig
        c = FederatedRegistryConfig(registry_id="reg", base_url="https://r")
        assert c.is_publisher_allowed("anyone")
        assert c.is_package_allowed("anything")


# ── AC2: Registry allowlist governed by policy ───────────────────────────────

class TestAC2AllowlistPolicy:
    """AC2: Federation requires organization profile approval."""

    def test_policy_denies_federation(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederationConfigStore, FederatedRegistryConfig,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r"))
        profile = get_builtin_profile("airgapped_high_assurance")
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v),
            store, org_profile=profile,
        )
        assert not result.all_passed
        assert any("Policy denied" in r["reason"] for r in result.rejected)

    def test_no_policy_allows(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederationConfigStore, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r"))
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v),
            store, org_profile=None,
        )
        assert result.all_passed


# ── AC3: CLI commands ────────────────────────────────────────────────────────

class TestAC3CLI:
    """AC3: Federation CLI commands."""

    def test_list_empty(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", str(tmp_path / "fed.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "federation", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_add(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", str(tmp_path / "fed.json"))
        runner = CliRunner()
        result = runner.invoke(cli, [
            "registry", "federation", "add",
            "--registry-id", "reg-a",
            "--base-url", "https://reg-a.example.com",
            "--priority", "10",
            "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["registry_id"] == "reg-a"

    def test_remove(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        fed_path = str(tmp_path / "fed.json")
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", fed_path)
        runner = CliRunner()
        runner.invoke(cli, [
            "registry", "federation", "add",
            "--registry-id", "reg-a",
            "--base-url", "https://r",
        ])
        result = runner.invoke(cli, ["registry", "federation", "remove", "reg-a"])
        assert result.exit_code == 0

    def test_verify(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", str(tmp_path / "fed.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "federation", "verify", "--json"])
        assert result.exit_code == 0

    def test_resolve(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", str(tmp_path / "fed.json"))
        monkeypatch.setenv("NODECHAIN_ACTIVE_POLICY_PROFILE", str(tmp_path / "policy.json"))
        runner = CliRunner()
        runner.invoke(cli, [
            "registry", "federation", "add",
            "--registry-id", "reg-a",
            "--base-url", "https://reg-a.example.com",
            "--priority", "10",
        ])
        result = runner.invoke(cli, [
            "registry", "federation", "resolve",
            "--package-id", "test_pkg",
            "--version", "1.0",
            "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["all_passed"] is True


# ── AC4: Federation resolver ─────────────────────────────────────────────────

class TestAC4Resolver:
    """AC4: Resolver searches, applies policy, detects conflicts, selects winner."""

    def test_single_registry_resolves(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg-a", base_url="https://r"))
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert result.all_passed
        assert result.selected.registry_id == "reg-a"

    def test_priority_selection(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="reg-low", base_url="https://r-low", priority=50),
            FederatedRegistryConfig(
                registry_id="reg-high", base_url="https://r-high", priority=10),
        )
        # Both return same digest
        def fetcher(r, p, v): return _meta(p, v)
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert result.all_passed
        assert result.selected.registry_id == "reg-high"

    def test_disabled_registry_skipped(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="reg-disabled", base_url="https://r", enabled=False),
            FederatedRegistryConfig(
                registry_id="reg-enabled", base_url="https://r2", priority=10),
        )
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert result.all_passed
        assert result.selected.registry_id == "reg-enabled"

    def test_disallowed_package_rejected(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r",
            allowed_packages=["other_pkg"]))
        result = resolve_federated_package(
            "target_pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert not result.all_passed

    def test_disallowed_publisher_rejected(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r",
            allowed_publishers=["good_pub"]))
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v, pub="bad_pub"), store)
        assert not result.all_passed


# ── AC5: Conflict handling ───────────────────────────────────────────────────

class TestAC5Conflict:
    """AC5: Same package/version with different digests fails closed."""

    def test_different_digests_fail_closed(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="reg-a", base_url="https://r-a", priority=10),
            FederatedRegistryConfig(
                registry_id="reg-b", base_url="https://r-b", priority=20),
        )
        def fetcher(r, p, v):
            if r == "reg-a":
                return _meta(p, v, digest="aaa")
            return _meta(p, v, digest="bbb")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0

    def test_same_digest_accepted(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="reg-a", base_url="https://r-a", priority=10),
            FederatedRegistryConfig(
                registry_id="reg-b", base_url="https://r-b", priority=20),
        )
        def fetcher(r, p, v):
            return _meta(p, v, digest="same_digest")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert result.all_passed
        assert result.selected.registry_id == "reg-a"  # Higher priority

    def test_priority_after_checks(self):
        """Priority only applies after digest/signature/policy checks."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="reg-low-pri", base_url="https://r", priority=100),
            FederatedRegistryConfig(
                registry_id="reg-high-pri", base_url="https://r2", priority=1),
        )
        # High priority has disallowed publisher
        def fetcher(r, p, v):
            if r == "reg-high-pri":
                return _meta(p, v, pub="bad")
            return _meta(p, v, pub="good")
        # Block "bad" publisher on high-pri registry
        store.get("reg-high-pri").allowed_publishers = ["good"]
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        # Should select low-pri because high-pri was rejected
        assert result.all_passed
        assert result.selected.registry_id == "reg-low-pri"


# ── AC6: Transparency integration ────────────────────────────────────────────

class TestAC6Transparency:
    """AC6: New transparency event types for federation."""

    def test_new_event_types(self):
        from nodechain.sdk.transparency_log import EVENT_TYPES
        assert "registry_selected" in EVENT_TYPES
        assert "registry_conflict" in EVENT_TYPES
        assert "federated_package_resolved" in EVENT_TYPES

    def test_can_log_federation_events(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        log.append("registry_selected", "reg-a", "1.0.0")
        log.append("registry_conflict", "pkg", "1.0.0")
        log.append("federated_package_resolved", "pkg", "1.0.0")
        assert log.length == 3
        assert log.verify().valid


# ── AC7: Evidence ────────────────────────────────────────────────────────────

class TestAC7Evidence:
    """AC7: federated_resolution_receipt evidence type and resolution data."""

    def test_evidence_type_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "federated_resolution_receipt" in EVIDENCE_TYPES

    def test_resolution_result_has_required_fields(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r"))
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        d = result.to_dict()
        assert "selected_registry_id" in d
        assert "candidate_registry_ids" in d
        assert "rejected_registry_reasons" in d
        assert "selected_package_digest" in d
        assert "policy_profile_digest" in d


# ── AC8: Dashboard ───────────────────────────────────────────────────────────

class TestAC8Dashboard:
    """AC8: HR-016 federation health rule."""

    def test_hr016_exists(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        assert "HR-016" in RULES_BY_ID

    def test_hr016_disabled_registries(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({"federation": {"enabled": True, "disabled_count": 2}})
        assert result is not None
        assert "disabled" in result["name"]

    def test_hr016_conflicts(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({"federation": {"enabled": True, "conflict_count": 1}})
        assert result is not None

    def test_hr016_policy_denied(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({"federation": {"enabled": True, "policy_denied_count": 1}})
        assert result is not None

    def test_hr016_no_registries(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({"federation": {"enabled": True, "total_registries": 0}})
        assert result is not None

    def test_hr016_healthy(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({
            "federation": {
                "enabled": True, "disabled_count": 0,
                "conflict_count": 0, "policy_denied_count": 0,
                "total_registries": 3,
            },
        })
        assert result is None

    def test_hr016_not_enabled(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({"federation": {"enabled": False}})
        assert result is None


# ── AC9: Negative tests ──────────────────────────────────────────────────────

class TestAC9Negative:
    """AC9: Adversarial federation scenarios."""

    def test_unlisted_registry_not_consulted(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederationConfigStore, FederatedRegistryConfig,
        )
        # Empty store
        store = FederationConfigStore()
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert not result.all_passed

    def test_signer_mismatch_rejected(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r",
            required_signer_fingerprint="expected_signer"))
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert not result.all_passed
        assert any("Signer mismatch" in r["reason"] for r in result.rejected)

    def test_publisher_mismatch_rejected(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r",
            allowed_publishers=["trusted_pub"]))
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v, pub="untrusted"), store)
        assert not result.all_passed

    def test_package_digest_conflict_fails_closed(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="reg-a", base_url="https://ra", priority=10),
            FederatedRegistryConfig(
                registry_id="reg-b", base_url="https://rb", priority=20),
        )
        def fetcher(r, p, v):
            return _meta(p, v, digest=f"digest_{r}")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0

    def test_priority_spoofing_blocked(self):
        """A high-priority registry can't override a rejected candidate."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="good-reg", base_url="https://r", priority=50,
                allowed_publishers=["good"]),
            FederatedRegistryConfig(
                registry_id="spoof-reg", base_url="https://r2", priority=1),
        )
        def fetcher(r, p, v):
            if r == "spoof-reg":
                return _meta(p, v, pub="evil")
            return _meta(p, v, pub="good")
        # Block evil publisher on spoof-reg
        store.get("spoof-reg").allowed_publishers = ["good"]
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert result.all_passed
        assert result.selected.registry_id == "good-reg"

    def test_registry_shadowing_detected(self):
        """A lower-priority registry with different digest is a conflict."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="primary", base_url="https://rp", priority=10),
            FederatedRegistryConfig(
                registry_id="shadow", base_url="https://rs", priority=100),
        )
        def fetcher(r, p, v):
            if r == "primary":
                return _meta(p, v, digest="real")
            return _meta(p, v, digest="shadowed")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0

    def test_dependency_confusion_across_registries(self):
        """Package from wrong registry with same name but different publisher."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="official", base_url="https://ro", priority=10,
                allowed_publishers=["official_pub"]),
            FederatedRegistryConfig(
                registry_id="unofficial", base_url="https://ru", priority=100,
                allowed_publishers=["attacker_pub"]),
        )
        def fetcher(r, p, v):
            if r == "official":
                return _meta(p, v, digest="d1", pub="official_pub")
            return _meta(p, v, digest="d2", pub="attacker_pub")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        # Both have different digests → conflict
        assert not result.all_passed

    def test_profile_denied_federation(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        store = _store_with(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r"))
        profile = get_builtin_profile("airgapped_high_assurance")
        result = resolve_federated_package(
            "pkg", "1.0", lambda r, p, v: _meta(p, v), store, org_profile=profile)
        assert not result.all_passed


# ── AC10: Config store persistence ────────────────────────────────────────────

class TestAC10StorePersistence:
    """AC10: Federation config persistence."""

    def test_save_and_load(self, tmp_path):
        from nodechain.sdk.federation import (
            FederationConfigStore, FederatedRegistryConfig,
            save_federation_config, load_federation_config,
        )
        path = str(tmp_path / "fed.json")
        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(
                registry_id="reg", base_url="https://r", priority=42),
        ])
        save_federation_config(store, path)
        loaded = load_federation_config(path)
        assert len(loaded.registries) == 1
        assert loaded.get("reg").priority == 42

    def test_add_replaces_existing(self, tmp_path):
        from nodechain.sdk.federation import FederationConfigStore, FederatedRegistryConfig
        store = FederationConfigStore()
        store.add(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r", priority=100))
        store.add(FederatedRegistryConfig(
            registry_id="reg", base_url="https://r", priority=50))
        assert len(store.registries) == 1
        assert store.get("reg").priority == 50

    def test_verify_federation(self):
        from nodechain.sdk.federation import (
            FederationConfigStore, FederatedRegistryConfig, verify_federation,
        )
        store = _store_with(
            FederatedRegistryConfig(
                registry_id="good", base_url="https://r"),
            FederatedRegistryConfig(
                registry_id="bad-url", base_url="not-a-url"),
        )
        report = verify_federation(store)
        assert not report["valid"]
        assert any("bad-url" in e for e in report["errors"])


# ── Additional: All 16 health rules ──────────────────────────────────────────

class TestHealthRules:
    def test_all_21_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
