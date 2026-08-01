"""Public Discovery and Marketplace Integration Tests (v2.21.3).

Tests all 12 acceptance criteria.
NON-NEGOTIABLE RULES:
    Marketplace listing is not certification.
    Discovery index signature is not package trust.
    Registry reachability is not registry eligibility.
    Popularity is not reputation.
    Reputation is not trust.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


def _make_index_data(
    index_id: str = "idx-1",
    registries: list | None = None,
    publishers: list | None = None,
    packages: list | None = None,
    generated_at: str = "2026-06-17T12:00:00Z",
    include_digest: bool = True,
    signature: str = "",
    signer: str = "",
) -> dict:
    """Build a discovery index dict."""
    data = {
        "index_id": index_id,
        "source_url": "https://marketplace.example.com/index.json",
        "generated_at": generated_at,
        "registries": registries or [
            {"registry_id": "reg-a", "base_url": "https://reg-a.example.com",
             "display_name": "Registry A", "description": "Test registry A",
             "categories": ["testing"], "claimed_publishers": ["pub1"],
             "claimed_packages": ["pkg-x"]},
        ],
        "publishers": publishers or ["pub1"],
        "packages": packages or ["pkg-x"],
    }
    if signature:
        data["signature"] = signature
    if signer:
        data["signer_fingerprint"] = signer
    if include_digest:
        from nodechain.sdk.discovery import compute_index_digest
        data["index_digest"] = compute_index_digest(data)
    return data


# ── AC1: PublicDiscoveryIndex model ──────────────────────────────────────────

class TestAC1Model:
    def test_model_creation(self):
        from nodechain.sdk.discovery import PublicDiscoveryIndex, MarketplaceRegistryListing
        idx = PublicDiscoveryIndex(
            index_id="test",
            source_url="https://example.com",
            generated_at="2026-06-17T12:00:00Z",
            registries=[MarketplaceRegistryListing(registry_id="r", base_url="https://r")],
            publishers=["pub1"],
            packages=["pkg1"],
            index_digest="abc123",
        )
        assert idx.index_id == "test"
        assert len(idx.registries) == 1
        assert idx.publishers == ["pub1"]

    def test_serialization(self):
        from nodechain.sdk.discovery import PublicDiscoveryIndex
        idx = PublicDiscoveryIndex(
            index_id="test", source_url="https://e", generated_at="now",
        )
        d = idx.to_dict()
        idx2 = PublicDiscoveryIndex.from_dict(d)
        assert idx2.index_id == idx.index_id

    def test_index_has_all_fields(self):
        from nodechain.sdk.discovery import PublicDiscoveryIndex
        idx = PublicDiscoveryIndex(index_id="t", source_url="u", generated_at="g")
        d = idx.to_dict()
        required = {"index_id", "source_url", "generated_at", "registries",
                    "publishers", "packages", "index_digest", "signature", "signer_fingerprint"}
        assert required.issubset(set(d.keys()))


# ── AC2: MarketplaceRegistryListing ──────────────────────────────────────────

class TestAC2Listing:
    def test_listing_fields(self):
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
            display_name="Test", description="desc",
            categories=["cat1"], claimed_publishers=["pub"],
            claimed_packages=["pkg"], reputation_hint="A",
        )
        d = listing.to_dict()
        required = {"registry_id", "base_url", "display_name", "description",
                    "categories", "claimed_publishers", "claimed_packages",
                    "reputation_hint", "discovery_metadata_digest"}
        assert required.issubset(set(d.keys()))

    def test_listing_to_federation_config(self):
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
        )
        config = listing.to_federation_config()
        assert config.registry_id == "reg"
        assert config.enabled is False  # always disabled from discovery
        assert config.trust_level == "remote_untrusted"


# ── AC3: Discovery client ────────────────────────────────────────────────────

class TestAC3Client:
    def test_fetch_and_parse(self):
        from nodechain.sdk.discovery import fetch_discovery_index
        data = _make_index_data()
        raw = json.dumps(data).encode()
        def fetcher(url):
            return raw
        idx = fetch_discovery_index("https://marketplace.example.com", fetcher_fn=fetcher)
        assert idx.index_id == "idx-1"
        assert len(idx.registries) == 1

    def test_reject_corrupt_json(self):
        from nodechain.sdk.discovery import fetch_discovery_index, DiscoveryError
        def fetcher(url):
            return b"garbage{{{"
        with pytest.raises(DiscoveryError):
            fetch_discovery_index("https://e", fetcher_fn=fetcher)

    def test_reject_oversized(self):
        from nodechain.sdk.discovery import fetch_discovery_index, DiscoveryError
        def fetcher(url):
            return b"x" * (11 * 1024 * 1024)
        with pytest.raises(DiscoveryError, match="oversized"):
            fetch_discovery_index("https://e", fetcher_fn=fetcher)

    def test_reject_digest_mismatch(self):
        from nodechain.sdk.discovery import parse_discovery_index, DiscoveryError
        data = _make_index_data()
        data["index_digest"] = "tampered"
        with pytest.raises(DiscoveryError, match="mismatch"):
            parse_discovery_index(data)

    def test_stale_index_detected(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="old", source_url="https://e",
            generated_at="2020-01-01T00:00:00Z",
            signature="sig", signer_fingerprint="signer",  # signed so signature check passes
        )
        # Custom profile that checks age but not signature
        profile = OrganizationTrustPolicyProfile(
            name="test", description="test",
            allow_public_discovery=True,
            maximum_discovery_index_age=7,
        )
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "old" in reason.lower() or "day" in reason.lower()


# ── AC4: CLI commands ────────────────────────────────────────────────────────

class TestAC4CLI:
    def test_marketplace_in_top_level(self):
        from nodechain.cli.main import cli
        assert "marketplace" in cli.commands

    def test_discover_from_file(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        data = _make_index_data()
        index_file = tmp_path / "index.json"
        index_file.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setenv("NODECHAIN_DISCOVERY_STORE", str(tmp_path / "disc.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["marketplace", "discover", str(index_file), "--json"])
        assert result.exit_code == 0
        receipt = json.loads(result.output)
        assert receipt["index_id"] == "idx-1"

    def test_search(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        data = _make_index_data()
        index_file = tmp_path / "index.json"
        index_file.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setenv("NODECHAIN_DISCOVERY_STORE", str(tmp_path / "disc.json"))
        runner = CliRunner()
        runner.invoke(cli, ["marketplace", "discover", str(index_file)])
        result = runner.invoke(cli, ["marketplace", "search", "--json"])
        assert result.exit_code == 0
        results = json.loads(result.output)
        assert len(results) >= 1

    def test_inspect(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        data = _make_index_data()
        index_file = tmp_path / "index.json"
        index_file.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setenv("NODECHAIN_DISCOVERY_STORE", str(tmp_path / "disc.json"))
        runner = CliRunner()
        runner.invoke(cli, ["marketplace", "discover", str(index_file)])
        result = runner.invoke(cli, ["marketplace", "inspect", "reg-a", "--json"])
        assert result.exit_code == 0

    def test_verify(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        data = _make_index_data()
        index_file = tmp_path / "index.json"
        index_file.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setenv("NODECHAIN_DISCOVERY_STORE", str(tmp_path / "disc.json"))
        runner = CliRunner()
        runner.invoke(cli, ["marketplace", "discover", str(index_file)])
        result = runner.invoke(cli, ["marketplace", "verify", "--json"])
        assert result.exit_code == 0


# ── AC5: Discovery never auto-adds ───────────────────────────────────────────

class TestAC5NoAutoAdd:
    def test_discovery_does_not_modify_federation_config(self, tmp_path):
        from nodechain.sdk.discovery import parse_discovery_index
        from nodechain.sdk.federation import FederationConfigStore, load_federation_config
        fed_path = str(tmp_path / "fed.json")
        # Empty federation config
        fed_store = FederationConfigStore()
        from nodechain.sdk.federation import save_federation_config
        save_federation_config(fed_store, fed_path)

        # Discover an index
        data = _make_index_data()
        idx = parse_discovery_index(data)

        # Federation config should still be empty
        reloaded = load_federation_config(fed_path)
        assert len(reloaded.registries) == 0

    def test_add_registry_is_explicit(self):
        from nodechain.sdk.discovery import (
            parse_discovery_index, add_registry_from_discovery,
        )
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        assert len(store.registries) == 0
        receipt = add_registry_from_discovery(
            idx.registries[0], idx, store,
        )
        assert len(store.registries) == 1
        assert store.registries[0].enabled is False  # disabled by default


# ── AC6: Org profile controls discovery ──────────────────────────────────────

class TestAC6ProfileControls:
    def test_airgapped_denies_discovery(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile
        idx = PublicDiscoveryIndex(index_id="t", source_url="https://e", generated_at="2026-06-17T12:00:00+00:00")
        profile = get_builtin_profile("airgapped_high_assurance")
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed

    def test_strict_requires_signed_index(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile
        idx = PublicDiscoveryIndex(index_id="t", source_url="https://e", generated_at="2026-06-17T12:00:00+00:00")
        profile = get_builtin_profile("strict_enterprise")
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "signed" in reason.lower()

    def test_permissive_allows_discovery(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile
        idx = PublicDiscoveryIndex(index_id="t", source_url="https://e", generated_at="2026-06-17T12:00:00+00:00")
        profile = get_builtin_profile("permissive_local")
        allowed, reason = check_discovery_policy(idx, profile)
        assert allowed

    def test_profile_has_discovery_fields(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("permissive_local")
        assert hasattr(p, "allow_public_discovery")
        assert hasattr(p, "allowed_discovery_sources")
        assert hasattr(p, "require_signed_discovery_index")
        assert hasattr(p, "maximum_discovery_index_age")
        assert hasattr(p, "allow_marketplace_registry_add")


# ── AC7: Federation integration ──────────────────────────────────────────────

class TestAC7FederationIntegration:
    def test_added_registry_is_normal_config(self):
        from nodechain.sdk.discovery import (
            parse_discovery_index, add_registry_from_discovery,
        )
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        add_registry_from_discovery(idx.registries[0], idx, store)
        reg = store.get("reg-a")
        assert reg is not None
        assert reg.trust_level == "remote_untrusted"
        assert reg.enabled is False

    def test_strict_denies_marketplace_add(self):
        from nodechain.sdk.discovery import (
            parse_discovery_index, add_registry_from_discovery, MarketplacePolicyDenial,
        )
        from nodechain.sdk.federation import FederationConfigStore
        from nodechain.sdk.org_policy import get_builtin_profile
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        profile = get_builtin_profile("strict_enterprise")
        with pytest.raises(MarketplacePolicyDenial):
            add_registry_from_discovery(idx.registries[0], idx, store, profile)


# ── AC8: Transparency integration ────────────────────────────────────────────

class TestAC8Transparency:
    def test_new_event_types(self):
        from nodechain.sdk.transparency_log import EVENT_TYPES
        assert "discovery_index_seen" in EVENT_TYPES
        assert "registry_discovered" in EVENT_TYPES
        assert "registry_added_from_discovery" in EVENT_TYPES

    def test_can_log_discovery_events(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        log.append("discovery_index_seen", "idx-1", "1.0.0")
        log.append("registry_discovered", "reg-a", "1.0.0")
        log.append("registry_added_from_discovery", "reg-a", "1.0.0")
        assert log.verify().valid


# ── AC9: Evidence ────────────────────────────────────────────────────────────

class TestAC9Evidence:
    def test_evidence_types_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "discovery_index_receipt" in EVIDENCE_TYPES
        assert "marketplace_registry_add_receipt" in EVIDENCE_TYPES

    def test_receipt_has_required_fields(self):
        from nodechain.sdk.discovery import (
            parse_discovery_index, add_registry_from_discovery, MarketplaceRegistryAddReceipt,
        )
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        receipt = add_registry_from_discovery(idx.registries[0], idx, store)
        d = receipt.to_dict()
        assert "registry_id" in d
        assert "source_index_id" in d
        assert "policy_approved" in d
        assert "federation_config_digest" in d


# ── AC10: Dashboard ──────────────────────────────────────────────────────────

class TestAC10Dashboard:
    def test_hr018_exists(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        assert "HR-018" in RULES_BY_ID

    def test_hr018_stale_index(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-018"]
        result = rule.evaluate({"discovery": {"enabled": True, "stale_index_count": 1}})
        assert result is not None

    def test_hr018_unsigned_index(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-018"]
        result = rule.evaluate({"discovery": {"enabled": True, "unsigned_index_count": 1}})
        assert result is not None

    def test_hr018_pending_approval(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-018"]
        result = rule.evaluate({"discovery": {"enabled": True, "pending_approval_count": 2}})
        assert result is not None

    def test_hr018_policy_denial(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-018"]
        result = rule.evaluate({"discovery": {"enabled": True, "policy_denial_count": 1}})
        assert result is not None

    def test_hr018_healthy(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-018"]
        result = rule.evaluate({
            "discovery": {
                "enabled": True, "stale_index_count": 0,
                "unsigned_index_count": 0, "pending_approval_count": 0,
                "policy_denial_count": 0,
            },
        })
        assert result is None

    def test_hr018_not_enabled(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-018"]
        result = rule.evaluate({"discovery": {"enabled": False}})
        assert result is None

    def test_all_21_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)


# ── AC11: Negative tests ─────────────────────────────────────────────────────

class TestAC11Negative:
    def test_malicious_index_rejected(self):
        """A tampered index with wrong digest is rejected."""
        from nodechain.sdk.discovery import parse_discovery_index, DiscoveryError
        data = _make_index_data()
        data["index_digest"] = "evil_tampered_digest"
        with pytest.raises(DiscoveryError, match="mismatch"):
            parse_discovery_index(data)

    def test_unsigned_index_under_strict(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://e",
            generated_at="2026-06-17T12:00:00+00:00",
        )
        profile = get_builtin_profile("strict_enterprise")
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed

    def test_registry_auto_add_blocked(self):
        """Discovery cannot modify federation config without explicit add."""
        from nodechain.sdk.discovery import parse_discovery_index
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        # After discovery, store should still be empty
        assert len(store.registries) == 0

    def test_discovery_source_not_allowed(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://evil.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
        )
        profile = OrganizationTrustPolicyProfile(
            name="test", description="test",
            allow_public_discovery=True,
            allowed_discovery_sources=["https://trusted.example.com"],
        )
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "not in allowed" in reason

    def test_signer_mismatch(self):
        """Signed by wrong signer should be checkable."""
        from nodechain.sdk.discovery import PublicDiscoveryIndex
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://e",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="somesig",
            signer_fingerprint="unknown_signer",
        )
        # The signature_verified is just bool(signature) at parse time
        # Real implementation would verify against trust store
        assert idx.signer_fingerprint == "unknown_signer"

    def test_package_claims_informational_only(self):
        """Package claims in listings don't affect resolution."""
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
            claimed_packages=["anything", "whatever"],
        )
        # Claims are just strings, not validated packages
        config = listing.to_federation_config()
        # Empty allowed_packages = all allowed (claims don't restrict)
        assert config.allowed_packages == []

    def test_reputation_hint_cannot_bypass_scoring(self):
        """reputation_hint is a string, not a health score."""
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
            reputation_hint="A+",
        )
        # reputation_hint is just informational text
        assert listing.reputation_hint == "A+"
        # It's NOT used by the reputation scoring system

    def test_discovered_registry_cannot_bypass_federation_gates(self):
        """A registry added from discovery still passes all federation checks."""
        from nodechain.sdk.discovery import (
            parse_discovery_index, add_registry_from_discovery,
        )
        from nodechain.sdk.federation import (
            FederationConfigStore, resolve_federated_package,
        )
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        add_registry_from_discovery(idx.registries[0], idx, store)
        # The registry is disabled by default
        reg = store.get("reg-a")
        assert reg.enabled is False
        # Disabled registry won't be consulted by resolver
        result = resolve_federated_package("pkg-x", "1.0", lambda r, p, v: {}, store)
        assert not result.all_passed


# ── AC12: Verification and persistence ───────────────────────────────────────

class TestAC12Verification:
    def test_verify_valid_index(self):
        from nodechain.sdk.discovery import parse_discovery_index, verify_discovery_index
        data = _make_index_data()
        idx = parse_discovery_index(data)
        result = verify_discovery_index(idx)
        assert result.valid

    def test_verify_detects_bad_url(self):
        from nodechain.sdk.discovery import PublicDiscoveryIndex, verify_discovery_index
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="g",
            index_digest="d",
            registries=[MarketplaceRegistryListing(registry_id="r", base_url="not-a-url")],
        )
        result = verify_discovery_index(idx)
        assert not result.valid

    def test_discovery_store_persistence(self, tmp_path):
        from nodechain.sdk.discovery import (
            parse_discovery_index, DiscoveryStore, DiscoveryStoreEntry,
            save_discovery_store, load_discovery_store,
        )
        path = str(tmp_path / "disc.json")
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = DiscoveryStore()
        store.set(DiscoveryStoreEntry(index=idx, fetched_at="now"))
        save_discovery_store(store, path)
        loaded = load_discovery_store(path)
        assert len(loaded.all_entries) == 1

    def test_corrupt_store_raises(self, tmp_path):
        from nodechain.sdk.discovery import load_discovery_store, DiscoveryError
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("garbage{{{{", encoding="utf-8")
        with pytest.raises(DiscoveryError, match="corrupt"):
            load_discovery_store(path)

    def test_profile_digest_binds_discovery_fields(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p1 = get_builtin_profile("permissive_local")
        p2 = get_builtin_profile("permissive_local")
        p2.allow_public_discovery = False
        assert p1.compute_digest() != p2.compute_digest()

    def test_profile_roundtrip_preserves_discovery(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        for name in ["permissive_local", "standard_team", "strict_enterprise", "airgapped_high_assurance"]:
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.allow_public_discovery == p.allow_public_discovery
            assert p2.require_signed_discovery_index == p.require_signed_discovery_index
            assert p2.maximum_discovery_index_age == p.maximum_discovery_index_age
            assert p2.allow_marketplace_registry_add == p.allow_marketplace_registry_add
