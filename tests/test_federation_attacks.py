"""Multi-Registry Federation Adversarial Test Suite (v2.21.3).

20 acceptance criteria exercising the actual resolver and CLI paths.
Tests break selection order, signing/certification separation, and
corrupt config handling.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


def _meta(pkg, ver, digest="", pub="pub_fp", signed=True, certified=True):
    """Create metadata dict with separate signing and certification."""
    return {
        "artifact_digest": digest or hashlib.sha256(f"{pkg}{ver}".encode()).hexdigest(),
        "metadata_digest": hashlib.sha256(f"meta-{pkg}{ver}".encode()).hexdigest(),
        "publisher_fingerprint": pub,
        "signer_fingerprint": "signer_fp",
        "metadata_signed": signed,
        "certified": certified,
    }


def _store_with(*regs):
    from nodechain.sdk.federation import FederationConfigStore
    return FederationConfigStore(registries=list(regs))


def _reg(rid="reg", url="https://r", priority=100, **kw):
    from nodechain.sdk.federation import FederatedRegistryConfig
    return FederatedRegistryConfig(registry_id=rid, base_url=url, priority=priority, **kw)


def _profile(name):
    from nodechain.sdk.org_policy import get_builtin_profile
    return get_builtin_profile(name)


# ── AC1: Unlisted registry rejected ──────────────────────────────────────────

class TestAC1UnlistedRegistry:
    def test_empty_store_no_resolution(self):
        from nodechain.sdk.federation import resolve_federated_package, FederationConfigStore
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v), FederationConfigStore())
        assert not result.all_passed

    def test_registry_not_in_store_not_consulted(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="official"))
        consulted = []
        def fetcher(r, p, v):
            consulted.append(r)
            return _meta(p, v)
        resolve_federated_package("pkg", "1.0", fetcher, store)
        assert "official" in consulted
        assert "attacker" not in consulted


# ── AC2: Disabled registry ignored + dashboard warns ─────────────────────────

class TestAC2DisabledRegistry:
    def test_disabled_not_consulted(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="disabled", enabled=False), _reg(rid="active", priority=10))
        consulted = []
        def fetcher(r, p, v):
            consulted.append(r)
            return _meta(p, v)
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert "disabled" not in consulted
        assert "active" in consulted
        assert result.selected.registry_id == "active"

    def test_dashboard_warns_disabled(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-016"]
        result = rule.evaluate({"federation": {"enabled": True, "disabled_count": 1}})
        assert result is not None


# ── AC3: Required signer mismatch rejected ───────────────────────────────────

class TestAC3SignerMismatch:
    def test_signer_mismatch_rejected(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg", required_signer_fingerprint="good_signer"))
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert not result.all_passed
        assert any("Signer mismatch" in r["reason"] for r in result.rejected)

    def test_signer_match_accepted(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg", required_signer_fingerprint="signer_fp"))
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v), store)
        assert result.all_passed


# ── AC4: Publisher allowlist mismatch rejected ────────────────────────────────

class TestAC4PublisherMismatch:
    def test_publisher_not_in_allowlist(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg", allowed_publishers=["trusted"]))
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v, pub="untrusted"), store)
        assert not result.all_passed


# ── AC5: Package allowlist mismatch rejected ──────────────────────────────────

class TestAC5PackageMismatch:
    def test_package_not_in_allowlist(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg", allowed_packages=["other"]))
        result = resolve_federated_package("target", "1.0", lambda r, p, v: _meta(p, v), store)
        assert not result.all_passed


# ── AC6: Different digests fail closed ────────────────────────────────────────

class TestAC6DigestConflict:
    def test_different_digests_fail_closed(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="a", priority=10), _reg(rid="b", priority=20))
        def fetcher(r, p, v):
            return _meta(p, v, digest=f"d_{r}")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0


# ── AC7: Same digest resolves deterministically ──────────────────────────────

class TestAC7SameDigest:
    def test_same_digest_picks_highest_priority(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="low", priority=50), _reg(rid="high", priority=10))
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v, digest="same"), store)
        assert result.all_passed
        assert result.selected.registry_id == "high"

    def test_same_priority_deterministic_by_id(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="zzz", priority=50), _reg(rid="aaa", priority=50))
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v, digest="same"), store)
        assert result.all_passed
        assert result.selected.registry_id == "aaa"


# ── AC8: Priority cannot override digest conflict ─────────────────────────────

class TestAC8PriorityVsConflict:
    def test_priority_does_not_override_conflict(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="high-pri", priority=1), _reg(rid="low-pri", priority=100))
        def fetcher(r, p, v):
            return _meta(p, v, digest=f"d_{r}")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0


# ── AC9: Priority spoofing ────────────────────────────────────────────────────

class TestAC9PrioritySpoofing:
    def test_high_pri_rejected_still_resolves_low_pri(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(
            _reg(rid="good", priority=50, allowed_publishers=["good_pub"]),
            _reg(rid="spoof", priority=1, allowed_publishers=["good_pub"]),
        )
        def fetcher(r, p, v):
            if r == "spoof":
                return _meta(p, v, pub="evil_pub")
            return _meta(p, v, pub="good_pub")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert result.all_passed
        assert result.selected.registry_id == "good"


# ── AC10: Registry shadowing ─────────────────────────────────────────────────

class TestAC10Shadowing:
    def test_shadow_different_digest_is_conflict(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="primary", priority=10), _reg(rid="shadow", priority=100))
        def fetcher(r, p, v):
            if r == "primary": return _meta(p, v, digest="real")
            return _meta(p, v, digest="shadowed")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed


# ── AC11: Dependency confusion across registries ─────────────────────────────

class TestAC11DependencyConfusion:
    def test_wrong_publisher_same_name_different_digest(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(
            _reg(rid="official", priority=10, allowed_publishers=["official_pub"]),
            _reg(rid="unofficial", priority=100, allowed_publishers=["attacker_pub"]),
        )
        def fetcher(r, p, v):
            if r == "official": return _meta(p, v, digest="d1", pub="official_pub")
            return _meta(p, v, digest="d2", pub="attacker_pub")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed  # Conflict


# ── AC12: Metadata signed but uncertified rejected under strict ───────────────

class TestAC12SignedButNotCertified:
    def test_strict_rejects_signed_uncertified(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg"))
        profile = _profile("strict_enterprise")
        result = resolve_federated_package(
            "pkg", "1.0",
            lambda r, p, v: _meta(p, v, signed=True, certified=False),
            store, org_profile=profile,
        )
        assert not result.all_passed
        assert any("Certification required" in r["reason"] for r in result.rejected)

    def test_permissive_allows_signed_uncertified(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg"))
        profile = _profile("permissive_local")
        result = resolve_federated_package(
            "pkg", "1.0",
            lambda r, p, v: _meta(p, v, signed=True, certified=False),
            store, org_profile=profile,
        )
        assert result.all_passed


# ── AC13: Certification and signing checked separately ────────────────────────

class TestAC13SeparateChecks:
    def test_unsigned_rejected_by_signing_check(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg"))
        profile = _profile("strict_enterprise")
        result = resolve_federated_package(
            "pkg", "1.0",
            lambda r, p, v: _meta(p, v, signed=False, certified=True),
            store, org_profile=profile,
        )
        assert not result.all_passed
        assert any("signing" in r["reason"].lower() for r in result.rejected)

    def test_unsigned_and_uncertified_rejected_both(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg"))
        profile = _profile("strict_enterprise")
        result = resolve_federated_package(
            "pkg", "1.0",
            lambda r, p, v: _meta(p, v, signed=False, certified=False),
            store, org_profile=profile,
        )
        assert not result.all_passed

    def test_signed_and_certified_accepted(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg"))
        profile = _profile("strict_enterprise")
        result = resolve_federated_package(
            "pkg", "1.0",
            lambda r, p, v: _meta(p, v, signed=True, certified=True),
            store, org_profile=profile,
        )
        assert result.all_passed


# ── AC14: Transparency entry missing denied when profile requires ─────────────

class TestAC14TransparencyMissing:
    def test_profile_requires_transparency(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = _profile("strict_enterprise")
        ok, msg = p.check_transparency_logging(False)
        assert not ok

    def test_airgapped_denies_transparency_missing(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = _profile("airgapped_high_assurance")
        ok, msg = p.check_transparency_logging(False)
        assert not ok


# ── AC15: Federation config tampering ────────────────────────────────────────

class TestAC15ConfigTampering:
    def test_config_digest_changes_on_tamper(self):
        store = _store_with(_reg(rid="a"), _reg(rid="b"))
        d1 = store.compute_digest()
        store.registries[0].priority = 1
        d2 = store.compute_digest()
        assert d1 != d2

    def test_config_digest_deterministic(self):
        s1 = _store_with(_reg(rid="a", priority=10))
        s2 = _store_with(_reg(rid="a", priority=10))
        assert s1.compute_digest() == s2.compute_digest()


# ── AC16: Corrupt config fails safely ─────────────────────────────────────────

class TestAC16CorruptConfig:
    def test_garbage_json_raises(self, tmp_path):
        from nodechain.sdk.federation import load_federation_config, FederationConfigError
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("garbage{{{{", encoding="utf-8")
        with pytest.raises(FederationConfigError, match="corrupt"):
            load_federation_config(path)

    def test_truncated_json_raises(self, tmp_path):
        from nodechain.sdk.federation import load_federation_config, FederationConfigError
        path = str(tmp_path / "trunc.json")
        Path(path).write_text('{"registries": [', encoding="utf-8")
        with pytest.raises(FederationConfigError):
            load_federation_config(path)

    def test_json_array_raises(self, tmp_path):
        from nodechain.sdk.federation import load_federation_config, FederationConfigError
        path = str(tmp_path / "arr.json")
        Path(path).write_text('[]', encoding="utf-8")
        with pytest.raises(FederationConfigError, match="not a valid JSON object"):
            load_federation_config(path)


# ── AC17: Duplicate registry IDs ──────────────────────────────────────────────

class TestAC17DuplicateIDs:
    def test_verify_detects_duplicates(self):
        from nodechain.sdk.federation import verify_federation
        store = _store_with(_reg(rid="dup"), _reg(rid="dup"))
        report = verify_federation(store)
        assert not report["valid"]
        assert any("Duplicate" in e for e in report["errors"])

    def test_add_replaces_existing(self):
        from nodechain.sdk.federation import FederationConfigStore
        store = FederationConfigStore()
        store.add(_reg(rid="r"))
        store.add(_reg(rid="r", priority=5))
        assert len(store.registries) == 1


# ── AC18: Invalid base URLs ───────────────────────────────────────────────────

class TestAC18InvalidURLs:
    def test_verify_rejects_bad_url(self):
        from nodechain.sdk.federation import verify_federation, FederatedRegistryConfig
        store = _store_with(FederatedRegistryConfig(registry_id="bad", base_url="not-a-url"))
        report = verify_federation(store)
        assert not report["valid"]
        assert any("invalid base_url" in e for e in report["errors"])

    def test_verify_accepts_valid_urls(self):
        from nodechain.sdk.federation import verify_federation
        store = _store_with(
            _reg(rid="a", url="https://a.com"),
            _reg(rid="b", url="http://b.com"),
        )
        report = verify_federation(store)
        assert report["valid"]


# ── AC19: Rejected reasons recorded ──────────────────────────────────────────

class TestAC19RejectedReasons:
    def test_rejected_reasons_in_result(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(_reg(rid="reg", allowed_publishers=["good"]))
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v, pub="bad"), store)
        d = result.to_dict()
        assert "rejected_registry_reasons" in d
        assert len(d["rejected_registry_reasons"]) > 0
        assert d["rejected_registry_reasons"][0]["registry_id"] == "reg"

    def test_multiple_rejected_reasons(self):
        from nodechain.sdk.federation import resolve_federated_package
        store = _store_with(
            _reg(rid="bad-pub", allowed_publishers=["good"]),
            _reg(rid="bad-pkg", allowed_packages=["other"]),
        )
        result = resolve_federated_package("pkg", "1.0", lambda r, p, v: _meta(p, v, pub="bad"), store)
        d = result.to_dict()
        assert len(d["rejected_registry_reasons"]) >= 2


# ── AC20: Runtime path integration ────────────────────────────────────────────

class TestAC20RuntimePaths:
    def test_cli_resolve_with_policy(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", str(tmp_path / "fed.json"))
        monkeypatch.setenv("NODECHAIN_ACTIVE_POLICY_PROFILE", str(tmp_path / "pol.json"))
        runner = CliRunner()
        runner.invoke(cli, ["registry", "federation", "add", "--registry-id", "reg", "--base-url", "https://r", "--priority", "10"])
        result = runner.invoke(cli, ["registry", "federation", "resolve", "--package-id", "pkg", "--version", "1.0", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["all_passed"] is True

    def test_cli_add_then_list(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_FEDERATION_CONFIG", str(tmp_path / "fed.json"))
        runner = CliRunner()
        runner.invoke(cli, ["registry", "federation", "add", "--registry-id", "test-reg", "--base-url", "https://test.com", "--priority", "5"])
        result = runner.invoke(cli, ["registry", "federation", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["registry_id"] == "test-reg"

    def test_all_16_health_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_evidence_type_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "federated_resolution_receipt" in EVIDENCE_TYPES
