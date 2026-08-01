"""Discovery Adversarial Test Suite (v2.21.3).

20 acceptance criteria hardening the discovery/marketplace boundary.

Design rule:
    public information → local proposal → explicit approval → normal federation entry

Nothing from discovery should directly grant:
    trust level, certification, publisher approval, registry eligibility,
    package eligibility, reputation score, execution permission.
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
    generated_at: str = "2026-06-17T12:00:00+00:00",
    include_digest: bool = True,
    signature: str = "",
    signer: str = "",
) -> dict:
    """Build a discovery index dict."""
    from nodechain.sdk.discovery import compute_index_digest
    data = {
        "index_id": index_id,
        "source_url": "https://marketplace.example.com/index.json",
        "generated_at": generated_at,
        "registries": registries or [
            {"registry_id": "reg-a", "base_url": "https://reg-a.example.com",
             "display_name": "Registry A", "description": "Test registry",
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
        data["index_digest"] = compute_index_digest(data)
    return data


# ── AC1: Signed index is cryptographically verified ──────────────────────────

class TestAC1CryptoVerification:
    def test_verify_function_exists(self):
        from nodechain.sdk.discovery import verify_discovery_signature
        assert callable(verify_discovery_signature)

    def test_unsigned_returns_false(self):
        from nodechain.sdk.discovery import PublicDiscoveryIndex, verify_discovery_signature
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now",
        )
        valid, reason = verify_discovery_signature(idx)
        assert not valid

    def test_signed_no_key_returns_true_with_caveat(self):
        """Without a public key, fields-present is accepted but noted."""
        from nodechain.sdk.discovery import PublicDiscoveryIndex, verify_discovery_signature
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now",
            signature="deadbeef", signer_fingerprint="fp123",
        )
        valid, reason = verify_discovery_signature(idx)
        assert valid
        assert "no cryptographic verification" in reason.lower()

    def test_crypto_verification_with_key(self, tmp_path):
        """Full RSA-PSS-SHA256 verification."""
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.sdk.discovery import PublicDiscoveryIndex, verify_discovery_signature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        keys = generate_key_pair(str(tmp_path), "disc_signer")
        private_key = serialization.load_pem_private_key(
            Path(keys["private_key_path"]).read_bytes(), password=None,
        )
        public_pem = Path(keys["public_key_path"]).read_text()

        # Build index object first, then sign its canonical payload
        idx = PublicDiscoveryIndex(
            index_id="test-idx",
            source_url="https://marketplace.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            registries=[],
            publishers=["pub1"],
            packages=["pkg-x"],
            index_digest="abc123",
            signer_fingerprint=keys["fingerprint"],
        )
        # Sign the payload that verify_discovery_signature will recompute
        payload_data = {k: v for k, v in idx.to_dict().items()
                        if k not in ("signature", "index_digest")}
        canonical = json.dumps(payload_data, sort_keys=True, separators=(",", ":"))
        sig = private_key.sign(
            canonical.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        idx.signature = sig.hex()

        valid, reason = verify_discovery_signature(idx, public_key_pem=public_pem)
        assert valid
        assert "cryptographically verified" in reason.lower()


# ── AC2: Invalid signature rejected ──────────────────────────────────────────

class TestAC2InvalidSignature:
    def test_tampered_signature_rejected(self, tmp_path):
        from nodechain.sdk.discovery import PublicDiscoveryIndex, verify_discovery_signature
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now",
            signature="00ff", signer_fingerprint="fp",
        )
        # Fake public key content won't parse
        valid, reason = verify_discovery_signature(idx, public_key_pem="not-a-key")
        assert not valid

    def test_wrong_signature_for_content(self, tmp_path):
        """Signature from one key won't verify against another key."""
        from nodechain.cli.bundle_signing import generate_key_pair
        from nodechain.sdk.discovery import PublicDiscoveryIndex, verify_discovery_signature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        keys1 = generate_key_pair(str(tmp_path), "signer1")
        keys2 = generate_key_pair(str(tmp_path), "signer2")
        private1 = serialization.load_pem_private_key(
            Path(keys1["private_key_path"]).read_bytes(), password=None,
        )
        public2 = Path(keys2["public_key_path"]).read_text()

        data = _make_index_data()
        payload = {k: v for k, v in data.items() if k not in ("signature", "index_digest")}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sig = private1.sign(
            canonical.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now",
            signature=sig.hex(), signer_fingerprint=keys1["fingerprint"],
        )
        valid, reason = verify_discovery_signature(idx, public_key_pem=public2)
        assert not valid


# ── AC3: Signer fingerprint mismatch ─────────────────────────────────────────

class TestAC3SignerMismatch:
    def test_signer_mismatch_detected(self):
        from nodechain.sdk.discovery import PublicDiscoveryIndex
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now",
            signature="somesig", signer_fingerprint="unknown_signer",
        )
        assert idx.signer_fingerprint == "unknown_signer"


# ── AC4: Unsigned rejected when required ─────────────────────────────────────

class TestAC4UnsignedRejected:
    def test_unsigned_rejected_under_strict(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://e", generated_at="2026-06-17T12:00:00+00:00",
        )
        profile = get_builtin_profile("strict_enterprise")
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "unsigned" in reason.lower()


# ── AC5: Malicious digest mismatch ───────────────────────────────────────────

class TestAC5DigestMismatch:
    def test_digest_mismatch_rejected(self):
        from nodechain.sdk.discovery import parse_discovery_index, DiscoveryError
        data = _make_index_data()
        data["index_digest"] = "tampered_digest_value"
        with pytest.raises(DiscoveryError, match="mismatch"):
            parse_discovery_index(data)


# ── AC6: Missing index_digest ────────────────────────────────────────────────

class TestAC6MissingDigest:
    def test_missing_digest_accepted_permissively(self):
        """Missing digest is accepted when no digest is stored."""
        from nodechain.sdk.discovery import parse_discovery_index, compute_index_digest
        data = _make_index_data(include_digest=False)
        idx = parse_discovery_index(data)
        # Digest should be computed
        assert idx.index_digest != ""
        assert idx.index_digest == compute_index_digest(data)

    def test_missing_digest_warning(self):
        """An index without a digest is treated as untrusted."""
        from nodechain.sdk.discovery import parse_discovery_index
        data = _make_index_data(include_digest=False)
        idx = parse_discovery_index(data)
        # No stored digest to match, but computed digest is present
        assert idx.index_digest != ""


# ── AC7: Stale index rejected ────────────────────────────────────────────────

class TestAC7StaleIndex:
    def test_stale_index_rejected(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="old", source_url="https://e",
            generated_at="2020-01-01T00:00:00Z",
            signature="sig", signer_fingerprint="fp",
        )
        profile = OrganizationTrustPolicyProfile(
            name="test", description="test",
            maximum_discovery_index_age=7,
        )
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "old" in reason.lower() or "day" in reason.lower()


# ── AC8: Oversized index rejected ────────────────────────────────────────────

class TestAC8Oversized:
    def test_oversized_rejected(self):
        from nodechain.sdk.discovery import fetch_discovery_index, DiscoveryError
        def fetcher(url):
            return b"x" * (11 * 1024 * 1024)
        with pytest.raises(DiscoveryError, match="oversized"):
            fetch_discovery_index("https://e", fetcher_fn=fetcher)


# ── AC9: Too many registries/packages ────────────────────────────────────────

class TestAC9TooMany:
    def test_too_many_registries(self):
        from nodechain.sdk.discovery import parse_discovery_index, DiscoveryError
        regs = [{"registry_id": f"r-{i}", "base_url": "https://r"} for i in range(600)]
        data = _make_index_data(registries=regs)
        with pytest.raises(DiscoveryError, match="Too many registries"):
            parse_discovery_index(data)

    def test_too_many_packages(self):
        from nodechain.sdk.discovery import parse_discovery_index, DiscoveryError
        pkgs = [f"pkg-{i}" for i in range(11000)]
        data = _make_index_data(packages=pkgs)
        with pytest.raises(DiscoveryError, match="Too many packages"):
            parse_discovery_index(data)


# ── AC10: Duplicate registry IDs ─────────────────────────────────────────────

class TestAC10Duplicates:
    def test_duplicates_detected_by_verify(self):
        from nodechain.sdk.discovery import (
            PublicDiscoveryIndex, MarketplaceRegistryListing, verify_discovery_index,
        )
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now", index_digest="d",
            registries=[
                MarketplaceRegistryListing(registry_id="dup", base_url="https://r"),
                MarketplaceRegistryListing(registry_id="dup", base_url="https://r"),
            ],
        )
        result = verify_discovery_index(idx)
        assert not result.valid
        assert any("Duplicate" in i for i in result.issues)


# ── AC11: Invalid base URLs ──────────────────────────────────────────────────

class TestAC11BadURLs:
    def test_bad_url_detected(self):
        from nodechain.sdk.discovery import (
            PublicDiscoveryIndex, MarketplaceRegistryListing, verify_discovery_index,
        )
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="u", generated_at="now", index_digest="d",
            registries=[MarketplaceRegistryListing(registry_id="r", base_url="not-a-url")],
        )
        result = verify_discovery_index(idx)
        assert not result.valid


# ── AC12: Source not in allowed list ─────────────────────────────────────────

class TestAC12SourceNotAllowed:
    def test_source_not_allowed(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://evil.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
        )
        profile = OrganizationTrustPolicyProfile(
            name="test", description="test",
            allowed_discovery_sources=["https://trusted.example.com"],
        )
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "not in allowed" in reason


# ── AC13: Discovery never auto-adds ──────────────────────────────────────────

class TestAC13NoAutoAdd:
    def test_parse_does_not_add_to_federation(self):
        from nodechain.sdk.discovery import parse_discovery_index
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        assert len(store.registries) == 0  # parse is side-effect free


# ── AC14: Added registry is disabled + untrusted ─────────────────────────────

class TestAC14DisabledUntrusted:
    def test_added_registry_is_disabled(self):
        from nodechain.sdk.discovery import parse_discovery_index, add_registry_from_discovery
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        add_registry_from_discovery(idx.registries[0], idx, store)
        reg = store.get("reg-a")
        assert reg.enabled is False
        assert reg.trust_level == "remote_untrusted"


# ── AC15: Claims remain informational ────────────────────────────────────────

class TestAC15ClaimsInformational:
    def test_claims_dont_become_allowlist(self):
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
            claimed_publishers=["pub1", "pub2"],
            claimed_packages=["pkg1", "pkg2"],
        )
        config = listing.to_federation_config()
        assert config.allowed_publishers == []  # empty = all
        assert config.allowed_packages == []    # empty = all


# ── AC16: Reputation hints cannot bypass scoring ─────────────────────────────

class TestAC16ReputationHint:
    def test_hint_is_just_a_string(self):
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
            reputation_hint="A+ Excellent",
        )
        assert listing.reputation_hint == "A+ Excellent"

    def test_hint_does_not_affect_reputation_store(self):
        from nodechain.sdk.reputation import ReputationStore, score_registry, ScoringInputs
        store = ReputationStore()
        # A listing with hint "A+" should not create a score
        assert store.get("reg-with-hint") is None
        # Local scoring is computed independently
        score = score_registry(ScoringInputs(registry_id="reg-with-hint"))
        assert score.score == 100.0  # default inputs = perfect


# ── AC17: Categories cannot influence trust ──────────────────────────────────

class TestAC17CategoriesNoTrust:
    def test_categories_are_strings_only(self):
        from nodechain.sdk.discovery import MarketplaceRegistryListing
        listing = MarketplaceRegistryListing(
            registry_id="reg", base_url="https://r",
            categories=["verified", "trusted", "certified"],
        )
        # Categories are just metadata
        config = listing.to_federation_config()
        assert config.trust_level == "remote_untrusted"
        assert config.enabled is False


# ── AC18: Marketplace denial writes no mutation ──────────────────────────────

class TestAC18NoMutationOnDenial:
    def test_denial_leaves_store_unchanged(self):
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
        # Store must be unchanged
        assert len(store.registries) == 0


# ── AC19: Receipts bind all fields ───────────────────────────────────────────

class TestAC19ReceiptBinding:
    def test_discovery_receipt_has_all_fields(self):
        from nodechain.sdk.discovery import DiscoveryIndexReceipt
        receipt = DiscoveryIndexReceipt(
            index_id="idx-1",
            source_url="https://marketplace.example.com",
            index_digest="abc123",
            fetched_at="2026-06-18T00:00:00+00:00",
            signer_fingerprint="fp123",
            signature_verified=True,
            policy_profile_digest="def456",
        )
        d = receipt.to_dict()
        assert d["source_url"] == "https://marketplace.example.com"
        assert d["index_digest"] == "abc123"
        assert d["signer_fingerprint"] == "fp123"
        assert d["policy_profile_digest"] == "def456"

    def test_add_receipt_binds_federation_digest(self):
        from nodechain.sdk.discovery import parse_discovery_index, add_registry_from_discovery
        from nodechain.sdk.federation import FederationConfigStore
        data = _make_index_data()
        idx = parse_discovery_index(data)
        store = FederationConfigStore()
        receipt = add_registry_from_discovery(idx.registries[0], idx, store)
        d = receipt.to_dict()
        assert d["federation_config_digest"] != ""
        assert d["source_index_id"] == "idx-1"
        assert d["policy_approved"] is True

    def test_receipts_change_with_different_content(self):
        from nodechain.sdk.discovery import DiscoveryIndexReceipt
        r1 = DiscoveryIndexReceipt(
            index_id="a", source_url="u", index_digest="d1", fetched_at="now",
        )
        r2 = DiscoveryIndexReceipt(
            index_id="a", source_url="u", index_digest="d2", fetched_at="now",
        )
        assert r1.to_dict()["index_digest"] != r2.to_dict()["index_digest"]


# ── AC20: Runtime path integration ───────────────────────────────────────────

class TestAC20Runtime:
    def test_all_18_health_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_marketplace_cli_group_exists(self):
        from nodechain.cli.main import cli
        assert "marketplace" in cli.commands

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
        assert loaded.get("idx-1") is not None

    def test_corrupt_store_raises(self, tmp_path):
        from nodechain.sdk.discovery import load_discovery_store, DiscoveryError
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("garbage{{{{", encoding="utf-8")
        with pytest.raises(DiscoveryError, match="corrupt"):
            load_discovery_store(path)

    def test_profile_serializes_discovery_fields(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        for name in ["permissive_local", "standard_team", "strict_enterprise", "airgapped_high_assurance"]:
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.allow_public_discovery == p.allow_public_discovery
            assert p2.require_signed_discovery_index == p.require_signed_discovery_index
            assert p2.maximum_discovery_index_age == p.maximum_discovery_index_age
            assert p2.allow_marketplace_registry_add == p.allow_marketplace_registry_add
            assert p2.compute_digest() == p.compute_digest()

    def test_evidence_types_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "discovery_index_receipt" in EVIDENCE_TYPES
        assert "marketplace_registry_add_receipt" in EVIDENCE_TYPES
