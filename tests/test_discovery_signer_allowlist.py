"""Discovery Signer Allowlist Fail-Closed Tests (v2.21.3).

When require_discovery_signature_verification=True:
  - trusted_discovery_signers must be non-empty (unless allow_any_resolver_discovery_signer=True)
  - signer fingerprint must appear in that list
  - resolver must return the mapped public key
  - RSA-PSS-SHA256 verification must succeed
  - otherwise deny

Core distinction enforced:
  cryptographically valid signer ≠ signer authorized by this organization profile
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

def _generate_keypair(tmp_path, name="disc_signer"):
    from nodechain.cli.bundle_signing import generate_key_pair
    from cryptography.hazmat.primitives import serialization
    keys = generate_key_pair(str(tmp_path), name)
    private_key = serialization.load_pem_private_key(
        Path(keys["private_key_path"]).read_bytes(), password=None,
    )
    public_pem = Path(keys["public_key_path"]).read_text()
    return private_key, public_pem, keys["fingerprint"]


def _make_signed_index(tmp_path, name="disc_signer"):
    from nodechain.sdk.discovery import PublicDiscoveryIndex, compute_index_digest
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key, public_pem, fingerprint = _generate_keypair(tmp_path, name)

    data = {
        "index_id": "idx-1",
        "source_url": "https://marketplace.example.com/index.json",
        "generated_at": "2026-06-17T12:00:00+00:00",
        "registries": [],
        "publishers": [],
        "packages": [],
        "signer_fingerprint": fingerprint,
    }
    payload = {k: v for k, v in data.items() if k not in ("signature", "index_digest")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = private_key.sign(
        canonical.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    idx = PublicDiscoveryIndex(
        index_id="idx-1",
        source_url="https://marketplace.example.com/index.json",
        generated_at="2026-06-17T12:00:00+00:00",
        registries=[],
        publishers=[],
        packages=[],
        index_digest=compute_index_digest(data),
        signature=sig.hex(),
        signer_fingerprint=fingerprint,
    )
    return idx, public_pem, fingerprint


# ── AC1: Empty trusted_discovery_signers fails closed ───────────────────────

class TestAC1EmptyAllowlistFailsClosed:
    def test_empty_allowlist_with_crypto_required_fails(self):
        """Empty trusted_discovery_signers + require_crypto → deny."""
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="deadbeef", signer_fingerprint="fp",
        )
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[],  # empty!
        )
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "empty" in reason.lower()

    def test_builtin_strict_fails_on_empty_allowlist(self):
        """strict_enterprise has crypto required but no trusted signers → deny."""
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="sig", signer_fingerprint="fp",
        )
        profile = get_builtin_profile("strict_enterprise")
        # strict_enterprise has require_crypto=True but empty trusted_signers
        assert profile.require_discovery_signature_verification is True
        assert profile.trusted_discovery_signers == []
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "empty" in reason.lower() or "allowlist" in reason.lower()

    def test_builtin_airgapped_fails_on_empty_allowlist(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="sig", signer_fingerprint="fp",
        )
        profile = get_builtin_profile("airgapped_high_assurance")
        # airgapped denies discovery entirely — which is also a denial
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        # Either discovery is disabled or allowlist is empty — both are denials


# ── AC2: allow_any_resolver_discovery_signer opt-in ─────────────────────────

class TestAC2AllowAnyOptIn:
    def test_allow_any_skips_empty_check(self, tmp_path):
        """When allow_any_resolver_discovery_signer=True, empty list is OK."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="resolver-wide", description="resolver-wide",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[],  # empty but allow_any=True
            allow_any_resolver_discovery_signer=True,
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert allowed, f"Should pass with allow_any=True: {reason}"

    def test_allow_any_default_false(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="t")
        assert p.allow_any_resolver_discovery_signer is False


# ── AC3: Signer must be in allowlist ─────────────────────────────────────────

class TestAC3SignerInAllowlist:
    def test_signer_in_allowlist_passes(self, tmp_path):
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fingerprint],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert allowed, f"Should pass: {reason}"

    def test_signer_not_in_allowlist_rejected(self, tmp_path):
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=["completely_different_fp"],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed
        assert "not in trusted" in reason.lower()

    def test_multiple_signers_one_match(self, tmp_path):
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=["fp-other-1", fingerprint, "fp-other-2"],
            maximum_discovery_index_age=0,
        )
        allowed, _ = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert allowed


# ── AC4: Crypto still required even with allowlist ──────────────────────────

class TestAC4CryptoStillRequired:
    def test_valid_allowlist_wrong_key_fails(self, tmp_path):
        """Signer in allowlist but resolver returns wrong key → deny."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, _, fingerprint = _make_signed_index(tmp_path, name="signer_a")
        _, public_pem_b, _ = _generate_keypair(tmp_path, name="signer_b")

        resolver = DiscoverySignerResolver()
        # Register wrong key under the correct fingerprint
        resolver.add_signer(fingerprint, public_pem_b)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fingerprint],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed

    def test_tampered_signature_with_valid_allowlist(self, tmp_path):
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        # Tamper
        idx.signature = "00" + idx.signature[2:]

        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fingerprint],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed


# ── AC5: allow_any still requires crypto ─────────────────────────────────────

class TestAC5AllowAnyStillCrypto:
    def test_allow_any_with_unknown_signer_fails(self, tmp_path):
        """allow_any=True but signer not in resolver → deny."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, _, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        # Don't add signer to resolver

        profile = OrganizationTrustPolicyProfile(
            name="resolver-wide", description="resolver-wide",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            allow_any_resolver_discovery_signer=True,
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed
        assert "not known" in reason.lower()

    def test_allow_any_with_invalid_sig_fails(self, tmp_path):
        """allow_any=True, signer in resolver, but bad signature → deny."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        idx.signature = "tampered"

        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="resolver-wide", description="resolver-wide",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            allow_any_resolver_discovery_signer=True,
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed

    def test_allow_any_no_resolver_fails(self):
        """allow_any=True but no resolver → deny."""
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="sig", signer_fingerprint="fp",
        )
        profile = OrganizationTrustPolicyProfile(
            name="resolver-wide", description="resolver-wide",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            allow_any_resolver_discovery_signer=True,
        )
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "no signer resolver" in reason.lower()


# ── AC6: Profile serialization and digest binding ───────────────────────────

class TestAC6SerializationBinding:
    def test_field_in_to_dict(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(
            name="t", description="t",
            allow_any_resolver_discovery_signer=True,
        )
        assert p.to_dict()["allow_any_resolver_discovery_signer"] is True

    def test_field_in_from_dict(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(
            name="t", description="t",
            allow_any_resolver_discovery_signer=True,
            trusted_discovery_signers=["fp"],
        )
        d = p.to_dict()
        p2 = OrganizationTrustPolicyProfile.from_dict(d)
        assert p2.allow_any_resolver_discovery_signer is True
        assert p2.trusted_discovery_signers == ["fp"]

    def test_digest_changes_with_field(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p1 = OrganizationTrustPolicyProfile(name="t", description="t")
        p2 = OrganizationTrustPolicyProfile(
            name="t", description="t",
            allow_any_resolver_discovery_signer=True,
        )
        assert p1.compute_digest() != p2.compute_digest()

    def test_all_builtin_profiles_roundtrip(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.allow_any_resolver_discovery_signer == p.allow_any_resolver_discovery_signer
            assert p2.compute_digest() == p.compute_digest()


# ── AC7: Backward compatibility ─────────────────────────────────────────────

class TestAC7BackwardCompat:
    def test_non_crypto_profile_unchanged(self):
        """Profiles without require_crypto still work with field-present."""
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="sig", signer_fingerprint="fp",
        )
        profile = OrganizationTrustPolicyProfile(
            name="moderate", description="moderate",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=False,
        )
        allowed, _ = check_discovery_policy(idx, profile)
        assert allowed

    def test_permissive_profile_allows_unsigned(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
        )
        profile = get_builtin_profile("permissive_local")
        allowed, _ = check_discovery_policy(idx, profile)
        assert allowed

    def test_standard_team_allows_unsigned(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile

        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
        )
        profile = get_builtin_profile("standard_team")
        allowed, _ = check_discovery_policy(idx, profile)
        assert allowed


# ── AC8: Strict profile with populated allowlist works end-to-end ───────────

class TestAC8EndToEnd:
    def test_strict_with_allowlist_and_resolver(self, tmp_path):
        """Full strict pipeline: allowlist + resolver + valid sig → pass."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        resolver.add_signer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict-populated", description="strict with real signers",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fingerprint],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert allowed
        assert reason == ""

    def test_strict_allowlist_blocks_unauthorized_valid_signer(self, tmp_path):
        """Valid crypto sig from signer NOT in allowlist → deny."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx_a, public_pem_a, fp_a = _make_signed_index(tmp_path, name="signer_a")
        _, _, fp_b = _generate_keypair(tmp_path, name="signer_b")

        resolver = DiscoverySignerResolver()
        resolver.add_signer(fp_a, public_pem_a)

        # Allowlist contains fp_b but the index is signed by fp_a
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fp_b],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx_a, profile, signer_resolver=resolver)
        assert not allowed
        assert "not in trusted" in reason.lower()

    def test_runtime_health_and_evidence(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
        assert "discovery_index_receipt" in EVIDENCE_TYPES
