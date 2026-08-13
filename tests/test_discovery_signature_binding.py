"""Discovery Signature Policy Binding Tests (v2.21.3).

10 acceptance criteria binding crypto verification into strict policy.

Core rule:
    require_discovery_signature_verification=True means cryptographic
    verification, NOT field presence. Field-present-only is insufficient.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

def _generate_keypair(tmp_path, name="disc_signer"):
    """Generate an RSA key pair, return (private_key_obj, public_pem_str, fingerprint)."""
    from nodechain.cli.bundle_signing import generate_key_pair
    from cryptography.hazmat.primitives import serialization
    keys = generate_key_pair(str(tmp_path), name)
    private_key = serialization.load_pem_private_key(
        Path(keys["private_key_path"]).read_bytes(), password=None,
    )
    public_pem = Path(keys["public_key_path"]).read_text()
    return private_key, public_pem, keys["fingerprint"]


def _sign_index(private_key, index_dict):
    """Sign the canonical payload of an index dict, return hex signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    payload = {k: v for k, v in index_dict.items()
               if k not in ("signature", "index_digest")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = private_key.sign(
        canonical.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return sig.hex()


def _make_signed_index(tmp_path, name="disc_signer"):
    """Create a signed PublicDiscoveryIndex with real crypto."""
    if name == "disc_signer":
        private_key, public_pem, fingerprint = _generate_keypair(tmp_path)
    else:
        private_key, public_pem, fingerprint = _generate_keypair(tmp_path, name=name)
    from nodechain.sdk.discovery import PublicDiscoveryIndex, compute_index_digest
    data = {
        "index_id": "idx-1",
        "source_url": "https://marketplace.example.com/index.json",
        "generated_at": "2026-06-17T12:00:00+00:00",
        "registries": [],
        "publishers": [],
        "packages": [],
        "signer_fingerprint": fingerprint,
    }
    sig_hex = _sign_index(private_key, data)
    digest = compute_index_digest(data)
    idx = PublicDiscoveryIndex(
        index_id="idx-1",
        source_url="https://marketplace.example.com/index.json",
        generated_at="2026-06-17T12:00:00+00:00",
        registries=[],
        publishers=[],
        packages=[],
        index_digest=digest,
        signature=sig_hex,
        signer_fingerprint=fingerprint,
    )
    return idx, public_pem, fingerprint


# ── AC1: Profile includes new fields ─────────────────────────────────────────

class TestAC1ProfileFields:
    def test_profile_has_trusted_discovery_signers(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="t")
        assert hasattr(p, "trusted_discovery_signers")
        assert p.trusted_discovery_signers == []

    def test_profile_has_require_discovery_signature_verification(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="t")
        assert hasattr(p, "require_discovery_signature_verification")
        assert p.require_discovery_signature_verification is False

    def test_strict_profile_enables_crypto_verification(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.require_discovery_signature_verification is True

    def test_airgapped_profile_enables_crypto_verification(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        assert p.require_discovery_signature_verification is True

    def test_permissive_does_not_require_crypto_verification(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("permissive_local")
        assert p.require_discovery_signature_verification is False

    def test_profile_serialization_roundtrip(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(
            name="test",
            description="test",
            trusted_discovery_signers=["fp1", "fp2"],
            require_discovery_signature_verification=True,
        )
        d = p.to_dict()
        assert d["trusted_discovery_signers"] == ["fp1", "fp2"]
        assert d["require_discovery_signature_verification"] is True

        p2 = OrganizationTrustPolicyProfile.from_dict(d)
        assert p2.trusted_discovery_signers == ["fp1", "fp2"]
        assert p2.require_discovery_signature_verification is True

    def test_digest_includes_new_fields(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p1 = OrganizationTrustPolicyProfile(name="t", description="t")
        p2 = OrganizationTrustPolicyProfile(
            name="t", description="t",
            require_discovery_signature_verification=True,
        )
        assert p1.compute_digest() != p2.compute_digest()

    def test_all_builtin_profiles_serialize_and_recover(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.trusted_discovery_signers == p.trusted_discovery_signers
            assert p2.require_discovery_signature_verification == p.require_discovery_signature_verification
            assert p2.compute_digest() == p.compute_digest()


# ── AC2: check_discovery_policy accepts signer resolver ─────────────────────

class TestAC2SignerResolver:
    def test_resolver_class_exists(self):
        from nodechain.sdk.discovery import DiscoverySignerResolver
        r = DiscoverySignerResolver()
        assert r.known_fingerprints == []

    def test_resolver_add_and_lookup(self):
        from nodechain.sdk.discovery import DiscoverySignerResolver
        r = DiscoverySignerResolver()
        r.add_signer("fp123", "PEM_CONTENT")
        assert r.resolve("fp123") == "PEM_CONTENT"
        assert r.resolve("unknown") is None
        assert "fp123" in r.known_fingerprints

    def test_check_policy_accepts_resolver_arg(self):
        from nodechain.sdk.discovery import (
            check_discovery_policy, PublicDiscoveryIndex,
            DiscoverySignerResolver,
        )
        idx = PublicDiscoveryIndex(index_id="t", source_url="u", generated_at="now")
        resolver = DiscoverySignerResolver()
        # Should not crash with resolver arg, even with no profile
        allowed, _ = check_discovery_policy(idx, None, signer_resolver=resolver)
        assert allowed


# ── AC3: Strict profiles require crypto verification, not field presence ────

class TestAC3CryptoRequired:
    def test_field_present_rejected_without_key(self, tmp_path):
        """Field-present-only must fail under crypto-required profiles."""
        from nodechain.sdk.discovery import check_discovery_policy, DiscoverySignerResolver, PublicDiscoveryIndex
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
            trusted_discovery_signers=["fp"],
        )
        # No resolver → must fail
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed
        assert "no signer resolver" in reason.lower() or "not known" in reason.lower()

    def test_resolver_missing_signer_fails(self, tmp_path):
        from nodechain.sdk.discovery import check_discovery_policy, DiscoverySignerResolver, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="deadbeef", signer_fingerprint="unknown_fp",
        )
        resolver = DiscoverySignerResolver()
        # v2.21.3: must populate trusted_signers to reach resolver check
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=["unknown_fp"],
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed
        assert "not known" in reason.lower()


# ── AC4: signer_fingerprint must resolve to exact key ───────────────────────

class TestAC4FingerprintBinding:
    def test_correct_key_passes(self, tmp_path):
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
        assert allowed, f"Should pass but got: {reason}"


# ── AC5: Signature covers same canonical payload as index_digest ────────────

class TestAC5CanonicalPayload:
    def test_same_excluded_fields(self):
        from nodechain.sdk.discovery import compute_index_digest, verify_discovery_signature
        # The digest and signature both exclude "signature" and "index_digest"
        data = {
            "index_id": "t", "source_url": "u", "generated_at": "2026-01-01T00:00:00Z",
            "registries": [], "publishers": [], "packages": [],
        }
        # compute_index_digest excludes signature and index_digest
        d1 = compute_index_digest(data)
        data_with_extras = dict(data)
        data_with_extras["signature"] = "somesig"
        data_with_extras["index_digest"] = d1
        d2 = compute_index_digest(data_with_extras)
        assert d1 == d2  # digest excludes those fields


# ── AC6: Invalid signature fails closed ─────────────────────────────────────

class TestAC6InvalidSigFailsClosed:
    def test_tampered_signature_rejected(self, tmp_path):
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem, fingerprint = _make_signed_index(tmp_path)
        # Tamper with the signature deterministically: flip exactly one bit
        # of the first byte. RSA-PSS signatures are randomized, so blindly
        # replacing the first byte with "00" is a no-op whenever the signature
        # already begins with 00 — the verifier then correctly accepts the
        # unmodified signature and the test false-fails. XOR with 0x01
        # guarantees the tampered signature differs from the original.
        original = idx.signature
        first_byte = int(original[:2], 16) ^ 0x01
        idx.signature = f"{first_byte:02x}" + original[2:]
        assert idx.signature != original
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
        assert "invalid" in reason.lower() or "failed" in reason.lower()

    def test_wrong_key_rejected(self, tmp_path):
        """Signature signed by key A but verified with key B → fail."""
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, public_pem_a, fingerprint_a = _make_signed_index(tmp_path, name="signer_a")
        _, public_pem_b, fingerprint_b = _generate_keypair(tmp_path, name="signer_b")
        resolver = DiscoverySignerResolver()
        # Add the WRONG key under the RIGHT fingerprint
        resolver.add_signer(fingerprint_a, public_pem_b)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fingerprint_a],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed


# ── AC7: Unknown signer fails closed ────────────────────────────────────────

class TestAC7UnknownSignerFails:
    def test_unknown_signer_rejected(self, tmp_path):
        from nodechain.sdk.discovery import (
            check_discovery_policy, DiscoverySignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        idx, _, fingerprint = _make_signed_index(tmp_path)
        resolver = DiscoverySignerResolver()
        # Don't add the signer to the resolver
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=[fingerprint],
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed
        assert "not known" in reason.lower()

    def test_signer_not_in_trusted_list(self, tmp_path):
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
            trusted_discovery_signers=["different_fp"],  # doesn't include the real signer
            maximum_discovery_index_age=0,
        )
        allowed, reason = check_discovery_policy(idx, profile, signer_resolver=resolver)
        assert not allowed
        assert "not in trusted" in reason.lower()


# ── AC8: Field-present-only fails under strict ──────────────────────────────

class TestAC8FieldPresentInsufficient:
    def test_field_present_without_resolver_fails(self):
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="aabbcc", signer_fingerprint="fp",
        )
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=True,
            trusted_discovery_signers=["fp"],
        )
        # No resolver → field-present is not enough
        allowed, reason = check_discovery_policy(idx, profile)
        assert not allowed

    def test_non_crypto_profile_accepts_field_present(self):
        """When require_crypto=False, field presence is still accepted."""
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://m.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="aabbcc", signer_fingerprint="fp",
        )
        profile = OrganizationTrustPolicyProfile(
            name="moderate", description="moderate",
            require_signed_discovery_index=True,
            require_discovery_signature_verification=False,
        )
        allowed, _ = check_discovery_policy(idx, profile)
        assert allowed  # field-present is sufficient when crypto not required


# ── AC9: Receipt records verification details ───────────────────────────────

class TestAC9ReceiptFields:
    def test_receipt_has_signature_present(self):
        from nodechain.sdk.discovery import DiscoveryIndexReceipt
        r = DiscoveryIndexReceipt(
            index_id="i", source_url="u", index_digest="d", fetched_at="now",
            signature_present=True,
        )
        d = r.to_dict()
        assert d["signature_present"] is True
        assert "signature_verified" in d
        assert "verifier_key_digest" in d

    def test_receipt_records_crypto_verification(self):
        from nodechain.sdk.discovery import DiscoveryIndexReceipt
        key_pem = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----"
        key_digest = hashlib.sha256(key_pem.encode()).hexdigest()
        r = DiscoveryIndexReceipt(
            index_id="i", source_url="u", index_digest="d", fetched_at="now",
            signature_present=True,
            signature_verified=True,
            signer_fingerprint="fp123",
            verifier_key_digest=key_digest,
        )
        d = r.to_dict()
        assert d["signature_verified"] is True
        assert d["signer_fingerprint"] == "fp123"
        assert d["verifier_key_digest"] == key_digest


# ── AC10: Runtime and integration ───────────────────────────────────────────

class TestAC10Runtime:
    def test_evidence_types_still_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "discovery_index_receipt" in EVIDENCE_TYPES
        assert "marketplace_registry_add_receipt" in EVIDENCE_TYPES

    def test_health_rules_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_marketplace_cli_group(self):
        from nodechain.cli.main import cli
        assert "marketplace" in cli.commands

    def test_backward_compat_no_resolver(self):
        """Old callers without resolver arg still work for non-crypto profiles."""
        from nodechain.sdk.discovery import check_discovery_policy, PublicDiscoveryIndex
        from nodechain.sdk.org_policy import get_builtin_profile
        idx = PublicDiscoveryIndex(
            index_id="t", source_url="https://marketplace.example.com",
            generated_at="2026-06-17T12:00:00+00:00",
            signature="sig", signer_fingerprint="fp",
        )
        profile = get_builtin_profile("standard_team")
        # standard_team doesn't require crypto, so field-presence is fine
        allowed, _ = check_discovery_policy(idx, profile)
        assert allowed

    def test_full_pipeline_crypto_verified(self, tmp_path):
        """End-to-end: signed index → resolver → strict profile → pass."""
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
        assert allowed
        assert reason == ""
