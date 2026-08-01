"""Attestation Issuer Key Binding Tests (v2.21.3).

Ensures the invariant:
    attestation.issuer_fingerprint
    = fingerprint(verification_public_key)
    = profile-authorized issuer fingerprint

A trusted issuer fingerprint string and a valid signature from an arbitrary
key are NOT sufficient. NodeChain must prove the key IS the key represented
by that fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


ARTIFACT_DIGEST = "a" * 64


def _gen_keypair(tmp_path, name="att_signer"):
    from nodechain.cli.bundle_signing import generate_key_pair
    from cryptography.hazmat.primitives import serialization
    keys = generate_key_pair(str(tmp_path), name)
    private_key = serialization.load_pem_private_key(
        Path(keys["private_key_path"]).read_bytes(), password=None,
    )
    public_pem = Path(keys["public_key_path"]).read_text()
    return private_key, public_pem, keys["fingerprint"]


def _make_signed_att(tmp_path, name="signer"):
    from nodechain.sdk.supply_chain_attestation import create_attestation
    private_key, public_pem, fingerprint = _gen_keypair(tmp_path, name)
    att = create_attestation(
        artifact_digest=ARTIFACT_DIGEST,
        package_name="pkg-a",
        package_version="1.0.0",
        attestation_type="build",
        attestation_level="build",
        subject="ci-builder",
        issuer="test-org",
        issuer_fingerprint=fingerprint,
        private_key=private_key,
    )
    return att, public_pem, fingerprint


# ── AC1: AttestationIssuerResolver exists ───────────────────────────────────

class TestAC1Resolver:
    def test_resolver_class(self):
        from nodechain.sdk.supply_chain_attestation import AttestationIssuerResolver
        r = AttestationIssuerResolver()
        assert r.known_fingerprints == []

    def test_add_and_resolve(self):
        from nodechain.sdk.supply_chain_attestation import AttestationIssuerResolver
        r = AttestationIssuerResolver()
        r.add_issuer("fp123", "PEM")
        assert r.resolve("fp123") == "PEM"
        assert r.resolve("unknown") is None
        assert "fp123" in r.known_fingerprints


# ── AC2: derive_fingerprint function ───────────────────────────────────────

class TestAC2DeriveFingerprint:
    def test_derive_matches_generate_key_pair(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import derive_fingerprint
        _, public_pem, fingerprint = _gen_keypair(tmp_path)
        derived = derive_fingerprint(public_pem)
        assert derived == fingerprint

    def test_different_keys_different_fingerprints(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import derive_fingerprint
        _, pub_a, fp_a = _gen_keypair(tmp_path, "key_a")
        _, pub_b, fp_b = _gen_keypair(tmp_path, "key_b")
        assert derive_fingerprint(pub_a) == fp_a
        assert derive_fingerprint(pub_b) == fp_b
        assert fp_a != fp_b


# ── AC3: verify_attestation accepts issuer_resolver ────────────────────────

class TestAC3ResolverInVerify:
    def test_verify_with_resolver(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            verify_attestation, AttestationIssuerResolver,
        )
        att, public_pem, fingerprint = _make_signed_att(tmp_path)
        resolver = AttestationIssuerResolver()
        resolver.add_issuer(fingerprint, public_pem)
        result = verify_attestation(att, issuer_resolver=resolver)
        assert result.valid
        assert result.signature_verified
        assert result.issuer_key_fingerprint_match
        assert result.derived_fingerprint == fingerprint

    def test_verify_with_direct_key(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import verify_attestation
        att, public_pem, fingerprint = _make_signed_att(tmp_path)
        result = verify_attestation(att, public_key_pem=public_pem)
        assert result.valid
        assert result.issuer_key_fingerprint_match


# ── AC4: Fingerprint mismatch detected ─────────────────────────────────────

class TestAC4FingerprintMismatch:
    def test_wrong_key_fails_fingerprint_check(self, tmp_path):
        """Signature from key A, but verifier uses key B → fingerprint mismatch."""
        from nodechain.sdk.supply_chain_attestation import verify_attestation
        att, _, fp_a = _make_signed_att(tmp_path, "signer_a")
        _, pub_b, _ = _gen_keypair(tmp_path, "signer_b")
        result = verify_attestation(att, public_key_pem=pub_b)
        assert not result.valid
        assert "fingerprint mismatch" in result.reason.lower()
        assert not result.issuer_key_fingerprint_match

    def test_attestation_claims_wrong_fingerprint(self, tmp_path):
        """Attestation claims a different fingerprint than the signing key."""
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        private_key, public_pem, real_fp = _gen_keypair(tmp_path)
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fake_fingerprint",
            private_key=private_key,
        )
        result = verify_attestation(att, public_key_pem=public_pem)
        assert not result.valid
        assert "fingerprint mismatch" in result.reason.lower()


# ── AC5: Resolver resolves unknown issuer → fail ───────────────────────────

class TestAC5UnknownIssuer:
    def test_resolver_unknown_fails(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            verify_attestation, AttestationIssuerResolver,
        )
        att, _, fingerprint = _make_signed_att(tmp_path)
        resolver = AttestationIssuerResolver()
        # Don't add the issuer
        result = verify_attestation(att, issuer_resolver=resolver)
        assert not result.valid
        assert "not known" in result.reason.lower()

    def test_no_resolver_no_key_passes_unsigned(self):
        """Unsigned attestation with no resolver → accepted (no sig to check)."""
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = verify_attestation(att)
        assert result.valid


# ── AC6: VerifyResult records all binding fields ───────────────────────────

class TestAC6ResultFields:
    def test_result_has_fingerprint_fields(self):
        from nodechain.sdk.supply_chain_attestation import AttestationVerifyResult
        r = AttestationVerifyResult(attestation_id="a", valid=True)
        d = r.to_dict()
        assert "issuer_key_fingerprint_match" in d
        assert "derived_fingerprint" in d
        assert "verifier_key_digest" in d

    def test_successful_verify_populates_fields(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            verify_attestation, AttestationIssuerResolver,
        )
        att, public_pem, fingerprint = _make_signed_att(tmp_path)
        resolver = AttestationIssuerResolver()
        resolver.add_issuer(fingerprint, public_pem)
        result = verify_attestation(att, issuer_resolver=resolver)
        d = result.to_dict()
        assert d["issuer_key_fingerprint_match"] is True
        assert d["derived_fingerprint"] == fingerprint
        assert d["signature_verified"] is True
        assert d["verifier_key_digest"] != ""


# ── AC7: End-to-end strict policy with resolver ────────────────────────────

class TestAC7EndToEnd:
    def test_strict_policy_accepts_with_resolver(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
            AttestationIssuerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        att, public_pem, fingerprint = _make_signed_att(tmp_path)
        resolver = AttestationIssuerResolver()
        resolver.add_issuer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            minimum_attestation_level="build",
            trusted_attestation_issuers=[fingerprint],
            require_attestation_signature=True,
        )
        result = verify_attestation(att, issuer_resolver=resolver)
        assert result.valid
        accepted, reason = check_attestation_policy(att, result, profile)
        assert accepted, f"Should be accepted: {reason}"

    def test_strict_policy_rejects_unlisted_issuer(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            verify_attestation, check_attestation_policy,
            AttestationIssuerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile

        att, public_pem, fingerprint = _make_signed_att(tmp_path)
        resolver = AttestationIssuerResolver()
        resolver.add_issuer(fingerprint, public_pem)

        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            minimum_attestation_level="build",
            trusted_attestation_issuers=["different-fp"],
            require_attestation_signature=True,
        )
        result = verify_attestation(att, issuer_resolver=resolver)
        assert result.valid  # crypto is fine
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "not in trusted" in reason


# ── AC8: Backward compatibility ─────────────────────────────────────────────

class TestAC8BackwardCompat:
    def test_direct_key_still_works(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import verify_attestation
        att, public_pem, _ = _make_signed_att(tmp_path)
        # No resolver, just direct key
        result = verify_attestation(att, public_key_pem=public_pem)
        assert result.valid

    def test_unsigned_still_works(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = verify_attestation(att)
        assert result.valid

    def test_expected_issuer_fingerprint_still_works(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            verify_attestation,
        )
        att, public_pem, fingerprint = _make_signed_att(tmp_path)
        result = verify_attestation(
            att, public_key_pem=public_pem,
            expected_issuer_fingerprint=fingerprint,
        )
        assert result.valid


# ── AC9: No resolver with signed attestation ────────────────────────────────

class TestAC9NoResolverSigned:
    def test_signed_no_key_no_resolver_fails(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import verify_attestation
        att, _, _ = _make_signed_att(tmp_path)
        result = verify_attestation(att)
        assert not result.valid
        assert "no public key" in result.reason.lower()

    def test_signed_resolver_provides_key(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            verify_attestation, AttestationIssuerResolver,
        )
        att, public_pem, fp = _make_signed_att(tmp_path)
        resolver = AttestationIssuerResolver()
        resolver.add_issuer(fp, public_pem)
        result = verify_attestation(att, issuer_resolver=resolver)
        assert result.valid


# ── AC10: Profile field and digest ──────────────────────────────────────────

class TestAC10Profile:
    def test_allow_any_field_exists(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="t")
        assert hasattr(p, "allow_any_attestation_issuer")
        assert p.allow_any_attestation_issuer is False

    def test_all_builtin_profiles_roundtrip(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.compute_digest() == p.compute_digest()

    def test_health_rules_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_evidence_types(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "supply_chain_attestation" in EVIDENCE_TYPES
        assert "attestation_receipt" in EVIDENCE_TYPES

    def test_cli_group(self):
        from nodechain.cli.main import cli
        assert "supply-chain" in cli.commands
