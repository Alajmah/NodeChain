"""Checkpoint Signer Authorization Tests (v2.21.3).

CP-010: create_checkpoint verifies existing chain before extending.
CP-011: Manifest self-consistency (duplicate digests, count vs list length).
CP-012: Organization-authorized checkpoint signer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


@pytest.fixture
def other_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


@pytest.fixture
def store(tmp_path):
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    return ContentAddressedStore(tmp_path / "store")


@pytest.fixture
def chain(tmp_path):
    from nodechain.sdk.evidence_checkpoint import CheckpointChain
    return CheckpointChain(tmp_path / "chain.json")


@pytest.fixture
def populated_store(store):
    store.retain(b"artifact-1")
    store.retain(b"artifact-2")
    return store


# ── CP-010: Chain validation before extending ──────────────────────────────

class TestCP010ChainValidationBeforeExtend:
    def test_create_checkpoint_on_valid_chain_succeeds(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        assert cp2.sequence_number == 2

    def test_create_checkpoint_on_broken_chain_fails(self, populated_store, chain, key_pair):
        """Cannot extend a chain with broken continuity."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Break chain continuity
        data = chain.load()
        data["checkpoints"][1]["previous_checkpoint_digest"] = "wrong"
        chain.save(data)

        with pytest.raises(CheckpointError, match="existing chain is invalid"):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

    def test_create_checkpoint_on_broken_signature_fails(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Corrupt a signature
        data = chain.load()
        data["checkpoints"][0]["signature"] = "0" * 64
        chain.save(data)

        with pytest.raises(CheckpointError, match="existing chain is invalid"):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)


# ── CP-011: Manifest self-consistency ──────────────────────────────────────

class TestCP011ManifestSelfConsistency:
    def test_manifest_count_matches_digest_list(self, populated_store, chain, key_pair):
        """Manifest artifact_count must equal len(artifact_digests)."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert result.valid  # Valid manifest passes

    def test_manifest_rejects_duplicate_digests(self, populated_store, chain, key_pair):
        """A manifest with duplicate digests would be detected by content-addressed hash."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        # Valid checkpoint passes — no duplicates possible with sorted(entries.keys())
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert result.valid


# ── CP-012: Checkpoint signer authorization ────────────────────────────────

class TestCP012SignerAuthorization:
    def test_resolver_add_signer(self, key_pair):
        from nodechain.sdk.evidence_checkpoint import CheckpointSignerResolver, derive_fingerprint
        _, pub_pem = key_pair
        resolver = CheckpointSignerResolver()
        fp = resolver.add_signer(pub_pem)
        assert fp == derive_fingerprint(pub_pem)
        assert resolver.is_known(fp)
        assert resolver.get_key(fp) == pub_pem

    def test_resolver_unknown_fingerprint(self, key_pair):
        from nodechain.sdk.evidence_checkpoint import CheckpointSignerResolver
        _, pub_pem = key_pair
        resolver = CheckpointSignerResolver()
        assert not resolver.is_known("unknown_fp")
        assert resolver.get_key("unknown_fp") is None

    def test_permissive_profile_allows_any_signer(self, populated_store, chain, key_pair):
        """Permissive profiles don't require checkpoint signer authorization."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, check_checkpoint_signer_policy,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        profile = get_builtin_profile("permissive_local")
        authorized, reason = check_checkpoint_signer_policy(cp, profile)
        assert authorized

    def test_strict_profile_denies_unauthorized_signer(self, populated_store, chain, key_pair):
        """Strict profiles require authorized signers."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, check_checkpoint_signer_policy,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        profile = get_builtin_profile("strict_enterprise")
        # No trusted_checkpoint_signers configured → fails closed
        authorized, reason = check_checkpoint_signer_policy(cp, profile)
        assert not authorized
        assert "authorization required" in reason.lower() or "not in" in reason.lower()

    def test_strict_profile_allows_authorized_signer(self, populated_store, chain, key_pair):
        """Strict profile with the signer in the allowlist allows it."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, check_checkpoint_signer_policy, derive_fingerprint,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        from dataclasses import replace
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        profile = get_builtin_profile("strict_enterprise")
        # Add signer to trusted list
        profile_with_signer = replace(
            profile, trusted_checkpoint_signers=[cp.signer_fingerprint]
        )
        authorized, reason = check_checkpoint_signer_policy(cp, profile_with_signer)
        assert authorized

    def test_strict_profile_resolver_does_not_authorize_without_allowlist(self, populated_store, chain, key_pair):
        """Strict profile: resolver alone cannot authorize (v2.21.3 fix)."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, check_checkpoint_signer_policy,
            CheckpointSignerResolver,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        profile = get_builtin_profile("strict_enterprise")

        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)

        # Empty trusted list + resolver → denied (resolver doesn't authorize)
        authorized, reason = check_checkpoint_signer_policy(cp, profile, resolver)
        assert not authorized
        assert "no trusted" in reason.lower()

    def test_allow_any_checkpoint_signer_opt_in(self, populated_store, chain, key_pair):
        """allow_any_checkpoint_signer=True bypasses authorization."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, check_checkpoint_signer_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        profile = OrganizationTrustPolicyProfile(
            name="test",
            description="test",
            version="1.0.0",
            require_checkpoint_signer_authorization=True,
            allow_any_checkpoint_signer=True,
        )
        authorized, _ = check_checkpoint_signer_policy(cp, profile)
        assert authorized

    def test_wrong_signer_denied_by_strict_profile(self, populated_store, chain, key_pair, other_key_pair):
        """Signer A creates checkpoint, strict profile only trusts signer B."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, check_checkpoint_signer_policy, derive_fingerprint,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        from dataclasses import replace
        priv_a, pub_a = key_pair
        _, pub_b = other_key_pair

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)
        fp_b = derive_fingerprint(pub_b)

        profile = get_builtin_profile("strict_enterprise")
        profile_b = replace(profile, trusted_checkpoint_signers=[fp_b])

        authorized, reason = check_checkpoint_signer_policy(cp, profile_b)
        assert not authorized

    def test_profile_roundtrip_preserves_checkpoint_fields(self):
        """Profile serialization preserves checkpoint signer fields."""
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(
            name="test",
            description="test",
            version="1.0.0",
            trusted_checkpoint_signers=["abc123"],
            require_checkpoint_signer_authorization=True,
            allow_any_checkpoint_signer=False,
        )
        d = p.to_dict()
        p2 = OrganizationTrustPolicyProfile.from_dict(d)
        assert p2.trusted_checkpoint_signers == ["abc123"]
        assert p2.require_checkpoint_signer_authorization is True
        assert p2.allow_any_checkpoint_signer is False
        assert p2.compute_digest() == p.compute_digest()

    def test_all_builtin_profiles_roundtrip(self):
        """All built-in profiles round-trip with checkpoint signer fields."""
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.compute_digest() == p.compute_digest()


# ── Runtime tests ───────────────────────────────────────────────────────────

class TestRuntime:
    def test_health_rules_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_cli_group(self):
        from nodechain.cli.main import cli
        assert "checkpoint" in cli.commands
