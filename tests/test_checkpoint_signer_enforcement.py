"""Checkpoint Signer Policy Enforcement Tests (v2.21.3).

CP-012: Signer authorization is enforced by verification APIs.
CP-013: Resolver provides keys, not authorization.
"""

from __future__ import annotations

import json
from dataclasses import replace
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


@pytest.fixture
def strict_profile_with_signer(key_pair):
    """Strict profile that authorizes the given signer."""
    from nodechain.sdk.org_policy import get_builtin_profile
    from nodechain.sdk.evidence_checkpoint import derive_fingerprint
    _, pub_pem = key_pair
    fp = derive_fingerprint(pub_pem)
    profile = get_builtin_profile("strict_enterprise")
    return replace(profile, trusted_checkpoint_signers=[fp])


# ── CP-012: Verification API enforcement ───────────────────────────────────

class TestCP012VerifyCheckpointEnforcement:
    def test_no_profile_uses_caller_key(self, populated_store, chain, key_pair):
        """Without profile, caller-supplied key is used (backwards-compatible)."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert result.valid

    def test_strict_profile_no_resolver_denies(self, populated_store, chain, key_pair, strict_profile_with_signer):
        """Strict profile with no resolver → deny (caller key ignored)."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint(
            cp, populated_store, pub_pem,
            profile=strict_profile_with_signer,
        )
        assert not result.valid
        assert "resolver" in result.error.lower()

    def test_strict_profile_with_resolver_allows(self, populated_store, chain, key_pair, strict_profile_with_signer):
        """Strict profile with resolver → authorized signer passes."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)
        result = verify_checkpoint(
            cp, populated_store, pub_pem,
            profile=strict_profile_with_signer, signer_resolver=resolver,
        )
        assert result.valid

    def test_strict_profile_wrong_signer_denies(self, populated_store, chain, key_pair, other_key_pair):
        """Strict profile authorizes signer A, checkpoint signed by A, but
        resolver has signer B — fingerprint mismatch."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, CheckpointSignerResolver,
            derive_fingerprint,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_a, pub_a = key_pair
        _, pub_b = other_key_pair

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)
        fp_a = derive_fingerprint(pub_a)

        # Profile authorizes A, resolver has B (not A)
        profile = replace(
            get_builtin_profile("strict_enterprise"),
            trusted_checkpoint_signers=[fp_a],
        )
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_b)  # Wrong key

        result = verify_checkpoint(
            cp, populated_store, pub_a,
            profile=profile, signer_resolver=resolver,
        )
        assert not result.valid
        assert "not found in the resolver" in result.error.lower() or "fingerprint" in result.error.lower()

    def test_permissive_profile_uses_caller_key(self, populated_store, chain, key_pair):
        """Permissive profile doesn't require authorization."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint(
            cp, populated_store, pub_pem,
            profile=get_builtin_profile("permissive_local"),
        )
        assert result.valid

    def test_caller_key_bypass_denied_in_strict_mode(
        self, populated_store, chain, key_pair, other_key_pair
    ):
        """Strict profile: caller supplies wrong key but profile doesn't
        authorize it — must deny even if checkpoint was validly signed."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, derive_fingerprint,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_a, pub_a = key_pair
        _, pub_b = other_key_pair
        fp_b = derive_fingerprint(pub_b)

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)

        # Profile authorizes B, not A
        profile = replace(
            get_builtin_profile("strict_enterprise"),
            trusted_checkpoint_signers=[fp_b],
        )
        # Caller supplies pub_b hoping to bypass
        result = verify_checkpoint(
            cp, populated_store, pub_b,
            profile=profile,
        )
        assert not result.valid
        assert "not in the trusted" in result.error.lower()


class TestCP012ChainVerificationEnforcement:
    def test_strict_profile_chain_verify_denies_without_resolver(
        self, populated_store, chain, key_pair, strict_profile_with_signer
    ):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        result = verify_checkpoint_chain(
            chain, pub_pem, profile=strict_profile_with_signer,
        )
        assert not result.chain_valid
        assert any("resolver" in e.lower() for e in result.errors)

    def test_strict_profile_chain_verify_with_resolver(
        self, populated_store, chain, key_pair, strict_profile_with_signer
    ):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)

        result = verify_checkpoint_chain(
            chain, pub_pem,
            profile=strict_profile_with_signer, signer_resolver=resolver,
        )
        assert result.chain_valid


class TestCP012RecoveryReportEnforcement:
    def test_recovery_with_strict_profile_and_resolver(
        self, populated_store, chain, key_pair, strict_profile_with_signer
    ):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)

        report = generate_recovery_report(
            populated_store, chain, pub_pem,
            profile=strict_profile_with_signer, signer_resolver=resolver,
        )
        assert report.checkpoint_verified

    def test_recovery_strict_no_resolver_fails_verification(
        self, populated_store, chain, key_pair, strict_profile_with_signer
    ):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        report = generate_recovery_report(
            populated_store, chain, pub_pem,
            profile=strict_profile_with_signer,
        )
        assert not report.checkpoint_verified


class TestCP012RollbackDetectionEnforcement:
    def test_rollback_with_strict_profile_and_resolver(
        self, populated_store, chain, key_pair, strict_profile_with_signer
    ):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)

        result = detect_rollback(
            populated_store, cp, chain, pub_pem,
            profile=strict_profile_with_signer, signer_resolver=resolver,
        )
        assert not result.rollback_detected
        assert result.is_descendant  # Forward progression

    def test_rollback_strict_no_resolver_indeterminate(
        self, populated_store, chain, key_pair, strict_profile_with_signer
    ):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        result = detect_rollback(
            populated_store, cp, chain, pub_pem,
            profile=strict_profile_with_signer,
        )
        assert result.indeterminate
        assert "resolver" in result.error.lower() or "authorization" in result.error.lower()


# ── CP-013: Resolver does not independently authorize ──────────────────────

class TestCP013ResolverNotAuthorization:
    def test_resolver_known_but_not_allowlisted_denied(
        self, populated_store, chain, key_pair, other_key_pair
    ):
        """Signer A in resolver but NOT in profile's trusted list → denied."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, CheckpointSignerResolver,
            derive_fingerprint,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_a, pub_a = key_pair
        _, pub_b = other_key_pair
        fp_b = derive_fingerprint(pub_b)

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)

        # Profile trusts B only
        profile = replace(
            get_builtin_profile("strict_enterprise"),
            trusted_checkpoint_signers=[fp_b],
        )
        # Resolver has A (the actual signer)
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_a)

        result = verify_checkpoint(
            cp, populated_store, pub_a,
            profile=profile, signer_resolver=resolver,
        )
        assert not result.valid
        assert "not in the trusted" in result.error.lower()

    def test_resolver_with_empty_trusted_list_denied(
        self, populated_store, chain, key_pair
    ):
        """require_auth=True + empty trusted list → denied even with resolver."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, CheckpointSignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        profile = OrganizationTrustPolicyProfile(
            name="test",
            description="test",
            version="1.0.0",
            require_checkpoint_signer_authorization=True,
            trusted_checkpoint_signers=[],  # empty
        )
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)

        result = verify_checkpoint(
            cp, populated_store, pub_pem,
            profile=profile, signer_resolver=resolver,
        )
        assert not result.valid
        assert "no trusted" in result.error.lower()

    def test_allow_any_bypasses_resolver_requirement(
        self, populated_store, chain, key_pair
    ):
        """allow_any_checkpoint_signer=True → caller key accepted, no resolver needed."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        profile = OrganizationTrustPolicyProfile(
            name="test",
            description="test",
            version="1.0.0",
            allow_any_checkpoint_signer=True,
        )
        result = verify_checkpoint(
            cp, populated_store, pub_pem,
            profile=profile,
        )
        assert result.valid

    def test_check_policy_resolver_does_not_authorize(self):
        """check_checkpoint_signer_policy: resolver membership alone doesn't authorize."""
        from nodechain.sdk.evidence_checkpoint import (
            check_checkpoint_signer_policy,
            CheckpointSignerResolver,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        from nodechain.sdk.evidence_checkpoint import derive_fingerprint

        # Create a fake checkpoint-like object
        class FakeCheckpoint:
            signer_fingerprint = "abc123"

        profile = OrganizationTrustPolicyProfile(
            name="test",
            description="test",
            version="1.0.0",
            require_checkpoint_signer_authorization=True,
            trusted_checkpoint_signers=["xyz789"],  # Different from signer
        )
        resolver = CheckpointSignerResolver()
        # Resolver "knows" abc123 but it's not in the trusted list
        resolver._signers["abc123"] = "fake_key"

        authorized, reason = check_checkpoint_signer_policy(
            FakeCheckpoint(), profile, resolver,
        )
        assert not authorized
        assert "not in the trusted" in reason.lower()


# ── Backwards compatibility ────────────────────────────────────────────────

class TestBackwardsCompat:
    def test_verify_without_profile_works(self, populated_store, chain, key_pair):
        """Existing callers without profile params still work."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert result.valid

    def test_chain_verify_without_profile_works(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint_chain(chain, pub_pem)
        assert result.chain_valid

    def test_detect_rollback_without_profile_works(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = detect_rollback(populated_store, cp, chain, pub_pem)
        assert not result.rollback_detected
