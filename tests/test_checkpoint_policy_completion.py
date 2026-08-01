"""Checkpoint Policy Completion Tests (v2.21.3).

CP-014: Strict recovery verification is fail-closed.
CP-015: Checkpoint creation is policy-governed.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dataclasses import replace


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
def strict_profile(key_pair):
    from nodechain.sdk.org_policy import get_builtin_profile
    from nodechain.sdk.evidence_checkpoint import derive_fingerprint
    _, pub_pem = key_pair
    fp = derive_fingerprint(pub_pem)
    profile = get_builtin_profile("strict_enterprise")
    return replace(profile, trusted_checkpoint_signers=[fp])


# ── CP-014: Strict recovery fail-closed ────────────────────────────────────

class TestCP014StrictRecoveryFailClosed:
    def test_strict_recovery_no_chain_indeterminate(self, populated_store, key_pair, strict_profile):
        """Strict profile + no chain → indeterminate."""
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        _, pub_pem = key_pair
        report = generate_recovery_report(
            populated_store, chain=None, public_key_pem=pub_pem,
            profile=strict_profile,
        )
        assert not report.valid
        assert report.checkpoint_indeterminate
        assert "chain required" in report.error.lower()

    def test_strict_recovery_no_resolver_indeterminate(self, populated_store, chain, key_pair, strict_profile):
        """Strict profile + no resolver → indeterminate."""
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        _, pub_pem = key_pair
        report = generate_recovery_report(
            populated_store, chain=chain, public_key_pem=pub_pem,
            profile=strict_profile,
        )
        assert not report.valid
        assert report.checkpoint_indeterminate
        assert "resolver" in report.error.lower()

    def test_strict_recovery_no_key_indeterminate(self, populated_store, chain, key_pair, strict_profile):
        """Strict profile + resolver but no key → indeterminate."""
        from nodechain.sdk.evidence_checkpoint import (
            generate_recovery_report, CheckpointSignerResolver,
        )
        _, pub_pem = key_pair
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)
        report = generate_recovery_report(
            populated_store, chain=chain, public_key_pem=None,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert not report.valid
        assert report.checkpoint_indeterminate
        assert "key" in report.error.lower()

    def test_strict_recovery_full_inputs_succeeds(self, populated_store, chain, key_pair, strict_profile):
        """Strict profile + chain + resolver + key → verified."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)
        report = generate_recovery_report(
            populated_store, chain, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert report.checkpoint_verified
        assert not report.checkpoint_indeterminate

    def test_no_profile_recovery_without_chain_ok(self, populated_store, key_pair):
        """No profile + no chain → storage-only report (backwards-compat)."""
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        _, pub_pem = key_pair
        report = generate_recovery_report(populated_store)
        assert not report.checkpoint_indeterminate
        # Valid based on storage integrity alone (no chain to verify)

    def test_allow_any_profile_recovery_without_resolver_ok(
        self, populated_store, chain, key_pair
    ):
        """allow_any profile doesn't require resolver."""
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        _, pub_pem = key_pair
        profile = OrganizationTrustPolicyProfile(
            name="test", description="t", version="1.0.0",
            allow_any_checkpoint_signer=True,
        )
        report = generate_recovery_report(
            populated_store, chain, pub_pem, profile=profile,
        )
        assert not report.checkpoint_indeterminate


# ── CP-015: Checkpoint creation policy-governed ────────────────────────────

class TestCP015CreationGate:
    def test_mismatched_keypair_rejected(self, populated_store, chain, key_pair, other_key_pair):
        """Private key A + public key B → CheckpointError."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        priv_a, _ = key_pair
        _, pub_b = other_key_pair
        with pytest.raises(CheckpointError, match="does not correspond"):
            create_checkpoint(populated_store, chain, priv_a, pub_b)

    def test_matching_keypair_accepted(self, populated_store, chain, key_pair):
        """Matching private/public key pair → success."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        assert cp.sequence_number == 1

    def test_strict_creation_unauthorized_signer_rejected(
        self, populated_store, chain, key_pair, other_key_pair
    ):
        """Strict profile trusts B, but signer is A → CheckpointError."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError, derive_fingerprint,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_a, _ = key_pair
        _, pub_b = other_key_pair
        fp_b = derive_fingerprint(pub_b)
        profile = replace(
            get_builtin_profile("strict_enterprise"),
            trusted_checkpoint_signers=[fp_b],
        )
        with pytest.raises(CheckpointError, match="Unauthorized"):
            create_checkpoint(
                populated_store, chain, priv_a, key_pair[1],
                profile=profile,
            )

    def test_strict_creation_authorized_signer_accepted(
        self, populated_store, chain, key_pair, strict_profile
    ):
        """Strict profile with authorized signer → success."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)
        cp = create_checkpoint(
            populated_store, chain, priv_pem, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert cp.sequence_number == 1

    def test_no_profile_creation_unrestricted(self, populated_store, chain, key_pair):
        """No profile → any signer can create."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        assert cp.sequence_number == 1

    def test_strict_creation_empty_trusted_list_rejected(
        self, populated_store, chain, key_pair
    ):
        """Strict profile with empty trusted list → CheckpointError."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_pem, pub_pem = key_pair
        profile = replace(
            get_builtin_profile("strict_enterprise"),
            trusted_checkpoint_signers=[],
        )
        with pytest.raises(CheckpointError, match="no trusted"):
            create_checkpoint(
                populated_store, chain, priv_pem, pub_pem,
                profile=profile,
            )

    def test_create_verify_recover_rollback_flow(
        self, populated_store, chain, key_pair, strict_profile
    ):
        """Full authorized flow: create → verify → recovery → rollback."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, verify_checkpoint_chain,
            generate_recovery_report, detect_rollback, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)

        cp1 = create_checkpoint(
            populated_store, chain, priv_pem, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        cp2 = create_checkpoint(
            populated_store, chain, priv_pem, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )

        # Verify
        result = verify_checkpoint(
            cp2, populated_store, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert result.valid

        # Chain verify
        chain_result = verify_checkpoint_chain(
            chain, pub_pem, profile=strict_profile, signer_resolver=resolver,
        )
        assert chain_result.chain_valid

        # Recovery
        report = generate_recovery_report(
            populated_store, chain, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert report.checkpoint_verified
        assert not report.checkpoint_indeterminate

        # Rollback
        rollback = detect_rollback(
            populated_store, cp1, chain, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert not rollback.rollback_detected
        assert rollback.is_descendant


# ── derive_fingerprint_from_private ───────────────────────────────────────

class TestFingerprintFromPrivate:
    def test_private_derives_same_fingerprint_as_public(self, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            derive_fingerprint, derive_fingerprint_from_private,
        )
        priv_pem, pub_pem = key_pair
        assert derive_fingerprint(pub_pem) == derive_fingerprint_from_private(priv_pem)

    def test_different_keys_different_fingerprints(self, key_pair, other_key_pair):
        from nodechain.sdk.evidence_checkpoint import derive_fingerprint_from_private
        priv_a, _ = key_pair
        priv_b, _ = other_key_pair
        assert derive_fingerprint_from_private(priv_a) != derive_fingerprint_from_private(priv_b)
