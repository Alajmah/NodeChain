"""Checkpoint Commit Atomicity Tests (v2.21.3).

CP-016: Failed checkpoint creation leaves no retained evidence.
CP-017: Strict genesis creation requires resolver consistency.
"""

from __future__ import annotations

import pytest
from dataclasses import replace
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
def strict_profile(key_pair):
    from nodechain.sdk.org_policy import get_builtin_profile
    from nodechain.sdk.evidence_checkpoint import derive_fingerprint
    _, pub_pem = key_pair
    fp = derive_fingerprint(pub_pem)
    profile = get_builtin_profile("strict_enterprise")
    return replace(profile, trusted_checkpoint_signers=[fp])


# ── CP-016: Failed creation leaves no retained evidence ────────────────────

class TestCP016CommitAtomicity:
    def test_failed_chain_validation_no_manifest_orphan(self, populated_store, chain, key_pair):
        """When chain validation fails, no manifest artifact is retained."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        priv_pem, pub_pem = key_pair

        # Create a valid first checkpoint
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Count artifacts before
        index_before = populated_store.load_index()
        count_before = len(index_before.get("entries", {}))

        # Break the chain
        data = chain.load()
        data["checkpoints"][0]["previous_checkpoint_digest"] = "wrong"
        chain.save(data)

        # Attempt to create another checkpoint — should fail
        with pytest.raises(CheckpointError, match="existing chain is invalid"):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # No new manifest artifact should have been retained
        index_after = populated_store.load_index()
        count_after = len(index_after.get("entries", {}))
        assert count_after == count_before, (
            f"Expected {count_before} artifacts after failed creation, "
            f"got {count_after}"
        )

    def test_failed_keypair_check_no_manifest(self, populated_store, chain, key_pair, other_key_pair):
        """When keypair check fails, no manifest artifact is retained."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        priv_a, _ = key_pair
        _, pub_b = other_key_pair

        index_before = populated_store.load_index()
        count_before = len(index_before.get("entries", {}))

        with pytest.raises(CheckpointError, match="does not correspond"):
            create_checkpoint(populated_store, chain, priv_a, pub_b)

        index_after = populated_store.load_index()
        count_after = len(index_after.get("entries", {}))
        assert count_after == count_before

    def test_failed_signer_auth_no_manifest(
        self, populated_store, chain, key_pair, other_key_pair
    ):
        """When signer authorization fails, no manifest artifact is retained."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError, derive_fingerprint,
            CheckpointSignerResolver,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        priv_a, _ = key_pair
        _, pub_b = other_key_pair
        fp_b = derive_fingerprint(pub_b)

        profile = replace(
            get_builtin_profile("strict_enterprise"),
            trusted_checkpoint_signers=[fp_b],
        )

        index_before = populated_store.load_index()
        count_before = len(index_before.get("entries", {}))

        with pytest.raises(CheckpointError, match="Unauthorized|resolver"):
            create_checkpoint(
                populated_store, chain, priv_a, key_pair[1],
                profile=profile,
            )

        index_after = populated_store.load_index()
        count_after = len(index_after.get("entries", {}))
        assert count_after == count_before

    def test_successful_creation_retains_manifest(self, populated_store, chain, key_pair):
        """Successful creation does retain the manifest."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair

        index_before = populated_store.load_index()
        count_before = len(index_before.get("entries", {}))

        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        index_after = populated_store.load_index()
        count_after = len(index_after.get("entries", {}))
        assert count_after == count_before + 1  # +1 for manifest

    def test_no_resolver_strict_creation_no_manifest(
        self, populated_store, chain, key_pair, strict_profile
    ):
        """Strict creation without resolver fails without retaining manifest."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        priv_pem, pub_pem = key_pair

        index_before = populated_store.load_index()
        count_before = len(index_before.get("entries", {}))

        with pytest.raises(CheckpointError, match="[Rr]esolver"):
            create_checkpoint(
                populated_store, chain, priv_pem, pub_pem,
                profile=strict_profile,
            )

        index_after = populated_store.load_index()
        count_after = len(index_after.get("entries", {}))
        assert count_after == count_before


# ── CP-017: Genesis resolver consistency ────────────────────────────────────

class TestCP017GenesisResolverBinding:
    def test_genesis_without_resolver_fails_strict(
        self, populated_store, chain, key_pair, strict_profile
    ):
        """Genesis checkpoint under strict profile without resolver → error."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        priv_pem, pub_pem = key_pair
        with pytest.raises(CheckpointError, match="[Rr]esolver"):
            create_checkpoint(
                populated_store, chain, priv_pem, pub_pem,
                profile=strict_profile,
            )

    def test_genesis_with_matching_resolver_succeeds(
        self, populated_store, chain, key_pair, strict_profile
    ):
        """Genesis checkpoint with matching resolver → success."""
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

    def test_genesis_resolver_missing_signer_fails(
        self, populated_store, chain, key_pair, other_key_pair, strict_profile
    ):
        """Genesis checkpoint: resolver has different key → fails."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        _, pub_b = other_key_pair
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_b)  # Wrong key
        with pytest.raises(CheckpointError, match="not found in the resolver"):
            create_checkpoint(
                populated_store, chain, priv_pem, pub_pem,
                profile=strict_profile, signer_resolver=resolver,
            )

    def test_genesis_no_profile_succeeds(self, populated_store, chain, key_pair):
        """Genesis checkpoint without profile → success (no resolver needed)."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        assert cp.sequence_number == 1

    def test_genesis_allow_any_no_resolver_needed(
        self, populated_store, chain, key_pair
    ):
        """allow_any_checkpoint_signer → no resolver required."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        priv_pem, pub_pem = key_pair
        profile = OrganizationTrustPolicyProfile(
            name="test", description="t", version="1.0.0",
            allow_any_checkpoint_signer=True,
        )
        cp = create_checkpoint(
            populated_store, chain, priv_pem, pub_pem,
            profile=profile,
        )
        assert cp.sequence_number == 1

    def test_created_checkpoint_verifiable_under_same_policy(
        self, populated_store, chain, key_pair, strict_profile
    ):
        """Full lifecycle: create under strict → verify under same strict."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, CheckpointSignerResolver,
        )
        priv_pem, pub_pem = key_pair
        resolver = CheckpointSignerResolver()
        resolver.add_signer(pub_pem)
        cp = create_checkpoint(
            populated_store, chain, priv_pem, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        result = verify_checkpoint(
            cp, populated_store, pub_pem,
            profile=strict_profile, signer_resolver=resolver,
        )
        assert result.valid


# ── Transaction ordering verification ──────────────────────────────────────

class TestTransactionOrdering:
    def test_lock_acquired_before_manifest_retained(
        self, populated_store, chain, key_pair, monkeypatch
    ):
        """Verify manifest retain happens after chain lock is acquired."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair

        call_order = []
        original_acquire = chain._acquire_lock
        original_retain = populated_store.retain

        def tracked_acquire():
            call_order.append("lock")
            return original_acquire()

        def tracked_retain(*args, **kwargs):
            call_order.append("retain")
            return original_retain(*args, **kwargs)

        monkeypatch.setattr(chain, "_acquire_lock", tracked_acquire)
        monkeypatch.setattr(populated_store, "retain", tracked_retain)

        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        assert call_order.index("lock") < call_order.index("retain")
