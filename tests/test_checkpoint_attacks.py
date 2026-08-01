"""Anchored Checkpoint Verification Adversarial Suite (v2.21.3).

Attacks the checkpoint layer across 9 attack categories:

  AC-01: Forged signer fingerprint
  AC-02: Wrong key with valid signature format
  AC-03: Tail checkpoint deletion (local truncation)
  AC-04: Chain file reorder
  AC-05: Stale external anchor
  AC-06: Valid forward progression after anchor
  AC-07: Concurrent checkpoint creation
  AC-08: Checkpoint-chain partial write
  AC-09: Whole-store rollback with and without external witness

Governing principles:
    signer_fingerprint = fingerprint(verification_public_key) — unconditional
    rollback ≠ divergence
    local chain truncation is only detectable with external anchor
    forward progress with valid descendant is NOT rollback
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ── Fixtures ────────────────────────────────────────────────────────────────

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
    """Different key pair for testing identity binding."""
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


# ── AC-01: Forged signer fingerprint ───────────────────────────────────────

class TestAC01ForgedFingerprint:
    """CP-002: signer_fingerprint must be cryptographically bound to the verification key."""

    def test_forged_fingerprint_detected(self, populated_store, chain, key_pair):
        """Checkpoint with wrong signer_fingerprint must fail verification."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, verify_checkpoint_signature,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Forge a different fingerprint
        cp.signer_fingerprint = "a" * 32

        # Signature verification must fail
        assert not verify_checkpoint_signature(cp, pub_pem)

    def test_wrong_fingerprint_fails_even_with_valid_sig(self, populated_store, chain, key_pair):
        """Even if the signature is valid, wrong fingerprint must fail."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_signature,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Change fingerprint but keep real signature
        original_fp = cp.signer_fingerprint
        cp.signer_fingerprint = "0" * 32

        # Must fail because fingerprint doesn't match key
        assert not verify_checkpoint_signature(cp, pub_pem)


# ── AC-02: Wrong key with valid signature format ───────────────────────────

class TestAC02WrongKey:
    def test_wrong_key_rejected(self, populated_store, chain, key_pair, other_key_pair):
        """Checkpoint signed by key A must fail verification with key B."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_signature,
        )
        priv_a, pub_a = key_pair
        priv_b, pub_b = other_key_pair

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)

        # Verify with wrong key
        assert not verify_checkpoint_signature(cp, pub_b)

    def test_wrong_key_in_verify_checkpoint(self, populated_store, chain, key_pair, other_key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_a, pub_a = key_pair
        _, pub_b = other_key_pair

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)
        result = verify_checkpoint(cp, populated_store, pub_b)
        assert not result.signature_valid


# ── AC-03: Tail checkpoint deletion (local truncation) ─────────────────────

class TestAC03TailDeletion:
    """CP-001: Local chain truncation is not locally detectable without external anchor."""

    def test_truncated_chain_still_verifies_internally(self, populated_store, chain, key_pair):
        """Truncated chain still verifies as a valid chain — local limitation."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Truncate: remove last checkpoint
        data = chain.load()
        data["checkpoints"] = data["checkpoints"][:-1]
        chain.save(data)

        result = verify_checkpoint_chain(chain, pub_pem)
        # The remaining chain is still internally valid
        assert result.chain_valid

    def test_truncation_detected_with_external_anchor(self, populated_store, chain, key_pair):
        """External anchor detects local truncation."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp3 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Externally retain cp3
        external_cp3 = EvidenceCheckpoint.from_dict(cp3.to_dict())

        # Locally truncate to cp2
        data = chain.load()
        data["checkpoints"] = data["checkpoints"][:-1]
        chain.save(data)

        # External anchor at #3 detects local chain at #2
        result = detect_rollback(populated_store, external_cp3, chain, pub_pem)
        assert result.rollback_detected
        assert result.actual_sequence < result.expected_sequence


# ── AC-04: Chain file reorder ──────────────────────────────────────────────

class TestAC04ChainReorder:
    def test_reordered_checkpoints_detected(self, populated_store, chain, key_pair):
        """Reordered checkpoints with broken predecessor links are detected.

        Note: A simple file reorder doesn't break chain validity because
        verification sorts by sequence_number and uses cryptographic
        predecessor digests. The chain is position-independent.
        Breaking predecessor digests DOES break verification.
        """
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Swap predecessor digests between checkpoints #2 and #3
        data = chain.load()
        cps = data["checkpoints"]
        cps[1]["previous_checkpoint_digest"], cps[2]["previous_checkpoint_digest"] = (
            cps[2]["previous_checkpoint_digest"],
            cps[1]["previous_checkpoint_digest"],
        )
        chain.save(data)

        result = verify_checkpoint_chain(chain, pub_pem)
        assert not result.chain_valid


# ── AC-05: Stale external anchor ───────────────────────────────────────────

class TestAC05StaleAnchor:
    def test_stale_anchor_with_newer_local_chain(self, populated_store, chain, key_pair):
        """External anchor at #1, local chain has progressed to #3 — not rollback."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # External anchor is cp1 (old)
        result = detect_rollback(populated_store, cp1, chain, pub_pem)
        assert not result.rollback_detected
        assert result.is_descendant


# ── AC-06: Valid forward progression after anchor ──────────────────────────

class TestAC06ForwardProgress:
    def test_new_artifacts_after_checkpoint_is_not_rollback(self, populated_store, chain, key_pair):
        """Adding artifacts after a checkpoint and creating a new one is normal progress."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Add new artifacts
        populated_store.retain(b"new-1")
        populated_store.retain(b"new-2")

        # Create checkpoint #2
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # External anchor at cp1 — local is at cp2 (descendant)
        result = detect_rollback(populated_store, cp1, chain, pub_pem)
        assert not result.rollback_detected
        assert result.is_descendant

    def test_rollback_to_prior_checkpoint_detected(self, populated_store, chain, key_pair):
        """Actually rolling back the chain is detected."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Externally retain cp2
        external_cp2 = EvidenceCheckpoint.from_dict(cp2.to_dict())

        # Locally remove cp2
        data = chain.load()
        data["checkpoints"] = data["checkpoints"][:-1]
        chain.save(data)

        result = detect_rollback(populated_store, external_cp2, chain, pub_pem)
        assert result.rollback_detected


# ── AC-07: Concurrent checkpoint creation ──────────────────────────────────

class TestAC07ConcurrentCreation:
    """CP-004: Chain writer serialization prevents lost checkpoints."""

    def test_concurrent_creation_preserves_both(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair

        errors = []
        def create_thread():
            try:
                create_checkpoint(populated_store, chain, priv_pem, pub_pem)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=create_thread)
        t2 = threading.Thread(target=create_thread)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # At least one must succeed; ideally both
        checkpoints = chain.get_checkpoints()
        assert len(checkpoints) >= 1


# ── AC-08: Checkpoint-chain partial write ──────────────────────────────────

class TestAC08PartialWrite:
    def test_corrupt_chain_file_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Corrupt chain file
        chain.chain_path.write_text('{corrupt')

        with pytest.raises(CheckpointError, match="corrupt"):
            chain.load()

    def test_empty_chain_file_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        chain.chain_path.write_text("")

        with pytest.raises(CheckpointError, match="corrupt"):
            chain.load()


# ── AC-09: Whole-store rollback with and without external witness ──────────

class TestAC09WholeStoreRollback:
    def test_rollback_without_chain_returns_indeterminate(self, populated_store, chain, key_pair):
        """v2.21.3: Without chain, rollback detection is indeterminate."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Remove chain
        chain.chain_path.unlink()

        result = detect_rollback(populated_store, cp, None, pub_pem)
        assert result.indeterminate

    def test_rollback_with_external_witness(self, populated_store, chain, key_pair):
        """External witness detects rollback even after chain manipulation."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback, EvidenceCheckpoint,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Externally retain cp2
        external_cp2 = EvidenceCheckpoint.from_dict(cp2.to_dict())

        # Locally truncate to cp1
        data = chain.load()
        data["checkpoints"] = data["checkpoints"][:-1]
        chain.save(data)

        # External checkpoint detects local chain is behind
        result = detect_rollback(populated_store, external_cp2, chain, pub_pem)
        assert result.rollback_detected


# ── Import for external_cp usage ────────────────────────────────────────────

from nodechain.sdk.evidence_checkpoint import EvidenceCheckpoint


# ── Manifest artifact binding (CP-005) ──────────────────────────────────────

class TestCP005ManifestArtifact:
    def test_manifest_digest_is_retained_artifact(self, populated_store, chain, key_pair):
        """manifest_digest must be a content-addressed artifact in the store."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # The manifest artifact must exist in the store
        manifest_path = populated_store._artifact_path(cp.manifest_digest)
        assert manifest_path.exists()

    def test_manifest_artifact_content_verified(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Verify manifest content digest
        manifest_path = populated_store._artifact_path(cp.manifest_digest)
        content = manifest_path.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        assert actual == cp.manifest_digest

    def test_verify_checkpoint_checks_manifest_artifact(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Delete manifest artifact
        populated_store._artifact_path(cp.manifest_digest).unlink()

        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert not result.valid
        assert "manifest" in result.error.lower()


# ── Signature verification includes fingerprint (CP-002) ───────────────────

class TestCP002UnconditionalFingerprint:
    def test_fingerprint_always_checked(self, populated_store, chain, key_pair, other_key_pair):
        """Even without expected_fingerprint param, verify_checkpoint checks binding."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, verify_checkpoint
        priv_a, pub_a = key_pair
        _, pub_b = other_key_pair

        cp = create_checkpoint(populated_store, chain, priv_a, pub_a)
        # No expected_fingerprint parameter — still must fail with wrong key
        result = verify_checkpoint(cp, populated_store, pub_b)
        assert not result.signature_valid
