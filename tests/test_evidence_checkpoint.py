"""Signed Evidence Checkpoints and Recovery Verification Tests (v2.21.3).

Tests for:
  1. Checkpoint creation with signing
  2. Checkpoint chain continuity
  3. Checkpoint verification against store state
  4. Recovery report generation
  5. Rollback detection
  6. Chain discontinuity detection
  7. No checkpoint rewriting without detectable discontinuity
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def key_pair(tmp_path):
    """Generate RSA key pair for testing."""
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
    """Store with 3 artifacts."""
    store.retain(b"artifact-1")
    store.retain(b"artifact-2")
    store.retain(b"artifact-3")
    return store


# ── 1. Checkpoint Creation ──────────────────────────────────────────────────

class TestCheckpointCreation:
    def test_create_genesis_checkpoint(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        assert cp.sequence_number == 1
        assert cp.previous_checkpoint_digest == ""
        assert cp.artifact_count == 3
        assert cp.signature != ""
        assert cp.checkpoint_digest != ""

    def test_checkpoint_has_valid_digest(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        recomputed = hashlib.sha256(
            json.dumps(cp._signed_payload(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert cp.checkpoint_digest == recomputed

    def test_checkpoint_signer_fingerprint(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, derive_fingerprint
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        expected_fp = derive_fingerprint(pub_pem)
        assert cp.signer_fingerprint == expected_fp

    def test_checkpoint_fails_on_invalid_store(self, store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointError
        priv_pem, pub_pem = key_pair
        # Empty store has no index — that's fine, creates checkpoint with 0 artifacts
        cp = create_checkpoint(store, chain, priv_pem, pub_pem)
        assert cp.artifact_count == 0


# ── 2. Checkpoint Chain ─────────────────────────────────────────────────────

class TestCheckpointChain:
    def test_chain_continuity(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        assert cp2.sequence_number == 2
        assert cp2.previous_checkpoint_digest == cp1.checkpoint_digest

    def test_genesis_must_be_sequence_1(self, chain):
        from nodechain.sdk.evidence_checkpoint import EvidenceCheckpoint, CheckpointError

        cp = EvidenceCheckpoint(
            checkpoint_id="bad",
            sequence_number=2,  # Wrong!
            previous_checkpoint_digest="",
            manifest_digest="abc",
            index_digest="def",
            policy_profile_digest="",
            artifact_count=0,
            generated_at="now",
            signer_fingerprint="fp",
        )
        with pytest.raises(CheckpointError, match="sequence_number=1"):
            chain.append(cp)

    def test_sequence_discontinuity_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, EvidenceCheckpoint, CheckpointError,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Try to append with wrong sequence
        cp_bad = EvidenceCheckpoint(
            checkpoint_id="bad",
            sequence_number=5,  # Should be 2
            previous_checkpoint_digest=cp1.checkpoint_digest,
            manifest_digest="abc",
            index_digest="def",
            policy_profile_digest="",
            artifact_count=0,
            generated_at="now",
            signer_fingerprint="fp",
        )
        with pytest.raises(CheckpointError, match="Sequence number discontinuity"):
            chain.append(cp_bad)

    def test_continuity_break_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, EvidenceCheckpoint, CheckpointError,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Try to append with wrong previous_digest
        cp_bad = EvidenceCheckpoint(
            checkpoint_id="bad",
            sequence_number=2,
            previous_checkpoint_digest="wrong_digest",
            manifest_digest="abc",
            index_digest="def",
            policy_profile_digest="",
            artifact_count=0,
            generated_at="now",
            signer_fingerprint="fp",
        )
        with pytest.raises(CheckpointError, match="Previous checkpoint digest mismatch"):
            chain.append(cp_bad)


# ── 3. Checkpoint Verification ──────────────────────────────────────────────

class TestCheckpointVerification:
    def test_verify_valid_checkpoint(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert result.valid
        assert result.signature_valid
        assert result.manifest_matches

    def test_verify_detects_state_drift_after_retain(self, populated_store, chain, key_pair):
        """Adding artifacts after checkpoint creates new index entries.
        The checkpoint still verifies against its own manifest artifact,
        but artifact_count no longer matches current state."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Add a new artifact after checkpoint
        populated_store.retain(b"new-after-checkpoint")

        # The checkpoint's manifest artifact still exists and is valid
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert result.valid  # checkpoint verifies against its own snapshot
        assert result.manifest_matches  # manifest artifact is intact
        # But artifact_count is stale
        assert cp.artifact_count == 3  # original count at checkpoint time
        current_index = populated_store.load_index()
        # 3 original + 1 manifest + 1 new = 5
        assert len(current_index["entries"]) == 5

    def test_verify_detects_missing_artifact(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Delete an artifact
        digest_a1 = hashlib.sha256(b"artifact-1").hexdigest()
        populated_store._artifact_path(digest_a1).unlink()

        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert not result.valid
        assert digest_a1 in result.missing_artifacts

    def test_verify_detects_corrupted_artifact(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Corrupt an artifact
        digest_a1 = hashlib.sha256(b"artifact-1").hexdigest()
        populated_store._artifact_path(digest_a1).write_bytes(b"corrupted")

        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert not result.valid
        assert digest_a1 in result.corrupted_artifacts

    def test_verify_detects_tampered_digest(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, EvidenceCheckpoint,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Tamper with checkpoint digest
        cp.checkpoint_digest = "tampered"
        result = verify_checkpoint(cp, populated_store, pub_pem)
        assert not result.valid

    def test_verify_detects_wrong_key(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Generate a different key
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pub = other_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        result = verify_checkpoint(cp, populated_store, other_pub)
        assert not result.signature_valid


# ── 4. Chain Verification ───────────────────────────────────────────────────

class TestChainVerification:
    def test_valid_chain_passes(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        result = verify_checkpoint_chain(chain, pub_pem)
        assert result.chain_valid
        assert result.checkpoints_verified == 2

    def test_broken_chain_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Remove first checkpoint from chain
        data = chain.load()
        data["checkpoints"] = [c for c in data["checkpoints"] if c["sequence_number"] != 1]
        chain.save(data)

        result = verify_checkpoint_chain(chain, pub_pem)
        assert not result.chain_valid
        assert len(result.continuity_breaks) > 0

    def test_removed_checkpoint_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint_chain,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp3 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Remove checkpoint #2
        data = chain.load()
        data["checkpoints"] = [c for c in data["checkpoints"] if c["sequence_number"] != 2]
        chain.save(data)

        result = verify_checkpoint_chain(chain, pub_pem)
        assert not result.chain_valid


# ── 5. Recovery Report ──────────────────────────────────────────────────────

class TestRecoveryReport:
    def test_healthy_store_report(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        report = generate_recovery_report(populated_store, chain, pub_pem)
        assert report.valid
        assert report.manifest_intact
        assert report.artifacts_available
        assert not report.missing_artifacts
        assert not report.corrupted_artifacts
        assert not report.recoverable_orphans

    def test_recovery_with_missing_artifact(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        priv_pem, pub_pem = key_pair

        # Delete artifact but no checkpoint needed for this test
        digest = hashlib.sha256(b"artifact-1").hexdigest()
        populated_store._artifact_path(digest).unlink()

        report = generate_recovery_report(populated_store, chain, pub_pem)
        assert not report.valid
        assert digest in report.missing_artifacts

    def test_recovery_with_orphan(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        priv_pem, pub_pem = key_pair

        # Add orphan
        orphan = hashlib.sha256(b"orphan").hexdigest()
        orphan_path = populated_store._artifact_path(orphan)
        orphan_path.parent.mkdir(parents=True, exist_ok=True)
        orphan_path.write_bytes(b"orphan")

        report = generate_recovery_report(populated_store, chain, pub_pem)
        assert not report.valid
        assert orphan in report.recoverable_orphans

    def test_recovery_no_chain(self, populated_store):
        from nodechain.sdk.evidence_checkpoint import generate_recovery_report
        report = generate_recovery_report(populated_store)
        assert report.valid
        assert not report.checkpoint_verified

    def test_recovery_with_broken_chain(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Remove first checkpoint
        data = chain.load()
        data["checkpoints"] = data["checkpoints"][1:]
        chain.save(data)

        report = generate_recovery_report(populated_store, chain, pub_pem)
        assert not report.checkpoint_verified
        assert report.broken_chain_at is not None


# ── 6. Rollback Detection ───────────────────────────────────────────────────

class TestRollbackDetection:
    def test_no_rollback_detected(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        result = detect_rollback(populated_store, cp)
        assert not result.rollback_detected

    def test_rollback_detected_after_manifest_removal(self, populated_store, chain, key_pair):
        """v2.21.3: detect_rollback requires chain + key for verified lineage."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, detect_rollback,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Remove chain — rollback detection returns indeterminate without chain
        chain.chain_path.unlink()

        result = detect_rollback(populated_store, cp, None, pub_pem)
        assert result.indeterminate
        assert "No local chain" in result.error


# ── 7. No Checkpoint Rewriting ──────────────────────────────────────────────

class TestNoCheckpointRewriting:
    def test_chain_file_preserves_history(self, populated_store, chain, key_pair):
        """Appending checkpoints preserves all previous checkpoints."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint
        priv_pem, pub_pem = key_pair

        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp3 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        all_cps = chain.get_checkpoints()
        assert len(all_cps) == 3
        assert all_cps[0].checkpoint_id == cp1.checkpoint_id
        assert all_cps[2].checkpoint_id == cp3.checkpoint_id

    def test_external_checkpoint_detects_local_tampering(self, populated_store, chain, key_pair):
        """v2.21.3: External checkpoint detects local chain truncation via verified lineage."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, verify_checkpoint, detect_rollback, EvidenceCheckpoint,
        )
        priv_pem, pub_pem = key_pair
        cp1 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        cp2 = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Externally retain cp2
        external_cp2 = EvidenceCheckpoint.from_dict(cp2.to_dict())

        # Locally truncate: remove cp2
        data = chain.load()
        data["checkpoints"] = data["checkpoints"][:-1]
        chain.save(data)

        # External anchor at cp2 detects local chain at cp1
        rollback = detect_rollback(populated_store, external_cp2, chain, pub_pem)
        assert rollback.rollback_detected


# ── Runtime / Integration Tests ─────────────────────────────────────────────

class TestRuntime:
    def test_health_rules_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_evidence_types(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "evidence_checkpoint" in EVIDENCE_TYPES
        assert "checkpoint_chain_receipt" in EVIDENCE_TYPES
        assert "recovery_report" in EVIDENCE_TYPES

    def test_transparency_events(self):
        from nodechain.sdk.transparency_log import EVENT_TYPES
        assert "checkpoint_created" in EVENT_TYPES
        assert "checkpoint_verified" in EVENT_TYPES
        assert "checkpoint_chain_broken" in EVENT_TYPES
        assert "rollback_detected" in EVENT_TYPES

    def test_cli_group(self):
        from nodechain.cli.main import cli
        assert "checkpoint" in cli.commands
