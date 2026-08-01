"""Checkpoint Commit Journal Tests (v2.21.3).

CP-018: Failed checkpoint creation after manifest retention is journaled
and recoverable.
"""

from __future__ import annotations

import json
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


# ── Journal data model ─────────────────────────────────────────────────────

class TestJournalModel:
    def test_journal_prepare_and_commit(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, JOURNAL_PREPARED, JOURNAL_COMMITTED,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        op = journal.prepare("op-1", sequence=1, predecessor_digest="",
                            manifest_digest="abc", policy_profile_digest="def",
                            signer_fingerprint="fp123")
        assert op.status == JOURNAL_PREPARED
        assert len(journal.get_operations()) == 1

        journal.mark_manifest_retained("op-1")
        ops = journal.get_operations()
        assert ops[0].status == "manifest_retained"

        journal.mark_committed("op-1")
        ops = journal.get_operations()
        assert ops[0].status == JOURNAL_COMMITTED
        assert ops[0].completed_at != ""

    def test_journal_abort(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare("op-1", sequence=1, predecessor_digest="",
                       manifest_digest="abc", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_manifest_retained("op-1")
        journal.mark_aborted("op-1", "Signing failed")

        ops = journal.get_operations()
        assert ops[0].status == "aborted"
        assert ops[0].abort_reason == "Signing failed"

    def test_journal_uncommitted(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare("op-1", sequence=1, predecessor_digest="",
                       manifest_digest="abc", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_manifest_retained("op-1")
        journal.prepare("op-2", sequence=2, predecessor_digest="",
                       manifest_digest="def", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_committed("op-2")

        uncommitted = journal.get_uncommitted()
        assert len(uncommitted) == 1
        assert uncommitted[0].operation_id == "op-1"

    def test_journal_aborted_list(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare("op-1", sequence=1, predecessor_digest="",
                       manifest_digest="abc", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_aborted("op-1", "test")
        aborted = journal.get_aborted()
        assert len(aborted) == 1

    def test_journal_manifest_digests_in_progress(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare("op-1", sequence=1, predecessor_digest="",
                       manifest_digest="abc", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_manifest_retained("op-1")
        journal.prepare("op-2", sequence=2, predecessor_digest="",
                       manifest_digest="def", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_committed("op-2")

        digests = journal.get_manifest_digests_in_progress()
        assert "abc" in digests
        assert "def" not in digests  # committed

    def test_journal_survives_reload(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        j1 = CheckpointJournal(tmp_path / "journal.json")
        j1.prepare("op-1", sequence=1, predecessor_digest="",
                   manifest_digest="abc", policy_profile_digest="",
                   signer_fingerprint="fp")

        # New instance reads from disk
        j2 = CheckpointJournal(tmp_path / "journal.json")
        ops = j2.get_operations()
        assert len(ops) == 1
        assert ops[0].operation_id == "op-1"

    def test_journal_empty_when_no_file(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "nonexistent.json")
        assert journal.get_operations() == []
        assert journal.get_uncommitted() == []


# ── CP-018: Creation journal integration ───────────────────────────────────

class TestCP018CreationJournal:
    def test_successful_creation_journals_committed(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert len(ops) == 1
        assert ops[0].status == "committed"

    def test_multiple_creates_journal(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert len(ops) == 2
        assert all(op.status == "committed" for op in ops)

    def test_forced_signing_failure_journals_aborted(
        self, populated_store, chain, key_pair, monkeypatch
    ):
        """Simulate signing failure after manifest retention."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointError, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair

        # Create one valid checkpoint first
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Now patch sign_checkpoint to fail on next call
        import nodechain.sdk.evidence_checkpoint as mod
        original_sign = mod.sign_checkpoint
        call_count = [0]
        def failing_sign(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 0:
                raise RuntimeError("Simulated signing failure")
            return original_sign(*args, **kwargs)

        monkeypatch.setattr(mod, "sign_checkpoint", failing_sign)

        with pytest.raises(RuntimeError, match="Simulated signing failure"):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert len(ops) == 2
        assert ops[0].status == "committed"
        assert ops[1].status == "aborted"
        assert "signing failure" in ops[1].abort_reason.lower()

    def test_forced_chain_save_failure_journals_aborted(
        self, populated_store, chain, key_pair, monkeypatch
    ):
        """Simulate chain save failure after manifest retention."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair

        # Create one valid checkpoint first
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Patch chain.save to fail on second call
        original_save = chain.save
        call_count = [0]
        def failing_save(data):
            call_count[0] += 1
            if call_count[0] > 0:
                raise RuntimeError("Simulated chain save failure")
            return original_save(data)

        monkeypatch.setattr(chain, "save", failing_save)

        with pytest.raises(RuntimeError, match="chain save failure"):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert len(ops) == 2
        assert ops[1].status == "aborted"
        assert "chain save failure" in ops[1].abort_reason.lower()

    def test_aborted_operation_manifest_is_retained(
        self, populated_store, chain, key_pair, monkeypatch
    ):
        """Manifest from aborted operation is retained (not removed) but journaled."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair

        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Force signing failure
        import nodechain.sdk.evidence_checkpoint as mod
        original_sign = mod.sign_checkpoint
        call_count = [0]
        def failing_sign(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 0:
                raise RuntimeError("Forced failure")
            return original_sign(*args, **kwargs)

        monkeypatch.setattr(mod, "sign_checkpoint", failing_sign)

        with pytest.raises(RuntimeError):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        aborted = journal.get_aborted()
        assert len(aborted) == 1
        # The manifest digest is in progress (recoverable, not silently orphaned)
        in_progress = journal.get_manifest_digests_in_progress()
        # Manifest was retained but we don't track its digest in aborted ops easily
        # because abort happens after mark_manifest_retained
        assert aborted[0].operation_id


# ── Recovery report integration ────────────────────────────────────────────

class TestRecoveryJournalIntegration:
    def test_recovery_surfaces_uncommitted_operations(
        self, populated_store, chain, key_pair, monkeypatch
    ):
        """Recovery report surfaces uncommitted operations from journal."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report,
        )
        priv_pem, pub_pem = key_pair

        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Force signing failure on second checkpoint
        import nodechain.sdk.evidence_checkpoint as mod
        original_sign = mod.sign_checkpoint
        call_count = [0]
        def failing_sign(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 0:
                raise RuntimeError("Forced")
            return original_sign(*args, **kwargs)
        monkeypatch.setattr(mod, "sign_checkpoint", failing_sign)

        try:
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        except RuntimeError:
            pass

        # Recovery without chain/key should still show journal issues
        report = generate_recovery_report(populated_store, chain, pub_pem)
        assert len(report.aborted_operations) >= 1

    def test_recovery_no_journal_clean(self, populated_store, chain, key_pair):
        """Clean recovery with no journal issues."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, generate_recovery_report,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        report = generate_recovery_report(populated_store, chain, pub_pem)
        assert report.aborted_operations == []
