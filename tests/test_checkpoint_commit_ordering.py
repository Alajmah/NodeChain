"""Checkpoint Journal Commit Ordering Tests (v2.21.3).

CP-022: Checkpoint identity persisted before chain save.
CP-023: Store-aware reconciliation.
CP-024: Aborted manifests excluded from snapshots.
CP-025: Journal locking.
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


# ── CP-022: Checkpoint identity before chain save ──────────────────────────

class TestCP022CheckpointIdentityBeforeChainSave:
    def test_checkpoint_prepared_state_before_chain_save(
        self, populated_store, chain, key_pair, monkeypatch
    ):
        """Simulate crash after mark_checkpoint_prepared, before chain.save."""
        from nodechain.sdk.evidence_checkpoint import create_checkpoint, CheckpointJournal
        import nodechain.sdk.evidence_checkpoint as mod
        priv_pem, pub_pem = key_pair

        # Patch chain.save to fail after checkpoint_prepared is recorded
        original_save = chain.save
        call_count = [0]
        def failing_save(data):
            call_count[0] += 1
            raise RuntimeError("Simulated crash before chain save")

        monkeypatch.setattr(chain, "save", failing_save)

        with pytest.raises(RuntimeError):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Journal should have checkpoint_prepared state with identity recorded
        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert ops[0].status == "aborted"  # caught by except handler
        # But checkpoint_id and checkpoint_digest should have been recorded
        assert ops[0].checkpoint_id != ""
        assert ops[0].checkpoint_digest != ""

    def test_reconcile_checkpoint_prepared_in_chain(self, tmp_path, chain, key_pair):
        """checkpoint_prepared + matching chain checkpoint → committed."""
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, create_checkpoint,
        )
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Create a real checkpoint
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

        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        cp = create_checkpoint(store, chain, priv_pem, pub_pem)

        # Manually create a checkpoint_prepared operation matching the checkpoint
        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        journal.prepare(
            "manual-op", sequence=1, predecessor_digest="",
            manifest_digest=cp.manifest_digest, policy_profile_digest="",
            signer_fingerprint=cp.signer_fingerprint,
        )
        journal.mark_checkpoint_prepared("manual-op", cp.checkpoint_id, cp.checkpoint_digest)

        # Reconcile should mark it committed
        needs = journal.reconcile(chain)
        assert needs == []
        ops = journal.get_operations()
        manual_ops = [o for o in ops if o.operation_id == "manual-op"]
        assert manual_ops[0].status == "committed"

    def test_reconcile_checkpoint_prepared_not_in_chain(self, tmp_path, chain):
        """checkpoint_prepared + NOT in chain → aborted."""
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        journal.mark_checkpoint_prepared("op-1", "cp-fake", "digest-fake")

        needs = journal.reconcile(chain)
        assert needs == []
        ops = journal.get_operations()
        assert ops[0].status == "aborted"


# ── CP-023: Store-aware reconciliation ─────────────────────────────────────

class TestCP023StoreAwareReconciliation:
    def test_reconcile_prepared_with_manifest_in_store(self, tmp_path, store):
        """prepared + manifest exists in store → needs intervention."""
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        # Retain an artifact
        artifact = store.retain(b"test-manifest")
        digest = artifact.digest

        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest=digest, policy_profile_digest="",
            signer_fingerprint="fp",
        )

        needs = journal.reconcile(chain=None, store=store)
        assert len(needs) == 1
        assert needs[0].operation_id == "op-1"

    def test_reconcile_prepared_without_manifest_safe_abort(self, tmp_path, store):
        """prepared + manifest absent from store → safe to abort."""
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, JOURNAL_ABORTED,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="nonexistent_digest", policy_profile_digest="",
            signer_fingerprint="fp",
        )

        needs = journal.reconcile(chain=None, store=store)
        assert needs == []
        ops = journal.get_operations()
        assert ops[0].status == JOURNAL_ABORTED

    def test_reconcile_without_store_assumes_prepared_safe(self, tmp_path):
        """prepared + no store → safe to abort (backwards-compat)."""
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, JOURNAL_ABORTED,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc", policy_profile_digest="",
            signer_fingerprint="fp",
        )

        needs = journal.reconcile()
        assert needs == []


# ── CP-024: Aborted manifests excluded from snapshots ──────────────────────

class TestCP024AbortedManifestExclusion:
    def test_aborted_manifest_digests_excluded(self, populated_store, chain, key_pair, monkeypatch):
        """An aborted checkpoint's manifest should not appear in later snapshots."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        import nodechain.sdk.evidence_checkpoint as mod
        priv_pem, pub_pem = key_pair

        # Force signing failure on first checkpoint to create aborted manifest
        original_sign = mod.sign_checkpoint
        call_count = [0]
        def failing_sign(*args, **kwargs):
            call_count[0] += 1
            raise RuntimeError("Forced signing failure")
        monkeypatch.setattr(mod, "sign_checkpoint", failing_sign)

        with pytest.raises(RuntimeError):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Restore
        monkeypatch.undo()

        # Get the aborted manifest digest
        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        aborted_digests = journal.get_aborted_manifest_digests()
        assert len(aborted_digests) == 1
        aborted_manifest = list(aborted_digests)[0]

        # Create a successful checkpoint — should NOT include the aborted manifest
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # The successful checkpoint's manifest should not include the aborted digest
        from nodechain.sdk.artifact_retention import RetentionManifest
        manifest_path = populated_store._artifact_path(cp.manifest_digest)
        manifest_data = json.loads(manifest_path.read_bytes())
        manifest = RetentionManifest.from_dict(manifest_data)
        assert aborted_manifest not in manifest.artifact_digests


# ── CP-025: Journal locking ────────────────────────────────────────────────

class TestCP025JournalLocking:
    def test_journal_has_lock_file(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        assert hasattr(journal, '_lock_path')
        assert str(journal._lock_path) == str(tmp_path / "journal.json.lock")

    def test_journal_operations_under_lock(self, tmp_path):
        """All mutation operations acquire and release the lock."""
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")

        # Multiple operations should work fine sequentially
        journal.prepare("op-1", sequence=1, predecessor_digest="",
                       manifest_digest="abc", policy_profile_digest="",
                       signer_fingerprint="fp")
        journal.mark_manifest_retained("op-1", "abc")
        journal.mark_checkpoint_prepared("op-1", "cp-1", "digest-1")
        journal.mark_chain_committed("op-1", "cp-1", "digest-1")
        journal.mark_committed("op-1")

        # Lock should be released
        assert not journal._lock_path.exists()

    def test_journal_lock_released_on_error(self, tmp_path):
        """Lock is released even when operation raises."""
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare("op-1", sequence=1, predecessor_digest="",
                       manifest_digest="abc", policy_profile_digest="",
                       signer_fingerprint="fp")

        try:
            journal.mark_manifest_retained("op-1", "wrong")
        except CheckpointError:
            pass

        assert not journal._lock_path.exists()


# ── Full lifecycle with new states ────────────────────────────────────────

class TestFullLifecycle:
    def test_successful_creation_uses_all_states(self, populated_store, chain, key_pair):
        """Verify the state sequence: prepared → manifest_retained → checkpoint_prepared → chain_committed → committed."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert len(ops) == 1
        assert ops[0].status == "committed"
        assert ops[0].checkpoint_id == cp.checkpoint_id
        assert ops[0].checkpoint_digest == cp.checkpoint_digest
        assert ops[0].manifest_digest == cp.manifest_digest

    def test_reconcile_after_crash_window_all_committed(self, populated_store, chain, key_pair):
        """Normal reconcile on fully committed journal = no issues."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        needs = journal.reconcile(chain, populated_store)
        assert needs == []
