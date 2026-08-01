"""Checkpoint Journal Integrity Tests (v2.21.3).

CP-019: Journal records actual manifest digest.
CP-020: Corrupt journal fails closed.
CP-021: Crash reconciliation implemented.
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


# ── CP-019: Manifest digest binding ────────────────────────────────────────

class TestCP019ManifestDigestBinding:
    def test_prepare_records_expected_manifest_digest(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        op = journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc123", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        assert op.manifest_digest == "abc123"

    def test_mark_manifest_retained_records_actual_digest(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc123", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        journal.mark_manifest_retained("op-1", manifest_digest="abc123")
        ops = journal.get_operations()
        assert ops[0].manifest_digest == "abc123"

    def test_mark_manifest_retained_rejects_mismatch(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc123", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        with pytest.raises(CheckpointError, match="digest mismatch"):
            journal.mark_manifest_retained("op-1", manifest_digest="wrong")

    def test_creation_journal_has_manifest_digest(self, populated_store, chain, key_pair):
        """Journal operation has the actual manifest digest after creation."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair
        cp = create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        ops = journal.get_operations()
        assert ops[0].manifest_digest == cp.manifest_digest
        assert ops[0].manifest_digest != ""


# ── CP-020: Corrupt journal fails closed ───────────────────────────────────

class TestCP020CorruptJournal:
    def test_missing_journal_is_empty(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "nonexistent.json")
        assert journal.get_operations() == []

    def test_corrupt_json_raises(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal_path = tmp_path / "journal.json"
        journal_path.write_text("not valid json {{{")
        journal = CheckpointJournal(journal_path)
        with pytest.raises(CheckpointError, match="corrupt"):
            journal.get_operations()

    def test_missing_schema_version_raises(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal_path = tmp_path / "journal.json"
        journal_path.write_text(json.dumps({"operations": []}))
        journal = CheckpointJournal(journal_path)
        with pytest.raises(CheckpointError, match="schema_version"):
            journal.get_operations()

    def test_missing_operations_raises(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal_path = tmp_path / "journal.json"
        journal_path.write_text(json.dumps({"schema_version": "1.0.0"}))
        journal = CheckpointJournal(journal_path)
        with pytest.raises(CheckpointError, match="operations"):
            journal.get_operations()

    def test_corrupt_operations_field_raises(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal_path = tmp_path / "journal.json"
        journal_path.write_text(json.dumps({
            "schema_version": "1.0.0",
            "operations": "not_a_list",
        }))
        journal = CheckpointJournal(journal_path)
        with pytest.raises(CheckpointError, match="not a list"):
            journal.get_operations()

    def test_operation_missing_required_field_raises(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointError,
        )
        journal_path = tmp_path / "journal.json"
        journal_path.write_text(json.dumps({
            "schema_version": "1.0.0",
            "operations": [{"sequence": 1}],  # missing operation_id, status
        }))
        journal = CheckpointJournal(journal_path)
        with pytest.raises(CheckpointError, match="required field"):
            journal.get_operations()


# ── CP-021: Crash reconciliation ───────────────────────────────────────────

class TestCP021CrashReconciliation:
    def test_reconcile_empty_journal(self, tmp_path, chain):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        assert journal.reconcile(chain) == []

    def test_reconcile_all_committed(self, populated_store, chain, key_pair):
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        needs = journal.reconcile(chain)
        assert needs == []

    def test_reconcile_chain_committed_after_crash(self, tmp_path, chain):
        """chain_committed operation is reconciled to committed."""
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, JOURNAL_CHAIN_COMMITTED, JOURNAL_COMMITTED,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        journal.mark_manifest_retained("op-1", "abc")
        journal.mark_chain_committed("op-1", "cp-1", "digest-1")

        # Simulate crash: chain_committed but never fully committed
        needs = journal.reconcile(chain)  # chain doesn't have "digest-1" but chain_committed auto-resolves
        assert needs == []

        ops = journal.get_operations()
        assert ops[0].status == JOURNAL_COMMITTED

    def test_reconcile_prepared_aborts_safely(self, tmp_path, chain):
        """prepared operation with no manifest retention is safely aborted."""
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, JOURNAL_ABORTED,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="", policy_profile_digest="",
            signer_fingerprint="fp",
        )

        needs = journal.reconcile(chain)
        assert needs == []

        ops = journal.get_operations()
        assert ops[0].status == JOURNAL_ABORTED

    def test_reconcile_manifest_retained_without_chain_needs_intervention(
        self, tmp_path, chain
    ):
        """manifest_retained without matching chain checkpoint needs intervention."""
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        journal.mark_manifest_retained("op-1", "abc")

        # Chain doesn't contain the checkpoint
        needs = journal.reconcile(chain)
        assert len(needs) == 1
        assert needs[0].operation_id == "op-1"

    def test_get_aborted_manifest_digests(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import CheckpointJournal
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=1, predecessor_digest="",
            manifest_digest="abc", policy_profile_digest="",
            signer_fingerprint="fp",
        )
        journal.mark_aborted("op-1", "test failure")

        digests = journal.get_aborted_manifest_digests()
        assert "abc" in digests

    def test_chain_committed_state_exists(self, populated_store, chain, key_pair, monkeypatch):
        """Verify chain_committed intermediate state is used."""
        from nodechain.sdk.evidence_checkpoint import (
            create_checkpoint, CheckpointJournal,
        )
        import nodechain.sdk.evidence_checkpoint as mod
        priv_pem, pub_pem = key_pair

        # Patch mark_committed to fail so we see chain_committed state
        original_mark_committed = mod.CheckpointJournal.mark_committed
        def fail_mark_committed(self, op_id):
            raise RuntimeError("Simulated crash after chain save")

        monkeypatch.setattr(mod.CheckpointJournal, "mark_committed", fail_mark_committed)

        with pytest.raises(RuntimeError):
            create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        # Restore and check journal
        journal_path = str(chain.chain_path) + ".journal"
        journal = mod.CheckpointJournal(journal_path)
        ops = journal.get_operations()
        assert ops[0].status == "chain_committed"
        assert ops[0].checkpoint_id != ""
        assert ops[0].checkpoint_digest != ""

        # Reconcile should fix it
        monkeypatch.undo()
        needs = journal.reconcile(chain)
        assert needs == []
        ops = journal.get_operations()
        assert ops[0].status == "committed"


# ── Operation model roundtrip ─────────────────────────────────────────────

class TestOperationRoundtrip:
    def test_operation_with_checkpoint_fields_roundtrip(self, tmp_path):
        from nodechain.sdk.evidence_checkpoint import (
            CheckpointJournal, CheckpointOperation,
        )
        journal = CheckpointJournal(tmp_path / "journal.json")
        journal.prepare(
            "op-1", sequence=5, predecessor_digest="prev",
            manifest_digest="manifest", policy_profile_digest="profile",
            signer_fingerprint="fp",
        )
        journal.mark_manifest_retained("op-1", "manifest")
        journal.mark_chain_committed("op-1", "cp-id", "cp-digest")

        # Reload
        journal2 = CheckpointJournal(tmp_path / "journal.json")
        ops = journal2.get_operations()
        assert ops[0].checkpoint_id == "cp-id"
        assert ops[0].checkpoint_digest == "cp-digest"
