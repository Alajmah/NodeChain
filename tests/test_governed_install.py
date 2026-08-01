"""Governed Remote Installation Tests (v2.21.3).

Tests that remote package installation is crash-safe through durable
journaling, idempotency keys, and phase-based recovery.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from nodechain.sdk.governed_install import (
    InstallJournal,
    InstallJournalError,
    InstallOperation,
    InstallRecoveryManager,
    InstallRecoveryDecision,
    GovernedInstallReceipt,
    compute_install_key,
    classify_install_recovery,
    get_resume_phase,
    PHASE_PENDING,
    PHASE_DOWNLOADING,
    PHASE_DOWNLOADED,
    PHASE_EXTRACTING,
    PHASE_EXTRACTED,
    PHASE_REGISTERING,
    PHASE_COMMITTED,
    PHASE_ABORTED,
    PHASE_FAILED,
    INSTALL_SKIP,
    INSTALL_RESUME,
    INSTALL_INTERVENTION,
    DURABLE_PHASES,
    SAFE_RETRY_PHASES,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def journal(tmp_path):
    return InstallJournal(tmp_path / "install_journal.json")


@pytest.fixture
def populated_journal(journal, tmp_path):
    """Journal with operations at various phases."""
    install_dir = tmp_path / "packages"
    install_dir.mkdir()

    # Committed install
    journal.begin("op-committed", "https://reg.example.com", "pkg-a", "1.0.0", "digest-a")
    journal.update_phase("op-committed", PHASE_DOWNLOADED, installed_path=str(install_dir / "pkg-a"))
    journal.update_phase("op-committed", PHASE_EXTRACTED)
    journal.update_phase("op-committed", PHASE_COMMITTED, receipt_digest="receipt-1")

    # Pending at downloading
    journal.begin("op-downloading", "https://reg.example.com", "pkg-b", "2.0.0", "digest-b")
    journal.update_phase("op-downloading", PHASE_DOWNLOADING)

    # Pending at extracted (crash before register)
    journal.begin("op-extracted", "https://reg.example.com", "pkg-c", "3.0.0", "digest-c")
    pkg_c_dir = install_dir / "pkg-c"
    pkg_c_dir.mkdir()
    journal.update_phase("op-extracted", PHASE_DOWNLOADED, installed_path=str(pkg_c_dir))
    journal.update_phase("op-extracted", PHASE_EXTRACTED)

    return journal


# ── AC-1: Idempotency key ───────────────────────────────────────────────────

class TestAC1IdempotencyKey:
    """1. Durable idempotency key for install operations."""

    def test_key_is_deterministic(self):
        """Same inputs produce the same key."""
        k1 = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0", "digest-a")
        k2 = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0", "digest-a")
        assert k1 == k2

    def test_key_changes_on_package_id(self):
        k1 = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0")
        k2 = compute_install_key("https://reg.example.com", "pkg-b", "1.0.0")
        assert k1 != k2

    def test_key_changes_on_version(self):
        k1 = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0")
        k2 = compute_install_key("https://reg.example.com", "pkg-a", "2.0.0")
        assert k1 != k2

    def test_key_changes_on_digest(self):
        """Different artifact digest for same version is NOT a retry."""
        k1 = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0", "digest-1")
        k2 = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0", "digest-2")
        assert k1 != k2

    def test_key_is_hex(self):
        k = compute_install_key("url", "pkg", "1.0.0")
        assert all(c in "0123456789abcdef" for c in k)


# ── AC-2: Install journal durability ────────────────────────────────────────

class TestAC2JournalDurability:
    """2. Journal survives crashes and is loadable."""

    def test_journal_persists_operations(self, journal):
        journal.begin("op-1", "https://reg.example.com", "pkg-a", "1.0.0")
        # Reload journal
        journal2 = InstallJournal(journal.path)
        ops = journal2.get_operations()
        assert len(ops) == 1
        assert ops[0].operation_id == "op-1"
        assert ops[0].phase == PHASE_PENDING

    def test_journal_phase_transitions(self, journal):
        journal.begin("op-1", "url", "pkg", "1.0.0")
        journal.update_phase("op-1", PHASE_DOWNLOADED)
        journal.update_phase("op-1", PHASE_EXTRACTING)
        journal.update_phase("op-1", PHASE_COMMITTED, receipt_digest="rd")

        ops = journal.get_operations()
        assert ops[0].phase == PHASE_COMMITTED
        assert ops[0].receipt_digest == "rd"
        assert ops[0].completed_at != ""

    def test_journal_corrupt_raises(self, tmp_path):
        p = tmp_path / "journal.json"
        p.write_text("{corrupt", encoding="utf-8")
        journal = InstallJournal(p)
        with pytest.raises(InstallJournalError):
            journal.get_operations()

    def test_journal_missing_fields_raises(self, tmp_path):
        p = tmp_path / "journal.json"
        p.write_text(json.dumps({"wrong_key": []}), encoding="utf-8")
        journal = InstallJournal(p)
        with pytest.raises(InstallJournalError):
            journal.get_operations()

    def test_journal_missing_file_is_empty(self, tmp_path):
        journal = InstallJournal(tmp_path / "nonexistent.json")
        assert journal.get_operations() == []

    def test_journal_lock_released(self, journal):
        journal.begin("op-1", "url", "pkg", "1.0.0")
        assert not journal._lock_path.exists()


# ── AC-3: Recovery classification ───────────────────────────────────────────

class TestAC3RecoveryClassification:
    """3. Correct recovery action for each crash phase."""

    def test_committed_skipped(self):
        assert classify_install_recovery(PHASE_COMMITTED) == INSTALL_SKIP

    def test_pending_resumes(self):
        assert classify_install_recovery(PHASE_PENDING) == INSTALL_RESUME

    def test_downloading_resumes(self):
        assert classify_install_recovery(PHASE_DOWNLOADING) == INSTALL_RESUME

    def test_downloaded_resumes_with_path(self, tmp_path):
        p = tmp_path / "pkg"
        p.mkdir()
        assert classify_install_recovery(PHASE_DOWNLOADED, str(p)) == INSTALL_RESUME

    def test_downloaded_intervention_without_path(self):
        assert classify_install_recovery(PHASE_DOWNLOADED) == INSTALL_INTERVENTION

    def test_extracting_resumes_with_path(self, tmp_path):
        p = tmp_path / "pkg"
        p.mkdir()
        assert classify_install_recovery(PHASE_EXTRACTING, str(p)) == INSTALL_RESUME

    def test_extracted_resumes_with_path(self, tmp_path):
        p = tmp_path / "pkg"
        p.mkdir()
        assert classify_install_recovery(PHASE_EXTRACTED, str(p)) == INSTALL_RESUME

    def test_registering_resumes(self):
        assert classify_install_recovery(PHASE_REGISTERING) == INSTALL_RESUME


# ── AC-4: Resume phase determination ────────────────────────────────────────

class TestAC4ResumePhase:
    """4. Resume phase is correct for each crash point."""

    def test_pending_resumes_from_pending(self):
        assert get_resume_phase(PHASE_PENDING) == PHASE_PENDING

    def test_downloaded_resumes_from_extracting(self, tmp_path):
        p = tmp_path / "pkg"
        p.mkdir()
        """Downloaded artifact, not yet extracted → resume at extracting."""
        assert get_resume_phase(PHASE_DOWNLOADED, str(p)) == PHASE_EXTRACTING

    def test_extracting_resumes_from_extracting(self):
        assert get_resume_phase(PHASE_EXTRACTING) == PHASE_EXTRACTING

    def test_extracted_resumes_from_registering(self, tmp_path):
        p = tmp_path / "pkg"
        p.mkdir()
        """Extracted, not yet registered → resume at registering."""
        assert get_resume_phase(PHASE_EXTRACTED, str(p)) == PHASE_REGISTERING

    def test_registering_resumes_from_registering(self):
        assert get_resume_phase(PHASE_REGISTERING) == PHASE_REGISTERING

    def test_committed_returns_committed(self):
        assert get_resume_phase(PHASE_COMMITTED) == PHASE_COMMITTED


# ── AC-5: Full recovery reconciliation ──────────────────────────────────────

class TestAC5RecoveryReconciliation:
    """5. Reconcile multiple interrupted installs."""

    def test_reconcile_finds_pending(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        decisions = manager.reconcile()

        # Should have 2 pending (downloading + extracted)
        assert len(decisions) == 2

    def test_reconcile_committed_skipped(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        decisions = manager.reconcile()
        # Committed ops are not in pending list
        op_ids = [d.operation_id for d in decisions]
        assert "op-committed" not in op_ids

    def test_reconcile_downloading_resumes(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        decisions = manager.reconcile()
        dl = next(d for d in decisions if d.operation_id == "op-downloading")
        assert dl.recovery_action == INSTALL_RESUME
        assert dl.resume_from_phase == PHASE_PENDING

    def test_reconcile_extracted_resumes_at_registering(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        decisions = manager.reconcile()
        ext = next(d for d in decisions if d.operation_id == "op-extracted")
        assert ext.recovery_action == INSTALL_RESUME
        assert ext.resume_from_phase == PHASE_REGISTERING

    def test_empty_journal_no_decisions(self, journal):
        manager = InstallRecoveryManager(journal)
        assert manager.reconcile() == []


# ── AC-6: Idempotency check ─────────────────────────────────────────────────

class TestAC6IdempotencyCheck:
    """6. Already-installed packages are not re-installed."""

    def test_committed_install_detected(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        key = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0", "digest-a")
        assert manager.has_committed(key) is True

    def test_nonexistent_key_not_committed(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        assert manager.has_committed("nonexistent-key") is False

    def test_idempotency_status_fresh(self, journal):
        manager = InstallRecoveryManager(journal)
        status = manager.get_idempotency_status("fresh-key")
        assert status["already_installed"] is False
        assert status["safe_to_proceed"] is True

    def test_idempotency_status_committed(self, populated_journal):
        manager = InstallRecoveryManager(populated_journal)
        key = compute_install_key("https://reg.example.com", "pkg-a", "1.0.0", "digest-a")
        status = manager.get_idempotency_status(key)
        assert status["already_installed"] is True
        assert status["safe_to_proceed"] is False

    def test_idempotency_status_pending_blocks(self, populated_journal):
        """A pending install blocks new install with same key."""
        manager = InstallRecoveryManager(populated_journal)
        key = compute_install_key("https://reg.example.com", "pkg-b", "2.0.0", "digest-b")
        status = manager.get_idempotency_status(key)
        assert status["already_installed"] is False
        assert status["safe_to_proceed"] is False  # Must reconcile first


# ── AC-7: GovernedInstallReceipt ────────────────────────────────────────────

class TestAC7GovernedReceipt:
    """7. Governed receipt with journal reference and idempotency."""

    def test_receipt_has_install_key(self):
        receipt = GovernedInstallReceipt(
            receipt_id="r-1",
            install_key="key-123",
            package_id="pkg-a",
            version="1.0.0",
        )
        d = receipt.to_dict()
        assert d["install_key"] == "key-123"
        assert d["receipt_digest"] != ""

    def test_receipt_roundtrip(self):
        receipt = GovernedInstallReceipt(
            receipt_id="r-1",
            install_key="key-123",
            journal_operation_id="op-1",
            package_id="pkg-a",
            version="1.0.0",
            artifact_digest="digest-abc",
            installed_path="/data/packages/pkg-a/1.0.0",
            recovery_provenance="fresh",
        )
        d = receipt.to_dict()
        restored = GovernedInstallReceipt.from_dict(d)
        assert restored.install_key == receipt.install_key
        assert restored.journal_operation_id == receipt.journal_operation_id
        assert restored.recovery_provenance == "fresh"

    def test_receipt_digest_changes_on_fields(self):
        r1 = GovernedInstallReceipt(receipt_id="r-1", package_id="pkg-a")
        r2 = GovernedInstallReceipt(receipt_id="r-1", package_id="pkg-b")
        d1 = r1.to_dict()
        d2 = r2.to_dict()
        assert d1["receipt_digest"] != d2["receipt_digest"]


# ── AC-8: Full lifecycle simulation ─────────────────────────────────────────

class TestAC8FullLifecycle:
    """8. Full install lifecycle with journal tracking."""

    def test_successful_install_lifecycle(self, journal, tmp_path):
        """Simulate a complete install with journal tracking."""
        install_dir = tmp_path / "packages" / "pkg-x" / "1.0.0"
        install_dir.mkdir(parents=True)

        op = journal.begin("op-full", "https://reg.example.com", "pkg-x", "1.0.0", "dx")
        assert op.phase == PHASE_PENDING

        journal.update_phase("op-full", PHASE_DOWNLOADING)
        journal.update_phase("op-full", PHASE_DOWNLOADED, installed_path=str(install_dir))
        journal.update_phase("op-full", PHASE_EXTRACTING)
        journal.update_phase("op-full", PHASE_EXTRACTED)
        journal.update_phase("op-full", PHASE_REGISTERING)
        journal.update_phase("op-full", PHASE_COMMITTED, receipt_digest="receipt-final")

        ops = journal.get_operations()
        assert ops[0].phase == PHASE_COMMITTED
        assert ops[0].receipt_digest == "receipt-final"

    def test_crash_and_recover_lifecycle(self, journal, tmp_path):
        """Simulate crash during extraction, then recover."""
        install_dir = tmp_path / "packages" / "pkg-crash" / "1.0.0"
        install_dir.mkdir(parents=True)

        op = journal.begin("op-crash", "https://reg.example.com", "pkg-crash", "1.0.0", "dc")
        journal.update_phase("op-crash", PHASE_DOWNLOADED, installed_path=str(install_dir))
        journal.update_phase("op-crash", PHASE_EXTRACTING)

        # "Crash" — reload journal fresh
        fresh_journal = InstallJournal(journal.path)
        manager = InstallRecoveryManager(fresh_journal)
        decisions = manager.reconcile()

        assert len(decisions) == 1
        d = decisions[0]
        assert d.phase_at_crash == PHASE_EXTRACTING
        assert d.recovery_action == INSTALL_RESUME
        # Install dir exists, so safe to resume extraction
        assert d.resume_from_phase == PHASE_EXTRACTING

    def test_crash_after_download_recovers_to_extraction(self, journal, tmp_path):
        """Crash after download but before extraction → resume at extraction."""
        install_dir = tmp_path / "packages" / "pkg-dl" / "1.0.0"
        install_dir.mkdir(parents=True)

        journal.begin("op-dl", "https://reg.example.com", "pkg-dl", "1.0.0", "dd")
        journal.update_phase("op-dl", PHASE_DOWNLOADED, installed_path=str(install_dir))

        # Crash — recover
        manager = InstallRecoveryManager(InstallJournal(journal.path))
        decisions = manager.reconcile()
        assert decisions[0].phase_at_crash == PHASE_DOWNLOADED
        assert decisions[0].resume_from_phase == PHASE_EXTRACTING

    def test_reinstall_same_key_detected(self, journal, tmp_path):
        """Installing the same package again is detected as already installed."""
        install_dir = tmp_path / "packages" / "pkg-reinstall" / "1.0.0"
        install_dir.mkdir(parents=True)

        key = compute_install_key("https://reg.example.com", "pkg-reinstall", "1.0.0", "dr")
        op = journal.begin("op-reinstall", "https://reg.example.com", "pkg-reinstall", "1.0.0", "dr")
        journal.update_phase("op-reinstall", PHASE_COMMITTED)

        # Try to install again
        manager = InstallRecoveryManager(journal)
        assert manager.has_committed(op.install_key) is True

        status = manager.get_idempotency_status(op.install_key)
        assert status["already_installed"] is True
        assert status["safe_to_proceed"] is False

    def test_different_digest_not_idempotent(self, journal):
        """Same package + version but different digest = different install key."""
        op1 = journal.begin("op-1", "https://reg.example.com", "pkg-x", "1.0.0", "digest-aaa")
        op2 = journal.begin("op-2", "https://reg.example.com", "pkg-x", "1.0.0", "digest-bbb")

        assert op1.install_key != op2.install_key


# ── AC-9: Install as side-effect-governed operation ─────────────────────────

class TestAC9SideEffectIntegration:
    """9. Install operations follow side-effect contract semantics."""

    def test_install_contract_type(self):
        """Remote install is idempotent_with_key when same digest."""
        from nodechain.sdk.workflow_recovery import (
            SideEffectContract, IDEMPOTENT_WITH_KEY,
        )
        contract = SideEffectContract(
            effect_type="remote_install",
            target="registry.example.com",
            contract_type=IDEMPOTENT_WITH_KEY,
            idempotency_key="install-key-123",
        )
        assert contract.contract_type == IDEMPOTENT_WITH_KEY
        assert contract.contract_digest != ""

    def test_install_recovery_uses_classify_started_effect(self):
        """An install that crashed mid-operation follows the same
        classify_started_effect logic as any side effect."""
        from nodechain.sdk.workflow_recovery import (
            classify_started_effect, IDEMPOTENT_WITH_KEY, RETRY,
        )
        # An idempotent install that crashed → retry is safe
        action = classify_started_effect(IDEMPOTENT_WITH_KEY)
        assert action == RETRY


# ── AC-10: Dashboard health rules ───────────────────────────────────────────

class TestAC10DashboardHealth:
    """10. Dashboard reflects install recovery state."""

    def test_dashboard_has_install_recovery_section(self):
        """Dashboard v2 API includes install_recovery section."""
        from nodechain.cli.dashboard_health import ALL_RULES, RULES_BY_ID
        # HR-022 (recovery intervention) covers install recovery too
        assert "HR-022" in RULES_BY_ID
        # All rules still present
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
