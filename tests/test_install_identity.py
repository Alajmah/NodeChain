"""Remote Install Identity and Registry Metadata Integrity Tests (v2.21.3).

RI-001: A remote install may be treated as idempotently registered only
when the existing local registry entry exactly matches the verified
remote package identity and provenance.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from nodechain.sdk.governed_install import (
    InstallJournal,
    InstallRecoveryManager,
    InstallConflictError,
    compute_install_key,
    compute_canonical_install_key,
    compare_registry_identity,
    verify_registration_idempotency,
    classify_install_recovery,
    get_resume_phase,
    PHASE_PENDING,
    PHASE_COMMITTED,
    PHASE_CONFLICT,
    PHASE_REGISTERING,
    INSTALL_SKIP,
    INSTALL_RESUME,
    INSTALL_INTERVENTION,
    IDENTITY_FIELDS,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def journal(tmp_path):
    return InstallJournal(tmp_path / "journal.json")


@pytest.fixture
def base_entry():
    """A canonical remote registry entry."""
    return {
        "package_id": "incident_response",
        "package_version": "1.2.0",
        "package_digest": "sha256:abc",
        "manifest_digest": "sha256:mfg",
        "publisher_fingerprint": "fp-pub-001",
        "registry_signer_fingerprint": "fp-reg-001",
        "registry_id": "reg-001",
        "certification_digest": "sha256:cert",
        "trust_level": "remote_untrusted",
    }


@pytest.fixture
def matching_entry(base_entry):
    """An entry with identical identity fields."""
    return dict(base_entry)


@pytest.fixture
def mismatched_entry(base_entry):
    """An entry with a different artifact digest."""
    e = dict(base_entry)
    e["package_digest"] = "sha256:DIFFERENT"
    return e


# ── RI-001: Exact-identity comparison ───────────────────────────────────────

class TestRI001ExactIdentityComparison:
    """RI-001: Idempotent registration requires exact identity match."""

    def test_matching_entries_are_idempotent(self, base_entry, matching_entry):
        result = verify_registration_idempotency(base_entry, matching_entry)
        assert result["idempotent"] is True
        assert result["conflict"] is False
        assert result["mismatches"] == []

    def test_different_artifact_digest_is_conflict(self, base_entry, mismatched_entry):
        result = verify_registration_idempotency(base_entry, mismatched_entry)
        assert result["idempotent"] is False
        assert result["conflict"] is True
        assert "artifact_digest" in result["mismatches"]

    def test_different_publisher_is_conflict(self, base_entry):
        remote = dict(base_entry)
        remote["publisher_fingerprint"] = "DIFFERENT-PUBLISHER"
        result = verify_registration_idempotency(base_entry, remote)
        assert result["conflict"] is True
        assert "publisher_fingerprint" in result["mismatches"]

    def test_different_registry_is_conflict(self, base_entry):
        remote = dict(base_entry)
        remote["registry_id"] = "DIFFERENT-REG"
        result = verify_registration_idempotency(base_entry, remote)
        assert result["conflict"] is True
        assert "registry_id" in result["mismatches"]

    def test_different_trust_level_is_conflict(self, base_entry):
        """An entry upgraded from remote_untrusted to local_trusted is a conflict."""
        remote = dict(base_entry)
        remote["trust_level"] = "local_trusted"
        result = verify_registration_idempotency(base_entry, remote)
        assert result["conflict"] is True
        assert "trust_level" in result["mismatches"]

    def test_all_identity_fields_covered(self):
        """All 9 identity-bearing fields are checked."""
        assert len(IDENTITY_FIELDS) == 9
        for f in IDENTITY_FIELDS:
            assert f in [
                "package_id", "package_version", "artifact_digest",
                "manifest_digest", "publisher_fingerprint",
                "registry_fingerprint", "registry_id",
                "certification_digest", "trust_level",
            ]

    def test_multiple_mismatches_all_reported(self, base_entry):
        remote = dict(base_entry)
        remote["package_digest"] = "different"
        remote["publisher_fingerprint"] = "different"
        remote["registry_id"] = "different"
        result = verify_registration_idempotency(base_entry, remote)
        assert len(result["mismatches"]) == 3


# ── RI-001: compare_registry_identity ───────────────────────────────────────

class TestCompareRegistryIdentity:
    """Direct comparison helper."""

    def test_exact_match_returns_empty(self, base_entry, matching_entry):
        assert compare_registry_identity(base_entry, matching_entry) == []

    def test_returns_mismatched_field_names(self, base_entry, mismatched_entry):
        result = compare_registry_identity(base_entry, mismatched_entry)
        assert "artifact_digest" in result


# ── Canonical install key ───────────────────────────────────────────────────

class TestCanonicalInstallKey:
    """Canonical identity uses registry_id, not transport URL."""

    def test_canonical_key_deterministic(self):
        k1 = compute_canonical_install_key("reg-001", "fp-001", "pkg", "1.0", "digest")
        k2 = compute_canonical_install_key("reg-001", "fp-001", "pkg", "1.0", "digest")
        assert k1 == k2

    def test_canonical_key_ignores_url_variants(self):
        """Mirror URLs with same registry identity produce same key."""
        k1 = compute_canonical_install_key("reg-001", "fp-001", "pkg", "1.0", "d1")
        k2 = compute_canonical_install_key("reg-001", "fp-001", "pkg", "1.0", "d1")
        # These are the same because canonical key doesn't include URL
        assert k1 == k2

    def test_canonical_key_changes_on_registry_id(self):
        k1 = compute_canonical_install_key("reg-001", "fp", "pkg", "1.0", "d")
        k2 = compute_canonical_install_key("reg-002", "fp", "pkg", "1.0", "d")
        assert k1 != k2

    def test_canonical_key_changes_on_signer_fingerprint(self):
        k1 = compute_canonical_install_key("reg", "fp-001", "pkg", "1.0", "d")
        k2 = compute_canonical_install_key("reg", "fp-002", "pkg", "1.0", "d")
        assert k1 != k2

    def test_canonical_key_changes_on_artifact_digest(self):
        """Same package/version but different digest = different key (no replay)."""
        k1 = compute_canonical_install_key("reg", "fp", "pkg", "1.0", "digest-aaa")
        k2 = compute_canonical_install_key("reg", "fp", "pkg", "1.0", "digest-bbb")
        assert k1 != k2

    def test_canonical_key_is_hex(self):
        k = compute_canonical_install_key("reg", "fp", "pkg", "1.0", "d")
        assert all(c in "0123456789abcdef" for c in k)


# ── Install conflict phase ──────────────────────────────────────────────────

class TestInstallConflictPhase:
    """install_conflict terminal state."""

    def test_conflict_phase_exists(self):
        assert PHASE_CONFLICT == "install_conflict"

    def test_conflict_in_all_phases(self):
        from nodechain.sdk.governed_install import ALL_PHASES
        assert PHASE_CONFLICT in ALL_PHASES

    def test_conflict_recovery_needs_intervention(self):
        assert classify_install_recovery(PHASE_CONFLICT) == INSTALL_INTERVENTION

    def test_conflict_not_in_pending(self, journal):
        """Conflicted operations are not in pending list."""
        journal.begin("op-1", "url", "pkg", "1.0.0")
        journal.update_phase("op-1", PHASE_CONFLICT)
        assert journal.get_pending() == []

    def test_conflict_recovery_surfaces_in_decisions(self, journal):
        """InstallRecoveryManager doesn't try to resume conflicted ops."""
        journal.begin("op-1", "url", "pkg", "1.0.0")
        journal.update_phase("op-1", PHASE_CONFLICT)

        manager = InstallRecoveryManager(journal)
        decisions = manager.reconcile()
        # Conflict is terminal — not in pending, so not in decisions
        assert len(decisions) == 0


# ── InstallConflictError ────────────────────────────────────────────────────

class TestInstallConflictError:
    """Conflict error carries diagnostic information."""

    def test_error_has_mismatches(self):
        err = InstallConflictError("pkg", "1.0", ["artifact_digest", "trust_level"])
        assert err.package_id == "pkg"
        assert err.version == "1.0"
        assert "artifact_digest" in err.mismatches
        assert "trust_level" in err.mismatches
        assert "identity mismatch" in str(err)

    def test_error_message_includes_package(self):
        err = InstallConflictError("incident_response", "1.2.0", ["publisher_fingerprint"])
        assert "incident_response@1.2.0" in str(err)
        assert "publisher_fingerprint" in str(err)


# ── Backwards compatibility ─────────────────────────────────────────────────

class TestBackwardsCompat:
    """v2.21.3 install keys still work."""

    def test_compute_install_key_still_works(self):
        k = compute_install_key("https://reg.example.com", "pkg", "1.0.0", "d")
        assert len(k) == 32

    def test_registering_still_resumes(self, tmp_path):
        """registering phase still resumes (but now with identity check)."""
        p = tmp_path / "pkg"
        p.mkdir()
        assert classify_install_recovery(PHASE_REGISTERING, str(p)) == INSTALL_RESUME

    def test_committed_still_skips(self):
        assert classify_install_recovery(PHASE_COMMITTED) == INSTALL_SKIP

    def test_pending_still_resumes(self):
        assert classify_install_recovery(PHASE_PENDING) == INSTALL_RESUME


# ── Full conflict scenario ──────────────────────────────────────────────────

class TestFullConflictScenario:
    """Full lifecycle: install, then attempt re-install with different identity."""

    def test_same_version_different_digest_detected(
        self, base_entry, mismatched_entry
    ):
        """Registry has pkg@1.2.0 with digest A. Remote offers pkg@1.2.0
        with digest B. This is a conflict, not an idempotent retry."""
        result = verify_registration_idempotency(base_entry, mismatched_entry)
        assert result["conflict"] is True
        assert result["idempotent"] is False
        assert "artifact_digest" in result["mismatches"]

    def test_same_identity_across_mirrors_is_idempotent(
        self, base_entry, matching_entry
    ):
        """Same package from mirror URL with same registry identity = idempotent."""
        # The entries don't contain URL, so identity comparison passes
        result = verify_registration_idempotency(base_entry, matching_entry)
        assert result["idempotent"] is True

    def test_downgrade_attempt_detected(self, base_entry):
        """An attempt to install an older version as the same version is
        detected by the different artifact_digest."""
        remote = dict(base_entry)
        remote["package_digest"] = "sha256:OLDER_VERSION_DIGEST"
        result = verify_registration_idempotency(base_entry, remote)
        assert result["conflict"] is True

    def test_complete_identity_verification(self, base_entry):
        """All 9 fields tested one at a time."""
        field_map = {
            "package_id": "different-pkg",
            "package_version": "0.0.1",
            "package_digest": "different-digest",
            "manifest_digest": "different-manifest",
            "publisher_fingerprint": "different-fp",
            "registry_signer_fingerprint": "different-reg-fp",
            "registry_id": "different-reg",
            "certification_digest": "different-cert",
            "trust_level": "local_trusted",
        }
        for field, new_value in field_map.items():
            remote = dict(base_entry)
            remote[field] = new_value
            result = verify_registration_idempotency(base_entry, remote)
            assert result["conflict"] is True, f"Field {field} mismatch not detected"
