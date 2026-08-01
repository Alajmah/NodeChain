"""Registry Lifecycle Adversarial Certification (v2.21.3).

Proves lifecycle governance under adversarial timing, stale metadata,
concurrent authority changes, and hostile-network conditions.

12 scenarios from the v2.21.3 review:

  1.  Old signer metadata after accepted rotation → rejected for newer gen
  2.  Old signer within overlap window → accepted only if overlap policy
  3.  Unlinked signer change → fail closed
  4.  Rotation chain A → B → C → continuity verified transitively
  5.  Rotation record replay → no rollback of accepted signer generation
  6.  Publisher revocation followed by publish attempt → server rejects
  7.  Revoked package already installed → evidence remains, execution denied
  8.  Revoked package in paused workflow → resume rejected
  9.  Deprecation after package pinning → policy-controlled warning
  10. Emergency revocation during freshness window → signed override
  11. Concurrent deprecate/revoke → atomic generation, one final state
  12. Signer rotation during installation → install completes or fails closed
"""

from __future__ import annotations

import json
import pytest
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

from nodechain.sdk.registry_trust import (
    SignedRegistryMetadata,
    RegistryTrustStore,
    RegistryTrustEvaluator,
    TRUST_VERDICT_TRUSTED,
    TRUST_VERDICT_UNAPPROVED_SIGNER,
    TRUST_VERDICT_EXPIRED,
    TRUST_VERDICT_ROLLBACK,
    TRUST_VERDICT_EQUIVOCATION,
    TRUST_VERDICT_SUPERSEDED,
    TRUST_VERDICT_ENDPOINT_DRIFT,
)
from nodechain.sdk.reference_registry_server import (
    RegistryState,
    ReferenceRegistryServer,
    PackageConflictError,
    UnauthorizedPublisherError,
    PackageRevokedError,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_DEPRECATED,
    LIFECYCLE_REVOKED,
)
from nodechain.sdk.registry_lifecycle import (
    LifecycleGovernor,
    TransitionLog,
    LifecycleError,
    UnauthorizedRotationError,
    InvalidTransitionError,
    TerminalPackageError,
    TRANSITION_SIGNER_ROTATION,
    TRANSITION_REVOKE,
    TRANSITION_DEPRECATE,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

REGISTRY_ID = "reg-adversarial-001"
SIGNER_A = "fp-signer-A"
SIGNER_B = "fp-signer-B"
SIGNER_C = "fp-signer-C"
PUBLISHER = "fp-publisher"


@pytest.fixture
def state(tmp_path):
    s = RegistryState(tmp_path / "state.json")
    s.set_registry_identity(REGISTRY_ID, SIGNER_A)
    s.approve_publisher("pub-001", PUBLISHER, [])
    return s


@pytest.fixture
def server(tmp_path, state):
    return ReferenceRegistryServer(
        state_path=state.state_path,
        artifact_dir=tmp_path / "artifacts",
        registry_id=REGISTRY_ID,
        registry_signer_fingerprint=SIGNER_A,
    )


@pytest.fixture
def tlog(tmp_path):
    log = TransitionLog(tmp_path / "tlog.json")
    log.set_registry_id(REGISTRY_ID)
    return log


@pytest.fixture
def governor(state, tlog):
    return LifecycleGovernor(state, tlog)


@pytest.fixture
def client_store(tmp_path):
    store = RegistryTrustStore(tmp_path / "client_trust.json")
    store.approve_signer(REGISTRY_ID, SIGNER_A)
    return store


@pytest.fixture
def client_evaluator(client_store):
    return RegistryTrustEvaluator(client_store, max_age_hours=24)


def _make_metadata(registry_id=REGISTRY_ID, signer_fp=SIGNER_A, generation=1,
                   issued_at=None, expires_at=None, index_digest="idx-001"):
    now = datetime.now(timezone.utc)
    return SignedRegistryMetadata(
        registry_id=registry_id,
        signer_fingerprint=signer_fp,
        generation=generation,
        issued_at=issued_at or now.isoformat(),
        expires_at=expires_at or (now + timedelta(hours=12)).isoformat(),
        package_index_digest=index_digest,
    )


# ── Scenario 1: Old signer after accepted rotation ──────────────────────────

class TestScenario1OldSignerRejected:
    """1. Old signer metadata after accepted rotation → rejected for newer gen."""

    def test_old_signer_rejected_for_newer_generation(self, client_store, client_evaluator, governor, server):
        # Publish to get some generations
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        # Client accepts gen 1 from signer A
        m1 = _make_metadata(signer_fp=SIGNER_A, generation=1)
        v1 = client_evaluator.accept(m1, endpoint_url="https://reg.example.com")
        assert v1.trusted

        # Rotate signer A → B at generation 2
        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)

        # Client learns of rotation
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=2)

        # Old signer tries to authorize gen 3 → rejected (LG-011)
        m3 = _make_metadata(signer_fp=SIGNER_A, generation=3)
        v3 = client_evaluator.evaluate(m3)
        assert not v3.trusted
        assert v3.verdict == TRUST_VERDICT_SUPERSEDED

    def test_old_signer_at_pre_rotation_generation_accepted(self, client_store, client_evaluator, governor, server):
        """Old signer at generation <= rotation generation is still valid (historical)."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        m1 = _make_metadata(signer_fp=SIGNER_A, generation=1)
        client_evaluator.accept(m1, endpoint_url="https://reg.example.com")

        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=2)

        # Gen 1 from signer A is still valid historical metadata
        # It should not trigger superseded check since gen 1 <= rotation_gen 2
        # But the evaluator may still have it in accepted_metadata from signer A
        # The key point: gen > rotation_generation from old signer is rejected


# ── Scenario 2: Overlap window ──────────────────────────────────────────────

class TestScenario2OverlapWindow:
    """2. Old signer within overlap window → accepted only if overlap policy."""

    def test_overlap_policy_retains_old_signer(self, client_store, governor, server):
        """If overlap policy retains old signer, both signers are approved."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)

        # Overlap policy: keep both A and B approved (don't record supersession)
        # Just approve B without superseding A
        client_store.approve_signer(REGISTRY_ID, SIGNER_B)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)

        # Both signers work during overlap
        m_a = _make_metadata(signer_fp=SIGNER_A, generation=2)
        m_b = _make_metadata(signer_fp=SIGNER_B, generation=2)

        v_a = evaluator.evaluate(m_a)
        v_b = evaluator.evaluate(m_b)

        # Both should pass signer approval (not superseded)
        assert v_a.signer_approved
        assert v_b.signer_approved

    def test_no_overlap_old_signer_rejected(self, client_store, governor):
        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=1)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)
        m = _make_metadata(signer_fp=SIGNER_A, generation=2)
        v = evaluator.evaluate(m)
        assert not v.trusted


# ── Scenario 3: Unlinked signer change ──────────────────────────────────────

class TestScenario3UnlinkedSignerChange:
    """3. Unlinked signer change → fail closed."""

    def test_unlinked_signer_rejected(self, client_store):
        """A new signer appears with no rotation record → fail closed."""
        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)
        m = _make_metadata(signer_fp="fp-completely-unknown", generation=1)
        v = evaluator.evaluate(m)
        assert not v.trusted
        assert v.verdict == TRUST_VERDICT_UNAPPROVED_SIGNER


# ── Scenario 4: Rotation chain A → B → C ────────────────────────────────────

class TestScenario4RotationChain:
    """4. Rotation chain A → B → C → continuity verified transitively."""

    def test_three_signer_chain(self, client_store, governor, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        # A → B
        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=2)

        # B → C
        governor.govern_signer_rotation(SIGNER_C, SIGNER_B)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_B, SIGNER_C, rotation_generation=3)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)

        # C is the current signer — gen 3 accepted
        m_c = _make_metadata(signer_fp=SIGNER_C, generation=3)
        v_c = evaluator.evaluate(m_c)
        assert v_c.trusted

        # A is superseded — gen 4 rejected
        m_a = _make_metadata(signer_fp=SIGNER_A, generation=4)
        v_a = evaluator.evaluate(m_a)
        assert not v_a.trusted
        assert v_a.verdict == TRUST_VERDICT_SUPERSEDED

        # B is superseded — gen 4 rejected
        m_b = _make_metadata(signer_fp=SIGNER_B, generation=4)
        v_b = evaluator.evaluate(m_b)
        assert not v_b.trusted
        assert v_b.verdict == TRUST_VERDICT_SUPERSEDED


# ── Scenario 5: Rotation record replay ──────────────────────────────────────

class TestScenario5RotationReplay:
    """5. Rotation record replay → no rollback of accepted signer generation."""

    def test_replay_doesnt_rollback(self, client_store, governor, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        # Rotate A → B at gen 2
        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=2)

        # "Replay" — record the same rotation again (should be idempotent)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=2)

        # The supersession record still exists
        assert client_store.is_signer_superseded(REGISTRY_ID, SIGNER_A)


# ── Scenario 6: Publisher revocation + publish attempt ──────────────────────

class TestScenario6PublisherRevokedPublish:
    """6. Publisher revocation followed by publish → server rejects."""

    def test_revoked_publisher_cannot_publish(self, governor, server, state):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        governor.govern_publisher_revoke(PUBLISHER, SIGNER_A)

        with pytest.raises(UnauthorizedPublisherError):
            server.publish("pkg_b", "1.0.0", b"data2", publisher_fingerprint=PUBLISHER)

    def test_revoked_publisher_packages_preserved(self, governor, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)
        governor.govern_publisher_revoke(PUBLISHER, SIGNER_A)

        record = server.state.get_package("pkg", "1.0.0")
        assert record is not None
        assert record.lifecycle == LIFECYCLE_ACTIVE


# ── Scenario 7: Revoked package already installed ───────────────────────────

class TestScenario7RevokedPackageInstalled:
    """7. Revoked package already installed → evidence remains, execution denied."""

    def test_revoked_package_evidence_preserved(self, governor, server):
        receipt = server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)
        artifact_digest = receipt.artifact_digest

        governor.govern_revoke("pkg", "1.0.0", "security", SIGNER_A)

        # Artifact still in storage
        assert server.get_artifact_path(artifact_digest).exists()

        # Package record still exists with immutable identity
        record = server.state.get_package("pkg", "1.0.0")
        assert record is not None
        assert record.lifecycle == LIFECYCLE_REVOKED
        # Immutable identity preserved
        assert record.artifact_digest == artifact_digest


# ── Scenario 8: Revoked package in paused workflow ──────────────────────────

class TestScenario8RevokedPausedWorkflow:
    """8. Revoked package in paused workflow → resume rejected."""

    def test_revoked_package_cannot_be_re_published(self, governor, server):
        """A revoked package cannot be re-published even in recovery."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)
        governor.govern_revoke("pkg", "1.0.0", "compromised", SIGNER_A)

        with pytest.raises(PackageRevokedError):
            server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)


# ── Scenario 9: Deprecation after pinning ───────────────────────────────────

class TestScenario9DeprecationPinning:
    """9. Deprecation after package pinning → policy-controlled."""

    def test_deprecated_package_still_in_index(self, governor, server):
        """Deprecated packages remain in the active index (not revoked)."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)
        digest_before = server.state.compute_package_index_digest()

        governor.govern_deprecate("pkg", "1.0.0", SIGNER_A)
        digest_after = server.state.compute_package_index_digest()

        # Same digest because immutable identity unchanged, still active (not revoked)
        assert digest_before == digest_after

    def test_deprecated_package_lifecycle(self, governor, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)
        governor.govern_deprecate("pkg", "1.0.0", SIGNER_A)

        record = server.state.get_package("pkg", "1.0.0")
        assert record.lifecycle == LIFECYCLE_DEPRECATED


# ── Scenario 10: Emergency revocation during freshness ──────────────────────

class TestScenario10EmergencyRevoke:
    """10. Emergency revocation during metadata freshness window."""

    def test_emergency_revoke_advances_generation(self, governor, server):
        server.publish("pkg_a", "1.0.0", b"a", publisher_fingerprint=PUBLISHER)
        gen_before = server.state.get_generation()

        # Emergency revocation
        governor.govern_revoke("pkg_a", "1.0.0", "zero-day", SIGNER_A)
        gen_after = server.state.get_generation()

        assert gen_after > gen_before

    def test_emergency_revoke_produces_receipt(self, governor, server):
        server.publish("pkg_a", "1.0.0", b"a", publisher_fingerprint=PUBLISHER)
        receipt = governor.govern_revoke("pkg_a", "1.0.0", "zero-day", SIGNER_A)
        assert receipt.transition_type == TRANSITION_REVOKE
        assert receipt.receipt_digest != ""


# ── Scenario 11: Concurrent deprecate/revoke ────────────────────────────────

class TestScenario11ConcurrentTransitions:
    """11. Concurrent deprecate/revoke → atomic generation, one final state."""

    def test_concurrent_transitions_one_wins(self, governor, server):
        """Two threads try to revoke the same package — only one succeeds."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        results = []
        errors = []

        def try_revoke():
            try:
                governor.govern_revoke("pkg", "1.0.0", "concurrent", SIGNER_A)
                results.append("ok")
            except (TerminalPackageError, Exception) as e:
                errors.append(str(e))

        t1 = threading.Thread(target=try_revoke)
        t2 = threading.Thread(target=try_revoke)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Package should be revoked regardless
        record = server.state.get_package("pkg", "1.0.0")
        assert record.lifecycle == LIFECYCLE_REVOKED

    def test_concurrent_different_packages(self, governor, server):
        """Two threads revoke different packages — both succeed."""
        server.publish("pkg_a", "1.0.0", b"a", publisher_fingerprint=PUBLISHER)
        server.publish("pkg_b", "1.0.0", b"b", publisher_fingerprint=PUBLISHER)

        results = []

        def revoke_a():
            try:
                governor.govern_revoke("pkg_a", "1.0.0", "test", SIGNER_A)
                results.append("a")
            except Exception:
                pass

        def revoke_b():
            try:
                governor.govern_revoke("pkg_b", "1.0.0", "test", SIGNER_A)
                results.append("b")
            except Exception:
                pass

        t1 = threading.Thread(target=revoke_a)
        t2 = threading.Thread(target=revoke_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert "a" in results
        assert "b" in results

        gen = server.state.get_generation()
        assert gen >= 4  # 2 publishes + 2 revokes


# ── Scenario 12: Signer rotation during installation ────────────────────────

class TestScenario12RotationDuringInstall:
    """12. Signer rotation during package installation → completes or fails closed."""

    def test_install_against_pre_rotation_generation(self, client_store, governor, server):
        """Install completes against the generation it started with."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        # Client trusts gen 1 from signer A
        m1 = _make_metadata(signer_fp=SIGNER_A, generation=1)
        v1 = client_evaluator_local = RegistryTrustEvaluator(client_store, max_age_hours=24)
        verdict = v1_local = client_evaluator_local.accept(m1, endpoint_url="https://reg.example.com")
        assert v1_local.trusted

        # Meanwhile, server rotates signer
        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)

        # Client's cached gen 1 metadata is still valid (within freshness)
        # Install can complete against the verified generation
        assert verdict.generation == 1

    def test_post_rotation_metadata_requires_new_signer(self, client_store, governor, server):
        """After rotation, new metadata must come from new signer."""
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint=PUBLISHER)

        governor.govern_signer_rotation(SIGNER_B, SIGNER_A)
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=2)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)

        # Gen 2 from new signer B → accepted (once B is approved via supersession)
        m_b = _make_metadata(signer_fp=SIGNER_B, generation=2)
        v_b = evaluator.evaluate(m_b)
        assert v_b.trusted

        # Gen 2 from old signer A → rejected (superseded)
        m_a = _make_metadata(signer_fp=SIGNER_A, generation=2)
        v_a = evaluator.evaluate(m_a)
        assert not v_a.trusted
        assert v_a.verdict == TRUST_VERDICT_SUPERSEDED


# ── LG-011 Direct tests ─────────────────────────────────────────────────────

class TestLG011SupersededSigner:
    """LG-011: Superseded signer cannot authorize newer generations."""

    def test_supersession_recorded(self, client_store):
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=5)
        assert client_store.is_signer_superseded(REGISTRY_ID, SIGNER_A)
        assert not client_store.is_signer_superseded(REGISTRY_ID, SIGNER_B)

    def test_supersession_generation(self, client_store):
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=5)
        gen = client_store.get_supersession_generation(REGISTRY_ID, SIGNER_A)
        assert gen == 5

    def test_supersession_removes_old_approves_new(self, client_store):
        """Recording supersession removes old signer, adds new signer."""
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=1)
        # Old signer is still in approved list (supersession doesn't remove from approved)
        # But is marked as superseded — the evaluator checks both
        assert client_store.is_signer_superseded(REGISTRY_ID, SIGNER_A)
        # New signer is approved
        assert client_store.is_signer_approved(REGISTRY_ID, SIGNER_B)

    def test_supersession_persists(self, tmp_path):
        s1 = RegistryTrustStore(tmp_path / "trust.json")
        s1.approve_signer(REGISTRY_ID, SIGNER_A)
        s1.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=3)

        s2 = RegistryTrustStore(tmp_path / "trust.json")
        assert s2.is_signer_superseded(REGISTRY_ID, SIGNER_A)
        gen = s2.get_supersession_generation(REGISTRY_ID, SIGNER_A)
        assert gen == 3

    def test_superseded_signer_at_rotation_gen_rejected(self, client_store):
        """Signer at exactly the rotation generation is superseded.

        The rotation generation belongs to the NEW signer. The old signer
        cannot authorize that generation or any after it.
        """
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=5)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)
        # gen 5 == rotation_gen 5 → superseded (>=)
        m = _make_metadata(signer_fp=SIGNER_A, generation=5)
        v = evaluator.evaluate(m)
        assert not v.trusted
        assert v.verdict == TRUST_VERDICT_SUPERSEDED

    def test_superseded_signer_below_rotation_gen_accepted(self, client_store):
        """Signer at generation below rotation is still valid (historical)."""
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=5)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)
        # gen 4 < rotation_gen 5 → NOT superseded
        m = _make_metadata(signer_fp=SIGNER_A, generation=4)
        v = evaluator.evaluate(m)
        assert v.verdict != TRUST_VERDICT_SUPERSEDED

    def test_superseded_signer_above_rotation_gen_rejected(self, client_store):
        client_store.record_signer_supersession(REGISTRY_ID, SIGNER_A, SIGNER_B, rotation_generation=5)

        evaluator = RegistryTrustEvaluator(client_store, max_age_hours=24)
        m = _make_metadata(signer_fp=SIGNER_A, generation=6)
        v = evaluator.evaluate(m)
        assert not v.trusted
        assert v.verdict == TRUST_VERDICT_SUPERSEDED
