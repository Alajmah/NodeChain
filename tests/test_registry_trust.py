"""Remote Registry Trust Protocol v1 Tests (v2.21.3).

Tests signed registry metadata with freshness, generation rollback
prevention, equivocation detection, endpoint identity drift, and
mirror authorization.
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from nodechain.sdk.registry_trust import (
    SignedRegistryMetadata,
    AcceptedMetadataRecord,
    EndpointIdentityRecord,
    RegistryTrustStore,
    RegistryTrustEvaluator,
    RegistryTrustVerdict,
    TransportProvenance,
    PROTOCOL_VERSION,
    TRUST_VERDICT_TRUSTED,
    TRUST_VERDICT_EXPIRED,
    TRUST_VERDICT_ROLLBACK,
    TRUST_VERDICT_EQUIVOCATION,
    TRUST_VERDICT_UNAPPROVED_SIGNER,
    TRUST_VERDICT_ENDPOINT_DRIFT,
    TRUST_VERDICT_STALE,
    TRUST_VERDICT_UNTRUSTED,
    DEFAULT_FRESHNESS_MAX_AGE_HOURS,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def trust_store(tmp_path):
    return RegistryTrustStore(tmp_path / "registry_trust.json")


@pytest.fixture
def evaluator(trust_store):
    return RegistryTrustEvaluator(trust_store, max_age_hours=24)


@pytest.fixture
def approved_store(trust_store):
    trust_store.approve_signer("reg-001", "fp-abc")
    return trust_store


@pytest.fixture
def approved_evaluator(approved_store):
    return RegistryTrustEvaluator(approved_store, max_age_hours=24)


def _make_metadata(
    registry_id="reg-001",
    signer_fingerprint="fp-abc",
    generation=1,
    issued_at=None,
    expires_at=None,
    package_index_digest="idx-001",
):
    now = datetime.now(timezone.utc)
    return SignedRegistryMetadata(
        registry_id=registry_id,
        signer_fingerprint=signer_fingerprint,
        generation=generation,
        issued_at=issued_at or now.isoformat(),
        expires_at=expires_at or (now + timedelta(hours=12)).isoformat(),
        package_index_digest=package_index_digest,
    )


# ── AC-1: SignedRegistryMetadata v1 ─────────────────────────────────────────

class TestAC1SignedMetadata:
    """1. Signed metadata with freshness, generation, and expiry."""

    def test_metadata_fields(self):
        m = _make_metadata()
        assert m.registry_id == "reg-001"
        assert m.protocol_version == PROTOCOL_VERSION
        assert m.generation == 1
        assert m.issued_at != ""
        assert m.expires_at != ""

    def test_metadata_digest_deterministic(self):
        m = _make_metadata()
        d1 = m.compute_digest()
        d2 = m.compute_digest()
        assert d1 == d2

    def test_metadata_digest_changes_on_generation(self):
        m1 = _make_metadata(generation=1)
        m2 = _make_metadata(generation=2)
        assert m1.compute_digest() != m2.compute_digest()

    def test_canonical_identity(self):
        m = _make_metadata()
        assert m.canonical_identity() == "reg-001:fp-abc"

    def test_is_expired_future(self):
        m = _make_metadata(expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        assert m.is_expired() is False

    def test_is_expired_past(self):
        m = _make_metadata(expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        assert m.is_expired() is True

    def test_is_expired_no_expiry(self):
        m = _make_metadata()
        m.expires_at = ""
        assert m.is_expired() is False

    def test_age_hours_fresh(self):
        m = _make_metadata(issued_at=datetime.now(timezone.utc).isoformat())
        assert m.age_hours() < 1.0


# ── AC-2: Registry onboarding ───────────────────────────────────────────────

class TestAC2RegistryOnboarding:
    """2. Registry onboarding: registry_id bound to approved signer."""

    def test_unapproved_signer_rejected(self, evaluator, trust_store):
        m = _make_metadata()
        verdict = evaluator.evaluate(m)
        assert not verdict.trusted
        assert verdict.verdict == TRUST_VERDICT_UNAPPROVED_SIGNER

    def test_approved_signer_accepted(self, approved_evaluator):
        m = _make_metadata()
        verdict = approved_evaluator.evaluate(m)
        assert verdict.trusted
        assert verdict.signer_approved

    def test_wrong_signer_for_registry_rejected(self, approved_evaluator):
        m = _make_metadata(signer_fingerprint="fp-DIFFERENT")
        verdict = approved_evaluator.evaluate(m)
        assert not verdict.trusted
        assert verdict.verdict == TRUST_VERDICT_UNAPPROVED_SIGNER

    def test_empty_allowlist_fails_closed(self, trust_store):
        """No approved signers for a registry = not trusted."""
        evaluator = RegistryTrustEvaluator(trust_store)
        m = _make_metadata()
        verdict = evaluator.evaluate(m)
        assert not verdict.trusted
        assert verdict.verdict == TRUST_VERDICT_UNAPPROVED_SIGNER


# ── AC-3: Freshness enforcement ─────────────────────────────────────────────

class TestAC3FreshnessEnforcement:
    """3. Reject expired metadata in strict mode."""

    def test_expired_rejected(self, approved_evaluator):
        m = _make_metadata(
            expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        )
        verdict = approved_evaluator.evaluate(m)
        assert not verdict.trusted
        assert verdict.verdict == TRUST_VERDICT_EXPIRED

    def test_stale_rejected_in_strict_mode(self, approved_evaluator):
        """Metadata older than max_age_hours is stale."""
        m = _make_metadata(
            issued_at=(datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        verdict = approved_evaluator.evaluate(m)
        assert not verdict.trusted
        assert verdict.verdict == TRUST_VERDICT_STALE

    def test_fresh_accepted(self, approved_evaluator):
        m = _make_metadata(
            issued_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        verdict = approved_evaluator.evaluate(m)
        assert verdict.trusted

    def test_non_strict_allows_stale(self, approved_store):
        """Non-strict mode doesn't check staleness (only expiry)."""
        evaluator = RegistryTrustEvaluator(approved_store, strict_freshness=False)
        m = _make_metadata(
            issued_at=(datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        verdict = evaluator.evaluate(m)
        assert verdict.trusted


# ── AC-4: Rollback prevention ───────────────────────────────────────────────

class TestAC4RollbackPrevention:
    """4. Reject metadata with generation lower than accepted."""

    def test_rollback_rejected(self, approved_evaluator):
        """Accept gen 5, then reject gen 3."""
        m5 = _make_metadata(generation=5)
        verdict5 = approved_evaluator.accept(m5)
        assert verdict5.trusted

        m3 = _make_metadata(generation=3)
        verdict3 = approved_evaluator.evaluate(m3)
        assert not verdict3.trusted
        assert verdict3.verdict == TRUST_VERDICT_ROLLBACK

    def test_equal_generation_accepted_if_same_digest(self, approved_evaluator):
        """Re-fetching same generation with same digest is idempotent."""
        m1 = _make_metadata(generation=3)
        v1 = approved_evaluator.accept(m1)
        assert v1.trusted

        v2 = approved_evaluator.evaluate(m1)
        assert v2.trusted

    def test_higher_generation_accepted(self, approved_evaluator):
        """Generation 5 → Generation 6 is forward progress."""
        m5 = _make_metadata(generation=5)
        approved_evaluator.accept(m5)

        m6 = _make_metadata(generation=6)
        v6 = approved_evaluator.evaluate(m6)
        assert v6.trusted

    def test_first_metadata_always_accepted_generation(self, approved_evaluator):
        """No prior accepted metadata → any generation is fine."""
        m = _make_metadata(generation=1)
        v = approved_evaluator.evaluate(m)
        assert v.trusted


# ── AC-5: Equivocation detection ────────────────────────────────────────────

class TestAC5EquivocationDetection:
    """5. Same registry_id + signer + generation but different digest."""

    def test_equivocation_detected(self, approved_evaluator):
        """Accept gen 3 with digest A, then gen 3 with digest B."""
        m1 = _make_metadata(generation=3, package_index_digest="index-A")
        v1 = approved_evaluator.accept(m1)
        assert v1.trusted

        m2 = _make_metadata(generation=3, package_index_digest="index-B")
        v2 = approved_evaluator.evaluate(m2)
        assert not v2.trusted
        assert v2.verdict == TRUST_VERDICT_EQUIVOCATION

    def test_same_generation_same_digest_accepted(self, approved_evaluator):
        """Re-fetching identical metadata is fine."""
        m = _make_metadata(generation=3)
        approved_evaluator.accept(m)

        v = approved_evaluator.evaluate(m)
        assert v.trusted


# ── AC-6: Endpoint identity drift ───────────────────────────────────────────

class TestAC6EndpointIdentityDrift:
    """6. Same endpoint serves different registry identity."""

    def test_endpoint_drift_detected(self, approved_evaluator):
        """Endpoint first serves reg-001, then serves reg-002."""
        m1 = _make_metadata(registry_id="reg-001")
        approved_evaluator.accept(m1, endpoint_url="https://reg.example.com")

        m2 = _make_metadata(registry_id="reg-002")
        approved_evaluator.trust_store.approve_signer("reg-002", "fp-abc")
        v2 = approved_evaluator.evaluate(m2, endpoint_url="https://reg.example.com")
        assert not v2.trusted
        assert v2.verdict == TRUST_VERDICT_ENDPOINT_DRIFT

    def test_same_endpoint_same_identity_ok(self, approved_evaluator):
        m = _make_metadata()
        approved_evaluator.accept(m, endpoint_url="https://reg.example.com")

        v = approved_evaluator.evaluate(m, endpoint_url="https://reg.example.com")
        assert v.trusted

    def test_different_endpoint_ok(self, approved_evaluator):
        """Different endpoints can serve different registries."""
        m1 = _make_metadata(registry_id="reg-001")
        approved_evaluator.accept(m1, endpoint_url="https://a.example.com")

        m2 = _make_metadata(registry_id="reg-002")
        # Need to approve reg-002 signer too
        approved_evaluator.trust_store.approve_signer("reg-002", "fp-abc")
        v2 = approved_evaluator.evaluate(m2, endpoint_url="https://b.example.com")
        assert v2.trusted

    def test_signer_drift_at_same_endpoint(self, approved_evaluator):
        """Same endpoint, same registry_id, different signer = drift."""
        m1 = _make_metadata(registry_id="reg-001", signer_fingerprint="fp-abc")
        approved_evaluator.accept(m1, endpoint_url="https://reg.example.com")

        # Approve second signer for same registry
        approved_evaluator.trust_store.approve_signer("reg-001", "fp-xyz")

        m2 = _make_metadata(registry_id="reg-001", signer_fingerprint="fp-xyz")
        v2 = approved_evaluator.evaluate(m2, endpoint_url="https://reg.example.com")
        assert not v2.trusted
        assert v2.verdict == TRUST_VERDICT_ENDPOINT_DRIFT


# ── AC-7: Mirror handling ───────────────────────────────────────────────────

class TestAC7MirrorHandling:
    """7. Mirror accepted when metadata validates to same canonical identity."""

    def test_mirror_with_same_identity_accepted(self, approved_evaluator):
        """Mirror URL serves same registry identity as primary."""
        m1 = _make_metadata()
        approved_evaluator.accept(m1, endpoint_url="https://primary.example.com")

        # Same metadata from mirror
        v = approved_evaluator.evaluate(m1, endpoint_url="https://mirror.example.com")
        assert v.trusted

    def test_mirror_records_endpoint(self, approved_evaluator):
        """Mirror endpoint is recorded in trust store."""
        m = _make_metadata()
        approved_evaluator.accept(m, endpoint_url="https://mirror.example.com")

        record = approved_evaluator.trust_store.get_endpoint_identity("https://mirror.example.com")
        assert record is not None
        assert record.registry_id == "reg-001"


# ── AC-8: Offline verification ──────────────────────────────────────────────

class TestAC8OfflineVerification:
    """8. Cached signed metadata usable within freshness policy."""

    def test_cached_metadata_within_freshness(self, approved_evaluator):
        """Metadata cached 2 hours ago, freshness max 24h → still valid."""
        m = _make_metadata(
            issued_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=10)).isoformat(),
        )
        v = approved_evaluator.evaluate(m)
        assert v.trusted

    def test_cached_metadata_outside_freshness_rejected(self, approved_evaluator):
        """Metadata cached 48 hours ago, freshness max 24h → stale."""
        m = _make_metadata(
            issued_at=(datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        v = approved_evaluator.evaluate(m)
        assert not v.trusted
        assert v.verdict == TRUST_VERDICT_STALE


# ── AC-9: Transport provenance ──────────────────────────────────────────────

class TestAC9TransportProvenance:
    """9. Transport provenance retained for forensic detail."""

    def test_provenance_fields(self):
        tp = TransportProvenance(
            requested_url="https://reg.example.com",
            final_url="https://cdn.example.com/redirected",
            redirect_chain=["https://reg.example.com", "https://cdn.example.com"],
            fetched_at="2026-06-19T05:00:00Z",
        )
        d = tp.to_dict()
        assert d["requested_url"] == "https://reg.example.com"
        assert d["final_url"] == "https://cdn.example.com/redirected"
        assert len(d["redirect_chain"]) == 2


# ── AC-10: Dashboard health rules ───────────────────────────────────────────

class TestAC10DashboardHealthRules:
    """10. Dashboard rules for trust violations."""

    def test_hr026_install_conflict(self):
        from nodechain.cli.dashboard_health import HR026RemoteInstallConflict
        rule = HR026RemoteInstallConflict()
        assert rule.rule_id == "HR-026"
        result = rule.evaluate({
            "remote_install": {"enabled": True, "conflict_count": 1}
        })
        assert result is not None

    def test_hr027_expired_metadata(self):
        from nodechain.cli.dashboard_health import HR027RegistryMetadataExpired
        rule = HR027RegistryMetadataExpired()
        result = rule.evaluate({
            "registry_trust": {"enabled": True, "expired_metadata_count": 2, "stale_metadata_count": 1}
        })
        assert result is not None
        assert "2 expired" in result["description"]

    def test_hr028_equivocation(self):
        from nodechain.cli.dashboard_health import HR028RegistryEquivocation
        rule = HR028RegistryEquivocation()
        result = rule.evaluate({
            "registry_trust": {"enabled": True, "equivocation_count": 1, "rollback_count": 0}
        })
        assert result is not None
        assert result["severity"] == "critical"

    def test_hr029_endpoint_drift(self):
        from nodechain.cli.dashboard_health import HR029EndpointIdentityDrift
        rule = HR029EndpointIdentityDrift()
        result = rule.evaluate({
            "registry_trust": {"enabled": True, "endpoint_drift_count": 1}
        })
        assert result is not None

    def test_hr030_unapproved_signer(self):
        from nodechain.cli.dashboard_health import HR030UnapprovedRegistrySigner
        rule = HR030UnapprovedRegistrySigner()
        result = rule.evaluate({
            "registry_trust": {"enabled": True, "unapproved_signer_count": 1}
        })
        assert result is not None

    def test_all_39_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES, RULES_BY_ID
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
        for i in range(1, 45):
            assert f"HR-{i:03d}" in RULES_BY_ID


# ── AC-11: Full trust evaluation lifecycle ──────────────────────────────────

class TestAC11FullLifecycle:
    """11. Complete trust evaluation with all checks."""

    def test_full_acceptance_lifecycle(self, approved_evaluator):
        """Onboard → accept gen 1 → accept gen 2 → reject rollback."""
        m1 = _make_metadata(generation=1)
        v1 = approved_evaluator.accept(m1, endpoint_url="https://reg.example.com")
        assert v1.trusted

        m2 = _make_metadata(generation=2)
        v2 = approved_evaluator.accept(m2, endpoint_url="https://reg.example.com")
        assert v2.trusted

        # Rollback attempt
        m0 = _make_metadata(generation=0)
        v0 = approved_evaluator.evaluate(m0, endpoint_url="https://reg.example.com")
        assert not v0.trusted
        assert v0.verdict == TRUST_VERDICT_ROLLBACK

    def test_all_checks_in_verdict(self, approved_evaluator):
        m = _make_metadata()
        v = approved_evaluator.accept(m, endpoint_url="https://reg.example.com")
        assert v.trusted
        assert v.signer_approved
        assert v.freshness_ok
        assert v.generation_ok
        assert v.equivocation_ok
        assert v.endpoint_ok


# ── Trust store persistence ─────────────────────────────────────────────────

class TestTrustStorePersistence:
    """Trust store survives reload."""

    def test_approved_signers_persist(self, trust_store):
        trust_store.approve_signer("reg-001", "fp-abc")
        store2 = RegistryTrustStore(trust_store.path)
        assert store2.is_signer_approved("reg-001", "fp-abc")

    def test_accepted_metadata_persists(self, trust_store):
        m = _make_metadata()
        trust_store.record_accepted_metadata(m)
        store2 = RegistryTrustStore(trust_store.path)
        record = store2.get_accepted_metadata("reg-001", "fp-abc")
        assert record is not None
        assert record.generation == 1

    def test_endpoint_identity_persists(self, trust_store):
        trust_store.record_endpoint_identity("https://reg.example.com", "reg-001", "fp-abc")
        store2 = RegistryTrustStore(trust_store.path)
        record = store2.get_endpoint_identity("https://reg.example.com")
        assert record is not None
        assert record.registry_id == "reg-001"
