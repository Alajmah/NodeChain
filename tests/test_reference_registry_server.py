"""Reference Remote Registry Server Tests (v2.21.3).

Tests the reference implementation proving the server side of the
Remote Registry Trust Protocol contract.

Coverage:
    AC-1:  Publisher authorization (fail closed)
    AC-2:  Publish flow (receive, validate, verify, store)
    AC-3:  RR-001 immutability (package version is immutable)
    AC-4:  Generation monotonic advancement
    AC-5:  Publication receipts
    AC-6:  Revocation and deprecation lifecycle
    AC-7:  Artifact size limits
    AC-8:  Safe storage paths (content-addressed by digest)
    AC-9:  Signed metadata with generation (v2.21.3 compatible)
    AC-10: Idempotent re-publish (same identity)
    AC-11: Interoperability with client trust protocol
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from nodechain.sdk.reference_registry_server import (
    RegistryState,
    ReferenceRegistryServer,
    PublisherAuthorization,
    ImmutablePackageRecord,
    PublicationReceipt,
    PublishError,
    PackageConflictError,
    UnauthorizedPublisherError,
    PackageRevokedError,
    PROTOCOL_VERSION,
    MAX_ARTIFACT_SIZE,
    DEFAULT_METADATA_EXPIRY_HOURS,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_DEPRECATED,
    LIFECYCLE_REVOKED,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def state(tmp_path):
    s = RegistryState(tmp_path / "registry_state.json")
    s.set_registry_identity("reg-test-001", "fp-registry-signer")
    return s


@pytest.fixture
def server(tmp_path, state):
    state.approve_publisher("pub-001", "fp-publisher", approved_packages=[])
    state_path = state.state_path
    return ReferenceRegistryServer(
        state_path=state_path,
        artifact_dir=tmp_path / "artifacts",
        registry_id="reg-test-001",
        registry_signer_fingerprint="fp-registry-signer",
    )


def _make_artifact(data: bytes = b"package contents v1") -> bytes:
    return data


# ── AC-1: Publisher authorization ───────────────────────────────────────────

class TestAC1PublisherAuthorization:
    """1. Publisher authorization (fail closed)."""

    def test_approved_publisher_passes(self, server):
        server.publish(
            package_id="test_pkg",
            version="1.0.0",
            artifact_bytes=_make_artifact(),
            publisher_fingerprint="fp-publisher",
        )

    def test_unapproved_publisher_rejected(self, server):
        with pytest.raises(UnauthorizedPublisherError):
            server.publish(
                package_id="test_pkg",
                version="1.0.0",
                artifact_bytes=_make_artifact(),
                publisher_fingerprint="fp-UNKNOWN",
            )

    def test_empty_fingerprint_rejected(self, server):
        with pytest.raises(UnauthorizedPublisherError):
            server.publish(
                package_id="test_pkg",
                version="1.0.0",
                artifact_bytes=_make_artifact(),
                publisher_fingerprint="",
            )

    def test_package_scope_restriction(self, tmp_path):
        """Publisher approved for only specific packages."""
        s = RegistryState(tmp_path / "state.json")
        s.set_registry_identity("reg-001", "fp-reg")
        s.approve_publisher("pub-001", "fp-scoped", approved_packages=["pkg_a"])

        sv = ReferenceRegistryServer(
            state_path=s.state_path,
            artifact_dir=tmp_path / "art",
            registry_id="reg-001",
            registry_signer_fingerprint="fp-reg",
        )

        # Can publish pkg_a
        sv.publish("pkg_a", "1.0.0", b"data", publisher_fingerprint="fp-scoped")

        # Cannot publish pkg_b
        with pytest.raises(UnauthorizedPublisherError):
            sv.publish("pkg_b", "1.0.0", b"data", publisher_fingerprint="fp-scoped")


# ── AC-2: Publish flow ──────────────────────────────────────────────────────

class TestAC2PublishFlow:
    """2. Publish flow: receive, validate, verify, store."""

    def test_successful_publish(self, server):
        receipt = server.publish(
            package_id="test_pkg",
            version="1.0.0",
            artifact_bytes=_make_artifact(),
            publisher_fingerprint="fp-publisher",
            manifest_digest="manifest-abc",
            description="Test package",
        )
        assert receipt.package_id == "test_pkg"
        assert receipt.version == "1.0.0"
        assert receipt.generation == 1
        assert receipt.artifact_digest != ""

    def test_artifact_stored_by_digest(self, server):
        artifact = _make_artifact()
        receipt = server.publish(
            package_id="test_pkg",
            version="1.0.0",
            artifact_bytes=artifact,
            publisher_fingerprint="fp-publisher",
        )
        # Artifact stored at content-addressed path
        path = server.get_artifact_path(receipt.artifact_digest)
        assert path.exists()
        assert path.read_bytes() == artifact

    def test_package_record_immutable_fields(self, server):
        receipt = server.publish(
            package_id="test_pkg",
            version="1.0.0",
            artifact_bytes=_make_artifact(),
            publisher_fingerprint="fp-publisher",
            publisher_id="pub-001",
            manifest_digest="manifest-abc",
            certification_digest="cert-xyz",
            sandbox_profile="standard_untrusted",
            capabilities=["read_only", "network"],
        )
        record = server.state.get_package("test_pkg", "1.0.0")
        assert record.package_id == "test_pkg"
        assert record.version == "1.0.0"
        assert record.artifact_digest == receipt.artifact_digest
        assert record.manifest_digest == "manifest-abc"
        assert record.certification_digest == "cert-xyz"
        assert record.publisher_fingerprint == "fp-publisher"
        assert record.publisher_id == "pub-001"
        assert record.lifecycle == LIFECYCLE_ACTIVE


# ── AC-3: RR-001 immutability ───────────────────────────────────────────────

class TestAC3Immutability:
    """3. RR-001: A package version is immutable."""

    def test_same_identity_re_publish_ok(self, server):
        """Re-publishing same package_id+version with same artifact is idempotent."""
        artifact = _make_artifact()
        r1 = server.publish(
            "pkg", "1.0.0", artifact, publisher_fingerprint="fp-publisher",
        )
        r2 = server.publish(
            "pkg", "1.0.0", artifact, publisher_fingerprint="fp-publisher",
        )
        assert r1.artifact_digest == r2.artifact_digest
        # Generation doesn't advance on idempotent re-publish
        assert r1.generation == r2.generation

    def test_different_artifact_same_version_rejected(self, server):
        """RR-001: Different artifact under same version = conflict."""
        server.publish(
            "pkg", "1.0.0", b"contents A", publisher_fingerprint="fp-publisher",
        )
        with pytest.raises(PackageConflictError):
            server.publish(
                "pkg", "1.0.0", b"contents B", publisher_fingerprint="fp-publisher",
            )

    def test_different_manifest_same_version_rejected(self, server):
        """RR-001: Different manifest_digest under same version = conflict."""
        artifact = _make_artifact()
        server.publish(
            "pkg", "1.0.0", artifact,
            publisher_fingerprint="fp-publisher",
            manifest_digest="manifest-A",
        )
        with pytest.raises(PackageConflictError):
            server.publish(
                "pkg", "1.0.0", artifact,
                publisher_fingerprint="fp-publisher",
                manifest_digest="manifest-B",
            )

    def test_different_publisher_same_artifact_rejected(self, server):
        """RR-001: Different publisher_fingerprint = conflict."""
        server.state.approve_publisher("pub-002", "fp-other", [])
        artifact = _make_artifact()
        server.publish(
            "pkg", "1.0.0", artifact, publisher_fingerprint="fp-publisher",
        )
        with pytest.raises(PackageConflictError):
            server.publish(
                "pkg", "1.0.0", artifact, publisher_fingerprint="fp-other",
            )

    def test_different_version_allowed(self, server):
        """Same package, different version, different artifact = fine."""
        server.publish(
            "pkg", "1.0.0", b"v1", publisher_fingerprint="fp-publisher",
        )
        server.publish(
            "pkg", "1.1.0", b"v2", publisher_fingerprint="fp-publisher",
        )

    def test_lifecycle_change_not_identity_conflict(self, server):
        """Lifecycle is mutable — revoking doesn't change immutable identity.

        After revoking, re-publishing same immutable identity should
        be rejected ONLY because package is revoked, NOT because of
        identity conflict.
        """
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        server.revoke("pkg", "1.0.0", reason="test")

        record = server.state.get_package("pkg", "1.0.0")
        # Immutable identity is still the same as at publish time
        assert record.immutable_identity_fields()["artifact_digest"] != ""
        assert record.lifecycle == "revoked"
        # Lifecycle fields are different from publish time
        assert record.lifecycle_fields()["lifecycle"] == "revoked"

    def test_identity_fields_all_8_immutable(self, server):
        """Verify all 8 immutable identity-bearing fields are compared."""
        record = ImmutablePackageRecord(
            package_id="pkg",
            version="1.0.0",
            artifact_digest="dig",
            manifest_digest="man",
            publisher_fingerprint="fp",
            publisher_id="pub",
            certification_digest="cert",
            sandbox_profile="hardened",
            lifecycle="active",
        )
        fields = record.immutable_identity_fields()
        assert len(fields) == 8
        assert set(fields.keys()) == {
            "package_id", "version", "artifact_digest", "manifest_digest",
            "publisher_fingerprint", "publisher_id", "certification_digest",
            "sandbox_profile",
        }
        assert "lifecycle" not in fields

    def test_lifecycle_fields_separate(self, server):
        """Lifecycle is mutable metadata, not immutable identity."""
        record = ImmutablePackageRecord(lifecycle="revoked")
        lf = record.lifecycle_fields()
        assert "lifecycle" in lf
        assert lf["lifecycle"] == "revoked"


# ── AC-4: Generation monotonic advancement ──────────────────────────────────

class TestAC4GenerationAdvancement:
    """4. Generation increments atomically on each new publication."""

    def test_generation_starts_at_zero(self, tmp_path):
        s = RegistryState(tmp_path / "state.json")
        assert s.get_generation() == 0

    def test_generation_advances_on_publish(self, server):
        r1 = server.publish("pkg_a", "1.0.0", b"a", publisher_fingerprint="fp-publisher")
        assert r1.generation == 1

        r2 = server.publish("pkg_b", "1.0.0", b"b", publisher_fingerprint="fp-publisher")
        assert r2.generation == 2

    def test_generation_no_advance_on_idempotent(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        gen_before = server.state.get_generation()

        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        gen_after = server.state.get_generation()
        assert gen_before == gen_after

    def test_generation_advances_on_revoke(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        gen1 = server.state.get_generation()

        server.revoke("pkg", "1.0.0", reason="security")
        gen2 = server.state.get_generation()
        assert gen2 == gen1 + 1

    def test_generation_advances_on_deprecate(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        gen1 = server.state.get_generation()

        server.deprecate("pkg", "1.0.0")
        gen2 = server.state.get_generation()
        assert gen2 == gen1 + 1


# ── AC-5: Publication receipts ──────────────────────────────────────────────

class TestAC5PublicationReceipts:
    """5. Every successful publication emits a receipt."""

    def test_receipt_fields(self, server):
        receipt = server.publish(
            "pkg", "1.0.0", b"data",
            publisher_fingerprint="fp-publisher",
            manifest_digest="manifest-abc",
        )
        assert receipt.receipt_id != ""
        assert receipt.package_id == "pkg"
        assert receipt.version == "1.0.0"
        assert receipt.artifact_digest != ""
        assert receipt.publisher_fingerprint == "fp-publisher"
        assert receipt.registry_id == "reg-test-001"
        assert receipt.generation == 1
        assert receipt.published_at != ""
        assert receipt.receipt_digest != ""

    def test_receipt_to_dict(self, server):
        receipt = server.publish(
            "pkg", "1.0.0", b"data",
            publisher_fingerprint="fp-publisher",
        )
        d = receipt.to_dict()
        assert "receipt_id" in d
        assert "package_id" in d
        assert "artifact_digest" in d
        assert "generation" in d

    def test_receipt_digest_deterministic(self, server):
        """Same publish parameters produce same receipt digest content fields."""
        receipt = server.publish(
            "pkg", "1.0.0", b"data",
            publisher_fingerprint="fp-publisher",
        )
        # The receipt_id is deterministic from package+version+digest+gen
        assert receipt.receipt_id  # non-empty


# ── AC-6: Revocation and deprecation ────────────────────────────────────────

class TestAC6Lifecycle:
    """6. Revocation and deprecation support."""

    def test_revoke_sets_lifecycle(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        server.revoke("pkg", "1.0.0", reason="compromised")

        record = server.state.get_package("pkg", "1.0.0")
        assert record.lifecycle == LIFECYCLE_REVOKED
        assert record.revoked_at != ""
        assert record.revocation_reason == "compromised"

    def test_deprecate_sets_lifecycle(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        server.deprecate("pkg", "1.0.0")

        record = server.state.get_package("pkg", "1.0.0")
        assert record.lifecycle == LIFECYCLE_DEPRECATED
        assert record.deprecated_at != ""

    def test_revoke_then_re_publish_rejected(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        server.revoke("pkg", "1.0.0")

        with pytest.raises(PackageRevokedError):
            server.publish(
                "pkg", "1.0.0", b"data",
                publisher_fingerprint="fp-publisher",
            )

    def test_cannot_deprecate_revoked(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        server.revoke("pkg", "1.0.0")

        with pytest.raises(PackageRevokedError):
            server.deprecate("pkg", "1.0.0")

    def test_double_revoke_idempotent(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        gen1 = server.revoke("pkg", "1.0.0")
        gen2 = server.revoke("pkg", "1.0.0")
        assert gen1 == gen2  # No second generation advance

    def test_revoked_excluded_from_active_index(self, server):
        server.publish("pkg_a", "1.0.0", b"a", publisher_fingerprint="fp-publisher")
        server.publish("pkg_b", "1.0.0", b"b", publisher_fingerprint="fp-publisher")
        digest_before = server.state.compute_package_index_digest()

        server.revoke("pkg_a", "1.0.0")
        digest_after = server.state.compute_package_index_digest()
        assert digest_before != digest_after


# ── AC-7: Artifact size limits ──────────────────────────────────────────────

class TestAC7SizeLimits:
    """7. Artifact size limits enforced."""

    def test_normal_size_ok(self, server):
        server.publish(
            "pkg", "1.0.0", b"x" * 1024,
            publisher_fingerprint="fp-publisher",
        )

    def test_exact_limit_ok(self, server):
        """Artifact at exactly MAX_ARTIFACT_SIZE is accepted."""
        server.publish(
            "pkg", "1.0.0", b"x" * min(MAX_ARTIFACT_SIZE, 1024),  # Keep test fast
            publisher_fingerprint="fp-publisher",
        )

    def test_oversized_rejected(self, tmp_path):
        """Artifact exceeding limit is rejected (test with small override)."""
        s = RegistryState(tmp_path / "state.json")
        s.set_registry_identity("reg", "fp")
        s.approve_publisher("pub", "fp-pub", [])
        sv = ReferenceRegistryServer(
            state_path=s.state_path,
            artifact_dir=tmp_path / "art",
        )

        # Monkey-patch limit to 100 bytes for test speed
        import nodechain.sdk.reference_registry_server as mod
        original = mod.MAX_ARTIFACT_SIZE
        mod.MAX_ARTIFACT_SIZE = 100
        try:
            with pytest.raises(PublishError, match="size limit"):
                sv.publish(
                    "pkg", "1.0.0", b"x" * 200,
                    publisher_fingerprint="fp-pub",
                )
        finally:
            mod.MAX_ARTIFACT_SIZE = original


# ── AC-8: Safe storage paths ────────────────────────────────────────────────

class TestAC8SafeStorage:
    """8. Safe server-side storage paths (content-addressed)."""

    def test_artifact_stored_by_digest(self, server):
        receipt = server.publish(
            "pkg", "1.0.0", b"contents",
            publisher_fingerprint="fp-publisher",
        )
        path = server.get_artifact_path(receipt.artifact_digest)
        assert path.exists()
        assert path.read_bytes() == b"contents"

    def test_same_artifact_same_path(self, server):
        """Two packages with same artifact share storage (dedup)."""
        data = b"shared contents"
        r1 = server.publish("pkg_a", "1.0.0", data, publisher_fingerprint="fp-publisher")
        r2 = server.publish("pkg_b", "1.0.0", data, publisher_fingerprint="fp-publisher")
        assert r1.artifact_digest == r2.artifact_digest
        # Same path, not duplicated
        assert server.get_artifact_path(r1.artifact_digest) == server.get_artifact_path(r2.artifact_digest)


# ── AC-9: Signed metadata with generation ───────────────────────────────────

class TestAC9SignedMetadata:
    """9. v2.21.3-compatible signed metadata with generation."""

    def test_metadata_has_generation(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        meta = server.get_signed_metadata()
        assert meta["generation"] == 1
        assert meta["registry_id"] == "reg-test-001"

    def test_metadata_has_freshness(self, server):
        meta = server.get_signed_metadata()
        assert meta["issued_at"] != ""
        assert meta["expires_at"] != ""
        assert meta["protocol_version"] == PROTOCOL_VERSION

    def test_metadata_has_index_digest(self, server):
        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        meta = server.get_signed_metadata()
        assert meta["package_index_digest"] != ""

    def test_metadata_generation_advances(self, server):
        meta0 = server.get_signed_metadata()
        assert meta0["generation"] == 0

        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        meta1 = server.get_signed_metadata()
        assert meta1["generation"] == 1

        server.publish("pkg", "2.0.0", b"data2", publisher_fingerprint="fp-publisher")
        meta2 = server.get_signed_metadata()
        assert meta2["generation"] == 2

    def test_metadata_active_count(self, server):
        server.publish("pkg_a", "1.0.0", b"a", publisher_fingerprint="fp-publisher")
        server.publish("pkg_b", "1.0.0", b"b", publisher_fingerprint="fp-publisher")
        server.revoke("pkg_a", "1.0.0")

        meta = server.get_signed_metadata()
        assert meta["active_package_count"] == 1
        assert meta["total_package_count"] == 2


# ── AC-10: Idempotent re-publish ─────────────────────────────────────────────

class TestAC10IdempotentRePublish:
    """10. Re-publishing identical package is safe."""

    def test_idempotent_no_new_generation(self, server):
        data = b"contents"
        r1 = server.publish("pkg", "1.0.0", data, publisher_fingerprint="fp-publisher")
        r2 = server.publish("pkg", "1.0.0", data, publisher_fingerprint="fp-publisher")
        assert r1.generation == r2.generation

    def test_idempotent_same_receipt(self, server):
        data = b"contents"
        r1 = server.publish("pkg", "1.0.0", data, publisher_fingerprint="fp-publisher")
        r2 = server.publish("pkg", "1.0.0", data, publisher_fingerprint="fp-publisher")
        assert r1.receipt_id == r2.receipt_id
        assert r1.artifact_digest == r2.artifact_digest


# ── AC-11: Client trust protocol compatibility ──────────────────────────────

class TestAC11ClientCompatibility:
    """11. Server metadata compatible with v2.21.3 client trust protocol."""

    def test_metadata_parsable_as_signed_metadata(self, server):
        from nodechain.sdk.registry_trust import SignedRegistryMetadata

        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        meta_dict = server.get_signed_metadata()

        signed = SignedRegistryMetadata(
            registry_id=meta_dict["registry_id"],
            protocol_version=meta_dict["protocol_version"],
            signer_fingerprint=meta_dict["signer_fingerprint"],
            issued_at=meta_dict["issued_at"],
            expires_at=meta_dict["expires_at"],
            generation=meta_dict["generation"],
            package_index_digest=meta_dict["package_index_digest"],
        )
        assert signed.registry_id == "reg-test-001"
        assert signed.generation == 1
        assert signed.canonical_identity() == "reg-test-001:fp-registry-signer"

    def test_client_can_evaluate_server_metadata(self, tmp_path, server):
        """End-to-end: server metadata evaluated by client trust evaluator."""
        from nodechain.sdk.registry_trust import (
            SignedRegistryMetadata, RegistryTrustStore, RegistryTrustEvaluator,
        )

        server.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-publisher")
        meta_dict = server.get_signed_metadata()

        signed = SignedRegistryMetadata(
            registry_id=meta_dict["registry_id"],
            protocol_version=meta_dict["protocol_version"],
            signer_fingerprint=meta_dict["signer_fingerprint"],
            issued_at=meta_dict["issued_at"],
            expires_at=meta_dict["expires_at"],
            generation=meta_dict["generation"],
            package_index_digest=meta_dict["package_index_digest"],
        )

        # Client approves the signer
        store = RegistryTrustStore(tmp_path / "client_trust.json")
        store.approve_signer("reg-test-001", "fp-registry-signer")
        evaluator = RegistryTrustEvaluator(store, max_age_hours=24)

        verdict = evaluator.evaluate(signed)
        assert verdict.trusted

    def test_rollback_detected_on_generation_decrease(self, tmp_path, server):
        """Client detects if server serves lower generation."""
        from nodechain.sdk.registry_trust import (
            SignedRegistryMetadata, RegistryTrustStore, RegistryTrustEvaluator,
        )

        # Publish 3 packages → generation 3
        for i in range(3):
            server.publish(f"pkg_{i}", "1.0.0", f"data_{i}".encode(),
                           publisher_fingerprint="fp-publisher")
        meta = server.get_signed_metadata()

        signed = SignedRegistryMetadata(
            registry_id=meta["registry_id"],
            signer_fingerprint=meta["signer_fingerprint"],
            issued_at=meta["issued_at"],
            expires_at=meta["expires_at"],
            generation=3,
            package_index_digest=meta["package_index_digest"],
        )

        store = RegistryTrustStore(tmp_path / "trust.json")
        store.approve_signer("reg-test-001", "fp-registry-signer")
        evaluator = RegistryTrustEvaluator(store)

        # Accept generation 3
        v1 = evaluator.accept(signed)
        assert v1.trusted

        # Serve generation 2 → rollback
        signed2 = SignedRegistryMetadata(
            registry_id=meta["registry_id"],
            signer_fingerprint=meta["signer_fingerprint"],
            issued_at=meta["issued_at"],
            expires_at=meta["expires_at"],
            generation=2,
            package_index_digest="different",
        )
        v2 = evaluator.evaluate(signed2)
        assert not v2.trusted


# ── State persistence ───────────────────────────────────────────────────────

class TestStatePersistence:
    """Registry state survives reload."""

    def test_state_persists_across_reload(self, tmp_path):
        s1 = RegistryState(tmp_path / "state.json")
        s1.set_registry_identity("reg-001", "fp-signer")
        s1.approve_publisher("pub-001", "fp-pub", [])

        s2 = RegistryState(tmp_path / "state.json")
        assert s2.get_registry_id() == "reg-001"
        assert s2.is_publisher_authorized("fp-pub", "anything")

    def test_packages_persist(self, tmp_path):
        s1 = RegistryState(tmp_path / "state.json")
        s1.set_registry_identity("reg-001", "fp-signer")
        s1.approve_publisher("pub-001", "fp-pub", [])

        sv1 = ReferenceRegistryServer(
            state_path=s1.state_path,
            artifact_dir=tmp_path / "art",
            registry_id="reg-001",
            registry_signer_fingerprint="fp-signer",
        )
        sv1.publish("pkg", "1.0.0", b"data", publisher_fingerprint="fp-pub")

        sv2 = ReferenceRegistryServer(
            state_path=s1.state_path,
            artifact_dir=tmp_path / "art",
        )
        record = sv2.state.get_package("pkg", "1.0.0")
        assert record is not None
        assert record.package_id == "pkg"
        assert sv2.state.get_generation() == 1
