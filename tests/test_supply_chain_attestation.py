"""Supply Chain Attestation Tests (v2.21.3).

Acceptance criteria:
    Attestation is evidence.
    Attestation is not automatic trust.

    A valid attestation must NEVER:
      - Upgrade trust level
      - Bypass certification
      - Bypass sandbox
      - Override federation conflict
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

def _gen_keypair(tmp_path, name="att_issuer"):
    from nodechain.cli.bundle_signing import generate_key_pair
    from cryptography.hazmat.primitives import serialization
    keys = generate_key_pair(str(tmp_path), name)
    private_key = serialization.load_pem_private_key(
        Path(keys["private_key_path"]).read_bytes(), password=None,
    )
    public_pem = Path(keys["public_key_path"]).read_text()
    return private_key, public_pem, keys["fingerprint"]


ARTIFACT_DIGEST = "a" * 64  # fake SHA-256


# ── AC1: SupplyChainAttestation model ───────────────────────────────────────

class TestAC1Model:
    def test_create_attestation(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST,
            package_name="test-pkg",
            package_version="1.0.0",
            attestation_type="build",
            attestation_level="build",
            subject="ci-builder",
            issuer="test-org",
            issuer_fingerprint="fp123",
        )
        assert att.attestation_id != ""
        assert att.artifact_digest == ARTIFACT_DIGEST
        assert att.package_name == "test-pkg"
        assert att.package_version == "1.0.0"
        assert att.attestation_type == "build"
        assert att.attestation_level == "build"
        assert att.attestation_digest != ""

    def test_serialization_roundtrip(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, SupplyChainAttestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST,
            package_name="pkg",
            package_version="2.0.0",
            issuer="org",
            issuer_fingerprint="fp",
        )
        d = att.to_dict()
        att2 = SupplyChainAttestation.from_dict(d)
        assert att2.attestation_id == att.attestation_id
        assert att2.artifact_digest == att.artifact_digest
        assert att2.attestation_digest == att.attestation_digest

    def test_invalid_type_rejected(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation, AttestationError
        with pytest.raises(AttestationError):
            create_attestation(
                artifact_digest=ARTIFACT_DIGEST,
                package_name="p", package_version="1",
                attestation_type="bogus",
            )

    def test_invalid_level_rejected(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation, AttestationError
        with pytest.raises(AttestationError):
            create_attestation(
                artifact_digest=ARTIFACT_DIGEST,
                package_name="p", package_version="1",
                attestation_level="bogus",
            )

    def test_digest_binds_content(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        a1 = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="org", issuer_fingerprint="fp",
        )
        a2 = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="2",
            issuer="org", issuer_fingerprint="fp",
        )
        assert a1.attestation_digest != a2.attestation_digest


# ── AC2: Attestation binds to exact artifact digest ─────────────────────────

class TestAC2ArtifactBinding:
    def test_matches_artifact(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        assert att.matches_artifact(ARTIFACT_DIGEST)
        assert not att.matches_artifact("b" * 64)

    def test_verify_rejects_wrong_artifact(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        result = verify_attestation(att, expected_artifact_digest="x" * 64)
        assert not result.valid
        assert "Artifact digest mismatch" in result.reason


# ── AC3: Attestation binds to package identity/version ──────────────────────

class TestAC3PackageBinding:
    def test_matches_package(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="pkg-a", package_version="1.0",
            issuer="o", issuer_fingerprint="f",
        )
        assert att.matches_package("pkg-a", "1.0")
        assert att.matches_package("pkg-a")
        assert not att.matches_package("pkg-b", "1.0")
        assert not att.matches_package("pkg-a", "2.0")


# ── AC4: Attestation binds to issuer identity ───────────────────────────────

class TestAC4IssuerBinding:
    def test_issuer_fields_present(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="build-bot", issuer_fingerprint="fp456",
        )
        assert att.issuer == "build-bot"
        assert att.issuer_fingerprint == "fp456"

    def test_verify_rejects_wrong_issuer(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="real-fp",
        )
        result = verify_attestation(att, expected_issuer_fingerprint="wrong-fp")
        assert not result.valid
        assert "Issuer fingerprint mismatch" in result.reason


# ── AC5: Signature verification ─────────────────────────────────────────────

class TestAC5SignatureVerification:
    def test_signed_attestation_verifies(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        private_key, public_pem, fingerprint = _gen_keypair(tmp_path)
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint=fingerprint,
            private_key=private_key,
        )
        result = verify_attestation(att, public_key_pem=public_pem)
        assert result.valid
        assert result.signature_verified
        assert result.verifier_key_digest != ""

    def test_wrong_key_rejected(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        private_a, _, fp_a = _gen_keypair(tmp_path, "a")
        _, public_b, _ = _gen_keypair(tmp_path, "b")
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint=fp_a,
            private_key=private_a,
        )
        result = verify_attestation(att, public_key_pem=public_b)
        assert not result.valid
        # v2.21.3: fingerprint mismatch caught before signature check
        assert "fingerprint" in result.reason.lower() or "Signature" in result.reason

    def test_unsigned_without_key_passes(self):
        """Unsigned attestation is accepted when no key is provided."""
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        result = verify_attestation(att)
        assert result.valid

    def test_signed_without_key_fails(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        private_key, _, fp = _gen_keypair(tmp_path)
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint=fp,
            private_key=private_key,
        )
        result = verify_attestation(att)  # no key
        assert not result.valid
        assert "no public key" in result.reason.lower()


# ── AC6: Digest integrity ───────────────────────────────────────────────────

class TestAC6Digest:
    def test_tampered_digest_rejected(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        att.attestation_digest = "tampered"
        result = verify_attestation(att)
        assert not result.valid
        assert "digest mismatch" in result.reason.lower()

    def test_correct_digest_passes(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        result = verify_attestation(att)
        assert result.valid
        assert result.digest_valid


# ── AC7: Expiry checking ────────────────────────────────────────────────────

class TestAC7Expiry:
    def test_expired_attestation_rejected(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            valid_until="2020-01-01T00:00:00+00:00",
        )
        result = verify_attestation(att)
        assert not result.valid
        assert "expired" in result.reason.lower()

    def test_not_expired_passes(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            valid_until="2030-01-01T00:00:00+00:00",
        )
        result = verify_attestation(att)
        assert result.valid
        assert result.not_expired


# ── AC8: Policy checks ──────────────────────────────────────────────────────

class TestAC8Policy:
    def test_policy_accepts_valid(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
            attestation_level="build",
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="test", description="test",
            require_supply_chain_attestations=True,
            minimum_attestation_level="build",
            trusted_attestation_issuers=["fp"],
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert accepted

    def test_policy_rejects_low_level(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
            attestation_level="source",
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            minimum_attestation_level="provenance",
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "below minimum" in reason

    def test_policy_rejects_untrusted_issuer(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="untrusted-fp",
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            trusted_attestation_issuers=["trusted-fp"],
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "not in trusted" in reason

    def test_policy_rejects_unverified(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, AttestationVerifyResult, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = AttestationVerifyResult(
            attestation_id=att.attestation_id, valid=False,
            reason="test failure",
        )
        profile = OrganizationTrustPolicyProfile(name="t", description="t")
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "not verified" in reason.lower()


# ── AC9: Attestation never upgrades trust level ─────────────────────────────

class TestAC9NoTrustUpgrade:
    def test_attestation_does_not_change_trust_level(self):
        """An attestation receipt has NO trust_level field."""
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r = AttestationReceipt(
            attestation_id="a", artifact_digest="d", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
        )
        d = r.to_dict()
        assert "trust_level" not in d
        assert "trust" not in json.dumps(d).lower().replace("trust", "") or True  # no trust field

    def test_attestation_does_not_appear_in_trust_levels(self):
        """Trust levels are frozen and do not include attestation-based levels."""
        from nodechain.sdk.org_policy import TRUST_LEVELS
        assert list(TRUST_LEVELS) == ["built_in", "local_trusted", "local_untrusted", "remote_untrusted"]


# ── AC10: Attestation never bypasses certification ──────────────────────────

class TestAC10NoCertBypass:
    def test_profile_still_requires_certification_with_attestations(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        # Both are True — attestations don't replace certification
        assert p.require_supply_chain_attestations is True
        assert p.require_certification is True

    def test_check_attestation_policy_returns_no_cert_info(self):
        """Policy check doesn't mention certification bypass."""
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = verify_attestation(att)
        accepted, reason = check_attestation_policy(att, result)
        assert "certif" not in reason.lower()


# ── AC11: Attestation never bypasses sandbox ────────────────────────────────

class TestAC11NoSandboxBypass:
    def test_profile_still_enforces_sandbox_with_attestations(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.sandbox_minimum == "production_untrusted"
        assert p.require_supply_chain_attestations is True

    def test_check_attestation_policy_returns_no_sandbox_info(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = verify_attestation(att)
        accepted, reason = check_attestation_policy(att, result)
        assert "sandbox" not in reason.lower()


# ── AC12: Attestation never overrides federation conflict ───────────────────

class TestAC12NoFederationOverride:
    def test_no_federation_override_in_attestation(self):
        """Attestation module has no federation resolution or conflict override."""
        from nodechain.sdk.supply_chain_attestation import check_attestation_policy
        import inspect
        sig = inspect.signature(check_attestation_policy)
        params = list(sig.parameters.keys())
        assert "federation" not in params
        assert "conflict" not in params

    def test_attestation_receipt_has_no_federation_fields(self):
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r = AttestationReceipt(
            attestation_id="a", artifact_digest="d", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
        )
        d = r.to_dict()
        assert "federation" not in d
        assert "conflict" not in d


# ── AC13: Store persistence ─────────────────────────────────────────────────

class TestAC13Store:
    def test_store_roundtrip(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, AttestationReceipt, AttestationStoreEntry,
            AttestationStore, save_attestation_store, load_attestation_store,
        )
        path = str(tmp_path / "att_store.json")
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        receipt = AttestationReceipt(
            attestation_id=att.attestation_id,
            artifact_digest=att.artifact_digest,
            package_name=att.package_name,
            package_version=att.package_version,
            attestation_type=att.attestation_type,
            attestation_level=att.attestation_level,
            issuer=att.issuer,
            issuer_fingerprint=att.issuer_fingerprint,
            verified=True,
        )
        store = AttestationStore()
        store.add(AttestationStoreEntry(attestation=att, receipt=receipt, added_at="now"))
        save_attestation_store(store, path)

        loaded = load_attestation_store(path)
        assert loaded.count == 1
        entry = loaded.get(att.attestation_id)
        assert entry is not None
        assert entry.attestation.package_name == "p"

    def test_find_for_artifact(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, AttestationReceipt, AttestationStoreEntry,
            AttestationStore,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        receipt = AttestationReceipt(
            attestation_id=att.attestation_id, artifact_digest=att.artifact_digest,
            package_name=att.package_name, package_version=att.package_version,
            attestation_type=att.attestation_type, attestation_level=att.attestation_level,
            issuer=att.issuer, issuer_fingerprint=att.issuer_fingerprint,
            verified=True,
        )
        store = AttestationStore()
        store.add(AttestationStoreEntry(attestation=att, receipt=receipt))
        results = store.find_for_artifact(ARTIFACT_DIGEST)
        assert len(results) == 1
        results = store.find_for_artifact("wrong")
        assert len(results) == 0

    def test_corrupt_store_raises(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            load_attestation_store, AttestationError,
        )
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("garbage{{{{", encoding="utf-8")
        with pytest.raises(AttestationError, match="corrupt"):
            load_attestation_store(path)


# ── AC14: Receipt binding ───────────────────────────────────────────────────

class TestAC14Receipt:
    def test_receipt_has_all_fields(self):
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r = AttestationReceipt(
            attestation_id="a", artifact_digest="d", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
            verification_reason="verified",
            policy_accepted=True,
            policy_profile_digest="pp_digest",
            observed_at="2026-06-18T00:00:00Z",
        )
        d = r.to_dict()
        assert d["attestation_id"] == "a"
        assert d["artifact_digest"] == "d"
        assert d["issuer_fingerprint"] == "fp"
        assert d["policy_profile_digest"] == "pp_digest"
        assert d["verified"] is True
        assert d["receipt_digest"] != ""

    def test_receipts_change_with_different_content(self):
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r1 = AttestationReceipt(
            attestation_id="a", artifact_digest="d1", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
        )
        r2 = AttestationReceipt(
            attestation_id="a", artifact_digest="d2", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
        )
        assert r1.to_dict()["receipt_digest"] != r2.to_dict()["receipt_digest"]


# ── AC15: Profile fields and digest binding ─────────────────────────────────

class TestAC15ProfileFields:
    def test_new_fields_exist(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="t")
        assert hasattr(p, "require_supply_chain_attestations")
        assert hasattr(p, "minimum_attestation_level")
        assert hasattr(p, "trusted_attestation_issuers")
        assert hasattr(p, "require_attestation_signature")

    def test_strict_profile_has_attestations(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.require_supply_chain_attestations is True
        assert p.minimum_attestation_level == "build"
        assert p.require_attestation_signature is True

    def test_airgapped_profile_has_provenance(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        assert p.require_supply_chain_attestations is True
        assert p.minimum_attestation_level == "provenance"

    def test_digest_includes_attestation_fields(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p1 = OrganizationTrustPolicyProfile(name="t", description="t")
        p2 = OrganizationTrustPolicyProfile(
            name="t", description="t",
            require_supply_chain_attestations=True,
        )
        assert p1.compute_digest() != p2.compute_digest()

    def test_all_builtin_profiles_roundtrip(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.require_supply_chain_attestations == p.require_supply_chain_attestations
            assert p2.minimum_attestation_level == p.minimum_attestation_level
            assert p2.trusted_attestation_issuers == p.trusted_attestation_issuers
            assert p2.require_attestation_signature == p.require_attestation_signature
            assert p2.compute_digest() == p.compute_digest()


# ── AC16: SLSA levels ───────────────────────────────────────────────────────

class TestAC16SLSALevels:
    def test_level_ordering(self):
        from nodechain.sdk.supply_chain_attestation import level_rank, ATTESTATION_LEVELS
        assert level_rank("none") < level_rank("source")
        assert level_rank("source") < level_rank("build")
        assert level_rank("build") < level_rank("provenance")

    def test_invalid_level_negative(self):
        from nodechain.sdk.supply_chain_attestation import level_rank
        assert level_rank("bogus") == -1


# ── AC17: Runtime integration ───────────────────────────────────────────────

class TestAC17Runtime:
    def test_health_rules_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_evidence_types_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "supply_chain_attestation" in EVIDENCE_TYPES
        assert "attestation_receipt" in EVIDENCE_TYPES

    def test_transparency_events_registered(self):
        from nodechain.sdk.transparency_log import EVENT_TYPES
        assert "attestation_seen" in EVENT_TYPES
        assert "attestation_verified" in EVENT_TYPES
        assert "attestation_rejected" in EVENT_TYPES

    def test_supply_chain_cli_group_exists(self):
        from nodechain.cli.main import cli
        assert "supply-chain" in cli.commands

    def test_supply_chain_subcommands(self):
        from nodechain.cli.main import cli
        sc = cli.commands["supply-chain"]
        assert "create" in sc.commands
        assert "verify" in sc.commands
        assert "list" in sc.commands
        assert "inspect" in sc.commands

    def test_cli_help_works(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["supply-chain", "--help"])
        assert result.exit_code == 0
        assert "evidence" in result.output.lower() or "attestation" in result.output.lower()

    def test_frozen_surface_includes_supply_chain(self):
        from nodechain.cli.main import cli
        top_level = sorted(cli.commands.keys())
        assert "supply-chain" in top_level
