"""Supply Chain Attestation Adversarial Test Suite (v2.21.3).

20 acceptance criteria attacking the attestation boundary.

Core rules:
    Attestation is evidence. Attestation is not automatic trust.
    A valid attestation must NEVER:
      - Upgrade trust level
      - Bypass certification
      - Bypass sandbox
      - Override federation conflict

    Cryptographically valid issuer ≠ issuer authorized by this organization.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

ARTIFACT_DIGEST = "a" * 64


def _gen_keypair(tmp_path, name="att_signer"):
    from nodechain.cli.bundle_signing import generate_key_pair
    from cryptography.hazmat.primitives import serialization
    keys = generate_key_pair(str(tmp_path), name)
    private_key = serialization.load_pem_private_key(
        Path(keys["private_key_path"]).read_bytes(), password=None,
    )
    public_pem = Path(keys["public_key_path"]).read_text()
    return private_key, public_pem, keys["fingerprint"]


def _make_att(tmp_path, **kwargs):
    """Create a signed attestation."""
    from nodechain.sdk.supply_chain_attestation import create_attestation
    defaults = dict(
        artifact_digest=ARTIFACT_DIGEST,
        package_name="pkg-a",
        package_version="1.0.0",
        attestation_type="build",
        attestation_level="build",
        subject="ci-builder",
        issuer="test-org",
        issuer_fingerprint="fp-test",
    )
    defaults.update(kwargs)
    private_key = defaults.pop("private_key", None)
    return create_attestation(private_key=private_key, **defaults)


# ── AC1: Tampered digest rejected ───────────────────────────────────────────

class TestAC1TamperedDigest:
    def test_modified_digest_rejected(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        att.attestation_digest = "tampered123"
        result = verify_attestation(att)
        assert not result.valid
        assert "mismatch" in result.reason.lower()

    def test_correct_digest_accepted(self):
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


# ── AC2: Content tampering after signing ────────────────────────────────────

class TestAC2ContentTampering:
    def test_modifying_artifact_after_digest(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, compute_attestation_digest,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        # Tamper with content but keep old digest
        old_digest = att.attestation_digest
        att.package_version = "2.0.0"
        att.attestation_digest = old_digest
        result = verify_attestation(att)
        assert not result.valid
        assert "mismatch" in result.reason.lower()

    def test_modifying_issuer_after_digest(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="real-issuer", issuer_fingerprint="real-fp",
        )
        old_digest = att.attestation_digest
        att.issuer = "fake-issuer"
        att.attestation_digest = old_digest
        result = verify_attestation(att)
        assert not result.valid


# ── AC3: Signature from different key ───────────────────────────────────────

class TestAC3SignatureFromDifferentKey:
    def test_wrong_key_rejected(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        priv_a, _, fp_a = _gen_keypair(tmp_path, "key_a")
        _, pub_b, _ = _gen_keypair(tmp_path, "key_b")
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint=fp_a,
            private_key=priv_a,
        )
        result = verify_attestation(att, public_key_pem=pub_b)
        assert not result.valid
        # v2.21.3: fingerprint mismatch detected before or during signature check
        assert "signature" in result.reason.lower() or "fingerprint" in result.reason.lower()

    def test_no_key_with_signature_fails(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        priv, _, fp = _gen_keypair(tmp_path)
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint=fp,
            private_key=priv,
        )
        result = verify_attestation(att)
        assert not result.valid
        assert "no public key" in result.reason.lower()


# ── AC4: Expired attestation ────────────────────────────────────────────────

class TestAC4Expired:
    def test_expired_rejected(self):
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

    def test_future_valid_passes(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            valid_until="2030-12-31T00:00:00+00:00",
        )
        result = verify_attestation(att)
        assert result.valid

    def test_invalid_expiry_treated_as_expired(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            valid_until="not-a-date",
        )
        result = verify_attestation(att)
        assert not result.valid
        assert "expired" in result.reason.lower()


# ── AC5: Cross-package attack ───────────────────────────────────────────────

class TestAC5CrossPackage:
    def test_attestation_for_wrong_package_rejected(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="pkg-a", package_version="1.0",
            issuer="o", issuer_fingerprint="f",
        )
        # Verify is fine, but matches_package won't match pkg-b
        assert att.matches_package("pkg-b") is False

    def test_cross_artifact_attack(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        result = verify_attestation(att, expected_artifact_digest="b" * 64)
        assert not result.valid
        assert "Artifact digest" in result.reason


# ── AC6: Level downgrade ────────────────────────────────────────────────────

class TestAC6LevelDowngrade:
    def test_source_level_rejected_when_build_required(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            attestation_level="source",
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            minimum_attestation_level="build",
            require_attestation_signature=False,
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "below minimum" in reason

    def test_provenance_accepted_when_build_required(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            attestation_level="provenance",
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            minimum_attestation_level="build",
            require_attestation_signature=False,
        )
        accepted, _ = check_attestation_policy(att, result, profile)
        assert accepted


# ── AC7: Empty issuer allowlist fails closed (v2.21.3 fix) ──────────────────

class TestAC7EmptyIssuerAllowlist:
    def test_empty_allowlist_fails_when_sig_required(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            require_attestation_signature=True,
            trusted_attestation_issuers=[],  # empty!
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "empty" in reason.lower()

    def test_builtin_strict_fails_with_empty_allowlist(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
            attestation_level="build",
        )
        result = verify_attestation(att)
        profile = get_builtin_profile("strict_enterprise")
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "empty" in reason.lower()

    def test_allow_any_opt_in_works_without_allowlist(self):
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
        # Mock a verified signature
        result.signature_verified = True
        profile = OrganizationTrustPolicyProfile(
            name="open", description="open",
            require_supply_chain_attestations=True,
            require_attestation_signature=True,
            trusted_attestation_issuers=[],
            allow_any_attestation_issuer=True,
        )
        accepted, _ = check_attestation_policy(att, result, profile)
        assert accepted


# ── AC8: Untrusted issuer rejected ──────────────────────────────────────────

class TestAC8UntrustedIssuer:
    def test_issuer_not_in_list(self):
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
            require_attestation_signature=False,
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted
        assert "not in trusted" in reason


# ── AC9: Attestation never upgrades trust ───────────────────────────────────

class TestAC9NoTrustUpgrade:
    def test_receipt_has_no_trust_level_field(self):
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r = AttestationReceipt(
            attestation_id="a", artifact_digest="d", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
        )
        d = r.to_dict()
        assert "trust_level" not in d
        assert "trust" not in [k for k in d if "trust" in k]

    def test_policy_check_returns_no_trust_upgrade(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
        )
        result = verify_attestation(att)
        accepted, reason = check_attestation_policy(att, result)
        assert "trust" not in reason.lower()

    def test_verify_result_has_no_trust_level(self):
        from nodechain.sdk.supply_chain_attestation import AttestationVerifyResult
        r = AttestationVerifyResult(attestation_id="a", valid=True)
        d = r.to_dict()
        assert "trust_level" not in d


# ── AC10: Attestation never bypasses certification ──────────────────────────

class TestAC10NoCertBypass:
    def test_strict_profile_still_requires_certification(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.require_certification is True
        assert p.require_supply_chain_attestations is True

    def test_attestation_policy_does_not_mention_cert(self):
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
    def test_strict_profile_still_enforces_sandbox(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.sandbox_minimum == "production_untrusted"

    def test_policy_check_has_no_sandbox_impact(self):
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


# ── AC12: Attestation never overrides federation ────────────────────────────

class TestAC12NoFederationOverride:
    def test_no_federation_in_policy_check(self):
        from nodechain.sdk.supply_chain_attestation import check_attestation_policy
        import inspect
        sig = inspect.signature(check_attestation_policy)
        assert "federation" not in sig.parameters

    def test_no_federation_in_receipt(self):
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r = AttestationReceipt(
            attestation_id="a", artifact_digest="d", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
        )
        d = r.to_dict()
        assert "federation" not in str(d).lower()


# ── AC13: Statement injection ───────────────────────────────────────────────

class TestAC13StatementInjection:
    def test_statement_is_just_a_dict(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            statement={"malicious": True, "trust_level": "built_in", "sandbox": "none"},
        )
        # Statement fields are informational only
        assert att.statement["trust_level"] == "built_in"  # it's just text
        # But they don't affect verification
        from nodechain.sdk.supply_chain_attestation import verify_attestation
        result = verify_attestation(att)
        assert result.valid  # statement is not verified or acted upon

    def test_statement_included_in_digest(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        a1 = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            statement={"v": 1},
        )
        a2 = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
            statement={"v": 2},
        )
        assert a1.attestation_digest != a2.attestation_digest


# ── AC14: Replay across versions ────────────────────────────────────────────

class TestAC14ReplayAttack:
    def test_v1_attestation_not_accepted_for_v2(self):
        """An attestation for v1 should not match v2."""
        from nodechain.sdk.supply_chain_attestation import create_attestation
        att_v1 = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="pkg", package_version="1.0",
            issuer="o", issuer_fingerprint="f",
        )
        assert not att_v1.matches_package("pkg", "2.0")

    def test_different_artifact_different_attestation_id(self):
        from nodechain.sdk.supply_chain_attestation import create_attestation
        a1 = create_attestation(
            artifact_digest="a" * 64, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        a2 = create_attestation(
            artifact_digest="b" * 64, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="f",
        )
        assert a1.attestation_id != a2.attestation_id


# ── AC15: Store corruption ──────────────────────────────────────────────────

class TestAC15StoreCorruption:
    def test_corrupt_json_raises(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            load_attestation_store, AttestationError,
        )
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("not json{{{", encoding="utf-8")
        with pytest.raises(AttestationError, match="corrupt"):
            load_attestation_store(path)

    def test_missing_store_returns_empty(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import load_attestation_store
        path = str(tmp_path / "nonexistent.json")
        store = load_attestation_store(path)
        assert store.count == 0

    def test_store_roundtrip_preserves_data(self, tmp_path):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, AttestationReceipt, AttestationStoreEntry,
            AttestationStore, save_attestation_store, load_attestation_store,
        )
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp", attestation_level="provenance",
        )
        receipt = AttestationReceipt(
            attestation_id=att.attestation_id, artifact_digest=att.artifact_digest,
            package_name=att.package_name, package_version=att.package_version,
            attestation_type=att.attestation_type, attestation_level=att.attestation_level,
            issuer=att.issuer, issuer_fingerprint=att.issuer_fingerprint,
            verified=True, policy_accepted=True, policy_profile_digest="pp",
        )
        store = AttestationStore()
        store.add(AttestationStoreEntry(attestation=att, receipt=receipt, added_at="now"))
        path = str(tmp_path / "store.json")
        save_attestation_store(store, path)
        loaded = load_attestation_store(path)
        entry = loaded.get(att.attestation_id)
        assert entry is not None
        assert entry.attestation.attestation_level == "provenance"
        assert entry.receipt.policy_accepted is True


# ── AC16: Receipt binding integrity ─────────────────────────────────────────

class TestAC16ReceiptBinding:
    def test_receipt_digest_changes_with_content(self):
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

    def test_receipt_binds_policy_profile(self):
        from nodechain.sdk.supply_chain_attestation import AttestationReceipt
        r = AttestationReceipt(
            attestation_id="a", artifact_digest="d", package_name="p",
            package_version="1", attestation_type="build", attestation_level="build",
            issuer="o", issuer_fingerprint="fp", verified=True,
            policy_profile_digest="abc123",
        )
        assert r.to_dict()["policy_profile_digest"] == "abc123"


# ── AC17: Profile serialization and digest binding ──────────────────────────

class TestAC17ProfileBinding:
    def test_new_field_in_roundtrip(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(
            name="t", description="t",
            allow_any_attestation_issuer=True,
        )
        d = p.to_dict()
        assert d["allow_any_attestation_issuer"] is True
        p2 = OrganizationTrustPolicyProfile.from_dict(d)
        assert p2.allow_any_attestation_issuer is True

    def test_digest_changes_with_field(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p1 = OrganizationTrustPolicyProfile(name="t", description="t")
        p2 = OrganizationTrustPolicyProfile(
            name="t", description="t",
            allow_any_attestation_issuer=True,
        )
        assert p1.compute_digest() != p2.compute_digest()

    def test_all_builtin_profiles_roundtrip(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.allow_any_attestation_issuer == p.allow_any_attestation_issuer
            assert p2.compute_digest() == p.compute_digest()


# ── AC18: Attestation types ─────────────────────────────────────────────────

class TestAC18Types:
    def test_all_types_accepted(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, ATTESTATION_TYPES,
        )
        for t in ATTESTATION_TYPES:
            att = create_attestation(
                artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
                issuer="o", issuer_fingerprint="f",
                attestation_type=t,
            )
            assert att.attestation_type == t

    def test_invalid_type_rejected(self):
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, AttestationError,
        )
        with pytest.raises(AttestationError):
            create_attestation(
                artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
                issuer="o", issuer_fingerprint="f",
                attestation_type="fake_type",
            )


# ── AC19: Enforcement order preserved ───────────────────────────────────────

class TestAC19EnforcementOrder:
    def test_attestation_evaluated_last(self):
        """Attestation is evidence evaluated after hard gates, not instead of them."""
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
            attestation_level="provenance",
        )
        # Even with provenance-level attestation, if verification fails,
        # the policy check still rejects
        from nodechain.sdk.supply_chain_attestation import AttestationVerifyResult
        failed_result = AttestationVerifyResult(
            attestation_id=att.attestation_id,
            valid=False,
            reason="intentionally failed",
        )
        profile = OrganizationTrustPolicyProfile(name="t", description="t")
        accepted, reason = check_attestation_policy(att, failed_result, profile)
        assert not accepted
        assert "not verified" in reason.lower()

    def test_valid_attestation_does_not_short_circuit_profile(self):
        """Even a valid attestation goes through the full policy pipeline."""
        from nodechain.sdk.supply_chain_attestation import (
            create_attestation, verify_attestation, check_attestation_policy,
        )
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        att = create_attestation(
            artifact_digest=ARTIFACT_DIGEST, package_name="p", package_version="1",
            issuer="o", issuer_fingerprint="fp",
            attestation_level="source",  # too low
        )
        result = verify_attestation(att)
        profile = OrganizationTrustPolicyProfile(
            name="strict", description="strict",
            require_supply_chain_attestations=True,
            minimum_attestation_level="provenance",  # higher than source
        )
        accepted, reason = check_attestation_policy(att, result, profile)
        assert not accepted


# ── AC20: Runtime integration ───────────────────────────────────────────────

class TestAC20Runtime:
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

    def test_cli_group(self):
        from nodechain.cli.main import cli
        assert "supply-chain" in cli.commands
        sc = cli.commands["supply-chain"]
        assert "create" in sc.commands
        assert "verify" in sc.commands
        assert "list" in sc.commands
        assert "inspect" in sc.commands

    def test_frozen_surface(self):
        from nodechain.cli.main import cli
        assert "supply-chain" in cli.commands
