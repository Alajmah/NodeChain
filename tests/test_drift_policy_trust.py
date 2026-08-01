"""Tests for v1.16.0 Drift Policy Trust.

Tests cover all 7 acceptance criteria:
  1. Drift policies can be signed
  2. Drift policy signer keys use trust-store purpose: drift_policy_signing
  3. --require-policy-signature verifies against trust store
  4. Strict mode fails on unsigned/untrusted/wrong-purpose/invalid/mismatched
  5. Drift report records policy signature evidence
  6. Default unsigned policy allowed in non-strict compatibility
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _generate_key_pair(tmp_path, suffix=""):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = str(tmp_path / f"priv_pt{suffix}.pem")
    pub_path = str(tmp_path / f"pub_pt{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _setup_history(tmp_path, artifact_digest="a" * 64, target="pve1/801"):
    from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
    rh_path = str(tmp_path / "rh.json")
    history = ReleaseHistory(path=rh_path)
    history.add(ReleaseRecord(
        release_id="rel-pt-001",
        artifact_digest=artifact_digest,
        final_deployment_state="applied",
        activation_verified=True,
        target=target,
        deployment_receipt_digest="r" * 64,
    ))
    return rh_path


def _write_policy(tmp_path, **overrides):
    policy = {
        "required_fields": ["artifact_digest", "service_state"],
        "advisory_fields": [],
        "ignored_fields": [],
        "acceptable_drift": {},
        "evidence_strength_required": {},
        "strict_mode": False,
    }
    policy.update(overrides)
    path = str(tmp_path / "drift_policy.json")
    Path(path).write_text(json.dumps(policy), encoding="utf-8")
    return path


def _setup_trust_store(tmp_path, pub_path, name="drift-signer", purposes=None):
    """Set up a trust store with a known key."""
    if purposes is None:
        purposes = ["drift_policy_signing"]
    import os
    ts_path = str(tmp_path / "trust_store.json")
    os.environ["NODECHAIN_TRUST_STORE"] = ts_path
    from nodechain.cli.trust_store import add_key
    add_key(
        public_key_path=pub_path,
        name=name,
        purposes=purposes,
    )
    del os.environ["NODECHAIN_TRUST_STORE"]
    return ts_path


# ── AC1: Drift Policy Signing ─────────────────────────────────────────────

class TestDriftPolicySigning:
    """AC1: Drift policies can be signed."""

    def test_sign_policy(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy
        priv_path, _ = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)

        signed = sign_drift_policy(policy_path, priv_path)
        assert "policy_signature" in signed
        assert signed["policy_signature_algorithm"] == "RSA-PSS-SHA256"
        assert "policy_signer_fingerprint" in signed
        assert signed["policy_signer_fingerprint"]
        assert signed.get("type") == "signed_drift_policy"

    def test_sign_policy_writes_file(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy
        priv_path, _ = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)
        out_path = str(tmp_path / "signed_policy.json")

        sign_drift_policy(policy_path, priv_path, output_path=out_path)
        data = json.loads(Path(out_path).read_text(encoding="utf-8"))
        assert "policy_signature" in data
        assert data["type"] == "signed_drift_policy"

    def test_signed_policy_has_digest(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy
        priv_path, _ = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)

        signed = sign_drift_policy(policy_path, priv_path)
        assert "policy_digest" in signed
        assert len(signed["policy_digest"]) == 64  # SHA-256 hex


# ── AC2: Trust Store Purpose ──────────────────────────────────────────────

class TestTrustStorePurpose:
    """AC2: drift_policy_signing is a valid trust store purpose."""

    def test_purpose_in_valid_purposes(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "drift_policy_signing" in VALID_PURPOSES

    def test_purpose_count(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert len(VALID_PURPOSES) == 13

    def test_add_key_with_purpose(self, tmp_path):
        import os
        from nodechain.cli.trust_store import load_trust_store
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = _setup_trust_store(tmp_path, pub_path, purposes=["drift_policy_signing"])

        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        try:
            store = load_trust_store()
            key_info = store["keys"]["drift-signer"]
            assert "drift_policy_signing" in key_info["allowed_purposes"]
        finally:
            del os.environ["NODECHAIN_TRUST_STORE"]


# ── AC3: Policy Signature Verification ─────────────────────────────────────

class TestPolicySignatureVerification:
    """AC3: --require-policy-signature verifies policy signature."""

    def test_valid_signed_policy(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, verify_drift_policy_signature
        priv_path, pub_path = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)

        sign_drift_policy(policy_path, priv_path, output_path=str(tmp_path / "signed.json"))
        pubkey_pem = Path(pub_path).read_text(encoding="utf-8")
        result = verify_drift_policy_signature(
            policy_path=str(tmp_path / "signed.json"),
            public_key_pem=pubkey_pem,
        )
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"

    def test_unsigned_policy_fails(self, tmp_path):
        from nodechain.cli.drift_detection import verify_drift_policy_signature
        policy_path = _write_policy(tmp_path)
        result = verify_drift_policy_signature(policy_path=policy_path)
        assert result["valid"] is False
        assert "not signed" in result["errors"][0].lower()

    def test_tampered_policy_fails(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, verify_drift_policy_signature
        priv_path, _ = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_drift_policy(policy_path, priv_path, output_path=out)

        # Tamper with digest
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        data["policy_digest"] = "0" * 64
        Path(out).write_text(json.dumps(data), encoding="utf-8")

        result = verify_drift_policy_signature(policy_path=out)
        assert result["valid"] is False
        assert any("digest mismatch" in e.lower() for e in result["errors"])

    def test_bad_signature_fails(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, verify_drift_policy_signature
        priv_path, pub_path = _generate_key_pair(tmp_path)
        priv_path2, pub_path2 = _generate_key_pair(tmp_path, suffix="2")
        policy_path = _write_policy(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_drift_policy(policy_path, priv_path, output_path=out)

        # Verify with WRONG key
        wrong_pubkey = Path(pub_path2).read_text(encoding="utf-8")
        result = verify_drift_policy_signature(
            policy_path=out, public_key_pem=wrong_pubkey,
        )
        assert result["valid"] is False
        assert result["details"]["signature_status"] == "invalid"

    def test_trust_store_lookup(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, verify_drift_policy_signature
        priv_path, pub_path = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_drift_policy(policy_path, priv_path, output_path=out)

        ts_path = _setup_trust_store(tmp_path, pub_path, purposes=["drift_policy_signing"])
        result = verify_drift_policy_signature(
            policy_path=out, trust_store_path=ts_path,
        )
        assert result["valid"] is True
        assert result["details"]["signer_trusted"] is True
        assert result["details"]["signer_purpose_ok"] is True


# ── AC4: Strict Mode Failures ──────────────────────────────────────────────

class TestStrictModePolicyFailures:
    """AC4: Strict mode fails on various policy trust failures."""

    def test_unsigned_policy_rejected_when_required(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy_path = _write_policy(tmp_path)

        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy_path,
            require_policy_signature=True,
        )
        assert result["valid"] is False
        assert "signature" in result.get("error", "").lower()

    def test_wrong_purpose_rejected(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, check_drift
        priv_path, pub_path = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_drift_policy(policy_path, priv_path, output_path=out)

        # Trust store with WRONG purpose
        ts_path = _setup_trust_store(tmp_path, pub_path, name="wrong-purpose-signer",
                                      purposes=["attestation_signing"])  # wrong purpose!

        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=out,
            require_policy_signature=True,
            trust_store_path=ts_path,
        )
        assert result["valid"] is False
        assert result["policy_signer_trusted"] is False

    def test_valid_signed_policy_accepted(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, check_drift
        priv_path, pub_path = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_drift_policy(policy_path, priv_path, output_path=out)

        ts_path = _setup_trust_store(tmp_path, pub_path, purposes=["drift_policy_signing"])

        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=out,
            require_policy_signature=True,
            trust_store_path=ts_path,
        )
        assert result["valid"] is True
        assert result["policy_signature_status"] == "valid"
        assert result["policy_signer_trusted"] is True


# ── AC5: Drift Report Records Policy Evidence ──────────────────────────────

class TestDriftReportPolicyEvidence:
    """AC5: Drift report records policy signature evidence."""

    def test_report_has_policy_sig_fields(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
        )
        report = create_drift_report(result)
        assert "policy_signature_status" in report
        assert "policy_signer_fingerprint" in report
        assert "policy_signer_trusted" in report

    def test_report_records_unsigned_status(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
        )
        report = create_drift_report(result)
        assert report["policy_signature_status"] == "unsigned"

    def test_report_records_valid_status(self, tmp_path):
        from nodechain.cli.drift_detection import sign_drift_policy, check_drift, create_drift_report
        priv_path, pub_path = _generate_key_pair(tmp_path)
        policy_path = _write_policy(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_drift_policy(policy_path, priv_path, output_path=out)
        ts_path = _setup_trust_store(tmp_path, pub_path)

        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=out,
            require_policy_signature=True,
            trust_store_path=ts_path,
        )
        report = create_drift_report(result)
        assert report["policy_signature_status"] == "valid"
        assert report["policy_signer_trusted"] is True


# ── AC6: Default Unsigned Policy Allowed ──────────────────────────────────

class TestDefaultUnsignedCompatibility:
    """AC6: Default unsigned policy remains allowed in non-strict mode."""

    def test_unsigned_policy_works_without_requirement(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy_path = _write_policy(tmp_path)

        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy_path,
            # NOT requiring signature
        )
        assert result["valid"] is True
        assert result["drift_detected"] is False

    def test_no_policy_still_works(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
        )
        assert result["valid"] is True
        assert result["drift_detected"] is False

    def test_backward_compat_v140_tests_still_pass(self, tmp_path):
        """v1.14.0 check_drift calls with no policy still work identically."""
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-pt-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,
        )
        assert result["drift_detected"] is True
        assert "artifact_digest" in result["drift_fields"]


# ── Trust Store Purpose Validation ─────────────────────────────────────────

class TestTrustStorePurposeValidation:
    """Additional tests for trust store purpose validation."""

    def test_unknown_purpose_rejected(self, tmp_path):
        import os
        from nodechain.cli.trust_store import add_key
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = str(tmp_path / "ts.json")
        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        try:
            with pytest.raises(ValueError, match="Unknown purpose"):
                add_key(
                    public_key_path=pub_path,
                    name="bad-key",
                    purposes=["drift_policy_signing", "unknown_purpose"],
                )
        finally:
            del os.environ["NODECHAIN_TRUST_STORE"]

    def test_is_trusted_fingerprint_with_purpose(self, tmp_path):
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = _setup_trust_store(tmp_path, pub_path, purposes=["drift_policy_signing"])

        store = json.loads(Path(ts_path).read_text())
        fp = store["keys"]["drift-signer"]["fingerprint"]

        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        try:
            assert is_trusted_fingerprint(fp, purpose="drift_policy_signing") is True
            assert is_trusted_fingerprint(fp, purpose="attestation_signing") is False
        finally:
            del os.environ["NODECHAIN_TRUST_STORE"]

    def test_is_trusted_fingerprint_no_purpose(self, tmp_path):
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = _setup_trust_store(tmp_path, pub_path, purposes=["drift_policy_signing"])

        store = json.loads(Path(ts_path).read_text())
        fp = store["keys"]["drift-signer"]["fingerprint"]

        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        try:
            assert is_trusted_fingerprint(fp) is True
        finally:
            del os.environ["NODECHAIN_TRUST_STORE"]
