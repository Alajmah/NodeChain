"""Tests for v1.18.2 Evaluation Certification.

Tests cover all 9 acceptance criteria:
  1. nodechain eval certify command
  2. Certification requires passed report, signatures, suite status
  3. Certification artifact fields
  4. Trust store purpose: certification_signing
  5. Certification can be signed
  6. Certification verify checks (8-point)
  7. Strict mode failures
  8. CLI supports verify, revoke, inspect
  9. Windows/Linux green
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
    priv_path = str(tmp_path / f"priv_cert{suffix}.pem")
    pub_path = str(tmp_path / f"pub_cert{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _write_report(tmp_path, **overrides):
    report = {
        "type": "evaluation_report",
        "eval_id": "eval-001",
        "suite_id": "test-suite",
        "suite_version": "1.0.0",
        "suite_digest": "a" * 64,
        "passed": True,
        "valid": True,
        "target_digest": "b" * 64,
        "report_digest": "c" * 64,
        "suite_signature_status": "valid",
        "suite_validity_status": "valid",
        "suite_signer_trusted": True,
        "suite_trust_verified": True,
        "suite_registry_digest": "",
        "nodechain_version": "3.5.0",
        "errors": [],
    }
    report.update(overrides)
    path = str(tmp_path / "report.json")
    Path(path).write_text(json.dumps(report), encoding="utf-8")
    return path, report


def _setup_trust_store(tmp_path, pub_path, name="certifier", purposes=None):
    import os
    if purposes is None:
        purposes = ["certification_signing"]
    ts_path = str(tmp_path / "ts.json")
    os.environ["NODECHAIN_TRUST_STORE"] = ts_path
    from nodechain.cli.trust_store import add_key
    add_key(public_key_path=pub_path, name=name, purposes=purposes)
    del os.environ["NODECHAIN_TRUST_STORE"]
    return ts_path


# ── AC1: Certify Command ───────────────────────────────────────────────────

class TestCreateCertification:
    """AC1: nodechain eval certify creates certification from report."""

    def test_certify_passed_report(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path)
        cert = create_certification(eval_report=report_path)
        assert cert["certification_status"] == "certified"
        assert cert["certification_id"]
        assert cert["type"] == "evaluation_certification"

    def test_certify_denied_for_failed_report(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, passed=False)
        cert = create_certification(eval_report=report_path)
        assert cert["certification_status"] == "denied"
        assert any("did not pass" in e for e in cert["errors"])

    def test_certify_denied_no_target_digest(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, target_digest="")
        cert = create_certification(eval_report=report_path)
        assert cert["certification_status"] == "denied"
        assert any("target_digest" in e for e in cert["errors"])


# ── AC2: Certification Requirements ────────────────────────────────────────

class TestCertificationRequirements:
    """AC2: Certification requires all checks to pass."""

    def test_require_report_signature_pass(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, report_signature_status="valid")
        cert = create_certification(eval_report=report_path, require_report_signature=True)
        assert cert["certification_status"] == "certified"

    def test_require_report_signature_fail(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, report_signature_status="unsigned")
        cert = create_certification(eval_report=report_path, require_report_signature=True)
        assert cert["certification_status"] == "denied"

    def test_require_suite_signature_pass(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, suite_signature_status="valid")
        cert = create_certification(eval_report=report_path, require_suite_signature=True)
        assert cert["certification_status"] == "certified"

    def test_require_suite_signature_fail(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, suite_signature_status="unsigned")
        cert = create_certification(eval_report=report_path, require_suite_signature=True)
        assert cert["certification_status"] == "denied"

    def test_strict_suite_validity_pass(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, suite_validity_status="valid")
        cert = create_certification(eval_report=report_path, strict=True)
        assert cert["certification_status"] == "certified"

    def test_strict_suite_validity_fail(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, suite_validity_status="invalid:expired")
        cert = create_certification(eval_report=report_path, strict=True)
        assert cert["certification_status"] == "denied"


# ── AC3: Certification Artifact Fields ─────────────────────────────────────

class TestCertificationFields:
    """AC3: Certification artifact includes all required fields."""

    def test_has_all_fields(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path)
        cert = create_certification(eval_report=report_path)
        required = [
            "certification_id", "target_type", "target_ref", "target_digest",
            "suite_id", "suite_version", "suite_digest", "eval_report_digest",
            "certifier_fingerprint", "certification_status", "valid_from",
            "valid_until", "issued_at",
        ]
        for field in required:
            assert field in cert, f"Missing field: {field}"

    def test_status_is_certified_or_denied(self, tmp_path):
        from nodechain.cli.certification import CERTIFICATION_STATUSES
        assert "certified" in CERTIFICATION_STATUSES
        assert "denied" in CERTIFICATION_STATUSES
        assert "revoked" in CERTIFICATION_STATUSES

    def test_certification_digest_present(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path)
        cert = create_certification(eval_report=report_path)
        assert cert["certification_digest"]
        assert len(cert["certification_digest"]) == 64


# ── AC4: Trust Store Purpose ───────────────────────────────────────────────

class TestTrustStorePurpose:
    """AC4: certification_signing is a valid trust store purpose."""

    def test_purpose_in_valid_purposes(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "certification_signing" in VALID_PURPOSES

    def test_purpose_count(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert len(VALID_PURPOSES) == 13


# ── AC5: Certification Signing ─────────────────────────────────────────────

class TestCertificationSigning:
    """AC5: Certification can be signed."""

    def test_sign_certification(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, _ = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)

        signed = sign_certification(cert, priv_path)
        assert signed["certification_signature"]
        assert signed["certification_signature_algorithm"] == "RSA-PSS-SHA256"
        assert signed["certifier_fingerprint"]

    def test_sign_writes_file(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, _ = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        out = str(tmp_path / "signed_cert.json")

        sign_certification(cert, priv_path, output_path=out)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["certification_signature"]


# ── AC6: Certification Verification (8-point) ──────────────────────────────

class TestCertificationVerification:
    """AC6: Certification verify checks all 8 points."""

    def test_valid_signed_certification(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, pub_path = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_certification(certification=signed, public_key_pem=pubkey)
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"

    def test_unsigned_certification_fails(self, tmp_path):
        from nodechain.cli.certification import create_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        cert = create_certification(eval_report=report_path)

        result = verify_certification(certification=cert)
        assert result["valid"] is False
        assert "not signed" in result["errors"][0].lower()

    def test_bad_signature_fails(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, _ = _generate_key_pair(tmp_path)
        priv_path2, pub_path2 = _generate_key_pair(tmp_path, suffix="2")
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        wrong_pub = Path(pub_path2).read_text(encoding="utf-8")
        result = verify_certification(certification=signed, public_key_pem=wrong_pub)
        assert result["valid"] is False

    def test_tampered_digest_fails(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, _ = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        signed["certification_digest"] = "0" * 64
        result = verify_certification(certification=signed)
        assert result["valid"] is False

    def test_trust_store_lookup(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, pub_path = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        ts_path = _setup_trust_store(tmp_path, pub_path)
        result = verify_certification(certification=signed, trust_store_path=ts_path)
        assert result["valid"] is True
        assert result["details"]["certifier_trusted"] is True

    def test_wrong_purpose_rejected(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, pub_path = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        ts_path = _setup_trust_store(tmp_path, pub_path, name="wrong",
                                      purposes=["attestation_signing"])
        result = verify_certification(certification=signed, trust_store_path=ts_path)
        assert result["valid"] is False
        assert result["details"]["certifier_trusted"] is False

    def test_denied_status_fails_verify(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path, passed=False)
        priv_path, _ = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        result = verify_certification(certification=signed)
        # status is "denied" not "certified"
        assert result["valid"] is False
        assert any("denied" in e for e in result["errors"])

    def test_expected_target_digest_mismatch(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, _ = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        result = verify_certification(
            certification=signed, expected_target_digest="z" * 64,
        )
        assert result["valid"] is False
        assert any("target digest mismatch" in e.lower() for e in result["errors"])


# ── AC7: Strict Mode Failures ──────────────────────────────────────────────

class TestStrictModeFailures:
    """AC7: Strict mode fails on all invalid conditions."""

    def test_strict_rejects_failed_eval(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, passed=False)
        cert = create_certification(eval_report=report_path, strict=True)
        assert cert["certification_status"] == "denied"

    def test_strict_rejects_unsigned_report(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, report_signature_status="unsigned")
        cert = create_certification(
            eval_report=report_path, strict=True, require_report_signature=True,
        )
        assert cert["certification_status"] == "denied"

    def test_strict_rejects_unsigned_suite(self, tmp_path):
        from nodechain.cli.certification import create_certification
        report_path, _ = _write_report(tmp_path, suite_signature_status="unsigned")
        cert = create_certification(
            eval_report=report_path, strict=True, require_suite_signature=True,
        )
        assert cert["certification_status"] == "denied"


# ── AC8: Revoke and Inspect ────────────────────────────────────────────────

class TestRevokeAndInspect:
    """AC8: Certification can be revoked and inspected."""

    def test_revoke_certification(self, tmp_path):
        from nodechain.cli.certification import create_certification, revoke_certification
        report_path, _ = _write_report(tmp_path)
        cert = create_certification(eval_report=report_path)

        revoked = revoke_certification(cert, reason="superseded")
        assert revoked["certification_status"] == "revoked"
        assert revoked["revoke_reason"] == "superseded"
        assert "revoked_at" in revoked

    def test_revoked_fails_verification(self, tmp_path):
        from nodechain.cli.certification import create_certification, sign_certification, revoke_certification, verify_certification
        report_path, _ = _write_report(tmp_path)
        priv_path, _ = _generate_key_pair(tmp_path)
        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)
        revoked = revoke_certification(signed)

        result = verify_certification(certification=revoked)
        assert result["valid"] is False
        assert any("revoked" in e for e in result["errors"])

    def test_inspect_certification(self, tmp_path):
        from nodechain.cli.certification import create_certification, inspect_certification
        report_path, _ = _write_report(tmp_path)
        cert = create_certification(eval_report=report_path)

        summary = inspect_certification(cert)
        assert summary["certification_status"] == "certified"
        assert summary["suite_id"] == "test-suite"
        assert summary["is_signed"] is False
        assert summary["certification_id"]


# ── Full Flow Integration ──────────────────────────────────────────────────

class TestFullCertificationFlow:
    """End-to-end: evaluate → certify → sign → verify."""

    def test_full_flow(self, tmp_path):
        from nodechain.cli.certification import (
            create_certification, sign_certification, verify_certification,
        )
        # 1. Create report (simulating eval run)
        report_path, _ = _write_report(tmp_path)

        # 2. Certify
        cert = create_certification(eval_report=report_path)
        assert cert["certification_status"] == "certified"

        # 3. Sign
        priv_path, pub_path = _generate_key_pair(tmp_path)
        signed = sign_certification(cert, priv_path)
        assert signed["certification_signature"]

        # 4. Verify
        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_certification(certification=signed, public_key_pem=pubkey)
        assert result["valid"] is True

    def test_full_flow_with_trust_store(self, tmp_path):
        from nodechain.cli.certification import (
            create_certification, sign_certification, verify_certification,
        )
        report_path, _ = _write_report(tmp_path)
        priv_path, pub_path = _generate_key_pair(tmp_path)

        cert = create_certification(eval_report=report_path)
        signed = sign_certification(cert, priv_path)

        ts_path = _setup_trust_store(tmp_path, pub_path)
        result = verify_certification(certification=signed, trust_store_path=ts_path)
        assert result["valid"] is True
        assert result["details"]["certifier_trusted"] is True
