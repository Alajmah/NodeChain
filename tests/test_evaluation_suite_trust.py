"""Tests for v1.18.2 Evaluation Suite Trust.

Tests cover all 7 acceptance criteria:
  1. Evaluation suites can be signed
  2. Trust store purpose: evaluation_suite_signing
  3. --require-suite-signature verifies against trust store
  4. Evaluation report records suite signature evidence
  5. Strict mode fails on unsigned/invalid/untrusted
  6. Backward compatibility with unsigned suites
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
    priv_path = str(tmp_path / f"priv_est{suffix}.pem")
    pub_path = str(tmp_path / f"pub_est{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _write_suite_json(tmp_path, **overrides):
    suite = {
        "suite_id": "trust-test-suite",
        "suite_version": "1.0.0",
        "target_type": "chain",
        "target_ref": "test",
        "cases": [{"case_id": "c1"}],
        "metrics": ["correctness"],
        "thresholds": {},
    }
    suite.update(overrides)
    path = str(tmp_path / "suite.json")
    Path(path).write_text(json.dumps(suite), encoding="utf-8")
    return path


def _setup_trust_store(tmp_path, pub_path, name="suite-signer", purposes=None):
    import os
    if purposes is None:
        purposes = ["evaluation_suite_signing"]
    ts_path = str(tmp_path / "ts.json")
    os.environ["NODECHAIN_TRUST_STORE"] = ts_path
    from nodechain.cli.trust_store import add_key
    add_key(public_key_path=pub_path, name=name, purposes=purposes)
    del os.environ["NODECHAIN_TRUST_STORE"]
    return ts_path


# ── AC1: Suite Signing ─────────────────────────────────────────────────────

class TestSuiteSigning:
    """AC1: Evaluation suites can be signed."""

    def test_sign_suite(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite
        priv_path, _ = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)

        signed = sign_evaluation_suite(suite_path, priv_path)
        assert "suite_signature" in signed
        assert signed["suite_signature_algorithm"] == "RSA-PSS-SHA256"
        assert "suite_signer_fingerprint" in signed
        assert signed.get("type") == "signed_evaluation_suite"
        assert "suite_digest" in signed

    def test_sign_writes_file(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite
        priv_path, _ = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed_suite.json")

        sign_evaluation_suite(suite_path, priv_path, output_path=out)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert "suite_signature" in data


# ── AC2: Trust Store Purpose ───────────────────────────────────────────────

class TestTrustStorePurpose:
    """AC2: evaluation_suite_signing is a valid purpose."""

    def test_purpose_in_valid_purposes(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "evaluation_suite_signing" in VALID_PURPOSES

    def test_purpose_count(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert len(VALID_PURPOSES) == 13

    def test_add_key_with_purpose(self, tmp_path):
        import os
        from nodechain.cli.trust_store import load_trust_store
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = _setup_trust_store(tmp_path, pub_path)

        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        try:
            store = load_trust_store()
            assert "evaluation_suite_signing" in store["keys"]["suite-signer"]["allowed_purposes"]
        finally:
            del os.environ["NODECHAIN_TRUST_STORE"]


# ── AC3: Suite Signature Verification ──────────────────────────────────────

class TestSuiteSignatureVerification:
    """AC3: --require-suite-signature verifies against trust store."""

    def test_valid_signed_suite(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, verify_evaluation_suite_signature
        priv_path, pub_path = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_evaluation_suite_signature(suite_path=out, public_key_pem=pubkey)
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"

    def test_unsigned_suite_fails(self, tmp_path):
        from nodechain.cli.evaluation import verify_evaluation_suite_signature
        suite_path = _write_suite_json(tmp_path)
        result = verify_evaluation_suite_signature(suite_path=suite_path)
        assert result["valid"] is False
        assert "not signed" in result["errors"][0].lower()

    def test_bad_signature_fails(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, verify_evaluation_suite_signature
        priv_path, _ = _generate_key_pair(tmp_path)
        priv_path2, pub_path2 = _generate_key_pair(tmp_path, suffix="2")
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        wrong_pub = Path(pub_path2).read_text(encoding="utf-8")
        result = verify_evaluation_suite_signature(suite_path=out, public_key_pem=wrong_pub)
        assert result["valid"] is False
        assert result["details"]["signature_status"] == "invalid"

    def test_tampered_digest_fails(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, verify_evaluation_suite_signature
        priv_path, _ = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        data = json.loads(Path(out).read_text(encoding="utf-8"))
        data["suite_digest"] = "0" * 64
        Path(out).write_text(json.dumps(data), encoding="utf-8")

        result = verify_evaluation_suite_signature(suite_path=out)
        assert result["valid"] is False

    def test_trust_store_lookup(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, verify_evaluation_suite_signature
        priv_path, pub_path = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        ts_path = _setup_trust_store(tmp_path, pub_path)
        result = verify_evaluation_suite_signature(suite_path=out, trust_store_path=ts_path)
        assert result["valid"] is True
        assert result["details"]["signer_trusted"] is True

    def test_wrong_purpose_rejected(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, verify_evaluation_suite_signature
        priv_path, pub_path = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        ts_path = _setup_trust_store(tmp_path, pub_path, name="wrong",
                                      purposes=["evaluation_report_signing"])  # wrong purpose
        result = verify_evaluation_suite_signature(suite_path=out, trust_store_path=ts_path)
        assert result["valid"] is False
        assert result["details"]["signer_trusted"] is False


# ── AC4: Report Records Suite Evidence ─────────────────────────────────────

class TestReportSuiteEvidence:
    """AC4: Evaluation report records suite signature evidence."""

    def test_report_has_suite_sig_fields(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert "suite_signature_status" in report
        assert "suite_signer_fingerprint" in report
        assert "suite_signer_trusted" in report
        assert "suite_trust_verified" in report

    def test_report_records_unsigned_by_default(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["suite_signature_status"] == "unsigned"

    def test_report_records_valid_with_requirement(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, run_evaluation
        priv_path, pub_path = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)
        ts_path = _setup_trust_store(tmp_path, pub_path)

        report = run_evaluation(
            suite=out, require_suite_signature=True, trust_store_path=ts_path,
        )
        assert report["suite_signature_status"] == "valid"
        assert report["suite_signer_trusted"] is True
        assert report["suite_trust_verified"] is True


# ── AC5: Strict Mode Failures ──────────────────────────────────────────────

class TestStrictModeFailures:
    """AC5: Strict mode fails on unsigned/invalid/untrusted suites."""

    def test_unsigned_rejected_when_required(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path, require_suite_signature=True)
        assert report["valid"] is False
        assert report["suite_signature_status"] == "unsigned"

    def test_invalid_signature_rejected(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, run_evaluation
        priv_path, _ = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        # Tamper
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        data["suite_digest"] = "0" * 64
        Path(out).write_text(json.dumps(data), encoding="utf-8")

        report = run_evaluation(suite=out, require_suite_signature=True)
        assert report["valid"] is False

    def test_untrusted_signer_rejected(self, tmp_path):
        from nodechain.cli.evaluation import sign_evaluation_suite, run_evaluation
        priv_path, pub_path = _generate_key_pair(tmp_path)
        suite_path = _write_suite_json(tmp_path)
        out = str(tmp_path / "signed.json")
        sign_evaluation_suite(suite_path, priv_path, output_path=out)

        # Trust store with WRONG purpose
        ts_path = _setup_trust_store(tmp_path, pub_path, name="wp",
                                      purposes=["attestation_signing"])
        report = run_evaluation(
            suite=out, require_suite_signature=True, trust_store_path=ts_path,
        )
        assert report["valid"] is False


# ── AC6: Backward Compatibility ────────────────────────────────────────────

class TestBackwardCompatibility:
    """AC6: Unsigned suites allowed outside strict/signature-required mode."""

    def test_unsigned_suite_runs_without_requirement(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["valid"] is True
        assert report["passed"] is True

    def test_yaml_suite_still_works(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        path = str(tmp_path / "suite.yaml")
        Path(path).write_text(
            "suite_id: yaml-bc\ntarget_type: node\ncases:\n  - case_id: c1\n",
            encoding="utf-8",
        )
        report = run_evaluation(suite=path)
        assert report["valid"] is True
