"""Tests for v1.18.2 Evaluation Runner.

Tests cover all 9 acceptance criteria:
  1. nodechain eval run command
  2. Suite schema (suite_id, version, target_type, cases, metrics, thresholds)
  3. Case schema (case_id, input, expected_output, etc.)
  4. Runner records eval_id, suite_digest, case_results, metrics, etc.
  5. Metrics include 9 built-in types
  6. Reports can be signed
  7. Trust store purpose: evaluation_report_signing
  8. Strict mode failures
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
    priv_path = str(tmp_path / f"priv_eval{suffix}.pem")
    pub_path = str(tmp_path / f"pub_eval{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _write_suite(tmp_path, **overrides):
    suite = {
        "suite_id": "test-suite-001",
        "suite_version": "1.0.0",
        "target_type": "chain",
        "target_ref": "test-chain",
        "description": "Test suite",
        "metrics": ["correctness", "schema_validity"],
        "thresholds": {"correctness": 1.0},
        "cases": [
            {
                "case_id": "case-1",
                "input": {"query": "test"},
                "expected_output": {"status": "ok"},
                "required_invariants": ["INV-001"],
            },
            {
                "case_id": "case-2",
                "input": {"query": "test2"},
                "expected_output": {"status": "ok"},
            },
        ],
    }
    suite.update(overrides)
    path = str(tmp_path / "suite.json")
    Path(path).write_text(json.dumps(suite), encoding="utf-8")
    return path


# ── AC1: Eval Run ──────────────────────────────────────────────────────────

class TestEvalRun:
    """AC1: nodechain eval run command works."""

    def test_run_suite_json(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["valid"] is True
        assert report["suite_id"] == "test-suite-001"
        assert "eval_id" in report
        assert report["total_cases"] == 2

    def test_run_suite_dict(self):
        from nodechain.cli.evaluation import run_evaluation, EvaluationSuite, EvaluationCase
        suite = EvaluationSuite(
            suite_id="direct-test",
            target_type="node",
            cases=[EvaluationCase(case_id="c1")],
        )
        report = run_evaluation(suite=suite)
        assert report["valid"] is True
        assert report["suite_id"] == "direct-test"

    def test_run_produces_case_results(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert len(report["case_results"]) == 2
        assert report["case_results"][0]["case_id"] == "case-1"

    def test_run_produces_metrics(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert "metric_results" in report
        assert "correctness" in report["metric_results"]

    def test_run_records_version(self, tmp_path):
        from nodechain import __version__
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["nodechain_version"] == __version__

    def test_run_records_timestamps(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["started_at"]
        assert report["finished_at"]
        assert report["duration_ms"] >= 0


# ── AC2: Suite Schema ──────────────────────────────────────────────────────

class TestSuiteSchema:
    """AC2: Suite schema fields."""

    def test_suite_has_all_fields(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(
            suite_id="s1", suite_version="2.0",
            target_type="adapter", target_ref="my-adapter",
            metrics=["correctness"], thresholds={"correctness": 0.9},
            required_artifacts=["manifest.json"], description="Test",
        )
        d = s.to_dict()
        assert d["suite_id"] == "s1"
        assert d["suite_version"] == "2.0"
        assert d["target_type"] == "adapter"
        assert d["target_ref"] == "my-adapter"
        assert "cases" in d
        assert d["metrics"] == ["correctness"]
        assert d["thresholds"] == {"correctness": 0.9}
        assert d["required_artifacts"] == ["manifest.json"]

    def test_suite_roundtrip(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="rt", target_type="policy")
        s2 = EvaluationSuite.from_dict(s.to_dict())
        assert s2.suite_id == "rt"
        assert s2.target_type == "policy"

    def test_suite_digest_stable(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s1 = EvaluationSuite(suite_id="d1")
        s2 = EvaluationSuite(suite_id="d1")
        assert s1.digest() == s2.digest()

    def test_suite_digest_changes_with_content(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s1 = EvaluationSuite(suite_id="d1")
        s2 = EvaluationSuite(suite_id="d2")
        assert s1.digest() != s2.digest()

    def test_suite_from_file_yaml(self, tmp_path):
        from nodechain.cli.evaluation import EvaluationSuite
        path = str(tmp_path / "suite.yaml")
        Path(path).write_text(
            "suite_id: yaml-test\ntarget_type: node\ncases:\n  - case_id: c1\n",
            encoding="utf-8",
        )
        s = EvaluationSuite.from_file(path)
        assert s.suite_id == "yaml-test"
        assert len(s.cases) == 1


# ── AC3: Case Schema ───────────────────────────────────────────────────────

class TestCaseSchema:
    """AC3: Case schema fields."""

    def test_case_has_all_fields(self):
        from nodechain.cli.evaluation import EvaluationCase
        c = EvaluationCase(
            case_id="full-case",
            input_data={"q": "test"},
            expected_output={"status": "ok"},
            expected_trace_properties={"events": 3},
            expected_policy_verdict="pass",
            expected_receipt_fields={"deploy_status": "accepted"},
            max_cost=0.01,
            max_latency_ms=500,
            required_invariants=["INV-001", "INV-007"],
            description="Full case",
        )
        d = c.to_dict()
        assert d["case_id"] == "full-case"
        assert d["input"] == {"q": "test"}
        assert d["expected_output"] == {"status": "ok"}
        assert d["max_cost"] == 0.01
        assert d["max_latency_ms"] == 500
        assert "INV-007" in d["required_invariants"]

    def test_case_roundtrip(self):
        from nodechain.cli.evaluation import EvaluationCase
        c = EvaluationCase(case_id="rt", max_cost=0.5)
        c2 = EvaluationCase.from_dict(c.to_dict())
        assert c2.case_id == "rt"
        assert c2.max_cost == 0.5


# ── AC4: Runner Records ────────────────────────────────────────────────────

class TestRunnerRecords:
    """AC4: Runner records eval_id, suite_digest, etc."""

    def test_report_has_all_fields(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        for field in ["eval_id", "suite_digest", "target_digest",
                       "case_results", "metric_results", "passed",
                       "failed_cases", "threshold_failures",
                       "started_at", "finished_at", "nodechain_version"]:
            assert field in report, f"Missing report field: {field}"

    def test_suite_digest_present(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation, EvaluationSuite
        suite_path = _write_suite(tmp_path)
        suite = EvaluationSuite.from_file(suite_path)
        report = run_evaluation(suite=suite_path)
        assert report["suite_digest"] == suite.digest()

    def test_report_digest_present(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert "report_digest" in report
        assert len(report["report_digest"]) == 64


# ── AC5: Metrics ───────────────────────────────────────────────────────────

class TestMetrics:
    """AC5: Built-in metrics present."""

    def test_builtin_metrics(self):
        from nodechain.cli.evaluation import BUILTIN_METRICS
        for metric in ["correctness", "schema_validity", "contract_validity",
                        "invariant_compliance", "policy_compliance",
                        "trace_completeness", "cost", "latency",
                        "deterministic_replay_match"]:
            assert metric in BUILTIN_METRICS

    def test_default_case_produces_all_metrics(self):
        from nodechain.cli.evaluation import _run_default_case, EvaluationCase, EvaluationSuite, BUILTIN_METRICS
        case = EvaluationCase(case_id="m1")
        suite = EvaluationSuite(suite_id="s", cases=[case])
        result = _run_default_case(case, suite)
        for metric in BUILTIN_METRICS:
            assert metric in result.metrics

    def test_invariant_compliance_unknown_invariant_fails(self):
        from nodechain.cli.evaluation import _run_default_case, EvaluationCase, EvaluationSuite
        case = EvaluationCase(
            case_id="bad-inv",
            required_invariants=["INV-999"],  # unknown
        )
        suite = EvaluationSuite(suite_id="s", cases=[case])
        result = _run_default_case(case, suite)
        assert result.passed is False
        assert result.metrics["invariant_compliance"] == 0.0

    def test_policy_compliance_invalid_verdict(self):
        from nodechain.cli.evaluation import _run_default_case, EvaluationCase, EvaluationSuite
        case = EvaluationCase(
            case_id="bad-pv",
            expected_policy_verdict="nonsense",
        )
        suite = EvaluationSuite(suite_id="s", cases=[case])
        result = _run_default_case(case, suite)
        assert result.passed is False
        assert result.metrics["policy_compliance"] == 0.0


# ── AC6: Report Signing ───────────────────────────────────────────────────

class TestReportSigning:
    """AC6: Reports can be signed."""

    def test_sign_report(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation, sign_evaluation_report
        priv_path, _ = _generate_key_pair(tmp_path)
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        report_path = str(tmp_path / "report.json")
        Path(report_path).write_text(json.dumps(report), encoding="utf-8")

        signed = sign_evaluation_report(report_path, priv_path)
        assert "report_signature" in signed
        assert signed["report_signature_algorithm"] == "RSA-PSS-SHA256"
        assert "report_signer_fingerprint" in signed

    def test_verify_signed_report(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation, sign_evaluation_report, verify_evaluation_report
        priv_path, pub_path = _generate_key_pair(tmp_path)
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        report_path = str(tmp_path / "report.json")
        Path(report_path).write_text(json.dumps(report), encoding="utf-8")
        sign_evaluation_report(report_path, priv_path)

        pubkey_pem = Path(pub_path).read_text(encoding="utf-8")
        result = verify_evaluation_report(report_path=report_path, public_key_pem=pubkey_pem)
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"

    def test_unsigned_report_fails_verification(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation, verify_evaluation_report
        suite_path = _write_suite(tmp_path)
        report = run_evaluation(suite=suite_path)
        report_path = str(tmp_path / "unsigned.json")
        Path(report_path).write_text(json.dumps(report), encoding="utf-8")

        result = verify_evaluation_report(report_path=report_path)
        assert result["valid"] is False
        assert "not signed" in result["errors"][0].lower()


# ── AC7: Trust Store Purpose ───────────────────────────────────────────────

class TestTrustStorePurpose:
    """AC7: evaluation_report_signing purpose."""

    def test_purpose_in_valid_purposes(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "evaluation_report_signing" in VALID_PURPOSES

    def test_purpose_count(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert len(VALID_PURPOSES) == 13

    def test_add_key_with_purpose(self, tmp_path):
        import os
        from nodechain.cli.trust_store import add_key, load_trust_store
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = str(tmp_path / "ts.json")
        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        try:
            add_key(public_key_path=pub_path, name="eval-signer",
                    purposes=["evaluation_report_signing"])
            store = load_trust_store()
            assert "evaluation_report_signing" in store["keys"]["eval-signer"]["allowed_purposes"]
        finally:
            del os.environ["NODECHAIN_TRUST_STORE"]


# ── AC8: Strict Mode ───────────────────────────────────────────────────────

class TestStrictMode:
    """AC8: Strict mode failures."""

    def test_malformed_suite_invalid(self):
        from nodechain.cli.evaluation import EvaluationSuite, run_evaluation
        # Missing suite_id, invalid target_type, no cases
        suite = EvaluationSuite(suite_id="", target_type="bogus")
        report = run_evaluation(suite=suite)
        assert report["valid"] is False
        assert len(report["errors"]) > 0

    def test_strict_missing_artifact_fails(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation, EvaluationSuite, EvaluationCase
        suite = EvaluationSuite(
            suite_id="art-test",
            target_type="node",
            cases=[EvaluationCase(case_id="c1")],
            required_artifacts=["nonexistent.json"],
        )
        report = run_evaluation(suite=suite, strict=True)
        assert report["passed"] is False
        assert report["valid"] is False
        assert "Missing required artifacts" in report["errors"][0]

    def test_non_strict_missing_artifact_warns(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation, EvaluationSuite, EvaluationCase
        suite = EvaluationSuite(
            suite_id="art-test-ns",
            target_type="node",
            cases=[EvaluationCase(case_id="c1")],
            required_artifacts=["nonexistent.json"],
        )
        report = run_evaluation(suite=suite, strict=False)
        assert report["valid"] is True
        assert "nonexistent.json" in report["missing_artifacts"]

    def test_threshold_failure_recorded(self):
        from nodechain.cli.evaluation import run_evaluation, EvaluationSuite, EvaluationCase
        suite = EvaluationSuite(
            suite_id="threshold-test",
            target_type="node",
            cases=[EvaluationCase(case_id="c1")],
            metrics=["correctness"],
            thresholds={"correctness": 2.0},  # impossible threshold
        )
        report = run_evaluation(suite=suite)
        assert len(report["threshold_failures"]) > 0
        assert report["passed"] is False


# ── Target Types ───────────────────────────────────────────────────────────

class TestTargetTypes:
    """AC2: All target types valid."""

    def test_all_target_types(self):
        from nodechain.cli.evaluation import TARGET_TYPES
        for tt in ["node", "chain", "policy", "adapter", "trace", "deployment", "remediation"]:
            assert tt in TARGET_TYPES

    def test_invalid_target_type_rejected(self):
        from nodechain.cli.evaluation import EvaluationSuite, run_evaluation
        suite = EvaluationSuite(
            suite_id="bad-tt",
            target_type="invalid_type",
            cases=[],
        )
        report = run_evaluation(suite=suite)
        assert report["valid"] is False
        assert any("Invalid target_type" in e for e in report["errors"])


# ── Custom Runner ──────────────────────────────────────────────────────────

class TestCustomRunner:
    """Custom runners for real execution."""

    def test_custom_runner(self):
        from nodechain.cli.evaluation import run_evaluation, EvaluationSuite, EvaluationCase, CaseResult
        suite = EvaluationSuite(
            suite_id="custom",
            target_type="node",
            cases=[EvaluationCase(case_id="custom-1")],
        )

        def my_runner(case, suite):
            return CaseResult(
                case_id=case.case_id,
                passed=True,
                metrics={"correctness": 1.0, "cost": 0.001},
                detail="Custom eval passed",
            )

        report = run_evaluation(suite=suite, custom_runner=my_runner)
        assert report["passed"] is True
        assert report["case_results"][0]["detail"] == "Custom eval passed"


# ── Real Suite Validation ──────────────────────────────────────────────────

class TestRealSuites:
    """Verify the 5 real eval suites load and run."""

    @pytest.mark.parametrize("suite_name", [
        "sandbox_hardening_eval",
        "trust_chain_eval",
        "proxmox_deployment_eval",
        "drift_remediation_eval",
        "reference_chain_eval",
    ])
    def test_suite_loads_and_passes(self, suite_name):
        from nodechain.cli.evaluation import EvaluationSuite, run_evaluation
        suite_path = f"eval_suites/{suite_name}.yaml"
        if not Path(suite_path).exists():
            pytest.skip(f"Suite not found: {suite_path}")
        suite = EvaluationSuite.from_file(suite_path)
        assert suite.suite_id == suite_name
        assert len(suite.cases) > 0
        report = run_evaluation(suite=suite)
        assert report["valid"] is True
        assert report["passed"] is True
