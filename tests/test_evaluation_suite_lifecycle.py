"""Tests for v1.18.2 Evaluation Suite Lifecycle.

Tests cover all 7 acceptance criteria:
  1. Lifecycle fields in EvaluationSuite
  2. Strict eval run rejects expired/not-yet-valid/revoked/deprecated
  3. Local suite registry (register, list, revoke, verify)
  4. Eval report records lifecycle evidence
  5. Trust-store enforcement still required when --require-suite-signature
  6. Backward compatibility with unsigned/unregistered suites
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write_suite_json(tmp_path, **overrides):
    suite = {
        "suite_id": "lifecycle-test-suite",
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


# ── AC1: Lifecycle Fields ──────────────────────────────────────────────────

class TestLifecycleFields:
    """AC1: EvaluationSuite includes lifecycle fields."""

    def test_default_lifecycle_fields(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", cases=[type("C", (), {"case_id": "c1", "to_dict": lambda self: {"case_id": "c1"}})()])
        assert s.valid_from == ""
        assert s.valid_until == ""
        assert s.supersedes_suite_digest == ""
        assert s.suite_status == "active"

    def test_lifecycle_fields_roundtrip(self, tmp_path):
        from nodechain.cli.evaluation import EvaluationSuite
        suite_path = _write_suite_json(tmp_path,
            valid_from="2020-01-01T00:00:00Z",
            valid_until="2030-01-01T00:00:00Z",
            supersedes_suite_digest="abc123",
            suite_status="deprecated",
        )
        suite = EvaluationSuite.from_file(suite_path)
        assert suite.valid_from == "2020-01-01T00:00:00Z"
        assert suite.valid_until == "2030-01-01T00:00:00Z"
        assert suite.supersedes_suite_digest == "abc123"
        assert suite.suite_status == "deprecated"

    def test_to_dict_includes_lifecycle(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1")
        d = s.to_dict()
        assert "valid_from" in d
        assert "valid_until" in d
        assert "supersedes_suite_digest" in d
        assert "suite_status" in d

    def test_suite_statuses_constant(self):
        from nodechain.cli.evaluation import SUITE_STATUSES
        assert "active" in SUITE_STATUSES
        assert "deprecated" in SUITE_STATUSES
        assert "revoked" in SUITE_STATUSES

    def test_check_validity_active(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", suite_status="active")
        valid, reason = s.check_validity()
        assert valid is True
        assert reason == ""

    def test_check_validity_revoked(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", suite_status="revoked")
        valid, reason = s.check_validity()
        assert valid is False
        assert "revoked" in reason

    def test_check_validity_deprecated(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", suite_status="deprecated")
        valid, reason = s.check_validity()
        assert valid is False
        assert "deprecated" in reason

    def test_check_validity_expired(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", suite_status="active",
                            valid_until="2020-01-01T00:00:00+00:00")
        valid, reason = s.check_validity()
        assert valid is False
        assert "expired" in reason.lower()

    def test_check_validity_not_yet_valid(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", suite_status="active",
                            valid_from="2099-01-01T00:00:00+00:00")
        valid, reason = s.check_validity()
        assert valid is False
        assert "not yet valid" in reason.lower()

    def test_check_validity_within_window(self):
        from nodechain.cli.evaluation import EvaluationSuite
        s = EvaluationSuite(suite_id="t1", suite_status="active",
                            valid_from="2020-01-01T00:00:00+00:00",
                            valid_until="2099-01-01T00:00:00+00:00")
        valid, reason = s.check_validity()
        assert valid is True


# ── AC2: Strict Mode Lifecycle Rejection ───────────────────────────────────

class TestStrictLifecycleRejection:
    """AC2: Strict eval run rejects invalid lifecycle suites."""

    def test_expired_rejected_in_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, valid_until="2020-01-01T00:00:00+00:00")
        report = run_evaluation(suite=suite_path, strict=True)
        assert report["valid"] is False
        assert "expired" in report.get("suite_validity_status", "").lower() or "expired" in report.get("errors", [""])[0].lower()

    def test_not_yet_valid_rejected_in_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, valid_from="2099-01-01T00:00:00+00:00")
        report = run_evaluation(suite=suite_path, strict=True)
        assert report["valid"] is False

    def test_revoked_rejected_in_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, suite_status="revoked")
        report = run_evaluation(suite=suite_path, strict=True)
        assert report["valid"] is False

    def test_deprecated_rejected_in_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, suite_status="deprecated")
        report = run_evaluation(suite=suite_path, strict=True)
        assert report["valid"] is False

    def test_require_active_suite_rejects_revoked(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, suite_status="revoked")
        report = run_evaluation(suite=suite_path, require_active_suite=True)
        assert report["valid"] is False

    def test_active_suite_passes_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, suite_status="active")
        report = run_evaluation(suite=suite_path, strict=True)
        assert report["valid"] is True
        assert report["suite_validity_status"] == "valid"


# ── AC3: Suite Registry ────────────────────────────────────────────────────

class TestSuiteRegistry:
    """AC3: Local suite registry with register/list/revoke/verify."""

    def test_register_suite(self, tmp_path, monkeypatch):
        import os
        from nodechain.cli.eval_suite_registry import register_suite, load_registry
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)

        entry = register_suite(suite_path=suite_path)
        assert entry["suite_id"] == "lifecycle-test-suite"
        assert entry["suite_status"] == "active"
        assert "suite_digest" in entry

    def test_list_suites(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, list_suites
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        register_suite(suite_path=suite_path)

        suites = list_suites()
        assert len(suites) == 1
        assert suites[0]["suite_id"] == "lifecycle-test-suite"

    def test_list_active_only(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, list_suites, revoke_suite
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        entry = register_suite(suite_path=suite_path)

        revoke_suite(entry["suite_digest"])
        active = list_suites(active_only=True)
        assert len(active) == 0

    def test_revoke_suite(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, revoke_suite, load_registry
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        entry = register_suite(suite_path=suite_path)

        revoked = revoke_suite(entry["suite_digest"], reason="superseded")
        assert revoked["suite_status"] == "revoked"
        assert revoked["revoke_reason"] == "superseded"

    def test_verify_in_registry(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, verify_suite_in_registry
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        entry = register_suite(suite_path=suite_path)

        result = verify_suite_in_registry(entry["suite_digest"])
        assert result["valid"] is True
        assert result["details"]["in_registry"] is True

    def test_verify_not_in_registry(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import verify_suite_in_registry
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        result = verify_suite_in_registry("0" * 64)
        assert result["valid"] is False

    def test_verify_revoked_not_active(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, revoke_suite, verify_suite_in_registry
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        entry = register_suite(suite_path=suite_path)
        revoke_suite(entry["suite_digest"])

        result = verify_suite_in_registry(entry["suite_digest"], require_active=True)
        assert result["valid"] is False

    def test_registry_has_audit_log(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, load_registry
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        register_suite(suite_path=suite_path)

        reg = load_registry()
        assert len(reg["audit_log"]) >= 1
        assert reg["audit_log"][0]["action"] == "register"

    def test_registry_digest(self, tmp_path, monkeypatch):
        from nodechain.cli.eval_suite_registry import register_suite, registry_digest
        monkeypatch.setenv("NODECHAIN_EVAL_SUITE_REGISTRY", str(tmp_path / "reg.json"))
        suite_path = _write_suite_json(tmp_path)
        register_suite(suite_path=suite_path)

        d = registry_digest()
        assert len(d) == 64  # SHA-256 hex


# ── AC4: Report Records Lifecycle Evidence ─────────────────────────────────

class TestReportLifecycleEvidence:
    """AC4: Eval report records suite lifecycle evidence."""

    def test_report_has_validity_status(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert "suite_validity_status" in report

    def test_report_records_not_checked_by_default(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["suite_validity_status"] == "not_checked"

    def test_report_records_valid_in_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, suite_status="active")
        report = run_evaluation(suite=suite_path, strict=True)
        assert report["suite_validity_status"] == "valid"

    def test_report_has_registry_digest_field(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert "suite_registry_digest" in report


# ── AC5: Trust-Store Enforcement Compatibility ─────────────────────────────

class TestTrustStoreCompatibility:
    """AC5: Trust-store enforcement still works with lifecycle."""

    def test_signature_and_lifecycle_both_check(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        # An active suite without signature should be rejected for sig requirement
        suite_path = _write_suite_json(tmp_path, suite_status="active")
        report = run_evaluation(suite=suite_path, require_suite_signature=True)
        assert report["valid"] is False
        assert report["suite_signature_status"] == "unsigned"


# ── AC6: Backward Compatibility ────────────────────────────────────────────

class TestBackwardCompatibility:
    """AC6: Unsigned/unregistered suites allowed outside strict mode."""

    def test_unsigned_unregistered_runs_normally(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path)
        report = run_evaluation(suite=suite_path)
        assert report["valid"] is True
        assert report["passed"] is True
        assert report["suite_validity_status"] == "not_checked"

    def test_revoked_runs_without_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, suite_status="revoked")
        # Without strict/require_active, revoked suite still runs
        report = run_evaluation(suite=suite_path)
        assert report["valid"] is True

    def test_expired_runs_without_strict(self, tmp_path):
        from nodechain.cli.evaluation import run_evaluation
        suite_path = _write_suite_json(tmp_path, valid_until="2020-01-01T00:00:00+00:00")
        report = run_evaluation(suite=suite_path)
        assert report["valid"] is True
