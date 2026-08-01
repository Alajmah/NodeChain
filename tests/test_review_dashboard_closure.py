"""
Review Dashboard Collection Actual Closure Tests (v2.21.3).

Verifies collect_dashboard_v2() — the function the CLI actually uses —
includes the review_workbench section and HR-045 through HR-048
auto-trigger from collected dashboard data.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

from nodechain.cli.dashboard_health import (
    collect_dashboard_v2,
    evaluate_all_rules,
    ALL_RULES,
)
from nodechain.cli.dashboard import collect_review_workbench_status
from nodechain.sdk.review_workbench import (
    ReviewRequest, ReviewSubject, ReviewQueue,
    SUBJECT_CAPABILITY, ROLE_SECURITY_OFFICER,
)


# ── DB isolation ─────────────────────────────────────────────────────────────
# These tests call collect_dashboard_v2(), which reads whatever DB
# NODECHAIN_DB_PATH points at (default: data/chain_state.db — the developer's
# real DB, which can hold thousands of runs and stale review states). Without
# isolation, assertions like stale_count == 0 and "HR-045 not triggered by
# default" fail against polluted dev state. The fixture points both the DB and
# trace dir at empty temp paths so the tests exercise the empty-environment path
# deterministically, regardless of local DB state. (v2.46.0 #12)
@pytest.fixture(autouse=True)
def _isolated_dashboard_env(tmp_path, monkeypatch):
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "empty.db"))
    monkeypatch.setenv("NODECHAIN_TRACE_DIR", str(trace_dir))
    yield


# ── AC-01: collect_dashboard_v2 includes review_workbench ───────────────────


class TestAC01DashboardV2HasReviewSection:
    """AC-01: collect_dashboard_v2()['sections'] contains 'review_workbench'."""

    def test_dashboard_v2_has_review_section(self):
        """The actual CLI dashboard collector includes review_workbench."""
        data = collect_dashboard_v2()
        assert "review_workbench" in data["sections"]

    def test_review_section_has_required_fields(self):
        data = collect_dashboard_v2()
        rw = data["sections"]["review_workbench"]
        for field in ("stale_count", "unauthorized_attempts",
                      "stale_decision_count", "rejected_blocking_count"):
            assert field in rw, f"Missing field: {field}"

    def test_review_section_defaults_zero(self):
        """Without a ReviewQueue, review_workbench reports zeros."""
        data = collect_dashboard_v2()
        rw = data["sections"]["review_workbench"]
        assert rw["stale_count"] == 0
        assert rw["unauthorized_attempts"] == 0
        assert rw["stale_decision_count"] == 0
        assert rw["rejected_blocking_count"] == 0

    def test_seven_sections_total(self):
        data = collect_dashboard_v2()
        # Assert the explicit section contract, not just a count — so a future
        # addition is named, not silently counted. (v2.46.0 adds 'recovery'.)
        # v2.67.3 adds 'reuse' + 'scorecards'.
        expected_sections = {
            "runtime",
            "trust",
            "registry",
            "evidence",
            "operations",
            "evaluation",
            "review_workbench",
            "memory",
            "workflow_recovery",
            "memory_read",
            "recovery",  # v2.46.0
            "reuse",     # v2.67.3
            "scorecards", # v2.67.3
        }
        assert set(data["sections"]) == expected_sections
        assert len(data["sections"]) == 13  # 7 + memory + workflow_recovery + memory_read + recovery + reuse + scorecards


# ── AC-02: HR-045 through HR-048 are in ALL_RULES ───────────────────────────


class TestAC02RulesRegistered:
    """AC-02: HR-045 through HR-048 registered in ALL_RULES."""

    def test_all_48_rules(self):
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_review_rule_ids_present(self):
        ids = {r.rule_id for r in ALL_RULES}
        for rid in ("HR-045", "HR-046", "HR-047", "HR-048"):
            assert rid in ids


# ── AC-03: HR-045 through HR-048 trigger from dashboard data ────────────────


class TestAC03RulesTriggerFromDashboard:
    """AC-03: HR-045 through HR-048 evaluate against review_workbench data."""

    def test_hr045_triggers_on_stale(self):
        """HR-045 triggers when stale_count > 0."""
        sections = {
            "review_workbench": {
                "stale_count": 1,
                "unauthorized_attempts": 0,
                "stale_decision_count": 0,
                "rejected_blocking_count": 0,
            }
        }
        issues = evaluate_all_rules(sections)
        ids = {i["rule_id"] for i in issues}
        assert "HR-045" in ids

    def test_hr046_triggers_on_unauthorized(self):
        sections = {
            "review_workbench": {
                "stale_count": 0,
                "unauthorized_attempts": 1,
                "stale_decision_count": 0,
                "rejected_blocking_count": 0,
            }
        }
        issues = evaluate_all_rules(sections)
        ids = {i["rule_id"] for i in issues}
        assert "HR-046" in ids

    def test_hr047_triggers_on_stale_decision(self):
        sections = {
            "review_workbench": {
                "stale_count": 0,
                "unauthorized_attempts": 0,
                "stale_decision_count": 1,
                "rejected_blocking_count": 0,
            }
        }
        issues = evaluate_all_rules(sections)
        ids = {i["rule_id"] for i in issues}
        assert "HR-047" in ids

    def test_hr048_triggers_on_rejected_blocking(self):
        sections = {
            "review_workbench": {
                "stale_count": 0,
                "unauthorized_attempts": 0,
                "stale_decision_count": 0,
                "rejected_blocking_count": 1,
            }
        }
        issues = evaluate_all_rules(sections)
        ids = {i["rule_id"] for i in issues}
        assert "HR-048" in ids

    def test_no_trigger_when_healthy(self):
        sections = {
            "review_workbench": {
                "stale_count": 0,
                "unauthorized_attempts": 0,
                "stale_decision_count": 0,
                "rejected_blocking_count": 0,
            }
        }
        issues = evaluate_all_rules(sections)
        review_issues = [i for i in issues if i["rule_id"] in
                         ("HR-045", "HR-046", "HR-047", "HR-048")]
        assert len(review_issues) == 0


# ── AC-04: End-to-end through collect_dashboard_v2 ───────────────────────────


class TestAC04EndToEndDashboardV2:
    """AC-04: collect_dashboard_v2() runs all rules against all sections."""

    def test_dashboard_v2_evaluates_all_sections(self):
        """collect_dashboard_v2() runs evaluate_all_rules on 7 sections."""
        data = collect_dashboard_v2()
        assert "rule_summary" in data
        # All 48 rules should be in summary
        assert len(data["rule_summary"]) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_dashboard_v2_review_rules_not_triggered_by_default(self):
        """By default (no ReviewQueue), HR-045-048 not triggered."""
        data = collect_dashboard_v2()
        triggered = {r["rule_id"] for r in data["rule_summary"] if r["triggered"]}
        for rid in ("HR-045", "HR-046", "HR-047", "HR-048"):
            assert rid not in triggered, f"{rid} should not trigger by default"

    def test_dashboard_v2_has_issues_list(self):
        data = collect_dashboard_v2()
        assert "issues" in data
        assert isinstance(data["issues"], list)


# ── AC-05: collect_review_workbench_status callable ─────────────────────────


class TestAC05CollectorFunction:
    """AC-05: collect_review_workbench_status works with and without queue."""

    def test_without_queue(self):
        result = collect_review_workbench_status()
        assert result["stale_count"] == 0
        assert result["enabled"] is False

    def test_with_empty_queue(self):
        queue = ReviewQueue()
        result = collect_review_workbench_status(review_queue=queue)
        assert result["pending_count"] == 0
        assert result["stale_count"] == 0
        assert result["enabled"] is True

    def test_with_stale_request(self):
        subject = ReviewSubject(
            subject_type=SUBJECT_CAPABILITY, subject_id="s1",
            subject_digest="d" * 64)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=80)).isoformat()
        req = ReviewRequest(
            request_id="stale_1", subject=subject,
            reason_for_review="Old",
            required_reviewer_role=ROLE_SECURITY_OFFICER,
            created_at=old_time,
        )
        queue = ReviewQueue()
        queue.submit(req)
        result = collect_review_workbench_status(review_queue=queue)
        assert result["stale_count"] >= 1


# ── AC-06: verify_receipt wording stays clean ───────────────────────────────


class TestAC06VerifyReceiptWording:
    """AC-06: verify_receipt() uses committed/digest, not signed/signature."""

    def test_no_signed_wording(self):
        import inspect
        from nodechain.sdk.review_workbench import ReviewVerifier
        source = inspect.getsource(ReviewVerifier.verify_receipt)
        assert "signed" not in source.lower()
        assert "signature" not in source.lower()
