"""Deterministic Node Quality Scorecard tests (v2.67.3).

Tests the node-level quality evaluation system for registry-resolved
deterministic nodes. Mirrors the test_research_eval_harness.py structure.

Proves 5 independent facts about the scorecard system:
1. Golden cases exist and cover all branches
2. Node execution produces correct outputs
3. All 6 metrics compute correctly
4. Report has stable digest (excluding timing) and correct content_digest
5. Volatile fields (trace_id) are handled correctly
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.runtime.node_quality_scorecard import (
    NodeScorecardCase,
    NodeScorecardReport,
    get_shared_node_golden_cases,
    run_node_scorecard,
    run_registry_node_scorecard,
    _canonicalize,
    _subset_match,
    _evaluate_branches,
    DEFAULT_NODE_THRESHOLDS,
)


SHARED_NODE_IDS = ["shared_risk_classifier", "shared_trace_collector"]


# ── 1. Golden cases ──────────────────────────────────────────────────────


class TestGoldenCases:
    """Golden case corpus shape and branch coverage."""

    def test_golden_cases_exist_for_both_nodes(self):
        cases = get_shared_node_golden_cases()
        assert "shared_risk_classifier" in cases
        assert "shared_trace_collector" in cases

    def test_risk_classifier_has_8_cases(self):
        cases = get_shared_node_golden_cases()
        assert len(cases["shared_risk_classifier"]) == 8

    def test_trace_collector_has_4_cases(self):
        cases = get_shared_node_golden_cases()
        assert len(cases["shared_trace_collector"]) == 4

    def test_all_case_ids_unique(self):
        cases = get_shared_node_golden_cases()
        all_ids = [c.case_id for node_cases in cases.values() for c in node_cases]
        assert len(all_ids) == len(set(all_ids)), "Duplicate case IDs"

    def test_risk_classifier_covers_all_factor_branches(self):
        """All 4 risk_factor branches must be covered across cases."""
        cases = get_shared_node_golden_cases()["shared_risk_classifier"]
        all_expected = set()
        for c in cases:
            all_expected.update(c.expected_branches)

        required_factors = {
            "risk_factor.high_severity_signals",
            "risk_factor.high_uncertainty_count",
            "risk_factor.low_confidence",
            "risk_factor.no_evidence_refs",
        }
        missing = required_factors - all_expected
        assert not missing, f"Missing factor branches: {missing}"

    def test_risk_classifier_covers_all_level_branches(self):
        """All level outcome branches must be covered."""
        cases = get_shared_node_golden_cases()["shared_risk_classifier"]
        all_expected = set()
        for c in cases:
            all_expected.update(c.expected_branches)

        required_levels = {
            "level.high_via_two_factors",
            "level.high_via_two_high_severity",
            "level.medium_via_one_factor",
            "level.medium_via_confidence_below_0_5",
            "level.low_baseline",
        }
        missing = required_levels - all_expected
        assert not missing, f"Missing level branches: {missing}"

    def test_trace_collector_covers_all_status_branches(self):
        cases = get_shared_node_golden_cases()["shared_trace_collector"]
        all_expected = set()
        for c in cases:
            all_expected.update(c.expected_branches)

        required = {"trace.trace_complete_true", "trace.trace_complete_false"}
        missing = required - all_expected
        assert not missing, f"Missing trace branches: {missing}"

    def test_trace_collector_cases_ignore_trace_id(self):
        """All trace collector cases must ignore trace_id (volatile uuid)."""
        cases = get_shared_node_golden_cases()["shared_trace_collector"]
        for c in cases:
            assert "trace_id" in c.ignored_fields, \
                f"{c.case_id}: trace_id must be in ignored_fields"


# ── 2. Node execution ────────────────────────────────────────────────────


class TestNodeExecution:
    """Running cases through the scorecard produces correct outputs."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_scorecard_passes(self, node_id):
        """Both shared nodes pass the scorecard."""
        report = run_registry_node_scorecard(node_id)
        assert report.passed, f"{node_id} scorecard failed"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_all_cases_pass(self, node_id):
        """Every individual case passes."""
        report = run_registry_node_scorecard(node_id)
        failed = [c["case_id"] for c in report.cases if not c["passed"]]
        assert not failed, f"{node_id}: failed cases: {failed}"


# ── 3. Metrics ───────────────────────────────────────────────────────────


class TestMetrics:
    """All 6 metrics compute correctly for passing nodes."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_reproducibility_is_1(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.metrics["reproducibility"] == 1.0

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_exact_match_is_1(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.metrics["exact_match_correctness"] == 1.0

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_schema_compliance_is_1(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.metrics["schema_compliance"] == 1.0

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_cost_compliance_is_1(self, node_id):
        """Deterministic nodes (model_required=false) must have cost_usd=0."""
        report = run_registry_node_scorecard(node_id)
        assert report.metrics["cost_compliance"] == 1.0

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_rule_branch_coverage_is_1(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.metrics["rule_branch_coverage"] == 1.0

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_latency_reported(self, node_id):
        """Latency is measured and reported (via NodeInvoker)."""
        report = run_registry_node_scorecard(node_id)
        assert "latency_ms_p95" in report.metrics
        assert "latency_ms_mean" in report.metrics
        assert report.metrics["latency_ms_p95"] >= 0.0


# ── 4. Report integrity ──────────────────────────────────────────────────


class TestReportIntegrity:
    """Report has stable digest, correct content_digest, proper structure."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_report_type_is_node_quality_scorecard(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.report_type == "node_quality_scorecard"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_target_type_is_node(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.target_type == "node"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_report_has_content_digest_64_chars(self, node_id):
        """content_digest in report must be full 64-char SHA-256."""
        report = run_registry_node_scorecard(node_id)
        assert len(report.content_digest) == 64, \
            f"content_digest must be 64 chars, got {len(report.content_digest)}"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_content_digest_matches_registry(self, node_id):
        """Report content_digest must match the registry package digest."""
        from nodechain.registry.local_registry import RegistryIndex
        reg = RegistryIndex()
        reg.scan()
        pkg = reg.get_package(node_id)
        report = run_registry_node_scorecard(node_id)
        assert report.content_digest == pkg.content_digest()

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_report_digest_is_64_chars(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert len(report.report_digest) == 64

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_report_digest_stable_across_runs(self, node_id):
        """report_digest must be identical across separate runs (excludes timing)."""
        report1 = run_registry_node_scorecard(node_id)
        report2 = run_registry_node_scorecard(node_id)
        assert report1.report_digest == report2.report_digest, \
            f"{node_id}: report_digest must be stable across runs"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_profile_is_deterministic(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.profile == "deterministic"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_node_origin_is_local_registry(self, node_id):
        report = run_registry_node_scorecard(node_id)
        assert report.node_origin == "local_registry"


# ── 5. Volatile field handling ───────────────────────────────────────────


class TestVolatileFieldHandling:
    """trace_id (uuid-derived) is correctly ignored for reproducibility."""

    def test_trace_collector_reproducibility_with_trace_id(self):
        """shared_trace_collector produces different trace_id each run,
        but reproducibility is still 1.0 because trace_id is ignored."""
        report = run_registry_node_scorecard("shared_trace_collector")
        assert report.metrics["reproducibility"] == 1.0

    def test_canonicalize_strips_ignored_fields(self):
        output = {"a": 1, "trace_id": "volatile-123", "b": 2}
        canonical = _canonicalize(output, ignored_fields=["trace_id"])
        assert "trace_id" not in canonical
        assert "a" in canonical

    def test_subset_match_ignores_extra_fields(self):
        """_subset_match allows actual to have extra fields beyond expected."""
        actual = {"risk_level": "LOW", "confidence": 0.7, "review_reason": "", "extra_field": True}
        expected = {"risk_level": "LOW", "confidence": 0.7}
        assert _subset_match(actual, expected)

    def test_subset_match_fails_on_wrong_value(self):
        actual = {"risk_level": "HIGH"}
        expected = {"risk_level": "LOW"}
        assert not _subset_match(actual, expected)

    def test_subset_match_fails_on_missing_key(self):
        actual = {"risk_level": "LOW"}
        expected = {"risk_level": "LOW", "confidence": 0.7}
        assert not _subset_match(actual, expected)


# ── 6. Per-case latency ──────────────────────────────────────────────────


class TestPerCaseLatency:
    """Each case result includes latency data from NodeInvoker."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_each_case_has_latencies_array(self, node_id):
        report = run_registry_node_scorecard(node_id)
        for c in report.cases:
            assert "latencies_ms" in c
            assert len(c["latencies_ms"]) == 3, \
                f"{c['case_id']}: expected 3 latency entries (replay_count=3)"
            assert "latency_ms_mean" in c
            assert "latency_ms_max" in c


# ── 7. Branch evaluation ─────────────────────────────────────────────────


class TestBranchEvaluation:
    """_evaluate_branches correctly identifies fired branches from output."""

    def test_risk_factor_branches_detected(self):
        output = {
            "risk_factors": ["low_confidence", "no_evidence_refs"],
            "risk_level": "HIGH",
            "signal_counts": {"high_severity": 0},
            "confidence": 0.3,
        }
        branches = _evaluate_branches("shared_risk_classifier", output)
        assert "risk_factor.low_confidence" in branches
        assert "risk_factor.no_evidence_refs" in branches
        assert "level.high_via_two_factors" in branches

    def test_level_branches_detected(self):
        output = {
            "risk_factors": [],
            "risk_level": "LOW",
            "signal_counts": {"high_severity": 0},
            "confidence": 0.7,
        }
        branches = _evaluate_branches("shared_risk_classifier", output)
        assert "level.low_baseline" in branches

    def test_trace_branches_detected(self):
        output = {"trace_complete": True, "error_count": 2}
        branches = _evaluate_branches("shared_trace_collector", output)
        assert "trace.trace_complete_true" in branches
        assert "trace.error_count" in branches

    def test_trace_false_branch_detected(self):
        output = {"trace_complete": False, "error_count": 0}
        branches = _evaluate_branches("shared_trace_collector", output)
        assert "trace.trace_complete_false" in branches
        assert "trace.error_count" not in branches


# ── 8. Thresholds ────────────────────────────────────────────────────────


class TestThresholds:
    """Default thresholds are correct and enforced."""

    def test_default_thresholds_target_1_for_quality_metrics(self):
        for key in ("reproducibility", "exact_match_correctness", "schema_compliance", "cost_compliance", "rule_branch_coverage"):
            assert DEFAULT_NODE_THRESHOLDS[key] == 1.0

    def test_latency_threshold_is_500ms(self):
        assert DEFAULT_NODE_THRESHOLDS["latency_ms_p95"] == 500.0
