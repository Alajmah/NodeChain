"""Research Evaluation Harness tests (v2.67.3).

Tests the deterministic chain-eval runner, metric computation, and release
gate behavior. These are the release-gated quality tests that must pass
before any release ships.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.research_eval_runner import (
    ResearchEvalCase, get_golden_corpus, run_research_eval_case,
)
from nodechain.runtime.research_eval_metrics import (
    compute_all_metrics, compute_citation_validity, compute_claim_support_rate,
    compute_fabrication_rate, compute_schema_compliance, compute_trace_completeness,
    compute_confidence_calibration, check_invariants, check_thresholds,
    DEFAULT_THRESHOLDS,
)


# ── Golden corpus structure ───────────────────────────────────────────────

class TestGoldenCorpus:
    def test_corpus_has_at_least_5_cases(self):
        corpus = get_golden_corpus()
        assert len(corpus) >= 5

    def test_corpus_covers_normal_path(self):
        corpus = get_golden_corpus()
        case_ids = [c.case_id for c in corpus]
        assert any("normal" in cid for cid in case_ids), "Must have normal-path case"

    def test_corpus_covers_zero_evidence(self):
        corpus = get_golden_corpus()
        case_ids = [c.case_id for c in corpus]
        assert any("zero" in cid for cid in case_ids), "Must have zero-evidence case"

    def test_corpus_covers_mixed_evidence(self):
        corpus = get_golden_corpus()
        case_ids = [c.case_id for c in corpus]
        assert any("mixed" in cid for cid in case_ids), "Must have mixed-evidence case"

    def test_all_cases_have_unique_ids(self):
        corpus = get_golden_corpus()
        ids = [c.case_id for c in corpus]
        assert len(ids) == len(set(ids)), "Case IDs must be unique"


# ── Chain execution ───────────────────────────────────────────────────────

class TestChainExecution:
    def test_normal_case_produces_all_nodes(self):
        case = ResearchEvalCase(
            case_id="test-normal", description="test",
            source_count=5, include_qualified=True,
        )
        result = run_research_eval_case(case)
        assert len(result["errors"]) == 0
        assert "evidence_synthesizer" in result["node_outputs"]
        assert "claim_validator" in result["node_outputs"]
        assert "risk_classifier" in result["node_outputs"]
        assert "response_generator" in result["node_outputs"]

    def test_normal_case_produces_claims(self):
        case = ResearchEvalCase(
            case_id="test-claims", description="test",
            source_count=5,
        )
        result = run_research_eval_case(case)
        claims = result["node_outputs"]["evidence_synthesizer"]["claims"]
        assert len(claims) >= 1

    def test_normal_case_produces_citations(self):
        case = ResearchEvalCase(
            case_id="test-citations", description="test",
            source_count=5,
        )
        result = run_research_eval_case(case)
        citations = result["node_outputs"]["response_generator"]["citations"]
        assert len(citations) >= 1

    def test_zero_evidence_produces_no_citations(self):
        case = ResearchEvalCase(
            case_id="test-zero", description="test",
            source_count=0, empty_evidence=True,
        )
        result = run_research_eval_case(case)
        citations = result["node_outputs"]["response_generator"]["citations"]
        assert len(citations) == 0

    def test_zero_evidence_risk_is_high(self):
        case = ResearchEvalCase(
            case_id="test-zero-risk", description="test",
            source_count=0, empty_evidence=True,
        )
        result = run_research_eval_case(case)
        risk = result["node_outputs"]["risk_classifier"]["risk_level"]
        assert risk == "HIGH"


# ── Metric computation ────────────────────────────────────────────────────

class TestMetrics:
    def test_schema_compliance_perfect_for_normal_case(self):
        case = ResearchEvalCase(case_id="m1", description="test", source_count=5)
        result = run_research_eval_case(case)
        compliance = compute_schema_compliance(result["node_outputs"])
        assert compliance == 1.0

    def test_citation_validity_perfect_for_normal_case(self):
        case = ResearchEvalCase(case_id="m2", description="test", source_count=5)
        result = run_research_eval_case(case)
        validity = compute_citation_validity(result["node_outputs"])
        assert validity == 1.0

    def test_claim_support_rate_positive_for_normal_case(self):
        case = ResearchEvalCase(case_id="m3", description="test", source_count=5)
        result = run_research_eval_case(case)
        rate = compute_claim_support_rate(result["node_outputs"])
        assert rate > 0.0, "Normal case should have some confirmed claims"

    def test_fabrication_rate_zero_for_normal_case(self):
        case = ResearchEvalCase(case_id="m4", description="test", source_count=5)
        result = run_research_eval_case(case)
        rate = compute_fabrication_rate(result["node_outputs"])
        assert rate == 0.0

    def test_trace_completeness_perfect(self):
        case = ResearchEvalCase(case_id="m5", description="test", source_count=5)
        result = run_research_eval_case(case)
        completeness = compute_trace_completeness(result["node_outputs"])
        assert completeness == 1.0

    def test_confidence_calibration_in_range(self):
        case = ResearchEvalCase(case_id="m6", description="test", source_count=5)
        result = run_research_eval_case(case)
        calibration = compute_confidence_calibration(result["node_outputs"])
        assert 0.0 <= calibration <= 1.0

    def test_all_metrics_returned(self):
        case = ResearchEvalCase(case_id="m7", description="test", source_count=5)
        result = run_research_eval_case(case)
        metrics = compute_all_metrics(result["node_outputs"])
        expected_keys = {
            "citation_validity", "claim_support_rate", "fabrication_rate",
            "schema_compliance", "confidence_calibration", "trace_completeness",
        }
        assert set(metrics.keys()) == expected_keys


# ── Invariant checks ──────────────────────────────────────────────────────

class TestInvariants:
    def test_no_invalid_markers(self):
        case = ResearchEvalCase(case_id="i1", description="test", source_count=5)
        result = run_research_eval_case(case)
        violations = check_invariants(result["node_outputs"])
        assert all("[INVALID]" not in v for v in violations)

    def test_citations_resolve_to_real_sources(self):
        case = ResearchEvalCase(case_id="i2", description="test", source_count=5)
        result = run_research_eval_case(case)
        violations = check_invariants(result["node_outputs"])
        assert all("unknown source" not in v for v in violations)

    def test_invariant_violations_empty_for_normal_case(self):
        case = ResearchEvalCase(case_id="i3", description="test", source_count=5)
        result = run_research_eval_case(case)
        violations = check_invariants(result["node_outputs"])
        assert len(violations) == 0


# ── Threshold enforcement ─────────────────────────────────────────────────

class TestThresholds:
    def test_normal_case_passes_thresholds(self):
        case = ResearchEvalCase(case_id="t1", description="test", source_count=5)
        result = run_research_eval_case(case)
        metrics = compute_all_metrics(result["node_outputs"])
        violations = check_thresholds(metrics)
        assert len(violations) == 0, f"Threshold violations: {violations}"

    def test_zero_evidence_passes_thresholds(self):
        case = ResearchEvalCase(
            case_id="t2", description="test",
            source_count=0, empty_evidence=True,
        )
        result = run_research_eval_case(case)
        metrics = compute_all_metrics(result["node_outputs"])
        violations = check_thresholds(metrics)
        assert len(violations) == 0, f"Threshold violations: {violations}"

    def test_missing_node_fails_trace_completeness(self):
        """If a node output is missing, trace_completeness drops below 1.0."""
        partial_outputs = {
            "evidence_synthesizer": {"claims": [], "synthesis": {}},
            # Missing claim_validator, risk_classifier, response_generator
        }
        metrics = compute_all_metrics(partial_outputs)
        violations = check_thresholds(metrics)
        assert any("trace_completeness" in v for v in violations)

    def test_missing_guaranteed_field_fails_schema_compliance(self):
        """If a node omits a guaranteed field, schema_compliance drops below 1.0."""
        partial_outputs = {
            "evidence_synthesizer": {"claims": []},  # Missing 'synthesis'
            "claim_validator": {"validated_claims": [], "validation_summary": {}},
            "risk_classifier": {
                "risk_level": "LOW", "confidence": 0.5,
                "review_required": False, "uncertainty_disclosures": [],
                "validated_claims": [], "sources": [],
            },
            "response_generator": {
                "recommendation": "test", "confidence_statement": {},
                "citations": [], "uncertainty_disclosures": [],
            },
        }
        metrics = compute_all_metrics(partial_outputs)
        assert metrics["schema_compliance"] < 1.0


# ── Full golden corpus run ────────────────────────────────────────────────

class TestGoldenCorpusRun:
    def test_all_golden_cases_pass(self):
        """The entire golden corpus must pass for a release to ship."""
        corpus = get_golden_corpus()
        failures = []
        for case in corpus:
            result = run_research_eval_case(case)
            metrics = compute_all_metrics(result["node_outputs"])
            invariant_violations = check_invariants(result["node_outputs"])
            threshold_violations = check_thresholds(metrics)

            if result["errors"]:
                failures.append(f"{case.case_id}: execution errors: {result['errors']}")
            if invariant_violations:
                failures.append(f"{case.case_id}: invariant violations: {invariant_violations}")
            if threshold_violations:
                failures.append(f"{case.case_id}: threshold violations: {threshold_violations}")

        assert len(failures) == 0, f"Golden corpus failures:\n" + "\n".join(failures)
