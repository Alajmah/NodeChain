"""Deterministic Node Quality Scorecards (v2.67.3).

Evaluates individual deterministic registry-resolved nodes for measurable
node-level quality: reproducibility, exact-match correctness, schema
compliance, cost compliance, latency, and rule branch coverage.

This module mirrors the research_eval_runner / research_eval_metrics split,
but at node granularity instead of chain granularity.

Key design decisions (agreed with ChatGPT):
- Deterministic-only profile for v2.67.3 (model-backed deferred)
- Runner takes node_instance directly (unit-testable, no registry coupling)
- Invokes through NodeInvoker (real latency measurement)
- Reproducibility uses canonical JSON with ignored volatile fields
- report_digest excludes volatile timing fields (stable across runs)
- Branch coverage covers both factor triggers AND outcome rules

Build a node once. Govern it forever. Reuse it everywhere.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Data models ───────────────────────────────────────────────────────────


@dataclass
class NodeScorecardCase:
    """A single golden I/O case for node quality evaluation.

    Attributes:
        case_id: Unique identifier for this case.
        node_id: The node being evaluated.
        input_payload: What goes into InvocationEnvelope.payload.
        expected_output: Golden expected output dict (for exact_match).
        expected_branches: Namespaced branch identifiers this case should
            trigger (e.g. "risk_factor.low_confidence", "level.high_via_two_factors").
        description: Human-readable description.
        ignored_fields: Volatile fields stripped before comparison (e.g. trace_id).
    """

    case_id: str
    node_id: str
    input_payload: dict[str, Any]
    expected_output: dict[str, Any]
    expected_branches: list[str] = field(default_factory=list)
    description: str = ""
    ignored_fields: list[str] = field(default_factory=list)


@dataclass
class NodeScorecardReport:
    """Quality scorecard report for a single deterministic node."""

    report_type: str = "node_quality_scorecard"
    target_type: str = "node"
    node_id: str = ""
    node_version: str = ""
    node_origin: str = "local_registry"
    content_digest: str = ""
    profile: str = "deterministic"
    metrics: dict[str, float] = field(default_factory=dict)
    thresholds: dict[str, float] = field(default_factory=dict)
    cases: list[dict[str, Any]] = field(default_factory=list)
    passed: bool = False
    report_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_type": self.report_type,
            "target_type": self.target_type,
            "node_id": self.node_id,
            "node_version": self.node_version,
            "node_origin": self.node_origin,
            "content_digest": self.content_digest,
            "profile": self.profile,
            "metrics": self.metrics,
            "thresholds": self.thresholds,
            "cases": self.cases,
            "passed": self.passed,
            "report_digest": self.report_digest,
        }


# ── Canonicalization ──────────────────────────────────────────────────────


def _canonicalize(output: dict[str, Any], ignored_fields: list[str] | None = None) -> str:
    """Return canonical JSON string of output with ignored fields removed.

    Used for reproducibility and exact-match comparisons.
    """
    import copy
    cleaned = copy.deepcopy(output)
    for field_name in (ignored_fields or []):
        cleaned.pop(field_name, None)
    return json.dumps(cleaned, sort_keys=True, default=str, ensure_ascii=False)


def _subset_match(
    actual: dict[str, Any],
    expected: dict[str, Any],
    ignored_fields: list[str] | None = None,
) -> bool:
    """Check that every key in expected exists in actual with the same value.

    This is a subset check, not a full equality check: extra self-reported
    fields in actual (review_reason, thresholds_applied, uncertainty_disclosures,
    etc.) are allowed. We verify classification correctness, not field absence.

    Nested dicts are compared recursively (expected sub-dict must be a subset
    of actual sub-dict). Lists are compared for equality.
    """
    ignore = set(ignored_fields or [])
    for key, expected_val in expected.items():
        if key in ignore:
            continue
        if key not in actual:
            return False
        actual_val = actual[key]
        if isinstance(expected_val, dict) and isinstance(actual_val, dict):
            if not _subset_match(actual_val, expected_val):
                return False
        elif isinstance(expected_val, list):
            if actual_val != expected_val:
                return False
        else:
            if actual_val != expected_val:
                return False
    return True


# ── Golden cases ──────────────────────────────────────────────────────────


def _rc_input(
    severity_signals: list[dict] | None = None,
    confidence_signals: list[dict] | None = None,
    uncertainty_factors: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    domain: str = "test",
) -> dict[str, Any]:
    """Build a shared_risk_classifier input payload."""
    return {
        "domain": domain,
        "subject": "test subject",
        "severity_signals": severity_signals or [],
        "confidence_signals": confidence_signals or [],
        "uncertainty_factors": uncertainty_factors or [],
        "evidence_refs": evidence_refs or [],
    }


def _rc_expected(
    risk_level: str,
    confidence: float,
    risk_factors: list[str],
    high_severity: int = 0,
    medium_severity: int = 0,
    low_severity: int = 0,
    signal_count: int = 0,
    evidence_count: int = 0,
) -> dict[str, Any]:
    """Build expected output for shared_risk_classifier."""
    return {
        "risk_level": risk_level,
        "confidence": round(confidence, 2),
        "review_required": risk_level == "HIGH",
        "risk_factors": risk_factors,
        "domain": "test",
        "subject": "test subject",
        "signal_counts": {
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
        },
        "confidence_factors": {
            "mean_confidence": round(confidence, 2),
            "signal_count": signal_count,
            "evidence_count": evidence_count,
        },
    }


def _tc_input(
    run_id: str = "run-test",
    final_status: str = "completed",
    nodes_executed: list[str] | None = None,
    errors: list[str] | None = None,
    total_cost: float = 0.0,
    total_duration_ms: int = 100,
) -> dict[str, Any]:
    """Build a shared_trace_collector input payload."""
    return {
        "run_id": run_id,
        "chain_id": "test-chain",
        "nodes_executed": nodes_executed or ["node_a", "node_b"],
        "total_cost": total_cost,
        "total_duration_ms": total_duration_ms,
        "final_status": final_status,
        "errors": errors or [],
    }


def _tc_expected(
    run_id: str = "run-test",
    nodes_executed: list[str] | None = None,
    final_status: str = "completed",
    errors: list[str] | None = None,
    total_cost: float = 0.0,
    total_duration_ms: int = 100,
) -> dict[str, Any]:
    """Build expected output for shared_trace_collector (trace_id excluded)."""
    return {
        "run_id": run_id,
        "chain_id": "test-chain",
        "nodes_executed": nodes_executed or ["node_a", "node_b"],
        "node_count": len(nodes_executed or ["node_a", "node_b"]),
        "total_cost_usd": round(total_cost, 6),
        "total_duration_ms": total_duration_ms,
        "final_status": final_status,
        "errors": errors or [],
        "error_count": len(errors or []),
        "trace_complete": final_status in ("completed", "cancelled", "failed"),
    }


def get_shared_node_golden_cases() -> dict[str, list[NodeScorecardCase]]:
    """Golden I/O cases for both shared deterministic nodes.

    Covers ALL meaningful branches per ChatGPT's requirement:
    - risk_factor triggers (high_severity, uncertainty, low_confidence, no_evidence)
    - outcome rules (HIGH via 2+ factors, HIGH via 2+ severity, MEDIUM, LOW)
    - trace statuses (completed, failed, cancelled, unknown)
    """
    return {
        "shared_risk_classifier": [
            # HIGH via 2+ risk factors
            NodeScorecardCase(
                case_id="rc-high-two-factors",
                node_id="shared_risk_classifier",
                description="HIGH risk via 2+ risk factors (low_confidence + no_evidence)",
                input_payload=_rc_input(
                    confidence_signals=[{"score": 0.2}],
                    evidence_refs=[],  # no evidence
                ),
                expected_output=_rc_expected("HIGH", 0.2, ["low_confidence", "no_evidence_refs"], signal_count=1),
                expected_branches=["risk_factor.low_confidence", "risk_factor.no_evidence_refs", "level.high_via_two_factors"],
            ),
            # HIGH via 2+ high severity signals
            NodeScorecardCase(
                case_id="rc-high-two-severity",
                node_id="shared_risk_classifier",
                description="HIGH risk via 2+ high severity signals",
                input_payload=_rc_input(
                    severity_signals=[
                        {"level": "high", "desc": "sig1"},
                        {"level": "high", "desc": "sig2"},
                    ],
                    confidence_signals=[{"score": 0.7}],
                    evidence_refs=["e1"],
                ),
                expected_output=_rc_expected("HIGH", 0.7, ["high_severity_signals"], high_severity=2, signal_count=1, evidence_count=1),
                expected_branches=["risk_factor.high_severity_signals", "level.high_via_two_high_severity"],
            ),
            # MEDIUM via 1 risk factor (high severity present)
            NodeScorecardCase(
                case_id="rc-medium-one-factor",
                node_id="shared_risk_classifier",
                description="MEDIUM risk via 1 risk factor (high_severity_signals)",
                input_payload=_rc_input(
                    severity_signals=[{"level": "high", "desc": "sig1"}],
                    confidence_signals=[{"score": 0.6}],
                    evidence_refs=["e1"],
                ),
                expected_output=_rc_expected("MEDIUM", 0.6, ["high_severity_signals"], high_severity=1, signal_count=1, evidence_count=1),
                expected_branches=["risk_factor.high_severity_signals", "level.medium_via_one_factor"],
            ),
            # MEDIUM via confidence < 0.5 (but >= 0.4, no other factors)
            NodeScorecardCase(
                case_id="rc-medium-low-confidence",
                node_id="shared_risk_classifier",
                description="MEDIUM risk via confidence < 0.5 (no other factors)",
                input_payload=_rc_input(
                    confidence_signals=[{"score": 0.45}],
                    evidence_refs=["e1"],
                ),
                expected_output=_rc_expected("MEDIUM", 0.45, [], signal_count=1, evidence_count=1),
                expected_branches=["level.medium_via_confidence_below_0_5"],
            ),
            # LOW baseline
            NodeScorecardCase(
                case_id="rc-low-baseline",
                node_id="shared_risk_classifier",
                description="LOW risk baseline (no factors, confidence >= 0.5)",
                input_payload=_rc_input(
                    confidence_signals=[{"score": 0.7}],
                    evidence_refs=["e1"],
                ),
                expected_output=_rc_expected("LOW", 0.7, [], signal_count=1, evidence_count=1),
                expected_branches=["level.low_baseline"],
            ),
            # high_uncertainty_count branch
            NodeScorecardCase(
                case_id="rc-uncertainty-count",
                node_id="shared_risk_classifier",
                description="high_uncertainty_count factor (3+ uncertainty factors)",
                input_payload=_rc_input(
                    confidence_signals=[{"score": 0.6}],
                    uncertainty_factors=["u1", "u2", "u3"],
                    evidence_refs=["e1"],
                ),
                expected_output=_rc_expected("MEDIUM", 0.6, ["high_uncertainty_count"], signal_count=1, evidence_count=1),
                expected_branches=["risk_factor.high_uncertainty_count", "level.medium_via_one_factor"],
            ),
            # low_confidence branch
            NodeScorecardCase(
                case_id="rc-low-confidence",
                node_id="shared_risk_classifier",
                description="low_confidence factor (confidence < 0.4)",
                input_payload=_rc_input(
                    confidence_signals=[{"score": 0.3}],
                    evidence_refs=["e1"],
                ),
                expected_output=_rc_expected("MEDIUM", 0.3, ["low_confidence"], signal_count=1, evidence_count=1),
                expected_branches=["risk_factor.low_confidence", "level.medium_via_one_factor"],
            ),
            # no_evidence_refs branch
            NodeScorecardCase(
                case_id="rc-no-evidence",
                node_id="shared_risk_classifier",
                description="no_evidence_refs factor (empty evidence)",
                input_payload=_rc_input(
                    confidence_signals=[{"score": 0.6}],
                    evidence_refs=[],
                ),
                expected_output=_rc_expected("MEDIUM", 0.6, ["no_evidence_refs"], signal_count=1, evidence_count=0),
                expected_branches=["risk_factor.no_evidence_refs", "level.medium_via_one_factor"],
            ),
        ],
        "shared_trace_collector": [
            NodeScorecardCase(
                case_id="tc-completed",
                node_id="shared_trace_collector",
                description="completed status → trace_complete=true",
                input_payload=_tc_input(final_status="completed"),
                expected_output=_tc_expected(final_status="completed"),
                expected_branches=["trace.trace_complete_true"],
                ignored_fields=["trace_id"],
            ),
            NodeScorecardCase(
                case_id="tc-failed",
                node_id="shared_trace_collector",
                description="failed status → trace_complete=true (with errors)",
                input_payload=_tc_input(final_status="failed", errors=["error1", "error2"]),
                expected_output=_tc_expected(final_status="failed", errors=["error1", "error2"]),
                expected_branches=["trace.trace_complete_true", "trace.error_count"],
                ignored_fields=["trace_id"],
            ),
            NodeScorecardCase(
                case_id="tc-cancelled",
                node_id="shared_trace_collector",
                description="cancelled status → trace_complete=true",
                input_payload=_tc_input(final_status="cancelled"),
                expected_output=_tc_expected(final_status="cancelled"),
                expected_branches=["trace.trace_complete_true"],
                ignored_fields=["trace_id"],
            ),
            NodeScorecardCase(
                case_id="tc-unknown",
                node_id="shared_trace_collector",
                description="unknown status → trace_complete=false",
                input_payload=_tc_input(final_status="unknown"),
                expected_output=_tc_expected(final_status="unknown"),
                expected_branches=["trace.trace_complete_false"],
                ignored_fields=["trace_id"],
            ),
        ],
    }


# ── Defaults ──────────────────────────────────────────────────────────────


DEFAULT_NODE_THRESHOLDS: dict[str, float] = {
    "reproducibility": 1.0,
    "exact_match_correctness": 1.0,
    "schema_compliance": 1.0,
    "cost_compliance": 1.0,
    "rule_branch_coverage": 1.0,
    "latency_ms_p95": 500.0,  # hard-fail threshold (warn at 100ms)
}

LATENCY_WARN_MS = 100.0


# ── Pure runner ───────────────────────────────────────────────────────────


def run_node_scorecard(
    node_instance: Any,
    cases: list[NodeScorecardCase],
    contract: Any,
    replay_count: int = 3,
    node_id: str = "",
    node_version: str = "",
    content_digest: str = "",
) -> NodeScorecardReport:
    """Run quality scorecard for a single deterministic node.

    Takes node_instance directly (unit-testable). Invokes through
    NodeInvoker for real latency measurement.

    Args:
        node_instance: The node to evaluate (BaseNode subclass instance).
        cases: Golden cases for this node.
        contract: NodeContract (for guaranteed_fields schema check).
        replay_count: Times to run each case for reproducibility.
        node_id, node_version, content_digest: Metadata for the report.

    Returns:
        NodeScorecardReport with metrics, per-case results, and stable digest.
    """
    from nodechain.core.envelope import InvocationEnvelope
    from nodechain.runtime.node_invoker import NodeInvoker

    invoker = NodeInvoker()
    guaranteed_fields = list(contract.exit.guaranteed_fields) if contract and contract.exit else []

    case_results: list[dict[str, Any]] = []
    all_latencies: list[float] = []

    for case in cases:
        run_outputs: list[dict[str, Any]] = []
        run_latencies: list[float] = []
        run_costs: list[float] = []

        for _ in range(replay_count):
            envelope = InvocationEnvelope(
                envelope_id=f"scorecard-{case.case_id}",
                run_id=f"scorecard-{case.case_id}",
                chain_id="scorecard",
                node_id=case.node_id,
                step_id=1,
                payload=case.input_payload,
            )
            response, latency_ms = asyncio.run(invoker.invoke(node_instance, envelope))
            run_outputs.append(response.output or {})
            run_latencies.append(float(latency_ms))
            run_costs.append(float(response.cost_usd or 0.0))

        all_latencies.extend(run_latencies)

        # Reproducibility: all runs produce same canonical output
        canonical_outputs = [_canonicalize(o, case.ignored_fields) for o in run_outputs]
        reproducible = len(set(canonical_outputs)) == 1

        # Exact match: expected_output is a subset of actual output.
        # Every key in expected must exist in actual with the same value.
        # Extra self-reported fields (review_reason, thresholds_applied, etc.)
        # are allowed — we check classification correctness, not field absence.
        exact_match = _subset_match(run_outputs[0], case.expected_output, case.ignored_fields)

        # Schema compliance: all guaranteed fields present
        first_output = run_outputs[0]
        schema_ok = all(f in first_output for f in guaranteed_fields)

        # Cost compliance: model_required=false → cost must be 0
        cost_ok = all(c == 0.0 for c in run_costs)

        # Branch coverage: check expected branches fired
        branches_fired = _evaluate_branches(case.node_id, first_output)
        expected_covered = all(b in branches_fired for b in case.expected_branches)

        case_results.append({
            "case_id": case.case_id,
            "description": case.description,
            "passed": reproducible and exact_match and schema_ok and cost_ok and expected_covered,
            "reproducible": reproducible,
            "exact_match": exact_match,
            "schema_ok": schema_ok,
            "cost_ok": cost_ok,
            "branches_expected": case.expected_branches,
            "branches_fired": sorted(branches_fired),
            "branches_covered": expected_covered,
            "latencies_ms": run_latencies,
            "latency_ms_mean": round(sum(run_latencies) / len(run_latencies), 3) if run_latencies else 0.0,
            "latency_ms_max": round(max(run_latencies), 3) if run_latencies else 0.0,
            "cost_usd": run_costs[0] if run_costs else 0.0,
        })

    # ── Aggregate metrics ─────────────────────────────────────────────────
    total_cases = len(case_results)
    metrics: dict[str, float] = {
        "reproducibility": sum(1 for c in case_results if c["reproducible"]) / total_cases if total_cases else 0.0,
        "exact_match_correctness": sum(1 for c in case_results if c["exact_match"]) / total_cases if total_cases else 0.0,
        "schema_compliance": sum(1 for c in case_results if c["schema_ok"]) / total_cases if total_cases else 0.0,
        "cost_compliance": sum(1 for c in case_results if c["cost_ok"]) / total_cases if total_cases else 0.0,
        "rule_branch_coverage": sum(1 for c in case_results if c["branches_covered"]) / total_cases if total_cases else 0.0,
    }

    # Latency metrics (aggregate)
    if all_latencies:
        metrics["latency_ms_p95"] = round(_percentile(all_latencies, 95), 3)
        metrics["latency_ms_mean"] = round(sum(all_latencies) / len(all_latencies), 3)
    else:
        metrics["latency_ms_p95"] = 0.0
        metrics["latency_ms_mean"] = 0.0

    # ── Threshold check ───────────────────────────────────────────────────
    threshold_violations: list[str] = []
    for key, threshold in DEFAULT_NODE_THRESHOLDS.items():
        actual = metrics.get(key, 0.0)
        if key == "latency_ms_p95":
            if actual > threshold:
                threshold_violations.append(f"{key}={actual:.1f}ms exceeds {threshold}ms")
        else:
            if actual < threshold:
                threshold_violations.append(f"{key}={actual:.2f} below {threshold}")

    # Latency warning (non-fatal)
    latency_warnings: list[str] = []
    if metrics.get("latency_ms_p95", 0) > LATENCY_WARN_MS:
        latency_warnings.append(f"latency_ms_p95={metrics['latency_ms_p95']:.1f}ms exceeds warning threshold {LATENCY_WARN_MS}ms")

    passed = len(threshold_violations) == 0 and all(c["passed"] for c in case_results)

    # ── Build report ──────────────────────────────────────────────────────
    report = NodeScorecardReport(
        node_id=node_id or cases[0].node_id if cases else "",
        node_version=node_version,
        node_origin="local_registry",
        content_digest=content_digest,
        profile="deterministic",
        metrics=metrics,
        thresholds=dict(DEFAULT_NODE_THRESHOLDS),
        cases=case_results,
        passed=passed,
    )

    # report_digest: stable digest over quality fields only (excludes timing)
    report.report_digest = _compute_report_digest(report)

    return report


# ── Branch evaluation ─────────────────────────────────────────────────────


def _evaluate_branches(node_id: str, output: dict[str, Any]) -> set[str]:
    """Determine which branches fired based on node output.

    Returns a set of namespaced branch identifiers covering both
    factor triggers and outcome rules.
    """
    branches: set[str] = set()

    if node_id == "shared_risk_classifier":
        risk_factors = output.get("risk_factors", [])
        risk_level = output.get("risk_level", "")
        signal_counts = output.get("signal_counts", {})
        confidence = output.get("confidence", 0.5)

        # Factor branches
        for rf in risk_factors:
            branches.add(f"risk_factor.{rf}")

        # Outcome / level branches
        if risk_level == "HIGH":
            if len(risk_factors) >= 2:
                branches.add("level.high_via_two_factors")
            if signal_counts.get("high_severity", 0) >= 2:
                branches.add("level.high_via_two_high_severity")
        elif risk_level == "MEDIUM":
            if len(risk_factors) >= 1:
                branches.add("level.medium_via_one_factor")
            if confidence < 0.5:
                branches.add("level.medium_via_confidence_below_0_5")
        elif risk_level == "LOW":
            branches.add("level.low_baseline")

    elif node_id == "shared_trace_collector":
        trace_complete = output.get("trace_complete", False)
        error_count = output.get("error_count", 0)

        if trace_complete:
            branches.add("trace.trace_complete_true")
        else:
            branches.add("trace.trace_complete_false")

        if error_count > 0:
            branches.add("trace.error_count")

    return branches


# ── Registry convenience helper ───────────────────────────────────────────


def run_registry_node_scorecard(
    node_id: str,
    registry: Any | None = None,
) -> NodeScorecardReport:
    """Run scorecard for a registry-resolved node.

    Resolves the node via NodeLoader (registry path, with provenance),
    gets content_digest from the registry package, and delegates to
    the pure runner. Used by CLI and integration tests.

    Args:
        node_id: The node to evaluate.
        registry: Optional pre-scanned RegistryIndex. When provided, it is
            used for the package lookup (content_digest). When None, a
            fresh NodeLoader is created which scans the local registry.
            The node instance is always resolved via NodeLoader so that
            provenance (_node_origin, _package_root, etc.) is stamped.
    """
    from nodechain.sdk.loader import NodeLoader

    # Always resolve the node instance via NodeLoader for provenance.
    loader = NodeLoader()
    node_instance = loader.load(node_id)

    # Use the provided registry for package lookup if given; otherwise
    # use the loader's own scanned registry.
    reg = registry if registry is not None else loader.registry

    # Get contract from manifest
    contract = node_instance.manifest.contract

    # Get content_digest from registry package
    pkg = reg.get_package(node_id) if reg else None
    content_digest = pkg.content_digest() if pkg else ""

    # Get golden cases
    all_cases = get_shared_node_golden_cases()
    cases = all_cases.get(node_id, [])

    # Get version from manifest
    node_version = node_instance.manifest.version if hasattr(node_instance.manifest, "version") else "1.0.0"

    return run_node_scorecard(
        node_instance=node_instance,
        cases=cases,
        contract=contract,
        node_id=node_id,
        node_version=node_version,
        content_digest=content_digest,
    )


# ── Report digest ─────────────────────────────────────────────────────────


# Fields excluded from the stable report digest (volatile across runs).
_DIGEST_EXCLUDED_CASE_KEYS = {"latencies_ms", "latency_ms_mean", "latency_ms_max"}


def _compute_report_digest(report: NodeScorecardReport) -> str:
    """Compute stable SHA-256 digest over quality fields only.

    Excludes volatile timing fields (latencies, generated_at) so the
    digest is deterministic across separate runs of the same node.
    """
    # Build a quality-only view of the report
    quality_view: dict[str, Any] = {
        "report_type": report.report_type,
        "node_id": report.node_id,
        "node_version": report.node_version,
        "content_digest": report.content_digest,
        "profile": report.profile,
        # Exclude latency metrics from digest
        "metrics": {k: v for k, v in report.metrics.items() if not k.startswith("latency")},
        "passed": report.passed,
        "cases": [],
    }

    for c in report.cases:
        quality_view["cases"].append({
            "case_id": c["case_id"],
            "passed": c["passed"],
            "reproducible": c["reproducible"],
            "exact_match": c["exact_match"],
            "schema_ok": c["schema_ok"],
            "cost_ok": c["cost_ok"],
            "branches_expected": c["branches_expected"],
            "branches_fired": c["branches_fired"],
            "branches_covered": c["branches_covered"],
            # Intentionally exclude latencies_ms, latency_ms_mean, latency_ms_max, cost_usd
        })

    canonical = json.dumps(quality_view, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Utilities ─────────────────────────────────────────────────────────────


def _percentile(values: list[float], pct: float) -> float:
    """Compute percentile of a list of values."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return d0 + d1


# ── Cache infrastructure (v2.67.3) ────────────────────────────────────────
#
# Centralized target discovery, pure cache loader, separate staleness check,
# and atomic cache writer. Designed so that eval CLI and dashboard --refresh
# share the same functions and the same report schema.

DEFAULT_SCORECARD_CACHE_PATH = Path(".nodechain") / "eval" / "node-scorecards" / "latest.json"

SCORECARD_CACHE_SCHEMA_VERSION = "nodechain.node_scorecard_cache.v1"


def get_shared_registry_node_ids() -> list[str]:
    """Centralized target discovery for shared deterministic nodes (v2.67.3).

    Single source of truth for which nodes the scorecard system evaluates.
    Used by eval node-scorecard --all-shared, dashboard scorecards --refresh,
    collect_reuse_status(), and tests.
    """
    return ["shared_risk_classifier", "shared_trace_collector"]


def write_scorecard_cache(
    reports: list[NodeScorecardReport],
    path: Path | None = None,
    source: dict[str, Any] | None = None,
) -> Path:
    """Write aggregate scorecard cache atomically (v2.67.3).

    Writes a single ``latest.json`` containing all reports in the envelope
    format. Uses atomic write (.tmp -> os.replace) to prevent half-written reads.

    Args:
        reports: Scorecard reports to cache.
        path: Cache file path. Defaults to DEFAULT_SCORECARD_CACHE_PATH.
        source: Explicit source metadata (mode, registry info).

    Returns:
        The path the cache was written to.
    """
    import os
    from datetime import datetime, timezone

    cache_path = Path(path) if path else DEFAULT_SCORECARD_CACHE_PATH
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from nodechain import __version__ as nc_version
    except (ImportError, AttributeError):
        nc_version = "0.0.0"

    if source is None:
        source = {"mode": "all_shared"}

    total = len(reports)
    passed_count = sum(1 for r in reports if r.passed)
    failed_count = total - passed_count

    envelope = {
        "schema_version": SCORECARD_CACHE_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nodechain_version": nc_version,
        "scorecard_runner_version": "1",
        "source": source,
        "summary": {
            "total": total,
            "passed": passed_count,
            "failed": failed_count,
            "status": "pass" if failed_count == 0 else "fail",
        },
        "reports": [r.to_dict() for r in reports],
    }

    tmp_path = cache_path.with_suffix(".json.tmp")
    tmp_path.write_text(
        json.dumps(envelope, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(str(tmp_path), str(cache_path))
    return cache_path


def load_scorecard_cache(path: Path | None = None) -> dict[str, Any] | None:
    """Pure cache loader. Read file, parse JSON, validate minimum envelope.

    Does NOT compare against live registry. Use is_scorecard_cache_stale() for that.
    Returns the cache dict, or None if missing/invalid.
    """
    cache_path = Path(path) if path else DEFAULT_SCORECARD_CACHE_PATH
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "schema_version" not in data or "reports" not in data:
        return None
    if not isinstance(data["reports"], list):
        return None
    return data


def is_scorecard_cache_stale(
    cache: dict[str, Any],
    registry: Any,
) -> tuple[bool, list[str]]:
    """Check if cached scorecard is stale vs live registry.

    Compares content_digest, node_version, and nodechain_version in cache
    against live packages and runtime. Returns (is_stale, reasons).
    """
    reasons: list[str] = []

    # Check nodechain_version (v2.67.3: prevents cross-version stale cache)
    try:
        from nodechain import __version__ as live_nc_version
    except (ImportError, AttributeError):
        live_nc_version = ""
    cached_nc_version = cache.get("nodechain_version", "")
    if cached_nc_version and live_nc_version and cached_nc_version != live_nc_version:
        reasons.append(
            f"nodechain_version changed ({cached_nc_version} -> {live_nc_version})"
        )

    for report in cache.get("reports", []):
        node_id = report.get("node_id", "")
        cached_digest = report.get("content_digest", "")
        cached_version = report.get("node_version", "")

        pkg = registry.get_package(node_id) if registry else None
        if pkg is None:
            reasons.append(f"{node_id}: package no longer admitted by registry")
            continue

        live_digest = pkg.content_digest()
        if cached_digest != live_digest:
            reasons.append(f"{node_id}: content_digest changed")
            continue

        if cached_version != pkg.manifest.version:
            reasons.append(
                f"{node_id}: version changed ({cached_version} -> {pkg.manifest.version})"
            )

    return (len(reasons) > 0, reasons)
