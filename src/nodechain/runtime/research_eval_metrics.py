"""Research Evaluation Metrics — quality metrics computed from chain outputs.

Reads per-node outputs from the research eval runner and computes:
- citation_validity: do citations resolve to real sources?
- claim_support_rate: confirmed / total claims
- fabrication_rate: quarantined_fabricated_source / total claims
- schema_compliance: do nodes emit guaranteed contract fields?
- confidence_calibration: is risk confidence consistent with claim validation rate?
- trace_completeness: are all expected nodes present in outputs?

These metrics use ranges for behavioral values and exact assertions for
contract invariants, per the v2.56.0 agreement.
"""

from __future__ import annotations

from typing import Any


# ── Required node output fields (from NodeContract.guaranteed_fields) ──────

CONTRACT_GUARANTEED_FIELDS = {
    "evidence_synthesizer": ["claims", "synthesis"],
    "claim_validator": ["validated_claims", "validation_summary"],
    "risk_classifier": [
        "risk_level", "confidence", "review_required",
        "uncertainty_disclosures", "validated_claims", "sources",
    ],
    "response_generator": [
        "recommendation", "confidence_statement",
        "citations", "uncertainty_disclosures",
    ],
}

EXPECTED_NODES = list(CONTRACT_GUARANTEED_FIELDS.keys())


def compute_schema_compliance(node_outputs: dict[str, dict]) -> float:
    """Fraction of nodes that emit ALL their guaranteed contract fields.

    Returns 1.0 if every node emits every guaranteed field, 0.0 if none do.
    """
    total_checks = 0
    passed_checks = 0

    for node_id, required_fields in CONTRACT_GUARANTEED_FIELDS.items():
        output = node_outputs.get(node_id, {})
        for field in required_fields:
            total_checks += 1
            if field in output:
                passed_checks += 1

    return passed_checks / total_checks if total_checks > 0 else 0.0


def compute_citation_validity(node_outputs: dict[str, dict]) -> float:
    """Fraction of citations that resolve to a known source ID.

    A citation is valid if its source_ref matches a source_id in the
    source set. Returns 1.0 if all citations resolve (or no citations exist).
    """
    sources = node_outputs.get("risk_classifier", {}).get("sources", [])
    source_ids = {s.get("source_id", "") for s in sources if isinstance(s, dict)}

    citations = node_outputs.get("response_generator", {}).get("citations", [])
    if not citations:
        return 1.0  # No citations to validate

    valid = sum(1 for c in citations if c.get("source_ref", "") in source_ids)
    return valid / len(citations)


def compute_claim_support_rate(node_outputs: dict[str, dict]) -> float:
    """Fraction of validated claims that are confirmed.

    claim_support_rate = confirmed / total_claims
    """
    summary = node_outputs.get("claim_validator", {}).get("validation_summary", {})
    total = summary.get("total_claims", 0)
    if total == 0:
        return 0.0

    confirmed = summary.get("confirmed", 0)
    return confirmed / total


def compute_fabrication_rate(node_outputs: dict[str, dict]) -> float:
    """Fraction of synthesizer claims quarantined for fabricated source IDs.

    fabrication_rate = quarantined_fabricated_source claims / total claims
    Returns 0.0 for normal cases. For fabricated-source eval cases, this
    should be 1.0 (all fabricated claims quarantined).
    """
    claims = node_outputs.get("evidence_synthesizer", {}).get("claims", [])
    if not claims:
        return 0.0

    quarantined = sum(
        1 for c in claims
        if c.get("status") == "quarantined_fabricated_source"
    )
    return quarantined / len(claims)


def compute_confidence_calibration(node_outputs: dict[str, dict]) -> float:
    """How well does risk confidence align with claim validation rate?

    Returns the absolute difference between risk confidence and claim
    validation rate. Lower is better calibrated. 0.0 = perfect calibration.

    For the metric report, we return 1.0 - diff so higher = better.
    """
    risk_output = node_outputs.get("risk_classifier", {})
    risk_confidence = risk_output.get("confidence", 0.0)
    val_rate = risk_output.get("confidence_factors", {}).get("claim_validation_rate", 0.0)

    diff = abs(risk_confidence - val_rate)
    return round(1.0 - diff, 4)


def compute_trace_completeness(node_outputs: dict[str, dict]) -> float:
    """Fraction of expected nodes that produced output.

    Returns 1.0 if all 4 research-critical nodes are present.
    """
    present = sum(1 for n in EXPECTED_NODES if n in node_outputs and node_outputs[n])
    return present / len(EXPECTED_NODES)


def compute_all_metrics(node_outputs: dict[str, dict]) -> dict[str, float]:
    """Compute all research quality metrics from node outputs."""
    return {
        "citation_validity": round(compute_citation_validity(node_outputs), 4),
        "claim_support_rate": round(compute_claim_support_rate(node_outputs), 4),
        "fabrication_rate": round(compute_fabrication_rate(node_outputs), 4),
        "schema_compliance": round(compute_schema_compliance(node_outputs), 4),
        "confidence_calibration": compute_confidence_calibration(node_outputs),
        "trace_completeness": round(compute_trace_completeness(node_outputs), 4),
    }


# ── Invariant checks (exact assertions, not ranges) ───────────────────────

def check_invariants(node_outputs: dict[str, dict]) -> list[str]:
    """Check exact invariants that must always hold.

    Returns list of violation descriptions (empty = all passed).
    """
    violations: list[str] = []

    # No [INVALID] soft-marking should survive
    import json
    output_str = json.dumps(node_outputs)
    if "[INVALID]" in output_str:
        violations.append("Found [INVALID] soft-marking in node outputs")

    # Fabricated IDs must not appear in citations
    sources = node_outputs.get("risk_classifier", {}).get("sources", [])
    source_ids = {s.get("source_id", "") for s in sources if isinstance(s, dict)}
    citations = node_outputs.get("response_generator", {}).get("citations", [])
    for ct in citations:
        ref = ct.get("source_ref", "")
        if ref and ref not in source_ids:
            violations.append(f"Citation references unknown source: {ref}")

    # Quarantined claims must have quarantine_reason
    claims = node_outputs.get("evidence_synthesizer", {}).get("claims", [])
    for claim in claims:
        if claim.get("status") == "quarantined_fabricated_source":
            if not claim.get("quarantine_reason"):
                violations.append(
                    f"Claim {claim.get('claim_id', '?')} quarantined without quarantine_reason"
                )

    # Risk level must be a valid value
    risk_level = node_outputs.get("risk_classifier", {}).get("risk_level", "")
    if risk_level and risk_level not in {"HIGH", "MEDIUM", "LOW"}:
        violations.append(f"Invalid risk_level: {risk_level}")

    return violations


# ── Threshold definitions ─────────────────────────────────────────────────

# Thresholds for the release gate. Cases that don't meet these fail.
DEFAULT_THRESHOLDS = {
    "schema_compliance": 1.0,       # Must be perfect
    "citation_validity": 0.95,      # At most 5% invalid citations
    "fabrication_rate_max": 0.0,    # Normal cases: no fabrication allowed
    "trace_completeness": 1.0,      # All nodes must produce output
    "claim_support_rate": 0.0,      # Per-case threshold (0 = no minimum)
}


def check_thresholds(
    metrics: dict[str, float],
    thresholds: dict[str, float] | None = None,
) -> list[str]:
    """Check if metrics meet release-gate thresholds.

    Returns list of threshold violation descriptions (empty = all passed).
    """
    t = thresholds or DEFAULT_THRESHOLDS
    violations: list[str] = []

    if metrics.get("schema_compliance", 0.0) < t["schema_compliance"]:
        violations.append(
            f"schema_compliance {metrics['schema_compliance']} < {t['schema_compliance']}"
        )

    if metrics.get("citation_validity", 0.0) < t["citation_validity"]:
        violations.append(
            f"citation_validity {metrics['citation_validity']} < {t['citation_validity']}"
        )

    if metrics.get("fabrication_rate", 0.0) > t["fabrication_rate_max"]:
        violations.append(
            f"fabrication_rate {metrics['fabrication_rate']} > {t['fabrication_rate_max']}"
        )

    if metrics.get("trace_completeness", 0.0) < t["trace_completeness"]:
        violations.append(
            f"trace_completeness {metrics['trace_completeness']} < {t['trace_completeness']}"
        )

    min_support = t.get("claim_support_rate", 0.0)
    if min_support > 0 and metrics.get("claim_support_rate", 0.0) < min_support:
        violations.append(
            f"claim_support_rate {metrics['claim_support_rate']} < {min_support}"
        )

    return violations
