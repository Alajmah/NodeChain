"""v2.68 regression tests for source_quality_policy.single_adapter_acceptance.v1.

Per agreement with strategic reviewer (round 4): the corroboration relaxation
is a governance-sensitive change, not just a bug fix. It must be visibly
policy-like — named, with explicit allow/deny thresholds and reason codes — and
it must have regression tests for the negative cases that should still trigger
the loop.

These tests pin the policy's behavior on the boundary conditions:
  - positive: the real-run path (single-API, high-quality → accepted)
  - negative: each threshold violation individually forces the loop
  - negative: model loop override refused when objective criteria not met
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.nodes.source_quality import SourceQualityEvaluatorNode


POLICY_ID = "source_quality_policy.single_adapter_acceptance.v1"


def _make_node() -> SourceQualityEvaluatorNode:
    return SourceQualityEvaluatorNode(model_adapter=MagicMock())


def _peer_reviewed_qual_sources(n: int, score: float = 0.7) -> list[dict]:
    """Build n included, peer-reviewed qualified sources with stable refs."""
    return [
        {
            "source_ref": f"s{i}",
            "quality_score": score,
            "included": True,
            "signals": {"peer_reviewed": True},
        }
        for i in range(n)
    ]


def _sources_for_quals(qual_sources: list[dict], api: str = "openalex") -> list[dict]:
    """Build the matching sources list (with title + origin_api) for the
    qualified-source refs."""
    return [
        {"source_id": q["source_ref"], "origin_api": api, "title": f"Title {q['source_ref']}"}
        for q in qual_sources
    ]


# ── Positive case: the real-run path ──────────────────────────────────────

def test_single_adapter_accepted_when_thresholds_met() -> None:
    """The path the v2.68 real run depends on: single-API but high-quality
    sources should NOT trigger a loop. The policy should fire and surface its
    decision + reason codes."""
    node = _make_node()
    qual = _peer_reviewed_qual_sources(10, score=0.7)
    sources = _sources_for_quals(qual, api="openalex")
    output = {
        "qualified_sources": qual,
        "quality_summary": {
            "total_evaluated": 10,
            "average_score": 0.7,
            "domain_coverage": "strong",
        },
        # Model set loop_required=True citing single-API — policy should override.
        "loop_required": True,
        "loop_reason": "Model: single-API, no corroboration.",
    }
    result = node._apply_deterministic_loop_trigger(output, sources)

    assert result["loop_required"] is False, "high-quality single-API must not loop"
    assert "policy_decision" in result, "policy decision must be surfaced"
    pd = result["policy_decision"]
    assert pd["policy_id"] == POLICY_ID
    assert pd["decision"] == "allow_single_adapter_acceptance"
    # All threshold reason codes present, plus the override marker
    expected_codes = {
        "single_adapter_mode",
        "qualified_source_threshold_met",
        "peer_reviewed_requirement_met",
        "average_quality_threshold_met",
        "citation_grounding_available",
        "model_loop_flag_overridden_by_policy",
    }
    assert expected_codes.issubset(set(pd["reason_codes"])), (
        f"missing reason codes: {expected_codes - set(pd['reason_codes'])}"
    )


# ── Negative case 1: fewer than 3 qualified ───────────────────────────────

def test_single_adapter_denied_when_fewer_than_three_qualified() -> None:
    """Fewer than 3 qualified sources on a single API must still trigger the
    loop, even if those 2 are peer-reviewed and high-quality."""
    node = _make_node()
    qual = _peer_reviewed_qual_sources(2, score=0.8)  # only 2 — below threshold
    sources = _sources_for_quals(qual, api="openalex")
    output = {
        "qualified_sources": qual,
        "quality_summary": {
            "total_evaluated": 2,
            "average_score": 0.8,
            "domain_coverage": "limited",
        },
    }
    result = node._apply_deterministic_loop_trigger(output, sources)
    assert result["loop_required"] is True, "2 qualified sources must trigger loop"
    assert "policy_decision" not in result or result.get("policy_decision", {}).get(
        "decision"
    ) != "allow_single_adapter_acceptance"


# ── Negative case 2: no peer-reviewed sources ─────────────────────────────

def test_single_adapter_denied_when_no_peer_reviewed() -> None:
    """Single-API with 5 qualified sources, decent average score, but NONE
    peer-reviewed → policy must deny, loop must trigger."""
    node = _make_node()
    qual = [
        {
            "source_ref": f"s{i}",
            "quality_score": 0.6,
            "included": True,
            "signals": {"peer_reviewed": False},  # none peer-reviewed
        }
        for i in range(5)
    ]
    sources = _sources_for_quals(qual, api="arxiv")
    output = {
        "qualified_sources": qual,
        "quality_summary": {
            "total_evaluated": 5,
            "average_score": 0.6,
            "domain_coverage": "adequate",
        },
    }
    result = node._apply_deterministic_loop_trigger(output, sources)
    assert result["loop_required"] is True
    assert (
        "policy_decision" not in result
        or result["policy_decision"].get("decision") != "allow_single_adapter_acceptance"
    )


# ── Negative case 3: average below threshold (0.4) ────────────────────────

def test_single_adapter_denied_when_average_below_threshold() -> None:
    """Single-API, 5 qualified, peer-reviewed, but average score 0.35
    (< 0.4) → policy must deny, loop must trigger."""
    node = _make_node()
    qual = [
        {
            "source_ref": f"s{i}",
            "quality_score": 0.35,  # below 0.4
            "included": True,
            "signals": {"peer_reviewed": True},
        }
        for i in range(5)
    ]
    sources = _sources_for_quals(qual, api="openalex")
    output = {
        "qualified_sources": qual,
        "quality_summary": {
            "total_evaluated": 5,
            "average_score": 0.35,
            "domain_coverage": "adequate",
        },
    }
    result = node._apply_deterministic_loop_trigger(output, sources)
    assert result["loop_required"] is True


# ── Negative case 4: model loop override refused without thresholds ───────

def test_model_loop_override_refused_without_objective_thresholds() -> None:
    """If the model sets loop_required=True but the objective thresholds are
    NOT met, the policy must NOT override the model — loop proceeds. The
    override is justified ONLY by stricter deterministic evidence, never
    subjective convenience."""
    node = _make_node()
    # Single-API but only 2 qualified, no peer-review — clearly insufficient.
    # Model correctly requested loop. Policy must not override.
    qual = [
        {
            "source_ref": f"s{i}",
            "quality_score": 0.3,
            "included": True,
            "signals": {"peer_reviewed": False},
        }
        for i in range(2)
    ]
    sources = _sources_for_quals(qual, api="arxiv")
    output = {
        "qualified_sources": qual,
        "quality_summary": {
            "total_evaluated": 2,
            "average_score": 0.3,
            "domain_coverage": "limited",
        },
        "loop_required": True,  # model requested loop
        "loop_reason": "Model: insufficient evidence.",
    }
    result = node._apply_deterministic_loop_trigger(output, sources)
    # Loop stays required — model's flag is honored because thresholds fail.
    assert result["loop_required"] is True
    # No policy_decision allowing single-adapter acceptance
    pd = result.get("policy_decision", {})
    assert pd.get("decision") != "allow_single_adapter_acceptance"
    # And no "model_loop_flag_overridden_by_policy" reason code anywhere
    if "reason_codes" in pd:
        assert "model_loop_flag_overridden_by_policy" not in pd["reason_codes"]


# ── Negative case 5: missing citation metadata (no title) ─────────────────

def test_single_adapter_denied_when_citation_not_groundable() -> None:
    """Even with 5 qualified peer-reviewed high-score sources, if any accepted
    source lacks citation-groundable metadata (empty title), the
    citation_grounding_available threshold fails and the policy must deny."""
    node = _make_node()
    qual = _peer_reviewed_qual_sources(5, score=0.7)
    # Sources exist but the 3rd one has an empty title → not citation-groundable
    sources = [
        {"source_id": f"s{i}", "origin_api": "openalex", "title": "" if i == 2 else f"Title s{i}"}
        for i in range(5)
    ]
    output = {
        "qualified_sources": qual,
        "quality_summary": {
            "total_evaluated": 5,
            "average_score": 0.7,
            "domain_coverage": "adequate",
        },
    }
    result = node._apply_deterministic_loop_trigger(output, sources)
    # Without citation_grounding_available, the policy cannot fire.
    pd = result.get("policy_decision", {})
    assert pd.get("decision") != "allow_single_adapter_acceptance", (
        "policy must not allow when any accepted source is not citation-groundable"
    )
