"""v2.70 tests for the baseline comparison harness.

Tests verify:
1. The frozen fixture loads and has the expected shape
2. The scorer correctly classifies fabricated vs valid citations
3. The gate evaluation is deterministic and reproducible
4. The harness script exists and is importable
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

FIXTURE = Path(__file__).resolve().parent.parent / "data" / "v2.70_baseline" / "frozen_comparison_fixture.json"
HARNESS = Path(__file__).resolve().parent.parent / "scripts" / "baseline_comparison.py"


class TestFrozenFixture:
    """The frozen fixture must be present and well-formed."""

    def test_fixture_exists(self):
        assert FIXTURE.exists(), f"frozen fixture not found at {FIXTURE}"

    def test_fixture_has_required_fields(self):
        if not FIXTURE.exists():
            pytest.skip("fixture not present")
        with open(FIXTURE) as f:
            data = json.load(f)
        assert data["comparison_version"] == "v2.70.0"
        assert "research_question" in data
        assert "sources" in data
        assert len(data["sources"]) > 0
        assert "source_set_hash" in data
        assert "nodechain_result" in data

    def test_source_set_hash_is_stable(self):
        """Recomputing the hash from the fixture's own sources must match."""
        if not FIXTURE.exists():
            pytest.skip("fixture not present")
        import hashlib
        with open(FIXTURE) as f:
            data = json.load(f)
        recomputed = hashlib.sha256(
            json.dumps(data["sources"], sort_keys=True).encode()
        ).hexdigest()[:16]
        assert recomputed == data["source_set_hash"], (
            f"source set hash mismatch: fixture says {data['source_set_hash']}, "
            f"recomputed {recomputed}"
        )


class TestScorer:
    """The comparison scorer must correctly classify citations."""

    def test_fabricated_citation_detected(self):
        """A source_id that's not in the valid set counts as fabricated."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from baseline_comparison import score_comparison

        sources = [{"source_id": "real-id-1", "title": "Real Paper"}]
        nodechain_result = {
            "claims": [
                {"supporting_sources": ["real-id-1"], "contradicting_sources": []},
                {"supporting_sources": ["FABRICATED-ID"], "contradicting_sources": []},
            ],
            "citations": [],
            "validated_claims": [],
        }
        baseline_result = {"content": "no citations here", "latency_ms": 1000}
        scores = score_comparison(nodechain_result, baseline_result, sources, "test_hash")
        assert scores["nodechain"]["fabricated_citations"] == 1

    def test_zero_fabricated_when_all_valid(self):
        """All valid source_ids = 0 fabricated."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from baseline_comparison import score_comparison

        sources = [{"source_id": "s1"}, {"source_id": "s2"}]
        nodechain_result = {
            "claims": [
                {"supporting_sources": ["s1", "s2"], "contradicting_sources": []},
            ],
            "citations": [],
            "validated_claims": [],
        }
        baseline_result = {"content": "", "latency_ms": 0}
        scores = score_comparison(nodechain_result, baseline_result, sources, "test_hash")
        assert scores["nodechain"]["fabricated_citations"] == 0

    def test_gate_overall_pass_when_all_pass(self):
        """When all gates pass, overall_pass is True."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from baseline_comparison import score_comparison

        sources = [{"source_id": "s1"}]
        nodechain_result = {
            "claims": [{"supporting_sources": ["s1"], "contradicting_sources": []}],
            "citations": [{"source_ref": "s1"}],
            "validated_claims": [{"claim_id": "c1"}],
        }
        baseline_result = {"content": "", "latency_ms": 0}
        scores = score_comparison(nodechain_result, baseline_result, sources, "test_hash")
        assert scores["overall_pass"] is True


class TestHarnessReproducibility:
    """The harness must be reproducible from committed artifacts."""

    def test_harness_script_exists(self):
        assert HARNESS.exists(), f"baseline_comparison.py not found at {HARNESS}"

    def test_harness_importable(self):
        sys.path.insert(0, str(HARNESS.parent))
        import baseline_comparison
        assert hasattr(baseline_comparison, "run_baseline_agent")
        assert hasattr(baseline_comparison, "score_comparison")
        assert hasattr(baseline_comparison, "_load_fixture")
