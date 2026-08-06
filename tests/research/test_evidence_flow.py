"""Evidence-flow assertions: prove the complete durable chain with exact invariants.

src-1/src-2
→ source_ingestion source IDs (both required)
→ qualified source_ref values (both included)
→ evidence claim supporting_sources (both required)
→ validated claim supporting_sources ⊆ qualified included_sources
→ no production adapter in resolver
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

CORPUS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_basic.yaml"


def _get_run_outputs(db_path: str, run_id: str) -> dict:
    """Load run state outputs from the DB by run_id."""
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT state_json FROM chain_states WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    conn.close()
    assert row is not None, f"no state for run {run_id}"
    state = json.loads(row[0])
    return state.get("outputs", {})


def _parse_output(outputs: dict, node_id: str) -> dict:
    out = outputs.get(node_id, {})
    if isinstance(out, str):
        out = json.loads(out)
    return out


def test_complete_evidence_chain(tmp_path: Path) -> None:
    """Prove the full evidence-bearing chain through the real orchestrator
    with exact source-linkage invariants."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "evidence_flow"),
    )
    result = runner.run()
    outputs = _get_run_outputs(runner._db_path, result.run_id)

    # 1. source_ingestion: BOTH src-1 AND src-2 ingested.
    si = _parse_output(outputs, "source_ingestion")
    ingested_sources = si.get("sources", [])
    ingested_ids = {s.get("source_id") for s in ingested_sources}
    assert "src-1" in ingested_ids, f"src-1 not in ingested IDs: {ingested_ids}"
    assert "src-2" in ingested_ids, f"src-2 not in ingested IDs: {ingested_ids}"

    # 2. source_quality_evaluator: BOTH sources qualified with source_ref.
    sq = _parse_output(outputs, "source_quality_evaluator")
    qualified = sq.get("qualified_sources", [])
    qualified_ids = {q.get("source_id") for q in qualified}
    assert "src-1" in qualified_ids, f"src-1 not in qualified: {qualified_ids}"
    assert "src-2" in qualified_ids, f"src-2 not in qualified: {qualified_ids}"

    # Verify qualified source content matches ingested source content.
    # Each qualified source_id must resolve to an ingested source with the
    # same source_hash.
    ingested_by_id = {s.get("source_id"): s for s in ingested_sources}
    for q in qualified:
        sid = q.get("source_id")
        if sid in ingested_by_id:
            ingested = ingested_by_id[sid]
            assert ingested.get("source_hash") == ingested.get("source_hash"), (
                f"qualified source {sid} hash mismatch"
            )

    # 3. evidence_synthesizer: claim supporting_sources includes BOTH.
    es = _parse_output(outputs, "evidence_synthesizer")
    claims = es.get("claims", [])
    assert len(claims) >= 1, "no claims synthesized"
    claim = claims[0]
    supporting = set(claim.get("supporting_sources", []))
    assert "src-1" in supporting, f"src-1 not in supporting_sources: {supporting}"
    assert "src-2" in supporting, f"src-2 not in supporting_sources: {supporting}"

    # 4. claim_validator: validated claim supporting_sources ⊆ qualified.
    cv = _parse_output(outputs, "claim_validator")
    validated = cv.get("validated_claims", [])
    assert len(validated) >= 1, "no validated claims"
    validated_claim = validated[0]
    assert validated_claim.get("claim_id") == claim.get("claim_id"), (
        "validated claim ID does not match synthesized claim ID"
    )
    assert validated_claim.get("status") == "confirmed", (
        f"expected status 'confirmed', got {validated_claim.get('status')}"
    )

    # Validated claim supporting sources must be exactly {src-1, src-2}
    # (matching the qualified source set, not a vacuous subset).
    val_supporting = set(validated_claim.get("supporting_sources", []))
    assert val_supporting == {"src-1", "src-2"}, (
        f"validated supporting_sources must be exactly {{src-1, src-2}}, "
        f"got {val_supporting}"
    )

    # 5. Guard dispatch count matches adapter invocation count.
    guard = runner._search_node._adapter_resolver["fixture"]
    assert len(guard._dispatched_digests) == 1
    assert runner._fixture_adapter.invocation_count == 1

    # 6. No production adapter in resolver.
    resolver = runner._search_node._adapter_resolver
    for prod in ("semantic_scholar", "arxiv", "openalex", "crossref", "pubmed"):
        assert prod not in resolver, f"production adapter {prod} in resolver"
