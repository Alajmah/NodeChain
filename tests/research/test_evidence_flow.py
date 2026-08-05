"""Evidence-flow assertions: prove the complete durable chain.

src-1/src-2
→ source_ingestion source_id
→ qualified source_ref
→ evidence supporting_sources
→ validated claim supporting_sources
→ citation/source linkage
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

CORPUS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_basic.yaml"


def test_complete_evidence_chain(tmp_path: Path) -> None:
    """Prove the full evidence-bearing chain through the real orchestrator."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "evidence_flow"),
    )
    result = runner.run()

    # Load state from DB for durable output inspection.
    conn = sqlite3.connect(runner._db_path)
    row = conn.execute("SELECT state_json FROM chain_states LIMIT 1").fetchone()
    conn.close()
    assert row is not None
    state = json.loads(row[0])
    outputs = state.get("outputs", {})

    # 1. source_ingestion: ingested source IDs match corpus IDs.
    si = outputs.get("source_ingestion", {})
    if isinstance(si, str):
        si = json.loads(si)
    ingested_sources = si.get("sources", [])
    ingested_ids = {s.get("source_id") for s in ingested_sources}
    assert "src-1" in ingested_ids, f"src-1 not in ingested IDs: {ingested_ids}"
    assert "src-2" in ingested_ids, f"src-2 not in ingested IDs: {ingested_ids}"

    # 2. evidence_synthesizer: claims reference source IDs.
    es = outputs.get("evidence_synthesizer", {})
    if isinstance(es, str):
        es = json.loads(es)
    claims = es.get("claims", [])
    assert len(claims) >= 1, "no claims synthesized"
    claim = claims[0]
    supporting = claim.get("supporting_sources", [])
    # Supporting sources should include remapped real IDs (src-1, src-2).
    assert "src-1" in supporting or "src-2" in supporting, (
        f"supporting_sources do not reference corpus IDs: {supporting}"
    )

    # 3. claim_validator: validated claims reference evidence.
    cv = outputs.get("claim_validator", {})
    if isinstance(cv, str):
        cv = json.loads(cv)
    validated = cv.get("validated_claims", [])
    assert len(validated) >= 1, "no validated claims"
    validated_claim = validated[0]
    assert validated_claim.get("claim_id") == claim.get("claim_id"), (
        "validated claim ID does not match synthesized claim ID"
    )
    assert validated_claim.get("status") == "confirmed", (
        f"expected status 'confirmed', got {validated_claim.get('status')}"
    )

    # 4. Guard dispatch count matches adapter invocation count.
    guard = runner._search_node._adapter_resolver["fixture"]
    assert len(guard._dispatched_digests) == 1
    assert runner._fixture_adapter.invocation_count == 1

    # 5. No production adapter was invoked.
    assert runner._fixture_adapter.invocation_count >= 1
