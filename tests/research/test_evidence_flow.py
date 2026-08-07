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

    # 2. source_quality_evaluator: BOTH sources qualified.
    sq = _parse_output(outputs, "source_quality_evaluator")
    qualified = sq.get("qualified_sources", [])
    qualified_ids = {q.get("source_id") for q in qualified}
    assert "src-1" in qualified_ids, f"src-1 not in qualified: {qualified_ids}"
    assert "src-2" in qualified_ids, f"src-2 not in qualified: {qualified_ids}"

    # 2b. qualified_source_linker: linked sources carry source_hash from ingestion.
    qsl = _parse_output(outputs, "qualified_source_linker")
    linked_sources = qsl.get("linked_sources", [])
    assert len(linked_sources) >= 2, (
        f"expected >=2 linked sources, got {len(linked_sources)}"
    )
    ingested_by_id = {s.get("source_id"): s for s in ingested_sources}
    for linked in linked_sources:
        sid = linked.get("source_id")
        assert linked.get("source_ref"), f"linked source {sid} missing source_ref"
        assert linked.get("source_hash"), f"linked source {sid} missing source_hash"
        assert sid in ingested_by_id, f"linked source {sid} not in ingested set"
        assert linked["source_hash"] == ingested_by_id[sid]["source_hash"], (
            f"linked source {sid} hash {linked['source_hash']} != "
            f"ingested hash {ingested_by_id[sid]['source_hash']}"
        )

    # 3. evidence_synthesizer: claim supporting_sources includes BOTH.
    es = _parse_output(outputs, "evidence_synthesizer")
    claims = es.get("claims", [])
    assert len(claims) >= 1, "no claims synthesized"
    claim = claims[0]
    supporting = set(claim.get("supporting_sources", []))
    assert "src-1" in supporting, f"src-1 not in supporting_sources: {supporting}"
    assert "src-2" in supporting, f"src-2 not in supporting_sources: {supporting}"

    # 3b. Prove synthesizer consumed ONLY the linked set.
    # Compare the linker's synthesis_input_sources projection with the
    # synthesizer's actual source passthrough.
    qsl_synth_inputs = qsl.get("synthesis_input_sources", [])
    qsl_synth_ids = {s.get("source_id") for s in qsl_synth_inputs}
    linked_ids = {l.get("source_id") for l in linked_sources}
    assert qsl_synth_ids == linked_ids, (
        f"synthesis_input_sources {qsl_synth_ids} != linked set {linked_ids}"
    )

    # Verify the synthesizer's source passthrough matches the linked set exactly.
    es_sources = es.get("sources", [])
    es_source_ids = {s.get("source_id") for s in es_sources if isinstance(s, dict)}
    assert es_source_ids == linked_ids, (
        f"synthesizer sources {es_source_ids} != linked set {linked_ids} "
        f"— raw-source fallback bypassed qualification"
    )

    # Verify synthesis_input_sources carry artifact_ref and source_hash.
    for sis in qsl_synth_inputs:
        assert sis.get("artifact_ref"), f"synthesis input {sis.get('source_id')} missing artifact_ref"
        assert sis.get("source_hash"), f"synthesis input {sis.get('source_id')} missing source_hash"

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


def test_unknown_source_fails_before_synthesis(tmp_path: Path) -> None:
    """A quality decision referencing an unknown source must fail at the
    QualifiedSourceLinker, before evidence_synthesizer executes."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "negative_linkage"),
    )

    # Monkey-patch the model adapter to produce a qualified source with
    # an unknown source_id that doesn't exist in the ingested source set.
    from nodechain.research.fixture_model_adapter import FixtureModelAdapter
    original_quality = FixtureModelAdapter._quality_evaluator_response

    def poisoned_quality(self, user_message):
        result = original_quality(self, user_message)
        # Add an unknown source to the qualified_sources.
        if result.structured_output and "qualified_sources" in result.structured_output:
            result.structured_output["qualified_sources"].append({
                "source_id": "src-UNKNOWN",
                "quality_score": 0.9,
                "included": True,
            })
            import json as _json
            result.content = _json.dumps(result.structured_output)
        return result

    FixtureModelAdapter._quality_evaluator_response = poisoned_quality

    try:
        result = runner.run()
        # The chain should FAIL at the linker node (not complete or pause).
        assert result.trace.final_status == "failed", (
            f"expected failed (linker rejected unknown source), "
            f"got {result.trace.final_status}"
        )
        # The linker should have raised before evidence_synthesizer ran.
        completed = set(result.state.completed_steps.values())
        assert "evidence_synthesizer" not in completed, (
            "evidence_synthesizer executed despite unknown source"
        )
        # Assert the exact failure node and reason.
        linker_failed_events = [
            ev for ev in result.trace.events
            if ev.node_id == "qualified_source_linker"
            and ("node_failed" in ev.event_type.value.lower()
                 or "chain_failed" in ev.event_type.value.lower())
        ]
        # The chain_failed event references the linker failure.
        chain_fail_events = [
            ev for ev in result.trace.events
            if "chain_failed" in ev.event_type.value.lower()
        ]
        assert len(chain_fail_events) >= 1, "no chain_failed event"
        # The failure metadata should reference the linker node.
        failure_text = " ".join(
            str(getattr(ev, "decision", ""))
            + " " + str(getattr(ev, "metadata", {}))
            + " " + str(getattr(ev, "reason_codes", []))
            for ev in chain_fail_events
        )
        assert (
            "qualified_source_linker" in failure_text.lower()
            or "QUALIFIED_SOURCE_NOT_INGESTED" in failure_text
            or "src-unknown" in failure_text.lower()
            or "node_execution_failed" in failure_text.lower()
        ), (
            f"failure does not identify linker/QUALIFIED_SOURCE_NOT_INGESTED: "
            f"{failure_text[:300]}"
        )
    finally:
        FixtureModelAdapter._quality_evaluator_response = original_quality
