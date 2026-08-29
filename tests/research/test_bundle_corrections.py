"""Correction tests for the ResearchWorkspaceBundleV1 contract blockers.

Each test targets one of the six blockers:

* Blocker 1 — research_trace.json schema + ResearchTrace model + canonical
  file-set membership.
* Blocker 2 — stale-hash finalization rejects manifests computed against
  different bytes, leaving no partial bundle.
* Blocker 3 — BundleReader contract: duplicate inventory paths, exact canonical
  set, missing/extra inventory entries, schema validation of every non-manifest
  document, unsupported-version rejection, get_document rejects non-canonical
  names.
* Blocker 4 — cross-document truth enforcement + terminal-status gating.
* Blocker 5 — set-like array canonicalization produces byte-identical output
  under permutation while preserving ordered arrays.
* Blocker 6 — bundle module reuses SCHEMA_ROOT from the shared validator.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

from nodechain.research import bundle as bundle_mod
from nodechain.research.bundle import (
    BUNDLE_FILES,
    BundleReader,
    BundleWriter,
    TERMINAL_RUN_STATUSES,
    _validate_cross_document_truth,
)
from nodechain.research.exceptions import (
    BundleError,
    BundleFinalizationError,
    BundleIntegrityError,
    BundleValidationError,
)
from nodechain.research.models import (
    ResearchTrace,
    TraceEvent,
)
from nodechain.research.serialization import (
    DEFAULT_SET_LIKE_PATHS,
    canonical_json,
    canonical_json_bytes,
    canonical_json_with_set_normalization,
)

# The deterministic fixtures are duplicated locally because ``tests`` is not a
# package (no ``tests/__init__.py``), so cross-module imports across test files
# are not reliable. Keep these in sync with test_bundle_contract.py.

TS = "2026-08-03T14:22:01Z"
RUN_ID = "run-001"
CHAIN_ID = "chain-research-1"
COMMIT = "0" * 40
INPUT_DIGEST = "a" * 64


def _brief() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "created_at": TS,
        "question": "Is async Rust memory-safe across await points?",
        "scope": {
            "domains": ["systems", "pl"],
            "time_range": {"start": "2020-01-01T00:00:00Z", "end": "2026-08-03T00:00:00Z"},
        },
        "constraints": {
            "min_sources": 1,
            "max_sources": 5,
            "required_adapters": ["arxiv"],
        },
        "target_depth": "standard",
        "preferred_language": "en",
        "memory_context_requested": False,
    }


def _run() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "chain_id": CHAIN_ID,
        "started_at": TS,
        "updated_at": TS,
        "status": "completed",
        "provider_mode": "live",
        "current_step": "report",
        "steps_completed": [
            {"node_id": "ingest", "completed_at": TS, "succeeded": True},
        ],
        "input_digest": INPUT_DIGEST,
        "finalized_at": TS,
        "replay_eligible": True,
    }


def _plan() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "created_at": TS,
        "steps": [
            {"node_id": "ingest", "position": 1, "node_type": "tool", "adapter": "arxiv"},
            {"node_id": "synthesize", "position": 2, "node_type": "model"},
        ],
        "adapters_required": ["arxiv"],
        "estimated_cost_usd": 0.12,
        "loop_triggered": False,
    }


def _sources() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "retrieved_at": TS,
        "sources": [
            {
                "source_id": "src-1",
                "origin_api": "arxiv",
                "query_used": "rust async safety",
                "retrieved_at": TS,
                "title": "Async Rust Safety",
                "doi": "10.1000/1",
                "authors": ["A. Author"],
                "abstract": "A study.",
                "source_hash": "b" * 64,
            }
        ],
        "adapter_coverage": {"arxiv": 1},
        "deduplication_count": 0,
    }


def _evidence() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "extracted_at": TS,
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source_ids": ["src-1"],
                "extracted_text": "Async rust is safe when pinned.",
                "evidence_type": "quote",
                "confidence": 0.9,
            }
        ],
        "extraction_model": "model-x",
        "mean_confidence": 0.9,
    }


def _claims() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "synthesized_at": TS,
        "claims": [
            {
                "claim_id": "cl-1",
                "statement": "Async Rust is memory-safe.",
                "status": "supported",
                "supporting_evidence_ids": ["ev-1"],
                "contradicting_evidence_ids": [],
                "citation_ids": ["cit-1"],
                "confidence": 0.85,
                "uncertainty_markers": [
                    {"marker_id": "u-1", "description": "edge cases", "affected_claim_ids": ["cl-1"]}
                ],
                "validation_results": [
                    {"validation_id": "v-1", "target_type": "claim", "target_id": "cl-1",
                     "check_name": "non_empty", "passed": True, "message": "ok"}
                ],
            }
        ],
        "synthesis_model": "model-x",
        "executive_answer": "Yes, with caveats.",
    }


def _citations() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "formatted_at": TS,
        "citations": [
            {
                "citation_id": "cit-1",
                "source_id": "src-1",
                "evidence_ids": ["ev-1"],
                "formatted_citation": "Author (2020). Async Rust Safety.",
            }
        ],
        "style": "apa",
    }


def _uncertainties() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "recorded_at": TS,
        "uncertainties": [
            {"marker_id": "u-1", "description": "edge cases", "affected_claim_ids": ["cl-1"]}
        ],
        "overall_uncertainty": "moderate",
    }


def _validations() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "executed_at": TS,
        "validation_results": [
            {"validation_id": "v-1", "target_type": "claim", "target_id": "cl-1",
             "check_name": "non_empty", "passed": True, "message": "ok"}
        ],
        "checks_run": ["non_empty"],
        "pass_rate": 1.0,
    }


def _policy_decisions() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "recorded_at": TS,
        "policy_decisions": [
            {"decision_id": "d-1", "decision_type": "memory_write_allow",
             "reason": "policy permits", "decided_at": TS, "decider_identity": "policy-v1"}
        ],
        "policy_version": "policy-v1",
    }


def _review_decisions() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "recorded_at": TS,
        "review_decisions": [
            {"review_id": "rev-1", "run_id": RUN_ID, "decision": "approve",
             "reason": "ok", "reviewer_identity": "alice", "decided_at": TS}
        ],
        "review_required": True,
        "review_completed": True,
    }


def _failures() -> dict:
    return {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "recorded_at": TS,
        "failures": [
            {"failure_id": "f-1", "adapter_name": "arxiv",
             "fault_type": "timeout_after_dispatch", "occurred_at": TS,
             "dispatch_occurred": True, "evidence_unavailable": False,
             "affected_claim_ids": []}
        ],
        "degraded_mode": False,
        "affected_adapter_count": 1,
    }


def _trace() -> dict:
    return {
        "run_id": RUN_ID,
        "chain_id": CHAIN_ID,
        "events": [
            {"step_id": 0, "node_id": "ingest", "event_type": "step_completed",
             "actor": "arxiv"},
            {"step_id": 1, "node_id": "synthesize", "event_type": "step_started",
             "actor": "orchestrator"},
        ],
        "total_cost_usd": 0.12,
        "total_duration_ms": 1500,
        "summary": {"steps": 2},
    }


def _report() -> dict:
    return {
        "run_id": RUN_ID,
        "run_status": "completed",
        "executive_answer": "Yes, with caveats.",
        "claim_count": 1,
        "supported_claims": 1,
        "contested_claims": 0,
        "sources_cited": 1,
        "adapters_used": ["arxiv"],
        "failures_recorded": 1,
        "review_required": True,
        "review_completed": True,
        "replay_eligible": True,
    }


def _all_documents() -> dict[str, dict]:
    """Return every non-manifest document keyed by canonical filename."""
    return {
        "brief.json": _brief(),
        "run.json": _run(),
        "plan.json": _plan(),
        "sources.json": _sources(),
        "evidence.json": _evidence(),
        "claims.json": _claims(),
        "citations.json": _citations(),
        "uncertainties.json": _uncertainties(),
        "validations.json": _validations(),
        "policy-decisions.json": _policy_decisions(),
        "review-decisions.json": _review_decisions(),
        "failures.json": _failures(),
        "trace.json": _trace(),
        "report.json": _report(),
    }


def _write_valid_bundle(dest: Path) -> Path:
    """Write a full valid bundle into ``dest`` and return the finalized path."""
    writer = BundleWriter(dest)
    docs = _all_documents()
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT,
        run_id=RUN_ID,
        chain_id=CHAIN_ID,
        blueprint_version="blueprint-1",
        created_at=TS,
        finalized_at=TS,
        run_status="completed",
        input_digest=INPUT_DIGEST,
        provider_mode="live",
        fixture_corpus_version=None,
        trace_reference="trace.json",
        replay_eligible=True,
    )
    return writer.finalize(manifest)


# --------------------------------------------------------------------------- #
# Blocker 1: research_trace.json schema + typed trace model
# --------------------------------------------------------------------------- #


def test_trace_schema_is_part_of_canonical_file_set() -> None:
    assert "trace.json" in BUNDLE_FILES
    assert bundle_mod._FILENAME_TO_SCHEMA_REF["trace"] == (
        "nodechain://schemas/semantic_types/research_trace"
    )


def test_trace_schema_file_exists() -> None:
    schema_path = bundle_mod.SCHEMA_ROOT / "semantic_types" / "research_trace.json"
    assert schema_path.exists(), schema_path
    schema = json.loads(schema_path.read_text())
    # Core required fields.
    for req in ("run_id", "chain_id", "events"):
        assert req in schema["required"], req
    # Strict contract: root rejects unknown fields.
    assert schema["additionalProperties"] is False
    event_item = schema["properties"]["events"]["items"]
    for req in ("step_id", "node_id", "event_type", "actor"):
        assert req in event_item["required"], req
    # Strict contract: event envelope rejects unknown fields; extensibility is
    # via the explicit, versioned extensions surface.
    assert event_item["additionalProperties"] is False
    assert "extensions" in event_item["properties"]
    assert "extensions_version" in event_item["properties"]
    assert "extensions" in schema["properties"]
    assert "extensions_version" in schema["properties"]


def test_research_trace_model_round_trip() -> None:
    trace = ResearchTrace(
        run_id=RUN_ID,
        chain_id=CHAIN_ID,
        events=[
            TraceEvent(step_id=0, node_id="ingest", event_type="step_started",
                       actor="orchestrator"),
            TraceEvent(step_id=1, node_id="synth", event_type="step_completed",
                       actor="model"),
        ],
        total_cost_usd=0.05,
        total_duration_ms=123,
        summary={"a": 1},
    )
    # Frozen.
    with pytest.raises(Exception):
        trace.run_id = "x"  # type: ignore[misc]
    # Rejects non-monotonic step_id.
    with pytest.raises(Exception):
        ResearchTrace(
            run_id=RUN_ID, chain_id=CHAIN_ID,
            events=[
                TraceEvent(step_id=2, node_id="a", event_type="x", actor="y"),
                TraceEvent(step_id=1, node_id="b", event_type="x", actor="y"),
            ],
        )


def test_trace_schema_validation_rejects_missing_chain_id(tmp_path: Path) -> None:
    """A trace without chain_id must fail schema validation during finalize."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    del docs["trace.json"]["chain_id"]
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="trace.json"):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists()


def test_trace_schema_validation_rejects_event_missing_core_field(
    tmp_path: Path,
) -> None:
    """A trace event missing a core required field must fail schema validation."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["trace.json"]["events"][0].pop("actor")
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="trace.json"):
        writer.finalize(manifest)


def test_trace_rejects_unknown_envelope_fields(tmp_path: Path) -> None:
    """Strict trace contract: arbitrary event/root envelope fields are rejected.
    Adapter-specific provenance must travel in the explicit ``extensions``
    object."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    # Arbitrary event field -> rejected.
    docs["trace.json"]["events"][0]["custom_meta"] = {"anything": [1, 2]}
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="trace.json"):
        writer.finalize(manifest)
    assert not (tmp_path / "bundle").exists()


def test_trace_rejects_unknown_root_field(tmp_path: Path) -> None:
    """Strict trace contract: arbitrary root fields are rejected."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["trace.json"]["custom_top"] = "ok"
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="trace.json"):
        writer.finalize(manifest)


def test_trace_explicit_extensions_surface_is_permitted(tmp_path: Path) -> None:
    """The explicit, versioned ``extensions`` object is the sanctioned extension
    surface on both the root and individual events."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["trace.json"]["extensions_version"] = "1.0"
    docs["trace.json"]["extensions"] = {"adapter_x": {"note": "ok"}}
    docs["trace.json"]["events"][0]["extensions_version"] = "1.0"
    docs["trace.json"]["events"][0]["extensions"] = {"latency_ms": 12}
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    finalized = writer.finalize(manifest)
    assert (finalized / "trace.json").exists()


def test_trace_extensions_require_version(tmp_path: Path) -> None:
    """``extensions`` without ``extensions_version`` is rejected by the model."""
    from nodechain.research.models import ResearchTrace, TraceEvent
    with pytest.raises(Exception):
        TraceEvent(
            step_id=0, node_id="n", event_type="t", actor="a",
            extensions={"foo": "bar"},
        )
    with pytest.raises(Exception):
        ResearchTrace(
            run_id="r", chain_id="c", events=[],
            extensions={"foo": "bar"},
        )


# --------------------------------------------------------------------------- #
# Blocker 2: stale-hash finalization
# --------------------------------------------------------------------------- #


def test_finalize_rejects_stale_file_hash(tmp_path: Path) -> None:
    """If a staged file is mutated AFTER compute_manifest, finalize must reject
    with BundleFinalizationError and leave no final bundle."""
    dest = tmp_path / "bundle"
    writer = BundleWriter(dest)
    docs = _all_documents()
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    # Mutate a staged file post-compute_manifest.
    brief_path = writer.staging_dir / "brief.json"
    doc = json.loads(brief_path.read_text())
    doc["question"] = "tampered after compute_manifest"
    brief_path.write_text(canonical_json(doc))

    with pytest.raises(BundleFinalizationError, match="stale hash"):
        writer.finalize(manifest)
    # No finalized bundle, no leftover staging.
    assert not dest.exists()
    assert not writer.staging_dir.exists()


def test_finalize_rejects_tampered_manifest_digest(tmp_path: Path) -> None:
    """If the manifest's bundle_digest is tampered but file hashes agree,
    finalize must reject the recomputed digest mismatch."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    bad_manifest = manifest.model_copy(
        update={"bundle_digest": "0" * 64}
    )
    with pytest.raises(BundleFinalizationError, match="stale bundle_digest"):
        writer.finalize(bad_manifest)
    assert not writer.staging_dir.exists()


def test_finalize_accepts_unchanged_staging(tmp_path: Path) -> None:
    """Sanity: with no mutation between compute_manifest and finalize, the
    stale-hash guard passes and the bundle finalizes."""
    dest = tmp_path / "bundle"
    finalized = _write_valid_bundle(dest)
    assert (finalized / "manifest.json").exists()


# --------------------------------------------------------------------------- #
# Blocker 3: BundleReader contract
# --------------------------------------------------------------------------- #


def _tamper_manifest(dest: Path, mutate) -> None:
    """Read the finalized manifest, apply ``mutate(doc) -> doc``, rewrite it."""
    path = dest / "manifest.json"
    doc = json.loads(path.read_text())
    doc = mutate(doc)
    path.write_text(canonical_json(doc))


def test_reader_rejects_duplicate_inventory_paths(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)

    def dup(doc):
        # Duplicate one entry in the inventory.
        entry = dict(doc["artifact_inventory"][0])
        doc["artifact_inventory"].append(entry)
        return doc

    _tamper_manifest(dest, dup)
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError, match="duplicate inventory path"):
        reader.verify_integrity()


def test_reader_rejects_missing_canonical_inventory_path(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)

    def drop(doc):
        doc["artifact_inventory"] = [
            e for e in doc["artifact_inventory"] if e["path"] != "brief.json"
        ]
        return doc

    _tamper_manifest(dest, drop)
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError, match="missing canonical paths"):
        reader.verify_integrity()


def test_reader_rejects_extra_noncanonical_inventory_path(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)

    def add_extra(doc):
        doc["artifact_inventory"].append(
            {"path": "secret.json", "sha256": "a" * 64}
        )
        return doc

    _tamper_manifest(dest, add_extra)
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError, match="noncanonical paths"):
        reader.verify_integrity()


def test_reader_schema_validates_every_non_manifest_document(
    tmp_path: Path,
) -> None:
    """A non-manifest document that no longer matches its schema (but whose
    hash has also been tampered to match the manifest) must still be caught by
    schema validation. We craft a document that is structurally invalid for the
    schema and recompute the manifest inventory + digest so hash checks pass,
    isolating the schema-validation path."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # Tamper brief.json with an unknown field, then fix up manifest hashes and
    # digest so the only remaining failure is schema validation.
    brief_path = dest / "brief.json"
    doc = json.loads(brief_path.read_text())
    doc["unknown_field"] = "boom"
    brief_path.write_text(canonical_json(doc))

    _recompute_manifest_hashes(dest)
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="brief.json"):
        reader.verify_integrity()


def _recompute_manifest_hashes(dest: Path) -> None:
    """Rewrite manifest.json with hashes/digest recomputed from current files
    so that only non-hash checks (schema, version, truth) can fail."""
    from nodechain.research.bundle import (
        _NON_MANIFEST_FILES,
        compute_bundle_digest,
    )
    from nodechain.research.serialization import compute_file_hash

    manifest_path = dest / "manifest.json"
    manifest_doc = json.loads(manifest_path.read_text())
    inventory = [
        {"path": f, "sha256": compute_file_hash(dest / f)}
        for f in _NON_MANIFEST_FILES
    ]
    manifest_doc["artifact_inventory"] = inventory
    new_digest = compute_bundle_digest(inventory, manifest_doc)
    manifest_doc["bundle_digest"] = new_digest
    manifest_path.write_text(canonical_json(manifest_doc))


def test_reader_rejects_unsupported_version_in_any_document(
    tmp_path: Path,
) -> None:
    """An unsupported bundle_version in any document must be rejected by the
    reader. Because the schema pins bundle_version to const '1.0', this is
    surfaced through schema validation (which runs on every non-manifest
    document per Blocker 3) before the explicit version check; either path
    satisfies the contract."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # Tamper run.json's bundle_version and fix up manifest hashes.
    run_path = dest / "run.json"
    doc = json.loads(run_path.read_text())
    doc["bundle_version"] = "2.0"
    run_path.write_text(canonical_json(doc))
    _recompute_manifest_hashes(dest)
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="run.json"):
        reader.verify_integrity()


def test_reader_get_document_rejects_noncanonical_name(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError):
        reader.get_document("not-a-bundle-file.json")
    with pytest.raises(BundleIntegrityError):
        reader.get_document("README.md")
    # Canonical name still works.
    assert reader.get_document("brief.json")["run_id"] == RUN_ID


# --------------------------------------------------------------------------- #
# Blocker 4: cross-document truth + terminal-status enforcement
# --------------------------------------------------------------------------- #


def test_cross_document_truth_detects_run_id_mismatch() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    docs["brief.json"]["run_id"] = "different-run"
    with pytest.raises(BundleValidationError, match="run_id"):
        _validate_cross_document_truth(docs)


def test_cross_document_truth_detects_review_record_run_id_mismatch() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    docs["review-decisions.json"]["review_decisions"][0]["run_id"] = "other"
    with pytest.raises(BundleValidationError, match="run_id"):
        _validate_cross_document_truth(docs)


def test_cross_document_truth_detects_run_status_mismatch() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    docs["run.json"]["status"] = "failed"  # disagrees with manifest
    with pytest.raises(BundleValidationError, match="run.json"):
        _validate_cross_document_truth(docs)


def test_cross_document_truth_detects_input_digest_mismatch() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    docs["run.json"]["input_digest"] = "b" * 64
    with pytest.raises(BundleValidationError, match="input_digest"):
        _validate_cross_document_truth(docs)


def test_cross_document_truth_detects_bad_trace_reference() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    docs["manifest.json"]["trace_reference"] = "trace elsewhere.json"
    with pytest.raises(BundleValidationError, match="trace_reference"):
        _validate_cross_document_truth(docs)


def test_cross_document_truth_detects_trace_run_id_mismatch() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    docs["trace.json"]["run_id"] = "wrong"
    with pytest.raises(BundleValidationError, match="trace"):
        _validate_cross_document_truth(docs)


def test_cross_document_truth_passes_on_consistent_bundle() -> None:
    docs = _all_documents()
    docs["manifest.json"] = _manifest_doc_from_docs(docs, run_status="completed")
    _validate_cross_document_truth(docs)  # must not raise


@pytest.mark.parametrize("status", ["running", "paused_for_review"])
def test_finalize_rejects_non_terminal_status(
    tmp_path: Path, status: str
) -> None:
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    # Make run.json AND report.json agree with the (non-terminal) manifest
    # status so the only blocker is the terminal-status gate.
    docs["run.json"]["status"] = status
    docs["report.json"]["run_status"] = status
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=status, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="non-terminal"):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists()


@pytest.mark.parametrize("status", sorted(TERMINAL_RUN_STATUSES))
def test_finalize_accepts_each_terminal_status(
    tmp_path: Path, status: str
) -> None:
    """All terminal statuses finalize successfully when the bundle is
    internally consistent."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["run.json"]["status"] = status
    docs["report.json"]["run_status"] = status
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=status, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    finalized = writer.finalize(manifest)
    assert (finalized / "manifest.json").exists()
    # verify_integrity must also pass (it re-runs truth + terminal checks).
    assert BundleReader(finalized).verify_integrity() is True


def test_reader_verify_integrity_enforces_cross_document_truth(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # Tamper report.run_status and recompute manifest hashes so the only
    # remaining failure is the truth check.
    report_path = dest / "report.json"
    doc = json.loads(report_path.read_text())
    doc["run_status"] = "failed"  # disagrees with manifest's 'completed'
    report_path.write_text(canonical_json(doc))
    _recompute_manifest_hashes(dest)
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="run_status"):
        reader.verify_integrity()


# --------------------------------------------------------------------------- #
# Blocker 5: set-like array canonicalization
# --------------------------------------------------------------------------- #


def test_set_normalization_byte_identical_under_permutation() -> None:
    """Shuffling the elements of designated set-like arrays must not change the
    canonical bytes."""
    docs = _all_documents()
    original = canonical_json_with_set_normalization(docs)

    permuted = json.loads(json.dumps(docs))  # deep copy
    # Permute several set-like arrays.
    permuted["evidence.json"]["evidence"][0]["source_ids"].reverse()
    permuted["claims.json"]["claims"][0]["supporting_evidence_ids"].reverse()
    permuted["claims.json"]["claims"][0]["citation_ids"].reverse()
    permuted["citations.json"]["citations"][0]["evidence_ids"].reverse()
    permuted["plan.json"]["adapters_required"].reverse()
    permuted["report.json"]["adapters_used"].reverse()
    permuted["sources.json"]["sources"][0]["authors"].reverse()

    permuted_bytes = canonical_json_with_set_normalization(permuted)
    assert permuted_bytes == original


def test_set_normalization_preserves_ordered_arrays() -> None:
    """Semantically ordered arrays (events, policy_decisions, steps) must NOT
    be reordered."""
    docs = _all_documents()
    # Add a second event with a distinct step_id.
    docs["trace.json"]["events"].append(
        {"step_id": 5, "node_id": "z", "event_type": "step_started",
         "actor": "orchestrator"}
    )
    forward = canonical_json_with_set_normalization(docs)
    # Build a reversed-events copy.
    reversed_docs = json.loads(json.dumps(docs))
    reversed_docs["trace.json"]["events"] = list(
        reversed(reversed_docs["trace.json"]["events"])
    )
    reversed_bytes = canonical_json_with_set_normalization(reversed_docs)
    assert forward != reversed_bytes, "events order must be preserved"


def test_set_normalization_default_paths_nonempty_and_ids_only() -> None:
    assert DEFAULT_SET_LIKE_PATHS
    # Ordered arrays must NOT appear in the default set.
    for forbidden in (
        "events",
        "policy_decisions",
        "review_decisions",
        "steps",
        "steps_completed",
        "failures",
    ):
        assert forbidden not in DEFAULT_SET_LIKE_PATHS


def test_set_normalization_explicit_paths_override() -> None:
    data = {"items": [3, 1, 2]}
    out = canonical_json_with_set_normalization(data, set_like_paths=["items"])
    assert json.loads(out)["items"] == [1, 2, 3]
    # Without the path, order is preserved.
    out2 = canonical_json_with_set_normalization(data, set_like_paths=[])
    assert json.loads(out2)["items"] == [3, 1, 2]


def test_set_normalization_handles_missing_fields() -> None:
    """Paths that do not resolve must be a no-op, not an error."""
    data = {"a": {"b": [2, 1]}}
    out = canonical_json_with_set_normalization(
        data, set_like_paths=["a.b", "a.missing", "x.y"]
    )
    assert json.loads(out)["a"]["b"] == [1, 2]


# --------------------------------------------------------------------------- #
# Blocker 6: shared SCHEMA_ROOT
# --------------------------------------------------------------------------- #


def test_bundle_module_uses_shared_schema_root() -> None:
    from nodechain.validation.schema_validator import SCHEMA_ROOT as SHARED

    assert bundle_mod.SCHEMA_ROOT is SHARED
    # No local schema-root computation symbols remain in the module namespace.
    for name in (
        "_PKG_SCHEMA_ROOT",
        "_SOURCE_SCHEMA_ROOT",
    ):
        assert not hasattr(bundle_mod, name), f"stale symbol {name} present"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _manifest_doc_from_docs(docs: dict[str, dict], run_status: str) -> dict:
    """Build a manifest doc consistent with the supplied documents (so truth
    checks pass) for use in unit-testing _validate_cross_document_truth."""
    from nodechain.research.bundle import (
        _NON_MANIFEST_FILES,
        compute_bundle_digest,
    )
    from nodechain.research.serialization import canonical_json_bytes, compute_sha256

    inventory = [
        {"path": f, "sha256": compute_sha256(canonical_json_bytes(docs[f]))}
        for f in _NON_MANIFEST_FILES
    ]
    base = {
        "bundle_version": "1.0",
        "run_id": RUN_ID,
        "chain_id": CHAIN_ID,
        "blueprint_version": "bp-1",
        "created_at": TS,
        "finalized_at": TS,
        "run_status": run_status,
        "source_commit": COMMIT,
        "input_digest": INPUT_DIGEST,
        "artifact_inventory": inventory,
        "provider_mode": "live",
        "fixture_corpus_version": "corpus-1",
        "trace_reference": "trace.json",
        "replay_eligible": True,
    }
    base["bundle_digest"] = compute_bundle_digest(inventory, base)
    return base


# =========================================================================== #
# Round-2 correction tests (reviewer blockers on cd624a9)
# =========================================================================== #
#
# These target the five blockers raised against the first correction commit:
#
# R2-1 — set-like canonicalization is wired into the production BundleWriter
#        path (not just the standalone helper), with genuinely multi-element
#        differently-ordered arrays, proving byte-identical files, identical
#        per-file hashes, identical bundle_digest, and that ordered arrays
#        (trace events, plan steps, review/policy decisions) remain
#        order-sensitive.
# R2-2 — BundleReader.verify_integrity enforces terminal-only status even when
#        every document is internally consistent on a non-terminal status, with
#        hashes and digest recomputed so the rejection is purely the terminal
#        gate.
# R2-3 — strict trace contract (covered above: root + event
#        additionalProperties:false, explicit extensions surface).
# R2-4 — trace.chain_id is checked against manifest.chain_id, with a tamper
#        test that recomputes hashes and digest before reader verification.
# R2-5 — physical directory member-set verification: extra files / directories
#        / symlinks are rejected even when the manifest inventory is correct.
# --------------------------------------------------------------------------- #


def _write_bundle_with_documents(dest: Path, docs: dict[str, dict]) -> Path:
    """Write a full bundle from the supplied document dict and finalize it."""
    writer = BundleWriter(dest)
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    return writer.finalize(manifest)


# --------------------------------------------------------------------------- #
# R2-1: production-path set-like canonicalization
# --------------------------------------------------------------------------- #


def _docs_with_multi_element_set_like_arrays() -> dict[str, dict]:
    """Documents whose set-like scalar arrays have >= 3 distinct elements so
    that reordering is a genuine permutation (not a no-op on 0/1-element
    arrays). All IDs referenced are real and cross-reference-valid: extra
    sources/evidence/citations are added so the multi-element arrays all point
    at entities that exist."""
    docs = _all_documents()
    # Add two more sources so source arrays can be multi-element.
    docs["sources.json"]["sources"].extend([
        {"source_id": "src-2", "origin_api": "arxiv", "query_used": "q2",
         "retrieved_at": TS, "title": "B", "doi": "10.1000/2",
         "authors": ["amy", "zoe"], "abstract": "B.", "source_hash": "c" * 64},
        {"source_id": "src-3", "origin_api": "arxiv", "query_used": "q3",
         "retrieved_at": TS, "title": "C", "doi": "10.1000/3",
         "authors": ["bob"], "abstract": "C.", "source_hash": "d" * 64},
    ])
    # sources.authors — nested per-source (multi-element on src-1).
    docs["sources.json"]["sources"][0]["authors"] = ["zoe", "amy", "bob"]
    # brief scope.domains + constraints.required/excluded_adapters.
    docs["brief.json"]["scope"]["domains"] = ["physics", "math", "cs"]
    docs["brief.json"]["constraints"]["required_adapters"] = ["arxiv", "web", "kb"]
    docs["brief.json"]["constraints"]["excluded_adapters"] = ["x", "y", "z"]
    # Add two more evidence records so evidence arrays can be multi-element.
    docs["evidence.json"]["evidence"].extend([
        {"evidence_id": "ev-2", "source_ids": ["src-2"], "extracted_text": "e2",
         "evidence_type": "quote", "confidence": 0.8},
        {"evidence_id": "ev-3", "source_ids": ["src-3"], "extracted_text": "e3",
         "evidence_type": "quote", "confidence": 0.7},
    ])
    # evidence.source_ids — per-record, multi-element.
    docs["evidence.json"]["evidence"][0]["source_ids"] = ["src-3", "src-1", "src-2"]
    # Add a second citation so citation arrays can be multi-element.
    docs["citations.json"]["citations"].append({
        "citation_id": "cit-2", "source_id": "src-2",
        "evidence_ids": ["ev-2"], "formatted_citation": "Author (2021). B.",
    })
    # claims supporting/contradicting/citation ids — per-record, multi-element.
    docs["claims.json"]["claims"][0]["supporting_evidence_ids"] = ["ev-3", "ev-1", "ev-2"]
    docs["claims.json"]["claims"][0]["contradicting_evidence_ids"] = ["ev-2", "ev-1"]
    docs["claims.json"]["claims"][0]["citation_ids"] = ["cit-2", "cit-1"]
    # citations.evidence_ids — per-record, multi-element.
    docs["citations.json"]["citations"][0]["evidence_ids"] = ["ev-2", "ev-1"]
    # validations.checks_run — top-level scalar array.
    docs["validations.json"]["checks_run"] = ["c3", "c1", "c2"]
    # report.adapters_used — top-level scalar array.
    docs["report.json"]["adapters_used"] = ["wb", "arxiv", "kb"]
    return docs


def test_production_canonicalization_byte_identical_under_permutation(
    tmp_path: Path,
) -> None:
    """Two complete bundles that differ ONLY in the order of multi-element
    set-like arrays must produce byte-identical canonical files for every
    affected document."""
    docs_a = _docs_with_multi_element_set_like_arrays()
    docs_b = _docs_with_multi_element_set_like_arrays()
    # Reverse every set-like array in docs_b (a genuine permutation, not a
    # no-op, because each has >= 2 distinct elements).
    docs_b["sources.json"]["sources"][0]["authors"].reverse()
    docs_b["brief.json"]["scope"]["domains"].reverse()
    docs_b["brief.json"]["constraints"]["required_adapters"].reverse()
    docs_b["brief.json"]["constraints"]["excluded_adapters"].reverse()
    docs_b["evidence.json"]["evidence"][0]["source_ids"].reverse()
    docs_b["claims.json"]["claims"][0]["supporting_evidence_ids"].reverse()
    docs_b["claims.json"]["claims"][0]["contradicting_evidence_ids"].reverse()
    docs_b["claims.json"]["claims"][0]["citation_ids"].reverse()
    docs_b["citations.json"]["citations"][0]["evidence_ids"].reverse()
    docs_b["validations.json"]["checks_run"].reverse()
    docs_b["report.json"]["adapters_used"].reverse()

    finalized_a = _write_bundle_with_documents(tmp_path / "a", docs_a)
    finalized_b = _write_bundle_with_documents(tmp_path / "b", docs_b)

    # 1. Affected canonical JSON files are byte-identical.
    for fname in (
        "brief.json", "sources.json", "evidence.json", "claims.json",
        "citations.json", "validations.json", "report.json",
    ):
        bytes_a = (finalized_a / fname).read_bytes()
        bytes_b = (finalized_b / fname).read_bytes()
        assert bytes_a == bytes_b, f"permutation changed bytes of {fname}"

    # 2. Per-file hashes are identical across the whole bundle.
    from nodechain.research.serialization import compute_file_hash
    for fname in BUNDLE_FILES:
        ha = compute_file_hash(finalized_a / fname)
        hb = compute_file_hash(finalized_b / fname)
        assert ha == hb, f"permutation changed hash of {fname}"

    # 3. bundle_digest is identical.
    ma = json.loads((finalized_a / "manifest.json").read_text())
    mb = json.loads((finalized_b / "manifest.json").read_text())
    assert ma["bundle_digest"] == mb["bundle_digest"], "permutation changed bundle_digest"


def test_production_canonicalization_preserves_ordered_arrays(
    tmp_path: Path,
) -> None:
    """Semantically ordered arrays (trace events, plan steps, review/policy
    decisions) remain order-sensitive: swapping their order changes bytes,
    hashes, and the digest."""
    docs_a = _all_documents()
    docs_b = _all_documents()
    # Swap two trace events (chronological order is semantic).
    evs_b = docs_b["trace.json"]["events"]
    evs_b[0], evs_b[1] = evs_b[1], evs_b[0]

    finalized_a = _write_bundle_with_documents(tmp_path / "a", docs_a)
    finalized_b = _write_bundle_with_documents(tmp_path / "b", docs_b)

    bytes_a = (finalized_a / "trace.json").read_bytes()
    bytes_b = (finalized_b / "trace.json").read_bytes()
    assert bytes_a != bytes_b, "trace event swap did not change bytes"
    ma = json.loads((finalized_a / "manifest.json").read_text())
    mb = json.loads((finalized_b / "manifest.json").read_text())
    assert ma["bundle_digest"] != mb["bundle_digest"], (
        "trace event swap did not change bundle_digest"
    )


def test_writer_rejects_unknown_filename_in_normalization_policy() -> None:
    """The filename-aware policy must reject filenames it has no entry for."""
    with pytest.raises(BundleError, match="no normalization policy"):
        _ = bundle_mod._set_like_paths_for("not-a-bundle-file.json")


# --------------------------------------------------------------------------- #
# R2-2: reader terminal-only enforcement (recomputed running bundle)
# --------------------------------------------------------------------------- #


def _recompute_manifest_for_directory(dest: Path, run_status: str) -> None:
    """Rewrite manifest.json for ``dest`` so that run_status reflects
    ``run_status`` AND every per-file hash + bundle_digest is recomputed
    against the current on-disk bytes. Used to build an adversarial bundle
    whose ONLY defect is a non-terminal status."""
    from nodechain.research.bundle import (
        _NON_MANIFEST_FILES, compute_bundle_digest,
    )
    from nodechain.research.serialization import compute_file_hash

    manifest_path = dest / "manifest.json"
    doc = json.loads(manifest_path.read_text())
    inventory = [
        {"path": f, "sha256": compute_file_hash(dest / f)}
        for f in _NON_MANIFEST_FILES
    ]
    doc["artifact_inventory"] = inventory
    doc["run_status"] = run_status
    doc.pop("bundle_digest", None)
    doc["bundle_digest"] = compute_bundle_digest(inventory, doc)
    manifest_path.write_text(canonical_json(doc))


def _set_run_status_everywhere(dest: Path, status: str) -> None:
    """Mutate run.json and report.json to agree on ``status`` so cross-document
    truth does not reject the bundle before the terminal gate, then recompute
    the manifest (hashes + digest) so the only remaining defect is the
    non-terminal status itself."""
    for fname, key in (("run.json", "status"), ("report.json", "run_status")):
        p = dest / fname
        d = json.loads(p.read_text())
        d[key] = status
        p.write_text(canonical_json(d))
    _recompute_manifest_for_directory(dest, status)


def test_reader_rejects_consistent_running_bundle(tmp_path: Path) -> None:
    """A bundle whose manifest/run/report all agree on 'running' (with hashes
    and digest recomputed) is still rejected by the reader's terminal gate."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    _set_run_status_everywhere(dest, "running")
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="non-terminal run_status"):
        reader.verify_integrity()


def test_reader_rejects_consistent_paused_bundle(tmp_path: Path) -> None:
    """Same as above for 'paused_for_review'."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    _set_run_status_everywhere(dest, "paused_for_review")
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="non-terminal run_status"):
        reader.verify_integrity()


def test_reader_accepts_consistent_terminal_bundle_after_recompute(
    tmp_path: Path,
) -> None:
    """Sanity: the same recompute flow with a terminal status passes."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    _set_run_status_everywhere(dest, "failed")
    reader = BundleReader(dest)
    assert reader.verify_integrity() is True


# --------------------------------------------------------------------------- #
# R2-4: trace.chain_id checked against manifest.chain_id
# --------------------------------------------------------------------------- #


def test_reader_rejects_trace_from_other_chain(tmp_path: Path) -> None:
    """A trace whose run_id matches the manifest but whose chain_id differs
    must be rejected, even after hashes and digest are recomputed."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # Tamper only trace.chain_id to a different chain.
    trace_path = dest / "trace.json"
    tdoc = json.loads(trace_path.read_text())
    tdoc["chain_id"] = "other-chain"
    trace_path.write_text(canonical_json(tdoc))
    # Recompute manifest so hash/digest checks pass.
    _recompute_manifest_for_directory(dest, "completed")
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match=r"trace\.json.*chain_id"):
        reader.verify_integrity()


def test_truth_check_rejects_trace_chain_id_mismatch_unit() -> None:
    """Unit-level: _validate_cross_document_truth rejects a trace whose
    chain_id disagrees with the manifest, independent of hashing."""
    docs = _all_documents()
    manifest_doc = _manifest_doc_from_docs(docs, "completed")
    bundle = dict(docs)
    bundle["manifest.json"] = manifest_doc
    # Trace chain_id disagrees.
    bundle["trace.json"]["chain_id"] = "other-chain"
    with pytest.raises(BundleValidationError, match=r"trace\.json.*chain_id"):
        _validate_cross_document_truth(bundle)


# --------------------------------------------------------------------------- #
# R2-5: physical directory member-set verification
# --------------------------------------------------------------------------- #


def test_reader_rejects_extra_physical_file(tmp_path: Path) -> None:
    """An extra unlisted file in the bundle directory is rejected even though
    the manifest inventory is canonical."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    (dest / "README.txt").write_text("sneaky")
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError, match="non-canonical members"):
        reader.verify_integrity()


def test_reader_rejects_extra_physical_directory(tmp_path: Path) -> None:
    """An extra subdirectory inside the bundle is rejected."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    (dest / "subdir").mkdir()
    (dest / "subdir" / "x.json").write_text("{}")
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError, match="non-canonical members"):
        reader.verify_integrity()


def test_reader_rejects_symlink_member(tmp_path: Path) -> None:
    """A symlink masquerading as a canonical member is rejected (skipped where
    symlinks cannot be created, e.g. unprivileged Windows)."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    target = dest / "brief.json"
    link = dest / "claims.json"  # replace a canonical file with a symlink
    try:
        link.unlink()
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks on this platform")
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError, match="symlink"):
        reader.verify_integrity()


# =========================================================================== #
# Round-3 correction tests: schema-enforced extension versioning
# =========================================================================== #
#
# The versioned trace-extension guarantee must be enforced by the JSON Schema
# (dependentRequired), not only by the Pydantic models. BundleWriter accepts
# raw dictionaries and finalization validates them through JSON Schema, so a
# caller can bypass model construction. These tests exercise the raw-dict /
# schema path exclusively (no Pydantic construction of the trace document).
# --------------------------------------------------------------------------- #


def test_schema_rejects_unversioned_root_extensions(tmp_path: Path) -> None:
    """Raw dict: a trace with root ``extensions`` but no ``extensions_version``
    is rejected during finalize via the schema's dependentRequired rule."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["trace.json"]["extensions"] = {"adapter_data": "unversioned"}
    # Note: extensions_version deliberately NOT set.
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="trace.json"):
        writer.finalize(manifest)
    assert not (tmp_path / "bundle").exists()


def test_schema_rejects_unversioned_event_extensions(tmp_path: Path) -> None:
    """Raw dict: a trace event with ``extensions`` but no ``extensions_version``
    is rejected during finalize via the event schema's dependentRequired rule."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["trace.json"]["events"][0]["extensions"] = {"latency_ms": 12}
    # Note: event extensions_version deliberately NOT set.
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="trace.json"):
        writer.finalize(manifest)
    assert not (tmp_path / "bundle").exists()


def test_schema_accepts_versioned_root_and_event_extensions(
    tmp_path: Path,
) -> None:
    """Raw dict: versioned extensions on both root and event are accepted."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["trace.json"]["extensions_version"] = "1.0"
    docs["trace.json"]["extensions"] = {"adapter_x": {"note": "ok"}}
    docs["trace.json"]["events"][0]["extensions_version"] = "1.0"
    docs["trace.json"]["events"][0]["extensions"] = {"latency_ms": 12}
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status="completed", input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    finalized = writer.finalize(manifest)
    assert (finalized / "trace.json").exists()


def test_reader_rejects_tampered_unversioned_extensions(tmp_path: Path) -> None:
    """A finalized trace tampered post-hoc to carry unversioned root extensions
    is rejected by BundleReader even after hashes and bundle_digest are
    recomputed, because the schema's dependentRequired rule fires during
    verify_integrity()."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # Tamper: add root extensions without extensions_version.
    trace_path = dest / "trace.json"
    tdoc = json.loads(trace_path.read_text())
    tdoc["extensions"] = {"injected": True}
    trace_path.write_text(canonical_json(tdoc))
    # Recompute manifest so hash/digest checks pass; the schema check is the
    # sole remaining gate.
    _recompute_manifest_for_directory(dest, "completed")
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="trace.json"):
        reader.verify_integrity()


def test_reader_rejects_tampered_unversioned_event_extensions(
    tmp_path: Path,
) -> None:
    """Same as above but for event-level extensions."""
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    trace_path = dest / "trace.json"
    tdoc = json.loads(trace_path.read_text())
    tdoc["events"][0]["extensions"] = {"injected": True}
    trace_path.write_text(canonical_json(tdoc))
    _recompute_manifest_for_directory(dest, "completed")
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError, match="trace.json"):
        reader.verify_integrity()
