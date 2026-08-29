"""Contract tests for the ResearchWorkspaceBundleV1 Python implementation.

These tests are deterministic and self-contained: every fixture is built inline
and uses ``tmp_path`` so nothing leaks onto the host filesystem. They cover the
round-trip (write -> read -> verify), schema rejection, cross-reference
failure, manifest self-hash, canonical JSON determinism, atomic finalization
fault tolerance, and path/symlink safety.
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
    compute_bundle_digest,
)
from nodechain.research.exceptions import (
    BundleFinalizationError,
    BundleIntegrityError,
    BundleValidationError,
)
from nodechain.research.models import (
    BundleVersion,
    ClaimRecord,
    ClaimStatus,
    EvidenceRecord,
    FailureRecord,
    FaultType,
    PolicyDecision,
    ReviewDecision,
    ReviewDecisionType,
    RunStatus,
    SourceRecord,
    TargetType,
    UncertaintyMarker,
    ValidationResult,
)
from nodechain.research.serialization import canonical_json, canonical_json_bytes


# --------------------------------------------------------------------------- #
# Deterministic fixtures
# --------------------------------------------------------------------------- #

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
            {
                "step_id": 0,
                "node_id": "ingest",
                "event_type": "step_completed",
                "actor": "arxiv",
            },
            {
                "step_id": 1,
                "node_id": "synthesize",
                "event_type": "step_started",
                "actor": "orchestrator",
            },
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
    # Write in BUNDLE_FILES order (skip manifest).
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
        run_status=RunStatus.COMPLETED,
        input_digest=INPUT_DIGEST,
        provider_mode="live",
        fixture_corpus_version=None,
        trace_reference="trace.json",
        replay_eligible=True,
    )
    return writer.finalize(manifest)


# --------------------------------------------------------------------------- #
# Tests: round trip and integrity
# --------------------------------------------------------------------------- #


def test_valid_bundle_round_trip(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    finalized = _write_valid_bundle(dest)
    assert finalized == dest
    assert (dest / "manifest.json").exists()

    reader = BundleReader(dest)
    assert reader.verify_integrity() is True
    manifest = reader.get_manifest()
    assert manifest.run_id == RUN_ID
    assert manifest.bundle_version == BundleVersion.V1_0
    assert len(manifest.artifact_inventory) == 14  # all non-manifest files
    # round-trip a single document
    brief = reader.get_document("brief.json")
    assert brief["question"].startswith("Is async")


def test_manifest_self_hash_correct(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    reader = BundleReader(dest)
    # Recompute digest independently and confirm equality.
    inventory = [
        {"path": fh.path, "sha256": fh.sha256}
        for fh in reader.get_manifest().artifact_inventory
    ]
    manifest_doc = json.loads((dest / "manifest.json").read_text())
    recomputed = compute_bundle_digest(inventory, manifest_doc)
    assert recomputed == reader.get_manifest().bundle_digest


def test_manifest_self_hash_detects_tamper(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # Tamper with a non-manifest file's content (without changing its hash in
    # the manifest) — verify_integrity must catch the mismatch.
    target = dest / "brief.json"
    doc = json.loads(target.read_text())
    doc["question"] = "tampered question"
    target.write_text(canonical_json(doc))
    reader = BundleReader(dest)
    with pytest.raises(BundleIntegrityError):
        reader.verify_integrity()


# --------------------------------------------------------------------------- #
# Tests: schema validation
# --------------------------------------------------------------------------- #


def test_unknown_field_rejected(tmp_path: Path) -> None:
    """Unknown fields must be rejected. The malformed payload is written
    BEFORE compute_manifest (so hashes agree); the schema validator then
    catches it. Mutating a staged file AFTER compute_manifest is covered
    separately by the stale-hash tests (Blocker 2)."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["brief.json"]["unexpected_field"] = "boom"
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists(), "staging must be cleaned up"


def test_missing_required_field_rejected(tmp_path: Path) -> None:
    """Missing required fields must be rejected. The malformed payload is
    written BEFORE compute_manifest so hashes agree and the schema validator
    fires."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    del docs["brief.json"]["question"]  # required field
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists()


def test_unsupported_bundle_version_rejected(tmp_path: Path) -> None:
    """Unsupported bundle_version must be rejected. The malformed payload is
    written BEFORE compute_manifest so hashes agree and the version check
    fires."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["run.json"]["bundle_version"] = "2.0"  # unsupported
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists()


# --------------------------------------------------------------------------- #
# Tests: cross-reference integrity
# --------------------------------------------------------------------------- #


def test_cross_reference_failure_orphan_evidence(tmp_path: Path) -> None:
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    # Make a claim reference an evidence id that does not exist.
    docs["claims.json"]["claims"][0]["supporting_evidence_ids"] = ["ev-missing"]
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="cross-reference"):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists()


def test_cross_reference_failure_orphan_source_on_citation(tmp_path: Path) -> None:
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["citations.json"]["citations"][0]["source_id"] = "src-missing"
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="cross-reference"):
        writer.finalize(manifest)
    assert not writer.staging_dir.exists()


def test_cross_reference_validation_target_type_routing(tmp_path: Path) -> None:
    """A validation result with target_type=source must resolve against sources."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["validations.json"]["validation_results"].append(
        {"validation_id": "v-bad", "target_type": "source",
         "target_id": "src-missing", "check_name": "x",
         "passed": False, "message": "no"}
    )
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="cross-reference"):
        writer.finalize(manifest)


# --------------------------------------------------------------------------- #
# Tests: canonical JSON determinism
# --------------------------------------------------------------------------- #


def test_canonical_json_determinism() -> None:
    a = _all_documents()
    # Same data, different in-memory key order.
    b = {k: dict(reversed(list(v.items()))) for k, v in a.items()}
    # Insert keys in different order at dict level too.
    sample = {"b": 1, "a": 2, "c": [3, 2, 1]}
    sample_rev = {"c": [3, 2, 1], "a": 2, "b": 1}
    assert canonical_json(sample) == canonical_json(sample_rev)
    assert canonical_json_bytes(a) == canonical_json_bytes(b)
    # Terminal newline present, exactly one.
    assert canonical_json({"a": 1}).endswith("\n")
    assert canonical_json({"a": 1}).count("\n") == 1


def test_canonical_json_rejects_nan() -> None:
    import math
    with pytest.raises(ValueError):
        canonical_json({"x": math.nan})
    with pytest.raises(ValueError):
        canonical_json({"x": math.inf})


# --------------------------------------------------------------------------- #
# Tests: atomic finalization
# --------------------------------------------------------------------------- #


def test_atomic_finalization_fault_leaves_no_partial(tmp_path: Path) -> None:
    """If a write fails DURING finalize, no partial directory remains."""
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    # Force os.replace to fail to simulate a fault at the final atomic step.
    with mock.patch(
        "nodechain.research.bundle.os.replace",
        side_effect=OSError("simulated rename failure"),
    ):
        with pytest.raises(BundleFinalizationError):
            writer.finalize(manifest)
    # Neither the staging dir nor a finalized bundle should remain.
    assert not (tmp_path / "bundle").exists()
    assert not (tmp_path / "bundle.staging").exists()


def test_existing_bundle_not_overwritten(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    # A second writer on the same destination must refuse outright.
    with pytest.raises(BundleFinalizationError):
        BundleWriter(dest)


def test_duplicate_id_rejected(tmp_path: Path) -> None:
    writer = BundleWriter(tmp_path / "bundle")
    docs = _all_documents()
    docs["sources.json"]["sources"].append(
        {**docs["sources.json"]["sources"][0]}  # same source_id
    )
    for fname in BUNDLE_FILES:
        if fname == "manifest.json":
            continue
        writer.write_document(fname, docs[fname])
    manifest = writer.compute_manifest(
        source_commit=COMMIT, run_id=RUN_ID, chain_id=CHAIN_ID,
        blueprint_version="bp-1", created_at=TS, finalized_at=TS,
        run_status=RunStatus.COMPLETED, input_digest=INPUT_DIGEST,
        provider_mode="live", fixture_corpus_version=None,
    )
    with pytest.raises(BundleValidationError, match="duplicate"):
        writer.finalize(manifest)


# --------------------------------------------------------------------------- #
# Tests: path safety
# --------------------------------------------------------------------------- #


def test_path_traversal_rejected_on_write(tmp_path: Path) -> None:
    writer = BundleWriter(tmp_path / "bundle")
    with pytest.raises(BundleValidationError):
        writer.write_document("../evil.json", {"x": 1})
    with pytest.raises(BundleValidationError):
        writer.write_document("/etc/passwd", {"x": 1})
    with pytest.raises(BundleValidationError):
        writer.write_document("sub/dir.json", {"x": 1})


def test_path_traversal_rejected_on_read(tmp_path: Path) -> None:
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    reader = BundleReader(dest)
    with pytest.raises(BundleValidationError):
        reader.get_document("../manifest.json")


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    """A symlink inside the bundle that points outside must be rejected."""
    # Creating symlinks on Windows requires elevated privileges (SeCreateSymbolicLinkPrivilege).
    # Skip the test on platforms where we cannot create one.
    dest = tmp_path / "bundle"
    _write_valid_bundle(dest)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = dest / "brief.json"
    link.unlink()
    try:
        os.symlink(outside.resolve(), link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not supported on this platform: {exc}")
    reader = BundleReader(dest)
    with pytest.raises((BundleIntegrityError, BundleValidationError)):
        reader.verify_integrity()


# --------------------------------------------------------------------------- #
# Tests: enums and models
# --------------------------------------------------------------------------- #


def test_enum_values_match_contract() -> None:
    assert BundleVersion.V1_0.value == "1.0"
    assert RunStatus.COMPLETED.value == "completed"
    assert ClaimStatus.SUPPORTED.value == "supported"
    assert ReviewDecisionType.APPROVE.value == "approve"
    assert FaultType.FAIL_BEFORE_DISPATCH.value == "fail_before_dispatch"
    assert TargetType.CLAIM.value == "claim"


def test_models_are_frozen() -> None:
    rec = SourceRecord(
        source_id="s", origin_api="api", query_used="q",
        retrieved_at=datetime.now(timezone.utc), title="t",
        source_hash="c" * 64,
    )
    with pytest.raises(Exception):
        rec.source_id = "mutated"  # type: ignore[misc]


def test_models_reject_empty_ids() -> None:
    with pytest.raises(Exception):
        SourceRecord(
            source_id="", origin_api="api", query_used="q",
            retrieved_at=datetime.now(timezone.utc), title="t",
            source_hash="c" * 64,
        )
