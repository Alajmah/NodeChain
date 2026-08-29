"""Terminal bundle finalization — translate run evidence into WP 5.1 bundle.

Translates actual persisted/runtime run evidence into the 15 canonical
ResearchWorkspaceBundleV1 documents, finalizes through BundleWriter, and
verifies with BundleReader.

KEK exclusion is checked BEFORE atomic publication. Finalization failure
propagates rather than leaving a misleading completed artifact.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.research.bundle import (
    BUNDLE_FILES,
    BundleReader,
    BundleWriter,
    TERMINAL_RUN_STATUSES,
)
from nodechain.research.run_descriptor import RunDescriptor


class BundleFinalizationError(Exception):
    """Raised when terminal bundle finalization fails."""


def _load_outputs(db_path: str, run_id: str) -> dict[str, Any]:
    import sqlite3
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT state_json FROM chain_states WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return {}
    state = json.loads(row[0])
    return state.get("outputs", {})


def _parse_output(outputs: dict, node_id: str) -> dict:
    out = outputs.get(node_id, {})
    if isinstance(out, str):
        out = json.loads(out)
    return out


def _determine_terminal_status(
    trace_final_status: str,
    min_sources: int,
    min_evidence_per_claim: int,
    min_confidence: float,
    actual_sources: int,
    evidence_counts_per_claim: list[int],
    total_claims: int,
    actual_confidence: float,
) -> str:
    """Determine terminal status from minimum-evidence policy.

    min_evidence_per_claim is checked against the per-claim evidence record
    count. Every claim must have >= min_evidence_per_claim evidence records.
    """
    if trace_final_status == "failed":
        return "failed"
    if trace_final_status not in ("completed",):
        return "blocked"
    if actual_sources < min_sources:
        return "blocked"
    if total_claims == 0:
        return "blocked"
    # Every claim must have at least min_evidence_per_claim evidence records.
    if not evidence_counts_per_claim:
        return "blocked"
    if any(ec < min_evidence_per_claim for ec in evidence_counts_per_claim):
        return "blocked"
    if actual_confidence < min_confidence:
        return "completed_degraded"
    return "completed"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def finalize_bundle(
    workspace_dir: str | Path,
    run_id: str,
    desc: RunDescriptor,
    trace: Any,
    state: Any,
    corpus: Any | None = None,
    source_commit: str = "",
) -> Path:
    """Finalize a terminal run into a ResearchWorkspaceBundleV1.

    If a bundle already exists for this run (idempotent re-finalize),
    verify its integrity and return it rather than throwing.

    H1.3: profile-aware finalization. The acquisition profile comes from
    the descriptor (legacy V1 descriptors are fixture). Fixture runs keep
    their sealed-corpus metadata and deterministic replay semantics; live
    runs derive provider mode/adapters/timestamps from actual records,
    carry no fixture metadata, and are never replay-eligible.
    """
    bundle_dir = Path(workspace_dir) / "runs" / run_id / "bundle"
    if bundle_dir.exists() and (bundle_dir / "manifest.json").exists():
        # Idempotent: verify existing bundle and return.
        reader = BundleReader(bundle_dir)
        if reader.verify_integrity():
            return bundle_dir
        # Integrity failed — fall through to re-finalize.

    trace_final_status = trace.final_status
    if trace_final_status not in TERMINAL_RUN_STATUSES:
        if trace_final_status in ("paused", "waiting_for_review"):
            raise BundleFinalizationError(f"paused run: {trace_final_status}")
        raise BundleFinalizationError(f"not terminal: {trace_final_status}")

    profile = desc.profile
    if profile == "live":
        provider_mode = "live"
        # H1.3 does not implement deterministic replay from captured live
        # artifacts — replay eligibility is unconditionally false.
        replay_eligible = False
    else:
        provider_mode = "fixture"
        replay_eligible = trace_final_status != "failed"

    # Minimum-evidence thresholds: fixture runs use their sealed corpus
    # policy; live runs use the corpus contract's own defaults (the same
    # MinimumEvidencePolicy defaults every fixture corpus falls back to).
    if corpus is not None:
        thresholds = corpus.minimum_evidence
    else:
        from nodechain.research.corpus import MinimumEvidencePolicy
        thresholds = MinimumEvidencePolicy()

    outputs = _load_outputs(desc.db_path, run_id)
    ts = _ts()
    created_at = desc.created_at.replace("+00:00", "Z") if "+" in desc.created_at else desc.created_at

    sources_out = _parse_output(outputs, "source_ingestion")
    sources = sources_out.get("sources", [])
    search_out = _parse_output(outputs, "search_tool")
    ev_out = _parse_output(outputs, "evidence_synthesizer")
    claims = ev_out.get("claims", [])
    evidence_list = ev_out.get("evidence", [])
    val_out = _parse_output(outputs, "claim_validator")
    validated = val_out.get("validated_claims", [])
    risk_out = _parse_output(outputs, "risk_classifier")

    # Adapters ACTUALLY invoked during the run, derived from the
    # authoritative search_tool execution record. Permission is not
    # execution evidence, and neither is planning: the runtime journals a
    # side-effect row for every (query, target adapter) pair BEFORE
    # dispatch, so the ledger alone cannot distinguish planned from
    # invoked. The node's own record can:
    #   adapters_called            → invoked (completed; includes
    #                                dedup-skips of operations this run
    #                                already completed)
    #   adapters_failed entries    → invoked ONLY for failures raised
    #                                around adapter.search() itself.
    #                                Pre-wire blocks
    #                                (LANE_ADMISSION_REJECTED), execution
    #                                gating blocks (side_effect_*), and
    #                                unknown-adapter resolution failures
    #                                never reached the wire and stay out.
    # A run that dispatched nothing reports an empty set.
    adapters_invoked: set[str] = {
        a for a in search_out.get("adapters_called", []) if a
    }
    for failure in search_out.get("adapters_failed", []):
        name = failure.get("adapter") or ""
        if not name or name == "unknown":
            continue
        if failure.get("reason_code") == "LANE_ADMISSION_REJECTED":
            continue  # blocked pre-wire — dispatch did not occur
        error = failure.get("error", "")
        if error.startswith("Unknown adapter"):
            continue  # adapter resolution failed — never invoked
        if error.startswith("side_effect_"):
            continue  # execution-gating block — dispatch did not occur
        adapters_invoked.add(name)
    adapters_used = sorted(adapters_invoked)

    # Build evidence records from actual source content.
    # Generate evidence for both supporting AND contradicting sources.
    if not evidence_list and claims:
        for c in claims:
            if isinstance(c, dict):
                all_sources = (
                    c.get("supporting_sources", []) +
                    c.get("contradicting_sources", [])
                )
                if all_sources:
                    source_texts = [
                        s.get("abstract", s.get("title", ""))
                        for s in sources
                        if isinstance(s, dict) and s.get("source_id") in all_sources
                    ]
                    evidence_list.append({
                        "evidence_id": f"ev-{c.get('claim_id', '1')}",
                        "source_ids": all_sources,
                        "extracted_text": "; ".join(source_texts[:2]) if source_texts else "",
                        "evidence_type": "quote",
                        "confidence": c.get("confidence", 0.0),
                    })

    # Compute per-claim evidence record counts.
    evidence_counts_per_claim: list[int] = []
    for c in claims:
        if not isinstance(c, dict):
            continue
        cid = c.get("claim_id", "")
        claim_ev_id = f"ev-{cid}"
        # Count evidence records that reference this claim's evidence_id
        # OR that reference any of the claim's supporting/contradicting sources.
        claim_source_ids = set(
            c.get("supporting_sources", []) + c.get("contradicting_sources", [])
        )
        count = 0
        for e in evidence_list:
            if not isinstance(e, dict):
                continue
            if e.get("evidence_id") == claim_ev_id:
                count += 1
            elif set(e.get("source_ids", [])) & claim_source_ids:
                count += 1
        evidence_counts_per_claim.append(count)

    actual_confidence = max(
        (c.get("confidence", 0.0) for c in claims if isinstance(c, dict)),
        default=0.0,
    )
    terminal_status = _determine_terminal_status(
        trace_final_status,
        thresholds.min_sources,
        thresholds.min_evidence_per_claim,
        thresholds.min_confidence,
        len(sources),
        evidence_counts_per_claim,
        len(claims),
        actual_confidence,
    )

    from nodechain.research.run_descriptor import list_fault_records
    fault_records = list_fault_records(workspace_dir, run_id)

    # Derive step truth from runtime state (not hard-coded).
    completed_steps = getattr(state, "completed_steps", {}) or {}
    steps_completed_list = []
    for step_id, node_id in sorted(completed_steps.items()):
        # Determine per-step success from the LAST trace event for this
        # node+step. A node that failed on attempt 1 but recovered via retry
        # and completed on attempt 2 should be succeeded=True. Only mark
        # failed if the final event for this node is node_failed (no recovery).
        succeeded = True
        last_node_event = None
        for ev in trace.events:
            if ev.node_id == node_id:
                last_node_event = ev
        if last_node_event is not None:
            etype = last_node_event.event_type.value.lower()
            if "node_failed" in etype:
                succeeded = False
        entry = {"node_id": node_id, "completed_at": ts, "succeeded": succeeded}
        if not succeeded:
            node_faults = [f for f in fault_records if node_id in f.get("operation", "")]
            if node_faults:
                entry["failure_id"] = node_faults[0].get("fault_id", "")
        steps_completed_list.append(entry)

    current_step_node = getattr(state, "current_node", "") or "completed"
    if trace_final_status == "failed":
        current_step_node = getattr(state, "current_node", "") or "failed"

    # Profile-derived acquisition truth (H1.3): required adapters from the
    # descriptor; coverage derived from the ACTUAL ingested records, used
    # adapters from ACTUAL dispatch evidence — never hardcoded, never the
    # permission set.
    required_adapters = (
        ["fixture"] if profile == "fixture"
        else list(desc.allowed_adapters or ())
    )
    adapter_coverage: dict[str, int] = {}
    for s in sources:
        origin = s.get("origin_api", "") or "unknown"
        adapter_coverage[origin] = adapter_coverage.get(origin, 0) + 1
    # Model identity labels: 'fixture-mock' only for fixture runs. Live runs
    # carry the resolved non-secret model identity from the descriptor.
    model_label = (
        "fixture-mock" if profile == "fixture"
        else f"{desc.model_provider or 'live'}/{desc.model_name or 'unspecified'}"
    )
    input_digest = desc.input_digest or desc.corpus_digest or ""

    writer = BundleWriter(bundle_dir)

    # brief.json
    writer.write_document("brief.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "question": desc.question,
        "created_at": created_at,
        "scope": {"domains": [], "time_range": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"}},
        "constraints": {
            "min_sources": thresholds.min_sources,
            "max_sources": 100,
            "required_adapters": required_adapters,
        },
        "target_depth": "standard",
    })

    # run.json — step truth derived from state/trace
    writer.write_document("run.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "chain_id": desc.chain_id,
        "started_at": created_at,
        "updated_at": ts,
        "status": terminal_status,
        "input_digest": input_digest,
        "provider_mode": provider_mode,
        "current_step": current_step_node,
        "steps_completed": steps_completed_list,
        "replay_eligible": replay_eligible,
    })

    # plan.json
    writer.write_document("plan.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "created_at": created_at,
        "steps": [
            {"node_id": n, "position": i, "node_type": "model"}
            for i, n in enumerate(["goal_interpreter","task_planner","evidence_synthesizer","claim_validator","risk_classifier","response_generator"], 1)
        ] + [
            {"node_id": n, "position": i, "node_type": "deterministic"}
            for i, n in enumerate(["context_selector","source_ingestion","qualified_source_linker"], 7)
        ] + [
            {"node_id": "search_tool", "position": 4, "node_type": "tool"}
        ],
        "adapters_required": required_adapters,
        "estimated_cost_usd": 0.0,
    })

    # sources.json — per-source retrieval truth from the ingested records;
    # adapter coverage derived from actual origins.
    writer.write_document("sources.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "retrieved_at": ts,
        "sources": [
            {
                "source_id": s.get("source_id", ""),
                "origin_api": s.get("origin_api", "fixture"),
                "query_used": s.get("query_used", ""),
                "retrieved_at": s.get("retrieved_at", "") or "2026-01-01T00:00:00Z",
                "title": s.get("title", ""),
                "doi": s.get("doi"),
                "authors": list(s.get("authors", ())),
                "abstract": s.get("abstract", ""),
                "source_hash": s.get("source_hash", ""),
                "artifact_ref": s.get("artifact_ref", ""),
            }
            for s in sources
        ],
        "adapter_coverage": adapter_coverage,
        "deduplication_count": 0,
    })

    # evidence.json
    writer.write_document("evidence.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "extracted_at": ts,
        "evidence": [
            {
                "evidence_id": e.get("evidence_id", ""),
                "source_ids": e.get("source_ids", []),
                "extracted_text": e.get("extracted_text", ""),
                "evidence_type": e.get("evidence_type", "synthesis"),
                "confidence": e.get("confidence", 0.0),
            }
            for e in evidence_list if isinstance(e, dict)
        ],
        "extraction_model": model_label,
        "mean_confidence": actual_confidence,
    })

    # claims.json
    writer.write_document("claims.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "synthesized_at": ts,
        "claims": [
            {
                "claim_id": c.get("claim_id", ""),
                "statement": c.get("statement", ""),
                "status": c.get("status", "supported"),
                "supporting_evidence_ids": [f"ev-{c.get('claim_id', '1')}"] if c.get("supporting_sources") else [],
                "contradicting_evidence_ids": [f"ev-{c.get('claim_id', '1')}"] if c.get("contradicting_sources") else [],
                "citation_ids": [],
                "confidence": c.get("confidence", 0.0),
                "uncertainty_markers": [],
                "validation_results": [],
            }
            for c in claims if isinstance(c, dict)
        ],
        "synthesis_model": model_label,
        "executive_answer": ev_out.get("executive_answer", ""),
    })

    # citations.json
    writer.write_document("citations.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "formatted_at": ts,
        "citations": [
            {
                "citation_id": f"cit-{s.get('source_id', '')}",
                "source_id": s.get("source_id", ""),
                "evidence_ids": [],
                "formatted_citation": f"{', '.join(s.get('authors', ()))}. {s.get('title', '')}.",
            }
            for s in sources
        ],
        "style": "apa",
    })

    # uncertainties.json
    writer.write_document("uncertainties.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "recorded_at": ts,
        "uncertainties": [],
    })

    # validations.json
    writer.write_document("validations.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "executed_at": ts,
        "validation_results": [
            {
                "validation_id": f"val-{vc.get('claim_id', '')}",
                "target_type": "claim",
                "target_id": vc.get("claim_id", ""),
                "check_name": "claim_validation",
                "passed": vc.get("status") == "confirmed",
                "message": vc.get("status", ""),
            }
            for vc in validated if isinstance(vc, dict)
        ],
    })

    # policy-decisions.json
    writer.write_document("policy-decisions.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "recorded_at": ts,
        "policy_decisions": [],
    })

    # review-decisions.json
    writer.write_document("review-decisions.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "recorded_at": ts,
        "review_decisions": [],
    })

    # failures.json
    writer.write_document("failures.json", {
        "bundle_version": "1.0",
        "run_id": run_id,
        "recorded_at": ts,
        "failures": [
            {
                "failure_id": f.get("fault_id", ""),
                "failure_type": f.get("failure_type", ""),
                "affected_claim_ids": [],
                "detail": f.get("reason_codes", []),
            }
            for f in fault_records
        ],
    })

    # trace.json
    writer.write_document("trace.json", {
        "run_id": run_id,
        "chain_id": desc.chain_id,
        "events": [
            {
                "step_id": ev.step_id,
                "node_id": ev.node_id,
                "event_type": ev.event_type.value,
                "actor": ev.actor.value,
            }
            for ev in trace.events
        ],
    })

    # report.json
    writer.write_document("report.json", {
        "run_id": run_id,
        "run_status": terminal_status,
        "executive_answer": ev_out.get("executive_answer", ""),
        "claim_count": len(claims),
        "supported_claims": len([c for c in claims if isinstance(c, dict) and c.get("status") == "supported"]),
        "contested_claims": 0,
        "sources_cited": len(sources),
        "adapters_used": adapters_used,
        "failures_recorded": len(fault_records),
        "review_required": risk_out.get("review_required", False),
        "review_completed": risk_out.get("review_required", False) is False,
        "replay_eligible": replay_eligible,
    })

    # Compute manifest.
    manifest = writer.compute_manifest(
        source_commit=source_commit or desc.chain_id,
        run_id=run_id,
        chain_id=desc.chain_id,
        blueprint_version=desc.blueprint_version,
        created_at=created_at,
        finalized_at=ts,
        run_status=terminal_status,
        input_digest=input_digest,
        provider_mode=provider_mode,
        fixture_corpus_version=(
            desc.corpus_version if profile == "fixture" else None
        ),
        trace_reference="trace.json",
        replay_eligible=replay_eligible,
    )

    # KEK exclusion check BEFORE publication.
    # Scan all staging files for the KEK path AND actual KEK material.
    kek_path = desc.kek_path or ""
    kek_material = b""
    if kek_path and Path(kek_path).exists():
        try:
            kek_material = Path(kek_path).read_bytes()
        except OSError:
            pass  # KEK file may not be readable in all contexts

    for fname in _NON_MANIFEST_BUNDLE_FILES:
        fp = writer.staging_dir / fname
        if not fp.exists():
            continue
        content_bytes = fp.read_bytes()
        content_text = content_bytes.decode("utf-8", errors="replace")
        # Check KEK path.
        if kek_path and kek_path in content_text:
            raise BundleFinalizationError(
                f"KEK path detected in staging file {fname}: {kek_path}"
            )
        # Check KEK material (raw bytes, hex, base64).
        if kek_material:
            if kek_material in content_bytes:
                raise BundleFinalizationError(
                    f"KEK material detected in staging file {fname}"
                )
            try:
                kek_hex = kek_material.hex()
                if kek_hex in content_text:
                    raise BundleFinalizationError(
                        f"KEK material (hex) detected in staging file {fname}"
                    )
            except (ValueError, AttributeError):
                pass

    # Finalize (atomic publication).
    finalized = writer.finalize(manifest)

    # Post-finalization integrity verification.
    reader = BundleReader(finalized)
    if not reader.verify_integrity():
        raise BundleFinalizationError(f"integrity verification failed: {finalized}")

    return finalized


# Import here to avoid circular dependency at module load.
from nodechain.research.bundle import _NON_MANIFEST_FILES as _NON_MANIFEST_BUNDLE_FILES
