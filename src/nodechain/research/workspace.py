"""H1.1: Read-only Workspace object model — a projection, not a truth store.

``open_workspace()`` discovers runs under a workspace root, selects one
(either explicitly or the most recently persisted), and projects the
authoritative runtime/evidence records into a frozen
``ResearchWorkspaceSnapshot``. The Workspace never executes nodes,
transitions ChainState, writes trace, resolves recovery, or maintains a
competing lifecycle; it reads only.

Authority map (each concept projects from one authoritative input):

| Workspace concept | Authoritative input |
|---|---|
| Objective / brief | run's verified ``RunDescriptor`` |
| Runs | persisted run descriptors + ``StateManager`` run state |
| Execution status / revision | ``StateManager.load()`` |
| Plan | persisted ``task_planner`` output |
| Sources | persisted ``source_ingestion`` output |
| Qualified sources | persisted ``qualified_source_linker`` output |
| Evidence / Claims | persisted ``evidence_synthesizer`` / ``claim_validator`` outputs |
| Citations / Uncertainties | bundle documents once terminal; node output otherwise |
| Faults | immutable fault records (``runs/<id>/faults/``) |
| Recovery | side-effect ledger + durable recovery decisions |
| Review decisions | runtime review evidence + CLI submission records |
| Trace | ``StateManager.get_trace_events()`` |
| Terminal bundle | ``BundleReader`` after integrity verification |
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nodechain.research.bundle import BundleReader
from nodechain.research.run_descriptor import (
    RunDescriptor,
    list_fault_records,
    list_outcome_records,
    list_review_records,
    list_run_ids,
    load_descriptor,
)

#: Bump when the projection shape gains a breaking change.
PROJECTION_VERSION = 2

#: Section availability states — absence is never fabricated as empty data.
SECTION_NOT_AVAILABLE = "not_available"
SECTION_LIVE_PARTIAL = "live_partial"
SECTION_LIVE_CURRENT = "live_current"
SECTION_TERMINAL_VERIFIED = "terminal_verified"

#: Terminal bundle states.
BUNDLE_ABSENT = "absent"
BUNDLE_VERIFIED = "verified"
BUNDLE_INVALID = "invalid"


# --------------------------------------------------------------------------- #
# Frozen models
# --------------------------------------------------------------------------- #


class _Frozen(BaseModel):
    """Base for all workspace models — immutable after construction."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkspaceSection(_Frozen):
    """One projected section with its availability state."""

    state: str
    data: Any = None
    error: str = ""


class WorkspaceRunSummary(_Frozen):
    """A lightweight per-run row for the workspace's runs listing."""

    run_id: str
    chain_id: str = ""
    question: str = ""
    execution_status: str = ""
    revision: int = 0
    step: int = 0
    current_node: str = ""
    updated_at: str = ""
    created_at: str = ""
    bundle_status: str = BUNDLE_ABSENT
    has_runtime_state: bool = False
    # H1.3: acquisition/reproducibility truth so a live run can never be
    # presented as a deterministic fixture run.
    acquisition_profile: str = "fixture"
    reproducibility_mode: str = "deterministic_fixture"


class WorkspaceFault(_Frozen):
    """One immutable fault record projected from runs/<id>/faults/."""

    fault_id: str = ""
    fault_type: str = ""
    node_id: str = ""
    operation: str = ""
    reason: str = ""
    timestamp: str = ""
    record: Any = None


class WorkspaceRecovery(_Frozen):
    """Recovery decisions and side-effect records for the selected run."""

    side_effects: list[dict[str, Any]] = Field(default_factory=list)
    recovery_decisions: list[dict[str, Any]] = Field(default_factory=list)


class WorkspaceReview(_Frozen):
    """Review truth: runtime-admitted decisions and CLI submission records."""

    runtime_review_attempts: list[dict[str, Any]] = Field(default_factory=list)
    cli_submission_records: list[dict[str, Any]] = Field(default_factory=list)
    resume_outcome_records: list[dict[str, Any]] = Field(default_factory=list)
    runtime_review_state: dict[str, Any] = Field(default_factory=dict)


class VerifiedBundleRef(_Frozen):
    """A reference to a verified terminal bundle."""

    bundle_dir: str
    bundle_digest: str = ""
    run_status: str = ""
    document_count: int = 0
    documents: list[str] = Field(default_factory=list)


class ResearchWorkspaceSnapshot(_Frozen):
    """The H1.1 read-only user/product model.

    One immutable snapshot of a workspace's selected run, projected from
    authoritative runtime/evidence records. Every section carries its
    availability state; absence is explicit, never fabricated.
    """

    projection_version: int
    workspace_root: str
    selected_run_id: str
    projection_state: str
    runtime_revision: int = 0

    objective: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    plan: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    runs: list[WorkspaceRunSummary] = Field(default_factory=list)

    sources: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    qualified_sources: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    evidence: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    claims: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    citations: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))
    uncertainties: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))

    faults: list[WorkspaceFault] = Field(default_factory=list)
    recovery: WorkspaceRecovery = Field(default_factory=WorkspaceRecovery)
    review_decisions: WorkspaceReview = Field(
        default_factory=WorkspaceReview)
    trace: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))

    terminal_bundle: WorkspaceSection = Field(
        default_factory=lambda: WorkspaceSection(state=SECTION_NOT_AVAILABLE))

    # Explicitly separated statuses (never one overloaded "status" field).
    execution_status: str = ""
    research_outcome: str = ""
    bundle_status: str = BUNDLE_ABSENT

    # H1.3: acquisition/reproducibility truth for the selected run.
    acquisition_profile: str = "fixture"
    reproducibility_mode: str = "deterministic_fixture"


# --------------------------------------------------------------------------- #
# Internal projection helpers
# --------------------------------------------------------------------------- #


#: H1.3 reproducibility classification. Fixture runs are deterministic
#: (sealed-corpus qualification semantics); live runs are artifact-bounded —
#: NodeChain can prove exactly which content/provenance was used, but cannot
#: promise a later network query returns the same sources or bytes.
def _reproducibility_mode(profile: str) -> str:
    if profile == "live":
        return "artifact_bounded_live"
    return "deterministic_fixture"


def _parse_output(outputs: dict[str, Any], node_id: str) -> dict[str, Any]:
    """Parse a persisted node output, handling the JSON-string form."""
    out = outputs.get(node_id)
    if out is None:
        return {}
    if isinstance(out, str):
        try:
            parsed = json.loads(out)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return out if isinstance(out, dict) else {}


def _detect_bundle_status(bundle_dir: Path) -> str:
    """Classify a bundle directory as absent/verified/invalid."""
    if not bundle_dir.is_dir():
        return BUNDLE_ABSENT
    if not (bundle_dir / "manifest.json").exists():
        return BUNDLE_ABSENT
    try:
        reader = BundleReader(bundle_dir)
        return BUNDLE_VERIFIED if reader.verify_integrity() else BUNDLE_INVALID
    except Exception:
        return BUNDLE_INVALID


def _terminal_bundle_ref(bundle_dir: Path) -> VerifiedBundleRef:
    """Build a VerifiedBundleRef from a verified bundle directory."""
    reader = BundleReader(bundle_dir)
    manifest = reader.get_manifest()
    digest = getattr(manifest, "bundle_digest", "")
    run_status = getattr(manifest, "run_status", "")
    from nodechain.research.bundle import BUNDLE_FILES
    docs = [f for f in BUNDLE_FILES if f != "manifest.json"]
    return VerifiedBundleRef(
        bundle_dir=str(bundle_dir),
        bundle_digest=digest,
        run_status=run_status,
        document_count=len(docs),
        documents=sorted(docs),
    )


def _research_outcome_from_bundle(bundle_status: str,
                                  bundle_ref: VerifiedBundleRef | None) -> str:
    """Derive the research_outcome from the verified bundle's run_status."""
    if bundle_status == BUNDLE_VERIFIED and bundle_ref is not None:
        return bundle_ref.run_status
    return ""


def _section_from_output(
    outputs: dict[str, Any], node_id: str, key: str | None = None,
) -> WorkspaceSection:
    """Project a node output as a section. Absent output → not_available."""
    parsed = _parse_output(outputs, node_id)
    if key is not None:
        data = parsed.get(key)
        if data is None:
            return WorkspaceSection(state=SECTION_NOT_AVAILABLE)
        return WorkspaceSection(state=SECTION_LIVE_CURRENT, data=data)
    if not parsed:
        return WorkspaceSection(state=SECTION_NOT_AVAILABLE)
    return WorkspaceSection(state=SECTION_LIVE_CURRENT, data=parsed)


def _project_faults(records: list[dict[str, Any]]) -> list[WorkspaceFault]:
    """Project immutable fault records into WorkspaceFault models."""
    out: list[WorkspaceFault] = []
    for rec in records:
        out.append(WorkspaceFault(
            fault_id=rec.get("fault_id", ""),
            fault_type=rec.get("fault_type", rec.get("type", "")),
            node_id=rec.get("node_id", ""),
            operation=rec.get("operation", ""),
            reason=rec.get("reason", rec.get("detail", "")),
            timestamp=rec.get("timestamp", rec.get("created_at", "")),
            record=rec,
        ))
    return out


# --------------------------------------------------------------------------- #
# The public projector
# --------------------------------------------------------------------------- #


def open_workspace(
    workspace_dir: str | Path,
    run_id: str | None = None,
) -> ResearchWorkspaceSnapshot:
    """Open a workspace and project one run as an immutable snapshot.

    Args:
        workspace_dir: path to the workspace root (the parent of ``runs/``).
        run_id: explicit run to project. When None, the most recently
            persisted run is selected deterministically (highest
            ``updated_at`` from the DB; ties break on run_id).

    Returns:
        A frozen ``ResearchWorkspaceSnapshot``. An empty or missing
        workspace returns a snapshot with an empty runs list and every
        section ``not_available``.

    Raises:
        FileNotFoundError: when ``run_id`` names a run with no descriptor.
        ValueError: when a named run's descriptor fails digest verification.
    """
    workspace = Path(workspace_dir)
    discoverable = list_run_ids(workspace)

    # -- Empty workspace: deterministic empty result --------------------
    if not discoverable:
        return ResearchWorkspaceSnapshot(
            projection_version=PROJECTION_VERSION,
            workspace_root=str(workspace),
            selected_run_id="",
            projection_state=SECTION_NOT_AVAILABLE,
        )

    # -- Run selection ---------------------------------------------------
    descriptors: dict[str, RunDescriptor] = {}
    for rid in discoverable:
        descriptors[rid] = load_descriptor(workspace, rid)

    if run_id is not None:
        if run_id not in descriptors:
            raise FileNotFoundError(
                f"no descriptor for run {run_id} in {workspace}"
            )
        selected_id = run_id
    else:
        # H1.1 frozen rule: select the MOST RECENTLY PERSISTED run —
        # the run with the highest DB updated_at (persistence freshness).
        # Descriptor-only runs (no runtime state) fall back to their
        # descriptor's created_at. Ties break deterministically on run_id.
        from nodechain.core.state import StateManager
        best_key: tuple[str, str] | None = None
        selected_id = ""
        for rid in discoverable:
            d = descriptors[rid]
            updated = ""
            try:
                sm_probe = StateManager(d.db_path, read_only=True)
                updated = sm_probe.get_run_updated_at(rid) or ""
            except Exception:
                pass
            # Persistence timestamp wins; descriptor created_at is the
            # fallback for runs whose state was never persisted.
            effective = updated or d.created_at
            key = (effective, rid)
            if best_key is None or key > best_key:
                best_key = key
                selected_id = rid

    desc = descriptors[selected_id]

    # -- Load runtime state through the authoritative StateManager ------
    # read_only=True: observation never creates a database, directory, or
    # schema. A missing DB is a legitimate observable fact (the run's
    # descriptor exists but its runtime state was never persisted).
    from nodechain.core.state import StateManager

    state: Any = None
    state_error = ""
    try:
        sm = StateManager(desc.db_path, read_only=True)
        state = sm.load(selected_id)
    except Exception as exc:
        state_error = str(exc)

    outputs: dict[str, Any] = {}
    revision = 0
    execution_status = ""
    current_node = ""
    step = 0
    updated_at = ""
    trace_events: list[dict[str, Any]] = []
    runtime_review_state: dict[str, Any] = {}
    side_effects: list[dict[str, Any]] = []
    recovery_decisions: list[dict[str, Any]] = []
    runtime_review_attempts: list[dict[str, Any]] = []

    if state is not None:
        outputs = dict(state.outputs or {})
        revision = state.revision
        execution_status = state.status
        current_node = state.current_node
        step = state.step
        runtime_review_state = (
            state.human_review.model_dump(mode="json")
            if state.human_review else {}
        )
        # H1.1 AC3: recovery side effects project from the AUTHORITATIVE
        # side-effect LEDGER (StateManager.get_side_effects), not from the
        # ChainState.side_effects snapshot. The ledger carries the full
        # lifecycle record (unknown, retry_authorized, recovery-child
        # lineage, dispatch/fencing state); the snapshot is a convenience
        # copy that may be stale or incomplete for recovery projection.
        try:
            trace_events = sm.get_trace_events(selected_id)
            updated_at = sm.get_run_updated_at(selected_id) or ""
            runtime_review_attempts = sm.get_review_attempts(
                run_id=selected_id)
            recovery_decisions = sm.get_recovery_decisions(
                run_id=selected_id)
            side_effects = sm.get_side_effects(selected_id)
        except Exception:
            pass  # read-side only; missing reads surface as empty sections

    projection_state = (
        SECTION_LIVE_CURRENT if state is not None
        else SECTION_NOT_AVAILABLE
    )

    # -- Project node outputs ---------------------------------------------
    objective_section = WorkspaceSection(
        state=SECTION_LIVE_CURRENT,
        data={"question": desc.question,
              "focus_areas": list(desc.focus_areas)},
    )
    plan_section = _section_from_output(outputs, "task_planner")
    sources_section = _section_from_output(outputs, "source_ingestion",
                                           "sources")
    # The linker produces `qualified_sources` (the bound set) and
    # `linked_sources` (with source_id → source_hash/artifact_ref binding).
    qualified_section = _section_from_output(
        outputs, "qualified_source_linker", "linked_sources")
    if qualified_section.state == SECTION_NOT_AVAILABLE:
        qualified_section = _section_from_output(
            outputs, "qualified_source_linker", "qualified_sources")
    # Evidence lives in the synthesizer's `synthesis` sub-dict and in the
    # validator's `sources`. Claims are a top-level key.
    synth_parsed = _parse_output(outputs, "evidence_synthesizer")
    synthesis = synth_parsed.get("synthesis")
    if isinstance(synthesis, dict) and synthesis.get("evidence"):
        evidence_section = WorkspaceSection(
            state=SECTION_LIVE_CURRENT, data=synthesis["evidence"])
    else:
        val_parsed = _parse_output(outputs, "claim_validator")
        val_sources = val_parsed.get("sources")
        evidence_section = (
            WorkspaceSection(state=SECTION_LIVE_CURRENT, data=val_sources)
            if val_sources is not None
            else WorkspaceSection(state=SECTION_NOT_AVAILABLE)
        )
    claims_section = _section_from_output(outputs, "evidence_synthesizer",
                                          "claims")

    # -- Terminal bundle ---------------------------------------------------
    bundle_dir = workspace / "runs" / selected_id / "bundle"
    bundle_status = _detect_bundle_status(bundle_dir)

    citations_section: WorkspaceSection
    uncertainties_section: WorkspaceSection
    terminal_section: WorkspaceSection
    bundle_ref: VerifiedBundleRef | None = None

    if bundle_status == BUNDLE_VERIFIED:
        bundle_ref = _terminal_bundle_ref(bundle_dir)
        try:
            reader = BundleReader(bundle_dir)
            citations_doc = reader.get_document("citations.json")
            uncertainties_doc = reader.get_document("uncertainties.json")
            citations_section = WorkspaceSection(
                state=SECTION_TERMINAL_VERIFIED,
                data=citations_doc.get("citations"),
            )
            uncertainties_section = WorkspaceSection(
                state=SECTION_TERMINAL_VERIFIED,
                data=uncertainties_doc.get("uncertainties"),
            )
        except Exception:
            citations_section = WorkspaceSection(
                state=SECTION_NOT_AVAILABLE)
            uncertainties_section = WorkspaceSection(
                state=SECTION_NOT_AVAILABLE)
        terminal_section = WorkspaceSection(
            state=SECTION_TERMINAL_VERIFIED,
            data=bundle_ref,
        )
    else:
        # Live citations/uncertainties from node outputs when no bundle.
        rg_parsed = _parse_output(outputs, "response_generator")
        citations_live = rg_parsed.get("citations")
        citations_section = (
            WorkspaceSection(state=SECTION_LIVE_CURRENT, data=citations_live)
            if citations_live is not None
            else WorkspaceSection(state=SECTION_NOT_AVAILABLE)
        )
        risk_parsed = _parse_output(outputs, "risk_classifier")
        uncertainties_live = (
            rg_parsed.get("uncertainty_disclosures")
            or risk_parsed.get("uncertainty_disclosures")
        )
        uncertainties_section = (
            WorkspaceSection(state=SECTION_LIVE_CURRENT,
                             data=uncertainties_live)
            if uncertainties_live is not None
            else WorkspaceSection(state=SECTION_NOT_AVAILABLE)
        )
        terminal_section = WorkspaceSection(
            state=SECTION_NOT_AVAILABLE,
            error=("bundle present but integrity verification failed"
                   if bundle_status == BUNDLE_INVALID else ""),
        )

    research_outcome = _research_outcome_from_bundle(
        bundle_status, bundle_ref)

    # -- Faults / recovery / review ----------------------------------------
    fault_records = list_fault_records(workspace, selected_id)
    faults = _project_faults(fault_records)

    cli_submissions = list_review_records(workspace, selected_id)
    resume_outcomes = list_outcome_records(workspace, selected_id)

    # -- Build the runs listing (summaries for every discoverable run) ----
    run_summaries: list[WorkspaceRunSummary] = []
    for rid in discoverable:
        d = descriptors[rid]
        r_state = None
        try:
            r_sm = StateManager(d.db_path, read_only=True)
            r_state = r_sm.load(rid)
        except Exception:
            pass
        r_bundle = _detect_bundle_status(
            workspace / "runs" / rid / "bundle")
        run_summaries.append(WorkspaceRunSummary(
            run_id=rid,
            chain_id=d.chain_id,
            question=d.question,
            execution_status=(r_state.status if r_state else ""),
            revision=(r_state.revision if r_state else 0),
            step=(r_state.step if r_state else 0),
            current_node=(r_state.current_node if r_state else ""),
            updated_at=(r_sm.get_run_updated_at(rid) or ""
                        if r_state else ""),
            created_at=d.created_at,
            bundle_status=r_bundle,
            has_runtime_state=r_state is not None,
            acquisition_profile=d.profile,
            reproducibility_mode=_reproducibility_mode(d.profile),
        ))

    # -- Trace section ------------------------------------------------------
    trace_section = (
        WorkspaceSection(state=SECTION_LIVE_CURRENT, data=trace_events)
        if trace_events else WorkspaceSection(state=SECTION_NOT_AVAILABLE)
    )

    return ResearchWorkspaceSnapshot(
        projection_version=PROJECTION_VERSION,
        workspace_root=str(workspace),
        selected_run_id=selected_id,
        projection_state=projection_state,
        runtime_revision=revision,
        objective=objective_section,
        plan=plan_section,
        runs=run_summaries,
        sources=sources_section,
        qualified_sources=qualified_section,
        evidence=evidence_section,
        claims=claims_section,
        citations=citations_section,
        uncertainties=uncertainties_section,
        faults=faults,
        recovery=WorkspaceRecovery(
            side_effects=side_effects,
            recovery_decisions=recovery_decisions,
        ),
        review_decisions=WorkspaceReview(
            runtime_review_attempts=runtime_review_attempts,
            cli_submission_records=cli_submissions,
            resume_outcome_records=resume_outcomes,
            runtime_review_state=runtime_review_state,
        ),
        trace=trace_section,
        terminal_bundle=terminal_section,
        execution_status=execution_status,
        research_outcome=research_outcome,
        bundle_status=bundle_status,
        acquisition_profile=desc.profile,
        reproducibility_mode=_reproducibility_mode(desc.profile),
    )
