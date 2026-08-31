"""Human-readable final research artifact (H1.4).

Turns a VERIFIED terminal ResearchWorkspaceBundleV1 into a readable
research memo without another model call and without creating a second
source of research truth.

Governing invariant:

    The memo explains the evidence. It never becomes evidence that did
    not already exist.

Construction consumes only a BundleReader-verified bundle: no live APIs,
no model calls, no node execution, no resume, no state mutation, no
recovery reinterpretation. Rendering is deterministic — the same verified
bundle produces byte-identical Markdown and structurally identical JSON.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .bundle import BundleReader


MEMO_VERSION = 1

#: Reproducibility labels per acquisition profile (H1.3 semantics).
_REPRODUCIBILITY_LABELS = {
    "fixture": "deterministic fixture",
    "live": "artifact-bounded live",
}

_REPRODUCIBILITY_MODES = {
    "fixture": "deterministic_fixture",
    "live": "artifact_bounded_live",
}


class MemoClaim(BaseModel):
    """One finding as presented in the memo."""
    model_config = ConfigDict(frozen=True)

    claim_id: str
    statement: str
    status: str
    confidence: float
    evidence_ids: list[str] = Field(default_factory=list)
    citation_ids: list[str] = Field(default_factory=list)


class MemoSource(BaseModel):
    """One cited source as presented in the memo."""
    model_config = ConfigDict(frozen=True)

    source_id: str
    title: str
    origin_api: str
    doi: str | None = None
    artifact_ref: str | None = None


class MemoReviewDecision(BaseModel):
    """One admitted review decision as presented in the memo."""
    model_config = ConfigDict(frozen=True)

    review_id: str
    decision: str
    reason: str
    reviewer_identity: str
    decided_at: str


class MemoFailure(BaseModel):
    """One recorded failure as presented in the memo."""
    model_config = ConfigDict(frozen=True)

    failure_id: str
    adapter_name: str
    fault_type: str
    occurred_at: str
    dispatch_occurred: bool
    evidence_unavailable: bool
    affected_claim_ids: list[str] = Field(default_factory=list)


class ResearchMemoV1(BaseModel):
    """The frozen, versioned memo presentation model.

    This is a presentation projection of one verified bundle. It is not a
    semantic port type, runtime contract, state table, or alternate
    bundle. ``unavailable_fields`` lists enriched fields the source bundle
    does not carry (pre-H1.4 legacy bundles), so the renderer can state
    "unavailable in this legacy bundle" rather than silently omitting.
    """

    model_config = ConfigDict(frozen=True)

    memo_version: int = MEMO_VERSION

    run_id: str
    bundle_digest: str
    run_status: str
    acquisition_profile: str
    reproducibility_mode: str

    question: str

    #: The raw BundleV1 executive_answer (a required field on every
    #: bundle). For legacy bundles this is the ONLY recorded answer-level
    #: content; it is presented as exactly that, never upgraded to a
    #: first-class Recommendation.
    executive_answer: str = ""
    executive_summary: str = ""
    recommendation: str = ""
    key_findings: list[str] = Field(default_factory=list)
    alternative_perspectives: list[str] = Field(default_factory=list)

    claims: list[MemoClaim] = Field(default_factory=list)

    confidence: str = ""
    risk_level: str = ""
    risk_factors: list[str] = Field(default_factory=list)
    uncertainties: list[dict[str, Any]] = Field(default_factory=list)

    review_required: bool = False
    review_completed: bool = False
    review_decisions: list[MemoReviewDecision] = Field(default_factory=list)

    failures: list[MemoFailure] = Field(default_factory=list)
    degraded: bool = False

    methodology: str = ""
    sources: list[MemoSource] = Field(default_factory=list)

    trace_event_count: int = 0
    validation_count: int = 0
    replay_eligible: bool = False
    adapters_used: list[str] = Field(default_factory=list)
    trace_reference: str = "trace.json"

    #: Enriched fields absent from the source bundle (legacy bundles).
    unavailable_fields: list[str] = Field(default_factory=list)


def build_memo(bundle_dir: str | Path) -> ResearchMemoV1:
    """Build the memo from a verified terminal bundle.

    Raises whatever BundleReader raises for an absent bundle, and
    propagates integrity failures — an invalid bundle is never rendered.
    """
    reader = BundleReader(Path(bundle_dir))
    reader.verify_integrity()
    manifest = reader.get_manifest()
    report = reader.get_document("report.json")
    brief = reader.get_document("brief.json")
    claims_doc = reader.get_document("claims.json")
    citations_doc = reader.get_document("citations.json")
    sources_doc = reader.get_document("sources.json")
    uncertainties_doc = reader.get_document("uncertainties.json")
    review_doc = reader.get_document("review-decisions.json")
    failures_doc = reader.get_document("failures.json")
    validations_doc = reader.get_document("validations.json")
    trace_doc = reader.get_document("trace.json")

    profile = manifest.provider_mode
    unavailable: list[str] = []

    # Legacy discrimination: final-response presence is NOT a version
    # marker. A modern run rejected at the risk review gate truthfully
    # produces no Response Generator output, so its bundle has no
    # recommendation by design. The clean discriminator is that H1.4
    # finalization UNCONDITIONALLY adds review_required/review_completed
    # to review-decisions.json; pre-H1.4 bundles never carry them.
    is_legacy = (
        "review_required" not in review_doc
        and "review_completed" not in review_doc
    )

    recommendation = str(report.get("recommendation", "") or "")
    executive_summary = str(report.get("executive_summary", "") or "")
    key_findings = [str(f) for f in report.get("key_findings", []) or []]
    methodology = str(report.get("methodology_notes", "") or "")
    alternative_perspectives = [
        str(p) for p in
        report.get("alternative_perspectives", []) or []
    ]

    if is_legacy:
        # Pre-H1.4 bundle: the enriched fields did not exist. They are
        # legacy-UNAVAILABLE (distinct from a modern bundle where the run
        # recorded none), and the recorded executive_answer is never
        # upgraded into a first-class Recommendation.
        recommendation = ""
        executive_summary = ""
        key_findings = []
        methodology = ""
        alternative_perspectives = []
        unavailable.extend([
            "recommendation", "executive_summary", "key_findings",
            "methodology", "alternative_perspectives", "uncertainties",
            "risk_level", "confidence_statement",
        ])
        risk_level = ""
        risk_factors = []
        confidence = ""
    else:
        risk_level = str(report.get("risk_level", "") or "")
        risk_factors = [str(f) for f in report.get("risk_factors", []) or []]
        confidence = ""
        if "confidence_statement" in report:
            cs = report.get("confidence_statement", {}) or {}
            confidence = str(cs.get("level", "") or "")
            if cs.get("numeric") is not None:
                confidence = f"{confidence} ({cs.get('numeric')})".strip()
        # A modern bundle whose run recorded no risk/confidence data
        # renders "not recorded in this verified bundle" — never
        # legacy-specific wording.

    claims = [
        MemoClaim(
            claim_id=str(c.get("claim_id", "")),
            statement=str(c.get("statement", "")),
            status=str(c.get("status", "")),
            confidence=float(c.get("confidence", 0.0) or 0.0),
            evidence_ids=[
                str(e) for e in
                (c.get("supporting_evidence_ids", [])
                 + c.get("contradicting_evidence_ids", [])) or []
            ],
            citation_ids=[str(x) for x in c.get("citation_ids", []) or []],
        )
        for c in claims_doc.get("claims", []) or []
        if isinstance(c, dict)
    ]

    sources = [
        MemoSource(
            source_id=str(s.get("source_id", "")),
            title=str(s.get("title", "")),
            origin_api=str(s.get("origin_api", "")),
            doi=s.get("doi"),
            artifact_ref=s.get("artifact_ref") or None,
        )
        for s in sources_doc.get("sources", []) or []
        if isinstance(s, dict)
    ]

    review_decisions = [
        MemoReviewDecision(
            review_id=str(d.get("review_id", "")),
            decision=str(d.get("decision", "")),
            reason=str(d.get("reason", "")),
            reviewer_identity=str(d.get("reviewer_identity", "")),
            decided_at=str(d.get("decided_at", "")),
        )
        for d in review_doc.get("review_decisions", []) or []
        if isinstance(d, dict)
    ]

    failures = [
        MemoFailure(
            failure_id=str(f.get("failure_id", "")),
            adapter_name=str(f.get("adapter_name", "")),
            fault_type=str(f.get("fault_type", "")),
            occurred_at=str(f.get("occurred_at", "")),
            dispatch_occurred=bool(f.get("dispatch_occurred", False)),
            evidence_unavailable=bool(f.get("evidence_unavailable", False)),
            affected_claim_ids=[
                str(c) for c in f.get("affected_claim_ids", []) or []],
        )
        for f in failures_doc.get("failures", []) or []
        if isinstance(f, dict)
    ]

    return ResearchMemoV1(
        run_id=manifest.run_id,
        bundle_digest=manifest.bundle_digest,
        run_status=str(manifest.run_status.value),
        acquisition_profile=profile,
        reproducibility_mode=_REPRODUCIBILITY_MODES.get(
            profile, "unspecified"),
        question=str(brief.get("question", "") or ""),
        executive_answer=str(report.get("executive_answer", "") or ""),
        executive_summary=executive_summary,
        recommendation=recommendation,
        key_findings=key_findings,
        alternative_perspectives=alternative_perspectives,
        claims=claims,
        confidence=confidence,
        risk_level=risk_level,
        risk_factors=risk_factors,
        uncertainties=[
            {
                "marker_id": str(u.get("marker_id", "")),
                "description": str(u.get("description", "")),
                "affected_claim_ids": list(
                    u.get("affected_claim_ids", []) or []),
            }
            for u in uncertainties_doc.get("uncertainties", []) or []
            if isinstance(u, dict)
        ],
        review_required=bool(review_doc.get(
            "review_required", report.get("review_required", False))),
        review_completed=bool(review_doc.get(
            "review_completed", report.get("review_completed", False))),
        review_decisions=review_decisions,
        failures=failures,
        degraded=bool(failures_doc.get(
            "degraded_mode", False)) or str(
                manifest.run_status.value) == "completed_degraded",
        methodology=methodology,
        sources=sources,
        trace_event_count=len(trace_doc.get("events", []) or []),
        validation_count=len(
            validations_doc.get("validation_results", []) or []),
        replay_eligible=bool(manifest.replay_eligible),
        adapters_used=[str(a) for a in report.get("adapters_used", []) or []],
        trace_reference=str(manifest.trace_reference),
        unavailable_fields=unavailable,
    )


# --------------------------------------------------------------------------- #
# Deterministic Markdown rendering
# --------------------------------------------------------------------------- #


def _reproducibility_line(memo: ResearchMemoV1) -> str:
    label = _REPRODUCIBILITY_LABELS.get(
        memo.acquisition_profile, memo.reproducibility_mode)
    replay = (
        "A later run of the same inputs is expected to produce the same "
        "results (deterministic fixture)."
        if memo.replay_eligible else
        "NodeChain can prove exactly which content and provenance this run "
        "used, but cannot promise a later network query returns the same "
        "sources (artifact-bounded)."
        if memo.acquisition_profile == "live" else
        "Not eligible for deterministic replay."
    )
    return f"Acquisition: {memo.acquisition_profile} — {label}. {replay}"


def render_markdown(memo: ResearchMemoV1) -> str:
    """Render the memo as deterministic Markdown.

    No current timestamp, random ID, environment-specific path, or other
    non-determinism enters the output. All content comes from the memo,
    which comes from one verified bundle.
    """
    lines: list[str] = []
    add = lines.append

    add("# Research Memo")
    add("")
    add(f"**Research question:** {memo.question or '(not recorded)'}")
    add("")
    add(f"- Run: `{memo.run_id}`")
    add(f"- Terminal status: {memo.run_status}")
    add(f"- {_reproducibility_line(memo)}")
    add(f"- Verified bundle digest: `{memo.bundle_digest}`")
    add("")

    add("## Executive Summary")
    add("")
    if memo.executive_summary:
        add(memo.executive_summary)
    elif "executive_summary" in memo.unavailable_fields:
        add(
            "Executive summary information is not available in this "
            "legacy bundle."
        )
    else:
        add("No executive summary was recorded in this verified bundle.")
    add("")

    add("## Recommendation")
    add("")
    if memo.recommendation:
        add(memo.recommendation)
    elif "recommendation" in memo.unavailable_fields:
        # The legacy bundle has no first-class recommendation; its recorded
        # executive answer is presented as exactly that, never upgraded.
        add("A final recommendation is not available in this legacy bundle.")
        if memo.executive_answer:
            add("")
            add(
                "The recorded legacy executive answer was: "
                f"{memo.executive_answer}"
            )
    else:
        add("No recommendation was recorded in this verified bundle.")
    add("")

    add("## Key Findings")
    add("")
    if memo.key_findings:
        for finding in memo.key_findings:
            add(f"- {finding}")
    elif "key_findings" in memo.unavailable_fields:
        add(
            "Key findings are not available in this legacy bundle; the "
            "claim list below carries the recorded evidence."
        )
    else:
        add("No key findings were recorded in this verified bundle.")
    add("")
    if memo.claims:
        for c in memo.claims:
            citations = (
                ", ".join(c.citation_ids) if c.citation_ids
                else "no citations linked"
            )
            add(
                f"- **{c.claim_id}** ({c.status}, confidence "
                f"{c.confidence:.2f}) — {c.statement} "
                f"[{citations}]"
            )
        add("")

    if memo.alternative_perspectives:
        add("### Alternative Perspectives")
        add("")
        for perspective in memo.alternative_perspectives:
            add(f"- {perspective}")
        add("")

    add("## Evidence and Sources")
    add("")
    if memo.sources:
        for s in memo.sources:
            doi = f" DOI: {s.doi}." if s.doi else ""
            add(f"- `{s.source_id}` — {s.title} ({s.origin_api}).{doi}")
    else:
        add("No sources were recorded in this verified bundle.")
    add("")

    add("## Confidence, Risk, and Uncertainty")
    add("")
    if memo.confidence:
        add(f"- Confidence: {memo.confidence}")
    elif "confidence_statement" in memo.unavailable_fields:
        add("- Confidence statement is not available in this legacy bundle.")
    else:
        add("- No confidence statement was recorded in this verified "
            "bundle.")
    if memo.risk_level:
        add(f"- Risk level: {memo.risk_level}")
    elif "risk_level" in memo.unavailable_fields:
        add("- Risk level is not available in this legacy bundle.")
    else:
        add("- No risk level was recorded in this verified bundle.")
    if memo.risk_factors:
        add(f"- Risk factors: {', '.join(memo.risk_factors)}")
    if memo.uncertainties:
        for u in memo.uncertainties:
            affected = (
                ", ".join(u["affected_claim_ids"])
                if u["affected_claim_ids"] else "no claim attribution recorded"
            )
            add(f"- Uncertainty {u['marker_id']}: {u['description']} "
                f"(affects: {affected})")
    elif "uncertainties" in memo.unavailable_fields:
        # A legacy empty uncertainty document proves nothing about whether
        # uncertainty existed — that is not the same statement as a modern
        # bundle whose risk assessment recorded no uncertainty.
        add(
            "- Uncertainty information is not available in this legacy "
            "bundle."
        )
    else:
        add("- No uncertainty was recorded in this verified bundle.")
    add("")

    add("## Human Review")
    add("")
    if memo.review_required:
        add("Review was required for this run.")
        if memo.review_completed and memo.review_decisions:
            for d in memo.review_decisions:
                add(
                    f"- Decision: **{d.decision}** by {d.reviewer_identity} "
                    f"at {d.decided_at} — {d.reason}"
                )
        else:
            add(
                "No admitted review decision is recorded in this verified "
                "bundle."
            )
    else:
        add("Review was not required for this run.")
        if memo.review_decisions:
            for d in memo.review_decisions:
                add(
                    f"- Decision: **{d.decision}** by {d.reviewer_identity} "
                    f"at {d.decided_at} — {d.reason}"
                )
    add("")

    add("## Failures and Degraded Operation")
    add("")
    if memo.failures:
        for f in memo.failures:
            dispatch = (
                "dispatch occurred" if f.dispatch_occurred
                else "blocked before dispatch")
            evidence = (
                "downstream evidence from this operation was unavailable"
                if f.evidence_unavailable else
                "partial downstream evidence was available")
            if f.affected_claim_ids:
                impact = f"affected claims: {', '.join(f.affected_claim_ids)}"
            else:
                impact = "no claim impact was established"
            add(
                f"- {f.fault_type} on {f.adapter_name} at {f.occurred_at} "
                f"({dispatch}); {impact}; {evidence}."
            )
        if memo.degraded:
            add("- The run completed in a degraded mode.")
    else:
        add("No failure was recorded in this verified bundle.")
    add("")

    add("## Methodology")
    add("")
    if memo.methodology:
        add(memo.methodology)
    elif "methodology" in memo.unavailable_fields:
        add("Methodology notes are not available in this legacy bundle.")
    else:
        add("No methodology was recorded in this verified bundle.")
    add(f"- Adapters actually used: "
        f"{', '.join(memo.adapters_used) if memo.adapters_used else 'none'}")
    add(f"- Sources ingested: {len(memo.sources)}")
    add("")

    add("## Governance Evidence")
    add("")
    add(f"- Run ID: `{memo.run_id}`")
    add(f"- Verified bundle digest: `{memo.bundle_digest}`")
    add(f"- Terminal status: {memo.run_status}")
    add(f"- Validation checks recorded: {memo.validation_count}")
    add(
        f"- Trace events: {memo.trace_event_count} "
        f"(reference: {memo.trace_reference})"
    )
    add(f"- Replay eligible: {memo.replay_eligible}")
    add("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Rich terminal rendering
# --------------------------------------------------------------------------- #


def render_rich(memo: ResearchMemoV1, console: Any) -> None:
    """Render the memo to a terminal through the existing Rich stack.

    Semantic parity with ``render_markdown``: every recorded memo section
    appears — final response (summary, recommendation, key findings,
    alternatives), uncertainty detail with legacy availability statements,
    methodology, failures, and governance. Formatting may differ; content
    does not.
    """
    from rich.panel import Panel
    from rich.table import Table

    console.print(Panel(
        f"[bold blue]Research Memo[/bold blue]\n\n"
        f"Question: {memo.question or '(not recorded)'}\n"
        f"Run: {memo.run_id}\n"
        f"Status: {memo.run_status}\n"
        f"{_reproducibility_line(memo)}\n"
        f"Bundle digest: {memo.bundle_digest[:16]}...",
        title="Research Memo",
    ))

    if memo.executive_summary:
        console.print(Panel(memo.executive_summary, title="Executive Summary"))
    elif "executive_summary" in memo.unavailable_fields:
        console.print(Panel(
            "Executive summary information is not available in this "
            "legacy bundle.",
            title="Executive Summary",
        ))

    if memo.recommendation:
        console.print(Panel(memo.recommendation, title="Recommendation"))
    elif "recommendation" in memo.unavailable_fields:
        fallback = (
            "A final recommendation is not available in this legacy "
            f"bundle. The recorded legacy executive answer was: "
            f"{memo.executive_answer}"
            if memo.executive_answer else
            "A final recommendation is not available in this legacy bundle."
        )
        console.print(Panel(fallback, title="Recommendation"))

    if memo.key_findings:
        console.print(Panel(
            "\n".join(f"- {f}" for f in memo.key_findings),
            title="Key Findings",
        ))
    elif "key_findings" in memo.unavailable_fields:
        console.print(Panel(
            "Key findings are not available in this legacy bundle; the "
            "claim list below carries the recorded evidence.",
            title="Key Findings",
        ))

    if memo.alternative_perspectives:
        console.print(Panel(
            "\n".join(f"- {p}" for p in memo.alternative_perspectives),
            title="Alternative Perspectives",
        ))

    if memo.claims:
        table = Table(title="Claims")
        table.add_column("Claim", style="cyan")
        table.add_column("Status")
        table.add_column("Conf.")
        table.add_column("Citations")
        for c in memo.claims:
            table.add_row(
                c.claim_id, c.status, f"{c.confidence:.2f}",
                ", ".join(c.citation_ids) or "—",
            )
        console.print(table)

    if memo.sources:
        table = Table(title="Evidence and Sources")
        table.add_column("Source", style="cyan")
        table.add_column("Title")
        table.add_column("Origin")
        for s in memo.sources:
            table.add_row(s.source_id, s.title, s.origin_api)
        console.print(table)

    risk_bits = []
    if memo.confidence:
        risk_bits.append(f"Confidence: {memo.confidence}")
    elif "confidence_statement" in memo.unavailable_fields:
        risk_bits.append(
            "Confidence statement is not available in this legacy bundle.")
    else:
        risk_bits.append(
            "No confidence statement was recorded in this verified bundle.")
    if memo.risk_level:
        risk_bits.append(f"Risk: {memo.risk_level}")
    elif "risk_level" in memo.unavailable_fields:
        risk_bits.append("Risk level is not available in this legacy bundle.")
    else:
        risk_bits.append(
            "No risk level was recorded in this verified bundle.")
    if memo.risk_factors:
        risk_bits.append(f"Factors: {', '.join(memo.risk_factors)}")
    if memo.uncertainties:
        for u in memo.uncertainties:
            affected = (
                ", ".join(u["affected_claim_ids"])
                if u["affected_claim_ids"]
                else "no claim attribution recorded")
            risk_bits.append(
                f"Uncertainty {u['marker_id']}: {u['description']} "
                f"(affects: {affected})")
    elif "uncertainties" in memo.unavailable_fields:
        risk_bits.append(
            "Uncertainty information is not available in this legacy "
            "bundle.")
    else:
        risk_bits.append(
            "No uncertainty was recorded in this verified bundle.")
    console.print(Panel("\n".join(risk_bits), title="Confidence and Risk"))

    if memo.review_required:
        review_lines = ["Review was required."]
        if memo.review_completed and memo.review_decisions:
            for d in memo.review_decisions:
                review_lines.append(
                    f"{d.decision} by {d.reviewer_identity} at "
                    f"{d.decided_at} — {d.reason}")
        else:
            review_lines.append(
                "No admitted review decision is recorded.")
    else:
        review_lines = ["Review was not required."]
    console.print(Panel("\n".join(review_lines), title="Human Review"))

    if memo.failures:
        failure_lines = []
        for f in memo.failures:
            impact = (
                f"affected claims: {', '.join(f.affected_claim_ids)}"
                if f.affected_claim_ids
                else "no claim impact was established")
            failure_lines.append(
                f"{f.fault_type} on {f.adapter_name} at {f.occurred_at} — "
                f"{impact}")
        if memo.degraded:
            failure_lines.append("Run completed in degraded mode.")
    else:
        failure_lines = [
            "No failure was recorded in this verified bundle."]
    console.print(Panel("\n".join(failure_lines), title="Failures"))

    methodology_lines = []
    if memo.methodology:
        methodology_lines.append(memo.methodology)
    elif "methodology" in memo.unavailable_fields:
        methodology_lines.append(
            "Methodology notes are not available in this legacy bundle.")
    methodology_lines.append(
        f"Adapters used: "
        f"{', '.join(memo.adapters_used) if memo.adapters_used else 'none'}")
    methodology_lines.append(f"Sources ingested: {len(memo.sources)}")
    methodology_lines.append(
        f"Validations: {memo.validation_count}   "
        f"Trace events: {memo.trace_event_count}")
    methodology_lines.append(f"Replay eligible: {memo.replay_eligible}")
    methodology_lines.append(f"Bundle digest: {memo.bundle_digest}")
    console.print(Panel(
        "\n".join(methodology_lines),
        title="Methodology and Governance",
    ))
