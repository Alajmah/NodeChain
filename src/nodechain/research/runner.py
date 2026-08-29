"""WorkspaceRunner — composition root for governed research workspace runs.

The WorkspaceRunner constructs and invokes the existing orchestrator. It does
NOT manually call research nodes in sequence, duplicate routing/validation/
pause/recovery logic, or perform direct SQLite lifecycle writes.

Permitted composition (mirrors cli/run.py + cli/resume.py):
  * load and validate configuration (brief + corpus)
  * construct existing nodes (via _create_nodes, with FixtureSearchToolNode)
  * construct the existing chain/blueprint representation
  * register guarded adapters (FixtureSearchAdapter via OrdinaryDispatchGuard)
  * invoke existing run/resume APIs
  * persist existing runtime state and trace representations
  * translate terminal runtime evidence into the WP 5.1 bundle contract

Prohibited:
  * direct node-by-node execution
  * direct SQLite lifecycle mutation
  * synthetic trace events presented as runtime events
  * duplicated routing, validation, pause, or recovery logic
  * silent correction of runtime outcomes
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.adapters.search.fixture import FixtureSearchAdapter
from nodechain.core.blueprint import ChainBlueprint, ConnectionDef, NodeDef, load_blueprint
from nodechain.core.capsule_crypto import KekManager
from nodechain.core.default_policies import DEFAULT_POLICIES
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.runtime.recovery_dispatch_guard import OrdinaryDispatchGuard
from nodechain.core.policy import PolicyEngine

from .corpus import (
    FixtureCorpus,
    compute_corpus_canonical_digest,
    corpus_to_fixture_map,
    load_corpus,
)
from .fixture_model_adapter import FixtureModelAdapter
from nodechain.nodes.fixture_search_tool import FixtureSearchToolNode
from .run_descriptor import RunDescriptor, save_descriptor, load_descriptor
from .scoped_env import scoped_env


# --------------------------------------------------------------------------- #
# Research blueprint (Phase 5 sealed-workspace chain)
# --------------------------------------------------------------------------- #

#: The five already-existing Research SearchToolNode adapters permitted by
#: the H1.3 live profile. No new search provider is part of H1.3; blueprint
#: capabilities remain the hard upper bound on what a run may dispatch.
LIVE_ACQUISITION_ADAPTERS: tuple[str, ...] = (
    "semantic_scholar",
    "arxiv",
    "openalex",
    "crossref",
    "pubmed",
)

ACQUISITION_PROFILES: tuple[str, ...] = ("fixture", "live")


def _research_blueprint(
    chain_id: str, goal: str, allowed_adapters: list[str]
) -> ChainBlueprint:
    """Build the Phase 5 research blueprint.

    This is a linear chain using the existing research nodes. The
    ``search_tool`` node's ``allowed_adapters`` config is parameterized by
    acquisition profile (H1.3): fixture runs grant only the sealed fixture
    adapter; live runs grant the five existing governed academic adapters.
    The ``risk_classifier`` node is included so the existing runtime
    review-pause mechanism (hard-wired to that node_id) can trigger a
    genuine pause/review/resume flow.
    """
    return ChainBlueprint(
        chain_id=chain_id,
        name="Phase 5 Research Workspace",
        version="1.0.0",
        goal=goal,
        nodes=[
            NodeDef(node_id="goal_interpreter", node_type="model", config={}, position=1),
            NodeDef(node_id="task_planner", node_type="model", config={}, position=2),
            NodeDef(node_id="context_selector", node_type="deterministic", config={}, position=3),
            NodeDef(
                node_id="search_tool",
                node_type="tool",
                config={
                    "allowed_adapters": list(allowed_adapters),
                    "allowed_tools": ["search"],
                },
                position=4,
            ),
            NodeDef(node_id="source_ingestion", node_type="deterministic", config={}, position=5),
            NodeDef(node_id="source_quality_evaluator", node_type="model", config={}, position=6),
            NodeDef(node_id="qualified_source_linker", node_type="deterministic", config={}, position=7),
            NodeDef(node_id="evidence_synthesizer", node_type="model", config={}, position=8),
            NodeDef(node_id="claim_validator", node_type="model", config={}, position=9),
            NodeDef(node_id="risk_classifier", node_type="model", config={}, position=10),
            NodeDef(node_id="response_generator", node_type="model", config={}, position=11),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="normalized_research_goal", to_node="task_planner", to_port="normalized_research_goal"),
            ConnectionDef(from_node="task_planner", from_port="task_plan", to_node="context_selector", to_port="task_plan"),
            ConnectionDef(from_node="context_selector", from_port="context_bundle", to_node="search_tool", to_port="context_bundle"),
            ConnectionDef(from_node="search_tool", from_port="raw_search_results", to_node="source_ingestion", to_port="raw_search_results"),
            ConnectionDef(from_node="source_ingestion", from_port="source_set", to_node="source_quality_evaluator", to_port="source_set"),
            ConnectionDef(from_node="source_quality_evaluator", from_port="qualified_source_set", to_node="qualified_source_linker", to_port="qualified_source_set"),
            ConnectionDef(from_node="qualified_source_linker", from_port="qualified_source_set", to_node="evidence_synthesizer", to_port="qualified_source_set"),
            ConnectionDef(from_node="evidence_synthesizer", from_port="evidence_base", to_node="claim_validator", to_port="evidence_base"),
            ConnectionDef(from_node="claim_validator", from_port="validated_evidence_base", to_node="risk_classifier", to_port="validated_evidence_base"),
            ConnectionDef(from_node="risk_classifier", from_port="risk_assessment", to_node="response_generator", to_port="risk_assessment"),
        ],
    )


# --------------------------------------------------------------------------- #
# Research brief loader
# --------------------------------------------------------------------------- #


class ResearchBrief:
    """A research brief: the question and scope for a sealed run."""

    def __init__(self, question: str, focus_areas: list[str] | None = None) -> None:
        self.question = question
        self.focus_areas = focus_areas or []

    @classmethod
    def from_file(cls, path: str | Path) -> "ResearchBrief":
        """Load a brief from a YAML or JSON file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"brief not found: {p}")
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            import yaml

            doc = yaml.safe_load(text)
        else:
            doc = json.loads(text)
        if not isinstance(doc, dict):
            raise ValueError("brief root must be a mapping")
        return cls(
            question=doc.get("question", doc.get("primary_question", "")),
            focus_areas=doc.get("focus_areas", []),
        )

    @classmethod
    def from_question(cls, question: str) -> "ResearchBrief":
        return cls(question=question)


# --------------------------------------------------------------------------- #
# WorkspaceRunner
# --------------------------------------------------------------------------- #


class WorkspaceRunner:
    """Composition root for a governed research workspace run.

    Constructs the existing orchestrator with Phase 5 fixture-specialized
    nodes, invokes ``orchestrator.run()`` or ``orchestrator.resume()``, and
    exposes the resulting trace and state for bundle translation.

    Usage::

        runner = WorkspaceRunner(brief, corpus_path)
        result = runner.run()
        if result.paused:
            # operator reviews, then:
            runner.apply_review(decision, reason, reviewer)
            result = runner.resume()
    """

    def __init__(
        self,
        brief: ResearchBrief | str,
        corpus_path: str | Path | None = None,
        *,
        profile: str = "fixture",
        db_path: str | Path | None = None,
        trace_dir: str | Path | None = None,
        workspace_dir: str | Path | None = None,
        chain_id: str = "research-workspace-v1",
        model_adapter: Any = None,
    ) -> None:
        if profile not in ACQUISITION_PROFILES:
            raise ValueError(
                f"unknown acquisition profile {profile!r}; "
                f"must be one of {ACQUISITION_PROFILES}"
            )
        if isinstance(brief, str):
            brief = ResearchBrief.from_question(brief)
        self.brief = brief
        self.profile = profile
        # Fail-closed profile/corpus combination rules — no silent fallback
        # from live to fixture and no fixture run without a sealed corpus.
        if profile == "fixture":
            if corpus_path is None:
                raise ValueError(
                    "the fixture acquisition profile requires --corpus"
                )
            self._corpus_path = str(corpus_path)
            self.corpus = load_corpus(corpus_path)
            self.corpus_digest = compute_corpus_canonical_digest(self.corpus)
        else:  # live
            if corpus_path is not None:
                raise ValueError(
                    "the live acquisition profile does not accept --corpus"
                )
            self._corpus_path = ""
            self.corpus = None
            self.corpus_digest = ""
        self.allowed_adapters = (
            ["fixture"] if profile == "fixture"
            else list(LIVE_ACQUISITION_ADAPTERS)
        )
        self.chain_id = chain_id
        self._workspace_dir = str(workspace_dir or "data/research_workspace")
        Path(self._workspace_dir).mkdir(parents=True, exist_ok=True)
        self._db_path = str(db_path or (Path(self._workspace_dir) / "run.db"))
        self._trace_dir = str(trace_dir or (Path(self._workspace_dir) / "traces"))
        Path(self._trace_dir).mkdir(parents=True, exist_ok=True)
        self._kek_path = str(Path(self._workspace_dir) / ".kek")
        self.orchestrator: Orchestrator | None = None
        self._search_node: Any = None
        self._fixture_adapter: FixtureSearchAdapter | None = None
        self._guard: Any = None
        self._run_descriptor: RunDescriptor | None = None
        self._review_env: dict[str, str] = {}
        self._adapter_versions: dict[str, str] = {}

        # Model adapter resolution. The fixture profile keeps its sealed
        # FixtureModelAdapter (built in _build_nodes). The live profile uses
        # the existing production model-provider resolution semantics — the
        # same authority as the ordinary NodeChain run path — or an explicitly
        # injected bounded deterministic adapter (qualification only).
        if profile == "live":
            if model_adapter is not None:
                self._model_adapter = model_adapter
                self.model_provider = "injected"
                self.model_name = type(model_adapter).__name__
            else:
                from nodechain.cli.run import resolve_production_model_adapter
                (self._model_adapter, provider, model_name
                 ) = resolve_production_model_adapter()
                self.model_provider = provider
                self.model_name = model_name
        else:
            self._model_adapter = None
            self.model_provider = "fixture"
            self.model_name = "fixture-mock"

    @classmethod
    def from_descriptor(cls, desc: RunDescriptor) -> "WorkspaceRunner":
        """Reconstruct a WorkspaceRunner from a persisted run descriptor.

        This is the fresh-process reconstruction path: a new WorkspaceRunner
        object is created with all paths from the descriptor, suitable for
        compose_for_resume + resume.

        For a live V2 descriptor, the persisted acquisition configuration is
        AUTHORITATIVE: allowed adapters, provider/model identity, adapter
        versions, and provenance version come from the descriptor, while
        credentials and endpoints remain current environment authority. If
        the current environment cannot satisfy the persisted configuration,
        reconstruction fails closed — it never silently substitutes current
        defaults, so a run cannot pause under configuration A and resume
        under configuration B.
        """
        if desc.profile == "live":
            allowed = [a for a in (desc.allowed_adapters or ()) if a]
            if not allowed or any(
                    a not in LIVE_ACQUISITION_ADAPTERS for a in allowed):
                raise ValueError(
                    f"descriptor for run {desc.run_id} declares an "
                    f"unsatisfiable live adapter set: {desc.allowed_adapters}"
                )
            if desc.model_provider == "injected":
                raise ValueError(
                    f"live run {desc.run_id} used an injected process-local "
                    f"model adapter; that acquisition configuration cannot "
                    f"be reconstructed in a fresh process — resume refused"
                )
            from nodechain.cli.run import resolve_production_model_adapter
            adapter, provider, model = resolve_production_model_adapter()
            if (provider, model) != (desc.model_provider, desc.model_name):
                raise ValueError(
                    f"current model resolution ({provider}/{model}) does not "
                    f"match the persisted acquisition configuration "
                    f"({desc.model_provider}/{desc.model_name}) for run "
                    f"{desc.run_id}; refusing to resume under a substituted "
                    f"configuration"
                )
            runner = cls(
                brief=ResearchBrief.from_question(desc.question),
                corpus_path=None,
                profile="live",
                workspace_dir=desc.workspace_dir,
                db_path=desc.db_path,
                trace_dir=desc.trace_dir,
                chain_id=desc.chain_id,
                model_adapter=adapter,
            )
            # The constructor labels injected adapters with their class
            # name; restore the persisted non-secret identity (the adapter
            # instance itself came from the current-environment resolution
            # verified above, so credentials stayed with the environment).
            runner.model_provider = desc.model_provider
            runner.model_name = desc.model_name
            # Descriptor-authoritative acquisition set (may be a subset of
            # the five permitted adapters granted at launch).
            runner.allowed_adapters = allowed
            runner._run_descriptor = desc
            return runner
        runner = cls(
            brief=ResearchBrief.from_question(desc.question),
            corpus_path=desc.corpus_path,
            profile="fixture",
            workspace_dir=desc.workspace_dir,
            db_path=desc.db_path,
            trace_dir=desc.trace_dir,
            chain_id=desc.chain_id,
        )
        runner._run_descriptor = desc
        return runner

    # ------------------------------------------------------------------ #
    # Composition
    # ------------------------------------------------------------------ #

    def _build_nodes(self) -> dict[str, Any]:
        """Construct the existing research nodes for the run's profile."""
        from nodechain.cli.run import _create_nodes

        if self.profile == "live":
            # Live composition: the ordinary production SearchToolNode and
            # the existing production model-provider resolution. The guarded
            # adapter registry is wired in _compose (it needs the run_id).
            nodes = _create_nodes(
                self._model_adapter,
                self._trace_dir,
                memory_manager=None,
                policy_engine=None,
                state_manager=None,
            )
        else:
            # Fixture composition: extract search terms from the corpus
            # query keys so the model adapter produces queries that match
            # the sealed corpus.
            search_terms = list(self.corpus.queries.keys())
            # Claim confidence: derived from the corpus scenario_kind.
            claim_confidence = 0.75  # default: high confidence (stable literature)
            scenario_kind = getattr(self.corpus, "scenario_kind", "stable_literature")
            if scenario_kind == "conflicting_evidence":
                claim_confidence = 0.2  # low confidence from genuinely contradictory evidence
            model_adapter = FixtureModelAdapter(
                latency_ms=0,
                search_terms=search_terms,
                claim_confidence=claim_confidence,
                scenario_kind=scenario_kind,
            )
            nodes = _create_nodes(
                model_adapter,
                self._trace_dir,
                memory_manager=None,  # sealed run — no ChromaDB
                policy_engine=None,  # set on orchestrator
                state_manager=None,  # set on orchestrator
            )
            # Replace the production SearchToolNode with the fixture
            # specialization.
            nodes["search_tool"] = FixtureSearchToolNode()
        # Add the QualifiedSourceLinker between quality evaluation and
        # synthesis (both profiles — it is the fail-closed linkage authority).
        from .qualified_source_linker import QualifiedSourceLinkerNode
        nodes["qualified_source_linker"] = QualifiedSourceLinkerNode()
        return nodes

    def _compose(self, persisted_run_id: str | None = None) -> Orchestrator:
        """Construct the orchestrator and wire the guarded fixture adapter.

        When ``persisted_run_id`` is provided (resume path), the guard is
        bound to that ID so capsule lookups match the original run's
        side-effect ledger. The orchestrator's resume(persisted_run_id) then
        loads the persisted state from the DB.
        """
        # Build explicit local-dev KEK (no process-global env mutation).
        kek_manager = KekManager(local_dev=True, kek_path=self._kek_path)
        sm = StateManager(
            self._db_path,
            kek_manager=kek_manager,
        )
        policy_engine = PolicyEngine()
        for policy in DEFAULT_POLICIES:
            policy_engine.register(policy)

        # Build blueprint.
        blueprint = _research_blueprint(
            self.chain_id, self.brief.question, list(self.allowed_adapters)
        )

        # Build nodes.
        nodes = self._build_nodes()
        self._search_node = nodes["search_tool"]

        # Construct orchestrator.
        orchestrator = Orchestrator(
            blueprint=blueprint,
            nodes=nodes,
            state_manager=sm,
            policy_engine=policy_engine,
        )

        # Wire the guarded acquisition adapters. For resume, bind to the
        # persisted run_id (for capsule lookup). For initial run, use the
        # orchestrator's newly allocated run_id.
        run_id = persisted_run_id or orchestrator.state.run_id

        def capsule_validator(check_run_id: str, adapter_name: str, digest: str) -> bool:
            """Verify an exact capsule exists for this run + adapter + digest
            with capsule_status='available'.

            The capsule-before-wire invariant (INV-004) requires that a
            capsule with capsule_status='available' was persisted before the
            adapter dispatch, with an exact canonical request digest match.
            """
            try:
                import sqlite3

                with sqlite3.connect(str(sm.db_path)) as conn:
                    row = conn.execute(
                        """SELECT COUNT(*) FROM side_effect_replay_capsules c
                           JOIN side_effect_ledger l
                             ON l.run_id = c.run_id
                             AND l.idempotency_key = c.side_effect_key
                           WHERE c.run_id = ?
                           AND c.capsule_digest = ?
                           AND c.side_effect_key LIKE ?
                           AND l.capsule_status = 'available'""",
                        (check_run_id, digest, f"search:{adapter_name}:%"),
                    ).fetchone()
                    return row[0] > 0
            except Exception:
                return False

        if self.profile == "live":
            # Live composition: reuse the existing production guarded
            # adapter registry. Every live search dispatch runs through the
            # ordinary SearchToolNode, the side-effect lifecycle, and the
            # capsule-before-wire invariant — the runner never calls an
            # adapter or an API directly.
            from nodechain.runtime.recovery_dispatch_guard import (
                build_ordinary_guarded_registry,
            )
            guarded_registry = build_ordinary_guarded_registry(
                run_id=run_id,
                adapter_names=list(self.allowed_adapters),
                capsule_validator=capsule_validator,
            )
            missing = [
                name for name in self.allowed_adapters
                if name not in guarded_registry
            ]
            if missing:
                raise RuntimeError(
                    f"live acquisition adapters unavailable: {missing}"
                )
            self._guard = guarded_registry
            self._adapter_versions = {
                name: str(getattr(g, "adapter_version", "") or "")
                for name, g in guarded_registry.items()
            }
            self._search_node.set_adapter_resolver(guarded_registry)
        else:
            fixture_map = corpus_to_fixture_map(self.corpus)
            self._fixture_adapter = FixtureSearchAdapter(fixture_map)

            # Lane-admission: fail_before_dispatch. When this fault is active,
            # a lane-admission wrapper rejects dispatch BEFORE the guard's
            # search() is invoked. This is a product-level admission
            # decision, NOT a capsule-integrity failure. The guard is never
            # called, so:
            #   guard.dispatch_count == 0
            #   adapter.invocation_count == 0
            #   no capsule-integrity violation
            fail_before_dispatch_active = bool(
                self.corpus.fault_injection.fail_before_dispatch_lanes
            )

            guard = OrdinaryDispatchGuard(
                target_adapter=self._fixture_adapter,
                run_id=run_id,
                capsule_validator=capsule_validator,
                skip_trust_check=False,  # MUST be False
            )

            # Lane-admission wrapper for fail_before_dispatch: wraps the
            # guard so search() is rejected BEFORE the guard processes it.
            # The guard's dispatch count stays 0 and the adapter is never
            # invoked. This is a product-level admission decision, not a
            # capsule-integrity failure.
            if fail_before_dispatch_active:
                original_search = guard.search

                async def fail_before_search(query):
                    from nodechain.adapters.search.base_search import (
                        SearchAdapterError,
                    )
                    from nodechain.adapters.search.failure_types import (
                        AdapterFailure,
                        SearchFailureType,
                    )
                    raise SearchAdapterError(
                        AdapterFailure(
                            adapter=self._fixture_adapter.adapter_name,
                            failure_type=SearchFailureType.UNKNOWN,
                            retryable=False,
                            message="fail_before_dispatch: lane admission rejected "
                            "(dispatch did not occur)",
                            reason_code="LANE_ADMISSION_REJECTED",
                        )
                    )
                guard.search = fail_before_search

            self._guard = guard
            self._adapter_versions = {"fixture": guard.adapter_version}
            self._search_node.set_adapter_resolver({"fixture": guard})

        # Validate contracts.
        issues = orchestrator.validate_contracts()
        if issues:
            raise RuntimeError(f"contract validation failed: {issues}")

        self.orchestrator = orchestrator
        return orchestrator

    # ------------------------------------------------------------------ #
    # Run / Resume
    # ------------------------------------------------------------------ #

    def _compute_input_digest(self) -> str:
        """Launch-intent/config digest for the run (H1.3 AC5/AC7).

        Canonical inputs: the brief, the acquisition profile, the allowed
        adapter set, the provenance version, and the resolved non-secret
        model identity — plus the corpus digest for fixture runs. This is
        NOT a source snapshot and NOT a deterministic replay digest: it
        identifies what the run was launched to do, never what the network
        returned.
        """
        import hashlib as _hl

        from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION

        payload = {
            "question": self.brief.question,
            "focus_areas": sorted(self.brief.focus_areas),
            "acquisition_profile": self.profile,
            "allowed_adapters": sorted(self.allowed_adapters),
            "provenance_version": CURRENT_PROVENANCE_VERSION,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
        }
        if self.profile == "fixture":
            payload["corpus_digest"] = self.corpus_digest
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return _hl.sha256(canonical.encode("utf-8")).hexdigest()

    def run(self) -> "RunResult":
        """Execute the research chain from start.

        Returns a RunResult capturing the trace, state, and whether the run
        paused for review.
        """
        import asyncio

        # Sealed research runs require explicit operator review — apply pause
        # mode through a scoped context so it doesn't leak to the process.
        with scoped_env({"NODECHAIN_REVIEW_MODE": "pause"}):
            orch = self._compose()

            # Persist the descriptor AFTER run_id allocation but BEFORE
            # execution, so a crash during dispatch leaves a discoverable run.
            desc = RunDescriptor(
                run_id=orch.state.run_id,
                chain_id=self.chain_id,
                question=self.brief.question,
                focus_areas=tuple(self.brief.focus_areas),
                db_path=self._db_path,
                trace_dir=self._trace_dir,
                workspace_dir=self._workspace_dir,
                kek_path=self._kek_path,
                descriptor_version=2,
                acquisition_profile=self.profile,
                input_digest=self._compute_input_digest(),
                allowed_adapters=tuple(self.allowed_adapters),
                adapter_versions=dict(self._adapter_versions),
                provenance_version=self._provenance_version(),
                model_provider=self.model_provider,
                model_name=self.model_name,
                **(
                    dict(
                        corpus_path=self._corpus_path,
                        corpus_digest=self.corpus_digest,
                        corpus_version=self.corpus.corpus_version,
                        scenario_id=self.corpus.scenario_id,
                    ) if self.profile == "fixture" else {}
                ),
            )
            save_descriptor(self._workspace_dir, desc)
            self._run_descriptor = desc

            trace = asyncio.run(orch.run(self.brief.question))

        # Record durable fault records for fault-injection scenarios.
        self._record_faults(orch.state.run_id, trace)

        # Finalize terminal bundle if the run reached a terminal state.
        if trace.final_status in ("completed", "failed"):
            from .bundle_finalizer import finalize_bundle
            # Finalization failure propagates — no silent recovery.
            self._bundle_path = finalize_bundle(
                workspace_dir=self._workspace_dir,
                run_id=orch.state.run_id,
                desc=desc,
                trace=trace,
                state=orch.state,
                corpus=self.corpus,
                source_commit=desc.chain_id,
            )
        else:
            self._bundle_path = None

        return RunResult(
            run_id=orch.state.run_id,
            chain_id=self.chain_id,
            trace=trace,
            state=orch.state,
            runner=self,
        )

    @staticmethod
    def _provenance_version() -> int:
        from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION

        return CURRENT_PROVENANCE_VERSION

    #: Recognized fault reason codes for event projection.
    _RECOGNIZED_FAULT_CODES: frozenset[str] = frozenset({
        "LANE_ADMISSION_REJECTED",
        "SEARCH_TIMEOUT_AFTER_DISPATCH",
        "SEARCH_PROVENANCE_MALFORMED",
        "SEARCH_PARTIAL_RESULT_SET",
        "SEARCH_RETRY_SCHEDULED",
        "SEARCH_RETRY_RECOVERED",
    })

    #: Map reason codes to fault types.
    _REASON_CODE_TO_FAULT_TYPE: dict[str, str] = {
        "LANE_ADMISSION_REJECTED": "fail_before_dispatch",
        "SEARCH_TIMEOUT_AFTER_DISPATCH": "timeout_after_dispatch",
        "SEARCH_PROVENANCE_MALFORMED": "malformed_provenance",
        "SEARCH_PARTIAL_RESULT_SET": "partial_result_set",
    }

    #: Provenance error keywords that map to SEARCH_PROVENANCE_MALFORMED.
    _PROVENANCE_KEYWORDS: tuple[str, ...] = (
        "PROVENANCE_VERSION", "provenance_version",
        "unknown version", "malformed_provenance",
    )

    def _record_faults(self, run_id: str, trace: Any) -> None:
        """Record durable fault records as a pure trace-event projection.

        Consumes ONLY trace events with recognized reason codes or provenance
        error evidence. Does NOT use corpus configuration to decide that a
        fault occurred.
        """
        from .run_descriptor import save_fault_record
        from datetime import datetime, timezone
        import hashlib as _hl

        trace_id = getattr(trace, "trace_id", None) or getattr(trace, "run_id", run_id)

        # Select events with recognized reason codes (exact match or prefix).
        fault_events = []
        for ev in trace.events:
            if not ev.reason_codes:
                continue
            for rc in ev.reason_codes:
                for known in self._REASON_CODE_TO_FAULT_TYPE:
                    if rc == known or rc.startswith(known + ":"):
                        fault_events.append(ev)
                        break
                else:
                    if rc in self._RECOGNIZED_FAULT_CODES:
                        fault_events.append(ev)
                        break

        # Build recovery lookup: map original_failure_event_id → recovery event.
        recovery_map: dict[str, Any] = {}
        for ev in trace.events:
            if "SEARCH_RETRY_RECOVERED" in getattr(ev, "reason_codes", []):
                meta = getattr(ev, "metadata", {}) or {}
                orig_id = meta.get("original_failure_event_id")
                if orig_id:
                    recovery_map[orig_id] = ev

        # Build retry-scheduled lookup: map original_failure_event_id → scheduled event.
        retry_scheduled_map: dict[str, Any] = {}
        for ev in trace.events:
            if "SEARCH_RETRY_SCHEDULED" in getattr(ev, "reason_codes", []):
                meta = getattr(ev, "metadata", {}) or {}
                orig_id = meta.get("original_failure_event_id")
                if orig_id:
                    retry_scheduled_map[orig_id] = ev

        # Determine final node outcome for search_tool.
        search_events = [ev for ev in trace.events if ev.node_id == "search_tool"]
        final_node_outcome = "unknown"
        for ev in reversed(search_events):
            if "node_succeeded" in ev.event_type.value.lower():
                final_node_outcome = "succeeded"
                break
            if "node_failed" in ev.event_type.value.lower():
                final_node_outcome = "failed"
                break

        for ev in fault_events:
            # Determine primary reason code. The actual trace event may carry
            # the reason code as a prefix (e.g. "SEARCH_PROVENANCE_MALFORMED: ...").
            # Extract the canonical code by checking prefix matches.
            primary_code = None
            for rc in ev.reason_codes:
                for known in self._REASON_CODE_TO_FAULT_TYPE:
                    if rc == known or rc.startswith(known + ":"):
                        primary_code = known
                        break
                if primary_code:
                    break
            if primary_code is None:
                # Check for SEARCH_RETRY_RECOVERED — these are recovery events,
                # not fault-creating events.
                if "SEARCH_RETRY_RECOVERED" in ev.reason_codes:
                    continue
                # Skip unrecognized codes.
                continue

            fault_type = self._REASON_CODE_TO_FAULT_TYPE[primary_code]
            step_id = getattr(ev, "step_id", 0)
            ev_meta = getattr(ev, "metadata", {}) or {}

            # Extract operation_digest: from the event metadata if available,
            # otherwise from the trace's side_effect_started idempotency_key.
            operation_digest = ev_meta.get("operation_digest", "")
            if not operation_digest:
                for se_ev in trace.events:
                    if (se_ev.node_id == ev.node_id
                            and "side_effect_started" in se_ev.event_type.value.lower()):
                        se_meta = getattr(se_ev, "metadata", {}) or {}
                        ikey = se_meta.get("idempotency_key", "")
                        if ":" in ikey:
                            parts = ikey.split(":")
                            if len(parts) >= 3:
                                operation_digest = parts[-1]
                                break

            fault_id = _hl.sha256(
                f"{run_id}|{step_id}|{primary_code}".encode("utf-8")
            ).hexdigest()

            # Check for recovery evidence.
            recovery_ev = recovery_map.get(ev.event_id)
            scheduled_ev = retry_scheduled_map.get(ev.event_id)
            attempt_outcome = "failed"
            recovery_meta = getattr(recovery_ev, "metadata", {}) if recovery_ev else {}
            recovery_outcome = recovery_meta.get("recovery_outcome")

            record = {
                "fault_id": fault_id,
                "run_id": run_id,
                "trace_id": trace_id,
                "step_id": step_id,
                "attempt_number": ev_meta.get("attempt_number", 1),
                "operation_digest": operation_digest,
                "dispatch_attempted": ev_meta.get("dispatch_attempted", primary_code != "LANE_ADMISSION_REJECTED"),
                "operation": f"search:{ev.node_id}",
                "failure_type": fault_type,
                "reason_codes": [primary_code],
                "proving_event_ids": [ev.event_id],
                "proving_events": [{
                    "event_id": ev.event_id,
                    "event_type": ev.event_type.value,
                    "step_id": step_id,
                    "decision": str(getattr(ev, "decision", "")),
                    "reason_codes": ev.reason_codes,
                    "metadata": ev_meta,
                }],
                "attempt_outcome": attempt_outcome,
                "recovery_outcome": recovery_outcome or "not_recovered",
                "final_node_outcome": final_node_outcome,
                "state_before": "pre_dispatch" if primary_code == "LANE_ADMISSION_REJECTED" else "dispatch_attempted",
                "state_after": {
                    "fail_before_dispatch": "not_dispatched",
                    "timeout_after_dispatch": "timeout",
                    "malformed_provenance": "provenance_rejected",
                    "partial_result_set": "partial",
                }.get(fault_type, "unknown"),
                "recoverability": {
                    "fail_before_dispatch": "retry_possible",
                    "timeout_after_dispatch": "retry_possible",
                    "malformed_provenance": "non_recoverable",
                    "partial_result_set": "degraded_completion",
                }.get(fault_type, "unknown"),
                "related_artifact_refs": [f"trace_event:{ev.event_id}"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            save_fault_record(self._workspace_dir, run_id, record)

    def compose_for_resume(self, persisted_run_id: str) -> Orchestrator:
        """Construct the orchestrator for a resume, bound to the persisted
        run_id. The guard, capsule validator, and resume call all use this ID.

        This does NOT manually assign orchestrator.state — the existing
        orchestrator.resume(persisted_run_id) seam loads state from the DB.

        For a live V2 run, the persisted acquisition configuration is
        ENFORCED against the reconstructed composition before the caller
        can resume: the descriptor's provenance version must equal the
        currently supported provenance version, and every authorized
        adapter's current version must exactly match the descriptor's
        recorded version. Missing or mismatched persisted version
        information fails closed — a run can never resume under a
        substituted provenance contract or adapter implementation.
        """
        orchestrator = self._compose(persisted_run_id=persisted_run_id)
        desc = self._run_descriptor
        if (desc is not None and desc.profile == "live"
                and desc.descriptor_version >= 2):
            from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION
            if desc.provenance_version is None:
                raise ValueError(
                    f"live descriptor for run {persisted_run_id} is missing "
                    f"provenance_version; resume refused"
                )
            if desc.provenance_version != CURRENT_PROVENANCE_VERSION:
                raise ValueError(
                    f"descriptor provenance_version "
                    f"{desc.provenance_version} != supported "
                    f"{CURRENT_PROVENANCE_VERSION} for run "
                    f"{persisted_run_id}; refusing to resume under a "
                    f"changed provenance contract"
                )
            persisted_versions = dict(desc.adapter_versions or {})
            if not persisted_versions:
                raise ValueError(
                    f"live descriptor for run {persisted_run_id} is missing "
                    f"adapter_versions; resume refused"
                )
            for name in self.allowed_adapters:
                persisted = persisted_versions.get(name)
                if not persisted:
                    raise ValueError(
                        f"live descriptor for run {persisted_run_id} is "
                        f"missing the persisted version for authorized "
                        f"adapter {name!r}; resume refused"
                    )
                current = self._adapter_versions.get(name)
                if current != persisted:
                    raise ValueError(
                        f"adapter {name!r} version changed since run "
                        f"{persisted_run_id} launched: descriptor records "
                        f"{persisted}, current is {current}; refusing to "
                        f"resume under a substituted configuration"
                    )
        return orchestrator

    def resume(self, run_id: str | None = None) -> "RunResult":
        """Resume a paused run through the existing runtime resume seam.

        Args:
            run_id: The persisted run ID to resume. If None, uses the
                orchestrator's current run_id (initial-run in-memory path).
        """
        import asyncio

        if self.orchestrator is None:
            raise RuntimeError("no orchestrator — call run() or compose_for_resume() first")
        target_run_id = run_id or self.orchestrator.state.run_id
        # The resume path reads review env vars. During resume, the review mode
        # must be 'interactive' (not 'pause') so _get_decision falls through to
        # the HumanAdapter which reads NODECHAIN_REVIEW_DECISION. In pause mode,
        # _get_decision would raise ReviewPausedException again.
        env_updates = {"NODECHAIN_REVIEW_MODE": "interactive"}
        env_updates.update(self._review_env)
        try:
            with scoped_env(env_updates):
                trace = asyncio.run(self.orchestrator.resume(target_run_id))
        finally:
            self._review_env = {}  # one-shot: clear after every resume attempt

        # Finalize terminal bundle if the resumed run reached a terminal state.
        if trace.final_status in ("completed", "failed") and self._run_descriptor:
            from .bundle_finalizer import finalize_bundle
            # Finalization failure propagates.
            self._bundle_path = finalize_bundle(
                workspace_dir=self._workspace_dir,
                run_id=target_run_id,
                desc=self._run_descriptor,
                trace=trace,
                state=self.orchestrator.state,
                corpus=self.corpus,
                source_commit=self._run_descriptor.chain_id,
            )

        return RunResult(
            run_id=target_run_id,
            chain_id=self.chain_id,
            trace=trace,
            state=self.orchestrator.state,
            runner=self,
        )

    def apply_review(
        self,
        decision: str,
        reason: str,
        reviewer: str,
    ) -> None:
        """Record a review decision for the current paused run.

        The decision is delivered through the existing runtime review seam
        (the env vars the HumanAdapter reads on resume). Applied through
        a scoped context so env vars don't leak to the process permanently.

        Rejects unknown decisions — only 'approve', 'reject', 'revise' are
        valid.
        """
        decision_map = {
            "approve": "approve",
            "reject": "reject",
            "revise": "request_revision",
        }
        if decision not in decision_map:
            raise ValueError(
                f"unknown review decision {decision!r}; "
                f"must be one of {sorted(decision_map)}"
            )
        runtime_decision = decision_map[decision]
        # Store for resume() to apply through scoped_env. This is one-shot:
        # resume() clears it in finally.
        self._review_env = {
            "NODECHAIN_REVIEW_DECISION": runtime_decision,
            "NODECHAIN_REVIEW_REASON": reason,
            "NODECHAIN_REVIEWER_IDENTITY": reviewer,
        }


# --------------------------------------------------------------------------- #
# RunResult
# --------------------------------------------------------------------------- #


class RunResult:
    """Result of a research run or resume."""

    def __init__(
        self,
        run_id: str,
        chain_id: str,
        trace: Any,
        state: Any,
        runner: WorkspaceRunner,
    ) -> None:
        self.run_id = run_id
        self.chain_id = chain_id
        self.trace = trace
        self.state = state
        self._runner = runner

    @property
    def paused(self) -> bool:
        """Whether the run is paused for review."""
        return (
            self.trace.final_status == "paused"
            or self.state.status == "waiting_for_review"
            or self.state.status == "paused"
            or self.state.status == "paused_for_budget"
            or self.trace.final_status == "waiting_for_review"
        )

    @property
    def completed(self) -> bool:
        return self.trace.final_status == "completed"

    @property
    def failed(self) -> bool:
        # A paused run is NOT failed — it's waiting for operator action.
        if self.paused:
            return False
        return self.trace.final_status not in ("completed",)

    @property
    def corpus_digest(self) -> str:
        return self._runner.corpus_digest
