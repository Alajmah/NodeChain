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


def _research_blueprint(chain_id: str, goal: str) -> ChainBlueprint:
    """Build the Phase 5 research blueprint.

    This is a linear chain using the existing research nodes with the
    FixtureSearchToolNode. The ``risk_classifier`` node is included so the
    existing runtime review-pause mechanism (hard-wired to that node_id) can
    trigger a genuine pause/review/resume flow.
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
                    "allowed_adapters": ["fixture"],
                    "allowed_tools": ["search"],
                },
                position=4,
            ),
            NodeDef(node_id="source_ingestion", node_type="deterministic", config={}, position=5),
            NodeDef(node_id="source_quality_evaluator", node_type="model", config={}, position=6),
            NodeDef(node_id="evidence_synthesizer", node_type="model", config={}, position=7),
            NodeDef(node_id="claim_validator", node_type="model", config={}, position=8),
            NodeDef(node_id="risk_classifier", node_type="model", config={}, position=9),
            NodeDef(node_id="response_generator", node_type="model", config={}, position=10),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="normalized_research_goal", to_node="task_planner", to_port="normalized_research_goal"),
            ConnectionDef(from_node="task_planner", from_port="task_plan", to_node="context_selector", to_port="task_plan"),
            ConnectionDef(from_node="context_selector", from_port="context_bundle", to_node="search_tool", to_port="context_bundle"),
            ConnectionDef(from_node="search_tool", from_port="raw_search_results", to_node="source_ingestion", to_port="raw_search_results"),
            ConnectionDef(from_node="source_ingestion", from_port="source_set", to_node="source_quality_evaluator", to_port="source_set"),
            ConnectionDef(from_node="source_quality_evaluator", from_port="qualified_source_set", to_node="evidence_synthesizer", to_port="qualified_source_set"),
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
        corpus_path: str | Path,
        *,
        db_path: str | Path | None = None,
        trace_dir: str | Path | None = None,
        workspace_dir: str | Path | None = None,
        chain_id: str = "research-workspace-v1",
    ) -> None:
        if isinstance(brief, str):
            brief = ResearchBrief.from_question(brief)
        self.brief = brief
        self._corpus_path = str(corpus_path)
        self.corpus = load_corpus(corpus_path)
        self.corpus_digest = compute_corpus_canonical_digest(self.corpus)
        self.chain_id = chain_id
        self._workspace_dir = str(workspace_dir or "data/research_workspace")
        Path(self._workspace_dir).mkdir(parents=True, exist_ok=True)
        self._db_path = str(db_path or (Path(self._workspace_dir) / "run.db"))
        self._trace_dir = str(trace_dir or (Path(self._workspace_dir) / "traces"))
        Path(self._trace_dir).mkdir(parents=True, exist_ok=True)
        self._kek_path = str(Path(self._workspace_dir) / ".kek")
        self.orchestrator: Orchestrator | None = None
        self._search_node: FixtureSearchToolNode | None = None
        self._fixture_adapter: FixtureSearchAdapter | None = None
        self._guard: Any = None
        self._run_descriptor: RunDescriptor | None = None
        self._review_env: dict[str, str] = {}

    @classmethod
    def from_descriptor(cls, desc: RunDescriptor) -> "WorkspaceRunner":
        """Reconstruct a WorkspaceRunner from a persisted run descriptor.

        This is the fresh-process reconstruction path: a new WorkspaceRunner
        object is created with all paths from the descriptor, suitable for
        compose_for_resume + resume.
        """
        return cls(
            brief=ResearchBrief.from_question(desc.question),
            corpus_path=desc.corpus_path,
            workspace_dir=desc.workspace_dir,
            db_path=desc.db_path,
            trace_dir=desc.trace_dir,
            chain_id=desc.chain_id,
        )

    # ------------------------------------------------------------------ #
    # Composition
    # ------------------------------------------------------------------ #

    def _build_nodes(self) -> dict[str, Any]:
        """Construct the existing research nodes with FixtureSearchToolNode."""
        from nodechain.cli.run import _create_nodes

        # Extract search terms from the corpus query keys so the model adapter
        # produces queries that match the sealed corpus.
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
        # Replace the production SearchToolNode with the fixture specialization.
        nodes["search_tool"] = FixtureSearchToolNode()
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
        blueprint = _research_blueprint(self.chain_id, self.brief.question)

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

        # Wire the guarded fixture adapter. For resume, bind to the persisted
        # run_id (for capsule lookup). For initial run, use the orchestrator's
        # newly allocated run_id.
        run_id = persisted_run_id or orchestrator.state.run_id
        fixture_map = corpus_to_fixture_map(self.corpus)
        self._fixture_adapter = FixtureSearchAdapter(fixture_map)

        # Lane-admission: fail_before_dispatch. When this fault is active,
        # a lane-admission wrapper rejects dispatch BEFORE the guard's search()
        # is invoked. This is a product-level admission decision, NOT a
        # capsule-integrity failure. The guard is never called, so:
        #   guard.dispatch_count == 0
        #   adapter.invocation_count == 0
        #   no capsule-integrity violation
        fail_before_dispatch_active = bool(
            self.corpus.fault_injection.fail_before_dispatch_lanes
        )

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

        guard = OrdinaryDispatchGuard(
            target_adapter=self._fixture_adapter,
            run_id=run_id,
            capsule_validator=capsule_validator,
            skip_trust_check=False,  # MUST be False
        )

        # Lane-admission wrapper for fail_before_dispatch: wraps the guard so
        # search() is rejected BEFORE the guard processes it. The guard's
        # dispatch count stays 0 and the adapter is never invoked. This is a
        # product-level admission decision, not a capsule-integrity failure.
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
                    )
                )
            guard.search = fail_before_search

        self._guard = guard
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
                corpus_path=str(self._corpus_path),
                corpus_digest=self.corpus_digest,
                corpus_version=self.corpus.corpus_version,
                scenario_id=self.corpus.scenario_id,
                db_path=self._db_path,
                trace_dir=self._trace_dir,
                workspace_dir=self._workspace_dir,
                kek_path=self._kek_path,
            )
            save_descriptor(self._workspace_dir, desc)
            self._run_descriptor = desc

            trace = asyncio.run(orch.run(self.brief.question))

        return RunResult(
            run_id=orch.state.run_id,
            chain_id=self.chain_id,
            trace=trace,
            state=orch.state,
            runner=self,
        )

    def compose_for_resume(self, persisted_run_id: str) -> Orchestrator:
        """Construct the orchestrator for a resume, bound to the persisted
        run_id. The guard, capsule validator, and resume call all use this ID.

        This does NOT manually assign orchestrator.state — the existing
        orchestrator.resume(persisted_run_id) seam loads state from the DB.
        """
        return self._compose(persisted_run_id=persisted_run_id)

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
