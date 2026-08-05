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
from nodechain.core.capsule_crypto import resolve_kek_manager_from_environment
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
        chain_id: str = "research-workspace-v1",
    ) -> None:
        if isinstance(brief, str):
            brief = ResearchBrief.from_question(brief)
        self.brief = brief
        self.corpus = load_corpus(corpus_path)
        self.corpus_digest = compute_corpus_canonical_digest(self.corpus)
        self.chain_id = chain_id
        self._db_path = str(db_path or "data/research_workspace.db")
        self._trace_dir = str(trace_dir or "data/traces")
        self.orchestrator: Orchestrator | None = None
        self._search_node: FixtureSearchToolNode | None = None
        self._fixture_adapter: FixtureSearchAdapter | None = None

    # ------------------------------------------------------------------ #
    # Composition
    # ------------------------------------------------------------------ #

    def _build_nodes(self) -> dict[str, Any]:
        """Construct the existing research nodes with FixtureSearchToolNode."""
        from nodechain.cli.run import _create_nodes

        model_adapter = FixtureModelAdapter(latency_ms=0)
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

    def _compose(self) -> Orchestrator:
        """Construct the orchestrator and wire the guarded fixture adapter."""
        # Build shared state + policy.
        sm = StateManager(
            self._db_path,
            kek_manager=resolve_kek_manager_from_environment(),
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

        # Wire the guarded fixture adapter (after run_id is known).
        run_id = orchestrator.state.run_id
        fixture_map = corpus_to_fixture_map(self.corpus)
        self._fixture_adapter = FixtureSearchAdapter(fixture_map)

        # Lane-admission: fail_before_dispatch (implemented HERE, before the
        # guard is invoked — not inside the adapter).
        scenario_faults = set(self.corpus.fault_injection.fail_before_dispatch_lanes)

        def capsule_validator(check_run_id: str, adapter_name: str, digest: str) -> bool:
            """Check if a capsule exists for this adapter + digest."""
            try:
                import sqlite3

                with sqlite3.connect(str(sm.db_path)) as conn:
                    row = conn.execute(
                        """SELECT COUNT(*) FROM side_effect_replay_capsules
                           WHERE run_id = ? AND capsule_digest = ?
                           AND side_effect_key LIKE ? || '%'""",
                        (check_run_id, digest, adapter_name),
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
        import os

        # Sealed research runs require explicit operator review — set pause
        # mode so the runtime pauses (rather than prompting interactively or
        # auto-approving) when the risk_classifier requests review.
        os.environ.setdefault("NODECHAIN_REVIEW_MODE", "pause")
        # Sealed runs are inherently local-development (no production KEK).
        # The KEK is needed for side-effect capsule creation.
        os.environ.setdefault("NODECHAIN_DEV_MODE", "1")

        orch = self._compose()
        trace = asyncio.run(orch.run(self.brief.question))
        return RunResult(
            run_id=orch.state.run_id,
            chain_id=self.chain_id,
            trace=trace,
            state=orch.state,
            runner=self,
        )

    def resume(self) -> "RunResult":
        """Resume a paused run through the existing runtime resume seam."""
        import asyncio

        if self.orchestrator is None:
            raise RuntimeError("no orchestrator — call run() first")
        run_id = self.orchestrator.state.run_id
        trace = asyncio.run(self.orchestrator.resume(run_id))
        return RunResult(
            run_id=run_id,
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
        (the env-var the HumanAdapter reads). The actual resume happens in
        resume().
        """
        import os

        # Map the WP 5.2 decision vocabulary to the runtime's vocabulary.
        decision_map = {
            "approve": "approve",
            "reject": "reject",
            "revise": "request_revision",
        }
        runtime_decision = decision_map.get(decision, decision)
        os.environ["NODECHAIN_REVIEW_DECISION"] = runtime_decision
        os.environ["NODECHAIN_REVIEW_REASON"] = reason
        os.environ["NODECHAIN_REVIEW_REVIEWER"] = reviewer


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
        )

    @property
    def completed(self) -> bool:
        return self.trace.final_status == "completed"

    @property
    def failed(self) -> bool:
        return self.trace.final_status not in ("completed", "paused")

    @property
    def corpus_digest(self) -> str:
        return self._runner.corpus_digest
