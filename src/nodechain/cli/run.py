"""Chain run command — execute the Research & Decision Assistant."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from nodechain.adapters.lim_model_adapter import LIMModelAdapter
from nodechain.core.blueprint import load_blueprint
from nodechain.core.trace import EventType

import os
from nodechain.nodes.goal_interpreter import GoalInterpreterNode
from nodechain.nodes.task_planner import TaskPlannerNode
from nodechain.nodes.context_selector import ContextSelectorNode
from nodechain.nodes.search_tool import SearchToolNode
from nodechain.nodes.source_ingestion import SourceIngestionNode
from nodechain.nodes.source_quality import SourceQualityEvaluatorNode
from nodechain.nodes.evidence_synthesizer import EvidenceSynthesizerNode
from nodechain.nodes.claim_validator import ClaimValidatorNode
from nodechain.nodes.risk_classifier import RiskClassifierNode
from nodechain.nodes.response_generator import ResponseGeneratorNode
from nodechain.nodes.memory_write import MemoryWriteDecisionNode
from nodechain.nodes.trace_collector import TraceCollectorNode
from nodechain.nodes.reuse_proof_nodes import (
    FactCheckEntryNode, FactCheckRiskAdapterNode,
    IncidentEntryNode, IncidentRiskAdapterNode,
    AuditEntryNode, AuditRiskAdapterNode,
    TraceInputAdapterNode,
)
# v2.71.0: Code Review Assistant nodes
from nodechain.nodes.code_review_request import CodeReviewRequestNode
from nodechain.nodes.file_reader import FileReaderNode
from nodechain.nodes.code_analyzer import CodeAnalyzerNode
from nodechain.nodes.finding_classifier import FindingClassifierNode
from nodechain.nodes.review_report_generator import ReviewReportGeneratorNode
# v2.72.0: Code Review patch proposal nodes
from nodechain.nodes.patch_generator import PatchGeneratorNode
from nodechain.nodes.patch_validator import PatchValidatorNode
from nodechain.nodes.patch_risk_classifier import PatchRiskClassifierNode
from nodechain.nodes.patch_report_assembler import PatchReportAssemblerNode
# v2.73.0: Code Review sandbox test execution nodes
from nodechain.nodes.sandbox_test_runner import SandboxTestRunnerNode
from nodechain.nodes.test_result_classifier import TestResultClassifierNode
from nodechain.memory.manager import MemoryManager
from nodechain.adapters.chroma_adapter import ChromaAdapter
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.core.policy import PolicyEngine
from nodechain.core.default_policies import DEFAULT_POLICIES
from nodechain.cli.exit_codes import EXIT_OK, EXIT_RUN_VALIDATION, EXIT_RUN_PAUSED, EXIT_RUN_FAILED

console = Console()


def _load_shared_node(name: str):
    """Load a shared reusable node from nodes/ directory (v2.62.0)."""
    import importlib
    import sys
    from pathlib import Path

    nodes_dir = Path(__file__).parent.parent.parent.parent / "nodes"
    if str(nodes_dir.parent) not in sys.path:
        sys.path.insert(0, str(nodes_dir.parent))

    try:
        mod = importlib.import_module(f"nodes.{name}.implementation")
        # Get the node class (convention: SharedXxxNode)
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if isinstance(obj, type) and attr_name.endswith("Node") and "Shared" in attr_name:
                return obj()
    except Exception:
        pass
    return None


def _create_nodes(model_adapter: LIMModelAdapter, trace_dir: str, memory_manager: MemoryManager | None = None, policy_engine: PolicyEngine | None = None, state_manager: Any = None, include_shared_nodes: bool = True) -> dict[str, Any]:
    """Create all 12 harness nodes.

    v2.67.3: ``include_shared_nodes`` (default True) gates whether the two
    shared reusable nodes are wired directly into the built-in map. When
    False, they are intentionally absent so that ``run_chain()``'s
    registry-resolved path must resolve them through NodeLoader instead.
    """
    # v2.28.0: wire the durable memory decision logger if a state_manager is available.
    record_md = state_manager.record_memory_decision if state_manager else None
    nodes: dict[str, Any] = {
        "goal_interpreter": GoalInterpreterNode(model_adapter),
        "task_planner": TaskPlannerNode(model_adapter),
        "context_selector": ContextSelectorNode(),
        "search_tool": SearchToolNode(allow_unguarded=True),
        "source_ingestion": SourceIngestionNode(),
        "source_quality_evaluator": SourceQualityEvaluatorNode(model_adapter),
        "evidence_synthesizer": EvidenceSynthesizerNode(model_adapter),
        "claim_validator": ClaimValidatorNode(model_adapter),
        "risk_classifier": RiskClassifierNode(model_adapter),
        "response_generator": ResponseGeneratorNode(model_adapter),
        "memory_write_decision": MemoryWriteDecisionNode(memory_manager=memory_manager, policy_engine=policy_engine, record_memory_decision=record_md),
        "trace_collector": TraceCollectorNode(trace_output_dir=trace_dir),
        # v2.62.0: Domain adapter nodes for reuse proof blueprints
        "fact_checker": FactCheckEntryNode(),
        "risk_context_adapter": FactCheckRiskAdapterNode(),
        "incident_triager": IncidentEntryNode(),
        "incident_risk_adapter": IncidentRiskAdapterNode(),
        "audit_scanner": AuditEntryNode(),
        "audit_risk_adapter": AuditRiskAdapterNode(),
        "trace_input_adapter": TraceInputAdapterNode(),
        # v2.71.0: Code Review Assistant nodes
        "code_review_request": CodeReviewRequestNode(model_adapter),
        "file_reader": FileReaderNode(repo_root=".", allowed_paths=["src/nodechain/**/*.py"]),
        "code_analyzer": CodeAnalyzerNode(model_adapter),
        "finding_classifier": FindingClassifierNode(model_adapter),
        "review_report_generator": ReviewReportGeneratorNode(model_adapter),
        # v2.72.0: Code Review patch proposal nodes
        "patch_generator": PatchGeneratorNode(model_adapter),
        "patch_validator": PatchValidatorNode(repo_root=".", allowed_paths=["src/nodechain/**/*.py"]),
        "patch_risk_classifier": PatchRiskClassifierNode(model_adapter),
        "patch_report_assembler": PatchReportAssemblerNode(model_adapter),
        # v2.73.0: Code Review sandbox test execution nodes
        "sandbox_test_runner": SandboxTestRunnerNode(
            repo_root=".", base_revision="HEAD", timeout_seconds=120,
        ),
        "test_result_classifier": TestResultClassifierNode(model_adapter),
    }
    # v2.62.0/v2.67.3: Shared reusable nodes for cross-chain proof.
    # Gated so registry-resolved mode can prove they come from NodeLoader.
    if include_shared_nodes:
        nodes["shared_risk_classifier"] = _load_shared_node("shared_risk_classifier")
        nodes["shared_trace_collector"] = _load_shared_node("shared_trace_collector")
    return nodes


def resolve_production_model_adapter(model_name: str | None = None):
    """Resolve the production model adapter from the environment.

    This is the single production model-provider resolution authority,
    factored from ``run_chain`` (H1.3) so the Research Workspace live
    profile reuses the same semantics instead of inventing a second
    provider abstraction. Returns ``(model_adapter, provider, model_name)``
    where ``provider``/``model_name`` are the resolved NON-SECRET identity
    suitable for persistence; credentials stay environment authority.

    Provider selection (unchanged from the ordinary run path):

    - ``NODECHAIN_PROVIDER=lim`` (default) → local LIM server;
    - ``NODECHAIN_PROVIDER=mock`` → deterministic MockModelAdapter;
    - anything else → OpenAI-compatible provider (LM Studio, Ollama,
      vLLM, cloud APIs) resolved from OPENAI_BASE_URL/NODECHAIN_BASE_URL.
    """
    provider = os.environ.get("NODECHAIN_PROVIDER", "lim").lower()
    model_name = model_name or os.environ.get("NODECHAIN_MODEL", "auto")
    lim_url = os.environ.get("LIM_BASE_URL", "http://localhost:8766")
    if provider == "lim":
        model_adapter = LIMModelAdapter(lim_url=lim_url, model=model_name)
    elif provider == "mock":
        from nodechain.adapters.mock_model_adapter import MockModelAdapter
        model_adapter = MockModelAdapter()
    else:
        from nodechain.adapters.model_adapter import ModelAdapter
        base_url = (
            os.environ.get("OPENAI_BASE_URL", "")
            or os.environ.get("NODECHAIN_BASE_URL", "")
            or lim_url
        )
        api_key = os.environ.get("OPENAI_API_KEY", "unused")
        model_adapter = ModelAdapter(
            provider="openai_compatible",
            model=model_name,
            api_key=api_key,
            base_url=base_url,
        )
    return model_adapter, provider, model_name


async def run_chain(
    query: str,
    blueprint_path: str,
    trace_dir: str,
    model_name: str,
    json_output: str | None = None,
    runner_config=None,
    registry_resolved: bool = False,
    enforce_lockfile: bool = False,
    lockfile_path: str | None = None,
) -> int:
    """Execute the full Research & Decision Assistant chain.

    Returns exit code: 0=completed, 10=validation, 11=paused, 12=failed.
    """
    console.print(Panel(
        f"[bold blue]NodeChain Research & Decision Assistant[/bold blue]\n\n{query}",
        title="Starting Chain",
    ))

    # Load blueprint
    try:
        blueprint = load_blueprint(blueprint_path)
        console.print(f"[green][ok][/green] Loaded blueprint: {blueprint.name} v{blueprint.version}")
    except Exception as e:
        console.print(f"[red]X[/red] Failed to load blueprint: {e}")
        sys.exit(EXIT_RUN_VALIDATION)

    # Create model adapter - supports local and cloud
    # (H1.3: resolution lives in resolve_production_model_adapter, the
    # shared authority also used by the Research Workspace live profile.)
    try:
        model_adapter, provider, model_name = resolve_production_model_adapter(model_name)
        if provider == "lim":
            loaded = model_adapter.get_loaded_models()
            console.print(f"[green]ok[/green] LIM adapter ready: {len(loaded)} models loaded")
        else:
            console.print(f"[green]ok[/green] {provider} adapter ready")
    except Exception as e:
        console.print(f"[red]X[/red] Failed to initialize model: {e}")
        return EXIT_RUN_VALIDATION

    # Create memory manager (optional — ChromaDB must be running)
    memory_manager = None
    chroma_host = os.environ.get("CHROMA_HOST", "localhost")
    chroma_port = os.environ.get("CHROMA_PORT", "8000")
    try:
        chroma = ChromaAdapter(base_url=f"http://{chroma_host}:{chroma_port}")
        memory_manager = MemoryManager(chroma=chroma)
        console.print(f"[green][ok][/green] Memory manager connected (ChromaDB at {chroma_host}:{chroma_port})")
    except Exception:
        console.print(f"[yellow]![/yellow] ChromaDB not available at {chroma_host}:{chroma_port} — memory writes will be recorded but not persisted")

    # Create nodes
    # v2.27.0: build a PolicyEngine with DEFAULT_POLICIES (incl. MEMORY_WRITE_POLICY)
    # and inject into the memory_write node so memory writes are governed by the
    # declarative policy, not hardcoded in-node thresholds.
    policy_engine = PolicyEngine()
    for policy in DEFAULT_POLICIES:
        policy_engine.register(policy)
    # v2.28.0: create a StateManager for the durable memory decision log.
    # v3.5.1 (#8) B3: the composition root resolves the KEK operating mode
    # via the dedicated helper and injects the manager. StateManager and the
    # retry coordinator never read the environment; KEK loading is lazy.
    from nodechain.core.state import StateManager as _StateManager
    from nodechain.core.capsule_crypto import resolve_kek_manager_from_environment
    sm = _StateManager(kek_manager=resolve_kek_manager_from_environment())
    # v2.67.3: in registry-resolved mode, exclude shared nodes from built-ins
    # so they MUST be resolved through NodeLoader (with provenance).
    nodes = _create_nodes(
        model_adapter, trace_dir,
        memory_manager=memory_manager, policy_engine=policy_engine, state_manager=sm,
        include_shared_nodes=not registry_resolved,
    )

    # Augment with registry-loaded nodes for any blueprint nodes not in built-in set.
    # v2.67.3: pass the shared StateManager so admission/provenance events tie to
    # the same run database; track resolved_ids for lockfile enforcement.
    blueprint_node_ids = [n.node_id for n in blueprint.nodes]
    missing_node_ids = [nid for nid in blueprint_node_ids if nid not in nodes]
    resolved_ids: list[str] = []
    if missing_node_ids:
        from nodechain.sdk.loader import NodeLoader, NodeLoadError
        loader = NodeLoader(state_manager=sm)
        for nid in missing_node_ids:
            try:
                nodes[nid] = loader.load(nid)
                resolved_ids.append(nid)
                console.print(f"  [green]+[/green] Loaded '{nid}' from local registry")
            except NodeLoadError:
                pass  # Will be caught by contract validation

    # v2.67.3: fail-closed lockfile enforcement for registry-resolved nodes.
    # Only nodes actually resolved by NodeLoader are enforced; unresolved
    # blueprint nodes remain a contract-validation concern.
    if enforce_lockfile and resolved_ids:
        from nodechain.sdk.lockfile import enforce_lockfile_for_nodes
        ok, errors = enforce_lockfile_for_nodes(
            resolved_ids,
            lockfile_path=lockfile_path,
            registry=loader.registry if missing_node_ids else None,
        )
        if not ok:
            console.print(f"[red]X[/red] Lockfile enforcement failed for registry-resolved nodes:")
            for err in errors:
                console.print(f"  [red]- {err}[/red]")
            return EXIT_RUN_VALIDATION
        console.print(f"[green][ok][/green] Lockfile verified for {len(resolved_ids)} registry-resolved node(s)")

    console.print(f"[green][ok][/green] {len(nodes)} nodes registered")

    # Create orchestrator
    orchestrator = Orchestrator(
        blueprint=blueprint,
        nodes=nodes,
        runner_config=runner_config,
        # code-review fix: pass the shared state_manager + policy_engine
        # so the orchestrator and the memory node use the same instances.
        state_manager=sm,
        policy_engine=policy_engine,
    )

    # v3.5.0: inject OrdinaryDispatchGuard-wrapped adapters into SearchToolNode
    # so production dispatch is capsule-before-wire enforced. The run_id is
    # available from the orchestrator's state (set at Orchestrator init).
    from nodechain.runtime.recovery_dispatch_guard import build_ordinary_guarded_registry
    search_node = nodes.get("search_tool")
    if search_node is not None and hasattr(search_node, "set_adapter_resolver"):
        run_id = orchestrator.state.run_id
        # Build a capsule validator that checks the side-effect ledger for
        # matching started rows with capsule_status=available.
        def capsule_validator(check_run_id: str, adapter_name: str,
                              canonical_digest: str) -> bool:
            """Check if a capsule exists for this adapter + digest combination.

            The side-effect ledger is keyed by (run_id, idempotency_key) where
            idempotency_key = f'{adapter_name}:{request_hash}'. For the ordinary
            guard, we need to match by the full canonical digest. Since the
            capsule stores the full digest, we search by capsule_digest.
            """
            try:
                with __import__("sqlite3").connect(str(sm.db_path)) as conn:
                    row = conn.execute(
                        """SELECT COUNT(*) FROM side_effect_replay_capsules
                           WHERE run_id = ? AND capsule_digest = ?
                           AND side_effect_key LIKE ? || '%%'""",
                        (check_run_id, canonical_digest, adapter_name),
                    ).fetchone()
                    return row[0] > 0
            except Exception:
                return False

        # Get all adapter names that this run might use
        adapter_names = list({
            a for sq_list in [
                [sq.get("target_adapters", []) for sq in node_search_queries]
                for node_search_queries in [getattr(search_node, "_search_queries", [])]
            ]
            for a in (sq_list if isinstance(sq_list, list) else [])
        })
        # Fall back to all attested adapters if no specific list
        if not adapter_names:
            from nodechain.runtime.recovery_dispatch_guard import ADAPTER_RETRY_ALLOWLIST
            adapter_names = list(ADAPTER_RETRY_ALLOWLIST.keys())

        guarded_registry = build_ordinary_guarded_registry(
            run_id=run_id,
            adapter_names=adapter_names,
            capsule_validator=capsule_validator,
        )
        search_node.set_adapter_resolver(guarded_registry)

    # Validate contracts
    issues = orchestrator.validate_contracts()
    if issues:
        console.print(f"[red]X[/red] Contract validation failed:")
        for issue in issues:
            console.print(f"  [red]- {issue}[/red]")
        return EXIT_RUN_VALIDATION
    console.print(f"[green][ok][/green] All contracts validated")

    # Run chain
    console.print("\n[bold]Executing chain...[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running chain...", total=None)

        # Track node progress via events
        trace = await orchestrator.run(query)

        progress.update(task, description="Chain complete!")

    # Display results
    _display_results(trace, orchestrator, json_output, trace_dir)

    # Return exit code based on final status
    if trace.final_status == "completed":
        return EXIT_OK
    elif trace.final_status in ("paused", "waiting_for_review"):
        return EXIT_RUN_PAUSED
    else:
        return EXIT_RUN_FAILED


def _display_results(trace: Any, orchestrator: Orchestrator, json_output: str | None = None, trace_dir: str = "data/traces") -> None:
    """Display chain results in readable format."""
    # Find the response generator output
    response_output = orchestrator.state.outputs.get("response_generator", {})

    if response_output:
        console.print(Panel(
            response_output.get("recommendation", "No recommendation generated"),
            title="[bold green]Recommendation[/bold green]",
        ))

        # Executive summary
        summary = response_output.get("executive_summary", "")
        if summary:
            console.print(f"\n[bold]Summary:[/bold] {summary}")

        # Key findings
        findings = response_output.get("key_findings", [])
        if findings:
            console.print("\n[bold]Key Findings:[/bold]")
            for f in findings:
                console.print(f"  • {f}")

        # Confidence
        conf = response_output.get("confidence_statement", {})
        if conf:
            level = conf.get("level", "UNKNOWN")
            numeric = conf.get("numeric", 0)
            color = "green" if level == "HIGH" else "yellow" if level == "MEDIUM" else "red"
            console.print(f"\n[bold]Confidence:[/bold] [{color}]{level}[/{color}] ({numeric:.0%})")
            explanation = conf.get("explanation", "")
            if explanation:
                console.print(f"  {explanation}")

        # Citations
        citations = response_output.get("citations", [])
        if citations:
            console.print(f"\n[bold]Citations ({len(citations)}):[/bold]")
            for c in citations[:10]:
                console.print(f"   {c.get('citation_text', 'Unknown')}")
                if c.get("claim_supported"):
                    console.print(f"     → {c['claim_supported'][:80]}...")

        # Uncertainties
        uncertainties = response_output.get("uncertainty_disclosures", [])
        if uncertainties:
            console.print(f"\n[bold yellow]Uncertainties:[/bold yellow]")
            for u in uncertainties:
                console.print(f"  ! {u}")

    # Trace summary
    console.print(f"\n[bold]Trace:[/bold]")
    console.print(f"  Run ID: {trace.run_id}")
    console.print(f"  Status: {trace.final_status}")
    console.print(f"  Events: {len(trace.events)}")
    console.print(f"  Cost: ${trace.total_cost_usd:.4f}")
    console.print(f"  Duration: {trace.total_duration_ms}ms")

    # Save trace
    trace_path = Path(trace_dir) / f"{trace.run_id}.json"
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    with open(trace_path, "w") as f:
        f.write(trace.to_json())
    console.print(f"\n  Trace saved: {trace_path}")

    # JSON output for scripting
    if json_output:
        import json as _json
        Path(json_output).parent.mkdir(parents=True, exist_ok=True)
        with open(json_output, "w") as f:
            _json.dump({
                "run_id": trace.run_id,
                "status": trace.final_status,
                "events": len(trace.events),
                "cost_usd": trace.total_cost_usd,
                "duration_ms": trace.total_duration_ms,
                "trace_path": str(trace_path),
                "db_path": "data/chain_state.db",
            }, f, indent=2)
        console.print(f"  JSON output: {json_output}")
