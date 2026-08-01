"""Direct tests for TraceReconciler — trace ↔ ledger verification.

Covers:
- Clean trace matches ledger
- Node/step mismatch detection
- Ledger coverage (ledger entries without trace events)
- Side-effect count mismatch
- Terminal status check
- Empty trace (minimal case)
- Real chain reconciliation
"""

import pytest
import pathlib

from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler, ReconciliationReport


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "reconcile.db")


@pytest.fixture
def state_manager(db_path):
    return StateManager(db_path)


@pytest.fixture
def reconciler(state_manager):
    return TraceReconciler(state_manager)


def _make_trace(run_id: str, events: list[TraceEvent] | None = None) -> ChainTrace:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


class TestCleanReconciliation:
    def test_clean_trace_passes(self, reconciler, state_manager):
        """When trace and ledger agree, report should be clean."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        # Record an invocation
        state_manager.save_with_invocation(
            state=state,
            step_id=1,
            node_id="goal_interpreter",
            event_type="node_completed",
            event_payload={"node_id": "goal_interpreter", "step_id": 1},
        )

        # Create matching trace
        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="goal_interpreter", step_id=1,
                event_type=EventType.NODE_SUCCEEDED,
                actor=Actor.RUNTIME,
            ),
        ])

        report = reconciler.reconcile(trace)
        assert report.is_clean, f"Issues: {report.issues}"
        assert report.checks_passed > 0

    def test_empty_trace_no_ledger(self, reconciler, state_manager):
        """Empty trace with no ledger entries should be clean."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)
        trace = _make_trace(state.run_id)

        report = reconciler.reconcile(trace)
        assert report.is_clean


class TestMismatchDetection:
    def test_node_step_mismatch(self, reconciler, state_manager):
        """Trace says step 1 = goal_interpreter but ledger says step 1 = task_planner."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.save_with_invocation(
            state=state, step_id=1, node_id="task_planner",
            event_type="node_completed",
            event_payload={"node_id": "task_planner"},
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="goal_interpreter", step_id=1,
                event_type=EventType.NODE_SUCCEEDED,
                actor=Actor.RUNTIME,
            ),
        ])

        report = reconciler.reconcile(trace)
        assert not report.is_clean
        assert any(i.check == "node_succeeded_ledger_match" for i in report.errors)

    def test_ledger_entry_without_trace(self, reconciler, state_manager):
        """Ledger has an invocation but no matching NODE_SUCCEEDED trace event.

        Since save_with_invocation writes to state_events, the reconciler
        classifies this as: covered only by internal state_events (warning).
        """
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.save_with_invocation(
            state=state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed",
            event_payload={"node_id": "goal_interpreter"},
        )

        # Empty trace — no NODE_SUCCEEDED events
        trace = _make_trace(state.run_id)

        report = reconciler.reconcile(trace)
        # Should have a warning about internal-only coverage
        warnings = [i for i in report.issues if i.check == "ledger_trace_coverage"]
        assert len(warnings) == 1
        assert warnings[0].severity == "warning"
        assert "internal state_events" in warnings[0].actual

    def test_side_effect_count_mismatch(self, reconciler, state_manager):
        """More completed side effects in ledger than trace events."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        # Record a side effect
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="api_call", idempotency_key="ss:abc",
            status="completed", request_hash="h1", response_hash="r1",
        )

        # Trace has no SIDE_EFFECT_COMPLETED events
        trace = _make_trace(state.run_id)

        report = reconciler.reconcile(trace)
        assert any(i.check == "side_effect_count_match" for i in report.issues)


class TestTerminalStatus:
    def test_completed_chain_has_terminal_event(self, reconciler, state_manager):
        """Completed chain should have terminal status."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="runtime", step_id=0,
                event_type=EventType.CHAIN_COMPLETED,
                actor=Actor.RUNTIME,
            ),
        ])
        trace.finalize("completed")

        report = reconciler.reconcile(trace)
        assert report.is_clean


class TestReconciliationReport:
    def test_summary_format(self):
        report = ReconciliationReport(
            run_id="test-123",
            checks_passed=5,
            issues=[],
        )
        assert "5 checks passed" in report.summary()
        assert "All checks passed" in report.summary()

    def test_summary_with_issues(self):
        from nodechain.runtime.trace_reconciler import ReconciliationIssue
        report = ReconciliationReport(
            run_id="test-123",
            checks_passed=3,
            issues=[
                ReconciliationIssue(
                    check="test_check",
                    severity="error",
                    expected="foo",
                    actual="bar",
                ),
            ],
        )
        assert "1 errors" in report.summary()
        assert not report.is_clean

    def test_errors_and_warnings_separation(self):
        from nodechain.runtime.trace_reconciler import ReconciliationIssue
        report = ReconciliationReport(
            run_id="test",
            issues=[
                ReconciliationIssue(check="a", severity="error", expected="x", actual="y"),
                ReconciliationIssue(check="b", severity="warning", expected="x", actual="y"),
                ReconciliationIssue(check="c", severity="error", expected="x", actual="y"),
            ],
        )
        assert len(report.errors) == 2
        assert len(report.warnings) == 1


class TestRealChainReconciliation:
    @pytest.mark.asyncio
    async def test_reconcile_completed_chain(self, tmp_path):
        """Run a real chain and reconcile the trace against ledgers."""
        import sys
        sys.path.insert(0, "tests")
        from test_runtime import MockNode
        from nodechain.core.blueprint import load_blueprint
        from nodechain.runtime.orchestrator import Orchestrator

        db = str(tmp_path / "reconcile_real.db")
        sm = StateManager(db_path=db)

        transforms = {
            "goal_interpreter": lambda p: {"primary_question": "q", "research_domain": "general", "success_criteria": ["t"], "domain_classification": []},
            "task_planner": lambda p: {"plan_id": "p", "tasks": [{"task_id": "t1", "description": "t", "query_terms": ["t"], "priority": 1}], "source_routing": {"primary": ["semantic_scholar"], "secondary": []}},
            "context_selector": lambda p: {"plan_ref": "p", "search_queries": [{"query_id": "q1", "terms": ["t"], "target_adapters": ["semantic_scholar"]}], "adapter_grants": ["semantic_scholar"]},
            "search_tool": lambda p: {"results": [{"origin_api": "semantic_scholar", "raw_data": {"title": "T"}, "query_used": "t", "retrieved_at": "2026"}], "total_found": 1, "adapters_called": ["semantic_scholar"], "adapters_failed": []},
            "source_ingestion": lambda p: {"sources": [{"source_id": "s1", "origin_api": "semantic_scholar", "title": "T", "quality_score": 0.8}], "total_found": 1},
            "source_quality_evaluator": lambda p: {"sources": [], "total_evaluated": 0, "passing": 0, "quality_summary": {"total": 5, "passing": 5}},
            "evidence_synthesizer": lambda p: {"claims": [{"claim_id": "c1", "text": "TC", "support_level": "strong", "source_refs": ["s1"]}], "confidence": 0.85, "evidence_base_id": "eb1"},
            "claim_validator": lambda p: {"validated_claims": [{"claim_id": "c1", "valid": True, "source_refs": ["s1"]}], "validation_rate": 1.0},
            "risk_classifier": lambda p: {"risk_level": "LOW", "confidence": 0.9, "review_required": False, "risk_factors": [], "uncertainty_disclosures": []},
            "response_generator": lambda p: {"recommendation": "R", "executive_summary": "S", "key_findings": ["F"], "confidence_statement": {"level": "HIGH", "numeric": 0.9}, "citations": []},
            "memory_write_decision": lambda p: {"candidates": [], "write_decision": "no_write"},
            "trace_collector": lambda p: {"trace_id": "t", "events_summary": []},
        }

        from nodechain.core.contract import SideEffect, Requirements as _Req
        _se = {"search_tool": [SideEffect(effect_type="external_call", target="search_apis")]}
        _tr = {"search_tool": _Req(tools_required=["search"], adapters_required=["semantic_scholar"])}
        # v2.44.2: model-backed nodes need model_required for trust gate
        _mr = {"goal_interpreter", "task_planner", "context_selector",
               "source_quality_evaluator", "evidence_synthesizer",
               "claim_validator", "risk_classifier", "response_generator"}
        nodes = {}
        for nid in transforms:
            req = _Req(
                tools_required=(_tr[nid].tools_required if nid in _tr else []),
                adapters_required=(_tr[nid].adapters_required if nid in _tr else []),
                model_required=(nid in _mr),
            )
            nodes[nid] = MockNode(nid, "any", "any", transforms[nid],
                                  side_effects=_se.get(nid, []),
                                  tools_required=req.tools_required,
                                  adapters_required=req.adapters_required,
                                  model_required=req.model_required)
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = await orch.run("test reconciliation")

        assert trace.final_status == "completed"

        # Reconcile
        reconciler = TraceReconciler(sm)
        report = reconciler.reconcile(trace)

        # The trace should reconcile cleanly
        assert report.is_clean, f"Reconciliation issues:\n{report.summary()}"
        assert report.checks_passed >= 12  # At least one per node


class TestReconcilerEscalation:
    """Regression tests for reconciler hard-error escalation.

    AC1: Corrupted trace/ledger/state step mapping produces an error.
    AC2: Reconciler is_clean becomes false on durable-surface contradiction.
    AC3: Two-branch run with StepAllocator remains clean after reconciliation.
    AC4: Simulated old race (same step_id, different node_id) fails reconciliation.
    AC5: Existing 424 tests remain green.
    """

    def test_ac1_state_ledger_step_mismatch_is_error(self, reconciler, state_manager):
        """AC1: State says step 3 = search_a, ledger says step 3 = search_b."""
        state = ChainState(chain_id="test-chain")
        # Simulate old race: materialized state has one mapping
        state.completed_steps = {3: "biomedical_search"}
        state_manager.save(state)

        # Ledger has a different mapping for the same step
        state_manager.save_with_invocation(
            state=state, step_id=3, node_id="technical_search",
            event_type="node_completed",
            event_payload={"node_id": "technical_search"},
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="biomedical_search", step_id=3,
                event_type=EventType.NODE_SUCCEEDED,
                actor=Actor.RUNTIME,
            ),
        ])

        report = reconciler.reconcile(trace)
        errors = [i for i in report.issues if i.check == "state_ledger_step_mapping"]
        assert len(errors) >= 1, f"Expected state_ledger_step_mapping error, got: {report.issues}"
        assert errors[0].severity == "error"

    def test_ac2_is_clean_false_on_state_ledger_mismatch(self, reconciler, state_manager):
        """AC2: is_clean returns false when surfaces disagree."""
        state = ChainState(chain_id="test-chain")
        state.completed_steps = {1: "goal_interpreter"}
        state_manager.save(state)

        # Ledger disagrees
        state_manager.save_with_invocation(
            state=state, step_id=1, node_id="task_planner",
            event_type="node_completed",
            event_payload={"node_id": "task_planner"},
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="goal_interpreter", step_id=1,
                event_type=EventType.NODE_SUCCEEDED,
                actor=Actor.RUNTIME,
            ),
        ])

        report = reconciler.reconcile(trace)
        assert not report.is_clean, (
            f"is_clean should be false on state/ledger mismatch. "
            f"Errors: {report.errors}"
        )

    def test_ac3_two_branch_run_clean_after_allocator(self, tmp_path):
        """AC3: Two-branch run with StepAllocator reconciles cleanly."""
        import asyncio
        import sys
        sys.path.insert(0, "tests")
        sys.path.insert(0, "src")
        from unittest.mock import patch
        from nodechain.core.port import PortType
        from nodechain.core.envelope import EnvelopeResponse
        from nodechain.nodes.goal_interpreter import GoalInterpreterNode
        from nodechain.nodes.domain_classifier import DomainClassifierNode
        from nodechain.nodes.evidence_joiner import EvidenceJoinerNode
        from nodechain.nodes.conflict_detector import ConflictDetectorNode
        from nodechain.nodes.branch_response_generator import BranchResponseGeneratorNode
        from nodechain.nodes.branch_trace_collector import BranchTraceCollectorNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.blueprint import (
            ChainBlueprint, NodeDef, ConnectionDef, BranchDef, JoinDef,
        )

        db = str(tmp_path / "reconcile_branch.db")
        sm = StateManager(db_path=db)

        # Inline MockModelAdapter
        class Model:
            def complete(self, **kw):
                from unittest.mock import MagicMock
                return MagicMock(
                    content='{"primary_question":"q","research_domain":"bio","domain_classification":[{"domain":"biomedical","confidence":0.9},{"domain":"technical","confidence":0.8}],"sub_questions":["s1"],"success_criteria":["c1"],"constraints":[],"time_sensitivity":"low","depth_required":"medium"}',
                    cost_usd=0.001, latency_ms=100, stop_reason="stop",
                    raw_output_size=100, structured_output=None,
                )
        model = Model()

        # Inline MockSearchNode
        class MockSearch:
            def __init__(self, nid, c=3):
                self._nid = nid
            @property
            def manifest(self):
                from nodechain.core.manifest import NodeManifest
                from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
                return NodeManifest(
                    node_id=self._nid, node_type="deterministic",
                    name=f"Mock ({self._nid})", description="test",
                    contract=NodeContract(
                        contract_id=f"mock.{self._nid}.v1", node_id=self._nid, version="1.0.0",
                        entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                        exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test", guaranteed_fields=["results"]),
                        requirements=Requirements(model_required=False),
                    ),
                )
            async def execute(self, envelope):
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,
                    chain_id=envelope.chain_id, node_id=self._nid,
                    step_id=envelope.step_id,
                    output={"results": [{"title": "r", "source_id": "s"}]},
                    output_type=PortType.RAW_SEARCH_RESULTS,
                )

        blueprint = ChainBlueprint(
            chain_id="test_reconcile_v1", name="Test Reconcile", version="1.0.0", goal="Test",
            nodes=[
                NodeDef(node_id="goal_interpreter", node_type="model", position=1),
                NodeDef(node_id="domain_classifier", node_type="deterministic", position=2),
                NodeDef(node_id="biomedical_search", node_type="deterministic", position=3),
                NodeDef(node_id="technical_search", node_type="deterministic", position=4),
                NodeDef(node_id="evidence_joiner", node_type="deterministic", position=5),
                NodeDef(node_id="response_generator", node_type="model", position=6),
                NodeDef(node_id="trace_collector", node_type="deterministic", position=7),
            ],
            connections=[
                ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="domain_classifier", to_port="input"),
            ],
            branches=[
                BranchDef(branch_id="b1", from_node="domain_classifier",
                          branches={"biomedical": ["biomedical_search"], "technical": ["technical_search"]},
                          default_branch="biomedical"),
            ],
            joins=[
                JoinDef(join_id="j1", to_node="evidence_joiner", from_branches=["biomedical", "technical"]),
            ],
        )

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "biomedical_search": MockSearch("biomedical_search"),
            "technical_search": MockSearch("technical_search"),
            "evidence_joiner": EvidenceJoinerNode(),
            "conflict_detector": ConflictDetectorNode(),
            "response_generator": BranchResponseGeneratorNode(model),
            "trace_collector": BranchTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        with patch.object(DomainClassifierNode, "_classify_domain",
                          return_value=["biomedical", "technical"]):
            trace = asyncio.run(orch.run("test query"))

        assert trace.final_status == "completed"

        reconciler = TraceReconciler(sm)
        report = reconciler.reconcile(trace)
        assert report.is_clean, (
            f"Two-branch run should reconcile clean after StepAllocator fix.\n"
            f"Errors: {[f'{e.check}: {e.expected} vs {e.actual}' for e in report.errors]}\n"
            f"Warnings: {len(report.warnings)}"
        )

    def test_ac4_simulated_race_fails_reconciliation(self, reconciler, state_manager):
        """AC4: Without captured step identity, old race would fail reconciliation.

        Simulates the pre-fix scenario: two branches both produce step 3
        but mapped to different nodes.
        """
        state = ChainState(chain_id="test-chain")
        # Old race: last writer wins in materialized state
        state.completed_steps = {
            1: "goal_interpreter",
            2: "domain_classifier",
            3: "biomedical_search",  # Last writer
        }
        state_manager.save(state)

        # But ledger has the FIRST writer for step 3
        state_manager.save_with_invocation(
            state=state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed",
            event_payload={"node_id": "goal_interpreter"},
        )
        state_manager.save_with_invocation(
            state=state, step_id=2, node_id="domain_classifier",
            event_type="node_completed",
            event_payload={"node_id": "domain_classifier"},
        )
        state_manager.save_with_invocation(
            state=state, step_id=3, node_id="technical_search",  # INSERT OR IGNORE kept first
            event_type="node_completed",
            event_payload={"node_id": "technical_search"},
        )

        # Trace shows both branches ran at step 3
        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="goal_interpreter", step_id=1,
                event_type=EventType.NODE_SUCCEEDED, actor=Actor.RUNTIME,
            ),
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="domain_classifier", step_id=2,
                event_type=EventType.NODE_SUCCEEDED, actor=Actor.RUNTIME,
            ),
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="biomedical_search", step_id=3,
                event_type=EventType.NODE_SUCCEEDED, actor=Actor.RUNTIME,
            ),
        ])

        report = reconciler.reconcile(trace)
        assert not report.is_clean, (
            f"Simulated old race should fail reconciliation. "
            f"Errors: {[f'{e.check}: {e.expected} vs {e.actual}' for e in report.errors]}"
        )
        # Must have state_ledger_step_mapping error
        mapping_errors = [i for i in report.errors if i.check == "state_ledger_step_mapping"]
        assert len(mapping_errors) >= 1, (
            f"Expected state_ledger_step_mapping error for simulated race. "
            f"All errors: {[e.check for e in report.errors]}"
        )

    def test_trace_duplicate_step_id_is_error(self, reconciler, state_manager):
        """Two NODE_SUCCEEDED events with same step_id but different nodes."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="biomedical_search", step_id=3,
                event_type=EventType.NODE_SUCCEEDED, actor=Actor.RUNTIME,
            ),
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="technical_search", step_id=3,
                event_type=EventType.NODE_SUCCEEDED, actor=Actor.RUNTIME,
            ),
        ])

        report = reconciler.reconcile(trace)
        dup_errors = [i for i in report.errors if i.check == "trace_step_id_uniqueness"]
        assert len(dup_errors) >= 1, (
            f"Expected trace_step_id_uniqueness error. Errors: {[e.check for e in report.errors]}"
        )
        assert not report.is_clean


class TestSideEffectTraceReconciliation:
    """AC6: Reconciler cross-checks side-effect trace events against ledger.

    AC1: SIDE_EFFECT_COMPLETED trace must match ledger idempotency_key.
    AC2: SIDE_EFFECT_STARTED trace must match ledger status.
    AC3: Ledger completed without trace → warning.
    AC4: Ledger completed without trace + strict → error.
    AC5: Unknown side effects → recovery_required warning.
    """

    @pytest.mark.asyncio
    async def test_completed_trace_matches_ledger(self, reconciler, state_manager):
        """AC1: SIDE_EFFECT_COMPLETED with matching ledger entry passes."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:abc123",
            status="completed", request_hash="req1", response_hash="resp1",
        )

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="search_tool", step_id=1,
                event_type=EventType.SIDE_EFFECT_COMPLETED,
                actor=Actor.NODE,
                metadata={"idempotency_key": "ss:abc123"},
            ),
        ])

        report = reconciler.reconcile(trace)
        # Should have no side_effect errors
        se_errors = [i for i in report.issues
                     if i.check.startswith("side_effect") and i.severity == "error"]
        assert len(se_errors) == 0, f"Unexpected errors: {se_errors}"

    @pytest.mark.asyncio
    async def test_completed_trace_without_ledger_is_error(self, reconciler, state_manager):
        """AC1: SIDE_EFFECT_COMPLETED without ledger entry is error."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="search_tool", step_id=1,
                event_type=EventType.SIDE_EFFECT_COMPLETED,
                actor=Actor.NODE,
                metadata={"idempotency_key": "ss:missing"},
            ),
        ])

        report = reconciler.reconcile(trace)
        match_errors = [i for i in report.errors
                        if i.check == "side_effect_trace_ledger_match"]
        assert len(match_errors) >= 1
        assert not report.is_clean

    @pytest.mark.asyncio
    async def test_ledger_completed_without_trace_is_warning(self, reconciler, state_manager):
        """AC3: Completed ledger entry with no trace event is warning."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:no_trace",
            status="completed", request_hash="req1", response_hash="resp1",
        )

        # No SIDE_EFFECT_COMPLETED event in trace
        trace = _make_trace(state.run_id)

        report = reconciler.reconcile(trace)
        coverage_warnings = [i for i in report.warnings
                            if i.check == "side_effect_ledger_trace_coverage"]
        assert len(coverage_warnings) >= 1

    @pytest.mark.asyncio
    async def test_unknown_side_effects_flagged(self, reconciler, state_manager):
        """AC5: Unknown side effects produce recovery_required warning."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:crash_unknown",
            status="unknown", request_hash="req1",
        )

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        recovery_warnings = [i for i in report.warnings
                             if i.check == "side_effect_recovery_required"]
        assert len(recovery_warnings) >= 1
        assert "unknown" in recovery_warnings[0].actual
