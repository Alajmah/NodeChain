"""Chain Orchestrator — the main execution loop of the NodeChain runtime."""

from __future__ import annotations

import os
import time
from typing import Any

from nodechain.core.blueprint import BranchDef, ChainBlueprint
from nodechain.core.contract import ContractRegistry
from nodechain.core.envelope import (
    Capabilities,
    Context,
    InvocationEnvelope,
    EnvelopeResponse,
    compile_envelope,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.policy import PolicyEngine, PolicyType, PolicyAction
from nodechain.core.state import ChainState, StateManager
from nodechain.core.trace import (
    Actor,
    ChainTrace,
    EventType,
    TraceEvent,
)
from nodechain.runtime.scheduler import GraphScheduler, SchedulingDecision
from nodechain.runtime.node_invoker import NodeInvoker, InvocationResult
from nodechain.runtime.policy_gate import PolicyGate, PolicyCheckResult
from nodechain.runtime.persistence import PersistenceCoordinator, RecoveryContext
from nodechain.runtime.review_manager import ReviewManager, ReviewDecision, ReviewPausedException
from nodechain.nodes.base_node import BaseNode
from nodechain.validation.schema_validator import SchemaValidator
from nodechain.validation.semantic_validators import SemanticValidationPipeline
from nodechain.runtime.validation_pipeline import ValidationPipeline, ValidationContext
from nodechain.runtime.invariant_engine import InvariantEngine
from nodechain.runtime.failure_manager import FailureManager, FailureType
from nodechain.runtime.branch_executor import BranchExecutor, BranchNodeResult
from nodechain.runtime.trace_emitter import TraceEmitter
from nodechain.runtime.step_allocator import StepAllocator, InvocationIdentity

# v3.2.0: retry-recovery success invariant. Actions whose recovered=True +
# response=None shape is an INTENTIONAL skip-continue (not an invalid recovery).
# Only the two existing skip handlers qualify; do not broaden this list.
_SKIP_CONTINUE_ACTIONS = frozenset({
    "skip_memory_write_policy_rejection",
    "trace_fallback_stderr",
})


class RecoveryCursorMismatch(Exception):
    """Raised when resume detects blueprint/execution-order drift.

    Contains enough context to diagnose and potentially migrate.
    """
    def __init__(self, run_id: str, blueprint_id: str, expected_hash: str, actual_hash: str):
        self.run_id = run_id
        self.blueprint_id = blueprint_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        super().__init__(
            f"Recovery cursor mismatch for run {run_id} "
            f"(blueprint={blueprint_id}): "
            f"expected order hash {expected_hash}, got {actual_hash}"
        )


from nodechain.runtime.node_event_emitter import NodeEventEmitterMixin
from nodechain.runtime.side_effect_journal import SideEffectJournalMixin


class Orchestrator(NodeEventEmitterMixin, SideEffectJournalMixin):
    """
    The chain orchestrator. Loads blueprint, validates contracts,
    invokes nodes in sequence, manages state, and emits trace events.
    """

    def __init__(
        self,
        blueprint: ChainBlueprint,
        nodes: dict[str, BaseNode],
        state_manager: StateManager | None = None,
        policy_engine: PolicyEngine | None = None,
        runner_config=None,
    ) -> None:
        self.blueprint = blueprint
        self._nodes = nodes
        self.state_manager = state_manager or StateManager()
        self.policy_engine = policy_engine or PolicyEngine()
        self.policy_gate = PolicyGate(
            policy_engine=self.policy_engine,
            get_capabilities=self._build_capabilities,
            get_trace_events=lambda: self.trace.events,
            get_step=lambda: self._step,
        )
        self.persistence = PersistenceCoordinator(self.state_manager)
        self.review_manager = ReviewManager(
            save_snapshot=self.persistence.save_snapshot,
            add_trace_event=lambda e: self.trace.add_event(e),
            record_attempt=self.state_manager.record_review_attempt,
        )

        # Load default policies if engine is empty
        if not self.policy_gate.has_policies():
            from nodechain.core.default_policies import DEFAULT_POLICIES
            for policy in DEFAULT_POLICIES:
                self.policy_engine.register(policy)
        self.schema_validator = SchemaValidator()
        self.validation_pipeline = ValidationPipeline()
        self.invariant_engine = InvariantEngine(strict_governance=
            os.environ.get("NODECHAIN_GOVERNANCE_STRICT", "").strip() in ("1", "true", "yes"))
        self.failure_manager = FailureManager(
            allocate_step_fn=lambda run_id, node_id, attempt=2: (
                self.step_allocator.allocate_sync(run_id, node_id, attempt=attempt).step_id
            ),
        )
        self.scheduler = GraphScheduler(blueprint)
        self.step_allocator = StepAllocator(initial=0)
        self.invoker = NodeInvoker(runner_config=runner_config)

        self.state = ChainState(chain_id=blueprint.chain_id)

        # Compute initial execution order hash for resume integrity
        initial_order = self.scheduler.resolve_execution_order()
        self.state.execution_order_hash = self._compute_order_hash(initial_order)
        self.state.blueprint_version = getattr(blueprint, 'version', '') or blueprint.chain_id

        self.trace = ChainTrace(
            run_id=self.state.run_id,
            chain_id=blueprint.chain_id,
            chain_name=blueprint.name,
        )
        self.emitter = TraceEmitter(
            trace=self.trace,
            run_id=self.state.run_id,
            chain_id=blueprint.chain_id,
        )
        self._contract_registry = ContractRegistry()
        self._step = 0
        self._session_memory: list[dict[str, Any]] = []
        self._memory_manager = None
        # v2.40.0: memory-read governance state
        # v2.40.1: decision-scoped — keyed by (step_id, node_id) → decision_id
        self._memory_read_allows: dict[tuple[int, str], str] = {}
        self._memory_derived_outputs: set[str] = set()  # node_ids whose output used memory

        # Register all node contracts
        for node_id, node in nodes.items():
            self._contract_registry.register(node.manifest.contract)

        # v2.92: extracted contract preflight controller (internal implementation detail)
        from nodechain.runtime.contract_preflight_controller import ContractPreflightController
        self._preflight = ContractPreflightController(
            blueprint=self.blueprint,
            contract_registry=self._contract_registry,
            trace=self.trace,
        )

        # v2.93: extracted node output validation controller (internal implementation detail).
        # Owns schema + semantic validation of node outputs. emit_fn is this
        # Orchestrator's bound _emit method, which both appends to the trace
        # and persists to the event log — preserving the pre-extraction
        # emission behavior for validation events.
        from nodechain.runtime.node_output_validation_controller import (
            NodeOutputValidationController,
        )
        self._output_validation = NodeOutputValidationController(
            validation_pipeline=self.validation_pipeline,
            blueprint=self.blueprint,
            trace=self.trace,
            emit_fn=self._emit,
        )

        # v2.96: extracted policy gate controller (internal implementation detail).
        # Owns per-node policy-gate evaluation and durable decision recording.
        # emit_fn is this Orchestrator's bound _emit method, which both appends
        # to the trace and persists to the event log — preserving the
        # pre-extraction emission behavior for every policy event. The
        # _memory_read_allows dict is shared by reference so the controller's
        # in-place update remains visible to downstream read-allow lookups.
        from nodechain.runtime.policy_gate_controller import PolicyGateController
        self._policy_gate_controller = PolicyGateController(
            policy_gate=self.policy_gate,
            emit_fn=self._emit,
            state_manager=self.state_manager,
            nodes=self._nodes,
            memory_read_allows=self._memory_read_allows,
        )

        # v2.98: extracted side-effect journal controller.
        # Wraps the SideEffectJournalMixin (which Orchestrator inherits from)
        # to provide a named controller entry point.
        from nodechain.runtime.side_effect_journal_controller import SideEffectJournalController
        self._side_effect_journal = SideEffectJournalController(mixin=self)

    def validate_contracts(self) -> list[str]:
        """
        Validate all node contracts and port connections at load time.
        Returns list of issues. Empty = all valid.

        v2.92: delegates to ContractPreflightController. Behavior unchanged.
        """
        return self._preflight.validate(
            run_id=self.state.run_id,
            chain_id=self.state.chain_id,
        )

    async def run(self, query: str) -> ChainTrace:
        """
        Execute the full chain from a research query.
        Returns the complete chain trace.
        """
        start_time = time.time()

        # Step 0: chain_started
        self.state.status = "running"
        self._emit_chain_started()

        try:
            # Validate contracts at load time
            issues = self.validate_contracts()
            if issues:
                self._fail_chain("contract_validation_failed", issues)
                return self.trace
            else:
                # Emit successful contract validation trace
                self._emit_all_contracts_validated()

            # Enforce blueprint invariants
            inv_report = self.invariant_engine.check_blueprint(blueprint=self.blueprint)
            if not inv_report.is_valid:
                self._fail_chain(
                    "blueprint_invariant_violation",
                    [v.message for v in inv_report.errors],
                )
                return self.trace

            # Enforce governance invariants
            # Build node configs from contract requirements and declared side effects
            node_configs = {}
            for nid, node in self._nodes.items():
                manifest = node.manifest
                contract = manifest.contract
                reqs = contract.requirements
                side_effects = contract.side_effects
                config = {
                    "model_required": reqs.model_required,
                    "can_call_tools": bool(reqs.tools_required),
                    "can_write_memory": reqs.memory_access in ("write", "read_write"),
                    "has_side_effects": bool(side_effects),
                    "side_effects": [se.effect_type for se in side_effects],
                }
                # AC4: Enrich with package-declared side effects from registry
                try:
                    from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer
                    from nodechain.registry.local_registry import RegistryIndex
                    _reg = RegistryIndex()
                    _reg.scan()
                    _pkg = _reg.get_package(nid)
                    if _pkg and _pkg.path:
                        import yaml as _y
                        from pathlib import Path as _P
                        _yp = _P(_pkg.path) / "node.yaml"
                        if not _yp.exists():
                            _yp = _P(_pkg.path) / "package.yaml"
                        if _yp.exists():
                            _raw = _y.safe_load(_yp.read_text(encoding="utf-8"))
                            _caps = _raw.get("capabilities", {})
                            if _caps:
                                config["package_capabilities"] = _caps
                            # Multi-node: find this node's entrypoint
                            _pkg_se = []
                            for _ep in _raw.get("entrypoints", []):
                                if _ep.get("node_id") == nid:
                                    _pkg_se = _ep.get("side_effects", [])
                                    break
                            if not _pkg_se:
                                _pkg_se = _raw.get("side_effects", [])
                            if _pkg_se:
                                config["package_declared_side_effects"] = _pkg_se
                except Exception:
                    pass
                node_configs[nid] = config

            policies_raw = []
            for p in self.policy_engine._policies.values():
                policies_raw.append({"type": p.policy_type.value if hasattr(p.policy_type, 'value') else str(p.policy_type)})

            gov_report = self.invariant_engine.check_runtime(
                blueprint=self.blueprint,
                node_configs=node_configs,
                policies=policies_raw,
                cancellation_policies={
                    j.join_id: "allow_all" for j in self.blueprint.joins if j.wait_for == "any"
                },
            )
            # Only hard errors block execution; warnings are logged to trace
            if gov_report.errors:
                self._fail_chain(
                    "governance_invariant_violation",
                    [v.message for v in gov_report.errors],
                )
                return self.trace
            # Emit governance warnings as trace events for visibility
            for w in gov_report.warnings:
                self._emit(
                    EventType.VALIDATION_FAILED,
                    node_id=w.node_id or "runtime",
                    decision=f"governance_warning:{w.invariant_id}",
                    metadata={"warning": w.message, "invariant_id": w.invariant_id},
                )

            # Build execution order from blueprint
            execution_order = self.scheduler.resolve_execution_order()

            # Execute nodes using index-based scheduler loop
            # (not for-in iteration, which ignores list mutation)
            payload: dict[str, Any] = {"query": query}
            sched_idx = 0

            while sched_idx < len(execution_order):
                node_id = execution_order[sched_idx]
                node = self._nodes.get(node_id)
                if node is None:
                    self._fail_chain(
                        "node_not_found", [f"Node '{node_id}' not registered"]
                    )
                    return self.trace

                # Allocate immutable step identity
                invocation = self.step_allocator.allocate_sync(
                    self.state.run_id, node_id,
                )
                self._step = invocation.step_id
                self.state.step = self._step
                self.state.current_node = node_id

                # Check for loop conditions
                loop_result = self.scheduler.check_loop_exhaustion(node_id, self.state)
                if loop_result == "escalate":
                    self._fail_chain(
                        "loop_exhausted",
                        [f"Loop exhausted at node '{node_id}'"],
                    )
                    return self.trace

                # Check loop entry condition
                entry_block = self.scheduler.check_loop_entry(
                    node_id, self.state,
                    cost_usd=self._compute_loop_cost(node_id),
                )
                # Emit advisory warning if condition was unparseable
                if entry_block and entry_block.advisory:
                    self._emit(
                        EventType.LOOP_ESCALATION,
                        node_id=node_id,
                        actor=Actor.RUNTIME,
                        decision="loop_condition_advisory",
                        reason_codes=[entry_block.advisory],
                        metadata={
                            "loop_id": entry_block.loop_id,
                            "check_type": "entry",
                            "advisory": entry_block.advisory,
                            "condition_treated_as": "advisory",
                        },
                    )
                if entry_block and not entry_block.allowed:
                    escalation = self.scheduler.get_escalation_message(
                        entry_block.loop_id, entry_block.reason or "entry blocked",
                    )
                    self._emit(
                        EventType.LOOP_BLOCKED,
                        node_id=node_id,
                        actor=Actor.RUNTIME,
                        decision="loop_entry_blocked",
                        reason_codes=[entry_block.reason or ""],
                        metadata={
                            "loop_id": entry_block.loop_id,
                            "check_type": "entry",
                            "condition_context": entry_block.context,
                        },
                    )
                    self._fail_chain(
                        "loop_entry_blocked",
                        [escalation or entry_block.reason or "Entry condition not met"],
                    )
                    return self.trace

                # Emit contract validation for this node
                self._emit_contract_validated(node_id, node)

                # Policy gate: check tool access, memory access, cost, trust
                # v2.44.3: sync emitter step so trace events carry correct step_id
                self.emitter.set_step(self._step)
                policy_denied = self._check_policy_gate(node_id, node)
                if policy_denied:
                    self._fail_chain("policy_denied", [policy_denied])
                    return self.trace

                # Compile invocation envelope
                context = self._build_context(node_id)
                capabilities = self._build_capabilities(node_id)
                envelope = compile_envelope(
                    run_id=self.state.run_id,
                    chain_id=self.state.chain_id,
                    node_id=node_id,
                    step_id=self._step,
                    payload=payload,
                    context=context,
                    capabilities=capabilities,
                )

                # Pre-call side-effect journaling: record intent before execution
                if not self._side_effect_journal.journal_planned_side_effects(node_id, envelope):
                    self._fail_chain("undeclared_side_effect", [
                        "pre-call side-effect declaration violation",
                    ])
                    return self.trace

                # Invoke node
                response = await self._invoke_node(node, envelope)

                if not response.success:
                    # Classify and handle failure
                    failure_type = self.failure_manager.classify_failure(
                        response.error or "unknown",
                        {"node_id": node_id, "step": self._step},
                    )

                    # Wrap invoke_fn so SEARCH_RETRY_SCHEDULED is emitted ONLY
                    # when a retry-capable handler actually calls the retry
                    # invocation — not unconditionally before handle().
                    # Non-retry handlers (escalation, pause, skip) never call
                    # the wrapper, so they never fabricate scheduling evidence.
                    orig_failed_ev = None
                    for ev in reversed(self.trace.events):
                        if (ev.node_id == node_id
                                and "node_failed" in ev.event_type.value.lower()):
                            orig_failed_ev = ev
                            break

                    # Derive operation_digest from the side-effect trace.
                    retry_digest = ""
                    if orig_failed_ev is not None:
                        for se_ev in self.trace.events:
                            if (se_ev.node_id == node_id
                                    and "side_effect_started" in se_ev.event_type.value.lower()):
                                se_meta = getattr(se_ev, "metadata", {}) or {}
                                ikey = se_meta.get("idempotency_key", "")
                                if ":" in ikey:
                                    parts = ikey.split(":")
                                    if len(parts) >= 3:
                                        retry_digest = parts[-1]
                                        break

                    failed_node_id = node_id
                    failed_orig_ev = orig_failed_ev
                    failed_error = response.error or str(failure_type)
                    failed_digest = retry_digest

                    async def invoke_retry_with_trace(retry_node, retry_envelope):
                        """Wrapped invoke_fn that emits SEARCH_RETRY_SCHEDULED
                        immediately before the retry actually dispatches.
                        Scoped to search_tool provenance recovery only —
                        unrelated node retries must not be mislabeled."""
                        if (failed_orig_ev is not None
                                and failed_node_id == "search_tool"
                                and "SEARCH_PROVENANCE_MALFORMED" in failed_error):
                            self._emit(
                                EventType.TOOL_RESULT_RECEIVED,
                                node_id=failed_node_id,
                                actor=Actor.RUNTIME,
                                decision="search_retry_scheduled",
                                reason_codes=["SEARCH_RETRY_SCHEDULED"],
                                metadata={
                                    "original_failure_event_id": failed_orig_ev.event_id,
                                    "retry_attempt_number": 2,
                                    "retry_reason": failed_error,
                                    "operation_digest": failed_digest,
                                },
                            )
                        return await self._invoke_node(retry_node, retry_envelope)

                    result = await self.failure_manager.handle(
                        failure_type, node, envelope,
                        response.error or "", {"outputs": self.state.outputs},
                        invoke_fn=invoke_retry_with_trace,
                    )
                    if not result.recovered:
                        self._record_last_failure(
                            failure_type, node_id, self._step,
                            response.error or "", retryable=False,
                        )
                        self._fail_chain(
                            f"node_execution_failed:{failure_type.value}",
                            [f"Node '{node_id}' failed: {response.error}", f"Recovery action: {result.action}"],
                        )
                        return self.trace
                    # v3.2.0: retry-recovery success invariant. recovered=True is
                    # authoritative ONLY with a valid successful response. Reject
                    # both invalid shapes (defense-in-depth, independent of the
                    # handler fixes): missing response (None, non-exempt action)
                    # and failed response (success=False). Do not feed garbage
                    # output downstream. Intentional skip-continue actions
                    # (memory-write policy rejection, trace fallback) are exempt.
                    if result.recovered and result.response is None:
                        if result.action not in _SKIP_CONTINUE_ACTIONS:
                            self._record_last_failure(
                                failure_type, node_id, self._step,
                                "recovered_with_no_response", retryable=False,
                            )
                            self._fail_chain(
                                "node_execution_failed:invalid_recovery_response",
                                [f"Node '{node_id}' recovery returned recovered=True with no response"],
                            )
                            return self.trace
                    if result.recovered and result.response is not None and not result.response.success:
                        self._record_last_failure(
                            failure_type, node_id, self._step,
                            result.response.error or "recovered_with_failed_response",
                            retryable=False,
                        )
                        self._fail_chain(
                            "node_execution_failed:invalid_recovery_response",
                            [f"Node '{node_id}' recovery returned recovered=True with a failed response"],
                        )
                        return self.trace
                    response = result.response
                    # Sync step_id from retry — FailureManager allocated a new step
                    if response is not None and hasattr(response, 'step_id'):
                        self._step = response.step_id
                        self.state.step = self._step
                    if response is None:
                        # Policy rejection or trace fallback — continue with empty output
                        self.state.outputs[node_id] = {"skipped": True, "reason": result.action}
                        payload = {"skipped": True, "reason": result.action}
                        sched_idx += 1
                        continue

                # Validate output against exit contract schema
                # v2.93: delegates to NodeOutputValidationController. The
                # controller emits the VALIDATION_PASSED / VALIDATION_FAILED
                # events and returns a ValidationResult; control-flow
                # (_fail_chain / return self.trace) stays here in run().
                exit_schema = node.manifest.contract.exit.schema_ref
                schema_result = self._output_validation.validate_schema(
                    node_id=node_id,
                    output=response.output,
                    exit_schema=exit_schema,
                    run_id=self.state.run_id,
                    chain_id=self.state.chain_id,
                    step_id=self._step,
                )
                if not schema_result.valid and schema_result.strict_violation:
                    self._fail_chain(
                        "schema_validation_failed",
                        schema_result.errors[:5],
                    )
                    return self.trace

                # Update state with output
                self.state.outputs[node_id] = response.output

                # Atomic write: state + ledger + event log
                self.persistence.commit_invocation_success(
                    self.state,
                    step_id=self._step,
                    node_id=node_id,
                    event_type="node_completed",
                    event_payload={"node_id": node_id, "step_id": self._step},
                    cost_usd=response.cost_usd or 0.0,
                )

                # Emit node-specific detail events (tool calls, model usage, memory)
                if not self._emit_node_detail_events(node_id, node, response, envelope):
                    self._fail_chain("undeclared_side_effect", [
                        "post-call side-effect declaration violation",
                    ])
                    return self.trace

                # v3.0.0: observed side-effect completion (Model C). The node may
                # report completion records in output["side_effect_records"]; the
                # runtime validates each against the started/planned ledger and
                # marks completed only for valid observed reports. Absent records
                # are legacy (no-op). Invalid records fail the chain cleanly.
                if not self._side_effect_journal.complete_reported_side_effects(
                    node_id, envelope, response.output,
                ):
                    self._fail_chain("undeclared_side_effect", [
                        "post-call side-effect completion validation violation",
                    ])
                    return self.trace

                # Run semantic validators on key nodes
                # v2.93: delegates to NodeOutputValidationController. The
                # controller emits semantic validation events and surfaces a
                # strict-mode semantic failure via the returned outcome; the
                # _fail_chain call stays here in run() (per the extraction
                # constraint). The original code did NOT return early after a
                # strict semantic failure — execution continued to the schema
                # strict check below — so neither do we.
                semantic_outcome = self._output_validation.run_semantic_validations(
                    node_id=node_id,
                    output=response.output,
                    step_id=self._step,
                    state=self.state,
                )
                if semantic_outcome.strict_failed:
                    self._fail_chain(
                        "semantic_validation_failed",
                        semantic_outcome.errors,
                    )

                if not schema_result.valid and schema_result.strict_violation:
                    self._fail_chain(
                        "schema_validation_failed",
                        schema_result.errors[:5],
                    )
                    return self.trace

                # Check if node output triggers a loop-back
                loop_decision = self.scheduler.check_loop_back(node_id, response.output, self.state)
                if loop_decision:
                    if loop_decision.action == loop_decision.TERMINATE:
                        self._fail_chain("loop_exhausted", [loop_decision.reason])
                        return self.trace

                    loop_id = loop_decision.loop_id or ""
                    # Compute loop cost (ledger-first, trace fallback)
                    loop_cost = self._compute_loop_cost(node_id)
                    # Determine cost source for metadata
                    try:
                        ledger_check = self.state_manager.get_invocation_cost(
                            self.state.run_id, node_ids=[],
                        )
                        cost_source = "invocation_ledger" if ledger_check >= 0 else "trace_events"
                    except Exception:
                        cost_source = "trace_events"

                    # Check budget before allowing iteration
                    budget_block = self.scheduler.check_loop_budget(
                        loop_id, self.state, loop_cost,
                    )
                    if budget_block and not budget_block.allowed:
                        escalation = self.scheduler.get_escalation_message(
                            loop_id, budget_block.reason or "budget exceeded",
                        )
                        self._emit(
                            EventType.LOOP_BLOCKED,
                            node_id=node_id,
                            actor=Actor.RUNTIME,
                            decision="loop_budget_exceeded",
                            reason_codes=[budget_block.reason or ""],
                            metadata={
                                "loop_id": loop_id,
                                "check_type": "budget",
                                "cost_usd": loop_cost,
                                "max_cost_usd": budget_block.context.get("max_cost_usd"),
                                "cost_source": cost_source,
                            },
                        )
                        # v2.47.0: pause for budget approval instead of failing.
                        # The run awaits operator APPROVE_BUDGET_INCREASE; cost
                        # is carried (absolute ceiling), not reset. Persist the
                        # pending loop-back so resume re-enters the loop target,
                        # not the post-loop node.
                        self._pause_for_budget(
                            loop_id, loop_cost,
                            budget_block.context.get("max_cost_usd", 0.0),
                            escalation or budget_block.reason or "Budget exceeded",
                            target_node=getattr(loop_decision, "target_node", None),
                            source_node=node_id,
                        )
                        return self.trace

                    # Check exit condition before allowing iteration
                    exit_result = self.scheduler.check_loop_exit(
                        loop_id, self.state, loop_cost,
                    )
                    if exit_result and not exit_result.allowed:
                        # Exit condition met — emit LOOP_EXITED and continue normally
                        self._emit(
                            EventType.LOOP_EXITED,
                            node_id=node_id,
                            actor=Actor.RUNTIME,
                            decision="loop_exit_condition_met",
                            reason_codes=[exit_result.reason or ""],
                            metadata={
                                "loop_id": loop_id,
                                "check_type": "exit",
                                "condition_context": exit_result.context,
                            },
                        )
                        # Do NOT loop back — continue normal execution
                        loop_decision = None

                    if loop_decision:
                        # Emit loop trace event
                        self._emit(
                            EventType.LOOP_ENTERED,
                            node_id=node_id,
                            actor=Actor.RUNTIME,
                            decision="loop_iteration",
                            reason_codes=[loop_decision.reason],
                        )
                        payload = self._build_loop_payload(loop_decision.target_node, response.output)
                        execution_order = self.scheduler.rebuild_order_with_loop(
                            execution_order, self.state.current_node, loop_decision.target_node
                        )
                        # Reset index to re-execute from target
                        sched_idx = execution_order.index(loop_decision.target_node)
                        continue

                # Check if node triggers a branch (fan-out)
                branch_defs = self.scheduler.get_branches_from(node_id)
                if branch_defs:
                    branch_def = branch_defs[0]  # One branch per node
                    selected = self.scheduler.resolve_branch_selection(branch_def, response.output)
                    branch_result = await self._execute_branches(
                        branch_def, selected, response.output, execution_order
                    )
                    if branch_result is None:
                        self._fail_chain("branch_execution_failed", ["Branch execution returned no results"])
                        return self.trace
                    payload = branch_result
                    # Skip to the join node by advancing past branch nodes
                    execution_order = self.scheduler.skip_to_join(execution_order, node_id, branch_def)
                    sched_idx += 1  # Advance past current node
                    continue

                payload = response.output  # Chain outputs

                # Check if human review is required
                if node_id == "risk_classifier" and self.review_manager.needs_review(response.output):
                    try:
                        review_result = await self.review_manager.request_review(
                            response.output, self.state, self.blueprint.name, self._step
                        )
                    except ReviewPausedException as e:
                        # Chain paused for manual review — return trace cleanly
                        self._emit(
                            EventType.HUMAN_REVIEW_REQUESTED,
                            node_id="risk_classifier",
                            actor=Actor.RUNTIME,
                            decision="chain_paused_for_review",
                            metadata={"reason": "pause mode", "step_id": e.step_id},
                        )
                        self.trace.final_status = "paused"
                        return self.trace
                    # code-review fix C: governance_failure is not a scheduler-native
                    # outcome. Handle it explicitly before scheduler translation so
                    # it isn't misinterpreted as REVIEW_REJECT.
                    if review_result.decision == "governance_failure":
                        self._fail_chain(
                            "review_receipt_verification_failed",
                            ["Governance failure: review receipt verification failed"],
                        )
                        return self.trace
                    # Translate review decision to scheduler transition
                    transition = self.scheduler.apply_review_decision(
                        review_result.decision, execution_order, node_id,
                    )

                    if transition.action == SchedulingDecision.REVIEW_REJECT:
                        self._fail_chain(
                            "human_review_rejected",
                            ["Human reviewer rejected the chain output"],
                        )
                        return self.trace

                    elif transition.action == SchedulingDecision.REVIEW_REVISION:
                        # Route back to revision target via scheduler
                        target = transition.revision_target or "task_planner"
                        execution_order = self.scheduler.rebuild_order_with_loop(
                            execution_order, node_id, target,
                        )
                        try:
                            sched_idx = execution_order.index(target)
                        except ValueError:
                            sched_idx = sched_idx + 1
                        continue

                    elif transition.action == SchedulingDecision.REVIEW_TIMEOUT:
                        self._fail_chain(
                            "review_timeout",
                            ["Review timed out without a decision"],
                        )
                        return self.trace

                    # REVIEW_APPROVE — continue normally

                # Save state for pause/resume
                self.persistence.save_snapshot(self.state)

                sched_idx += 1  # Advance to next node

            # Chain completed successfully
            self.state.status = "completed"
            self.state.completed_at = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            self._emit_chain_completed()
            self.persistence.save_final(self.state)  # Final save

        except Exception as e:
            self._fail_chain("unhandled_exception", [str(e)])

        finally:
            # Finalize trace
            elapsed_ms = int((time.time() - start_time) * 1000)
            self.trace.total_duration_ms = elapsed_ms
            self.trace.finalize(self.state.status)

        return self.trace

    async def resume(self, run_id: str) -> ChainTrace:
        """
        Resume a previously paused/interrupted chain from its last checkpoint.

        Loads the materialized state, determines which nodes already executed
        (from the invocation ledger), and continues from the next unexecuted node.

        Guarantees:
        - Same run_id and chain_id
        - Monotonic step_id (continues from last completed step)
        - No duplicate node invocations
        - No duplicate side effects
        - Trace continuity (same trace object, appended events)
        """
        start_time = time.time()

        # Load materialized state via persistence coordinator
        recovery = self.persistence.load_for_recovery(run_id)
        if recovery is None:
            raise ValueError(f"No saved state found for run_id '{run_id}'")

        saved = recovery.state

        # Restore state
        self.state = saved
        self.state.is_resumed = True
        self._step = self.state.step
        self.step_allocator.initialize_from(self._step)

        # Verify resume integrity — fail clearly on blueprint drift
        try:
            self._verify_resume_integrity(saved)
        except RecoveryCursorMismatch:
            self._fail_chain(
                "recovery_cursor_mismatch",
                [f"Blueprint/order changed since run was saved. "
                 f"expected_hash={saved.execution_order_hash}, "
                 f"run_id={saved.run_id}"],
            )
            return self.trace

        # Track invocation-level completed steps for skip decisions
        completed_invocations = recovery.completed_steps  # step_id → node_id

        # Rebuild trace from saved state
        self.trace = ChainTrace(
            run_id=self.state.run_id,
            chain_id=self.state.chain_id,
        )
        # Sync emitter with new trace
        self.emitter.trace = self.trace
        self.emitter.run_id = self.state.run_id
        self.emitter.chain_id = self.state.chain_id

        # Emit resume event
        self._emit(
            EventType.CHAIN_STARTED,
            decision="chain_resumed",
            metadata={"resumed_from_revision": saved.revision, "resumed_from_step": saved.step},
        )

        # Reconcile side effects: mark started-but-not-completed as 'unknown'
        self._reconcile_side_effects_on_resume(saved.run_id)

        # Emit pending review event (from _resume_waiting_for_review delegation)
        pending_review = saved.metadata.get("pending_review_event")
        if pending_review:
            self._emit(
                EventType.HUMAN_REVIEW_COMPLETED,
                node_id="risk_classifier",
                actor=Actor.HUMAN,
                decision=pending_review["decision"],
                metadata={
                    "resumed_review": True,
                    "transition": pending_review["transition"],
                    "reason": pending_review["reason"],
                    "receipt_id": pending_review.get("receipt_id"),
                    "receipt_digest": pending_review.get("receipt_digest"),
                    "request_id": pending_review.get("request_id"),
                    "request_digest": pending_review.get("request_digest"),
                    "subject_type": pending_review.get("subject_type"),
                    "reviewer_identity": pending_review.get("reviewer_identity"),
                },
            )
            # Clear pending event so it's not re-emitted
            saved.metadata.pop("pending_review_event", None)
            self.persistence.save_snapshot(saved)

        # Handle waiting_for_review: don't continue execution until decision exists
        if saved.status == "waiting_for_review":
            return await self._resume_waiting_for_review(saved)

        try:
            # Validate contracts
            issues = self.validate_contracts()
            if issues:
                self._fail_chain("contract_validation_failed", issues)
                return self.trace

            # Build execution order
            execution_order = self.scheduler.resolve_execution_order()

            # Invocation-level resume cursor: find the correct position
            # for the last completed step, even when a node appears multiple times.
            #
            # Strategy: count how many times the node at self._step was invoked
            # (by counting steps ≤ self._step with the same node_id),
            # then find the Nth occurrence in the execution order.
            start_index = 0
            if self._step > 0 and completed_invocations:
                target_nid = completed_invocations.get(self._step)
                if target_nid:
                    # How many times was this node invoked up to and including self._step?
                    occurrence = sum(
                        1 for sid, nid in completed_invocations.items()
                        if nid == target_nid and sid <= self._step
                    )
                    # Find the Nth occurrence in the execution order
                    seen = 0
                    for i, nid in enumerate(execution_order):
                        if nid == target_nid:
                            seen += 1
                            if seen == occurrence:
                                start_index = i + 1
                                break

            # Build payload from last output
            payload: dict[str, Any] = {}
            # Walk outputs in execution order to get the most recent
            for nid in execution_order[:start_index]:
                if nid in self.state.outputs:
                    payload = self.state.outputs[nid]

            # Handle review revision: rebuild execution order from revision target
            revision_target = saved.metadata.get("review_revision_target")
            if revision_target:
                # Find the node that triggered the review
                review_node = "risk_classifier"
                execution_order = self.scheduler.rebuild_order_with_loop(
                    execution_order, review_node, revision_target,
                )
                try:
                    start_index = execution_order.index(revision_target)
                except ValueError:
                    start_index = 0  # Fall back to beginning
                payload = {"revision_requested": True, "previous_outputs": saved.outputs}
                # Clear revision target so it's not reapplied on subsequent resumes
                saved.metadata.pop("review_revision_target", None)
                self.persistence.save_snapshot(saved)

            # v2.47.0: handle pending loop-back from budget approval resume.
            # The pause happened AFTER loop_decision but BEFORE rebuild_order_with_loop,
            # so the loop target needs to be re-entered, not skipped past.
            pending_loop = saved.metadata.get("pending_loop_back")
            if pending_loop:
                target_node = pending_loop.get("target_node")
                source_node = pending_loop.get("source_node")
                if target_node and source_node:
                    execution_order = self.scheduler.rebuild_order_with_loop(
                        execution_order, source_node, target_node,
                    )
                    try:
                        start_index = execution_order.index(target_node)
                    except ValueError:
                        start_index = 0
                    # Build the target-specific payload the live loop path would
                    # have used — not the generic pre-computed payload. The live
                    # path calls _build_loop_payload(target, current_output),
                    # which has context_selector/task_planner logic per target.
                    source_output = self.state.outputs.get(source_node, payload)
                    payload = self._build_loop_payload(target_node, source_output)
                # Clear so it's not reapplied on subsequent resumes
                saved.metadata.pop("pending_loop_back", None)
                self.persistence.save_snapshot(saved)

            # Resume: check for pending branch execution
            # If state was paused after routing decision but before branch execution,
            # the routing_decisions will be populated but branch_outputs won't
            routing = self.state.routing_decisions
            if routing and not self.state.branch_outputs:
                # Resume branch execution
                last_routing = routing[-1]
                selected = last_routing.get("selected", [])
                from_node = last_routing.get("from_node", "")

                branch_defs = self.scheduler.get_branches_from(from_node)
                if branch_defs:
                    branch_def = branch_defs[0]
                    branch_result = await self._execute_branches(
                        branch_def, selected, payload, execution_order
                    )
                    if branch_result is not None:
                        payload = branch_result
                        execution_order = self.scheduler.skip_to_join(execution_order, from_node, branch_def)

            # Execute remaining nodes using scheduler loop
            sched_idx = start_index
            while sched_idx < len(execution_order):
                node_id = execution_order[sched_idx]
                node = self._nodes.get(node_id)
                if node is None:
                    self._fail_chain("node_not_found", [f"Node '{node_id}' not registered"])
                    return self.trace

                # Check idempotency — skip only if this specific invocation
                # (step_id ≤ restored step) was already completed.
                # Do NOT skip re-executions from loop-backs.
                already_done = (
                    node_id in recovery.completed_node_ids
                    and any(
                        nid == node_id and sid <= self._step
                        for sid, nid in completed_invocations.items()
                    )
                )
                if already_done:
                    payload = self.state.outputs.get(node_id, payload)
                    sched_idx += 1
                    continue

                invocation = self.step_allocator.allocate_sync(
                    self.state.run_id, node_id,
                )
                self._step = invocation.step_id
                self.state.step = self._step
                self.state.current_node = node_id

                # Policy gate
                policy_denied = self._check_policy_gate(node_id, node)
                if policy_denied:
                    self._fail_chain("policy_denied", [policy_denied])
                    return self.trace

                # Compile envelope
                context = self._build_context(node_id)
                capabilities = self._build_capabilities(node_id)
                envelope = compile_envelope(
                    run_id=self.state.run_id,
                    chain_id=self.state.chain_id,
                    node_id=node_id,
                    step_id=self._step,
                    payload=payload,
                    context=context,
                    capabilities=capabilities,
                )

                # Pre-call side-effect journaling: record intent before execution
                if not self._side_effect_journal.journal_planned_side_effects(node_id, envelope):
                    self._fail_chain("undeclared_side_effect", [
                        "pre-call side-effect declaration violation",
                    ])
                    return self.trace

                # Invoke node
                response = await self._invoke_node(node, envelope)

                if not response.success:
                    failure_type = self.failure_manager.classify_failure(
                        response.error or "unknown",
                        {"node_id": node_id, "step": self._step},
                    )
                    result = await self.failure_manager.handle(
                        failure_type, node, envelope,
                        response.error or "", {"outputs": self.state.outputs},
                        invoke_fn=self._invoke_node,
                    )
                    if not result.recovered:
                        self._record_last_failure(
                            failure_type, node_id, self._step,
                            response.error or "", retryable=False,
                        )
                        self._fail_chain(
                            f"node_execution_failed:{failure_type.value}",
                            [f"Node '{node_id}' failed: {response.error}"],
                        )
                        return self.trace
                    # v3.2.0: retry-recovery success invariant. recovered=True is
                    # authoritative ONLY with a valid successful response. Reject
                    # both invalid shapes (defense-in-depth, independent of the
                    # handler fixes): missing response (None, non-exempt action)
                    # and failed response (success=False). Do not feed garbage
                    # output downstream. Intentional skip-continue actions
                    # (memory-write policy rejection, trace fallback) are exempt.
                    if result.recovered and result.response is None:
                        if result.action not in _SKIP_CONTINUE_ACTIONS:
                            self._record_last_failure(
                                failure_type, node_id, self._step,
                                "recovered_with_no_response", retryable=False,
                            )
                            self._fail_chain(
                                "node_execution_failed:invalid_recovery_response",
                                [f"Node '{node_id}' recovery returned recovered=True with no response"],
                            )
                            return self.trace
                    if result.recovered and result.response is not None and not result.response.success:
                        self._record_last_failure(
                            failure_type, node_id, self._step,
                            result.response.error or "recovered_with_failed_response",
                            retryable=False,
                        )
                        self._fail_chain(
                            "node_execution_failed:invalid_recovery_response",
                            [f"Node '{node_id}' recovery returned recovered=True with a failed response"],
                        )
                        return self.trace
                    response = result.response
                    # Sync step_id from retry — FailureManager allocated a new step
                    if response is not None and hasattr(response, 'step_id'):
                        self._step = response.step_id
                        self.state.step = self._step
                    if response is None:
                        self.state.outputs[node_id] = {"skipped": True, "reason": result.action}
                        payload = {"skipped": True, "reason": result.action}
                        sched_idx += 1
                        continue

                # Validate output
                exit_schema = node.manifest.contract.exit.schema_ref
                if exit_schema:
                    schema_result = self.validation_pipeline.validate_schema(
                        node_id, response.output, exit_schema
                    )
                    if schema_result.valid:
                        self._emit(EventType.VALIDATION_PASSED, node_id, decision="schema_valid")
                    if not schema_result.valid:
                        self.trace.add_event(TraceEvent(
                            run_id=self.state.run_id,
                            chain_id=self.state.chain_id,
                            node_id=node_id,
                            step_id=self._step,
                            event_type=EventType.VALIDATION_FAILED,
                            actor=Actor.RUNTIME,
                            decision="schema_validation_warning",
                            reason_codes=schema_result.errors[:3],
                        ))

                # Update state (atomic write)
                self.state.outputs[node_id] = response.output
                self.persistence.commit_invocation_success(
                    self.state,
                    step_id=self._step,
                    node_id=node_id,
                    event_type="node_completed",
                    event_payload={"node_id": node_id, "step_id": self._step, "resumed": True},
                )
                if not self._emit_node_detail_events(node_id, node, response, envelope):
                    self._fail_chain("undeclared_side_effect", [
                        "post-call side-effect declaration violation",
                    ])
                    return self.trace

                # v3.1.0: observed side-effect completion on the resume path.
                # Mirror of v3.0's run() wiring (line ~494). For freshly
                # re-executed nodes (Case A1: side-effect key is genuinely new),
                # this completes the effect exactly like run(). Crash-window
                # ``unknown`` effects (Case A2) are rejected by the existing
                # v3.0 validation rules (reason="completion_requires_started_status")
                # and remain deferred to the recovery-decision design (v3.2).
                if not self._side_effect_journal.complete_reported_side_effects(
                    node_id, envelope, response.output,
                ):
                    self._fail_chain("undeclared_side_effect", [
                        "post-call side-effect completion validation violation (resume)",
                    ])
                    return self.trace

                # Check for branch execution
                branch_defs = self.scheduler.get_branches_from(node_id)
                if branch_defs:
                    branch_def = branch_defs[0]
                    selected = self.scheduler.resolve_branch_selection(branch_def, response.output)
                    branch_result = await self._execute_branches(
                        branch_def, selected, response.output, execution_order
                    )
                    if branch_result is None:
                        self._fail_chain("branch_execution_failed", ["Branch execution returned no results"])
                        return self.trace
                    payload = branch_result
                    execution_order = self.scheduler.skip_to_join(execution_order, node_id, branch_def)
                    sched_idx += 1
                    continue

                payload = response.output
                self.persistence.save_snapshot(self.state)
                sched_idx += 1

            # Chain completed
            self.state.status = "completed"
            self.state.completed_at = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            self._emit_chain_completed()
            self.persistence.save_final(self.state)  # Final save

        except Exception as e:
            self._fail_chain("unhandled_exception", [str(e)])

        finally:
            elapsed_ms = int((time.time() - start_time) * 1000)
            self.trace.total_duration_ms = elapsed_ms
            self.trace.finalize(self.state.status)

        return self.trace

    async def route_fallback(self, run_id: str, target_step_id: int) -> str:
        """Operator-initiated fallback for one failed step (#13).

        Loads durable state, reconstructs the failed node + envelope from
        last_failure metadata, and calls FailureManager.route_fallback (which
        only executes for fallback-capable failure types). The recovery delegate
        (CLI layer) calls this; RecoveryService owns policy/audit. Returns the
        resulting run status.
        """
        recovery = self.persistence.load_for_recovery(run_id)
        if recovery is None:
            raise ValueError(f"No saved state found for run_id '{run_id}'")
        self.state = recovery.state
        self._step = self.state.step

        md = self.state.metadata or {}
        last_failure = md.get("last_failure") or {}
        node_id = last_failure.get("node_id")
        failure_type_str = last_failure.get("failure_type")
        error = last_failure.get("error", "")

        if not node_id or not failure_type_str:
            raise ValueError(
                f"route_fallback requires durable last_failure with node_id + "
                f"failure_type for run {run_id}"
            )

        from nodechain.runtime.failure_manager import FailureType
        try:
            failure_type = FailureType(failure_type_str)
        except ValueError:
            raise ValueError(f"unknown failure_type '{failure_type_str}'")

        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError(f"node '{node_id}' not in blueprint for run {run_id}")

        envelope = compile_envelope(
            run_id=run_id, chain_id=self.state.chain_id,
            node_id=node_id, step_id=target_step_id,
            payload={}, context={},
        )

        result = await self.failure_manager.route_fallback(
            failure_type, node, envelope, error,
            {"outputs": self.state.outputs}, invoke_fn=self._invoke_node,
        )

        if result.recovered and result.response is not None:
            response = result.response
            if hasattr(response, "outputs") and response.outputs:
                self.state.outputs[node_id] = response.outputs
            self.state.status = "running"
        else:
            self.state.status = "failed"

        self.state_manager.save(self.state)
        return self.state.status

    async def _resume_waiting_for_review(self, saved: ChainState) -> ChainTrace:
        """Handle resume when chain is waiting for human review.

        Resolves the review decision via ReviewManager, applies the
        scheduler transition, updates saved state, then delegates to
        resume() for execution. The review event is emitted inside
        resume() as a startup event.

        No duplicated execution loop.
        """
        # Resolve the review decision
        review_result = await self.review_manager.resolve_resume_review(
            saved, self.blueprint.name
        )

        # code-review fix C: governance_failure — handle explicitly before scheduler.
        if review_result.decision == "governance_failure":
            self._fail_chain(
                "review_receipt_verification_failed",
                ["Governance failure: review receipt verification failed on resume"],
            )
            return self.trace

        # Translate to scheduler transition
        transition = self.scheduler.apply_review_decision(
            review_result.decision,
            self.scheduler.resolve_execution_order(),
            "risk_classifier",
        )

        # Handle rejection and timeout as terminal states (before resume)
        if transition.action in (
            SchedulingDecision.REVIEW_REJECT,
            SchedulingDecision.REVIEW_TIMEOUT,
        ):
            # Need to initialize state and trace for the terminal event
            self.state = saved
            self.state.is_resumed = True
            self._step = self.state.step
            self.step_allocator.initialize_from(self._step)
            self.trace = ChainTrace(
                run_id=saved.run_id,
                chain_id=saved.chain_id,
            )
            self.emitter.trace = self.trace
            self.emitter.run_id = saved.run_id
            self.emitter.chain_id = saved.chain_id

            self._emit(
                EventType.HUMAN_REVIEW_COMPLETED,
                node_id="risk_classifier",
                actor=Actor.HUMAN,
                decision=review_result.decision,
                metadata=self._resume_receipt_metadata(review_result, {
                    "resumed_review": True,
                    "transition": transition.action,
                    "reason": transition.reason,
                }),
            )
            reason = (
                "human_review_rejected" if transition.action == SchedulingDecision.REVIEW_REJECT
                else "review_timeout"
            )
            message = (
                "Human reviewer rejected the chain output"
                if transition.action == SchedulingDecision.REVIEW_REJECT
                else "Review timed out without a decision"
            )
            self._fail_chain(reason, [message])
            return self.trace

        # For revision: store revision target in metadata
        if transition.action == SchedulingDecision.REVIEW_REVISION:
            saved.metadata["review_revision_target"] = transition.revision_target

        # Store review info so resume() can emit the event
        saved.metadata["pending_review_event"] = {
            "decision": review_result.decision,
            "transition": transition.action,
            "reason": transition.reason,
            **self._resume_receipt_metadata(review_result, {}),
        }

        # Mark state as running so resume() doesn't re-enter this method
        saved.status = "running"
        saved.paused_at = None
        self.persistence.save_snapshot(saved)

        # Delegate to resume() — it handles the execution loop
        # with proper step allocation, persistence, and trace emission
        return await self.resume(saved.run_id)

    async def _invoke_node(
        self, node: BaseNode, envelope: InvocationEnvelope
    ) -> EnvelopeResponse:
        """Invoke a single node with full lifecycle tracing.

        Delegates execution to NodeInvoker and wraps with trace events.
        """
        node_id = node.manifest.node_id
        step_id = envelope.step_id

        # Emit node_invoked
        self.trace.add_event(
            TraceEvent(
                run_id=self.state.run_id,
                chain_id=self.state.chain_id,
                node_id=node_id,
                step_id=step_id,
                event_type=EventType.NODE_INVOKED,
                actor=Actor.RUNTIME,
            )
        )

        # Delegate to NodeInvoker
        trust_level = getattr(node, "_trust_level", "built_in")
        isolation_config = getattr(node, "isolation_config", None)
        response, elapsed_ms = await self.invoker.invoke(
            node, envelope,
            trust_level=trust_level,
            isolation_config=isolation_config,
        )

        if response.success:
            # Emit node_succeeded
            self.trace.add_event(
                TraceEvent(
                    run_id=self.state.run_id,
                    chain_id=self.state.chain_id,
                    node_id=node_id,
                    step_id=step_id,
                    event_type=EventType.NODE_SUCCEEDED,
                    actor=Actor.NODE,
                    cost_usd=response.cost_usd,
                    latency_ms=elapsed_ms,
                )
            )
            return response
        else:
            # Emit node_failed
            self.trace.add_event(
                TraceEvent(
                    run_id=self.state.run_id,
                    chain_id=self.state.chain_id,
                    node_id=node_id,
                    step_id=step_id,
                    event_type=EventType.NODE_FAILED,
                    actor=Actor.NODE,
                    latency_ms=elapsed_ms,
                    reason_codes=[response.error or "unknown"],
                )
            )
            return response

    async def _handle_failure(
        self,
        node_id: str,
        node: BaseNode,
        envelope: InvocationEnvelope,
        failed_response: EnvelopeResponse,
    ) -> EnvelopeResponse | None:
        """
        Handle node failure based on failure handling strategy.
        Returns None if failure is unrecoverable.
        """
        # Default: retry once with same envelope
        self.trace.add_event(
            TraceEvent(
                run_id=self.state.run_id,
                chain_id=self.state.chain_id,
                node_id=node_id,
                step_id=envelope.step_id,
                event_type=EventType.NODE_FAILED,
                actor=Actor.RUNTIME,
                decision="retry",
                reason_codes=["retrying_once"],
            )
        )

        # Retry once
        retry_invocation = self.step_allocator.allocate_sync(
            self.state.run_id, node_id, attempt=2,
        )
        self._step = retry_invocation.step_id
        retry_envelope = compile_envelope(
            run_id=self.state.run_id,
            chain_id=self.state.chain_id,
            node_id=node_id,
            step_id=self._step,
            payload=envelope.payload,
            context=envelope.context,
            capabilities=envelope.capabilities,
        )

        response = await self._invoke_node(node, retry_envelope)
        return response if response.success else None

    # v2.75: side-effect journaling methods (_journal_planned_side_effects,
    # _journal_search_operations, _assert_declared_side_effect, _journal_one,
    # _reconcile_side_effects_on_resume, _get_declared_se_types) extracted to
    # SideEffectJournalMixin. _node_has_contract remains here (general helper).

    def _node_has_contract(self, node_id: str) -> bool:
        """Return True if the node is in the registry (contract available)."""
        node = self._nodes.get(node_id)
        return node is not None and hasattr(node, "manifest")

    def _build_context(self, node_id: str) -> Context:
        """Build context for a node invocation from current state.

        v2.40.0: memory sanitizer. By default, session_memory is stripped
        unless a MEMORY_READ allow decision exists for this node. Memory-
        derived outputs from upstream nodes are also filtered unless the
        node has a read allow. This is the second enforcement layer (the
        first is PolicyGate.check() which blocks declared read nodes on
        deny before context construction).
        """
        # v2.40.1: decision-scoped allow check — keyed by (step_id, node_id)
        allow_key = (self._step, node_id)
        has_read_allow = allow_key in self._memory_read_allows

        # Strip session_memory unless allow exists
        session_memory = self._session_memory if has_read_allow else []

        # Strip memory-derived outputs from chain_state unless allow exists
        outputs = self.state.outputs
        if not has_read_allow and self._memory_derived_outputs:
            # Filter out outputs from nodes that used memory
            outputs = {
                k: v for k, v in outputs.items()
                if k not in self._memory_derived_outputs
            }

        ctx = Context(
            chain_state={
                "outputs": outputs,
                "step": self.state.step,
                # v2.68: include trace data so trace_collector node can verify
                # truth rule and report event count. The trace is the
                # authoritative execution record — the collector verifies it.
                "trace": self.trace.model_dump() if node_id == "trace_collector" else None,
            },
            session_memory=session_memory,
            # v2.40.2: carry the authorization reference for exposed memory
            memory_read_decision_id=(
                self._memory_read_allows.get(allow_key, "")
                if has_read_allow else ""
            ),
        )

        # v2.41.0: emit MEMORY_READ_EXPOSED only when memory was actually
        # exposed (not just authorized with empty session_memory and no
        # memory-derived outputs). Allowed + empty = not an exposure event.
        if has_read_allow and (session_memory or
                               (self._memory_derived_outputs and
                                any(k in outputs for k in self._memory_derived_outputs))):
            decision_id = self._memory_read_allows.get(allow_key, "")
            self._emit(
                EventType.MEMORY_READ_EXPOSED,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="memory_exposed",
                metadata={
                    "decision_id": decision_id,
                    "node_id": node_id,
                    "step_id": self._step,
                    "exposed_session_memory_count": len(session_memory),
                    "exposed_memory_derived_node_count": (
                        sum(1 for k in self._memory_derived_outputs if k in outputs)
                        if self._memory_derived_outputs else 0
                    ),
                },
            )

        return ctx

    @staticmethod
    def _compute_order_hash(order: list[str]) -> str:
        """Compute SHA-256 hash of the execution order for integrity checks."""
        import hashlib
        payload = ",".join(order)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _verify_resume_integrity(self, saved: ChainState) -> None:
        """Verify that the blueprint/execution order hasn't drifted since the run was saved.

        Raises RecoveryCursorMismatch if hashes don't match.
        """
        current_order = self.scheduler.resolve_execution_order()
        current_hash = self._compute_order_hash(current_order)

        if not saved.execution_order_hash:
            # Legacy state without hash — allow with a warning in metadata
            return

        if saved.execution_order_hash != current_hash:
            from nodechain.core.trace import EventType, Actor
            self._emit(
                EventType.CHAIN_FAILED,
                decision="recovery_cursor_mismatch",
                reason_codes=[
                    f"execution_order_hash mismatch: expected={saved.execution_order_hash}, actual={current_hash}",
                    f"blueprint_version={saved.blueprint_version}",
                    f"run_id={saved.run_id}",
                ],
            )
            raise RecoveryCursorMismatch(
                run_id=saved.run_id,
                blueprint_id=saved.chain_id,
                expected_hash=saved.execution_order_hash,
                actual_hash=current_hash,
            )

    def _build_capabilities(self, node_id: str) -> Capabilities:
        """Build capabilities grant for a node invocation.

        Includes side-effect gating: completed side effects are listed
        so the node can skip duplicate external calls on resume.

        v2.42.0: capabilities sanitizer. allowed_tools is intersected
        with contract-declared tools_required so nodes cannot receive
        undeclared tool grants.
        """
        node_def = self.blueprint.get_node(node_id)
        if node_def is None:
            return Capabilities()

        config = node_def.config

        # Get side-effect state for this run (execution gating)
        completed_se_keys = self.persistence.get_completed_side_effect_keys(self.state.run_id)
        se_status_map = self.persistence.get_side_effect_status_map(self.state.run_id)

        # v2.42.0: capabilities sanitizer
        # Runtime allowed_tools from blueprint config
        runtime_allowed = set(config.get("allowed_tools", []))
        # Contract-declared tools
        node = self._nodes.get(node_id)
        declared_tools: set[str] = set()
        if node and hasattr(node, "manifest"):
            req = node.manifest.contract.requirements
            if req.tools_required:
                declared_tools = set(req.tools_required)

        # Sanitize: only declared ∩ runtime tools are exposed
        if declared_tools:
            sanitized_tools = list(runtime_allowed & declared_tools)
        else:
            sanitized_tools = list(runtime_allowed)

        # v2.43.0: adapter sanitizer — separate from tools
        # v2.43.1: empty declaration = no adapter access (don't inherit config)
        runtime_adapters = set(config.get("allowed_adapters", []))
        declared_adapters: set[str] = set()
        if node and hasattr(node, "manifest"):
            req = node.manifest.contract.requirements
            if req.adapters_required:
                declared_adapters = set(req.adapters_required)
        if declared_adapters:
            # Only declared ∩ runtime are exposed
            sanitized_adapters = list(runtime_adapters & declared_adapters)
        else:
            # v2.43.1: no declaration = no adapter access
            sanitized_adapters = []

        return Capabilities(
            can_call_tools=bool(declared_tools or config.get("can_call_tools", False)),
            can_read_memory=config.get("can_read_memory", False),
            can_write_memory=config.get("can_write_memory", False),
            max_cost_usd=config.get("max_cost_usd", 1.0),
            allowed_tools=sanitized_tools,
            allowed_adapters=sanitized_adapters,
            side_effect_completed_keys=completed_se_keys,
            side_effect_status_map=se_status_map,
        )

    def _emit(
        self,
        event_type: EventType,
        node_id: str = "runtime",
        actor: Actor = Actor.RUNTIME,
        decision: str | None = None,
        reason_codes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        cost_usd: float = 0.0,
        latency_ms: int = 0,
        step_id: int | None = None,
    ) -> None:
        """Emit a trace event via TraceEmitter and persist to event log."""
        effective_step = step_id if step_id is not None else self._step
        self.emitter.emit(
            event_type=event_type,
            node_id=node_id,
            actor=actor,
            decision=decision,
            reason_codes=reason_codes,
            metadata=metadata,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            step_id=effective_step,
        )
        # Persist to append-only event log
        self.persistence.append_event(
            run_id=self.state.run_id,
            revision=self.state.revision,
            event_type=event_type.value,
            node_id=node_id,
            step_id=effective_step,
            payload={
                "decision": decision,
                "reason_codes": reason_codes or [],
                "metadata": metadata or {},
            },
        )

    def _emit_chain_started(self) -> None:
        self.trace.add_event(
            TraceEvent(
                run_id=self.state.run_id,
                chain_id=self.state.chain_id,
                node_id="runtime",
                step_id=0,
                event_type=EventType.CHAIN_STARTED,
                actor=Actor.RUNTIME,
                decision="chain_initialized",
                reason_codes=["goal_received"],
            )
        )

    def _emit_chain_completed(self) -> None:
        self.trace.add_event(
            TraceEvent(
                run_id=self.state.run_id,
                chain_id=self.state.chain_id,
                node_id="runtime",
                step_id=self._step,
                event_type=EventType.CHAIN_COMPLETED,
                actor=Actor.RUNTIME,
                decision="chain_completed_successfully",
                metadata={
                    "nodes_executed": sum(
                        1 for e in self.trace.events
                        if e.event_type == EventType.NODE_SUCCEEDED
                    ),
                    "loops_entered": sum(
                        1 for e in self.trace.events
                        if e.event_type == EventType.LOOP_ENTERED
                    ),
                    "human_reviews": sum(
                        1 for e in self.trace.events
                        if e.event_type == EventType.HUMAN_REVIEW_REQUESTED
                    ),
                },
            )
        )

    def _resume_receipt_metadata(self, review_result, base: dict) -> dict:
        """Build full receipt metadata for resume trace events (code-review fix B).

        Extracts receipt binding fields from review_result.decision_receipt so
        the reconciler can bind resumed events the same way as live ones.
        """
        receipt = review_result.decision_receipt or {}
        decision = receipt.get("decision") or {}
        meta = dict(base)
        meta["receipt_id"] = review_result.receipt_id
        meta["receipt_digest"] = review_result.receipt_digest
        meta["request_id"] = receipt.get("request_id")
        meta["request_digest"] = receipt.get("request_digest")
        meta["subject_type"] = receipt.get("subject_type")
        meta["reviewer_identity"] = decision.get("reviewer_identity")
        return meta

    def _pause_for_budget(
        self, loop_id: str, accumulated_cost: float,
        previous_budget: float, reason: str,
        *, target_node: str | None = None, source_node: str | None = None,
    ) -> None:
        """Pause the chain for budget-increase approval (v2.47.0).

        Sets status='paused_for_budget' and records durable budget context so
        the recovery console + classifier + OperatorActionPolicy can drive
        APPROVE_BUDGET_INCREASE. Cost is carried (absolute ceiling), not reset.

        Persists pending_loop_back so resume re-enters the loop target node
        (not the post-loop node) after the operator approves the budget.
        """
        self.state.status = "paused_for_budget"
        md = dict(self.state.metadata or {})
        md["loop_budget_exceeded"] = loop_id
        md["budget_context"] = {
            "loop_id": loop_id,
            "accumulated_cost": accumulated_cost,
            "previous_budget": previous_budget,
            "reason": reason,
        }
        if target_node:
            md["pending_loop_back"] = {
                "loop_id": loop_id,
                "source_node": source_node,
                "target_node": target_node,
                "accumulated_cost": accumulated_cost,
            }
        self.state.metadata = md
        self.state_manager.save(self.state)

    async def approve_budget_increase(
        self, run_id: str, new_budget: float,
    ) -> str:
        """Operator-approved budget increase for a paused run (v2.47.0).

        Raises the loop's cost ceiling to new_budget (absolute — accumulated
        spend is carried, not reset), then resumes the run. Returns the
        resulting status. The recovery delegate calls this after the policy
        admits APPROVE_BUDGET_INCREASE.
        """
        recovery = self.persistence.load_for_recovery(run_id)
        if recovery is None:
            raise ValueError(f"No saved state found for run_id '{run_id}'")
        self.state = recovery.state
        self._step = self.state.step

        md = self.state.metadata or {}
        ctx = md.get("budget_context") or {}
        loop_id = ctx.get("loop_id")
        if not loop_id:
            raise ValueError(f"no budget_context for paused run {run_id}")

        # v2.47.0: persist the budget override so LoopEnforcer.check_budget
        # uses the operator-approved ceiling (effective_budget). The override
        # is an absolute ceiling — accumulated spend is carried, not reset.
        md = dict(self.state.metadata or {})
        md["budget_overrides"] = {
            **md.get("budget_overrides", {}),
            loop_id: new_budget,
        }
        self.state.metadata = md

        # Clear the pause markers and resume.
        self.state.status = "running"
        md = dict(self.state.metadata or {})
        md.pop("loop_budget_exceeded", None)
        md["budget_approved"] = {
            "loop_id": loop_id,
            "previous_budget": ctx.get("previous_budget", 0.0),
            "new_budget": new_budget,
            "accumulated_cost_at_pause": ctx.get("accumulated_cost", 0.0),
            "remaining_budget": new_budget - ctx.get("accumulated_cost", 0.0),
        }
        self.state.metadata = md
        self.state_manager.save(self.state)

        # Resume execution from the paused point.
        trace = await self.resume(run_id)
        resulting = self.state_manager.load(run_id)
        return resulting.status if resulting else "unknown"

    def _record_last_failure(
        self, failure_type, node_id: str, step_id: int,
        error: str, *, retryable: bool = False,
    ) -> None:
        """Persist durable last_failure metadata for recovery classification (#13).

        The recovery classifier + OperatorActionPolicy read this to determine
        FAILED_RETRYABLE vs FAILED_NON_RETRYABLE, the failed step for retry
        precision, and the failure_type for ROUTE_FALLBACK eligibility. Without
        this, failed runs fall through to CRASH_RECOVERABLE and retry/fallback
        actions can't target the right step.
        """
        md = dict(self.state.metadata or {})
        md["last_failure"] = {
            "failure_type": failure_type.value if hasattr(failure_type, "value") else str(failure_type),
            "node_id": node_id,
            "step_id": step_id,
            "error": error,
            "retryable": retryable,
        }
        self.state.metadata = md

    def _fail_chain(self, reason: str, details: list[str]) -> None:
        self.state.status = "failed"
        self.trace.add_event(
            TraceEvent(
                run_id=self.state.run_id,
                chain_id=self.state.chain_id,
                node_id="runtime",
                step_id=self._step,
                event_type=EventType.CHAIN_FAILED,
                actor=Actor.RUNTIME,
                decision=reason,
                reason_codes=details,
            )
        )
        self.trace.finalize("failed")

    def _compute_loop_cost(self, node_id: str) -> float:
        """Compute cumulative cost for the loop containing node_id.

        Prefers invocation ledger (durable accounting) when available.
        Falls back to trace events (audit surface) when ledger is empty.
        """
        loop = None
        for l in self.blueprint.loops:
            if node_id in l.path:
                loop = l
                break
        if loop is None:
            return 0.0

        # Primary: invocation ledger (durable accounting)
        # Check if ledger has invocation rows for loop nodes (not just cost > 0)
        # This handles the legitimate zero-cost case correctly.
        try:
            completed = self.state_manager.get_completed_steps(self.state.run_id)
            has_loop_invocations = any(
                nid in completed.values() for nid in loop.path
            )
            if has_loop_invocations:
                return self.state_manager.get_invocation_cost(
                    self.state.run_id, node_ids=loop.path,
                )
        except Exception:
            pass  # Fall through to trace

        # Fallback: trace events (audit surface)
        total = 0.0
        for event in self.trace.events:
            if (event.node_id in loop.path
                    and event.cost_usd is not None):
                total += event.cost_usd
        return total

    def _build_loop_payload(
        self, target_node: str, current_output: dict[str, Any]
    ) -> dict[str, Any]:
        """Build appropriate payload for a loop-back target node.

        The loop target needs the correct input schema, not the triggering
        node's output. We reconstruct from saved state outputs.
        """
        # For loops back to context_selector, rebuild from original inputs
        if target_node == "context_selector":
            return {
                "normalized_goal": self.state.outputs.get("goal_interpreter", {}).get("normalized_goal", {}),
                "task_plan": self.state.outputs.get("task_planner", {}).get("plan", {}),
                # Carry prior search context for dedup
                "prior_search_results": current_output.get("search_results", []),
            }
        # For loops back to task_planner
        if target_node == "task_planner":
            return {
                "normalized_goal": self.state.outputs.get("goal_interpreter", {}).get("normalized_goal", {}),
                "revision_context": current_output,
            }
        # Default: pass current output
        return current_output

    async def _execute_branches(
        self,
        branch_def: "BranchDef",
        selected_branches: list[str],
        parent_output: dict[str, Any],
        execution_order: list[str],
    ) -> dict[str, Any] | None:
        """Execute selected branches using BranchExecutor.

        Delegates parallel execution to BranchExecutor and translates
        the BranchExecutionReport into orchestrator state updates.
        """
        from nodechain.core.blueprint import BranchDef

        all_branch_names = list(branch_def.branches.keys())

        # Record routing decision in state
        self.state.routing_decisions.append({
            "from_node": branch_def.from_node,
            "selected": selected_branches,
            "skipped": [b for b in all_branch_names if b not in selected_branches],
            "available": all_branch_names,
        })

        # Initialize branch states
        for bname in all_branch_names:
            if bname not in selected_branches:
                self.state.branch_states[bname] = "skipped"
            else:
                self.state.branch_states[bname] = "pending"

        # ── Build node executor callback ──
        async def node_executor(
            node_id: str, payload: dict[str, Any], branch_name: str,
        ) -> BranchNodeResult:
            node = self._nodes.get(node_id)
            if node is None:
                return BranchNodeResult(
                    node_id=node_id, success=False,
                    error=f"Branch node '{node_id}' not registered",
                )

            # v2.40.1: allocate step BEFORE policy gate so memory-read
            # decisions get the correct step_id (was reversed before).
            invocation = await self.step_allocator.allocate(
                self.state.run_id, node_id, branch_name=branch_name,
            )
            captured_step = invocation.step_id

            self.state.step = captured_step
            self.state.current_node = node_id
            self.state.branch_states[branch_name] = "running"

            # Policy gate (after step allocation)
            policy_denied = self._check_policy_gate(node_id, node)
            if policy_denied:
                # Don't fail the branch — just skip this node
                return BranchNodeResult(
                    node_id=node_id, success=True, output={"policy_denied": policy_denied},
                )

            # Build envelope with captured step_id
            context = self._build_context(node_id)
            capabilities = self._build_capabilities(node_id)
            envelope = compile_envelope(
                run_id=self.state.run_id,
                chain_id=self.state.chain_id,
                node_id=node_id,
                step_id=captured_step,
                payload=payload,
                context=context,
                capabilities=capabilities,
            )

            response = await self._invoke_node(node, envelope)
            if not response.success:
                return BranchNodeResult(
                    node_id=node_id, success=False, error=response.error or "unknown",
                )

            # Update state (branch-local output)
            self.state.outputs[node_id] = response.output

            # Atomic write using captured step_id (not mutable self._step)
            self.persistence.commit_invocation_success(
                self.state,
                step_id=captured_step,
                node_id=node_id,
                branch_name=branch_name,
                event_type="branch_node_completed",
                event_payload={"node_id": node_id, "branch": branch_name, "step_id": captured_step},
            )

            return BranchNodeResult(node_id=node_id, success=True, output=response.output)

        # ── Find join def ──
        join_def = None
        for j in self.blueprint.joins:
            join_def = j
            break

        # ── Determine cancellation policy ──
        cancellation_policy = "allow_all"
        governance = getattr(self.blueprint, 'governance', None)
        if governance and isinstance(governance, dict):
            cancellation_policies = governance.get("cancellation_policies", {})
            if join_def and join_def.join_id in cancellation_policies:
                cancellation_policy = cancellation_policies[join_def.join_id]
            elif "default" in cancellation_policies:
                cancellation_policy = cancellation_policies["default"]

        # ── Execute via BranchExecutor ──
        bx = BranchExecutor(node_executor=node_executor)
        report = await bx.execute(
            branch_def=branch_def,
            selected_branches=selected_branches,
            parent_output=parent_output,
            join_def=join_def,
            cancellation_policy=cancellation_policy,
        )

        # ── Translate report to orchestrator state ──
        for evt in report.events:
            evt_type = evt["type"]
            metadata = evt.get("metadata", {})
            node_id = evt.get("node_id", branch_def.from_node)

            if evt_type == "routing_decision":
                self._emit(
                    EventType.ROUTING_DECISION,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="branch_selected",
                    metadata=metadata,
                )
            elif evt_type == "branch_skipped":
                self._emit(
                    EventType.NODE_SKIPPED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision=f"branch_{metadata.get('branch', '')}_skipped",
                    metadata=metadata,
                )
            elif evt_type == "branch_started":
                self.state.branch_states[metadata.get("branch", "")] = "running"
                self._emit(
                    EventType.BRANCH_STARTED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision=f"branch_{metadata.get('branch', '')}_started",
                    metadata=metadata,
                )
            elif evt_type == "branch_completed":
                self.state.branch_states[metadata.get("branch", "")] = "completed"
                self._emit(
                    EventType.BRANCH_COMPLETED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision=f"branch_{metadata.get('branch', '')}_completed",
                    metadata=metadata,
                )
            elif evt_type == "branch_failed":
                self.state.branch_states[metadata.get("branch", "")] = "failed"
                self._emit(
                    EventType.BRANCH_FAILED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision=f"branch_{metadata.get('branch', '')}_failed",
                    metadata=metadata,
                )
            elif evt_type == "branch_cancelled":
                self.state.branch_states[metadata.get("branch", "")] = "cancelled"
                self._emit(
                    EventType.BRANCH_CANCELLED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision=f"branch_{metadata.get('branch', '')}_cancelled",
                    metadata=metadata,
                )
            elif evt_type in ("cancel_on_first_enforced", "first_success_only_enforced"):
                self._emit(
                    EventType.BRANCH_FIRST_SELECTED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision=evt_type,
                    metadata=metadata,
                )
            elif evt_type == "join_blocked":
                self._emit(
                    EventType.JOIN_BLOCKED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="join_blocked",
                    metadata=metadata,
                )
            elif evt_type == "join_partial":
                self._emit(
                    EventType.JOIN_PARTIAL,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="join_partial",
                    metadata=metadata,
                )
            elif evt_type == "join_ready":
                self._emit(
                    EventType.JOIN_READY,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="join_ready",
                    metadata=metadata,
                )
            elif evt_type == "join_completed":
                self._emit(
                    EventType.JOIN_COMPLETED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="join_completed",
                    metadata=metadata,
                )
            elif evt_type == "ignore_late_enforced":
                self._emit(
                    EventType.BRANCH_FIRST_SELECTED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="ignore_late_enforced",
                    metadata=metadata,
                )
                # Mark ignored branches in state
                for bname in metadata.get("ignored_late_branches", []):
                    if bname in self.state.branch_states:
                        self.state.branch_states[bname] = "ignored_late"
            elif evt_type == "first_branch_selected":
                self._emit(
                    EventType.BRANCH_FIRST_SELECTED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="first_branch_selected",
                    metadata=metadata,
                )
                for bname in metadata.get("ignored_late_branches", []):
                    if bname in self.state.branch_states:
                        self.state.branch_states[bname] = "ignored_late"

        # Update state from report (even if blocked — for post-mortem)
        self.state.branch_outputs.update({
            bname: bout.get("outputs", {})
            for bname, bout in report.branch_outputs.items()
            if not bout.get("skipped", False)
        })

        # Skipped nodes
        for bname in report.skipped_branches:
            if bname in branch_def.branches:
                self.state.skipped_nodes.append({
                    "branch": bname,
                    "nodes": branch_def.branches[bname],
                    "reason": "not_selected",
                })

        # Join inputs
        if join_def:
            self.state.join_inputs[join_def.join_id] = {
                bname: bout for bname, bout in report.branch_outputs.items()
                if not bout.get("skipped", False)
            }

        # Handle blocked join (after state update for post-mortem)
        if report.blocked:
            self._fail_chain("join_blocked", [report.block_reason])
            return None

        return report.merged_output

    # v2.74: Node event emission methods (_emit_all_contracts_validated,
    # _emit_contract_validated, _emit_model_requirements_evaluation,
    # _emit_node_detail_events) extracted to NodeEventEmitterMixin.
    # See node_event_emitter.py.
    #
    # v2.93: per-node output validation (schema + semantic) extracted to
    # NodeOutputValidationController. See node_output_validation_controller.py.

    # ── Policy Enforcement ──────────────────────────────────────

    def _check_policy_gate(
        self, node_id: str, node: BaseNode
    ) -> str | None:
        """Evaluate policies for a node. Returns denial reason or None.

        v2.96: delegates to PolicyGateController. Behavior unchanged.
        """
        return self._policy_gate_controller.check(
            node_id, node,
            run_id=self.state.run_id,
            step_id=self._step,
            chain_id=self.blueprint.chain_id,
        )

    def _get_review_timeout(self) -> int:
        """Get review timeout from blueprint gates."""
        for gate in self.blueprint.gates:
            return gate.timeout_minutes
        return 30  # Default
