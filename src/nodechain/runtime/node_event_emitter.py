"""v2.74: Node Event Emission — extracted from orchestrator.py.

Contains the trace-event emission logic for node-level events:
- Contract validation events
- Model call + model_requirements evaluation events
- Search/tool/memory detail events
- Side-effect observed/declared matching

Extracted as a mixin to preserve self. references. Zero behavioral change.
"""
from __future__ import annotations

import logging
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.trace import EventType, Actor
from nodechain.nodes.base_node import BaseNode

logger = logging.getLogger(__name__)


class NodeEventEmitterMixin:
    """v2.74: Extracted node-event-emission methods from Orchestrator.

    These methods were physically in orchestrator.py (lines 2288-2760).
    Moved here to reduce orchestrator size without behavioral change.
    The Orchestrator class inherits this mixin; all self. references work
    as before because the mixin is mixed into Orchestrator.
    """

    def _emit_all_contracts_validated(self) -> None:
        """Emit a single event confirming all contracts passed load-time validation."""
        node_ids = list(self._nodes.keys())
        self._emit(
            EventType.CONTRACT_VALIDATED,
            node_id="runtime",
            decision="all_contracts_valid",
            reason_codes=[f"validated_{len(node_ids)}_node_contracts"],
            metadata={"nodes": node_ids},
        )

    def _emit_contract_validated(
        self, node_id: str, node: BaseNode
    ) -> None:
        """Emit per-node contract validation event before invocation."""
        entry = node.manifest.contract.entry
        exit_c = node.manifest.contract.exit
        entry_type = entry.input_type.value if hasattr(entry.input_type, 'value') else str(entry.input_type)
        exit_type = exit_c.output_type.value if hasattr(exit_c.output_type, 'value') else str(exit_c.output_type)
        self._emit(
            EventType.CONTRACT_VALIDATED,
            node_id=node_id,
            decision="contract_pre_validated",
            metadata={
                "entry_type": entry_type,
                "exit_type": exit_type,
                "schema_ref": entry.schema_ref,
            },
        )

    def _emit_model_requirements_evaluation(
        self,
        node_id: str,
        node: BaseNode,
        response: EnvelopeResponse,
        configured_max_tokens: int | None = None,
    ) -> None:
        """v2.68: evaluate declared model_requirements against what is known
        about the model call, and emit a MODEL_REQUIREMENTS_EVALUATED trace event.

        v2.68 enforcement posture: declare, evaluate what is known, trace, warn on
        unknown. Does NOT block the run. Hard enforcement + capability profile
        registry deferred to v2.69+.
        """
        req = node.manifest.contract.requirements.model_requirements
        if req is None or req.is_empty():
            return  # legacy node — no declared floor

        # Resolve model name from the adapter (preferred) or response metadata.
        model_selected = ""
        try:
            adapter = getattr(self, "_model_adapter", None)
            if adapter is not None and hasattr(adapter, "model"):
                model_selected = adapter.model or ""
        except Exception:
            pass
        if not model_selected:
            rmeta = getattr(response, "metadata", None) or {}
            if isinstance(rmeta, dict) and rmeta.get("model"):
                model_selected = rmeta["model"]

        known: dict[str, Any] = {}
        unknown_reasons: list[str] = []
        evaluation_status = "unknown"

        if req.min_output_tokens is not None and configured_max_tokens is not None:
            satisfied = configured_max_tokens >= req.min_output_tokens
            known["configured_output_tokens"] = configured_max_tokens
            known["min_output_tokens_satisfied"] = satisfied
            evaluation_status = "satisfied" if satisfied else "unsatisfied"

        if req.structured_output_required and "structured_output" not in known:
            unknown_reasons.append("no_model_capability_profile")
        if req.json_schema_adherence == "required" and "json_schema_adherence" not in known:
            if "no_model_capability_profile" not in unknown_reasons:
                unknown_reasons.append("no_model_capability_profile")

        if unknown_reasons:
            evaluation_status = "unknown"

        # Warn-only mode (v2.68): the trace event IS the warning. Hard
        # enforcement (block the run) is deferred to v2.69+ with the capability
        # profile registry. Do not raise or block here.

        self._emit(
            EventType.MODEL_REQUIREMENTS_EVALUATED,
            node_id=node_id,
            actor=Actor.RUNTIME,
            decision="model_requirements_evaluated",
            metadata={
                "contract_id": node.manifest.contract.contract_id,
                "model_selected": model_selected,
                "requirements": req.to_trace_dict(),
                "evaluation_status": evaluation_status,
                "known_capabilities": known,
                "unknown_reasons": unknown_reasons,
                "enforcement_mode": "warn_only",
            },
        )

    def _emit_node_detail_events(
        self,
        node_id: str,
        node: BaseNode,
        response: EnvelopeResponse,
        envelope: InvocationEnvelope | None = None,
    ) -> bool:
        """Emit additional trace events based on what the node did.

        v2.35.3: returns False if a CONTRACT_VIOLATION was detected during
        side-effect recording. Callers must check and _fail_chain on False.
        Returns True otherwise.
        """
        output = response.output

        # Model-backed nodes: emit model call event
        req = node.manifest.contract.requirements
        is_model_node = req.model_required or node_id in {
            "goal_interpreter", "task_planner", "context_selector",
            "source_quality_evaluator", "evidence_synthesizer",
            "claim_validator", "risk_classifier", "response_generator",
        }
        if is_model_node:
            self._emit(
                EventType.MODEL_CALLED,
                node_id=node_id,
                actor=Actor.NODE,
                decision="model_invoked",
                cost_usd=response.cost_usd,
                latency_ms=response.latency_ms,
                metadata={
                    "model_required": True,
                    "output_type": response.output_type,
                    "usage": response.usage if hasattr(response, 'usage') else {},
                    "stop_reason": response.stop_reason if hasattr(response, 'stop_reason') else "",
                    "raw_output_size": response.raw_output_size if hasattr(response, 'raw_output_size') else 0,
                },
            )
            # v2.68: evaluate model_requirements declared on the node contract.
            configured = None
            try:
                adapter = getattr(self, "_model_adapter", None)
                if adapter is not None and hasattr(adapter, "default_max_tokens"):
                    configured = adapter.default_max_tokens
            except Exception:
                configured = None
            self._emit_model_requirements_evaluation(
                node_id=node_id,
                node=node,
                response=response,
                configured_max_tokens=configured,
            )

        # Search tool: emit tool call events and complete side-effect journal
        _declared_types = self._get_declared_se_types(node_id)
        if node_id == "search_tool" or node_id.endswith("_search"):
            adapters_called = output.get("adapters_called", [])
            adapters_failed = output.get("adapters_failed", [])
            import hashlib as _hl
            import json as _json

            if isinstance(adapters_called, list):
                for adapter_name in adapters_called:
                    self._emit(
                        EventType.TOOL_CALLED,
                        node_id=node_id,
                        actor=Actor.NODE,
                        decision="external_api_called",
                        metadata={"adapter": adapter_name},
                    )

                    search_queries = (envelope.payload or {}).get("search_queries", []) if envelope else []
                    from nodechain.core.side_effect_utils import compute_side_effect_request_hash, compute_side_effect_response_hash
                    req_hash = "unknown"
                    for sq in search_queries:
                        targets = sq.get("target_adapters", [])
                        if adapter_name in targets or not targets:
                            terms = sq.get("terms", [])
                            if isinstance(terms, str):
                                terms = [terms]
                            operation = {
                                "terms": sorted(terms),
                                "max": sq.get("max_results", 10),
                                "filters": sq.get("filters", {}),
                            }
                            req_hash = compute_side_effect_request_hash(
                                "external_call", node_id, "", operation=operation,
                            )
                            break

                    op_ikey = f"search:{adapter_name}:{req_hash}"
                    _canonical = self._assert_declared_side_effect(
                        node_id, "external_call", idempotency_key=op_ikey,
                    )
                    if _canonical is None:
                        self._emit(
                            EventType.CONTRACT_VIOLATION,
                            node_id=node_id,
                            decision="undeclared_side_effect",
                            metadata={
                                "observed_type": "external_call",
                                "adapter": adapter_name,
                                "ikey": op_ikey,
                            },
                        )
                        return False

                    resp_hash_val = ""
                    try:
                        resp_hash_val = compute_side_effect_response_hash(
                            output, adapter_name,
                        )
                    except Exception:
                        pass

                    self._journal_one(
                        op_ikey, node_id, _canonical, envelope,
                        operation={
                            "adapter": adapter_name,
                            "request_hash": req_hash,
                            "response_hash": resp_hash_val,
                        },
                    )

            if isinstance(adapters_failed, list):
                for failure in adapters_failed:
                    adapter_name = failure.get("adapter", "unknown")
                    failure_type = failure.get("failure_type", "unknown")
                    retryable = failure.get("retryable", False)
                    attempts = failure.get("attempts", 1)
                    reason_code = failure.get("reason_code", "")
                    dispatch_attempted = reason_code != "LANE_ADMISSION_REJECTED"
                    self._emit(
                        EventType.TOOL_RESULT_RECEIVED,
                        node_id=node_id,
                        actor=Actor.NODE,
                        decision=f"adapter_{failure_type}",
                        reason_codes=[reason_code] if reason_code else ([f"SEARCH_{failure_type.upper()}"] if failure_type != "unknown" else []),
                        metadata={
                            "adapter": adapter_name,
                            "error": failure.get("error", ""),
                            "retryable": retryable,
                            "attempts": attempts,
                            "attempt_number": attempts,
                            "dispatch_attempted": dispatch_attempted,
                            "operation_digest": failure.get("query_hash", failure.get("request_hash", "")),
                        },
                    )

            # Detect prior fault failures for this node from the trace.
            # When a node_failed or TOOL_RESULT_RECEIVED event with a
            # recognized fault reason code exists for this node, emit
            # retry lifecycle evidence (SCHEDULED before RECOVERED).
            # These events reference the original failure event ID.
            REASON_CODES_WITH_RECOVERY = {
                "SEARCH_TIMEOUT_AFTER_DISPATCH",
                "SEARCH_PROVENANCE_MALFORMED",
            }
            prior_fault_events = [
                ev for ev in self.trace.events
                if ev.node_id == node_id
                and ev.reason_codes
                and any(
                    rc == known or rc.startswith(known + ":")
                    for rc in ev.reason_codes
                    for known in REASON_CODES_WITH_RECOVERY
                )
            ]
            for orig in prior_fault_events:
                # Emit SEARCH_RETRY_SCHEDULED at the retry-success boundary.
                # While this is emitted on the success path (the emitter only
                # runs on success), it faithfully records that a retry was
                # scheduled after the original failure.
                self._emit(
                    EventType.TOOL_RESULT_RECEIVED,
                    node_id=node_id,
                    actor=Actor.NODE,
                    decision="search_retry_scheduled",
                    reason_codes=["SEARCH_RETRY_SCHEDULED"],
                    metadata={
                        "original_failure_event_id": orig.event_id,
                        "retry_reason": orig.reason_codes[0] if orig.reason_codes else "",
                    },
                )
                # Emit SEARCH_RETRY_RECOVERED.
                self._emit(
                    EventType.TOOL_RESULT_RECEIVED,
                    node_id=node_id,
                    actor=Actor.NODE,
                    decision="search_retry_recovered",
                    reason_codes=["SEARCH_RETRY_RECOVERED"],
                    metadata={
                        "original_failure_event_id": orig.event_id,
                        "recovery_attempt_number": 2,
                        "recovery_outcome": "recovered",
                        "final_node_outcome": "succeeded",
                    },
                )

            # Detect partial result sets in the node output.
            # The fixture adapter marks partial results with _partial metadata.
            results = output.get("results", [])
            if isinstance(results, list):
                partial_results = [
                    r for r in results
                    if isinstance(r, dict)
                    and isinstance(r.get("raw_data"), dict)
                    and r["raw_data"].get("_partial") is True
                ]
                if partial_results:
                    r = partial_results[0]["raw_data"]
                    self._emit(
                        EventType.TOOL_RESULT_RECEIVED,
                        node_id=node_id,
                        actor=Actor.NODE,
                        decision="partial_result_set",
                        reason_codes=["SEARCH_PARTIAL_RESULT_SET"],
                        metadata={
                            "returned_count": r.get("_returned_count", len(partial_results)),
                            "total_available": r.get("_total_available", 0),
                            "unavailable_source_ids": r.get("_unavailable_source_ids", []),
                            "incompleteness_reason": r.get("_incompleteness_reason", ""),
                            "attempt_number": 1,
                            "dispatch_attempted": True,
                            "operation_digest": "",
                        },
                    )

        # v2.42.0: Tool access events
        if node_id != "search_tool" and not node_id.endswith("_search"):
            _observed_tools = set()
            if "tool_used" in output:
                tool_name = output["tool_used"]
                _observed_tools.add(tool_name)
            if "tools_called" in output and isinstance(output["tools_called"], list):
                _observed_tools.update(output["tools_called"])

            for tool_name in _observed_tools:
                _canonical = self._assert_declared_side_effect(
                    node_id, "external_call", idempotency_key=f"tool:{tool_name}",
                )
                if _canonical is None:
                    self._emit(
                        EventType.CONTRACT_VIOLATION,
                        node_id=node_id,
                        decision="undeclared_side_effect",
                        metadata={"observed_type": "external_call", "tool": tool_name},
                    )
                    return False

        # v2.34.0: Observe and record side effects from output
        _observed_se_types = set()
        if output.get("side_effects_observed"):
            _observed_se_types.update(output["side_effects_observed"])
        if output.get("_side_effect_types"):
            _observed_se_types.update(output["_side_effect_types"])

        # v2.35.0: Check for side effects in output that weren't pre-journaled
        if _observed_se_types:
            for se_type in _observed_se_types:
                _canonical = self._assert_declared_side_effect(
                    node_id, se_type, idempotency_key=f"observed:{se_type}",
                )
                if _canonical is None:
                    self._emit(
                        EventType.CONTRACT_VIOLATION,
                        node_id=node_id,
                        decision="undeclared_side_effect",
                        metadata={
                            "observed_type": se_type,
                            "declared_types": _declared_types,
                        },
                    )
                    return False

        # Memory read exposure (v2.41.0)
        if output.get("memory_exposed") or output.get("memory_read_used"):
            memory_items = output.get("memory_items_exposed", [])
            if isinstance(memory_items, list) and memory_items:
                self._emit(
                    EventType.MEMORY_READ_EXPOSED,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="memory_exposed",
                    metadata={
                        "items_count": len(memory_items),
                        "item_subjects": [m.get("subject", "") for m in memory_items[:5]],
                    },
                )

        # Human review
        if output.get("human_review_requested") or output.get("review_required"):
            self._emit(
                EventType.HUMAN_REVIEW_REQUESTED,
                node_id=node_id,
                actor=Actor.NODE,
                decision="review_required",
                metadata={
                    "risk_level": output.get("risk_level", ""),
                    "review_reason": output.get("review_reason", ""),
                },
            )

        # Source quality: emit routing decision
        if node_id == "source_quality_evaluator":
            loop_required = output.get("loop_required", False)
            self._emit(
                EventType.ROUTING_DECISION,
                node_id=node_id,
                actor=Actor.NODE,
                decision="loop_required" if loop_required else "proceed",
                metadata={
                    "loop_required": loop_required,
                    "quality_decision": output.get("quality_summary", {}).get("set_quality_decision", "unknown"),
                    "avg_score": output.get("quality_summary", {}).get("average_score", 0),
                },
            )

        # Risk classifier: emit routing decision
        if node_id == "risk_classifier":
            risk_level = output.get("risk_level", "UNKNOWN")
            review_required = output.get("review_required", False)
            self._emit(
                EventType.ROUTING_DECISION,
                node_id=node_id,
                actor=Actor.NODE,
                decision="review_required" if review_required else "proceed",
                metadata={
                    "risk_level": risk_level,
                    "review_required": review_required,
                },
            )

        # v2.76: emit sandbox/code-execution events from a node's structured
        # sandbox_event_log (currently produced by sandbox_test_runner). The
        # node never writes trace events directly — the runtime owns emission.
        self._emit_sandbox_event_log(node_id, output)

        return True

    # v2.76: mapping from sandbox_event_log entry types to EventType constants.
    # Kept as a class attribute so it is easy to audit and extend.
    _SANDBOX_EVENT_TYPE_MAP = {
        "sandbox_workspace_requested": EventType.SANDBOX_WORKSPACE_REQUESTED,
        "sandbox_workspace_created": EventType.SANDBOX_WORKSPACE_CREATED,
        "patch_apply_started": EventType.PATCH_APPLY_STARTED,
        "patch_apply_succeeded": EventType.PATCH_APPLY_SUCCEEDED,
        "patch_apply_failed": EventType.PATCH_APPLY_FAILED,
        "test_command_authorized": EventType.TEST_COMMAND_AUTHORIZED,
        "test_command_blocked": EventType.TEST_COMMAND_BLOCKED,
        "code_execution_started": EventType.CODE_EXECUTION_STARTED,
        "code_execution_completed": EventType.CODE_EXECUTION_COMPLETED,
        "code_execution_failed": EventType.CODE_EXECUTION_FAILED,
        "code_execution_timed_out": EventType.CODE_EXECUTION_TIMED_OUT,
        "sandbox_output_capped": EventType.SANDBOX_OUTPUT_CAPPED,
        "sandbox_cleanup_started": EventType.SANDBOX_CLEANUP_STARTED,
        "sandbox_cleanup_succeeded": EventType.SANDBOX_CLEANUP_SUCCEEDED,
        "sandbox_cleanup_failed": EventType.SANDBOX_CLEANUP_FAILED,
        "test_result_classified": EventType.TEST_RESULT_CLASSIFIED,
    }

    def _emit_sandbox_event_log(self, node_id: str, output: dict[str, Any]) -> None:
        """v2.76: consume a node's sandbox_event_log and emit EventType constants.

        Nodes that perform governed sandbox execution (currently
        sandbox_test_runner) return a ``sandbox_event_log`` list of structured
        event intents. This method maps each entry to its canonical EventType
        constant and emits it via self._emit, preserving the runtime's
        authority over the trace. Unknown event types are skipped (forward-
        compatible) rather than raising.
        """
        log = output.get("sandbox_event_log")
        if not log or not isinstance(log, list):
            return
        type_map = self._SANDBOX_EVENT_TYPE_MAP
        for entry in log:
            if not isinstance(entry, dict):
                continue
            raw_type = entry.get("event_type")
            event_type = type_map.get(raw_type) if isinstance(raw_type, str) else None
            if event_type is None:
                continue
            self._emit(
                event_type,
                node_id=node_id,
                actor=Actor.NODE,
                decision=raw_type,
                metadata=entry.get("metadata", {}),
            )
