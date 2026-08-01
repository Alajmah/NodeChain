"""v2.96: Policy Gate Controller — extracted from Orchestrator.

Internal implementation detail. Orchestrator remains the public facade; this
controller holds the per-node policy-gate evaluation logic that was previously
inline in Orchestrator._check_policy_gate().

Responsibilities:
  - Normalize node provenance (derive _module_path for digest)
  - Call policy_gate.check(node_id, node)
  - Emit POLICY_EVALUATED trace events for each evaluated policy
  - Process PACKAGE_TRUST results (record durable decision, emit trace events)
  - Process TOOL_ACCESS results (record durable decisions per tool, emit events)
  - Process ADAPTER_ACCESS results (record durable decisions per adapter, emit)
  - Process MEMORY_READ results (record durable decision, update the
    orchestrator's _memory_read_allows dict, emit trace events)
  - On denial: process SIDE_EFFECT_BLOCKED (record durable attempts, emit events)
  - Return denial_reason string or None

The Orchestrator retains:
  - The _memory_read_allows dict (the controller mutates the passed-in dict
    in place, matching the original `self._memory_read_allows[...] = ...`).
  - The _nodes registry (passed in so the controller can look up declared side
    effects, exactly as the original did via self._nodes.get(node_id)).

Emission fidelity:
  All trace events go through the Orchestrator's bound _emit callable
  (emit_fn), which both appends to the trace AND persists to the event log —
  matching the original behavior where every _check_policy_gate emission used
  self._emit(...). No direct trace.add_event calls exist in this method.

Behavior is identical to the pre-extraction code — this is a pure move
refactor. v2.95 characterization tests must pass unchanged.
"""
from __future__ import annotations

from typing import Any, Callable

from nodechain.core.trace import Actor, EventType
from nodechain.nodes.base_node import BaseNode
from nodechain.runtime.policy_gate import PolicyGate


class PolicyGateController:
    """Evaluates policy gates for a node and records durable decisions.

    Extracted from Orchestrator._check_policy_gate() in v2.96.
    """

    def __init__(
        self,
        policy_gate: PolicyGate,
        emit_fn: Callable[..., None],
        state_manager: Any,
        nodes: dict[str, BaseNode],
        memory_read_allows: dict[tuple[int, str], str],
    ) -> None:
        self.policy_gate = policy_gate
        # emit_fn is the Orchestrator's bound _emit method — it both appends
        # to the trace AND persists to the event log.
        self._emit = emit_fn
        self.state_manager = state_manager
        self._nodes = nodes
        # Mutated in place by the MEMORY_READ path so the orchestrator's dict
        # stays authoritative for downstream read-allow lookups.
        self._memory_read_allows = memory_read_allows

    def check(
        self,
        node_id: str,
        node: BaseNode,
        run_id: str,
        step_id: int,
        chain_id: str,
    ) -> str | None:
        """Evaluate policies for a node. Returns denial reason or None.

        Args:
            node_id: The node being evaluated.
            node: The BaseNode instance (mutated: _module_path is derived).
            run_id: Current run ID (for durable decision records).
            step_id: Current step ID (for durable decision records).
            chain_id: Chain ID (for side-effect attempt records).

        Returns:
            The denial reason string if the gate denied the node, else None.
        """
        # v2.44.1: normalize provenance — derive module_path for digest,
        # but do NOT assume missing provenance means built_in.
        # BaseNode defaults _trust_level="built_in" and _node_origin="built_in"
        # at class level, so nodes loaded through the loader with explicit
        # trust values will override those. Nodes that don't get loader
        # normalization keep the class default, which IS "built_in" —
        # but we verify this is the actual class default, not a missing attr.
        import inspect as _inspect
        # v2.44.1: always derive _module_path for digest (even built-ins)
        if not getattr(node, '_module_path', ''):
            try:
                node._module_path = _inspect.getfile(type(node))
            except (TypeError, OSError):
                node._module_path = ""

        result = self.policy_gate.check(node_id, node)

        # Emit trace events for each evaluated policy
        for ep in result.evaluated_policies:
            ptype = ep["type"]
            decision = ep["decision"]
            rule_ids = ep.get("rule_ids", [])

            if decision == "denied":
                self._emit(
                    EventType.POLICY_EVALUATED, node_id,
                    actor=Actor.POLICY_ENGINE,
                    decision=f"{ptype}_denied",
                    reason_codes=[result.denial_reason or ""],
                )
            elif decision == "allowed" or decision == "ok":
                metadata = {"decisions": rule_ids}
                if ptype == "trust_level":
                    metadata["trust_level"] = ep.get("trust_level", "verified")
                if ptype == "cost_limit":
                    metadata["accumulated"] = ep.get("accumulated", 0)
                    metadata["budget"] = ep.get("budget", 1.0)
                self._emit(
                    EventType.POLICY_EVALUATED, node_id,
                    actor=Actor.POLICY_ENGINE,
                    decision=f"{ptype}_{'allowed' if ptype != 'trust_level' else 'ok'}",
                    metadata=metadata,
                )
            elif decision == "requires_approval":
                self._emit(
                    EventType.POLICY_EVALUATED, node_id,
                    actor=Actor.POLICY_ENGINE,
                    decision=f"{ptype}_requires_approval",
                    reason_codes=[result.approval_required or ""],
                )

        # v2.44.0: process PACKAGE_TRUST gate result — record durable decision
        trust_eval = next(
            (ep for ep in result.evaluated_policies
             if ep.get("type") == "package_trust"),
            None,
        )
        if trust_eval:
            import uuid as _pt_uuid
            from datetime import datetime as _pt_dt, timezone as _pt_tz
            from nodechain.core.contract import is_privileged_node
            now_iso = _pt_dt.now(_pt_tz.utc).isoformat()
            pt_decision = trust_eval["decision"]
            decision_id = str(_pt_uuid.uuid4())
            observed_trust = trust_eval.get("observed_trust_level", "built_in")
            required_trust = trust_eval.get("required_trust_level", "trusted")
            origin = trust_eval.get("origin", "built_in")
            is_priv = trust_eval.get("is_privileged", False)

            # v2.44.0: derive package digest from module_path
            import hashlib as _pt_hl
            module_path = getattr(node, '_module_path', '')
            package_digest = "unknown"
            if module_path:
                try:
                    with open(module_path, 'rb') as _f:
                        package_digest = _pt_hl.sha256(_f.read()).hexdigest()[:16]
                except (OSError, IOError):
                    pass

            # Determine trust_source
            trust_source = "built_in_default"
            if origin == "local_registry":
                trust_source = "local_trust_marker"
            elif origin == "remote":
                trust_source = "registry_metadata"
            elif observed_trust == "local_trusted":
                trust_source = "local_trust_marker"

            self.state_manager.record_package_trust_decision({
                "decision_id": decision_id,
                "run_id": run_id,
                "step_id": step_id,
                "node_id": node_id,
                "package_name": node_id,
                "package_version": getattr(node.manifest, 'version', '1.0.0'),
                "package_digest": package_digest,
                "origin": origin,
                "observed_trust_level": observed_trust,
                "required_trust_level": required_trust,
                "signature_status": "not_required" if origin == "built_in" else "not_verified",
                "lockfile_status": "not_checked",
                "is_privileged": is_priv,
                "trust_source": trust_source,
                "decision": "allow" if pt_decision == "allowed" else "deny",
                "reason": "" if pt_decision == "allowed" else (result.denial_reason or ""),
                "created_at": now_iso,
            })

            if pt_decision == "allowed":
                self._emit(
                    EventType.PACKAGE_TRUST_ALLOWED, node_id,
                    actor=Actor.RUNTIME,
                    decision="package_trust_allowed",
                    metadata={
                        "decision_id": decision_id,
                        "origin": origin,
                        "observed_trust_level": observed_trust,
                        "required_trust_level": required_trust,
                        "is_privileged": is_priv,
                        "package_digest": package_digest,
                        "trust_source": trust_source,
                    },
                )
            else:
                self._emit(
                    EventType.PACKAGE_TRUST_DENIED, node_id,
                    actor=Actor.RUNTIME,
                    decision="package_trust_denied",
                    reason_codes=[result.denial_reason or ""],
                    metadata={
                        "decision_id": decision_id,
                        "origin": origin,
                        "observed_trust_level": observed_trust,
                        "required_trust_level": required_trust,
                        "is_privileged": is_priv,
                        "package_digest": package_digest,
                        "trust_source": trust_source,
                    },
                )

        # v2.42.0: process TOOL_ACCESS gate result — record durable decisions
        ta_eval = next(
            (ep for ep in result.evaluated_policies
             if ep.get("type") == "tool_access"),
            None,
        )
        if ta_eval:
            import uuid as _ta_uuid
            from datetime import datetime as _ta_dt, timezone as _ta_tz
            now_iso = _ta_dt.now(_ta_tz.utc).isoformat()
            ta_decision = ta_eval["decision"]
            policy_id = ta_eval.get("policy_id", "")
            rule_id = ta_eval.get("rule_id", "")
            tools = ta_eval.get("tools_required", [])
            allowed = ta_eval.get("allowed_tools", [])

            # v2.42.1: collect durable decision IDs for trace binding
            durable_decision_ids: list[str] = []
            for tool_name in tools:
                decision_id = str(_ta_uuid.uuid4())
                durable_decision_ids.append(decision_id)
                is_allowed = tool_name in allowed and ta_decision == "allowed"
                self.state_manager.record_tool_access_decision({
                    "decision_id": decision_id,
                    "run_id": run_id,
                    "step_id": step_id,
                    "node_id": node_id,
                    "tool_name": tool_name,
                    "policy_id": policy_id,
                    "rule_id": rule_id,
                    "decision": "allow" if is_allowed else "deny",
                    "reason": "" if is_allowed else (result.denial_reason or ""),
                    "created_at": now_iso,
                })

            # v2.42.1: trace events reference durable decision IDs
            if ta_decision == "allowed":
                self._emit(
                    EventType.TOOL_ACCESS_ALLOWED, node_id,
                    actor=Actor.RUNTIME,
                    decision="tool_access_allowed",
                    metadata={
                        "decision_ids": durable_decision_ids,
                        "tools": tools,
                        "allowed_tools": allowed,
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                    },
                )
            else:
                self._emit(
                    EventType.TOOL_ACCESS_DENIED, node_id,
                    actor=Actor.RUNTIME,
                    decision="tool_access_denied",
                    reason_codes=[result.denial_reason or ""],
                    metadata={
                        "decision_ids": durable_decision_ids,
                        "tools": tools,
                        "allowed_tools": allowed,
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                        "ungranted": ta_eval.get("ungranted_tools", []),
                    },
                )

        # v2.43.0: process ADAPTER_ACCESS gate result — record durable decisions
        aa_eval = next(
            (ep for ep in result.evaluated_policies
             if ep.get("type") == "adapter_access"),
            None,
        )
        if aa_eval:
            import uuid as _aa_uuid
            from datetime import datetime as _aa_dt, timezone as _aa_tz
            now_iso = _aa_dt.now(_aa_tz.utc).isoformat()
            aa_decision = aa_eval["decision"]
            policy_id = aa_eval.get("policy_id", "")
            rule_id = aa_eval.get("rule_id", "")
            adapters = aa_eval.get("adapters_required", [])
            allowed = aa_eval.get("allowed_adapters", [])
            # v2.43.2: split allow/deny decision IDs for unambiguous trace binding
            aa_allow_ids: list[str] = []
            aa_deny_ids: list[str] = []

            for adapter_name in adapters:
                decision_id = str(_aa_uuid.uuid4())
                is_allowed = adapter_name in allowed and aa_decision == "allowed"
                self.state_manager.record_adapter_access_decision({
                    "decision_id": decision_id,
                    "run_id": run_id,
                    "step_id": step_id,
                    "node_id": node_id,
                    "adapter_type": "search",
                    "adapter_name": adapter_name,
                    "tool_name": "search",
                    "policy_id": policy_id,
                    "rule_id": rule_id,
                    "decision": "allow" if is_allowed else "deny",
                    "reason": "" if is_allowed else (result.denial_reason or ""),
                    "created_at": now_iso,
                })
                if is_allowed:
                    aa_allow_ids.append(decision_id)
                else:
                    aa_deny_ids.append(decision_id)

            # v2.43.2: ADAPTER_ACCESS_ALLOWED carries only allow_decision_ids
            if aa_decision == "allowed":
                self._emit(
                    EventType.ADAPTER_ACCESS_ALLOWED, node_id,
                    actor=Actor.RUNTIME,
                    decision="adapter_access_allowed",
                    metadata={
                        "allow_decision_ids": aa_allow_ids,
                        "deny_decision_ids": aa_deny_ids,
                        "adapters": adapters,
                        "allowed_adapters": allowed,
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                    },
                )
            else:
                self._emit(
                    EventType.ADAPTER_ACCESS_DENIED, node_id,
                    actor=Actor.RUNTIME,
                    decision="adapter_access_denied",
                    reason_codes=[result.denial_reason or ""],
                    metadata={
                        "allow_decision_ids": aa_allow_ids,
                        "deny_decision_ids": aa_deny_ids,
                        "adapters": adapters,
                        "allowed_adapters": allowed,
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                        "ungranted": aa_eval.get("ungranted_adapters", []),
                    },
                )

        # v2.40.0: process MEMORY_READ gate result
        mr_eval = next(
            (ep for ep in result.evaluated_policies
             if ep.get("type") == "memory_read"),
            None,
        )
        if mr_eval:
            import uuid as _mrd_uuid
            from datetime import datetime as _mrd_dt, timezone as _mrd_tz
            decision_id = str(_mrd_uuid.uuid4())
            mr_decision = mr_eval["decision"]  # allowed / denied / requires_approval
            policy_id = mr_eval.get("policy_id", "")
            rule_id = mr_eval.get("rule_id", "")

            # Record durable decision
            self.state_manager.record_memory_read_decision({
                "decision_id": decision_id,
                "run_id": run_id,
                "step_id": step_id,
                "node_id": node_id,
                "policy_id": policy_id,
                "rule_id": rule_id,
                "decision": "allow" if mr_decision == "allowed" else "deny",
                "purpose": "node_context",
                "source": "session_memory",
                "exposed_to_node": mr_decision == "allowed",
                "created_at": _mrd_dt.now(_mrd_tz.utc).isoformat(),
            })

            # Emit trace events
            if mr_decision == "allowed":
                # v2.40.1: decision-scoped — keyed by (step_id, node_id)
                self._memory_read_allows[(step_id, node_id)] = decision_id
                self._emit(
                    EventType.MEMORY_READ_ALLOWED, node_id,
                    actor=Actor.RUNTIME,
                    decision="memory_read_allowed",
                    metadata={
                        "decision_id": decision_id,
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                        "purpose": "node_context",
                        "exposed_to_node": True,
                    },
                )
            else:
                self._emit(
                    EventType.MEMORY_READ_DENIED, node_id,
                    actor=Actor.RUNTIME,
                    decision="memory_read_denied",
                    reason_codes=[result.denial_reason or ""],
                    metadata={
                        "decision_id": decision_id,
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                        "purpose": "node_context",
                        "exposed_to_node": False,
                    },
                )

        if not result.allowed:
            # v2.34.0: if the denial came from the SIDE_EFFECT gate, record
            # one durable blocked attempt per declared side-effect and emit
            # SIDE_EFFECT_BLOCKED trace events. The structured evaluated data
            # (correction 3) lets us identify the SIDE_EFFECT denial without
            # string parsing.
            se_eval = next(
                (ep for ep in result.evaluated_policies
                 if ep.get("type") == "side_effect"
                 and ep.get("decision") in ("denied", "requires_approval")),
                None,
            )
            if se_eval:
                import uuid as _uuid
                from datetime import datetime as _dt, timezone as _tz
                now_iso = _dt.now(_tz.utc).isoformat()
                policy_id = se_eval.get("policy_id", "")
                rule_id = se_eval.get("rule_id", "")
                se_decision = "require_approval" if se_eval["decision"] == "requires_approval" else "deny"
                node_obj = self._nodes.get(node_id)
                declared = (
                    node_obj.manifest.contract.side_effects
                    if node_obj and hasattr(node_obj, "manifest") else []
                )
                for se in (declared or [type("SE", (), {"effect_type": "unknown", "target": ""})()]):
                    attempt_id = str(_uuid.uuid4())
                    attempt = {
                        "attempt_id": attempt_id,
                        "run_id": run_id,
                        "chain_id": chain_id,
                        "step_id": step_id,
                        "node_id": node_id,
                        "side_effect_type": se.effect_type,
                        "effect_target": getattr(se, "target", ""),
                        "policy_id": policy_id,
                        "rule_id": rule_id,
                        "decision": se_decision,
                        "denial_reason": result.denial_reason or "",
                        "created_at": now_iso,
                    }
                    self.state_manager.record_side_effect_block(attempt)
                    self._emit(
                        EventType.SIDE_EFFECT_BLOCKED,
                        node_id=node_id,
                        actor=Actor.RUNTIME,
                        decision="side_effect_blocked",
                        metadata={
                            "attempt_id": attempt_id,
                            "side_effect_type": se.effect_type,
                            "effect_target": getattr(se, "target", ""),
                            "policy_id": policy_id,
                            "rule_id": rule_id,
                            "decision": se_decision,
                            "denial_reason": result.denial_reason or "",
                            "side_effect_types": se_eval.get("side_effect_types", []),
                        },
                    )
            return result.denial_reason
        return None
