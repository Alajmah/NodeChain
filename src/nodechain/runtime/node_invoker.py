"""Node Invoker — envelope construction, node execution, output capture.

Responsible for:
- Building invocation envelopes
- Calling node.execute()
- Capturing output, latency, and metadata
- Running immediate schema validation

Does NOT:
- Check policies (PolicyGate)
- Persist state (PersistenceCoordinator)
- Emit trace events (TraceEmitter)
- Handle failures (FailureManager)
"""

from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from typing import Any

from nodechain.core.envelope import (
    Capabilities,
    Context,
    InvocationEnvelope,
    EnvelopeResponse,
    compile_envelope,
)
from nodechain.core.manifest import NodeManifest
from nodechain.nodes.base_node import BaseNode


@dataclass
class InvocationResult:
    """Structured result from a node invocation."""

    node_id: str
    step_id: int
    success: bool
    output: dict[str, Any] | None = None
    error: str | None = None
    latency_ms: int = 0
    validation_errors: list[dict[str, Any]] = field(default_factory=list)
    envelope_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class NodeInvoker:
    """Constructs envelopes and invokes nodes.

    Given an authorized node and execution context, produces an InvocationResult.
    """

    def __init__(self, runner_config=None) -> None:
        self._runner_config = runner_config

    def build_envelope(
        self,
        *,
        run_id: str,
        chain_id: str,
        node_id: str,
        step_id: int,
        payload: dict[str, Any],
        context: Context,
        capabilities: Capabilities,
    ) -> InvocationEnvelope:
        """Build an invocation envelope for a node."""
        return compile_envelope(
            run_id=run_id,
            chain_id=chain_id,
            node_id=node_id,
            step_id=step_id,
            payload=payload,
            context=context,
            capabilities=capabilities,
        )

    async def invoke(
        self,
        node: BaseNode,
        envelope: InvocationEnvelope,
        trust_level: str | None = None,
        isolation_config: dict[str, Any] | None = None,
    ) -> tuple[EnvelopeResponse, int]:
        """Invoke a node and return (response, latency_ms).

        Returns the raw EnvelopeResponse from the node, plus elapsed time.
        On exception, returns a failure EnvelopeResponse.

        If trust_level is provided, import and filesystem policy is enforced.
        If isolation_config is provided (with module_path, class_name),
        the node runs in a subprocess for isolation.
        """
        start = _time.monotonic()
        try:
            # Subprocess isolation for untrusted nodes
            if isolation_config and trust_level and trust_level != "built_in":
                from nodechain.runtime.subprocess_runner import get_subprocess_runner
                from nodechain.sdk.trust import TrustLevel as TL
                runner = get_subprocess_runner(config=self._runner_config)
                tl = TL(trust_level)
                if runner.should_use_subprocess(tl):
                    result = await runner.run_isolated(
                        envelope=envelope,
                        module_path=isolation_config["module_path"],
                        class_name=isolation_config.get("class_name", "Node"),
                        node_id=envelope.node_id,
                        trust_level=trust_level,
                        package_root=isolation_config.get("package_root", ""),
                        enable_seccomp=isolation_config.get("enable_seccomp", False),
                    )
                    elapsed_ms = int((_time.monotonic() - start) * 1000)
                    if result["success"]:
                        resp_data = result["response"]
                        response = EnvelopeResponse(**resp_data)
                        response.latency_ms = elapsed_ms
                        response.metadata = response.metadata or {}
                        response.metadata["isolation_mode"] = "subprocess"
                        response.metadata["subprocess_duration_ms"] = result["duration_ms"]
                        # Propagate seccomp fields from child metadata (v1.2.3)
                        child_meta = resp_data.get("metadata", {})
                        for sk in ("seccomp_enforced", "seccomp_available",
                                    "seccomp_profile_name", "syscall_filtering_enforced",
                                    "seccomp_error"):
                            if sk in child_meta:
                                response.metadata[sk] = child_meta[sk]
                        # Propagate cgroup fields from subprocess result (v1.3.1)
                        response.metadata["cgroup_accounting"] = result.get("cgroup_accounting")
                        response.metadata["cgroup_path"] = result.get("cgroup_path")
                        response.metadata["cgroup_accounting_scope"] = result.get("cgroup_accounting_scope", "")
                        # v1.3.2: cgroup limit enforcement fields
                        response.metadata["cgroup_limits_requested"] = result.get("cgroup_limits_requested", False)
                        response.metadata["cgroup_limits_enforced"] = result.get("cgroup_limits_enforced", False)
                        response.metadata["cgroup_memory_max_mb"] = result.get("cgroup_memory_max_mb", 0)
                        response.metadata["cgroup_pids_max"] = result.get("cgroup_pids_max", 0)
                        response.metadata["cgroup_cpu_max_quota"] = result.get("cgroup_cpu_max_quota", 0)
                        # v1.4.0: network namespace enforcement
                        response.metadata["network_namespace_enforced"] = result.get("network_namespace_enforced", False)
                        # v1.4.3: mount namespace enforcement
                        response.metadata["mount_namespace_enforced"] = result.get("mount_namespace_enforced", False)
                        # v1.4.5: mount confinement enforcement
                        response.metadata["mount_confinement_enforced"] = result.get("mount_confinement_enforced", False)
                        # v1.5.0: PID namespace enforcement
                        response.metadata["pid_namespace_enforced"] = result.get("pid_namespace_enforced", False)
                        # v1.5.1: procfs namespace view
                        response.metadata["procfs_namespace_view_enforced"] = result.get("procfs_namespace_view_enforced", False)
                        # T3 (H0.2): trusted supervised evidence projection —
                        # start/containment truth rides on success too.
                        if "supervised_execution" in result:
                            response.metadata["supervised_execution"] = result["supervised_execution"]
                        # T3 (H0.2): supervised seccomp truth — the trusted
                        # translator owns these on the supervised route (the
                        # workload deliberately does not). Projected from the
                        # translated result when present; the legacy
                        # child-metadata handling above is untouched.
                        for _sk in ("seccomp_enforced", "seccomp_available"):
                            if _sk in result:
                                response.metadata[_sk] = result[_sk]
                        return response, elapsed_ms
                    else:
                        failure_metadata = {
                            "isolation_mode": "subprocess",
                            "exit_code": result.get("exit_code", -1),
                        }
                        # T3 (H0.2): prevent evidence collapse on failure —
                        # the supervised projection distinguishes
                        # never-started from started-but-failed with trusted
                        # containment truth. Cancellation is NOT consumed
                        # here: CancelledError is BaseException and bypasses
                        # this handler entirely.
                        if "supervised_execution" in result:
                            failure_metadata["supervised_execution"] = result["supervised_execution"]
                        response = EnvelopeResponse(
                            request_envelope_id=envelope.envelope_id,
                            run_id=envelope.run_id,
                            chain_id=envelope.chain_id,
                            node_id=envelope.node_id,
                            step_id=envelope.step_id,
                            output={},
                            output_type="error",
                            success=False,
                            error=result.get("error", "subprocess failed"),
                            latency_ms=elapsed_ms,
                            metadata=failure_metadata,
                        )
                        return response, elapsed_ms

            # Wrap execution with enforcement if trust level is set
            if trust_level and trust_level != "built_in":
                from nodechain.sdk.trust import TrustLevel
                from nodechain.sdk.import_enforcer import enforce_imports_for_node
                from nodechain.sdk.filesystem_enforcer import enforce_filesystem_for_node
                from nodechain.sdk.subprocess_enforcer import enforce_subprocess_for_node
                from nodechain.sdk.network_enforcer import enforce_network_for_node
                tl = TrustLevel(trust_level)
                imp_enforcer = enforce_imports_for_node(tl, envelope.node_id)
                fs_enforcer = enforce_filesystem_for_node(tl, envelope.node_id)
                sp_enforcer = enforce_subprocess_for_node(tl, envelope.node_id)
                net_enforcer = enforce_network_for_node(tl, envelope.node_id)
                with imp_enforcer.enforce(), fs_enforcer.enforce(), sp_enforcer.enforce(), net_enforcer.enforce():
                    response: EnvelopeResponse = await node.execute(envelope)
                # Record violations on the response metadata
                response.metadata = response.metadata or {}
                if imp_enforcer.had_violations:
                    response.metadata["import_policy"] = imp_enforcer.get_report()
                if fs_enforcer.had_violations:
                    response.metadata["filesystem_policy"] = fs_enforcer.get_report()
                if sp_enforcer.had_violations:
                    response.metadata["subprocess_policy"] = sp_enforcer.get_report()
                if net_enforcer.had_violations:
                    response.metadata["network_policy"] = net_enforcer.get_report()
            else:
                response: EnvelopeResponse = await node.execute(envelope)

            elapsed_ms = int((_time.monotonic() - start) * 1000)
            response.latency_ms = elapsed_ms
            return response, elapsed_ms
        except Exception as e:
            elapsed_ms = int((_time.monotonic() - start) * 1000)
            response = EnvelopeResponse(
                request_envelope_id=envelope.envelope_id,
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id=envelope.node_id,
                step_id=envelope.step_id,
                output={},
                output_type="error",
                success=False,
                error=str(e),
                latency_ms=elapsed_ms,
            )
            return response, elapsed_ms

    def validate_output(
        self,
        output: dict[str, Any],
        schema_ref: str | None,
        validator: Any,  # SchemaValidator
    ) -> list[dict[str, Any]]:
        """Validate output against exit contract schema.

        Returns list of validation errors (empty if valid or no schema).
        """
        if not schema_ref:
            return []

        result = validator.validate(output, schema_ref)
        if result.valid:
            return []
        return [{"errors": result.errors[:5]}]
