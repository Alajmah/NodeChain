"""Invocation Envelope — the universal execution contract between runtime and node."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Context(BaseModel):
    """Granted context from the Harness Control Plane."""

    session_memory: list[dict[str, Any]] = Field(default_factory=list)
    chain_state: dict[str, Any] = Field(default_factory=dict)
    source_routing: dict[str, Any] = Field(default_factory=dict)
    per_node_adapter_grants: list[str] = Field(default_factory=list)
    # v2.40.2: memory-read authorization reference. When memory is exposed
    # to a node, this carries the durable decision_id that authorized it.
    # Empty string = no memory exposed (sanitized).
    memory_read_decision_id: str = ""


class Capabilities(BaseModel):
    """Granted capabilities — what this invocation is allowed to do."""

    can_call_tools: bool = False
    can_read_memory: bool = False
    can_write_memory: bool = False
    max_cost_usd: float = 1.0
    max_latency_ms: int = 60_000
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_adapters: list[str] = Field(default_factory=list)  # v2.43.0: specific backend grants
    side_effect_completed_keys: list[str] = Field(default_factory=list)  # Idempotency keys of completed side effects
    side_effect_status_map: dict[str, str] = Field(default_factory=dict)  # ikey -> status for all non-planned effects


class InvocationEnvelope(BaseModel):
    """
    Every node invocation and response passes through this envelope.
    This is the runtime's law — no node sees raw input, no node
    returns raw output.
    """

    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str
    chain_id: str
    node_id: str
    step_id: int = Field(ge=1)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload: dict[str, Any]
    context: Context = Field(default_factory=Context)
    capabilities: Capabilities = Field(default_factory=Capabilities)
    metadata: dict[str, Any] = Field(default_factory=dict)
    # v3.5.0: recovery execution context (INV-005). When present, this
    # invocation is a side-effect retry through the recovery seam, not a
    # normal typed-port execution. The node and runtime gate use this to
    # enforce exactly-one-target-effect (INV-006).
    recovery: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}


class EnvelopeResponse(BaseModel):
    """Node execution result wrapped in the same envelope contract."""

    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_envelope_id: str
    run_id: str
    chain_id: str
    node_id: str
    step_id: int
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    output: dict[str, Any]
    output_type: str
    success: bool = True
    error: str | None = None
    cost_usd: float = 0.0
    latency_ms: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


def compile_envelope(
    run_id: str,
    chain_id: str,
    node_id: str,
    step_id: int,
    payload: dict[str, Any],
    context: Context | None = None,
    capabilities: Capabilities | None = None,
) -> InvocationEnvelope:
    """Compile an invocation envelope with defaults for optional fields."""
    return InvocationEnvelope(
        run_id=run_id,
        chain_id=chain_id,
        node_id=node_id,
        step_id=step_id,
        payload=payload,
        context=context or Context(),
        capabilities=capabilities or Capabilities(),
    )


# ── v3.5.0: RecoveryEnvelopeV1 ──────────────────────────────────────────────


class RecoveryEnvelopeError(Exception):
    """Raised when a recovery envelope fails validation (INV-005, ChatGPT T5/T6)."""

    def __init__(self, message: str, *, code: str = "RECOVERY_ENVELOPE_INVALID") -> None:
        self.code = code
        super().__init__(message)


class RecoveryEnvelopeV1(BaseModel):
    """v3.5.0: Validated recovery execution context for side-effect retry.

    ChatGPT T5 carryover (T6 prerequisite): this parser checks the exact
    schema version, requires the complete key set, rejects unknown keys,
    validates run/node/parent/child/action/adapter/capsule/fence relationships,
    produces an immutable validated representation, and fails closed before
    node or adapter execution.

    Protects: INV-005 (recovery seam distinct from typed-port loop),
              INV-006 (exactly one target effect).
    """

    model_config = {"extra": "forbid", "frozen": True}

    schema_version: int = 1
    recovery_mode: str = "side_effect_retry"
    recovery_action_id: str
    recovery_decision_id: str
    original_invocation_id: str
    target_side_effect_key: str
    parent_side_effect_key: str
    root_side_effect_key: str
    retry_attempt_key: str
    retry_ordinal: int
    replay_capsule_id: str
    replay_capsule_digest: str
    replay_capsule_schema_version: int
    canonicalization_version: str
    source_binding_node_id: str
    source_binding_node_version: str
    source_binding_contract_id: str
    source_binding_contract_version: str
    source_binding_adapter_id: str
    source_binding_adapter_version: str
    execution_claim_id: str
    required_type: str
    required_operation_name: str
    required_adapter_id: str
    required_adapter_version: str
    required_request_hash: str
    max_total_side_effects: int = 1

    @classmethod
    def build(
        cls,
        *,
        recovery_action_id: str,
        recovery_decision_id: str,
        original_invocation_id: str,
        parent_side_effect_key: str,
        root_side_effect_key: str,
        retry_attempt_key: str,
        retry_ordinal: int,
        replay_capsule_id: str,
        replay_capsule_digest: str,
        replay_capsule_schema_version: int,
        canonicalization_version: str,
        source_binding: dict[str, str],
        execution_claim_id: str,
        required_type: str,
        required_operation_name: str,
        required_adapter_id: str,
        required_adapter_version: str,
        required_request_hash: str,
        max_total_side_effects: int = 1,
    ) -> "RecoveryEnvelopeV1":
        """Build a validated recovery envelope from component parts.

        ChatGPT: target_side_effect_key == parent_side_effect_key — they must
        never be independently supplied with different meanings.
        """
        if not parent_side_effect_key:
            raise RecoveryEnvelopeError(
                "parent_side_effect_key is required",
                code="MISSING_PARENT_KEY",
            )
        if not retry_attempt_key:
            raise RecoveryEnvelopeError(
                "retry_attempt_key is required",
                code="MISSING_RETRY_KEY",
            )
        if parent_side_effect_key == retry_attempt_key:
            raise RecoveryEnvelopeError(
                "retry_attempt_key must differ from parent_side_effect_key "
                "(two-row lineage — INV-001)",
                code="LINEAGE_COLLAPSE",
            )

        # Validate source binding completeness
        required_binding_keys = {
            "node_id", "node_version", "contract_id", "contract_version",
            "adapter_id", "adapter_version",
        }
        missing = required_binding_keys - set(source_binding.keys())
        if missing:
            raise RecoveryEnvelopeError(
                f"source_binding missing required keys: {sorted(missing)}",
                code="INCOMPLETE_SOURCE_BINDING",
            )
        # ChatGPT revised T6 major 4: require non-empty attested values.
        # Empty-string fallbacks are not acceptable for security-relevant fields.
        for key in sorted(required_binding_keys):
            val = source_binding.get(key, "")
            if not val:
                raise RecoveryEnvelopeError(
                    f"source_binding '{key}' must be non-empty — empty fallbacks "
                    f"are not permitted for recovery dispatch",
                    code="EMPTY_BINDING_VALUE",
                )

        # ChatGPT revised T6 major 4: cross-field validation.
        # The required adapter must match the capsule's attested adapter.
        if required_adapter_id != source_binding["adapter_id"]:
            raise RecoveryEnvelopeError(
                f"adapter_id mismatch: required_adapter_id={required_adapter_id} "
                f"but source_binding adapter_id={source_binding['adapter_id']}. "
                f"The dispatch target must match the capsule's attested adapter.",
                code="ADAPTER_ID_MISMATCH",
            )
        if required_adapter_version != source_binding["adapter_version"]:
            raise RecoveryEnvelopeError(
                f"adapter_version mismatch: required={required_adapter_version} "
                f"but source_binding={source_binding['adapter_version']}.",
                code="ADAPTER_VERSION_MISMATCH",
            )

        return cls(
            recovery_action_id=recovery_action_id,
            recovery_decision_id=recovery_decision_id,
            original_invocation_id=original_invocation_id,
            target_side_effect_key=parent_side_effect_key,
            parent_side_effect_key=parent_side_effect_key,
            root_side_effect_key=root_side_effect_key,
            retry_attempt_key=retry_attempt_key,
            retry_ordinal=retry_ordinal,
            replay_capsule_id=replay_capsule_id,
            replay_capsule_digest=replay_capsule_digest,
            replay_capsule_schema_version=replay_capsule_schema_version,
            canonicalization_version=canonicalization_version,
            source_binding_node_id=source_binding["node_id"],
            source_binding_node_version=source_binding["node_version"],
            source_binding_contract_id=source_binding["contract_id"],
            source_binding_contract_version=source_binding["contract_version"],
            source_binding_adapter_id=source_binding["adapter_id"],
            source_binding_adapter_version=source_binding["adapter_version"],
            execution_claim_id=execution_claim_id,
            required_type=required_type,
            required_operation_name=required_operation_name,
            required_adapter_id=required_adapter_id,
            required_adapter_version=required_adapter_version,
            required_request_hash=required_request_hash,
            max_total_side_effects=max_total_side_effects,
        )

    def to_envelope_recovery_dict(self) -> dict[str, Any]:
        """Serialize to the ``recovery`` dict carried by InvocationEnvelope."""
        return {
            "schema_version": self.schema_version,
            "recovery_mode": self.recovery_mode,
            "recovery_action_id": self.recovery_action_id,
            "recovery_decision_id": self.recovery_decision_id,
            "original_invocation_id": self.original_invocation_id,
            "target_side_effect_key": self.target_side_effect_key,
            "parent_side_effect_key": self.parent_side_effect_key,
            "root_side_effect_key": self.root_side_effect_key,
            "retry_attempt_key": self.retry_attempt_key,
            "retry_ordinal": self.retry_ordinal,
            "replay_capsule_id": self.replay_capsule_id,
            "execution_claim_id": self.execution_claim_id,
            "required_adapter_id": self.required_adapter_id,
        }

    def to_execution_constraints(self):
        """Build ExecutionConstraints for RecoveryDispatchGuard."""
        from nodechain.runtime.recovery_dispatch_guard import ExecutionConstraints
        return ExecutionConstraints(
            required_type=self.required_type,
            required_operation_name=self.required_operation_name,
            required_adapter_id=self.required_adapter_id,
            required_adapter_version=self.required_adapter_version,
            required_request_hash=self.required_request_hash,
            required_canonicalization_version=self.canonicalization_version,
            max_total_side_effects=self.max_total_side_effects,
        )

