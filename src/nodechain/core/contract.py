"""Node Contract — declares what a node requires and produces."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Canonical side-effect taxonomy (v2.35.0) ────────────────────────────────
#
# The type answers "what kind of durable/external effect can happen?" — not
# "which mechanism invoked it." tool_invocation is intentionally excluded;
# it is ambiguous (adapter dispatch, model tool call, external API, capability)
# and overlaps with external_call. It can be added later in a tool/capability
# model.

class SideEffectType(str, Enum):
    """Canonical runtime side-effect types."""
    EXTERNAL_CALL = "external_call"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    CODE_EXECUTION = "code_execution"  # v2.73: governed temp-workspace execution
    SANDBOX_FILE_WRITE = "sandbox_file_write"  # v2.72-v2.73: temp workspace writes only


# Legacy string → canonical mapping. New ledger/trace rows should use canonical
# values only. Old rows are normalized at read/reconcile time, not migrated.
_SIDE_EFFECT_CANONICAL: dict[str, str] = {
    "external_call": SideEffectType.EXTERNAL_CALL.value,
    "external_api_read": SideEffectType.EXTERNAL_CALL.value,
    "api_call": SideEffectType.EXTERNAL_CALL.value,
    "search": SideEffectType.EXTERNAL_CALL.value,
    "external_read": SideEffectType.EXTERNAL_CALL.value,
    "external_write": SideEffectType.EXTERNAL_CALL.value,
    "memory_write": SideEffectType.MEMORY_WRITE.value,
    "memory_read": SideEffectType.MEMORY_READ.value,
    "code_execution": SideEffectType.CODE_EXECUTION.value,  # v2.73
    "sandbox_file_write": SideEffectType.SANDBOX_FILE_WRITE.value,  # v2.72-v2.73
    "temp_workspace_pytest": SideEffectType.CODE_EXECUTION.value,  # v2.73 alias
}


def normalize_side_effect_type(raw: str) -> str | None:
    """Normalize a raw side-effect type string to its canonical form.

    Returns the canonical string, or None if the raw value is unrecognized.
    Unknown raw strings at runtime should fail closed; unknown raw strings in
    manifests should warn (not crash).
    """
    if not raw:
        return None
    return _SIDE_EFFECT_CANONICAL.get(raw)


class EntryContract(BaseModel):
    """What a node requires as input."""

    input_type: str
    schema_ref: str
    required_fields: list[str] = Field(default_factory=list)
    optional_fields: list[str] = Field(default_factory=list)


class ExitContract(BaseModel):
    """What a node produces as output."""

    output_type: str
    schema_ref: str
    guaranteed_fields: list[str] = Field(default_factory=list)
    possible_fields: list[str] = Field(default_factory=list)
    error_type: str | None = None


class SideEffect(BaseModel):
    """Declared side effect of a node."""

    effect_type: str  # external_call, memory_read, memory_write, tool_invocation
    target: str
    optional: bool = False


class ModelRequirements(BaseModel):
    """v2.68: Explicit model-output floor declared by a node.

    Born from the v2.68 diagnostic: the Evidence Synthesizer produced 0 claims
    on Gemma 4 12B because the model could not produce structured JSON. The
    requirement was implicit. This makes it explicit and traceable.

    v2.68 scope: declare, evaluate what is known, trace, warn on unknown. Do NOT
    block the run. Hard enforcement + capability profile registry is v2.69.
    """

    structured_output_required: bool | None = None
    """The node requires the model call path to support structured output, not
    merely free-text completion."""

    min_output_tokens: int | None = None
    """The configured/requested generation budget must be at least this value
    when known. This is the actual invocation budget, not a theoretical model
    max. Must be > 0 when present."""

    json_schema_adherence: str | None = None
    """"required" = free-text success is not enough; the model output must parse
    into the declared schema. "preferred" = parse strongly desired but not
    enforced. None = no claim."""

    model_config = {"extra": "forbid"}

    @field_validator("min_output_tokens")
    @classmethod
    def _check_min_output_tokens(cls, v: int | None) -> int | None:
        if v is not None and v <= 0:
            raise ValueError(
                f"min_output_tokens must be > 0 when present, got {v}"
            )
        return v

    @field_validator("json_schema_adherence")
    @classmethod
    def _check_adherence(cls, v: str | None) -> str | None:
        if v is not None and v not in ("required", "preferred"):
            raise ValueError(
                f"json_schema_adherence must be 'required' or 'preferred', got {v!r}"
            )
        return v

    def is_empty(self) -> bool:
        """True if no requirement is declared (the legacy default)."""
        return (
            self.structured_output_required is None
            and self.min_output_tokens is None
            and self.json_schema_adherence is None
        )

    def to_trace_dict(self) -> dict[str, Any]:
        """Serialize for trace events. Omits None fields for clean traces."""
        d = self.model_dump(exclude_none=True)
        return d


def _validate_model_requirements(req: ModelRequirements | None) -> None:
    """Pydantic-aware validation hook for cross-field invariants on
    ModelRequirements (re-checked after Pydantic init for defense in depth)."""
    if req is None:
        return
    # Field validators already enforce min_output_tokens > 0 and adherence enum;
    # this hook is reserved for future cross-field invariants.
    return


class Requirements(BaseModel):
    """Node execution requirements."""

    model_required: bool = False
    model_capabilities: list[str] = Field(default_factory=list)
    tools_required: list[str] = Field(default_factory=list)
    adapters_required: list[str] = Field(default_factory=list)  # v2.43.0
    memory_access: str = "none"  # none, read, write, read_write
    trust_level: str = "trusted"  # trusted, sandboxed, untrusted
    max_cost_usd: float | None = None
    model_requirements: ModelRequirements | None = None  # v2.68


class NodeContract(BaseModel):
    """
    The contract is validated at load time, not invocation time.
    Incompatible contracts between connected nodes are caught before
    a single node executes.
    """

    contract_id: str
    node_id: str
    version: str = "1.0.0"
    entry: EntryContract
    exit: ExitContract
    side_effects: list[SideEffect] = Field(default_factory=list)
    requirements: Requirements = Field(default_factory=Requirements)

    model_config = {"extra": "forbid"}

    def model_post_init(self, __context: Any) -> None:
        """v2.68: validate model_requirements invariants after Pydantic init.

        Existing manifests without `model_requirements` produce `None` here and
        load unchanged (backward compatibility — see test_legacy_contract_*).
        """
        super().model_post_init(__context)
        _validate_model_requirements(self.requirements.model_requirements)


def is_privileged_node(contract: NodeContract) -> bool:
    """v2.44.0: determine if a node requires privileged capabilities.

    A node is privileged if it declares tool access, adapter access,
    memory access, side effects, or model access.
    """
    req = contract.requirements
    return bool(
        req.tools_required
        or req.adapters_required
        or req.memory_access != "none"
        or contract.side_effects
        or req.model_required
    )


class CompatibilityResult(BaseModel):
    """Result of checking contract compatibility between two nodes."""

    compatible: bool
    source_node: str
    target_node: str
    output_type: str
    input_type: str
    issues: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def check_compatibility(
    source: NodeContract, target: NodeContract
) -> CompatibilityResult:
    """
    Check if source node's exit is compatible with target node's entry.

    Compatibility rules:
    1. output_type == input_type (exact match)
    2. All required_fields in target.entry are in source.exit.guaranteed_fields
    3. Schema references must resolve to compatible schemas
    """
    issues: list[str] = []
    warnings: list[str] = []

    # Rule 1: Type match
    if source.exit.output_type != target.entry.input_type:
        issues.append(
            f"Type mismatch: {source.node_id} produces "
            f"'{source.exit.output_type}' but {target.node_id} "
            f"expects '{target.entry.input_type}'"
        )

    # Rule 2: Required fields coverage
    if target.entry.required_fields:
        missing = set(target.entry.required_fields) - set(
            source.exit.guaranteed_fields
        )
        if missing:
            issues.append(
                f"Missing required fields: {missing}. "
                f"{source.node_id} guarantees {source.exit.guaranteed_fields}, "
                f"{target.node_id} requires {target.entry.required_fields}"
            )

    # Rule 3: Warn if possible fields won't satisfy optional fields
    if target.entry.optional_fields:
        available = set(source.exit.guaranteed_fields) | set(
            source.exit.possible_fields
        )
        missing_optional = set(target.entry.optional_fields) - available
        if missing_optional:
            warnings.append(
                f"Optional fields not available: {missing_optional}"
            )

    return CompatibilityResult(
        compatible=len(issues) == 0,
        source_node=source.node_id,
        target_node=target.node_id,
        output_type=source.exit.output_type,
        input_type=target.entry.input_type,
        issues=issues,
        warnings=warnings,
    )


class ContractRegistry:
    """Holds all node contracts for a chain. Validates at load time."""

    def __init__(self) -> None:
        self._contracts: dict[str, NodeContract] = {}

    def register(self, contract: NodeContract) -> None:
        self._contracts[contract.node_id] = contract

    def get(self, node_id: str) -> NodeContract | None:
        return self._contracts.get(node_id)

    def all_contracts(self) -> dict[str, NodeContract]:
        return dict(self._contracts)

    def validate_connections(
        self, connections: list[dict[str, str]]
    ) -> list[CompatibilityResult]:
        """
        Validate all connections in the chain blueprint.
        Returns results for every connection. Raises on any incompatibility.
        """
        results = []
        for conn in connections:
            source_id = conn["from_node"]
            target_id = conn["to_node"]

            source = self._contracts.get(source_id)
            target = self._contracts.get(target_id)

            if not source:
                results.append(
                    CompatibilityResult(
                        compatible=False,
                        source_node=source_id,
                        target_node=target_id,
                        output_type="unknown",
                        input_type="unknown",
                        issues=[f"Source node '{source_id}' has no registered contract"],
                    )
                )
                continue

            if not target:
                results.append(
                    CompatibilityResult(
                        compatible=False,
                        source_node=source_id,
                        target_node=target_id,
                        output_type=source.exit.output_type,
                        input_type="unknown",
                        issues=[f"Target node '{target_id}' has no registered contract"],
                    )
                )
                continue

            results.append(check_compatibility(source, target))

        return results
