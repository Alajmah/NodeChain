"""v2.93: Node Output Validation Controller — extracted from Orchestrator.

Internal implementation detail. Orchestrator remains the public facade; this
controller holds the per-node output-validation logic that was previously
inline in Orchestrator.run() (schema validation) and in
Orchestrator._run_semantic_validations() (semantic validation).

Responsibilities:
  - Validate node output against the exit-contract schema (validate_schema)
  - Emit VALIDATION_PASSED / VALIDATION_FAILED trace events for schema results
  - Run semantic validators and apply confidence calibration
  - Emit semantic validation / calibration / warning trace events

The Orchestrator retains:
  - Control-flow decisions (_fail_chain, return self.trace) — it branches on
    the ValidationResult returned by this controller.
  - The second strict-violation re-check after semantic validation (it reads
    schema_result.strict_violation from the returned result).
  - State mutation for state.outputs[node_id] and persistence commits — these
    happen in run() between the schema and semantic validation phases.

Emission fidelity:
  The original code used two distinct emission paths, both of which are
  preserved here exactly:
    - Orchestrator._emit(...)  — emits to the trace AND appends to the
      persistent event log. Used for: schema PASSED, and all semantic
      validation events (failed / calibrated / warning / validator_error).
    - self.trace.add_event(TraceEvent(...)) — emits to the trace only, WITHOUT
      persisting. Used for: schema FAILED (the "schema_validation_warning"
      event at the original line ~420-431).
  To preserve this, the controller is constructed with the Orchestrator's
  bound _emit callable (emit_fn) and the ChainTrace (trace). The schema-FAILED
  path appends directly to trace; every other path goes through emit_fn.

Because the schema-validation phase and the semantic-validation phase are
separated in run() by orchestrator-owned work (state update, persistence
commit, side-effect detail events), this controller exposes two entry points
that mirror the two original call sites:

  - validate_schema(...)  -> ValidationResult  (replaces inline block ~L411-437)
  - run_semantic_validations(...) -> None       (replaces _run_semantic_validations)

Behavior is identical to the pre-extraction code — this is a pure move
refactor. v2.92 characterization tests must pass unchanged.
"""
from __future__ import annotations

from typing import Any, Callable

from nodechain.core.blueprint import ChainBlueprint
from nodechain.core.state import ChainState
from nodechain.core.trace import Actor, ChainTrace, EventType, TraceEvent
from nodechain.runtime.validation_pipeline import (
    ValidationContext,
    ValidationPipeline,
)


class NodeOutputValidationController:
    """Validates node output (schema + semantic) after each node invocation.

    Extracted from Orchestrator in v2.93. Holds the validation orchestration
    that was previously inline in Orchestrator.run() and
    Orchestrator._run_semantic_validations().
    """

    def __init__(
        self,
        validation_pipeline: ValidationPipeline,
        blueprint: ChainBlueprint,
        trace: ChainTrace,
        emit_fn: Callable[..., None],
    ) -> None:
        self.validation_pipeline = validation_pipeline
        self.blueprint = blueprint
        self.trace = trace
        # emit_fn is the Orchestrator's bound _emit method — it both appends
        # to the trace AND persists to the event log. Used for all validation
        # events except the schema-FAILED path (see module docstring).
        self._emit = emit_fn

    def validate_schema(
        self,
        node_id: str,
        output: dict[str, Any],
        exit_schema: Any,
        run_id: str,
        chain_id: str,
        step_id: int,
    ) -> "ValidationResult":
        """Validate node output against the exit-contract schema.

        Emits VALIDATION_PASSED (decision="schema_valid") on success, or
        VALIDATION_FAILED (decision="schema_validation_warning") on failure.

        Does NOT call _fail_chain — that control-flow decision stays in
        Orchestrator.run(), which inspects the returned result.

        Args:
            node_id: The node whose output is being validated.
            output: The node's output dict.
            exit_schema: The exit-contract schema_ref (may be None / empty).
            run_id: Current run ID (for the non-persisted trace event).
            chain_id: Current chain ID (for the non-persisted trace event).
            step_id: Current step ID (for trace event attribution).

        Returns:
            ValidationResult with valid, strict_violation, errors, and a
            None calibrated_output (schema validation does not calibrate).
        """
        schema_result = self.validation_pipeline.validate_schema(
            node_id, output, exit_schema
        )
        if schema_result.valid:
            self._emit(
                EventType.VALIDATION_PASSED,
                node_id,
                decision="schema_valid",
                step_id=step_id,
            )
        else:
            self.trace.add_event(
                TraceEvent(
                    run_id=run_id,
                    chain_id=chain_id,
                    node_id=node_id,
                    step_id=step_id,
                    event_type=EventType.VALIDATION_FAILED,
                    actor=Actor.RUNTIME,
                    decision="schema_validation_warning",
                    reason_codes=schema_result.errors[:3],
                )
            )

        return ValidationResult(
            valid=schema_result.valid,
            strict_violation=schema_result.strict_violation,
            errors=list(schema_result.errors),
            calibrated_output=None,
        )

    def run_semantic_validations(
        self,
        node_id: str,
        output: dict[str, Any],
        step_id: int,
        state: ChainState,
    ) -> "SemanticValidationOutcome":
        """Run semantic validators after key nodes produce output.

        Mirrors the pre-extraction Orchestrator._run_semantic_validations()
        method exactly: builds the source-quality map from state.outputs,
        runs the typed semantic validators, applies calibration in place,
        and emits validation / calibration / warning trace events (all
        through emit_fn, which persists them).

        Does NOT call _fail_chain — that control-flow decision stays in
        Orchestrator.run(). Instead, when semantic validation fails in
        strict mode, the returned SemanticValidationOutcome carries
        strict_failed=True with the errors, and run() is responsible for
        calling _fail_chain (without returning early, matching the original
        behavior where execution continued after a strict semantic failure).

        Note: this method mutates `output` in place when calibration applies
        and also writes the calibrated output back into state.outputs[node_id],
        matching the original behavior.

        Args:
            node_id: The node whose output is being validated.
            output: The node's output dict (mutated in place on calibration).
            step_id: Current step ID (for trace event attribution).
            state: Current ChainState — used to build the source-quality map
                   and the prior_outputs context, and to write back calibrated
                   output.

        Returns:
            SemanticValidationOutcome describing whether a strict-mode semantic
            failure occurred (with errors) so run() can call _fail_chain.
        """
        try:
            # Build source quality map for calibration
            sq_map: dict[str, float] = {}
            qualified = state.outputs.get("source_quality_evaluator", {}).get(
                "qualified_sources", []
            )
            for q in qualified:
                ref = q.get("source_ref", "")
                score = q.get("quality_score", 0.5)
                if ref:
                    sq_map[ref] = score

            # Build validation context from current state
            ctx = ValidationContext(
                node_id=node_id,
                chain_name=self.blueprint.name,
                prior_outputs=dict(state.outputs),
                source_quality_map=sq_map,
                strict=self.validation_pipeline.strict_mode,
            )

            result = self.validation_pipeline.validate_semantic_typed(
                output, ctx,
            )

            # Apply normalized output if calibration happened
            if result.normalized_output:
                output.update(result.normalized_output)
                # Also update in state
                state.outputs[node_id] = output

            # Emit validation events
            if result.errors:
                self._emit(
                    EventType.VALIDATION_FAILED,
                    node_id=node_id,
                    decision="semantic_validation_failed",
                    reason_codes=result.errors,
                    step_id=step_id,
                )

            if result.calibration_applied:
                self._emit(
                    EventType.VALIDATION_PASSED,
                    node_id=node_id,
                    actor=Actor.POLICY_ENGINE,
                    decision="confidence_calibrated",
                    metadata={"calibration_summary": result.calibration_summary},
                    step_id=step_id,
                )

            if result.warnings:
                self._emit(
                    EventType.ROUTING_DECISION,
                    node_id=node_id,
                    decision="semantic_warning",
                    metadata={"warnings": result.warnings},
                    step_id=step_id,
                )

            # Surface strict-mode semantic failure to the caller. The original
            # code called _fail_chain here directly; per the extraction
            # constraint, _fail_chain now stays in run(), which reads this
            # outcome. Execution continued (no early return) in the original,
            # so run() must NOT return early on this signal either.
            if result.errors and self.validation_pipeline.strict_mode:
                return SemanticValidationOutcome(
                    strict_failed=True, errors=list(result.errors)
                )

        except Exception as e:
            self._emit(
                EventType.VALIDATION_FAILED,
                node_id=node_id,
                decision="semantic_validator_error",
                reason_codes=[f"Validator error: {e}"],
                step_id=step_id,
            )

        return SemanticValidationOutcome(strict_failed=False, errors=[])


class ValidationResult:
    """Structured result returned by NodeOutputValidationController.validate_schema.

    Carries the information Orchestrator.run() needs to make control-flow
    decisions (_fail_chain / continue) without re-running validation.

    Attributes:
        valid: True if the schema validation passed.
        strict_violation: True if the failure is a strict-mode violation
            (i.e. the chain should fail).
        errors: List of validation error strings (schema result errors).
        calibrated_output: The calibrated output dict if semantic validation
            applied calibration, else None. (Schema validation never
            calibrates, so this is always None from validate_schema.)
    """

    __slots__ = ("valid", "strict_violation", "errors", "calibrated_output")

    def __init__(
        self,
        valid: bool,
        strict_violation: bool,
        errors: list[str],
        calibrated_output: dict[str, Any] | None,
    ) -> None:
        self.valid = valid
        self.strict_violation = strict_violation
        self.errors = errors
        self.calibrated_output = calibrated_output


class SemanticValidationOutcome:
    """Outcome returned by NodeOutputValidationController.run_semantic_validations.

    Carries the information Orchestrator.run() needs to decide whether to
    fail the chain after semantic validation, without the controller needing
    to call _fail_chain itself (per the extraction constraint).

    Attributes:
        strict_failed: True if semantic validation produced errors while the
            pipeline was in strict mode — the original code called
            _fail_chain("semantic_validation_failed", errors) in that case.
            run() reproduces that call (without an early return, matching the
            original behavior where execution continued after the failure).
        errors: The semantic validation errors (empty when strict_failed is
            False).
    """

    __slots__ = ("strict_failed", "errors")

    def __init__(self, strict_failed: bool, errors: list[str]) -> None:
        self.strict_failed = strict_failed
        self.errors = errors
