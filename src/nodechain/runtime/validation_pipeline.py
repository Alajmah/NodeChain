"""Validation Pipeline — schema + semantic + confidence validation.

Owns:
- Schema validation against exit contracts
- Semantic validation (referential integrity, source refs, confidence consistency)
- Confidence calibration from structured evidence features
- Strict mode enforcement

Does NOT own:
- Node invocation
- State persistence
- Trace emission (returns results for caller to emit)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from nodechain.validation.schema_validator import SchemaValidator
from nodechain.validation.semantic_validators import SemanticValidationPipeline


@dataclass
class ValidationContext:
    """Typed context for semantic validation — replaces **kwargs.

    Provides all the information a validator needs without
    importing orchestrator assumptions.
    """

    node_id: str
    chain_name: str = ""
    source_registry: dict[str, dict[str, Any]] = field(default_factory=dict)
    allowed_source_ids: set[str] = field(default_factory=set)
    prior_outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_quality_map: dict[str, float] = field(default_factory=dict)
    risk_policy: dict[str, Any] = field(default_factory=dict)
    memory_policy: dict[str, Any] = field(default_factory=dict)
    strict: bool = False


@dataclass
class SchemaValidationResult:
    """Result from exit-contract schema validation."""

    node_id: str
    valid: bool
    errors: list[str] = field(default_factory=list)
    strict_violation: bool = False


@dataclass
class SemanticValidationResult:
    """Result from semantic validators on a node's output."""

    node_id: str
    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    calibration_applied: bool = False
    calibration_summary: list[dict[str, Any]] = field(default_factory=list)
    normalized_output: dict[str, Any] | None = None


class ValidationPipeline:
    """Runs schema and semantic validations after node execution.

    The orchestrator should call:
    1. validate_schema() — after each node invocation
    2. validate_semantic() — after key nodes (evidence_synthesizer, response_generator)

    Both return structured results. The orchestrator decides whether to emit
    trace events, fail the chain, or continue.
    """

    def __init__(self) -> None:
        self.schema_validator = SchemaValidator()
        self.semantic_pipeline = SemanticValidationPipeline()

    @property
    def strict_mode(self) -> bool:
        """Whether strict schema enforcement is active."""
        return os.environ.get("NODECHAIN_STRICT_SCHEMA") == "1"

    def validate_schema(
        self,
        node_id: str,
        output: dict[str, Any],
        schema_ref: str | None,
    ) -> SchemaValidationResult:
        """Validate output against exit contract schema.

        Returns SchemaValidationResult with:
        - valid: True if schema matches or no schema defined
        - errors: List of validation errors
        - strict_violation: True if strict mode and validation failed
        """
        if not schema_ref:
            return SchemaValidationResult(node_id=node_id, valid=True)

        result = self.schema_validator.validate(output, schema_ref)
        if not result.valid:
            strict_violation = self.strict_mode
            return SchemaValidationResult(
                node_id=node_id,
                valid=False,
                errors=result.errors[:5],
                strict_violation=strict_violation,
            )

        return SchemaValidationResult(node_id=node_id, valid=True)

    def validate_semantic(
        self,
        node_id: str,
        output: dict[str, Any],
        *,
        evidence_output: dict[str, Any] | None = None,
        response_output: dict[str, Any] | None = None,
        sources: list[dict[str, Any]] | None = None,
        source_quality_map: dict[str, float] | None = None,
    ) -> SemanticValidationResult:
        """Run semantic validators on a node's output.

        After evidence_synthesizer: validates source refs and calibrates confidence.
        After response_generator: validates confidence consistency.

        Returns SemanticValidationResult with:
        - passed: True if all validations passed
        - errors: Hard validation failures
        - warnings: Soft validation warnings
        - calibration_applied: Whether confidence was calibrated
        - calibration_summary: Per-claim calibration metadata
        - normalized_output: The (possibly modified) output
        """
        errors: list[str] = []
        warnings: list[str] = []
        calibration_applied = False
        calibration_summary: list[dict[str, Any]] = []
        normalized = dict(output)

        # ── Evidence synthesizer: referential integrity + confidence calibration ──
        if node_id == "evidence_synthesizer":
            pipeline = SemanticValidationPipeline()
            results = pipeline.validate_chain_output(
                evidence_output=output,
                response_output={},
                sources=output.get("sources", []),
            )

            # Check referential integrity
            for r in results:
                if not r.valid and r.validator == "referential_integrity":
                    errors.extend(r.errors)

            # Calibrate confidence
            from nodechain.validation.confidence_calibrator import ConfidenceCalibrator
            calibrator = ConfidenceCalibrator()
            claims = output.get("claims", [])
            if claims:
                sq_map = source_quality_map or {}
                calibrated = calibrator.calibrate_claims(claims, sq_map)
                normalized["claims"] = calibrated
                normalized["calibration_applied"] = True
                calibration_applied = True

                for c in calibrated:
                    meta = c.get("calibration_metadata", {})
                    calibration_summary.append({
                        "claim_id": c.get("claim_id"),
                        "raw": meta.get("feature_based_confidence", c.get("raw_confidence")),
                        "final": c.get("calibrated_confidence"),
                        "reasons": meta.get("reason_codes", []),
                    })

        # ── Response generator: confidence consistency ──
        elif node_id == "response_generator":
            if evidence_output:
                pipeline = SemanticValidationPipeline()
                results = pipeline.validate_chain_output(
                    evidence_output=evidence_output,
                    response_output=output,
                )
                for r in results:
                    if not r.valid:
                        errors.extend(r.errors)
                    elif r.warnings:
                        warnings.extend(r.warnings)

        return SemanticValidationResult(
            node_id=node_id,
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            calibration_applied=calibration_applied,
            calibration_summary=calibration_summary,
            normalized_output=normalized if calibration_applied or errors else None,
        )

    def validate_semantic_typed(
        self,
        output: dict[str, Any],
        ctx: ValidationContext,
    ) -> SemanticValidationResult:
        """Run semantic validators using a typed ValidationContext.

        This is the preferred interface — replaces validate_semantic(**kwargs).
        """
        return self.validate_semantic(
            node_id=ctx.node_id,
            output=output,
            evidence_output=ctx.prior_outputs.get("evidence_synthesizer"),
            response_output=output if ctx.node_id == "response_generator" else None,
            sources=[],
            source_quality_map=ctx.source_quality_map,
        )
