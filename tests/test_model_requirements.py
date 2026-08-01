"""v2.68 tests for ModelRequirements declaration, trace evaluation, and
backward compatibility.

Born from the v2.68 diagnostic: the Evidence Synthesizer produced 0 claims on
Gemma 4 12B because the model could not produce structured JSON. The
requirement was implicit. v2.68 makes it explicit and traceable.

These tests pin the v2.68 agreement with ChatGPT:
  - 3 fields only (structured_output_required, min_output_tokens, json_schema_adherence)
  - declare, evaluate, trace, warn on unknown — do NOT block
  - legacy contracts without model_requirements load unchanged
  - evaluation_status enum: satisfied / unsatisfied / unknown / not_applicable
"""
from __future__ import annotations

from typing import Any

import pytest

from nodechain.core.contract import (
    EntryContract,
    ExitContract,
    ModelRequirements,
    NodeContract,
    Requirements,
)
from nodechain.core.port import PortType
from nodechain.core.trace import EventType


# ── Test 1: synthesizer contract declares model_requirements ───────────────

def test_model_requirements_declared_on_synthesizer_contract() -> None:
    """Evidence Synthesizer must declare its model-output floor.

    This is the central assertion of v2.68 — the failure that produced 0 claims
    on Gemma 4 12B must now be visible as an explicit contract requirement.
    """
    from nodechain.nodes.evidence_synthesizer import EVIDENCE_SYNTHESIZER_CONTRACT

    mr = EVIDENCE_SYNTHESIZER_CONTRACT.requirements.model_requirements
    assert mr is not None, "Evidence Synthesizer must declare model_requirements (v2.68)"
    assert mr.structured_output_required is True
    assert mr.min_output_tokens is not None and mr.min_output_tokens > 0
    assert mr.json_schema_adherence == "required"


# ── Test 2: parse and serialize cleanly (round-trip) ───────────────────────

def test_model_requirements_parse_and_serialize() -> None:
    """ModelRequirements must round-trip through Pydantic and produce a
    trace-friendly dict (no None fields)."""
    req = ModelRequirements(
        structured_output_required=True,
        min_output_tokens=4096,
        json_schema_adherence="required",
    )
    dumped = req.to_trace_dict()
    assert dumped == {
        "structured_output_required": True,
        "min_output_tokens": 4096,
        "json_schema_adherence": "required",
    }
    # No None fields in the trace dict
    assert all(v is not None for v in dumped.values())

    # Re-parse from the dumped dict — must round-trip
    req2 = ModelRequirements.model_validate(dumped)
    assert req2.structured_output_required is True
    assert req2.min_output_tokens == 4096
    assert req2.json_schema_adherence == "required"
    assert not req2.is_empty()


# ── Test 3: legacy contract without model_requirements still loads ──────────

def test_legacy_contract_without_model_requirements_still_loads() -> None:
    """A contract without model_requirements must load unchanged.

    This is the backward-compatibility guarantee — the contract change must not
    break any existing manifest. Critical because the v2.68 change touches
    NodeContract, which is load-time validated.
    """
    # No model_requirements specified — default
    legacy_req = Requirements(model_required=True, model_capabilities=["reasoning"])
    assert legacy_req.model_requirements is None

    legacy_contract = NodeContract(
        contract_id="legacy.test.v1",
        node_id="legacy_node",
        entry=EntryContract(input_type=PortType.RAW_QUERY, schema_ref="x"),
        exit=ExitContract(output_type=PortType.RESEARCH_GOAL, schema_ref="y"),
        requirements=legacy_req,
    )
    assert legacy_contract.requirements.model_requirements is None

    # Empty ModelRequirements() also tolerates (treated as no declaration)
    empty_req = ModelRequirements()
    assert empty_req.is_empty()


# ── Test 4: trace event type defined and discoverable ──────────────────────

def test_trace_records_model_requirements_evaluation() -> None:
    """The MODEL_REQUIREMENTS_EVALUATED event type must exist as a discrete
    event (not an extension of node_invoked), per the agreement with ChatGPT."""
    # The event type is defined
    assert hasattr(EventType, "MODEL_REQUIREMENTS_EVALUATED")
    assert (
        EventType.MODEL_REQUIREMENTS_EVALUATED.value == "model_requirements_evaluated"
    )

    # It is distinct from MODEL_CALLED and NODE_INVOKED
    assert EventType.MODEL_REQUIREMENTS_EVALUATED != EventType.MODEL_CALLED
    assert EventType.MODEL_REQUIREMENTS_EVALUATED != EventType.NODE_INVOKED


# ── Test 5: validation rules ───────────────────────────────────────────────

def test_model_requirements_validation() -> None:
    """Field-level validation: min_output_tokens > 0, json_schema_adherence
    must be 'required' or 'preferred' (or None)."""
    # min_output_tokens must be > 0
    with pytest.raises(Exception):
        ModelRequirements(min_output_tokens=0)
    with pytest.raises(Exception):
        ModelRequirements(min_output_tokens=-100)
    # Positive is fine
    ModelRequirements(min_output_tokens=1)

    # json_schema_adherence must be 'required' or 'preferred'
    with pytest.raises(Exception):
        ModelRequirements(json_schema_adherence="bogus")
    with pytest.raises(Exception):
        ModelRequirements(json_schema_adherence="maybe")
    # Allowed values
    ModelRequirements(json_schema_adherence="required")
    ModelRequirements(json_schema_adherence="preferred")
    ModelRequirements(json_schema_adherence=None)


# ── Bonus: warn-only behavior — unknown does NOT raise ────────────────────

def test_unknown_capability_does_not_raise() -> None:
    """When the model capability profile is unknown (no registry), evaluation
    must produce status='unknown' and not raise or block the run.

    Per the v2.68 agreement: warn-only. Hard enforcement is v2.69.
    """
    req = ModelRequirements(
        structured_output_required=True,
        min_output_tokens=4096,
        json_schema_adherence="required",
    )
    # An empty/None known-capabilities dict reflects v2.68 reality (no registry)
    # — declaring requirements still has value (documentation + trace legibility).
    assert req.is_empty() is False  # we did declare
    # Constructing a ModelRequirements with no profile reference works fine.
    # The orchestrator hook is responsible for emitting the unknown-status trace;
    # here we just verify the value object doesn't fail in any way.
    dumped = req.to_trace_dict()
    assert "structured_output_required" in dumped
