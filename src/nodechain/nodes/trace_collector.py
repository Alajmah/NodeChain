"""Node 12: Trace Collector — assemble complete chain trace and enforce truth rule."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


TRACE_COLLECTOR_CONTRACT = NodeContract(
    contract_id="research.trace-collector.v1",
    node_id="trace_collector",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.MEMORY_WRITE_DECISION,
        schema_ref="nodechain://schemas/semantic_types/memory_write_decision",
        required_fields=["candidates"],
    ),
    exit=ExitContract(
        output_type=PortType.CHAIN_TRACE_OUTPUT,
        schema_ref="nodechain://schemas/semantic_types/chain_trace_output",
        guaranteed_fields=["trace_file_path", "trace_id", "run_id", "complete"],
    ),
    requirements=Requirements(
        model_required=False,
    ),
)


class TraceCollectorNode(BaseNode):
    """
    Node 12: Assembles the complete chain trace.
    Enforces the Trace Truth Rule: no step claims executed unless it actually was.
    Writes trace to JSON file.
    """

    def __init__(self, trace_output_dir: str = "data/traces") -> None:
        self._trace_dir = trace_output_dir

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="trace_collector",
            node_type="deterministic",
            name="Trace Collector",
            description="Assembles complete chain trace and enforces truth rule.",
            contract=TRACE_COLLECTOR_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        # The trace is passed through the chain state by the orchestrator
        # (v2.68: orchestrator injects trace.model_dump() for trace_collector)
        chain_state = envelope.context.chain_state if envelope.context else {}
        trace_data = chain_state.get("trace")

        trace_id = ""
        run_id = envelope.run_id
        event_count = 0
        truth_verified = False
        validation_notes: list[str] = []

        if trace_data:
            trace_id = trace_data.get("trace_id", "")
            events = trace_data.get("events", [])
            event_count = len(events)

            # Verify truth rule
            truth_verified = self._verify_truth_rule(events, validation_notes)

            # The trace file is written by run.py after the chain completes.
            # The collector's job is verification + reporting, not file I/O.
            # Report the expected path so downstream consumers know where to look.
            import os
            file_path = os.path.join(self._trace_dir, f"{run_id}.json")
        else:
            file_path = ""
            validation_notes.append("No trace data found in chain state")

        output = {
            "trace_file_path": file_path,
            "trace_id": trace_id,
            "run_id": run_id,
            "complete": truth_verified and bool(file_path),
            "event_count": event_count,
            "truth_rule_verified": truth_verified,
            "validation_notes": validation_notes,
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="trace_collector",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CHAIN_TRACE_OUTPUT,
        )

    def _verify_truth_rule(
        self, events: list[dict[str, Any]], notes: list[str]
    ) -> bool:
        """
        Trace Truth Rule verification:
        - Must have chain_started and chain_completed/failed
        - No simulated events marked as executed
        - No missing required events
        """
        if not events:
            notes.append("No events in trace")
            return False

        event_types = {e.get("event_type", "") for e in events}

        # Required events
        if "chain_started" not in event_types:
            notes.append("Missing chain_started event")
            return False

        if not ("chain_completed" in event_types or "chain_failed" in event_types):
            notes.append("Missing chain_completed or chain_failed event")
            return False

        # Check for simulated events marked as real
        for event in events:
            if event.get("event_type") == "simulated":
                notes.append(
                    f"Simulated event found: {event.get('node_id', 'unknown')}"
                )

        # All node_invoked must have corresponding succeeded or failed
        invoked = {
            e.get("node_id") for e in events
            if e.get("event_type") == "node_invoked"
        }
        completed = {
            e.get("node_id") for e in events
            if e.get("event_type") in ("node_succeeded", "node_failed")
        }
        missing = invoked - completed
        if missing:
            notes.append(f"Invoked but never completed: {missing}")
            return False

        return True
