"""v2.92: Contract Preflight Controller — extracted from Orchestrator.

Internal implementation detail. Orchestrator remains the public facade; this
controller holds the contract-validation logic that was previously inline in
Orchestrator.validate_contracts().

Responsibilities:
  - Validate backbone connections via ContractRegistry
  - Validate port compatibility (including branches and joins)
  - Emit CONTRACT_VALIDATED trace events on validation failures
  - Return list of issue strings (empty = all valid)

The all_contracts_validated success event is emitted by the Orchestrator
(via _emit_all_contracts_validated from NodeEventEmitterMixin), not by this
controller — preserving the pre-extraction ordering where the success event
fires from run() after validate_contracts() returns empty.

Behavior is identical to the pre-extraction code — this is a pure move
refactor. v2.91 characterization tests must pass unchanged.
"""
from __future__ import annotations

import os

from nodechain.core.blueprint import ChainBlueprint
from nodechain.core.contract import ContractRegistry
from nodechain.core.trace import Actor, ChainTrace, EventType, TraceEvent


class ContractPreflightController:
    """Validates node contracts and port connections before chain execution.

    Extracted from Orchestrator.validate_contracts() in v2.92.
    """

    def __init__(
        self,
        blueprint: ChainBlueprint,
        contract_registry: ContractRegistry,
        trace: ChainTrace,
    ) -> None:
        self.blueprint = blueprint
        self.contract_registry = contract_registry
        self.trace = trace

    def validate(self, run_id: str, chain_id: str) -> list[str]:
        """Validate all node contracts and port connections.

        Returns list of issue strings. Empty list = all valid.
        Emits CONTRACT_VALIDATED trace events on failures (not on success).

        Args:
            run_id: The current chain run ID (for trace event attribution).
            chain_id: The chain ID (for trace event attribution).
        """
        issues: list[str] = []

        # Validate all backbone connections
        connections = [
            {
                "from_node": c.from_node,
                "to_node": c.to_node,
            }
            for c in self.blueprint.connections
        ]
        results = self.contract_registry.validate_connections(connections)

        for result in results:
            if not result.compatible:
                issues.extend(result.issues)
                # Emit trace event for validation failure
                self.trace.add_event(
                    TraceEvent(
                        run_id=run_id,
                        chain_id=chain_id,
                        node_id=result.source_node,
                        step_id=0,
                        event_type=EventType.CONTRACT_VALIDATED,
                        actor=Actor.RUNTIME,
                        decision="invalid",
                        reason_codes=result.issues,
                    )
                )

        # Validate port compatibility (including branches and joins)
        from nodechain.validation.port_compatibility import validate_port_compatibility
        contracts = self.contract_registry.all_contracts()
        strict = os.environ.get("NODECHAIN_GOVERNANCE_STRICT", "").strip() in ("1", "true", "yes")
        port_report = validate_port_compatibility(self.blueprint, contracts, strict=strict)

        for error in port_report.errors:
            issue_str = (
                f"{error.source_node}:{error.source_port} → "
                f"{error.target_node}:{error.target_port}: "
                f"{error.message}"
            )
            issues.append(issue_str)

        return issues
