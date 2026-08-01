"""Node 3: Context Selector — determine per-node access grants and search queries."""

from __future__ import annotations

import uuid
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


CONTEXT_SELECTOR_CONTRACT = NodeContract(
    contract_id="research.context-selector.v1",
    node_id="context_selector",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.TASK_PLAN,
        schema_ref="nodechain://schemas/semantic_types/task_plan",
        required_fields=["tasks", "source_routing"],
    ),
    exit=ExitContract(
        output_type=PortType.CONTEXT_BUNDLE,
        schema_ref="nodechain://schemas/semantic_types/context_bundle",
        guaranteed_fields=["plan_ref", "search_queries", "adapter_grants"],
    ),
    requirements=Requirements(
        model_required=False,
        memory_access="read",
    ),
)


class ContextSelectorNode(BaseNode):
    """
    Node 3: Deterministic node that compiles context bundles.
    Determines per-node adapter grants and builds search queries.
    No model call — pure deterministic transformation.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="context_selector",
            node_type="deterministic",
            name="Context Selector",
            description="Compiles context bundles with per-adapter grants and search queries.",
            contract=CONTEXT_SELECTOR_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        task_plan = envelope.payload
        tasks = task_plan.get("tasks", [])
        source_routing = task_plan.get("source_routing", {})

        # Compute the full adapter list from primary + secondary + domain_specific
        # BEFORE building per-task queries, so each query targets every adapter the
        # planner routed to — not just `primary`. v2.68 fix: previously line 74 used
        # `source_routing.get("primary", [])` only, which silently dropped secondary
        # and domain_specific adapters. They were granted (adapter_grants) but never
        # targeted, so the search tool never invoked them. This caused the chain to
        # see single-API results and the corroboration rule to loop to exhaustion.
        primary = source_routing.get("primary", [])
        secondary = source_routing.get("secondary", [])
        domain_specific_map = source_routing.get("domain_specific", {})
        domain_specific = []
        if isinstance(domain_specific_map, dict):
            for adapters in domain_specific_map.values():
                if isinstance(adapters, list):
                    domain_specific.extend(adapters)
                else:
                    domain_specific.append(adapters)
        elif isinstance(domain_specific_map, list):
            domain_specific.extend(domain_specific_map)

        # Ordered, de-duped target list for search queries. Use a dict to preserve
        # insertion order (primary first, then secondary, then domain_specific)
        # while deduping — matches the priority the planner intended.
        seen: set[str] = set()
        all_targets: list[str] = []
        for adapter in (primary + secondary + domain_specific):
            if adapter and adapter not in seen:
                seen.add(adapter)
                all_targets.append(adapter)

        adapter_grants = list(set(primary + secondary + domain_specific))

        # Build search queries from tasks
        search_queries = []
        for task in tasks:
            # Flatten any nested lists and ensure all terms are strings
            raw_terms = task.get("query_terms", [])
            flat_terms = []
            for t in raw_terms:
                if isinstance(t, list):
                    flat_terms.extend(str(x) for x in t)
                else:
                    flat_terms.append(str(t))
            query = {
                "query_id": str(uuid.uuid4()),
                "terms": flat_terms,
                "target_adapters": list(all_targets),
                "filters": {},
                "max_results": 10,
            }
            search_queries.append(query)

        # Get session memory if available
        session_memory = envelope.context.session_memory if envelope.context else []

        output = {
            "plan_ref": task_plan.get("plan_id", ""),
            "research_goal_ref": "",
            "search_queries": search_queries,
            "adapter_grants": adapter_grants,
            "session_memory": session_memory,
            "focus_areas": [t.get("description", "") for t in tasks],
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="context_selector",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CONTEXT_BUNDLE,
        )
