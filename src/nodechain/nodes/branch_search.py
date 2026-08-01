"""Branch Search Nodes — domain-specific search wrappers for the branch chain."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.contract import (
    EntryContract, ExitContract, Requirements, NodeContract,
)
from nodechain.nodes.base_node import BaseNode
from nodechain.nodes.search_tool import SearchToolNode


def _make_branch_search_contract(node_id: str) -> NodeContract:
    """Create a search contract for a branch search node."""
    return NodeContract(
        contract_id=f"branch.{node_id}.v1",
        node_id=node_id,
        version="1.0.0",
        entry=EntryContract(
            input_type=PortType.TASK_PLAN,
            schema_ref="nodechain://schemas/semantic_types/task_plan",
            required_fields=[],
        ),
        exit=ExitContract(
            output_type=PortType.RAW_SEARCH_RESULTS,
            schema_ref="nodechain://schemas/semantic_types/raw_search_results",
            guaranteed_fields=["results"],
        ),
        requirements=Requirements(
            model_required=False,
            # v2.43.1: branch search declares tool/adapter grants
            tools_required=["search"],
            adapters_required=[
                "semantic_scholar", "arxiv", "openalex", "crossref", "pubmed",
            ],
        ),
    )


class BranchSearchNode(BaseNode):
    """Domain-specific search node for branch chains.
    
    Wraps SearchToolNode with a branch-specific contract and adapter filter.
    """

    def __init__(self, node_id: str, adapter_filter: list[str] | None = None) -> None:
        self._node_id = node_id
        self._adapter_filter = adapter_filter
        self._inner = SearchToolNode(allow_unguarded=True)

    @property
    def manifest(self) -> NodeManifest:
        inner = self._inner.manifest
        return NodeManifest(
            node_id=self._node_id,
            node_type=inner.node_type,
            name=f"Branch Search ({self._node_id})",
            description=inner.description,
            contract=_make_branch_search_contract(self._node_id),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        # Build proper search payload from whatever we receive
        payload = envelope.payload
        
        # Get branch-specific queries — try both node_id and domain name as keys
        branch_queries = payload.get("branch_queries", {})
        queries = branch_queries.get(self._node_id, [])
        if not queries:
            # Try domain name: biomedical_search -> biomedical
            domain_name = self._node_id.replace("_search", "")
            queries = branch_queries.get(domain_name, [])
        
        # Build search_queries format that SearchToolNode expects
        search_queries = []
        for bq in queries:
            search_queries.append({
                "terms": [bq.get("terms", "")],
                "target_adapters": self._adapter_filter or bq.get("target_adapters", []),
                "max_results": bq.get("max_results", 5),
                "filters": bq.get("filters", {}),
            })
        
        # Fallback: use primary_question or key terms
        if not search_queries:
            question = payload.get("primary_question", "")
            terms = question if question else " ".join(str(t) for t in payload.get("key_terms", [])[:5])
            if terms:
                # v2.43.1: no hardcoded adapter fallback — use capabilities
                cap_adapters = getattr(envelope.capabilities, 'allowed_adapters', [])
                fallback_adapters = self._adapter_filter or cap_adapters[:1]
                search_queries = [{
                    "terms": [terms],
                    "target_adapters": fallback_adapters,
                    "max_results": 10,
                    "filters": {},
                }]
        
        # Construct payload that SearchToolNode expects
        search_payload = {
            "search_queries": search_queries,
            "adapter_grants": self._adapter_filter or [],
        }
        
        search_envelope = InvocationEnvelope(
            envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=self._node_id,
            step_id=envelope.step_id,
            payload=search_payload,
            context=envelope.context,
            capabilities=envelope.capabilities,
        )

        result = await self._inner.execute(search_envelope)

        return EnvelopeResponse(
            request_envelope_id=result.request_envelope_id,
            run_id=result.run_id,
            chain_id=result.chain_id,
            node_id=self._node_id,
            step_id=result.step_id,
            output=result.output,
            output_type=result.output_type,
            cost_usd=result.cost_usd,
            latency_ms=result.latency_ms,
        )
