"""Evidence Joiner Node — merges evidence from multiple branches."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
from nodechain.nodes.base_node import BaseNode


class EvidenceJoinerNode(BaseNode):
    """Joins evidence from multiple search branches into a unified evidence base.
    
    Receives merged branch outputs from the orchestrator and produces
    a deduplicated, merged evidence set.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="evidence_joiner",
            node_type="deterministic",
            name="Evidence Joiner",
            description="Merges evidence from multiple search branches.",
            contract=NodeContract(
                contract_id="branch.evidence-joiner.v1",
                node_id="evidence_joiner",
                version="1.0.0",
                entry=EntryContract(
                    input_type=PortType.RAW_SEARCH_RESULTS,
                    schema_ref="nodechain://schemas/semantic_types/raw_search_results",
                    required_fields=[],
                ),
                exit=ExitContract(
                    output_type=PortType.EVIDENCE_BASE,
                    schema_ref="nodechain://schemas/semantic_types/evidence_base",
                    guaranteed_fields=["sources", "merge_summary", "claims"],
                ),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload
        branch_outputs = payload.get("branch_outputs", {})
        
        all_claims = payload.get("claims", [])
        all_sources = payload.get("sources", [])
        
        # Collect claims and sources from executed branches
        branch_stats = {}
        for branch_name, branch_result in branch_outputs.items():
            if branch_result.get("skipped"):
                branch_stats[branch_name] = {"status": "skipped", "claims": 0, "sources": 0}
                continue
            
            branch_claims = 0
            branch_sources = 0
            for node_id, node_output in branch_result.get("outputs", {}).items():
                if isinstance(node_output, dict):
                    if "claims" in node_output:
                        branch_claims += len(node_output["claims"])
                    if "sources" in node_output:
                        branch_sources += len(node_output["sources"])
            
            branch_stats[branch_name] = {
                "status": "executed",
                "claims": branch_claims,
                "sources": branch_sources,
            }
        
        # Deduplicate sources by title
        seen_titles = set()
        unique_sources = []
        for s in all_sources:
            if isinstance(s, dict):
                title = (s.get("title", "") or "").strip().lower()
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    unique_sources.append(s)
            else:
                unique_sources.append(s)
        
        # Detect conflicts between branches
        conflicts = self._detect_conflicts(all_claims)
        
        output = {
            "sources": unique_sources,
            "claims": all_claims,
            "branch_stats": branch_stats,
            "conflicts": conflicts,
            "merge_summary": {
                "total_sources_raw": len(all_sources),
                "total_sources_deduplicated": len(unique_sources),
                "total_claims": len(all_claims),
                "total_conflicts": len(conflicts),
                "branches_executed": sum(
                    1 for b in branch_stats.values() 
                    if b["status"] == "executed"
                ),
                "branches_skipped": sum(
                    1 for b in branch_stats.values() 
                    if b["status"] == "skipped"
                ),
            },
        }
        
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="evidence_joiner",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.EVIDENCE_BASE,
        )
    
    def _detect_conflicts(self, claims: list[dict]) -> list[dict]:
        """Detect claims that contradict each other."""
        if len(claims) < 2:
            return []
        
        conflicts = []
        for i, c1 in enumerate(claims):
            for c2 in claims[i+1:]:
                if not isinstance(c1, dict) or not isinstance(c2, dict):
                    continue
                # Simple heuristic: check for opposite confidence directions
                # on similar topics
                stmt1 = (c1.get("statement", "") or "").lower()
                stmt2 = (c2.get("statement", "") or "").lower()
                if stmt1 and stmt2 and self._are_contradictory(stmt1, stmt2):
                    conflicts.append({
                        "claim_1": c1.get("claim_id", f"claim_{i}"),
                        "claim_2": c2.get("claim_id", f"claim_{i+1}"),
                        "type": "potential_contradiction",
                    })
        return conflicts
    
    def _are_contradictory(self, s1: str, s2: str) -> bool:
        """Simple contradiction detection via negation patterns."""
        negation_words = ["not", "no ", "never", "fails", "unable", "cannot"]
        for neg in negation_words:
            if neg in s1 and neg not in s2:
                # One statement has negation, other doesn't — possible conflict
                # Check for topic overlap (common words)
                words1 = set(s1.replace(neg, "").split())
                words2 = set(s2.split())
                overlap = words1 & words2
                if len(overlap) >= 3:
                    return True
        return False
