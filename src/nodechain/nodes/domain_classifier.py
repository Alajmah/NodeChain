"""Domain Classifier Node — classifies query domain and selects search branches."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
from nodechain.nodes.base_node import BaseNode

DOMAIN_CLASSIFIER_CONTRACT = NodeContract(
    contract_id="branch.domain-classifier.v1",
    node_id="domain_classifier",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RESEARCH_GOAL,
        schema_ref="nodechain://schemas/semantic_types/normalized_research_goal",
        required_fields=[],  # Accept whatever goal_interpreter produces
    ),
    exit=ExitContract(
        output_type=PortType.TASK_PLAN,
        schema_ref="nodechain://schemas/semantic_types/task_plan",
        guaranteed_fields=["selected_branches", "domain"],
    ),
    requirements=Requirements(model_required=False),
)

# Domain → adapter mapping
DOMAIN_ADAPTER_MAP = {
    "biomedical": ["pubmed", "semantic_scholar"],
    "technical": ["arxiv", "semantic_scholar"],
    "general": ["openalex", "crossref"],
}


class DomainClassifierNode(BaseNode):
    """Classifies research query into domain categories and selects
    which search branches to execute.
    
    Output includes selected_branches for the orchestrator's branch logic,
    plus per-branch search queries.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="domain_classifier",
            node_type="deterministic",
            name="Domain Classifier",
            description="Classifies query domain and selects search branches.",
            contract=DOMAIN_CLASSIFIER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload
        
        # Extract query information — goal_interpreter output uses flat keys
        primary_question = payload.get("primary_question", "")
        domain = (payload.get("research_domain", "") or "").lower()
        domain_classifications = payload.get("domain_classification", [])
        key_terms = payload.get("key_terms", [])
        task_plan = payload.get("plan", payload.get("task_plan", {}))
        tasks = task_plan.get("tasks", [])
        
        # Also try nested normalized_goal (from research chain's context_selector)
        if not domain:
            ng = payload.get("normalized_goal", {})
            domain = (ng.get("domain", "") or "").lower()
            primary_question = primary_question or ng.get("primary_question", "")
        
        # Derive key_terms from sub_questions if not explicit
        if not key_terms:
            sub_questions = payload.get("sub_questions", [])
            key_terms = [primary_question] + [sq for sq in sub_questions if isinstance(sq, str)][:3]
        
        # Classify domain from goal domain + key terms
        selected_branches = self._classify_domain(domain, key_terms, primary_question, domain_classifications)
        
        # Build per-branch search queries
        branch_queries = {}
        for branch in selected_branches:
            queries = self._build_branch_queries(branch, tasks, key_terms)
            # Use the branch name as key (matches blueprint branch names)
            branch_queries[branch] = queries
        
        output = {
            "selected_branches": selected_branches,
            "branch_queries": branch_queries,
            "domain": domain,
            "classified_domains": selected_branches,
            "primary_question": primary_question,
        }
        
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="domain_classifier",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.TASK_PLAN,
        )
    
    def _classify_domain(
        self, domain: str, key_terms: list[str], question: str,
        domain_classifications: list[dict] | None = None,
    ) -> list[str]:
        """Determine which branches to execute based on domain signals."""
        branches = set()
        
        # Use domain_classification from goal_interpreter if available
        if domain_classifications:
            for dc in domain_classifications:
                d = (dc.get("domain", "") or "").lower()
                if d in ("biomedical", "medicine", "healthcare", "clinical", "health"):
                    branches.add("biomedical")
                elif d in ("computer_science", "technology", "technical", "ai", "ml"):
                    branches.add("technical")
        
        # Direct domain mapping
        if domain in ("healthcare", "biomedical", "medicine", "clinical"):
            branches.add("biomedical")
        if domain in ("computer_science", "technology", "technical", "ai", "ml"):
            branches.add("technical")
        
        # Keyword signals
        text = f"{question} {' '.join(key_terms)}".lower()
        biomedical_keywords = [
            "clinical", "medical", "patient", "ehr", "health", "diagnosis",
            "treatment", "disease", "drug", "mortality", "icu", "hospital",
            "pubmed", "biomedical",
        ]
        technical_keywords = [
            "transformer", "model", "architecture", "neural", "deep learning",
            "attention", "bert", "gpt", "rnn", "lstm", "arxiv", "algorithm",
        ]
        
        for kw in biomedical_keywords:
            if kw in text:
                branches.add("biomedical")
                break
        
        for kw in technical_keywords:
            if kw in text:
                branches.add("technical")
                break
        
        # Always include general as fallback
        branches.add("general")
        
        return sorted(branches)
    
    def _build_branch_queries(
        self, branch: str, tasks: list[dict], key_terms: list[str]
    ) -> list[dict]:
        """Build search queries for a specific branch."""
        adapters = DOMAIN_ADAPTER_MAP.get(branch, ["openalex"])
        queries = []
        
        for task in tasks[:3]:  # Max 3 tasks per branch
            terms = task.get("query_terms", key_terms)
            if isinstance(terms, list):
                terms = " ".join(str(t) for t in terms[:5])
            queries.append({
                "query_id": f"{branch}_{len(queries)}",
                "terms": terms,
                "target_adapters": adapters,
                "filters": {},
                "max_results": 5,
            })
        
        if not queries:
            queries.append({
                "query_id": f"{branch}_default",
                "terms": " ".join(str(t) for t in key_terms[:5]),
                "target_adapters": adapters,
                "filters": {},
                "max_results": 5,
            })
        
        return queries
