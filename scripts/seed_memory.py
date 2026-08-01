"""Seed ChromaDB with initial domain knowledge for the research chain.

Run once to populate the memory store with verified baseline knowledge
that the chain can read across runs.
"""

import asyncio
import sys
from datetime import datetime, timezone

from nodechain.adapters.chroma_adapter import ChromaAdapter


SEED_DOCUMENTS = [
    {
        "id": "seed_ai_radiology_overview",
        "content": (
            "AI-assisted diagnosis in radiology has shown significant progress since 2015. "
            "Deep learning models, particularly convolutional neural networks (CNNs), have "
            "demonstrated radiologist-level performance in detecting pneumonia, lung nodules, "
            "breast cancer metastases, and diabetic retinopathy. Key challenges include "
            "limited generalization across hospitals, lack of diverse training data, and "
            "regulatory barriers to clinical deployment. The FDA has approved over 500 AI "
            "medical devices as of 2024, with radiology being the most common category."
        ),
        "metadata": {
            "subject": "AI radiology diagnosis overview",
            "confidence": 0.9,
            "source": "seed_knowledge",
            "domain": "medical_ai",
            "written_at": datetime.now(timezone.utc).isoformat(),
            "memory_type": "domain_knowledge",
        },
    },
    {
        "id": "seed_ai_healthcare_challenges",
        "content": (
            "Key challenges in AI healthcare deployment: (1) Data privacy and HIPAA compliance "
            "limit data sharing across institutions. (2) Model interpretability remains critical "
            "for clinician trust. (3) Distribution shift between training and deployment sites "
            "causes performance degradation. (4) Regulatory frameworks vary globally. "
            "(5) Integration with existing clinical workflows (EHR systems) is non-trivial. "
            "(6) Validation requires multi-site clinical trials, not just retrospective studies."
        ),
        "metadata": {
            "subject": "AI healthcare deployment challenges",
            "confidence": 0.85,
            "source": "seed_knowledge",
            "domain": "medical_ai",
            "written_at": datetime.now(timezone.utc).isoformat(),
            "memory_type": "domain_knowledge",
        },
    },
    {
        "id": "seed_llm_limitations_research",
        "content": (
            "Large language models in research synthesis have known limitations: "
            "(1) Hallucination of citations and factual claims. (2) Recency bias toward "
            "training data cutoff. (3) Inability to access paywalled or subscription content. "
            "(4) Tendency toward optimistic conclusions about AI capabilities. "
            "(5) Poor calibration of confidence scores. (6) Limited ability to detect "
            "methodological flaws in studies. These limitations must be disclosed in any "
            "AI-generated research summary."
        ),
        "metadata": {
            "subject": "LLM limitations in research synthesis",
            "confidence": 0.95,
            "source": "seed_knowledge",
            "domain": "ai_methodology",
            "written_at": datetime.now(timezone.utc).isoformat(),
            "memory_type": "methodological_knowledge",
        },
    },
    {
        "id": "seed_search_adapter_coverage",
        "content": (
            "The research chain uses 5 academic search APIs: Semantic Scholar (broad CS/biomedical "
            "coverage, citation graphs), arXiv (preprints, physics/CS/math), OpenAlex (broad "
            "multidisciplinary, open access), CrossRef (DOI metadata, citation links), and "
            "PubMed (biomedical/clinical). Each has strengths: Semantic Scholar for citation "
            "networks, arXiv for cutting-edge preprints, PubMed for clinical evidence, "
            "OpenAlex for comprehensive coverage, CrossRef for publication metadata."
        ),
        "metadata": {
            "subject": "search adapter coverage and strengths",
            "confidence": 0.95,
            "source": "seed_knowledge",
            "domain": "system_knowledge",
            "written_at": datetime.now(timezone.utc).isoformat(),
            "memory_type": "system_knowledge",
        },
    },
]


async def seed(chroma_url: str = "http://localhost:8000") -> None:
    """Seed ChromaDB with initial knowledge."""
    adapter = ChromaAdapter(base_url=chroma_url)

    # Check if ChromaDB is reachable
    healthy = await adapter.health_check()
    if not healthy:
        print(f"ChromaDB not reachable at {chroma_url}. Skipping seed.")
        print("Start ChromaDB first: docker run -p 8000:8000 chromadb/chroma")
        return

    print(f"ChromaDB healthy at {chroma_url}")

    # Add documents
    count = await adapter.add_documents(
        documents=SEED_DOCUMENTS,
        collection_name="memory",
    )
    print(f"Seeded {count} documents into ChromaDB 'memory' collection")

    # Verify by reading back
    results = await adapter.read_memory(
        subject="AI radiology",
        collection_name="memory",
        max_results=3,
    )
    print(f"Verification: read back {len(results)} documents")
    for r in results:
        print(f"  - {r.get('content', '')[:80]}...")

    await adapter.close()


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    asyncio.run(seed(url))
