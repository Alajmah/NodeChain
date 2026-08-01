"""Domain Router — routes research queries to appropriate academic APIs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RoutingDecision(BaseModel):
    """Result of domain routing."""

    primary: list[str]
    secondary: list[str]
    domain_specific: list[str]
    routing_reason: str


# Domain-to-adapter mapping
DOMAIN_ROUTES: dict[str, dict[str, list[str]]] = {
    "biomedical": {
        "primary": ["pubmed", "semantic_scholar"],
        "secondary": ["crossref", "openalex"],
        "domain_specific": ["pubmed"],
    },
    "computer_science": {
        "primary": ["semantic_scholar", "arxiv"],
        "secondary": ["crossref", "openalex"],
        "domain_specific": ["arxiv"],
    },
    "mathematics": {
        "primary": ["arxiv", "semantic_scholar"],
        "secondary": ["crossref"],
        "domain_specific": ["arxiv"],
    },
    "physics": {
        "primary": ["arxiv", "semantic_scholar"],
        "secondary": ["crossref", "openalex"],
        "domain_specific": ["arxiv"],
    },
    "social_sciences": {
        "primary": ["semantic_scholar", "openalex"],
        "secondary": ["crossref"],
        "domain_specific": ["openalex"],
    },
    "engineering": {
        "primary": ["semantic_scholar", "openalex"],
        "secondary": ["crossref", "arxiv"],
        "domain_specific": [],
    },
    "general": {
        "primary": ["semantic_scholar", "openalex"],
        "secondary": ["crossref"],
        "domain_specific": [],
    },
}

# Keywords for domain detection
DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "biomedical": [
        "medical", "clinical", "drug", "disease", "patient", "therapy",
        "biology", "genetics", "pharmaceutical", "health", "hospital",
        "cancer", "diagnosis", "treatment", "vaccine", "epidemiology",
        "neuroscience", "immunology", "pathology",
    ],
    "computer_science": [
        "algorithm", "software", "programming", "machine learning",
        "artificial intelligence", "neural network", "database",
        "computer vision", "nlp", "deep learning", "blockchain",
        "cybersecurity", "distributed systems", "cloud computing",
    ],
    "mathematics": [
        "theorem", "proof", "mathematical", "calculus", "algebra",
        "topology", "statistics", "probability", "optimization",
        "differential", "geometry", "number theory",
    ],
    "physics": [
        "quantum", "particle", "physics", "astrophysics", "cosmology",
        "thermodynamics", "relativity", "electromagnetic", "nuclear",
        "condensed matter", "photonics",
    ],
    "social_sciences": [
        "sociology", "psychology", "economics", "political",
        "anthropology", "education", "social", "policy",
        "demographics", "behavioral", "cognitive",
    ],
    "engineering": [
        "engineering", "structural", "mechanical", "electrical",
        "civil", "materials science", "manufacturing", "robotics",
        "aerospace", "automotive", "energy",
    ],
}


def detect_domain(research_goal: str, domain_hints: list[str] | None = None) -> str:
    """
    Detect the research domain from the query text.
    Uses keyword matching. Returns domain string.
    """
    text = research_goal.lower()

    # Score each domain by keyword matches
    scores: dict[str, int] = {}
    for domain, keywords in DOMAIN_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        scores[domain] = score

    # Apply domain hints from task planner if available
    if domain_hints:
        for hint in domain_hints:
            hint_lower = hint.lower()
            for domain in DOMAIN_ROUTES:
                if hint_lower in domain or domain in hint_lower:
                    scores[domain] = scores.get(domain, 0) + 3

    # Return highest scoring domain, default to general
    if not scores or max(scores.values()) == 0:
        return "general"

    return max(scores, key=scores.get)  # type: ignore[arg-type]


def route_to_adapters(
    domain: str,
    source_routing: dict[str, Any] | None = None,
) -> RoutingDecision:
    """
    Route to appropriate adapters based on detected domain.
    Respects source_routing overrides from Task Planner when provided.
    """
    if source_routing:
        return RoutingDecision(
            primary=source_routing.get("primary", []),
            secondary=source_routing.get("secondary", []),
            domain_specific=source_routing.get("domain_specific", {}).get(
                domain, []
            ),
            routing_reason=f"Task planner routing for domain: {domain}",
        )

    route = DOMAIN_ROUTES.get(domain, DOMAIN_ROUTES["general"])
    return RoutingDecision(
        primary=route["primary"],
        secondary=route["secondary"],
        domain_specific=route["domain_specific"],
        routing_reason=f"Auto-detected domain: {domain}",
    )
