"""Dedup — duplicate detection for memory writes."""

from __future__ import annotations

import hashlib
from typing import Any


def content_fingerprint(content: str) -> str:
    """Generate a deterministic fingerprint for content."""
    normalized = (content or "").strip().lower()
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def check_text_similarity(content_a: str, content_b: str) -> float:
    """
    Simple Jaccard similarity between two texts.
    Returns 0.0–1.0 where 1.0 = identical.
    """
    words_a = set(content_a.lower().split())
    words_b = set(content_b.lower().split())

    if not words_a and not words_b:
        return 1.0
    if not words_a or not words_b:
        return 0.0

    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)


def find_duplicate(
    candidate_content: str,
    existing_entries: list[dict[str, Any]],
    threshold: float = 0.9,
) -> dict[str, Any] | None:
    """
    Check if a candidate is a duplicate of any existing entry.
    Returns the matching entry or None.
    """
    candidate_fp = content_fingerprint(candidate_content)

    for entry in existing_entries:
        existing_content = entry.get("content", "")
        existing_fp = entry.get("fingerprint", "")

        # Exact fingerprint match
        if existing_fp and candidate_fp == existing_fp:
            return entry

        # Similarity check
        similarity = check_text_similarity(candidate_content, existing_content)
        if similarity >= threshold:
            return entry

    return None
