"""Memory Manager — orchestrates memory read/write operations."""

from __future__ import annotations

from typing import Any

from nodechain.adapters.chroma_adapter import ChromaAdapter


class MemoryManager:
    """
    Orchestrates memory operations through the ChromaDB adapter.
    Handles reads, writes, and dedup checks.
    """

    def __init__(self, chroma: ChromaAdapter | None = None):
        self.chroma = chroma or ChromaAdapter()

    async def search_session_memory(
        self,
        query: str,
        max_results: int = 5,
    ) -> list[dict[str, Any]]:
        """Search session memory for relevant prior knowledge."""
        return await self.chroma.read_memory(
            subject=query,
            collection_name="memory",
            max_results=max_results,
        )

    async def search_local_documents(
        self,
        query: str,
        max_results: int = 10,
    ) -> list[dict[str, Any]]:
        """Search local document collection."""
        return await self.chroma.search_documents(
            query=query,
            collection_name="documents",
            max_results=max_results,
        )

    async def commit_write_candidate(
        self,
        candidate: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute the commit stage of the 5-stage write flow.
        Returns write result from ChromaDB.
        """
        # Dedup check
        dedup = await self.chroma.check_duplicate(
            subject=candidate.get("subject", ""),
            content=candidate.get("content", ""),
            collection_name="memory",
        )
        if dedup["is_duplicate"]:
            return {
                "committed": False,
                "reason": "duplicate_detected",
                "existing_id": dedup["existing_id"],
            }

        # Write to ChromaDB
        result = await self.chroma.write_memory(candidate)
        return result

    async def health_check(self) -> bool:
        """Check if ChromaDB is reachable."""
        return await self.chroma.health_check()
