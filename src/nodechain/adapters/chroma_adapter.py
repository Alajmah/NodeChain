"""ChromaDB Adapter — local vector store for documents and memory."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx


class ChromaAdapter:
    """
    Adapter for ChromaDB HTTP API (runs as Docker service or standalone).
    Handles both document search and memory store operations.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 30.0,
    ):
        if base_url is None:
            import os as _os
            host = _os.environ.get("CHROMA_HOST", "localhost")
            port = _os.environ.get("CHROMA_PORT", "8000")
            base_url = f"http://{host}:{port}"
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
            )
        return self._client

    async def health_check(self) -> bool:
        """Check if ChromaDB is reachable."""
        client = await self._ensure_client()
        try:
            resp = await client.get("/api/v2/heartbeat")
            return resp.status_code == 200
        except httpx.ConnectError:
            return False

    # ── Collection Management ──────────────────────────────────

    async def _get_or_create_collection(
        self, collection_name: str
    ) -> dict[str, Any]:
        """Get or create a ChromaDB collection."""
        client = await self._ensure_client()
        resp = await client.post(
            "/api/v2/collections",
            json={"name": collection_name, "get_or_create": True},
        )
        resp.raise_for_status()
        return resp.json()

    # ── Document Search ────────────────────────────────────────

    async def search_documents(
        self,
        query: str,
        collection_name: str = "documents",
        max_results: int = 10,
    ) -> list[dict[str, Any]]:
        """Search local document collection by semantic similarity."""
        collection = await self._get_or_create_collection(collection_name)
        collection_id = collection["id"]

        client = await self._ensure_client()
        resp = await client.post(
            f"/api/v2/collections/{collection_id}/query",
            json={
                "query_texts": [query],
                "n_results": max_results,
                "include": ["documents", "metadatas", "distances"],
            },
        )
        resp.raise_for_status()
        data = resp.json()

        results = []
        documents = data.get("documents", [[]])[0]
        metadatas = data.get("metadatas", [[]])[0]
        distances = data.get("distances", [[]])[0]

        for doc, meta, dist in zip(documents, metadatas, distances):
            results.append({
                "content": doc,
                "metadata": meta or {},
                "distance": dist,
                "source": meta.get("source", "local_document") if meta else "local_document",
            })

        return results

    async def add_documents(
        self,
        documents: list[dict[str, Any]],
        collection_name: str = "documents",
    ) -> int:
        """Add documents to the collection. Returns count added."""
        collection = await self._get_or_create_collection(collection_name)
        collection_id = collection["id"]

        client = await self._ensure_client()
        ids = [doc.get("id", str(uuid.uuid4())) for doc in documents]
        texts = [doc.get("content", "") for doc in documents]
        metadatas = [doc.get("metadata", {}) for doc in documents]

        resp = await client.post(
            f"/api/v2/collections/{collection_id}/add",
            json={
                "ids": ids,
                "documents": texts,
                "metadatas": metadatas,
            },
        )
        resp.raise_for_status()
        return len(documents)

    # ── Memory Operations ──────────────────────────────────────

    async def read_memory(
        self,
        subject: str,
        collection_name: str = "memory",
        max_results: int = 5,
    ) -> list[dict[str, Any]]:
        """Read from memory collection by subject."""
        return await self.search_documents(
            query=subject,
            collection_name=collection_name,
            max_results=max_results,
        )

    async def write_memory(
        self,
        candidate: dict[str, Any],
        collection_name: str = "memory",
    ) -> dict[str, Any]:
        """
        Write a memory candidate to the memory collection.
        Returns write result with commit status.
        """
        content = candidate.get("content", "")
        subject = candidate.get("subject", "")
        confidence = candidate.get("confidence", 0.0)
        provenance = candidate.get("provenance", {})

        # Generate deterministic ID from content hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        doc_id = f"mem_{content_hash}"

        metadata = {
            "subject": subject,
            "confidence": confidence,
            "written_at": datetime.now(timezone.utc).isoformat(),
            "origin_chain": provenance.get("chain_id", ""),
            "origin_run": provenance.get("run_id", ""),
            "source_count": provenance.get("source_count", 0),
            "memory_type": candidate.get("memory_type", "session_knowledge"),
        }

        collection = await self._get_or_create_collection(collection_name)
        collection_id = collection["id"]

        client = await self._ensure_client()
        resp = await client.post(
            f"/api/v2/collections/{collection_id}/add",
            json={
                "ids": [doc_id],
                "documents": [content],
                "metadatas": [metadata],
            },
        )

        if resp.status_code in (200, 201):
            return {
                "committed": True,
                "doc_id": doc_id,
                # v2.27.0: write_ref aliases doc_id so trace metadata and the
                # side-effect ledger's external_reference carry the real durable
                # identifier. Previously the orchestrator read write_ref but the
                # adapter only returned doc_id, leaving the binding always empty.
                "write_ref": doc_id,
                "collection": collection_name,
            }
        else:
            return {
                "committed": False,
                "error": f"ChromaDB returned {resp.status_code}: {resp.text[:200]}",
            }

    async def check_duplicate(
        self,
        subject: str,
        content: str,
        collection_name: str = "memory",
        window_hours: int = 24,
        similarity_threshold: float = 0.95,
    ) -> dict[str, Any]:
        """
        Check if a similar memory already exists within the time window.
        Returns {"is_duplicate": bool, "existing_id": str | None}.
        """
        results = await self.read_memory(
            subject=subject,
            collection_name=collection_name,
            max_results=5,
        )

        for result in results:
            distance = result.get("distance", 1.0)
            # ChromaDB distance: lower = more similar (for cosine, 0 = identical)
            if distance < (1.0 - similarity_threshold):
                return {
                    "is_duplicate": True,
                    "existing_id": result.get("metadata", {}).get("id", ""),
                }

        return {"is_duplicate": False, "existing_id": None}

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
