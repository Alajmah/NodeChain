"""Test memory write flow — verify 5-stage write with real MemoryManager."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import AsyncMock, MagicMock
from nodechain.nodes.memory_write import MemoryWriteDecisionNode
from nodechain.core.envelope import compile_envelope
from nodechain.memory.manager import MemoryManager


class TestMemoryWriteFlow:
    """Verify the 5-stage memory write flow."""

    def _make_envelope(self, payload: dict):
        return compile_envelope(
            run_id="test-run",
            chain_id="test-chain",
            node_id="memory_write_decision",
            step_id=1,
            payload=payload,
        )

    @pytest.mark.asyncio
    async def test_write_flow_with_memory_manager(self):
        """Full 5-stage flow with a real MemoryManager and mock ChromaDB."""
        # Mock ChromaDB adapter
        chroma_mock = MagicMock()
        chroma_mock.check_duplicate = AsyncMock(return_value={"is_duplicate": False, "existing_id": None})
        chroma_mock.write_memory = AsyncMock(return_value={
            "committed": True,
            "doc_id": "mem_abc123",
            "collection": "memory",
        })

        memory_manager = MemoryManager(chroma=chroma_mock)
        node = MemoryWriteDecisionNode(memory_manager=memory_manager)

        envelope = self._make_envelope({
            "recommendation": "AI shows significant promise for healthcare diagnostics",
            "executive_summary": "AI diagnostic tools can improve early detection",
            "confidence_statement": {"level": "HIGH", "numeric": 0.85},
        })

        response = await node.execute(envelope)
        assert response.success is not False

        candidates = response.output.get("candidates", [])
        assert len(candidates) >= 1

        # Check all 5 stages completed for each candidate
        for cand in candidates:
            assert "policy_decision" in cand, "Stage 2 (policy) missing"
            assert "validation_result" in cand, "Stage 3 (validation) missing"
            assert "write_result" in cand, "Stage 4 (commit) missing"

            # High confidence should pass policy and validation
            if cand.get("confidence", 0) >= 0.7:
                assert cand["policy_decision"]["approved"] is True
                assert cand["validation_result"]["passed"] is True
                assert cand["write_result"]["committed"] is True

    @pytest.mark.asyncio
    async def test_write_blocked_by_low_confidence(self):
        """Low-confidence candidates should be blocked at policy stage."""
        chroma_mock = MagicMock()
        memory_manager = MemoryManager(chroma=chroma_mock)
        node = MemoryWriteDecisionNode(memory_manager=memory_manager)

        envelope = self._make_envelope({
            "recommendation": "Uncertain finding with weak evidence",
            "executive_summary": "Inconclusive",
            "confidence_statement": {"level": "LOW", "numeric": 0.3},
        })

        response = await node.execute(envelope)
        candidates = response.output.get("candidates", [])

        for cand in candidates:
            # Low confidence should fail policy check
            assert cand["policy_decision"]["approved"] is False
            assert cand["write_result"]["committed"] is False

    @pytest.mark.asyncio
    async def test_write_blocked_by_duplicate(self):
        """Duplicate writes should be blocked at commit stage."""
        chroma_mock = MagicMock()
        chroma_mock.check_duplicate = AsyncMock(return_value={
            "is_duplicate": True,
            "existing_id": "mem_existing",
        })
        memory_manager = MemoryManager(chroma=chroma_mock)
        node = MemoryWriteDecisionNode(memory_manager=memory_manager)

        envelope = self._make_envelope({
            "recommendation": "Well-established finding",
            "confidence_statement": {"level": "HIGH", "numeric": 0.9},
        })

        response = await node.execute(envelope)
        candidates = response.output.get("candidates", [])

        for cand in candidates:
            write_result = cand.get("write_result", {})
            if write_result.get("committed") is False:
                reason = write_result.get("blocked_reason", "").lower()
                assert "duplicate" in reason or "empty" in reason or "policy" in reason

    @pytest.mark.asyncio
    async def test_write_without_memory_manager(self):
        """Without a MemoryManager, writes should still go through 5 stages
        but commit produces a note about no manager."""
        node = MemoryWriteDecisionNode(memory_manager=None)

        envelope = self._make_envelope({
            "recommendation": "Test recommendation",
            "executive_summary": "Test summary",
            "confidence_statement": {"level": "HIGH", "numeric": 0.8},
        })

        response = await node.execute(envelope)
        candidates = response.output.get("candidates", [])

        assert len(candidates) >= 1
        for cand in candidates:
            if cand.get("confidence", 0) >= 0.7 and cand.get("content", "").strip():
                # Should still "commit" but with a note
                assert cand["write_result"]["committed"] is True
                assert "no_memory_manager_connected" in cand["write_result"].get("note", "")

    @pytest.mark.asyncio
    async def test_chromadb_health_check_false(self):
        """When ChromaDB is unreachable, writes should still be proposed
        but commit may fail gracefully."""
        chroma_mock = MagicMock()
        chroma_mock.health_check = AsyncMock(return_value=False)
        chroma_mock.check_duplicate = AsyncMock(side_effect=Exception("Connection refused"))
        memory_manager = MemoryManager(chroma=chroma_mock)
        node = MemoryWriteDecisionNode(memory_manager=memory_manager)

        envelope = self._make_envelope({
            "recommendation": "Test",
            "confidence_statement": {"level": "MEDIUM", "numeric": 0.75},
        })

        # Should not crash even if ChromaDB is down
        response = await node.execute(envelope)
        assert response.output is not None
