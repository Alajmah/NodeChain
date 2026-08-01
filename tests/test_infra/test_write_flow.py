"""Tests for memory write flow."""

import pytest
from nodechain.memory.write_flow import WriteFlow


class TestProposalStage:
    def test_proposes_from_recommendation(self):
        flow = WriteFlow()
        candidates = flow.propose_candidates({
            "recommendation": "AI improves diagnostics by 20%",
            "executive_summary": "Summary here",
            "confidence_statement": {"numeric": 0.85},
            "query": "AI in healthcare",
        })
        assert len(candidates) >= 1
        assert candidates[0]["content"] == "AI improves diagnostics by 20%"
        assert candidates[0]["confidence"] == 0.85

    def test_no_candidates_without_recommendation(self):
        flow = WriteFlow()
        candidates = flow.propose_candidates({})
        assert len(candidates) == 0

    def test_proposes_summary_as_separate_candidate(self):
        flow = WriteFlow()
        candidates = flow.propose_candidates({
            "recommendation": "Rec",
            "executive_summary": "Different summary",
            "confidence_statement": {"numeric": 0.9},
            "query": "test",
        })
        assert len(candidates) == 2
        assert candidates[1]["memory_type"] == "session_summary"


class TestPolicyStage:
    def test_high_confidence_passes(self):
        flow = WriteFlow()
        result = flow.evaluate_policy({
            "content": "Sufficient content for memory",
            "confidence": 0.85,
        })
        assert result["allowed"] is True

    def test_low_confidence_blocked(self):
        flow = WriteFlow()
        result = flow.evaluate_policy({
            "content": "Content here",
            "confidence": 0.3,
        })
        assert result["allowed"] is False
        assert any("below threshold" in r for r in result["reasons"])

    def test_short_content_blocked(self):
        flow = WriteFlow()
        result = flow.evaluate_policy({
            "content": "hi",
            "confidence": 0.9,
        })
        assert result["allowed"] is False


class TestValidationStage:
    def test_valid_candidate_passes(self):
        flow = WriteFlow()
        result = flow.validate_candidate({
            "content": "Good content",
            "subject": "Good subject",
            "confidence": 0.85,
        })
        assert result["passed"] is True

    def test_empty_content_fails(self):
        flow = WriteFlow()
        result = flow.validate_candidate({
            "content": "",
            "subject": "subject",
            "confidence": 0.85,
        })
        assert result["passed"] is False

    def test_low_confidence_fails(self):
        flow = WriteFlow()
        result = flow.validate_candidate({
            "content": "Content",
            "subject": "subject",
            "confidence": 0.3,
        })
        assert result["passed"] is False


class TestFullFlow:
    @pytest.mark.asyncio
    async def test_full_flow_high_confidence(self):
        flow = WriteFlow()
        committed = []

        async def mock_commit(candidate):
            committed.append(candidate)
            return {"committed": True, "doc_id": "test_123"}

        result = await flow.execute_flow(
            {
                "recommendation": "AI improves outcomes significantly",
                "executive_summary": "Summary text that is different from rec",
                "confidence_statement": {"numeric": 0.85},
                "query": "AI healthcare",
            },
            commit_fn=mock_commit,
        )
        assert result["total_committed"] >= 1

    @pytest.mark.asyncio
    async def test_full_flow_low_confidence(self):
        flow = WriteFlow()

        result = await flow.execute_flow({
            "recommendation": "Uncertain finding",
            "confidence_statement": {"numeric": 0.3},
            "query": "test",
        })
        assert result["total_committed"] == 0
