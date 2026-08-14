"""Direct tests for ReviewManager — the human review lifecycle.

Covers:
- needs_review for all risk levels and modes
- request_review for all review modes (auto-approve/reject/revision)
- resolve_resume_review for pre-made decisions and adapter fallback
- ReviewDecision shape validation
- Disabled mode
"""

import pytest
import os

from nodechain.runtime.review_manager import ReviewManager, ReviewDecision
from nodechain.core.state import ChainState


def _stub_review_transition(state, event, *, status, paused_at=None, metadata=None):
    """In-memory stand-in for the H0.5 atomic review-transition seam."""
    state.status = status
    state.paused_at = paused_at
    if metadata:
        state.metadata = {**(state.metadata or {}), **metadata}


def _make_review_manager():
    """Create a ReviewManager with the in-memory transition-seam stub."""
    return ReviewManager(
        commit_review_transition=_stub_review_transition,
        add_trace_event=lambda e: None,
    )


class TestNeedsReview:
    def test_high_risk_triggers(self):
        rm = _make_review_manager()
        assert rm.needs_review({"risk_level": "HIGH", "review_required": False}) is True

    def test_medium_risk_low_confidence_triggers(self):
        rm = _make_review_manager()
        assert rm.needs_review({"risk_level": "MEDIUM", "confidence": 0.2, "review_required": False}) is True

    def test_medium_risk_high_confidence_no_trigger(self):
        rm = _make_review_manager()
        assert rm.needs_review({"risk_level": "MEDIUM", "confidence": 0.8, "review_required": False}) is False

    def test_low_risk_no_trigger(self):
        rm = _make_review_manager()
        assert rm.needs_review({"risk_level": "LOW", "confidence": 0.8, "review_required": False}) is False

    def test_explicit_review_required_overrides(self):
        rm = _make_review_manager()
        assert rm.needs_review({"risk_level": "LOW", "confidence": 0.9, "review_required": True}) is True

    def test_disabled_mode_blocks_all(self):
        rm = _make_review_manager()
        os.environ["NODECHAIN_REVIEW_MODE"] = "disabled"
        try:
            assert rm.needs_review({"risk_level": "HIGH", "review_required": True}) is False
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]

    def test_no_risk_level_defaults_safe(self):
        rm = _make_review_manager()
        assert rm.needs_review({"confidence": 0.5}) is False

    def test_numeric_confidence_string_risk(self):
        rm = _make_review_manager()
        assert rm.needs_review({"risk_level": "high", "review_required": False}) is True


class TestRequestReview:
    @pytest.mark.asyncio
    async def test_auto_approve(self):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        try:
            rm = _make_review_manager()
            state = ChainState(chain_id="test")
            result = await rm.request_review(
                {"risk_level": "HIGH"}, state, "Test Chain", step_id=5
            )
            assert isinstance(result, ReviewDecision)
            assert result.decision == "approve"
            assert result.needs_review is True
            assert result.risk_assessment == {"risk_level": "HIGH"}
            assert result.review_request["step_id"] == 5
            # State should be restored to running
            assert state.status == "running"
            assert state.paused_at is None
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]

    @pytest.mark.asyncio
    async def test_auto_reject(self):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
        try:
            rm = _make_review_manager()
            state = ChainState(chain_id="test")
            result = await rm.request_review(
                {"risk_level": "HIGH"}, state, "Test Chain", step_id=3
            )
            assert result.decision == "reject"
            # H0.5 amendment 3: reject commits its terminal failed outcome
            # directly — no intermediate running state.
            assert state.status == "failed"
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]

    @pytest.mark.asyncio
    async def test_auto_revision(self):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-revision"
        try:
            rm = _make_review_manager()
            state = ChainState(chain_id="test")
            result = await rm.request_review(
                {"risk_level": "HIGH"}, state, "Test Chain", step_id=3
            )
            assert result.decision == "request_revision"
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]

    @pytest.mark.asyncio
    async def test_saves_waiting_state(self):
        """During review, state should be persisted as waiting_for_review."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        saved_statuses = []

        def capture_status(s):
            saved_statuses.append(s.status)

        def capture_transition(s, e, *, status, paused_at=None, metadata=None):
            _stub_review_transition(s, e, status=status, paused_at=paused_at, metadata=metadata)
            saved_statuses.append(s.status)

        rm = ReviewManager(
            commit_review_transition=capture_transition,
            add_trace_event=lambda e: None,
        )
        state = ChainState(chain_id="test")
        await rm.request_review({"risk_level": "HIGH"}, state, "Test", step_id=1)

        # The snapshot should have been saved with waiting_for_review status
        assert "waiting_for_review" in saved_statuses
        assert state.status == "running"

        del os.environ["NODECHAIN_REVIEW_MODE"]

    @pytest.mark.asyncio
    async def test_emits_trace_events(self):
        """Review should emit requested and completed events."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        events = []

        def capture_events(s, e, *, status, paused_at=None, metadata=None):
            _stub_review_transition(s, e, status=status, paused_at=paused_at, metadata=metadata)
            events.append(e)

        rm = ReviewManager(
            commit_review_transition=capture_events,
            add_trace_event=lambda e: None,
        )
        state = ChainState(chain_id="test")
        await rm.request_review({"risk_level": "HIGH"}, state, "Test", step_id=1)

        assert len(events) == 2
        event_types = [str(e.event_type) for e in events]
        assert any("REVIEW_REQUESTED" in t for t in event_types)
        assert any("REVIEW_COMPLETED" in t for t in event_types)

        del os.environ["NODECHAIN_REVIEW_MODE"]


class TestResolveResumeReview:
    @pytest.mark.asyncio
    async def test_pre_made_decision(self):
        """If review_decision is in metadata, use it directly."""
        rm = _make_review_manager()
        state = ChainState(chain_id="test")
        state.metadata["review_decision"] = "approve"
        state.metadata["review_request"] = {
            "risk_assessment": {"risk_level": "HIGH"},
            "step_id": 5,
            "node_id": "risk_classifier",
        }

        result = await rm.resolve_resume_review(state, "Test Chain")
        assert result.decision == "approve"
        assert result.risk_assessment == {"risk_level": "HIGH"}

    @pytest.mark.asyncio
    async def test_adapter_fallback(self):
        """Without pre-made decision, fall back to adapter."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
        try:
            rm = _make_review_manager()
            state = ChainState(chain_id="test")
            state.metadata["review_request"] = {
                "risk_assessment": {"risk_level": "HIGH"},
                "step_id": 5,
            }

            result = await rm.resolve_resume_review(state, "Test Chain")
            assert result.decision == "reject"
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]

    @pytest.mark.asyncio
    async def test_empty_metadata(self):
        """No review_request metadata should still work (empty risk)."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        try:
            rm = _make_review_manager()
            state = ChainState(chain_id="test")
            result = await rm.resolve_resume_review(state, "Test Chain")
            assert result.decision == "approve"
            assert result.risk_assessment == {}
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]


class TestReviewDecision:
    def test_decision_shape(self):
        rd = ReviewDecision(
            decision="approve",
            needs_review=True,
            review_request={"step_id": 1},
            risk_assessment={"risk_level": "HIGH"},
        )
        assert rd.decision == "approve"
        assert rd.needs_review is True
        assert rd.review_request["step_id"] == 1
        assert rd.risk_assessment["risk_level"] == "HIGH"
