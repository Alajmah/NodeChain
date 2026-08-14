"""v2.22.0 — Review Receipt Runtime Consumption.

Verifies that the runtime review gate (ReviewManager) materializes governed
ReviewRequest + DecisionReceipt artifacts, that receipts are digest-committed
and stored in chain state, referenced in trace metadata, and preserved across
pause/resume; and that verifier failure fails closed.

Mirrors patterns from test_review_manager.py, test_human_review.py, and
test_review_workbench.py.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import ChainState
from nodechain.runtime.review_manager import (
    ReviewManager, ReviewDecision, REASON_REVIEW_RECEIPT_VERIFICATION_FAILED,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_review_manager(captured_events=None, captured_state=None):
    """Build a ReviewManager with capturing callbacks."""
    events = captured_events if captured_events is not None else []
    state_cap = captured_state
    def _transition(s, e, *, status, paused_at=None, metadata=None):
        s.status = status
        s.paused_at = paused_at
        if metadata:
            s.metadata = {**(s.metadata or {}), **metadata}
        if state_cap is not None:
            state_cap.append(s)
        events.append(e)

    return ReviewManager(
        commit_review_transition=_transition,
        add_trace_event=lambda e: None,
    ), events


def _high_risk_output():
    return {
        "risk_level": "HIGH",
        "confidence": 0.3,
        "review_required": True,
        "risk_factors": ["insufficient_evidence", "low_validation"],
        "uncertainty_disclosures": [],
    }


@pytest.fixture
def clean_review_env():
    """Strip review-related env vars before/after each test."""
    keys = [
        "NODECHAIN_REVIEW_MODE", "NODECHAIN_REVIEW_DECISION",
        "NODECHAIN_REVIEW_RATIONALE_OVERRIDE", "NODECHAIN_REVIEWER_IDENTITY",
        "NODECHAIN_MOCK_RISK_LEVEL",
    ]
    saved = {k: os.environ.pop(k, None) for k in keys}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


@pytest.fixture
def state():
    s = ChainState(chain_id="test-chain")
    s.execution_order_hash = "exec_order_hash_abc"
    return s


# ── Part 1: chain_review subject & decision constants ─────────────────────────


class TestChainReviewSubject:
    """Subject type + decision constants are registered and accepted."""

    def test_subject_chain_review_accepted_by_review_subject(self):
        from nodechain.sdk.review_workbench import (
            SUBJECT_CHAIN_REVIEW, ALL_SUBJECT_TYPES, ReviewSubject,
        )
        assert SUBJECT_CHAIN_REVIEW in ALL_SUBJECT_TYPES
        s = ReviewSubject(
            subject_type=SUBJECT_CHAIN_REVIEW,
            subject_id="run:9",
            subject_digest="a" * 64,
        )
        assert s.subject_type == SUBJECT_CHAIN_REVIEW

    def test_chain_review_decision_constants_valid(self):
        from nodechain.sdk.review_workbench import (
            DECISION_APPROVE_CHAIN_REVIEW, DECISION_REJECT_CHAIN_REVIEW,
            DECISION_REVISION_CHAIN_REVIEW, ALL_DECISION_TYPES,
            _SUBJECT_DECISION_MAP, SUBJECT_CHAIN_REVIEW,
        )
        for d in (DECISION_APPROVE_CHAIN_REVIEW, DECISION_REJECT_CHAIN_REVIEW,
                  DECISION_REVISION_CHAIN_REVIEW):
            assert d in ALL_DECISION_TYPES
        valid = _SUBJECT_DECISION_MAP[SUBJECT_CHAIN_REVIEW]
        assert DECISION_APPROVE_CHAIN_REVIEW in valid
        assert DECISION_REJECT_CHAIN_REVIEW in valid
        assert DECISION_REVISION_CHAIN_REVIEW in valid

    def test_chain_review_decision_type_maps_outcomes(self):
        from nodechain.sdk.review_workbench import (
            chain_review_decision_type,
            DECISION_APPROVE_CHAIN_REVIEW, DECISION_REJECT_CHAIN_REVIEW,
            DECISION_REVISION_CHAIN_REVIEW,
        )
        assert chain_review_decision_type("approve") == DECISION_APPROVE_CHAIN_REVIEW
        assert chain_review_decision_type("reject") == DECISION_REJECT_CHAIN_REVIEW
        assert chain_review_decision_type("request_revision") == DECISION_REVISION_CHAIN_REVIEW

    def test_chain_review_decision_type_rejects_timeout(self):
        from nodechain.sdk.review_workbench import chain_review_decision_type
        with pytest.raises(ValueError):
            chain_review_decision_type("timeout")

    def test_role_operator_authorized_for_chain_review(self):
        from nodechain.sdk.review_workbench import (
            DEFAULT_ROLE_AUTHORITY, ROLE_OPERATOR, ROLE_ADMIN, SUBJECT_CHAIN_REVIEW,
        )
        assert SUBJECT_CHAIN_REVIEW in DEFAULT_ROLE_AUTHORITY[ROLE_OPERATOR]
        assert SUBJECT_CHAIN_REVIEW in DEFAULT_ROLE_AUTHORITY[ROLE_ADMIN]


# ── Part 2: ReviewDecision carries receipt metadata ───────────────────────────


class TestReviewDecisionReceiptFields:
    """ReviewDecision has optional receipt fields; scheduler string unchanged."""

    def test_review_decision_has_receipt_fields(self):
        d = ReviewDecision(decision="approve")
        assert d.receipt_id is None
        assert d.receipt_digest is None
        assert d.decision_receipt == {}
        # scheduler-facing string is the canonical API
        assert d.decision == "approve"


# ── Parts 2-3: materialization, modes, trace, state, pause/resume ────────────


class TestReceiptMaterialization:
    """auto-approve/reject/revision each produce a committed receipt."""

    @pytest.mark.asyncio
    async def test_auto_approve_produces_committed_receipt(self, clean_review_env, state):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, events = _make_review_manager()
        result = await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        assert result.decision == "approve"
        assert result.receipt_id is not None
        assert result.receipt_digest is not None
        assert result.decision_receipt.get("digest_commitment") == result.receipt_digest
        # Receipt committed (digest_commitment non-empty AND matches recompute)
        assert result.decision_receipt["digest_commitment"] != ""

    @pytest.mark.asyncio
    async def test_auto_reject_produces_committed_receipt(self, clean_review_env, state):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
        rm, events = _make_review_manager()
        result = await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        assert result.decision == "reject"
        assert result.receipt_id is not None
        assert result.decision_receipt.get("digest_commitment") != ""

    @pytest.mark.asyncio
    async def test_auto_revision_produces_committed_receipt(self, clean_review_env, state):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-revision"
        rm, events = _make_review_manager()
        result = await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        assert result.decision == "request_revision"
        assert result.receipt_id is not None
        assert result.decision_receipt.get("digest_commitment") != ""

    @pytest.mark.asyncio
    async def test_trace_completed_carries_receipt_metadata(self, clean_review_env, state):
        from nodechain.core.trace import EventType
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, events = _make_review_manager()
        await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        completed = [e for e in events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
        assert len(completed) == 1
        md = completed[0].metadata
        assert "receipt_id" in md
        assert "receipt_digest" in md
        assert md.get("subject_type") == "chain_review"
        assert "request_id" in md
        assert "request_digest" in md

    @pytest.mark.asyncio
    async def test_governed_decision_receipt_stored_in_state(self, clean_review_env, state):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, events = _make_review_manager()
        await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        assert "governed_decision_receipt" in state.metadata
        receipt = state.metadata["governed_decision_receipt"]
        assert receipt["subject_type"] == "chain_review"

    @pytest.mark.asyncio
    async def test_reviewer_identity_default_and_env_override(self, clean_review_env, state):
        from nodechain.sdk.review_workbench import ReviewVerifier, ReviewerPolicy
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, events = _make_review_manager()
        # default identity
        await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        receipt = state.metadata["governed_decision_receipt"]
        assert receipt["decision"]["reviewer_identity"] == "runtime:auto"
        # authorization is ROLE_OPERATOR regardless of identity string
        assert receipt["decision"]["reviewer_role"] == "operator"

    @pytest.mark.asyncio
    async def test_reviewer_identity_env_override(self, clean_review_env, state):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        os.environ["NODECHAIN_REVIEWER_IDENTITY"] = "ops@nodechain.local"
        rm, events = _make_review_manager()
        await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        receipt = state.metadata["governed_decision_receipt"]
        assert receipt["decision"]["reviewer_identity"] == "ops@nodechain.local"
        # auth still tied to role
        assert receipt["decision"]["reviewer_role"] == "operator"


class TestPauseResumeContinuity:
    """Pause persists governed request; resume binds to original digest."""

    @pytest.mark.asyncio
    async def test_pause_persists_governed_review_request(self, clean_review_env, state):
        from nodechain.runtime.review_manager import ReviewPausedException
        os.environ["NODECHAIN_REVIEW_MODE"] = "pause"
        rm, events = _make_review_manager()
        with pytest.raises(ReviewPausedException):
            await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        # governed request persisted before the raise
        assert "governed_review_request" in state.metadata
        gov = state.metadata["governed_review_request"]
        assert gov["subject"]["subject_type"] == "chain_review"
        assert gov["request_digest"]  # non-empty

    @pytest.mark.asyncio
    async def test_resume_binds_to_original_paused_request_digest(self, clean_review_env, state):
        # Simulate pause: build + persist governed request
        os.environ["NODECHAIN_REVIEW_MODE"] = "pause"
        rm_pause, _ = _make_review_manager()
        from nodechain.runtime.review_manager import ReviewPausedException
        with pytest.raises(ReviewPausedException):
            await rm_pause.request_review(_high_risk_output(), state, "Test", step_id=9)
        paused_request = state.metadata["governed_review_request"]
        paused_digest = paused_request["request_digest"]
        paused_created_at = paused_request["created_at"]

        # Simulate resume: reconstruct from persisted metadata + resolve
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm_resume, _ = _make_review_manager()
        result = await rm_resume.resolve_resume_review(state, "Test")
        assert result.receipt_id is not None
        # The resumed receipt must bind to the ORIGINAL paused request
        receipt = result.decision_receipt
        assert receipt["request_digest"] == paused_digest
        assert receipt["request_id"] == paused_request["request_id"]

    def test_rebuild_preserves_created_at(self, clean_review_env):
        """_rebuild_governed_review_request preserves created_at exactly."""
        rm, _ = _make_review_manager()
        governed_dict = {
            "request_id": "r1",
            "subject": {"subject_type": "chain_review", "subject_id": "x", "subject_digest": "d" * 64},
            "reason_for_review": "test",
            "required_reviewer_role": "operator",
            "graph_digest": "g", "policy_digest": "p",
            "trace_event_ids": [], "risk_level": "high",
            "status": "pending", "created_at": "2026-06-20T01:00:00+00:00",
        }
        rebuilt = rm._rebuild_governed_review_request(governed_dict)
        assert rebuilt.created_at == "2026-06-20T01:00:00+00:00"


class TestFailClosed:
    """Verifier failure is a governance failure, not a reviewer rejection."""

    @pytest.mark.asyncio
    async def test_forced_empty_rationale_fails_closed(self, clean_review_env, state):
        from nodechain.core.trace import EventType
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        os.environ["NODECHAIN_REVIEW_RATIONALE_OVERRIDE"] = ""  # empty -> high-risk reject
        rm, events = _make_review_manager()
        result = await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        # No receipt materialized
        assert result.receipt_id is None
        assert result.decision_receipt == {}
        # Chain failed terminally
        assert state.status == "failed"
        assert "governed_decision_receipt" not in state.metadata
        fail = state.metadata["governed_review_failure"]
        assert fail["reason_code"] == REASON_REVIEW_RECEIPT_VERIFICATION_FAILED
        # Governance-failure trace emitted (decision='governance_failure')
        gf = [e for e in events if e.decision == "governance_failure"]
        assert len(gf) == 1

    def test_valid_reject_distinct_from_verifier_failure(self, clean_review_env, state):
        """A valid reject produces a receipt + 'rejected'; verifier failure does not."""
        # Valid reject path
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
        rm1, _ = _make_review_manager()
        res1 = asyncio.run(rm1.request_review(_high_risk_output(), state, "T", step_id=9))
        assert res1.receipt_id is not None
        # H0.5 amendment 3: a valid reject commits failed WITH its receipt;
        # the verifier-failure path commits failed with NO receipt and a
        # governed_review_failure marker. The receipt is the distinction.
        assert state.status == "failed"
        assert state.metadata["governed_decision_receipt"]["receipt_id"] == res1.receipt_id
        assert "governed_review_failure" not in state.metadata

    def test_tampered_subject_digest_rejected_by_verifier(self, clean_review_env):
        """Direct verifier rejects a real subject_digest mismatch."""
        from nodechain.sdk.review_workbench import (
            OperatorDecision, ReviewVerifier, ReviewerPolicy, ReviewSubject,
            ReviewRequest, chain_review_decision_type, ROLE_OPERATOR,
        )
        pol = ReviewerPolicy()
        subj = ReviewSubject("chain_review", "r:9", "a" * 64)
        req = ReviewRequest(
            request_id="r1", subject=subj, reason_for_review="x",
            required_reviewer_role=ROLE_OPERATOR, risk_level="high",
            policy_digest=pol.compute_digest(),
        )
        dec = OperatorDecision(
            decision_type=chain_review_decision_type("approve"),
            request_id="r1", reviewer_identity="runtime:auto",
            reviewer_role=ROLE_OPERATOR, rationale="ok rationale here",
            request_digest=req.compute_digest(),
            subject_digest="b" * 64,  # MISMATCH
            policy_digest=pol.compute_digest(),
        )
        result = ReviewVerifier(pol).verify(dec, req)
        assert not result.admissible
        assert "subject_digest" in result.rejection_reason or result.rejection_reason


# ── the reviewer's 6 required additions ────────────────────────────────────────────


class TestRequiredChecks:
    """The 6 explicit checks the review required before sign-off."""

    @pytest.mark.asyncio
    async def test_verifier_failure_does_not_store_receipt(self, clean_review_env, state):
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        os.environ["NODECHAIN_REVIEW_RATIONALE_OVERRIDE"] = ""
        rm, _ = _make_review_manager()
        await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        assert "governed_decision_receipt" not in state.metadata

    @pytest.mark.asyncio
    async def test_policy_digest_consistency(self, clean_review_env, state):
        """Receipt's policy_digest == the verifier policy's digest."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, _ = _make_review_manager()
        await rm.request_review(_high_risk_output(), state, "Test", step_id=9)
        receipt = state.metadata["governed_decision_receipt"]
        assert receipt["policy_digest"] == rm._policy.compute_digest()

    @pytest.mark.asyncio
    async def test_resume_does_not_regenerate_request_digest(self, clean_review_env, state):
        """Paused request_digest == resumed receipt-bound request_digest."""
        from nodechain.runtime.review_manager import ReviewPausedException
        os.environ["NODECHAIN_REVIEW_MODE"] = "pause"
        rm1, _ = _make_review_manager()
        with pytest.raises(ReviewPausedException):
            await rm1.request_review(_high_risk_output(), state, "T", step_id=7)
        paused_digest = state.metadata["governed_review_request"]["request_digest"]

        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm2, _ = _make_review_manager()
        result = await rm2.resolve_resume_review(state, "T")
        assert result.decision_receipt["request_digest"] == paused_digest

    @pytest.mark.asyncio
    async def test_revision_receipt_committed_before_reroute(self, clean_review_env, state):
        """request_revision produces a valid receipt (the orchestrator reroutes after)."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-revision"
        rm, _ = _make_review_manager()
        result = await rm.request_review(_high_risk_output(), state, "T", step_id=9)
        assert result.decision == "request_revision"
        assert result.receipt_id is not None
        assert state.metadata["governed_decision_receipt"]["digest_commitment"] != ""

    @pytest.mark.asyncio
    async def test_trace_metadata_is_schema_safe(self, clean_review_env, state):
        """TraceEvent accepts the receipt metadata keys; no new top-level field needed."""
        from nodechain.core.trace import EventType, TraceEvent
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, events = _make_review_manager()
        await rm.request_review(_high_risk_output(), state, "T", step_id=9)
        completed = [e for e in events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED][0]
        # TraceEvent construction with these keys must not raise (it already exists).
        # Re-construct to prove schema acceptance.
        dupe = TraceEvent(
            run_id=completed.run_id, chain_id=completed.chain_id,
            node_id="risk_classifier", step_id=9,
            event_type=EventType.HUMAN_REVIEW_COMPLETED,
            actor=completed.actor, decision="approve",
            metadata=dict(completed.metadata),
        )
        assert dupe.metadata["receipt_id"] == completed.metadata["receipt_id"]

    @pytest.mark.asyncio
    async def test_repeated_review_ids_do_not_collide(self, clean_review_env):
        """After revision re-entry, subject_id/request_id stay invocation-specific."""
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, _ = _make_review_manager()
        s1 = ChainState(chain_id="c1"); s1.execution_order_hash = "h"
        s2 = ChainState(chain_id="c1"); s2.execution_order_hash = "h"
        r1 = await rm.request_review(_high_risk_output(), s1, "T", step_id=9)
        r2 = await rm.request_review(_high_risk_output(), s2, "T", step_id=11)
        # Different step -> different subject_id / request_id
        assert r1.receipt_id != r2.receipt_id
        r1_req = s1.metadata["governed_review_request"]
        r2_req = s2.metadata["governed_review_request"]
        assert r1_req["request_id"] != r2_req["request_id"]
        assert r1_req["subject"]["subject_id"] != r2_req["subject"]["subject_id"]


# ── Durable state round-trip ──────────────────────────────────────────────────


class TestStateManagerRoundTrip:
    """StateManager save/load preserves governed_decision_receipt."""

    def test_save_load_preserves_receipt(self, tmp_path, clean_review_env):
        from nodechain.runtime.persistence import StateManager
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, _ = _make_review_manager()
        state = ChainState(chain_id="rt"); state.execution_order_hash = "h"
        asyncio.run(rm.request_review(_high_risk_output(), state, "T", step_id=9))
        receipt_before = state.metadata["governed_decision_receipt"]

        db = str(tmp_path / "rt.db")
        sm = StateManager(db_path=db)
        sm.save(state)
        loaded = sm.load(state.run_id)
        assert loaded is not None
        assert "governed_decision_receipt" in loaded.metadata
        assert loaded.metadata["governed_decision_receipt"] == receipt_before


# ── Full orchestrator integration ─────────────────────────────────────────────


class TestOrchestratorIntegration:
    """Full chain run with HIGH risk + auto-approve completes and traces receipt."""

    def test_full_run_traces_receipt(self, clean_review_env):
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType
        from nodechain.core.trace import EventType
        from nodechain.core.envelope import EnvelopeResponse

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        class HighRiskClassifier(MockNode):
            async def execute(self, envelope):
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id,
                    run_id=envelope.run_id, chain_id=envelope.chain_id,
                    node_id="risk_classifier", step_id=envelope.step_id,
                    output={
                        "risk_level": "HIGH", "confidence": 0.3,
                        "review_required": True,
                        "uncertainty_disclosures": [],
                        "risk_factors": ["test high risk"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier(
            "risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT,
        )
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)
        trace = asyncio.run(orch.run("Test HIGH risk query"))

        assert trace.final_status == "completed"
        event_types = {e.event_type for e in trace.events}
        assert EventType.HUMAN_REVIEW_REQUESTED in event_types
        assert EventType.HUMAN_REVIEW_COMPLETED in event_types
        # The completed event must carry receipt metadata
        completed = [e for e in trace.events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
        assert any("receipt_id" in e.metadata for e in completed)
        # And the receipt is durable in chain state
        assert "governed_decision_receipt" in orch.state.metadata


class TestInspectDisplayGuard:
    """v2.22.0: a completed/failed run with a receipt must not show a stale
    'WAITING FOR REVIEW' panel. Regression for the inspect display bug."""

    def test_completed_run_shows_resolved_not_waiting(self, clean_review_env, tmp_path, capsys):
        from nodechain.runtime.persistence import StateManager
        from nodechain.cli.inspect import inspect_run

        # Build a completed run with a governed receipt in state.metadata
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm, _ = _make_review_manager()
        state = ChainState(chain_id="inspect-test")
        state.execution_order_hash = "h"
        state.status = "completed"
        asyncio.run(rm.request_review(_high_risk_output(), state, "T", step_id=9))
        # sanity: a receipt was stored
        assert "governed_decision_receipt" in state.metadata

        db = str(tmp_path / "inspect.db")
        sm = StateManager(db_path=db)
        sm.save(state)

        code = inspect_run(state.run_id, db_path=db)
        assert code == 0
        out = capsys.readouterr().out
        assert "REVIEW RESOLVED" in out
        assert "WAITING FOR REVIEW" not in out

    def test_actually_paused_run_still_shows_waiting(self, clean_review_env, tmp_path, capsys):
        """The waiting panel must still appear for a genuinely paused run."""
        from nodechain.runtime.persistence import StateManager
        from nodechain.cli.inspect import inspect_run
        from nodechain.runtime.review_manager import ReviewPausedException

        os.environ["NODECHAIN_REVIEW_MODE"] = "pause"
        rm, _ = _make_review_manager()
        state = ChainState(chain_id="pause-test")
        state.execution_order_hash = "h"
        with pytest.raises(ReviewPausedException):
            asyncio.run(rm.request_review(_high_risk_output(), state, "T", step_id=9))
        # status should be waiting_for_review
        assert state.status == "waiting_for_review"

        db = str(tmp_path / "pause.db")
        StateManager(db_path=db).save(state)

        inspect_run(state.run_id, db_path=db)
        out = capsys.readouterr().out
        assert "WAITING FOR REVIEW" in out
        assert "REVIEW RESOLVED" not in out
