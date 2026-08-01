"""v2.26.0 — Reconciler Review Attempt Binding.

Verifies the audit triangle: trace ↔ receipt ↔ attempt log. The new
_check_review_attempt_binding (sibling to the v2.23.0 receipt binding) binds
review_decision_attempts rows to the HUMAN_REVIEW_COMPLETED trace event and
the persisted DecisionReceipt.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler


def _high_risk():
    return {"risk_level": "HIGH", "confidence": 0.3, "review_required": True,
            "risk_factors": ["x"], "uncertainty_disclosures": []}


def _make_trace(run_id, events=None):
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


def _completed_event(run_id, step_id, metadata=None, decision="approve"):
    return TraceEvent(
        run_id=run_id, chain_id="test-chain", node_id="risk_classifier",
        step_id=step_id, event_type=EventType.HUMAN_REVIEW_COMPLETED,
        actor=Actor.HUMAN, decision=decision, metadata=metadata or {},
    )


def _record_attempt(sm, run_id, *, admitted=True, rejection_reason="",
                    attempt_id="rda1", outcome="approve", request_digest="d",
                    subject_type="chain_review", reviewer_identity="runtime:auto",
                    subject_id="r:9"):
    sm.record_review_attempt({
        "review_attempt_id": attempt_id, "run_id": run_id, "chain_id": "c",
        "step_id": 9, "request_id": "req1", "request_digest": request_digest,
        "subject_type": subject_type, "subject_id": subject_id,
        "attempted_decision_type": "approve_chain_review", "attempted_outcome": outcome,
        "reviewer_identity": reviewer_identity, "required_reviewer_role": "operator",
        "admitted": admitted, "rejection_reason": rejection_reason,
        "verifier_checks": {"warnings": []}, "policy_digest": "p",
        "graph_digest": "", "created_at": "2026-06-20T01:00:00+00:00",
        "retention_status": "active",
    })


@pytest.fixture
def clean_env():
    keys = ["NODECHAIN_REVIEW_MODE", "NODECHAIN_REVIEW_RATIONALE_OVERRIDE",
            "NODECHAIN_REVIEWER_IDENTITY", "NODECHAIN_MOCK_RISK_LEVEL",
            "NODECHAIN_DB_PATH"]
    saved = {k: os.environ.pop(k, None) for k in keys}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


def _produce_full_run(db_path, mode="auto-approve"):
    """Produce a run with receipt + attempt + trace via the real ReviewManager."""
    from nodechain.runtime.review_manager import ReviewManager
    os.environ["NODECHAIN_REVIEW_MODE"] = mode
    events = []
    sm = StateManager(db_path=db_path)
    rm = ReviewManager(
        save_snapshot=lambda s: None,
        add_trace_event=lambda e: events.append(e),
        record_attempt=sm.record_review_attempt,
    )
    state = ChainState(chain_id="bind")
    state.execution_order_hash = "h"
    asyncio.run(rm.request_review(_high_risk(), state, "T", step_id=9))
    sm.save(state)
    completed = [e for e in events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
    return state, sm, (completed[0] if completed else None)


# ── Clean audit triangle ─────────────────────────────────────────────────────


class TestCleanAttemptBinding:
    def test_admitted_attempt_bound_to_trace_and_receipt(self, clean_env, tmp_path):
        db = str(tmp_path / "clean.db")
        state, sm, completed_ev = _produce_full_run(db)
        assert completed_ev, "setup: no completed event"
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata=completed_ev.metadata),
        ])
        report = TraceReconciler(sm).reconcile(trace)
        attempt_errors = [i for i in report.errors if "attempt" in i.check]
        assert attempt_errors == [], f"unexpected attempt errors: {attempt_errors}"


# ── Missing / mismatch detection ─────────────────────────────────────────────


class TestAttemptMissing:
    def test_missing_admitted_attempt_is_error(self, clean_env, tmp_path):
        """A completed review with NO attempt row in the log → error."""
        db = str(tmp_path / "miss.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="m")
        # No attempt recorded.
        sm.save(state)
        md = {"receipt_id": "r", "receipt_digest": "d", "request_id": "q", "request_digest": "qd"}
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=md)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_log_missing" for i in report.errors)

    def test_request_digest_mismatch_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "rdm.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="m")
        sm.save(state)
        _record_attempt(sm, state.run_id, request_digest="attempt_digest")
        md = {"receipt_id": "r", "receipt_digest": "d", "request_id": "q",
              "request_digest": "trace_digest"}  # differs from attempt
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=md)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_request_digest_mismatch" for i in report.errors)

    def test_subject_type_drift_is_error(self, clean_env, tmp_path):
        """code-review fix: subject_type drift is now ERROR (was warning)."""
        db = str(tmp_path / "subj.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="m")
        sm.save(state)
        _record_attempt(sm, state.run_id, subject_type="deployment")
        md = {"receipt_id": "r", "receipt_digest": "d", "request_id": "q", "request_digest": "d"}
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=md)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_subject_type_unexpected" and i.severity == "error"
                   for i in report.issues)


# ── Governance failure path ──────────────────────────────────────────────────


class TestGovernanceFailureAttemptBinding:
    def test_zero_non_admitted_for_failure_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "gf0.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="gf")
        sm.save(state)
        # No attempt recorded, but a governance_failure trace event exists.
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata={"rejection_reason": "x"},
                             decision="governance_failure"),
        ])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_log_missing" for i in report.errors)

    def test_multiple_non_admitted_for_failure_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "gf2.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="gf")
        sm.save(state)
        _record_attempt(sm, state.run_id, admitted=False, rejection_reason="r1", attempt_id="a1")
        _record_attempt(sm, state.run_id, admitted=False, rejection_reason="r2", attempt_id="a2")
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata={"rejection_reason": "r1"},
                             decision="governance_failure"),
        ])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_duplicate_failure" for i in report.errors)

    def test_rejection_reason_mismatch_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "gfm.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="gf")
        sm.save(state)
        _record_attempt(sm, state.run_id, admitted=False, rejection_reason="attempt_reason")
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata={"rejection_reason": "trace_reason"},
                             decision="governance_failure"),
        ])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_rejection_mismatch" for i in report.errors)

    def test_single_matching_non_admitted_is_clean(self, clean_env, tmp_path):
        db = str(tmp_path / "gfok.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="gf")
        sm.save(state)
        _record_attempt(sm, state.run_id, admitted=False, rejection_reason="reject_missing_rationale_high_risk")
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9,
                             metadata={"rejection_reason": "reject_missing_rationale_high_risk"},
                             decision="governance_failure"),
        ])
        report = TraceReconciler(sm).reconcile(trace)
        attempt_errors = [i for i in report.errors if "attempt" in i.check]
        assert attempt_errors == [], f"governance failure path should be clean: {attempt_errors}"


# ── Duplicate admitted attempts ──────────────────────────────────────────────


class TestDuplicateAdmitted:
    def test_equivalent_duplicates_are_warning(self, clean_env, tmp_path):
        db = str(tmp_path / "dup.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="d")
        sm.save(state)
        _record_attempt(sm, state.run_id, attempt_id="a1")
        _record_attempt(sm, state.run_id, attempt_id="a2")  # identical binding fields
        md = {"receipt_id": "r", "receipt_digest": "d", "request_id": "q", "request_digest": "d"}
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=md)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_duplicate_admitted" and i.severity == "warning"
                   for i in report.issues)

    def test_conflicting_duplicates_are_error(self, clean_env, tmp_path):
        db = str(tmp_path / "conf.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="d")
        sm.save(state)
        _record_attempt(sm, state.run_id, attempt_id="a1", outcome="approve")
        _record_attempt(sm, state.run_id, attempt_id="a2", outcome="reject")  # conflicts
        md = {"receipt_id": "r", "receipt_digest": "d", "request_id": "q", "request_digest": "d"}
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=md)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_duplicate_conflict" for i in report.errors)


# ── Receipt-triangle binding (attempt ↔ receipt) ─────────────────────────────


class TestReceiptTriangle:
    def test_outcome_mismatch_with_receipt_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "out.db")
        state, sm, completed_ev = _produce_full_run(db)
        # Tamper the persisted receipt's outcome so it disagrees with the attempt.
        state.metadata["governed_decision_receipt"]["decision"]["outcome"] = "reject"
        sm.save(state)
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=completed_ev.metadata)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_outcome_receipt_mismatch" for i in report.errors)

    def test_reviewer_identity_explicit_disagreement_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "rid.db")
        state, sm, completed_ev = _produce_full_run(db)
        # Tamper the attempt's reviewer_identity to disagree with the receipt.
        for att in sm.get_review_attempts(run_id=state.run_id):
            sm.record_review_attempt({**att, "reviewer_identity": "evil@attacker"})
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=completed_ev.metadata)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_attempt_reviewer_identity_mismatch" for i in report.errors)
