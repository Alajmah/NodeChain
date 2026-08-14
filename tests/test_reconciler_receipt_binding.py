"""v2.23.0 — Reconciler Receipt Binding.

Verifies that TraceReconciler binds HUMAN_REVIEW_COMPLETED trace events to the
persisted governed DecisionReceipt (digest-recomputed, tamper-detecting) and,
when available, to the original governed ReviewRequest digest.

Mirrors patterns from tests/test_trace_reconciler.py and
tests/test_review_receipt_runtime.py.
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


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _high_risk():
    return {
        "risk_level": "HIGH", "confidence": 0.3, "review_required": True,
        "risk_factors": ["insufficient_evidence"], "uncertainty_disclosures": [],
    }


def _make_trace(run_id, events=None):
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


def _completed_event(run_id, step_id, metadata=None, decision="approve"):
    """A HUMAN_REVIEW_COMPLETED trace event with receipt metadata."""
    return TraceEvent(
        run_id=run_id, chain_id="test-chain", node_id="risk_classifier",
        step_id=step_id, event_type=EventType.HUMAN_REVIEW_COMPLETED,
        actor=Actor.HUMAN, decision=decision, metadata=metadata or {},
    )


def _produce_real_receipt(db_path, mode="auto-approve", rationale_override=None):
    """Run a real ReviewManager.request_review to produce an authentic receipt
    persisted in state, and return (state, receipt_dict, governed_request_dict)."""
    from nodechain.runtime.review_manager import ReviewManager
    os.environ["NODECHAIN_REVIEW_MODE"] = mode
    if rationale_override is not None:
        os.environ["NODECHAIN_REVIEW_RATIONALE_OVERRIDE"] = rationale_override
    events = []
    sm = StateManager(db_path=db_path)
    # v2.26.0: wire record_attempt so the attempt log is populated alongside
    # the receipt (the real orchestrator does this).
    rm = ReviewManager(
        commit_review_transition=(
            lambda s, e, *, status, paused_at=None, metadata=None: (
                setattr(s, "status", status),
                setattr(s, "paused_at", paused_at),
                s.metadata.update(metadata or {}),
                events.append(e),
            )
        ),
        add_trace_event=lambda e: None,
        record_attempt=sm.record_review_attempt,
    )
    state = ChainState(chain_id="bind-test")
    state.execution_order_hash = "exec_hash"
    asyncio.run(rm.request_review(_high_risk(), state, "Test", step_id=9))
    sm.save(state)
    receipt = state.metadata.get("governed_decision_receipt", {})
    gov_req = state.metadata.get("governed_review_request", {})
    completed = [e for e in events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
    return state, receipt, gov_req, (completed[0] if completed else None)


@pytest.fixture
def clean_env():
    keys = ["NODECHAIN_REVIEW_MODE", "NODECHAIN_REVIEW_RATIONALE_OVERRIDE",
            "NODECHAIN_REVIEWER_IDENTITY", "NODECHAIN_MOCK_RISK_LEVEL"]
    saved = {k: os.environ.pop(k, None) for k in keys}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


# ── Clean binding ─────────────────────────────────────────────────────────────


class TestCleanReceiptBinding:
    def test_completed_event_with_matching_receipt_reconciles_clean(self, clean_env, tmp_path):
        db = str(tmp_path / "clean.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        assert receipt, "setup: no receipt produced"
        # Reconcile a trace carrying the SAME metadata as the real completed event.
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata=completed_ev.metadata, decision="approve"),
        ])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        binding_errors = [i for i in report.errors if i.check.startswith("review_") or i.check.startswith("governance_")]
        assert binding_errors == [], f"unexpected binding errors: {binding_errors}"
        assert report.checks_passed > 0


# ── Mismatch / tamper detection ───────────────────────────────────────────────


class TestMismatchDetection:
    def test_tampered_receipt_digest_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "tamper.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        # Tamper the trace metadata's receipt_digest.
        bad_md = dict(completed_ev.metadata)
        bad_md["receipt_digest"] = "0" * 64
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=bad_md)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_receipt_digest_mismatch" and i.severity == "error" for i in report.issues)

    def test_mismatched_receipt_id_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "rid.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        bad_md = dict(completed_ev.metadata)
        bad_md["receipt_id"] = "receipt_wrong"
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=bad_md)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_receipt_id_mismatch" for i in report.errors)

    def test_mismatched_request_id_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "rqid.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        bad_md = dict(completed_ev.metadata)
        bad_md["request_id"] = "wrong_req"
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=bad_md)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_request_id_mismatch" for i in report.errors)

    def test_mismatched_request_digest_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "rqd.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        bad_md = dict(completed_ev.metadata)
        bad_md["request_digest"] = "x" * 64
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=bad_md)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_request_digest_mismatch" for i in report.errors)

    def test_persisted_receipt_tamper_detected(self, clean_env, tmp_path):
        """If the persisted receipt's stored digest no longer matches a recompute
        (fields mutated after commit), the reconciler flags tamper."""
        db = str(tmp_path / "ptamper.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        # Mutate the persisted receipt in state to corrupt its stored receipt_digest
        # so it disagrees with a fresh recompute.
        state.metadata["governed_decision_receipt"]["receipt_digest"] = "corrupted_digest"
        StateManager(db_path=db).save(state)
        trace = _make_trace(state.run_id, [
            # trace carries the (now-stale) corrupted digest so trace==persisted,
            # but recomputed != persisted → tamper.
            _completed_event(state.run_id, 9, metadata={
                **completed_ev.metadata, "receipt_digest": "corrupted_digest",
            }),
        ])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_receipt_digest_tamper" for i in report.errors)


# ── Missing metadata / state ──────────────────────────────────────────────────


class TestMissingArtifacts:
    def test_missing_receipt_metadata_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "miss.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="m")
        sm.save(state)
        # Completed event with empty metadata.
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata={})])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_receipt_metadata_missing" and i.severity == "error" for i in report.issues)

    def test_completed_event_without_persisted_receipt_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "nop.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="m")
        sm.save(state)
        md = {"receipt_id": "r1", "receipt_digest": "d", "request_id": "q1", "request_digest": "qd"}
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=md)])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "review_receipt_state_missing" for i in report.errors)


# ── Governance failure path ───────────────────────────────────────────────────


class TestGovernanceFailurePath:
    def test_governance_failure_without_receipt_is_clean(self, clean_env, tmp_path):
        db = str(tmp_path / "gf.db")
        sm = StateManager(db_path=db)
        state = ChainState(chain_id="gf")
        state.status = "failed"
        state.metadata["governed_review_failure"] = {"reason_code": "review_receipt_verification_failed"}
        sm.save(state)
        # v2.26.0: a governance failure must have exactly 1 non-admitted attempt
        # in the durable log (the real runtime records this before fail-closed).
        sm.record_review_attempt({
            "review_attempt_id": "rda_gf", "run_id": state.run_id, "chain_id": "gf",
            "step_id": 9, "request_id": "req_gf", "request_digest": "d_gf",
            "subject_type": "chain_review", "subject_id": f"{state.run_id}:9",
            "attempted_decision_type": "approve_chain_review", "attempted_outcome": "approve",
            "reviewer_identity": "runtime:auto", "required_reviewer_role": "operator",
            "admitted": False, "rejection_reason": "reject_missing_rationale_high_risk",
            "verifier_checks": {"warnings": []}, "policy_digest": "p",
            "graph_digest": "", "created_at": "2026-06-20T01:00:00+00:00",
            "retention_status": "active",
        })
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata={
                "reason": "fail", "rejection_reason": "reject_missing_rationale_high_risk",
            }, decision="governance_failure"),
        ])
        report = TraceReconciler(sm).reconcile(trace)
        gf_errors = [i for i in report.errors if i.check.startswith("governance_") or i.check.startswith("review_")]
        assert gf_errors == [], f"failure-path should be valid: {gf_errors}"

    def test_governance_failure_with_receipt_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "gfr.db")
        state, receipt, _, _ = _produce_real_receipt(db)
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata={"reason": "fail"}, decision="governance_failure"),
        ])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "governance_failure_with_receipt" for i in report.errors)


# ── Valid reject + subject_type ───────────────────────────────────────────────


class TestValidRejectAndSubjectType:
    def test_valid_reject_with_committed_receipt_reconciles_clean(self, clean_env, tmp_path):
        db = str(tmp_path / "rej.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db, mode="auto-reject")
        assert receipt.get("decision", {}).get("outcome") == "reject"
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata=completed_ev.metadata, decision="reject"),
        ])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        binding_errors = [i for i in report.errors if i.check.startswith("review_") or i.check.startswith("governance_")]
        assert binding_errors == [], f"valid reject should reconcile clean: {binding_errors}"

    def test_uncommitted_receipt_is_error(self, clean_env, tmp_path):
        db = str(tmp_path / "unc.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        # Force is_committed False in persisted state.
        state.metadata["governed_decision_receipt"]["is_committed"] = False
        StateManager(db_path=db).save(state)
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=completed_ev.metadata)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_receipt_not_committed" for i in report.errors)

    def test_subject_type_drift_is_warning(self, clean_env, tmp_path):
        db = str(tmp_path / "subj.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        bad_md = dict(completed_ev.metadata)
        bad_md["subject_type"] = "deployment"  # differs from persisted chain_review
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=bad_md)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        subj = [i for i in report.issues if i.check == "review_subject_type_mismatch"]
        assert len(subj) == 1 and subj[0].severity == "warning"


# ── Cross-bind against governed_review_request ────────────────────────────────


class TestRequestCrossBind:
    def test_receipt_request_digest_matches_governed_request(self, clean_env, tmp_path):
        """The receipt's request_digest must equal the recomputed governed
        ReviewRequest digest (created_at preserved)."""
        db = str(tmp_path / "xb.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        assert gov_req, "setup: no governed request persisted"
        trace = _make_trace(state.run_id, [
            _completed_event(state.run_id, 9, metadata=completed_ev.metadata),
        ])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        xbind_errors = [i for i in report.errors if i.check == "review_request_digest_request_mismatch"]
        assert xbind_errors == [], f"cross-bind should pass for authentic receipt: {xbind_errors}"

    def test_tampered_governed_request_detected(self, clean_env, tmp_path):
        """If governed_review_request is mutated after persist (digest breaks),
        the cross-bind flags it."""
        db = str(tmp_path / "xbind.db")
        state, receipt, gov_req, completed_ev = _produce_real_receipt(db)
        # Mutate the persisted request's reason → its stored digest no longer
        # matches a recompute, and no longer matches the receipt's request_digest.
        state.metadata["governed_review_request"]["reason_for_review"] = "tampered reason"
        StateManager(db_path=db).save(state)
        trace = _make_trace(state.run_id, [_completed_event(state.run_id, 9, metadata=completed_ev.metadata)])
        report = TraceReconciler(StateManager(db_path=db)).reconcile(trace)
        assert any(i.check == "review_request_digest_request_mismatch" for i in report.errors)
