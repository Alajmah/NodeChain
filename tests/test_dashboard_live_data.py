"""v2.24.0 — Dashboard Live Data.

Verifies that collect_review_workbench_status derives its counters from durable
chain state (not hardcoded zeros), that HR-045/047/048 fire from real derived
data, that HR-046 (unauthorized_attempts) correctly reports unavailable, and
that StateManager.list_all_review_states is scoped to review-governance runs.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager, ChainState
from nodechain.cli.dashboard import collect_review_workbench_status


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _high_risk():
    return {"risk_level": "HIGH", "confidence": 0.3, "review_required": True,
            "risk_factors": ["x"], "uncertainty_disclosures": []}


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


def _rm_transition(state, event, *, status, paused_at=None, metadata=None):
    """In-memory stand-in for the H0.5 review-transition seam."""
    state.status = status
    state.paused_at = paused_at
    if metadata:
        state.metadata = {**(state.metadata or {}), **metadata}


def _make_paused_run(sm, *, stale=False):
    """Create a run paused waiting for review (governed_review_request present)."""
    from nodechain.runtime.review_manager import ReviewManager, ReviewPausedException
    os.environ["NODECHAIN_REVIEW_MODE"] = "pause"
    rm = ReviewManager(commit_review_transition=_rm_transition, add_trace_event=lambda e: None)
    s = ChainState(chain_id="paused")
    s.execution_order_hash = "h"
    s.outputs = {"run_id": s.run_id, "step_id": 9}
    try:
        asyncio.run(rm.request_review(_high_risk(), s, "T", step_id=9))
    except ReviewPausedException:
        pass
    if stale:
        old = (datetime.now(timezone.utc) - timedelta(hours=80)).isoformat()
        s.metadata["governed_review_request"]["created_at"] = old
    sm.save(s)
    return s


def _make_rejected_run(sm):
    """Create a run with a committed reject receipt, terminal failed status."""
    from nodechain.runtime.review_manager import ReviewManager
    os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
    rm = ReviewManager(commit_review_transition=_rm_transition, add_trace_event=lambda e: None)
    s = ChainState(chain_id="rej")
    s.execution_order_hash = "h"
    asyncio.run(rm.request_review(_high_risk(), s, "T", step_id=9))
    s.status = "failed"
    sm.save(s)
    return s


def _make_approved_run(sm):
    """Create a run with a committed approve receipt (not blocking)."""
    from nodechain.runtime.review_manager import ReviewManager
    os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
    rm = ReviewManager(commit_review_transition=_rm_transition, add_trace_event=lambda e: None)
    s = ChainState(chain_id="appr")
    s.execution_order_hash = "h"
    asyncio.run(rm.request_review(_high_risk(), s, "T", step_id=9))
    sm.save(s)
    return s


# ── StateManager.list_all_review_states ───────────────────────────────────────


class TestListAllReviewStates:
    def test_scoped_to_review_metadata(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "scoped.db"))
        # A run WITHOUT review metadata — should be excluded.
        plain = ChainState(chain_id="plain")
        sm.save(plain)
        # A run WITH review metadata — included.
        _make_approved_run(sm)
        review_states = sm.list_all_review_states()
        run_ids = {s.run_id for s in review_states}
        assert plain.run_id not in run_ids
        assert len(review_states) == 1

    def test_includes_governed_review_failure(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fail.db"))
        s = ChainState(chain_id="gf")
        s.metadata["governed_review_failure"] = {"reason_code": "review_receipt_verification_failed"}
        sm.save(s)
        assert any(st.run_id == s.run_id for st in sm.list_all_review_states())


# ── Counter derivation ────────────────────────────────────────────────────────


class TestCounterDerivation:
    def test_stale_pending_review_counted(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "stale.db"))
        _make_paused_run(sm, stale=True)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["stale_count"] == 1
        assert r["pending_count"] == 1

    def test_fresh_pending_review_not_stale(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        _make_paused_run(sm, stale=False)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["stale_count"] == 0
        assert r["pending_count"] == 1

    def test_rejected_blocking_counted(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "rej.db"))
        _make_rejected_run(sm)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["rejected_blocking_count"] == 1

    def test_approved_not_counted_as_blocking(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "appr.db"))
        _make_approved_run(sm)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["rejected_blocking_count"] == 0

    def test_unauthorized_attempts_available_but_zero_for_admitted(self, clean_env, tmp_path):
        """v2.25.0: an approved run records an admitted attempt, so
        unauthorized_attempts is 0 but the counter IS now available."""
        sm = StateManager(db_path=str(tmp_path / "unauth.db"))
        _make_approved_run(sm)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["unauthorized_attempts"] == 0
        assert r["unauthorized_attempts_available"] is True
        assert r["unauthorized_attempts_source"] == "review_decision_attempts_log"

    def test_empty_db_returns_zeros(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "empty.db"))
        r = collect_review_workbench_status(state_manager=sm)
        assert r["stale_count"] == 0
        assert r["rejected_blocking_count"] == 0
        assert r["stale_decision_count"] == 0


# ── stale_decision_count (conservative, decision-timestamp based) ─────────────


class TestStaleDecisionCount:
    def test_decision_on_stale_request_counted(self, clean_env, tmp_path):
        """A receipt whose request was >72h old at decision time is counted."""
        sm = StateManager(db_path=str(tmp_path / "sd.db"))
        s = _make_approved_run(sm)
        # Backdate the governed request to 80h ago; receipt.created_at is ~now,
        # so request was stale at decision time.
        old = (datetime.now(timezone.utc) - timedelta(hours=80)).isoformat()
        s.metadata["governed_review_request"]["created_at"] = old
        sm.save(s)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["stale_decision_count"] == 1

    def test_fresh_request_decision_not_counted(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "sdf.db"))
        _make_approved_run(sm)
        r = collect_review_workbench_status(state_manager=sm)
        assert r["stale_decision_count"] == 0


# ── HR rule firing end-to-end ─────────────────────────────────────────────────


class TestHealthRuleFiring:
    def test_hr045_fires_from_stale_review(self, clean_env, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "hr45.db"))
        _make_paused_run(sm, stale=True)
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "hr45.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "HR-045" in fired

    def test_hr048_fires_from_rejected_blocking(self, clean_env, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "hr48.db"))
        _make_rejected_run(sm)
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "hr48.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "HR-048" in fired

    def test_hr046_does_not_fire_when_no_unauthorized_attempts(self, clean_env, tmp_path, monkeypatch):
        """HR-046 does not fire when only admitted attempts exist (no unauthorized)."""
        sm = StateManager(db_path=str(tmp_path / "hr46.db"))
        _make_approved_run(sm)
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "hr46.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "HR-046" not in fired
        # v2.25.0: available is now True (attempt log exists), but count is 0.
        assert data["sections"]["review_workbench"]["unauthorized_attempts_available"] is True
        assert data["sections"]["review_workbench"]["unauthorized_attempts"] == 0


# ── Back-compat: review_queue path still works ───────────────────────────────


class TestLegacyReviewQueue:
    def test_review_queue_still_honored(self, clean_env, tmp_path):
        from nodechain.sdk.review_workbench import ReviewQueue, ReviewRequest, ReviewSubject
        sm = StateManager(db_path=str(tmp_path / "legacy.db"))
        # Pass a review_queue with a pending stale request.
        q = ReviewQueue()
        from datetime import datetime as _dt
        old = (_dt.now(timezone.utc) - timedelta(hours=80)).isoformat()
        req = ReviewRequest(
            request_id="rq1",
            subject=ReviewSubject("chain_review", "x", "a" * 64),
            reason_for_review="t", required_reviewer_role="operator",
            risk_level="high", created_at=old,
        )
        q.submit(req)
        r = collect_review_workbench_status(review_queue=q, state_manager=sm)
        # Both sources honored; stale_count takes the max.
        assert r["stale_count"] >= 1
