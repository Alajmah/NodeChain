"""v2.25.0 — Durable Review Decision Attempt Log.

Verifies that every ReviewVerifier.verify() attempt is persisted (admitted OR
rejected), that rejected attempts survive the fail-closed path, that HR-046
(unauthorized_attempts) derives from the log and counts ONLY
authorization/admissibility rejections, and that the dashboard now reports the
counter as available.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager, ChainState
from nodechain.runtime.review_manager import ReviewManager
from nodechain.cli.dashboard import collect_review_workbench_status, _is_authorization_rejection


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


def _make_rm(sm):
    """ReviewManager wired to persist attempts to the given StateManager."""
    return ReviewManager(
        save_snapshot=lambda s: None,
        add_trace_event=lambda e: None,
        record_attempt=sm.record_review_attempt,
    )


# ── Attempt persistence ───────────────────────────────────────────────────────


class TestAttemptPersistence:
    def test_admitted_attempt_recorded(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "adm.db"))
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm = _make_rm(sm)
        s = ChainState(chain_id="c"); s.execution_order_hash = "h"
        asyncio.run(rm.request_review(_high_risk(), s, "T", step_id=9))
        attempts = sm.get_review_attempts()
        assert len(attempts) == 1
        a = attempts[0]
        assert a["admitted"] == 1
        assert a["attempted_outcome"] == "approve"
        assert a["rejection_reason"] == ""
        assert a["retention_status"] == "active"

    def test_rejected_attempt_recorded_before_fail_closed(self, clean_env, tmp_path):
        """A rejected attempt must persist even though the chain then fails."""
        sm = StateManager(db_path=str(tmp_path / "rej.db"))
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        os.environ["NODECHAIN_REVIEW_RATIONALE_OVERRIDE"] = ""  # force high-risk reject
        rm = _make_rm(sm)
        s = ChainState(chain_id="c"); s.execution_order_hash = "h"
        asyncio.run(rm.request_review(_high_risk(), s, "T", step_id=9))
        attempts = sm.get_review_attempts()
        assert len(attempts) == 1
        assert attempts[0]["admitted"] == 0
        assert attempts[0]["rejection_reason"]  # non-empty
        # The fail-closed path still ran (chain failed), but attempt persisted first
        assert s.status == "failed"

    def test_verifier_checks_stores_warnings(self, clean_env, tmp_path):
        import json
        sm = StateManager(db_path=str(tmp_path / "vc.db"))
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        rm = _make_rm(sm)
        s = ChainState(chain_id="c"); s.execution_order_hash = "h"
        asyncio.run(rm.request_review(_high_risk(), s, "T", step_id=9))
        a = sm.get_review_attempts()[0]
        checks = json.loads(a["verifier_checks"])
        assert "warnings" in checks


# ── Authorization classification ──────────────────────────────────────────────


class TestAuthorizationClassification:
    @pytest.mark.parametrize("reason,counts", [
        ("reject_unauthorized_reviewer", True),
        ("reject_decision_type_not_valid_for_subject", True),
        ("reject_subject_type_mismatch", True),
        ("reject_no_review_request", True),
        ("reject_subject_digest_mismatch", False),
        ("reject_policy_digest_mismatch", False),
        ("reject_receipt_digest_invalid", False),
        ("reject_missing_rationale_high_risk", False),
        ("reject_stale_request", False),
    ])
    def test_classifier(self, reason, counts):
        assert _is_authorization_rejection(reason) is counts


# ── HR-046 derivation ─────────────────────────────────────────────────────────


class TestHR046Derivation:
    def _record_attempt(self, sm, *, admitted, rejection_reason, attempt_id="rda1"):
        sm.record_review_attempt({
            "review_attempt_id": attempt_id, "run_id": "r1", "chain_id": "c",
            "step_id": 9, "request_id": "req1", "request_digest": "d",
            "subject_type": "chain_review", "subject_id": "r:9",
            "attempted_decision_type": "approve_chain_review", "attempted_outcome": "approve",
            "reviewer_identity": "x", "required_reviewer_role": "operator",
            "admitted": admitted, "rejection_reason": rejection_reason,
            "verifier_checks": {"warnings": []}, "policy_digest": "p",
            "graph_digest": "", "created_at": "2026-06-20T01:00:00+00:00",
            "retention_status": "active",
        })

    def test_unauthorized_attempt_counted(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "u1.db"))
        self._record_attempt(sm, admitted=False, rejection_reason="reject_unauthorized_reviewer")
        r = collect_review_workbench_status(state_manager=sm)
        assert r["unauthorized_attempts"] == 1
        assert r["unauthorized_attempts_available"] is True

    def test_data_failure_not_counted_as_unauthorized(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "u2.db"))
        self._record_attempt(sm, admitted=False, rejection_reason="reject_receipt_digest_invalid")
        r = collect_review_workbench_status(state_manager=sm)
        assert r["unauthorized_attempts"] == 0  # integrity failure, not unauthorized

    def test_admitted_attempt_not_counted(self, clean_env, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "u3.db"))
        self._record_attempt(sm, admitted=True, rejection_reason="")
        r = collect_review_workbench_status(state_manager=sm)
        assert r["unauthorized_attempts"] == 0

    def test_hr046_fires_from_unauthorized_attempt(self, clean_env, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "hr46fire.db"))
        self._record_attempt(sm, admitted=False, rejection_reason="reject_unauthorized_reviewer")
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "hr46fire.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "HR-046" in fired


# ── Full orchestrator integration ─────────────────────────────────────────────


class TestOrchestratorIntegration:
    def test_full_run_records_attempt(self, clean_env):
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType
        from nodechain.core.envelope import EnvelopeResponse

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        class HighRiskClassifier(MockNode):
            async def execute(self, envelope):
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id,
                    run_id=envelope.run_id, chain_id=envelope.chain_id,
                    node_id="risk_classifier", step_id=envelope.step_id,
                    output={"risk_level": "HIGH", "confidence": 0.3,
                            "review_required": True, "uncertainty_disclosures": [],
                            "risk_factors": ["test"]},
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier(
            "risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT,
        )
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)
        trace = asyncio.run(orch.run("Test HIGH risk query"))
        assert trace.final_status == "completed"
        # The orchestrator's StateManager should have one admitted attempt
        # for THIS run (filter by run_id — the shared default DB may hold
        # attempts from prior runs).
        attempts = orch.state_manager.get_review_attempts(run_id=trace.run_id)
        assert len(attempts) == 1
        assert attempts[0]["admitted"] == 1
