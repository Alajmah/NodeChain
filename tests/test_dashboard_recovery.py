"""Tests for the recovery dashboard section + HR-049 rule (v2.46.0 Phase 5).

Surfaces the recovery backlog on the operator dashboard: a 'recovery' section
listing runs in non-terminal recovery states, and HR-049 firing when any exist.
This binds the recovery console into the existing dashboard discipline so an
operator scanning the dashboard sees recovery work, not just side-effect
ambiguity (SE-001..006) or review gates (HR-044..048).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.cli.dashboard_health import ALL_RULES, RULES_BY_ID, evaluate_all_rules
from nodechain.core.state import ChainState, StateManager


def _rule(rule_id: str):
    return RULES_BY_ID[rule_id]


# --- HR-049 exists and is registered -----------------------------------------

def test_hr049_is_registered() -> None:
    rule = _rule("HR-049")
    assert rule.name == "operator_recovery_backlog"


def test_hr049_does_not_fire_when_no_recovery_section() -> None:
    """No recovery section → rule does not fire (dashboard without the section
    is healthy from this rule's perspective)."""
    rule = _rule("HR-049")
    assert rule.evaluate({}) is None


def test_hr049_does_not_fire_when_backlog_zero() -> None:
    rule = _rule("HR-049")
    assert rule.evaluate({"recovery": {"actionable_run_count": 0}}) is None


def test_hr049_fires_when_actionable_runs_exist() -> None:
    """A non-zero actionable_run_count fires the rule with the count + a
    pointer to the recovery console."""
    rule = _rule("HR-049")
    result = rule.evaluate({"recovery": {"actionable_run_count": 3}})
    assert result is not None
    assert result["rule_id"] == "HR-049"
    assert "3" in result["description"]
    assert "recover" in result["recommendation"].lower()


def test_hr049_included_in_evaluate_all_rules() -> None:
    """The rule runs as part of the dashboard evaluation, so a recovery backlog
    surfaces in dashboard issues without bespoke wiring."""
    issues = evaluate_all_rules({"recovery": {"actionable_run_count": 2}})
    assert any(i["rule_id"] == "HR-049" for i in issues)


# --- recovery section collector ---------------------------------------------

@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> str:
    d = tmp_path / "traces"
    d.mkdir()
    return str(d)


def test_collect_recovery_status_counts_actionable_runs(sm, trace_dir) -> None:
    """The collector classifies each run and counts those in a non-terminal
    recovery state (anything except COMPLETED/CANCELLED)."""
    from nodechain.cli.dashboard import collect_recovery_status

    sm.save(ChainState(run_id="run-ok", chain_id="c", status="completed"))
    sm.save(ChainState(run_id="run-fail", chain_id="c", status="failed",
                       metadata={"last_failure": {"retryable": True}}))
    sm.save(ChainState(run_id="run-review", chain_id="c", status="waiting_for_review",
                       metadata={"governed_review_request": {"request_id": "r", "step_id": 1}}))

    status = collect_recovery_status(state_manager=sm, trace_dir=trace_dir)

    assert status["actionable_run_count"] == 2  # failed + review; completed excluded
    assert {r["run_id"] for r in status["runs"]} == {"run-fail", "run-review"}


def test_collect_recovery_status_empty_when_all_clean(sm, trace_dir) -> None:
    """All completed/cancelled runs → zero backlog."""
    from nodechain.cli.dashboard import collect_recovery_status

    sm.save(ChainState(run_id="r1", chain_id="c", status="completed"))
    sm.save(ChainState(run_id="r2", chain_id="c", status="cancelled"))

    status = collect_recovery_status(state_manager=sm, trace_dir=trace_dir)
    assert status["actionable_run_count"] == 0
    assert status["runs"] == []


def test_collect_recovery_status_empty_db(sm, trace_dir) -> None:
    from nodechain.cli.dashboard import collect_recovery_status
    status = collect_recovery_status(state_manager=sm, trace_dir=trace_dir)
    assert status["actionable_run_count"] == 0


# --- v2 dashboard health path (the real rule-evaluation entry) ───────────────

def test_collect_dashboard_v2_includes_recovery_section(tmp_path, monkeypatch) -> None:
    """#rework: HR-049 must fire through collect_dashboard_v2 — the versioned
    health API the rule path actually uses. Sets NODECHAIN_DB_PATH to a temp DB
    with a review-blocked run and asserts both the recovery section count > 0
    and HR-049 in the issues list."""
    import os
    from nodechain.cli.dashboard_health import collect_dashboard_v2
    from nodechain.core.state import ChainState, StateManager

    db_path = tmp_path / "state.db"
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    sm = StateManager(db_path=db_path)
    sm.save(ChainState(
        run_id="r1", chain_id="c", status="waiting_for_review",
        metadata={"governed_review_request": {"request_id": "r", "step_id": 1}},
    ))

    monkeypatch.setenv("NODECHAIN_DB_PATH", str(db_path))
    monkeypatch.setenv("NODECHAIN_TRACE_DIR", str(trace_dir))

    data = collect_dashboard_v2()

    assert data["sections"]["recovery"]["actionable_run_count"] > 0
    issue_ids = [issue["rule_id"] for issue in data["issues"]]
    assert "HR-049" in issue_ids


def test_collect_dashboard_v2_recovery_zero_when_all_clean(tmp_path, monkeypatch) -> None:
    """Mirror: a DB with only completed runs → recovery count 0, HR-049 not fired."""
    import os
    from nodechain.cli.dashboard_health import collect_dashboard_v2
    from nodechain.core.state import ChainState, StateManager

    db_path = tmp_path / "state.db"
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    sm = StateManager(db_path=db_path)
    sm.save(ChainState(run_id="r1", chain_id="c", status="completed"))

    monkeypatch.setenv("NODECHAIN_DB_PATH", str(db_path))
    monkeypatch.setenv("NODECHAIN_TRACE_DIR", str(trace_dir))

    data = collect_dashboard_v2()
    assert data["sections"]["recovery"]["actionable_run_count"] == 0
    assert "HR-049" not in [i["rule_id"] for i in data["issues"]]
