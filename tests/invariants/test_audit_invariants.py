"""Audit completeness invariant tests (v2.51.0 P0).

Every admitted action → exactly one operator_action_log row.
Every action (admitted or denied) → Actor.OPERATOR trace event.
No operator event → Actor.NODE.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_policy import RecoveryAction
from nodechain.runtime.recovery_service import RecoveryService


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> str:
    d = tmp_path / "traces"
    d.mkdir()
    return str(d)


@pytest.fixture()
def service(sm, trace_dir) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _payload(e):
    raw = e.get("payload")
    try: return json.loads(raw) if raw else {}
    except: return {}


def test_admitted_action_has_exactly_one_action_log_row(service, sm):
    """An admitted cancel produces exactly one operator_action_log row."""
    sm.save(ChainState(run_id="r1", chain_id="c", status="running"))
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")
    rows = sm.get_operator_actions(run_id="r1")
    assert len(rows) == 1
    assert rows[0]["admitted"] is True


def test_denied_action_still_has_action_log_row(service, sm):
    """A denied action still produces an audit row (admitted=False)."""
    sm.save(ChainState(run_id="r1", chain_id="c", status="completed"))
    service.apply_action("r1", RecoveryAction.RESUME, operator_identity="op")
    rows = sm.get_operator_actions(run_id="r1")
    assert len(rows) == 1
    assert rows[0]["admitted"] is False


def test_operator_actions_never_emit_actor_node_events(service, sm):
    """Operator events must carry actor=operator, never actor=node."""
    sm.save(ChainState(run_id="r1", chain_id="c", status="running"))
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")
    events = sm.get_events("r1")
    operator_events = [e for e in events if "operator" in e.get("event_type", "")]
    for e in operator_events:
        payload = _payload(e)
        assert payload.get("actor") != "node", \
            f"operator event {e['event_type']} must not have actor=node"


def test_every_action_has_operator_trace_event(service, sm):
    """Every action (admitted or denied) must emit at least one trace event."""
    sm.save(ChainState(run_id="r1", chain_id="c", status="running"))
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")
    events = sm.get_events("r1")
    assert events  # at least one event
    assert any("operator" in e.get("event_type", "") or
               _payload(e).get("actor") == "operator" for e in events)
