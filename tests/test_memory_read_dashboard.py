"""Memory Read Dashboard + Exposure Audit Tests (v2.41.0).

Proves:
  - collect_memory_read_status returns live counts from memory_read_decisions + state_events
  - MR-001..005 fire from real data
  - MEMORY_READ_EXPOSED events distinguish exposure from authorization
  - Clean environment stays healthy (no false MR-005)
  - Decision counts come from durable table
  - nodes_with_memory_exposure derived from exposure events
"""

from __future__ import annotations

import pytest

from nodechain.cli.dashboard import collect_memory_read_status
from nodechain.cli.dashboard_health import (
    MR001MemoryReadDenied,
    MR002MemoryReadWithoutDecision,
    MR003MemoryReadPolicyMismatch,
    MR004MemoryReadExposureDetected,
    MR005MemoryReadDecisionLogUnavailable,
)


@pytest.fixture
def sm(tmp_path):
    from nodechain.core.state import StateManager
    return StateManager(db_path=str(tmp_path / "mrd.db"))


class TestLiveDecisionCounts:
    """Decision counts come from memory_read_decisions table."""

    def test_allowed_and_denied_from_durable(self, sm):
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "mr-1", "run_id": state.run_id,
            "node_id": "reader", "decision": "allow",
            "exposed_to_node": True,
        })
        sm.record_memory_read_decision({
            "decision_id": "mr-2", "run_id": state.run_id,
            "node_id": "reader2", "decision": "deny",
            "exposed_to_node": False,
        })

        status = collect_memory_read_status(state_manager=sm)
        assert status["enabled"] is True
        assert status["memory_read_allowed_count"] == 1
        assert status["memory_read_denied_count"] == 1
        assert status["memory_read_requested_count"] == 2
        assert status["memory_read_decision_count"] == 2


class TestExposureFromEvents:
    """Exposure counts come from MEMORY_READ_EXPOSED events, not authorization."""

    def test_exposure_from_real_event(self, sm):
        """v2.41.1: uses _emit-shaped payload (metadata nested)."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "mr-1", "run_id": state.run_id,
            "node_id": "reader", "decision": "allow",
            "exposed_to_node": True,
        })

        # v2.41.1: _emit-shaped payload — metadata is nested
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "mr-1", "node_id": "reader", "step_id": 1,
                                   "exposed_session_memory_count": 3}},
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_exposed_node_count"] == 1
        assert "reader" in status["nodes_with_memory_exposure"]
        assert status["memory_read_without_decision_count"] == 0

    def test_allowed_without_exposure_not_counted_as_exposed(self, sm):
        """Allowed but no MEMORY_READ_EXPOSED event → not in exposure list."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "mr-1", "run_id": state.run_id,
            "node_id": "reader", "decision": "allow",
            "exposed_to_node": True,
        })
        # No exposure event — memory was empty

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_exposed_node_count"] == 0
        assert status["nodes_with_memory_exposure"] == []


class TestWithoutDecisionDetection:
    """Exposure without matching durable allow = without_decision."""

    def test_exposed_without_durable_allow(self, sm):
        """v2.41.1: _emit-shaped payload with nonexistent decision_id."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "nonexistent", "node_id": "reader"}},
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_without_decision_count"] == 1

    def test_exposed_without_any_decision_id(self, sm):
        """v2.41.1 blocker 4: exposure event with NO decision_id → without_decision."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"node_id": "reader"}},  # no decision_id
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_without_decision_count"] == 1


class TestPolicyMismatch:
    """v2.41.1: deny decision. v2.41.2: node_id/step_id identity binding."""

    def test_exposed_with_deny_decision_is_mismatch(self, sm):
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "mr-deny", "run_id": state.run_id,
            "node_id": "reader", "decision": "deny",
            "exposed_to_node": False,
        })

        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "mr-deny", "node_id": "reader"}},
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_policy_mismatch_count"] == 1

    def test_allow_for_node_a_but_exposed_by_node_b(self, sm):
        """v2.41.2: decision_id is a valid allow for node_A, but exposure
        event is for node_B → identity mismatch."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "d1", "run_id": state.run_id,
            "node_id": "node_A", "step_id": 1,
            "decision": "allow",
        })
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="node_B", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "d1", "node_id": "node_B", "step_id": 1}},
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_policy_mismatch_count"] == 1

    def test_allow_for_step_1_but_exposed_at_step_2(self, sm):
        """v2.41.2: decision_id is a valid allow at step 1, but exposure
        event is at step 2 → identity mismatch."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "d2", "run_id": state.run_id,
            "node_id": "reader", "step_id": 1,
            "decision": "allow",
        })
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=2,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "d2", "node_id": "reader", "step_id": 2}},
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_policy_mismatch_count"] == 1

    def test_allow_in_run_a_but_exposed_in_run_b(self, sm):
        """v2.41.3: valid allow for run_A, but exposure in run_B → mismatch."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        sm.record_memory_read_decision({
            "decision_id": "d3", "run_id": "run_A",
            "node_id": "reader", "step_id": 1,
            "decision": "allow",
        })
        sm.append_event(
            run_id="run_B", revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "d3", "node_id": "reader", "step_id": 1}},
        )

        status = collect_memory_read_status(state_manager=sm)
        assert status["memory_read_policy_mismatch_count"] == 1


class TestHealthRules:
    """MR-001..005 fire from real collector data."""

    def test_mr001_denied_triggers(self, sm):
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)
        sm.record_memory_read_decision({
            "decision_id": "d1", "run_id": state.run_id,
            "node_id": "n", "decision": "deny",
        })
        status = collect_memory_read_status(state_manager=sm)
        result = MR001MemoryReadDenied().evaluate({"memory_read": status})
        assert result is not None
        assert result["rule_id"] == "MR-001"

    def test_mr002_without_decision_triggers(self, sm):
        """v2.41.1: _emit-shaped payload."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="n", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "missing", "node_id": "n"}},
        )
        status = collect_memory_read_status(state_manager=sm)
        result = MR002MemoryReadWithoutDecision().evaluate({"memory_read": status})
        assert result is not None
        assert result["rule_id"] == "MR-002"

    def test_mr003_mismatch_triggers(self, sm):
        """v2.41.1 blocker 3: exposure with deny decision → mismatch."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)
        sm.record_memory_read_decision({
            "decision_id": "d-deny", "run_id": state.run_id,
            "node_id": "n", "decision": "deny",
        })
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="n", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "d-deny", "node_id": "n"}},
        )
        status = collect_memory_read_status(state_manager=sm)
        result = MR003MemoryReadPolicyMismatch().evaluate({"memory_read": status})
        assert result is not None
        assert result["rule_id"] == "MR-003"

    def test_mr004_exposure_triggers(self, sm):
        """v2.41.1: _emit-shaped payload."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)
        sm.record_memory_read_decision({
            "decision_id": "d1", "run_id": state.run_id,
            "node_id": "reader", "decision": "allow",
        })
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision": "memory_exposed", "reason_codes": [],
                      "metadata": {"decision_id": "d1", "node_id": "reader"}},
        )
        status = collect_memory_read_status(state_manager=sm)
        result = MR004MemoryReadExposureDetected().evaluate({"memory_read": status})
        assert result is not None
        assert result["rule_id"] == "MR-004"

    def test_clean_environment_healthy(self):
        """No state_manager → section absent → no MR rules fire."""
        rule = MR005MemoryReadDecisionLogUnavailable()
        result = rule.evaluate({})  # no memory_read section at all
        assert result is None

    def test_mr005_fires_on_real_collector_failure(self):
        """v2.41.1: broken state_manager → collector emits lookup_failed → MR-005."""
        class BrokenStateManager:
            db_path = "/nonexistent/path/no.db"

        status = collect_memory_read_status(state_manager=BrokenStateManager())
        assert status["lookup_failed"] is True
        assert status["enabled"] is False

        result = MR005MemoryReadDecisionLogUnavailable().evaluate(
            {"memory_read": status},
        )
        assert result is not None
        assert result["rule_id"] == "MR-005"

    def test_mr004_exposure_triggers(self, sm):
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)
        sm.record_memory_read_decision({
            "decision_id": "d1", "run_id": state.run_id,
            "node_id": "reader", "decision": "allow",
        })
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="memory_read_exposed",
            node_id="reader", step_id=1,
            payload={"decision_id": "d1", "node_id": "reader"},
        )
        status = collect_memory_read_status(state_manager=sm)
        result = MR004MemoryReadExposureDetected().evaluate({"memory_read": status})
        assert result is not None
        assert result["rule_id"] == "MR-004"

    def test_clean_environment_healthy(self):
        """No state_manager → section absent → no MR rules fire."""
        rule = MR005MemoryReadDecisionLogUnavailable()
        result = rule.evaluate({})  # no memory_read section at all
        assert result is None

    def test_mr005_fires_on_explicit_failure(self):
        """lookup_failed=True → MR-005 triggers."""
        section = {"memory_read": {"lookup_failed": True}}
        result = MR005MemoryReadDecisionLogUnavailable().evaluate(section)
        assert result is not None
        assert result["rule_id"] == "MR-005"


class TestZeroDataHealthy:
    """Zero-data dashboard with real state_manager stays healthy."""

    def test_empty_state_manager_healthy(self, sm):
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="t")
        sm.save(state)

        status = collect_memory_read_status(state_manager=sm)
        assert status["enabled"] is True
        assert status["health"] == "healthy"
        assert status["memory_read_allowed_count"] == 0
        assert status["memory_read_denied_count"] == 0
