"""SE-003/005/006 Live Trigger Tests (v2.37.1 + v2.40.3).

Proves that SE rules actually fire from real collector-provided signals,
not just stub zeros. v2.40.3 adds tests proving collect_workflow_recovery_status
returns real counts from state_manager data.
"""

from __future__ import annotations

from nodechain.cli.dashboard import collect_workflow_recovery_status
from nodechain.cli.dashboard_health import (
    SE003UndeclaredSideEffects,
    SE005SideEffectLedgerUnavailable,
    SE006CompletedWithoutLedger,
)


class TestSE003LiveTrigger:
    """SE-003 fires when undeclared_side_effect_count > 0."""

    def test_triggers_with_nonzero(self):
        section = collect_workflow_recovery_status(
            state_manager=None,
            contract_violation_count=3,
        )
        assert section["undeclared_side_effect_count"] == 3

        rule = SE003UndeclaredSideEffects()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is not None
        assert result["rule_id"] == "SE-003"
        assert "3" in result["description"]

    def test_does_not_trigger_with_zero(self):
        section = collect_workflow_recovery_status(
            state_manager=None,
            contract_violation_count=0,
        )
        rule = SE003UndeclaredSideEffects()
        result = rule.evaluate({"workflow_recovery": section})
        # enabled=False when no state_manager, so returns None
        assert result is None


class TestSE005LiveTrigger:
    """SE-005 fires when ledger_lookup_failed is True."""

    def test_triggers_on_lookup_failure(self):
        # Simulate a section with ledger_lookup_failed=True
        section = {
            "enabled": True,
            "ledger_lookup_failed": True,
        }
        rule = SE005SideEffectLedgerUnavailable()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is not None
        assert result["rule_id"] == "SE-005"

    def test_does_not_trigger_when_clean(self):
        section = {
            "enabled": True,
            "ledger_lookup_failed": False,
        }
        rule = SE005SideEffectLedgerUnavailable()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is None


class TestSE006LiveTrigger:
    """SE-006 fires when unreconciled_completed_count > 0."""

    def test_triggers_with_nonzero(self):
        section = collect_workflow_recovery_status(
            state_manager=None,
            unreconciled_completed_count=2,
        )
        assert section["unreconciled_completed_count"] == 2

        rule = SE006CompletedWithoutLedger()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is not None
        assert result["rule_id"] == "SE-006"
        assert "2" in result["description"]

    def test_does_not_trigger_with_zero(self):
        section = collect_workflow_recovery_status(
            state_manager=None,
            unreconciled_completed_count=0,
        )
        rule = SE006CompletedWithoutLedger()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is None


class TestRealStateManagerCounts:
    """v2.40.3: collect_workflow_recovery_status returns real counts from
    state_manager data, not just injected parameters."""

    def test_contract_violation_count_from_events(self, tmp_path):
        from nodechain.core.state import StateManager, ChainState

        sm = StateManager(db_path=str(tmp_path / "real.db"))
        state = ChainState(chain_id="t")
        sm.save(state)

        # Insert a CONTRACT_VIOLATION event into the events table
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="contract_violation",
            node_id="n", step_id=1,
        )

        section = collect_workflow_recovery_status(state_manager=sm)
        assert section["undeclared_side_effect_count"] == 1

        # SE-003 should trigger
        rule = SE003UndeclaredSideEffects()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is not None
        assert "1" in result["description"]

    def test_unreconciled_completed_from_event_ledger_mismatch(self, tmp_path):
        from nodechain.core.state import StateManager, ChainState

        sm = StateManager(db_path=str(tmp_path / "real2.db"))
        state = ChainState(chain_id="t")
        sm.save(state)

        # Insert SIDE_EFFECT_COMPLETED events WITHOUT matching ledger rows
        for i in range(3):
            sm.append_event(
                run_id=state.run_id, revision=i + 1,
                event_type="side_effect_completed",
                node_id="n", step_id=1,
                payload={"idempotency_key": f"orphan-{i}"},
            )

        section = collect_workflow_recovery_status(state_manager=sm)
        # 3 trace completed events with keys, 0 ledger completed → 3 unreconciled
        assert section["unreconciled_completed_count"] == 3

        # SE-006 should trigger
        rule = SE006CompletedWithoutLedger()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is not None
        assert "3" in result["description"]

    def test_se006_false_negative_regression(self, tmp_path):
        """v2.40.4: one unmatched trace + one unrelated ledger row = still detected.
        Aggregate subtraction would show 1-1=0 (miss). Key-level matching shows 1."""
        from nodechain.core.state import StateManager, ChainState

        sm = StateManager(db_path=str(tmp_path / "fn.db"))
        state = ChainState(chain_id="t")
        sm.save(state)

        # Trace has completed key A
        sm.append_event(
            run_id=state.run_id, revision=1,
            event_type="side_effect_completed",
            node_id="n", step_id=1,
            payload={"idempotency_key": "key_A"},
        )
        # Ledger has completed key B (different key)
        sm.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="key_B", status="completed",
        )

        section = collect_workflow_recovery_status(state_manager=sm)
        # key_A is in trace but not in ledger → 1 unreconciled
        assert section["unreconciled_completed_count"] == 1

    def test_se005_fires_on_real_ledger_failure(self, tmp_path):
        """v2.40.4: _count_side_effects_by_status failure → collector emits
        ledger_lookup_failed=True from a real failing state_manager."""
        # Simulate a state_manager whose db_path points to a non-existent file
        # (corrupt/unreadable DB)
        class BrokenStateManager:
            db_path = "/nonexistent/path/no.db"

        section = collect_workflow_recovery_status(
            state_manager=BrokenStateManager(),
        )
        assert section["ledger_lookup_failed"] is True
        assert section["enabled"] is False

        rule = SE005SideEffectLedgerUnavailable()
        result = rule.evaluate({"workflow_recovery": section})
        assert result is not None
        assert result["rule_id"] == "SE-005"
