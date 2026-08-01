"""Surface verification — resolved unknown side effects are clean across
dashboard / inspect / reconciler surfaces (v3.4.0 Task 5).

Acceptance criteria (from the v3.4.0 design doc):

  19. Resolved effects no longer appear as unresolved unknowns in
      dashboard/inspect/reconciler surfaces.
  20. Existing SE-R3/R4/R5 reconciler checks remain green for resolved
      effects.

The reconciler proper takes a ``ChainTrace`` (heavier than this task needs),
so rather than invoking it end-to-end we verify the THREE durable facts its
SE-R3/R4/R5 checks read from the side-effect ledger + recovery-decision log:

  * SE-R3 (illegal transition): the resolved ledger status is a legal value
    (``completed``/``failed`` are legal terminals).
  * SE-R4 (recovery decision references a missing ledger row): every
    recovery decision's ``(run_id, idempotency_key)`` matches an existing
    ledger row.
  * SE-R5 (recovery decision conflicts with terminal ledger state): the
    decision/ledger pair is consistent (``verified_completed`` ↔
    ``completed``, ``verified_failed`` ↔ ``failed``).

Plus the surface query the dashboard/inspect path uses:

  * ``get_side_effects_by_status(run_id, "unknown")`` excludes the resolved
    key.

And the recovery classifier (used by dashboard/recovery-console to decide
operator intervention posture):

  * a run that classified ``CRASH_NEEDS_OPERATOR`` while the side effect was
    unknown must classify differently once the effect is resolved (no more
    ``unknown`` rows → the unknown-SE branch is skipped).
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_classifier import (
    RecoveryState,
    classify,
)
from nodechain.runtime.recovery_policy import RecoveryAction
from nodechain.runtime.recovery_service import RecoveryService


# --- fixtures -------------------------------------------------------------

@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> str:
    d = tmp_path / "traces"
    d.mkdir(parents=True)
    return str(d)


@pytest.fixture()
def service(sm: StateManager, trace_dir: str) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


# --- helpers --------------------------------------------------------------

def _seed_run(sm: StateManager, run_id: str = "r1", *, status: str = "running") -> ChainState:
    """Seed a non-terminal run. RESOLVE_SIDE_EFFECT is admitted for any
    non-terminal recovery state."""
    state = ChainState(run_id=run_id, chain_id="c", status=status, step=1,
                       current_node="search_tool")
    sm.save(state)
    return state


def _seed_unknown_side_effect(sm: StateManager, *, run_id: str, key: str,
                              node_id: str = "search_tool") -> None:
    """Seed an unknown side-effect ledger row (the resolution precondition).

    Mirrors the helper in test_recovery_side_effect_resolution.py: record
    started, then transition to unknown."""
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id=node_id,
        side_effect_type="external_call",
        idempotency_key=key,
        status="started",
    )
    sm.update_side_effect_status(run_id, key, status="unknown")


def _resolve(service, sm, *, run_id: str, key: str, decision: str,
             **kwargs) -> None:
    """Resolve an unknown side effect through the governed boundary and assert
    it was admitted."""
    result = service.apply_action(
        run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
        operator_identity="op@x",
        side_effect_key=key,
        side_effect_decision=decision,
        **kwargs,
    )
    assert result.admitted is True, (
        f"resolution not admitted: {result.rejection_reason}"
    )


# --- the surface checks ---------------------------------------------------

class TestResolvedSurfacesClean:
    """v3.4.0 Task 5: after an operator resolves an unknown side effect, the
    dashboard / inspect / reconciler surfaces no longer flag it as
    unresolved, and the reconciler's SE-R3/R4/R5 invariants hold."""

    def test_resolved_effect_not_in_unknown_query(self, service, sm):
        """Surface: ``get_side_effects_by_status(run_id, 'unknown')`` excludes
        the resolved key. This is the query the dashboard/inspect surfaces use
        to flag unresolved unknowns."""
        run_id, key = "r1", "se:surface-1"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        # Precondition: the unknown surface DOES include it before resolution.
        pre = sm.get_side_effects_by_status(run_id, "unknown")
        assert any(se["idempotency_key"] == key for se in pre)

        _resolve(service, sm, run_id=run_id, key=key,
                 decision="verified_completed",
                 external_reference="ref-1")

        # Post-resolution: the unknown surface is clean for this key.
        post = sm.get_side_effects_by_status(run_id, "unknown")
        assert all(se["idempotency_key"] != key for se in post), (
            f"resolved key {key!r} still flagged as unknown: {post}"
        )
        # And the resolved row now reports a terminal status.
        row = sm.get_side_effect_by_key(run_id, key)
        assert row is not None
        assert row["status"] == "completed"

    def test_se_r3_ledger_status_is_legal_after_resolution(self, service, sm):
        """SE-R3 (illegal transition): the reconciler flags any ledger status
        outside ``{planned, started, completed, failed, unknown,
        retry_authorized}``. After resolution the status is ``completed``
        (a legal terminal) — so SE-R3 cannot fire for this row."""
        run_id, key = "r1", "se:surface-2"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        _resolve(service, sm, run_id=run_id, key=key,
                 decision="verified_completed",
                 external_reference="ref-2")

        row = sm.get_side_effect_by_key(run_id, key)
        LEGAL_STATES = {"planned", "started", "completed", "failed",
                        "unknown", "retry_authorized"}
        assert row["status"] in LEGAL_STATES, (
            f"resolved status {row['status']!r} outside legal set — SE-R3 "
            f"would fire"
        )

    def test_recovery_decision_references_existing_ledger_row(self, service, sm):
        """SE-R4 (recovery decision references a missing ledger row): every
        recovery decision's ``idempotency_key`` must match an existing ledger
        row. After resolution the decision + ledger row are written together,
        so each decision resolves to a real row."""
        run_id, key = "r1", "se:surface-3"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        _resolve(service, sm, run_id=run_id, key=key,
                 decision="verified_completed",
                 external_reference="ref-3")

        decisions = sm.get_recovery_decisions(run_id=run_id)
        assert decisions, "expected at least one recovery decision"

        for rd in decisions:
            rd_key = rd.get("idempotency_key", "")
            assert rd_key, (
                f"recovery decision {rd.get('decision_id')} has no "
                f"idempotency_key — SE-R4 would fire"
            )
            # SE-R4 invariant: the ledger row referenced by the decision exists.
            # ``get_side_effect_by_key`` is scoped by run_id, so a non-None row
            # proves the decision's (run_id, idempotency_key) resolves to a
            # real ledger entry — exactly what SE-R4 checks against
            # ``ledger_status_by_key``.
            row = sm.get_side_effect_by_key(run_id, rd_key)
            assert row is not None, (
                f"recovery decision references missing ledger row {rd_key!r} "
                f"— SE-R4 would fire"
            )
            # The resolved ledger row is terminal (the decision advanced it).
            assert row["status"] in ("completed", "failed", "retry_authorized")

    def test_recovery_decision_matches_terminal_state(self, service, sm):
        """SE-R5 (recovery decision conflicts with terminal ledger state):
        a ``verified_completed`` decision requires the ledger to be
        ``completed``; ``verified_failed`` requires ``failed``. After
        resolution the pair is consistent — so SE-R5 cannot fire."""
        run_id, key = "r1", "se:surface-4"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        # Resolve to completed via verified_completed.
        _resolve(service, sm, run_id=run_id, key=key,
                 decision="verified_completed",
                 external_reference="ref-4")

        row = sm.get_side_effect_by_key(run_id, key)
        decisions = sm.get_recovery_decisions(run_id=run_id, idempotency_key=key)
        assert decisions, "expected the recovery decision for this key"
        rd = decisions[0]

        # SE-R5 consistent pair for verified_completed.
        assert rd["decision"] == "verified_completed"
        assert row["status"] == "completed", (
            f"verified_completed decision but ledger status "
            f"{row['status']!r} — SE-R5 would fire"
        )

    def test_recovery_decision_matches_terminal_state_failed(self, service, sm):
        """SE-R5 counterpart: a ``verified_failed`` decision must pair with a
        ``failed`` ledger status."""
        run_id, key = "r1", "se:surface-5"
        _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        _resolve(service, sm, run_id=run_id, key=key,
                 decision="verified_failed",
                 reason="confirmed dead via provider console")

        row = sm.get_side_effect_by_key(run_id, key)
        decisions = sm.get_recovery_decisions(run_id=run_id, idempotency_key=key)
        assert decisions, "expected the recovery decision for this key"
        rd = decisions[0]

        assert rd["decision"] == "verified_failed"
        assert row["status"] == "failed", (
            f"verified_failed decision but ledger status "
            f"{row['status']!r} — SE-R5 would fire"
        )

    def test_classifier_no_longer_needs_operator_after_resolution(
        self, service, sm,
    ):
        """Recovery classifier: while the side effect is ``unknown`` the run
        classifies ``CRASH_NEEDS_OPERATOR`` (unknown exists, no recovery
        decision). After resolution there are no ``unknown`` rows for this
        effect, so the classifier must NOT return
        ``CRASH_NEEDS_OPERATOR`` for it.

        We feed the classifier the same durable rows the dashboard /
        recovery-console loads (``get_side_effects`` +
        ``get_recovery_decisions``)."""
        run_id, key = "r1", "se:surface-6"
        state = _seed_run(sm, run_id)
        _seed_unknown_side_effect(sm, run_id=run_id, key=key)

        # Re-load the latest state (seeding may have bumped metadata).
        state = sm.load(run_id)
        assert state is not None

        # Pre-resolution: unknown exists, no recovery decision → needs operator.
        # The classifier's blocking_reason is a count message (e.g. "1 unknown
        # side effect(s) require an operator recovery decision"), so we assert
        # on the state + that an unknown-side-effect reason is present.
        pre = classify(
            state,
            side_effects=sm.get_side_effects(run_id),
            report=None,
            review_attempts=[],
            recovery_decisions=sm.get_recovery_decisions(run_id=run_id),
        )
        assert pre.state is RecoveryState.CRASH_NEEDS_OPERATOR, (
            f"pre-resolution expected CRASH_NEEDS_OPERATOR, got {pre.state}"
        )
        assert pre.blocking_reason and "unknown" in pre.blocking_reason

        # Resolve the unknown side effect.
        _resolve(service, sm, run_id=run_id, key=key,
                 decision="verified_completed",
                 external_reference="ref-6")

        # Re-load state + durable rows after resolution.
        state = sm.load(run_id)
        assert state is not None

        post = classify(
            state,
            side_effects=sm.get_side_effects(run_id),
            report=None,
            review_attempts=[],
            recovery_decisions=sm.get_recovery_decisions(run_id=run_id),
        )

        # The classifier must no longer flag this run as needing an operator
        # decision for the resolved effect. With no unknown side effects, no
        # review pause, no reconciler report, and a non-terminal status, the
        # run falls through to the CRASH_RECOVERABLE fallback (or any other
        # non-intervention state) — the contract is just "not
        # CRASH_NEEDS_OPERATOR driven by this effect".
        assert post.state is not RecoveryState.CRASH_NEEDS_OPERATOR, (
            f"post-resolution still CRASH_NEEDS_OPERATOR: {post}"
        )
        # And specifically: the resolved key is not referenced as an
        # unresolved unknown in the blocking reason (if any).
        assert key not in (post.blocking_reason or ""), (
            f"resolved key {key!r} still referenced in blocking reason: "
            f"{post.blocking_reason!r}"
        )
        # Sanity: no unknown side effects remain for this run.
        assert not sm.get_side_effects_by_status(run_id, "unknown")
