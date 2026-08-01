"""v2.98: Side-Effect Journal Controller — extracted from Orchestrator.

Internal implementation detail. Orchestrator remains the public facade; this
controller coordinates pre-invocation side-effect journaling through the
existing SideEffectJournalMixin.

The SideEffectJournalMixin (extracted in v2.75) holds the journaling logic
(key derivation, ledger writes, trace emission). This controller provides a
named entry point that the orchestrator delegates to, consistent with the
ContractPreflightController / NodeOutputValidationController /
PolicyGateController pattern from v2.92–v2.96.

What this controller owns:
  - Pre-invocation journaling coordination (journal_planned_side_effects)
  - Post-call observed-completion coordination (complete_reported_side_effects, v3.0)
  - Delegation to SideEffectJournalMixin for key/type/ledger/trace logic

What this controller does NOT own (stays on Orchestrator / mixin):
  - Resume reconciliation (_reconcile_side_effects_on_resume stays on mixin)
  - Policy blocking semantics (stays on PolicyGateController)
  - Node invocation, execution loop, failure management

Behavior is identical to the pre-extraction code — this is a pure delegation
refactor. v2.97 characterization tests must pass unchanged.
"""
from __future__ import annotations

from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.trace import EventType, Actor
from nodechain.runtime.side_effect_journal import SideEffectJournalMixin


class SideEffectJournalController:
    """Coordinates pre-invocation side-effect journaling.

    Wraps the SideEffectJournalMixin (which holds the actual journaling logic)
    to provide a named controller entry point consistent with the other
    orchestrator controllers.

    Extracted from Orchestrator in v2.98. The mixin's methods are accessed
    through this controller's reference to the mixin instance (which is the
    orchestrator itself, since Orchestrator IS-A SideEffectJournalMixin).
    """

    def __init__(self, mixin: SideEffectJournalMixin) -> None:
        """Initialize with the SideEffectJournalMixin instance.

        Args:
            mixin: The SideEffectJournalMixin instance (typically the
                   Orchestrator itself, since Orchestrator inherits from it).
        """
        self._mixin = mixin

    def journal_planned_side_effects(
        self, node_id: str, envelope: InvocationEnvelope,
    ) -> bool:
        """Pre-call journaling: record side-effect intent before execution.

        Delegates to SideEffectJournalMixin._journal_planned_side_effects.
        Returns True if journaling succeeded, False on CONTRACT_VIOLATION.

        Args:
            node_id: The node about to be invoked.
            envelope: The invocation envelope for this node.

        Returns:
            True if journaling succeeded (or no side effects to journal).
            False if a CONTRACT_VIOLATION was emitted (caller must abort).
        """
        return self._mixin._journal_planned_side_effects(node_id, envelope)

    def complete_reported_side_effects(
        self, node_id: str, envelope: InvocationEnvelope, output: dict,
    ) -> bool:
        """Post-call: validate and apply node-reported side-effect completion records.

        v3.0.0 Model C path. Reads ``output["side_effect_records"]`` (if present)
        and validates each record against the started/planned ledger via the
        mixin's ``_complete_reported_side_effect``. Marks the matching ledger
        entry ``completed`` (persisting response_hash) and emits
        SIDE_EFFECT_COMPLETED only for validated observed reports.

        Absence of ``side_effect_records`` is legacy behavior and returns True
        (no-op — the effect stays ``started``). An invalid/unmatched record
        emits CONTRACT_VIOLATION and returns False; the caller must
        ``_fail_chain``.

        Args:
            node_id: The node that just executed.
            envelope: The invocation envelope for this node.
            output: The node's output dict (may contain ``side_effect_records``).

        Returns:
            True if no completion records were present or all were valid.
            False if any record failed validation (caller must _fail_chain).
        """
        records = output.get("side_effect_records") if isinstance(output, dict) else None
        if not records or not isinstance(records, list):
            return True  # legacy path: no report ⇒ no completion
        for record in records:
            # Fail closed: a present-but-malformed record is a contract
            # violation, not silently skipped. The completion path must not
            # tolerate garbage in side_effect_records.
            if not isinstance(record, dict):
                self._mixin._emit(
                    EventType.CONTRACT_VIOLATION,
                    node_id=node_id,
                    actor=Actor.RUNTIME,
                    decision="invalid_completion_report",
                    metadata={
                        "reason": "malformed_completion_record_not_dict",
                        "record_repr": repr(record)[:200],
                    },
                )
                return False
            if not self._mixin._complete_reported_side_effect(node_id, record):
                return False
        return True
