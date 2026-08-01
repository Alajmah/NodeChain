"""v2.75: Side-Effect Journaling — extracted from orchestrator.py.

Contains the side-effect declaration, journaling, and resume reconciliation
helpers that govern how observed effects are declared, recorded, and reconciled
after a crash window:
- Pre-call journaling of side-effect intent (_journal_planned_side_effects)
- Per-adapter search operation journaling (_journal_search_operations)
- Declared-vs-observed enforcement (_assert_declared_side_effect)
- Single-entry journal write (_journal_one)
- Canonical declared-type lookup (_get_declared_se_types)
- Resume reconciliation for started-but-not-completed effects
  (_reconcile_side_effects_on_resume)

This mixin assumes the host class provides trace emission (self._emit,
self.emitter), state access (self.state, self._nodes), and side-effect ledger
persistence (self.persistence). It performs no independent orchestration and
intentionally preserves existing behavior — zero semantic change.
"""
from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.trace import EventType, Actor


class SideEffectJournalMixin:
    """v2.75: Extracted side-effect journaling methods from Orchestrator.

    These methods were physically in orchestrator.py. Moved here to reduce
    orchestrator size without behavioral change. The Orchestrator class
    inherits this mixin; all self. references work as before because the
    mixin is mixed into Orchestrator.
    """

    def _journal_planned_side_effects(
        self, node_id: str, envelope: InvocationEnvelope,
    ) -> bool:
        """Pre-call journaling: record side-effect intent before execution.

        Derives operation-level keys when possible (search per-adapter),
        or node-level reservation keys when the operation plan isn't known
        until execution (memory write candidates).

        Key formats:
          Search:  ``search:<adapter_name>:<request_hash>``  (per adapter)
          Memory:  ``memory_write_decision:memory_write:<step_id>``  (reservation)
          Other:   ``<node_id>:<effect_type>:<step_id>``  (fallback)

        Post-call MUST update these same keys via update_side_effect_status(),
        never create new rows with different keys.
        """
        node = self._nodes.get(node_id)
        if node is None:
            return True  # nothing to journal

        contract = node.manifest.contract
        if not contract.side_effects:
            return True

        for se in contract.side_effects:
            # Search: derive per-adapter operation keys from payload
            if se.effect_type in ("external_api_read", "external_call") and node_id in (
                "search_tool", "branch_search",
            ):
                if not self._journal_search_operations(node_id, envelope, se.effect_type):
                    return False
                continue

            # Memory: journal reservation (actual writes aren't known yet)
            if se.effect_type == "memory_write":
                ikey = f"{node_id}:memory_write:{envelope.step_id}"
                if not self._journal_one(ikey, node_id, se.effect_type, envelope):
                    return False
                continue

            # Fallback: node-level key
            ikey = f"{node_id}:{se.effect_type}:{envelope.step_id}"
            if not self._journal_one(ikey, node_id, se.effect_type, envelope):
                return False

        return True

    def _journal_search_operations(
        self, node_id: str, envelope: InvocationEnvelope, effect_type: str,
    ) -> bool:
        """Journal per-adapter search operations from the envelope payload.

        Derives canonical operation keys from search_queries in the payload.
        Each adapter gets its own row: ``search:<adapter>:<request_hash>``.
        Returns False on CONTRACT_VIOLATION.
        """
        import hashlib as _hl
        import json as _json

        search_queries = (envelope.payload or {}).get("search_queries", [])
        if not search_queries:
            # No queries planned — journal a single reservation
            ikey = f"{node_id}:{effect_type}:{envelope.step_id}"
            return self._journal_one(ikey, node_id, effect_type, envelope)

        for sq in search_queries:
            terms = sq.get("terms", [])
            if isinstance(terms, str):
                terms = [terms]
            adapters = sq.get("target_adapters", [])
            if not adapters:
                adapters = ["unknown"]

            # v2.38.0: canonical request hash from the operation dict.
            # Same function used for the idempotency_key suffix AND the
            # ledger row's request_hash (via _journal_one's operation param).
            from nodechain.core.side_effect_utils import compute_side_effect_request_hash
            operation = {
                "terms": sorted(terms),
                "max": sq.get("max_results", 10),
                "filters": sq.get("filters", {}),
            }
            req_hash = compute_side_effect_request_hash(
                effect_type, node_id, "", operation=operation,
            )

            for adapter_name in adapters:
                ikey = f"search:{adapter_name}:{req_hash}"
                if not self._journal_one(
                    ikey, node_id, effect_type, envelope,
                    operation=operation, adapter_name=adapter_name,
                ):
                    return False

        return True

    def _assert_declared_side_effect(
        self,
        node_id: str,
        observed_type: str,
        *,
        idempotency_key: str | None = None,
    ) -> str | None:
        """v2.35.0: normalize observed type and verify it's declared by the node.

        Returns the canonical type string if the observed type is declared.
        Returns None (and emits CONTRACT_VIOLATION + fails the chain) if the
        observed type is undeclared or unrecognized. The caller must check the
        return value and abort on None.
        """
        from nodechain.core.contract import normalize_side_effect_type

        canonical = normalize_side_effect_type(observed_type)
        if canonical is None:
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="undeclared_side_effect",
                metadata={
                    "observed_side_effect_type": observed_type,
                    "canonical_side_effect_type": None,
                    "declared_side_effect_types": self._get_declared_se_types(node_id),
                    "idempotency_key": idempotency_key or "",
                    "reason": "unrecognized_side_effect_type",
                },
            )
            return None

        declared = self._get_declared_se_types(node_id)
        # v2.35.1: a node that declares side effects must declare the observed
        # type. A node that declares NOTHING but produces a side effect is also
        # a contract violation — backward compat is NOT an escape hatch for
        # runtime-observed effects. (Manifest-level unknowns remain warning-only.)
        node_known = self._node_has_contract(node_id)
        if node_known and canonical not in declared:
            reason = (
                "node_declares_no_side_effects"
                if not declared
                else "side_effect_not_declared_by_node"
            )
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="undeclared_side_effect",
                metadata={
                    "observed_side_effect_type": observed_type,
                    "canonical_side_effect_type": canonical,
                    "declared_side_effect_types": declared,
                    "idempotency_key": idempotency_key or "",
                    "reason": reason,
                },
            )
            return None
        return canonical

    def _get_declared_se_types(self, node_id: str) -> list[str]:
        """Return canonical declared side-effect types for a node."""
        from nodechain.core.contract import normalize_side_effect_type
        node = self._nodes.get(node_id)
        if not node or not hasattr(node, "manifest"):
            return []
        declared = []
        for se in node.manifest.contract.side_effects:
            canon = normalize_side_effect_type(se.effect_type)
            if canon and canon not in declared:
                declared.append(canon)
        return declared

    def _journal_one(
        self, ikey: str, node_id: str, effect_type: str, envelope: InvocationEnvelope,
        operation: dict[str, Any] | None = None,
        *,
        adapter_name: str = "",
    ) -> bool:
        """Journal a single side-effect entry (idempotent).

        v2.33.1: emits SIDE_EFFECT_STARTED when a row transitions to 'started'.
        v2.35.0: normalizes effect_type to canonical form before recording.
        v2.35.1: enforces declared-vs-observed via _assert_declared_side_effect.
        v2.35.3: returns bool — False on CONTRACT_VIOLATION so callers can abort.
        v2.38.0: accepts optional operation dict for canonical request_hash.
        v3.5.0: routes through start_side_effect_with_capsule for proactive
            replay capsule persistence.
        v3.5.0 (ChatGPT T6 re-review fix 1): threads adapter_name and derives
            complete source binding fields from the node manifest and contract,
            so production capsules have non-empty binding values.

        Returns True if the journaling succeeded (or was already done), False
        if a CONTRACT_VIOLATION was emitted and the write was aborted.
        """
        # v2.35.1: enforce declared-vs-observed before any ledger/trace write
        canonical = self._assert_declared_side_effect(
            node_id, effect_type, idempotency_key=ikey,
        )
        if canonical is None:
            return False  # CONTRACT_VIOLATION already emitted; abort the write

        existing = self.persistence.get_side_effect_by_key(
            self.state.run_id, ikey,
        )
        # v3.5.0: build capsule operation from the operation dict (preferred)
        # or full payload fallback. Used for proactive capsule persistence.
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        req_hash = compute_side_effect_request_hash(
            canonical, node_id, ikey,
            payload=envelope.payload if operation is None else None,
            operation=operation,
        )
        capsule_operation = operation if operation is not None else dict(envelope.payload)

        # v3.5.0 (ChatGPT T6 re-review fix 1): derive complete source binding
        # from the node manifest and contract, not from the operation dict.
        # The operation dict has no "adapter" key — adapter_name is threaded
        # separately from _journal_search_operations.
        node = self._nodes.get(node_id)
        node_version = ""
        contract_id = ""
        contract_version = ""
        if node and hasattr(node, "manifest"):
            manifest = node.manifest
            node_version = getattr(manifest, "version", "") or ""
            contract = getattr(manifest, "contract", None)
            if contract:
                contract_id = getattr(contract, "contract_id", "") or ""
                contract_version = getattr(contract, "version", "") or ""
        # adapter_version: look up from the adapter registry if available
        adapter_version = "1.0.0"  # default; adapters declare their own
        if adapter_name:
            try:
                from nodechain.nodes.search_tool import _get_adapter
                ad = _get_adapter(adapter_name)
                if ad is not None:
                    adapter_version = getattr(ad, "adapter_version", "1.0.0")
            except Exception:
                pass

        if existing is not None:
            # Already journalled — ensure started (with capsule)
            if existing["status"] == "planned":
                # v3.5.0: route through start_side_effect_with_capsule so
                # the capsule is persisted atomically with planned→started.
                self.persistence.start_side_effect_with_capsule(
                    self.state.run_id,
                    step_id=envelope.step_id,
                    node_id=node_id,
                    side_effect_type=canonical,
                    idempotency_key=ikey,
                    request_hash=req_hash,
                    capsule_operation=capsule_operation,
                    operation_name="search",
                    adapter_id=adapter_name,
                    adapter_version=adapter_version,
                    node_version=node_version,
                    contract_id=contract_id,
                    contract_version=contract_version,
                )
                self.emitter.side_effect_started(
                    node_id=node_id, effect_type=canonical, key=ikey,
                )
            return True

        # v3.5.0: new row — route through start_side_effect_with_capsule
        # so the capsule is persisted atomically with the started insert.
        self.persistence.start_side_effect_with_capsule(
            self.state.run_id,
            step_id=envelope.step_id,
            node_id=node_id,
            side_effect_type=canonical,
            idempotency_key=ikey,
            request_hash=req_hash,
            capsule_operation=capsule_operation,
            operation_name="search",
            adapter_id=adapter_name,
            adapter_version=adapter_version,
            node_version=node_version,
            contract_id=contract_id,
            contract_version=contract_version,
        )
        self.emitter.side_effect_started(
            node_id=node_id, effect_type=canonical, key=ikey,
            request_hash=req_hash,
        )
        return True

    def _reconcile_side_effects_on_resume(self, run_id: str) -> None:
        """On resume, mark any started-but-not-completed side effects as 'unknown'.

        This detects the crash window: a side effect was started before the
        process died, but never completed. These cannot be blindly retried
        because the external action may have succeeded.
        """
        started_effects = self.persistence.get_side_effects_by_status(run_id, "started")
        planned_effects = self.persistence.get_side_effects_by_status(run_id, "planned")

        for effect in started_effects:
            self.persistence.update_side_effect_status(
                run_id, effect["idempotency_key"], "unknown",
            )
            # v2.33.0: emit NO side-effect trace event for the unknown
            # transition. Unknown is not failed and not completed — it means
            # the runtime lost certainty after a crash window. The ledger
            # `unknown` status is the source of truth; the reconciler's
            # Check 4d (side_effect_recovery_required) warns from the ledger,
            # not from trace. Emitting a trace event here would be another
            # semantic lie (the previous code emitted a fake
            # SIDE_EFFECT_COMPLETED with decision="side_effect_marked_unknown").

        # Planned effects that never started are safe to re-execute
        for effect in planned_effects:
            self.persistence.update_side_effect_status(
                run_id, effect["idempotency_key"], "planned",  # Keep as planned
            )

    # v3.0.0: accepted completion authorities. Model C (node-output-reported)
    # is the only authority wired in v3.0. Model B (adapter/executor) will add
    # "adapter" / "executor" in v3.1.
    _ACCEPTED_COMPLETION_AUTHORITIES = frozenset({"node"})

    def _complete_reported_side_effect(
        self, node_id: str, record: dict[str, Any],
    ) -> bool:
        """v3.0.0: validate and apply ONE node-reported side-effect completion record.

        Model C path: the node emits ``output["side_effect_records"]``; the
        orchestrator calls this per record via the SideEffectJournalController.

        A record is valid only if ALL hold:
          1. side_effect_key exactly matches a started ledger row for
             the current run.
          2. side_effect_type matches the ledger row's canonical type.
          3. status == "completed".
          4. observed_by is an accepted authority (node, in v3.0).
          5. response_hash is non-empty.
          6. observed_at is non-empty.
        On an invalid record, emit CONTRACT_VIOLATION and return False (the
        caller must _fail_chain). On a valid record, transition the ledger row
        to "completed" (persisting response_hash), emit SIDE_EFFECT_COMPLETED,
        and return True.

        Idempotency (duplicate records): if the ledger row is already
        ``completed``:
          - same response_hash  ⇒ safe replay, return True (no re-emission).
          - different response_hash ⇒ CONTRACT_VIOLATION, return False
            (also enforced at the store layer via SideEffectIntegrityError,
            but validated here first to emit a precise trace event and keep
            the failure on the soft-fail path).
        Records whose key matches a planned-but-not-started row are rejected —
        completion requires the effect to have been started first.
        """
        from nodechain.core.contract import normalize_side_effect_type

        se_key = record.get("side_effect_key", "")
        se_type = record.get("side_effect_type", "")
        status = record.get("status", "")
        observed_by = record.get("observed_by", "")
        response_hash = record.get("response_hash", "")
        observed_at = record.get("observed_at", "")

        # Validation gate — fail closed on every field.
        existing = self.persistence.get_side_effect_by_key(self.state.run_id, se_key)
        if existing is None:
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "reason": "no_matching_started_side_effect",
                },
            )
            return False

        # Idempotency: already-completed row.
        if existing.get("status") == "completed":
            existing_resp = existing.get("response_hash", "") or ""
            if response_hash and existing_resp == response_hash:
                return True  # safe replay — same evidence
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "existing_response_hash": existing_resp,
                    "reported_response_hash": response_hash,
                    "reason": "completion_response_hash_conflict",
                },
            )
            return False

        if existing.get("status") != "started":
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "ledger_status": existing.get("status"),
                    "reason": "completion_requires_started_status",
                },
            )
            return False

        canonical = normalize_side_effect_type(se_type)
        # v3.0.0: the reported type must already BE canonical (se_type ==
        # canonical) — non-canonical aliases (e.g. "external_read") are
        # rejected even though they normalize to the ledger's type. This
        # forces callers to emit the normalized type and closes drift where
        # an alias silently completes a canonical ledger row. The ledger's
        # stored type is itself canonical, so canonical must also equal it.
        if (
            canonical is None
            or se_type != canonical
            or canonical != existing.get("side_effect_type")
        ):
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "reported_type": se_type,
                    "canonical_type": canonical,
                    "ledger_type": existing.get("side_effect_type"),
                    "reason": "type_mismatch",
                },
            )
            return False

        if status != "completed":
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "reported_status": status,
                    "reason": "status_not_completed",
                },
            )
            return False

        if observed_by not in self._ACCEPTED_COMPLETION_AUTHORITIES:
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "observed_by": observed_by,
                    "accepted": sorted(self._ACCEPTED_COMPLETION_AUTHORITIES),
                    "reason": "unaccepted_authority",
                },
            )
            return False

        if not response_hash:
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "reason": "empty_response_hash",
                },
            )
            return False

        if not observed_at:
            self._emit(
                EventType.CONTRACT_VIOLATION,
                node_id=node_id,
                actor=Actor.RUNTIME,
                decision="invalid_completion_report",
                metadata={
                    "side_effect_key": se_key,
                    "reason": "empty_observed_at",
                },
            )
            return False

        # Valid — transition ledger and emit completion.
        self.persistence.update_side_effect_status(
            self.state.run_id, se_key, "completed", response_hash=response_hash,
        )
        self.emitter.side_effect_completed(
            node_id=node_id,
            effect_type=canonical,
            key=se_key,
            request_hash=existing.get("request_hash", ""),
            response_hash=response_hash,
        )
        return True
