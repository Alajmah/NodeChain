"""Extracted persistence stores for StateManager.

Internal implementation detail. StateManager remains the public facade; these
classes hold the persistence logic that was previously inline in StateManager.
Each store takes a db_path and opens a fresh sqlite3 connection per call
(same pattern as StateManager — required because StateManager doesn't hold a
persistent connection).

Extraction scope:
  - EventLogStore (v2.82): append_event, get_events (state_events table)
  - InvocationLedgerStore (v2.82): record_invocation, is_step_completed,
    is_node_completed, get_completed_steps, get_invocation_cost
    (invocation_ledger table)
  - SideEffectLedgerStore (v2.83): record_side_effect,
    update_side_effect_status, get_side_effects, get_side_effect_by_key,
    is_side_effect_completed, get_side_effects_by_status,
    validate_side_effect_transition (side_effect_ledger table)
  - DecisionLogStore (v2.83): operator/review/memory/side-effect-block/
    recovery/memory-read/tool-access/adapter-access/package-trust/
    registry-admission decision logs (their respective tables)

NOT extracted (stays on StateManager):
  - save_with_invocation / save_with_event: atomic multi-table transactions
    (chain_states + invocation_ledger + state_events). These are the core
    write boundary and must not be split across stores.
  - save / load / delete: chain_states materialized snapshot
  - replay_state / list_all_runs / list_all_review_states /
    get_run_updated_at: cross-table/multi-step reconstruction
  - _init_db: schema creation stays centralized on StateManager

Behavior is identical to the pre-extraction code — this is a pure move
refactor. Characterization tests must pass unchanged.
"""
from __future__ import annotations

import json as _json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.core.state import (
    SideEffectCollisionError,
    SideEffectIntegrityError,
    SideEffectRecoveryError,
    SideEffectTransitionError,
)


class EventLogStore:
    """Persistence for the append-only state event log (state_events table).

    Extracted from StateManager in v2.82. StateManager delegates append_event
    and get_events here. The atomic write methods (save_with_invocation,
    save_with_event) stay on StateManager because they write to multiple tables
    in a single transaction.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def append_event(
        self,
        run_id: str,
        revision: int,
        event_type: str,
        node_id: str | None = None,
        step_id: int | None = None,
        payload: dict | None = None,
    ) -> None:
        """Append a state event to the append-only log."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO state_events (run_id, revision, event_type, node_id, step_id, payload, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, revision, event_type, node_id, step_id,
                 _json.dumps(payload) if payload else None, now),
            )

    def get_events(self, run_id: str) -> list[dict]:
        """Get all events for a run (for replay)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT seq, revision, event_type, node_id, step_id, payload, timestamp
                FROM state_events WHERE run_id = ? ORDER BY seq
                """,
                (run_id,),
            )
            return [
                {"seq": r[0], "revision": r[1], "event_type": r[2],
                 "node_id": r[3], "step_id": r[4], "payload": r[5], "timestamp": r[6]}
                for r in cursor.fetchall()
            ]


class InvocationLedgerStore:
    """Persistence for the invocation ledger (invocation_ledger table).

    Extracted from StateManager in v2.82. StateManager delegates the standalone
    invocation queries here. The atomic save_with_invocation method stays on
    StateManager because it writes to chain_states + invocation_ledger +
    state_events in a single transaction.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def record_invocation(
        self,
        run_id: str,
        step_id: int,
        node_id: str,
        branch_name: str | None = None,
        status: str = "completed",
        output_hash: str | None = None,
        cost_usd: float = 0.0,
    ) -> None:
        """Record a completed node invocation in the ledger.

        v3.5.1 (#13) B2: detect incompatible duplicates rather than silently
        discarding via INSERT OR IGNORE. A duplicate (run_id, step_id) is
        acceptable only as an identical idempotency replay (same node, branch,
        status, output_hash, cost_usd); otherwise raise. Uses the shared
        _insert_invocation_checked helper so both write paths enforce the same
        invariant.
        """
        from nodechain.core.state import SideEffectIntegrityError
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            self._insert_invocation_checked(
                conn,
                run_id=run_id, step_id=step_id, node_id=node_id,
                branch_name=branch_name, status=status,
                output_hash=output_hash, cost_usd=cost_usd, now=now,
            )
            conn.commit()

    @staticmethod
    def _insert_invocation_checked(
        conn,
        *,
        run_id: str,
        step_id: int,
        node_id: str,
        branch_name: str | None,
        status: str,
        output_hash: str | None,
        cost_usd: float,
        now: str,
    ) -> None:
        """Shared invocation-insert helper with conflict detection.

        v3.5.1 (#13) B2: on a duplicate (run_id, step_id), reload the existing
        row and compare the full idempotency identity (node_id, branch_name,
        status, output_hash, cost_usd). Accept only an identical replay;
        otherwise raise SideEffectIntegrityError.

        Race safety: a plain INSERT (not INSERT OR IGNORE) lets the PK
        constraint atomically reject a concurrent conflicting insert that the
        preceding SELECT could not see (uncommitted row). On IntegrityError,
        reload and compare the full identity — accept identical replay,
        raise on conflict.
        """
        from nodechain.core.state import SideEffectIntegrityError

        def _identity_match(row) -> bool:
            ex_node, ex_branch, ex_status, ex_hash, ex_cost = row
            return (ex_node, ex_branch, ex_status, ex_hash, ex_cost) == (
                node_id, branch_name, status, output_hash, cost_usd,
            )

        def _conflict_error(existing_row) -> SideEffectIntegrityError:
            ex_node, ex_branch, ex_status, _ex_hash, _ex_cost = existing_row
            return SideEffectIntegrityError(
                f"invocation conflict at (run={run_id}, step={step_id}): "
                f"existing (node={ex_node}, branch={ex_branch}, "
                f"status={ex_status}) vs new (node={node_id}, "
                f"branch={branch_name}, status={status})"
            )

        # Fast path: check for an existing committed row.
        existing = conn.execute(
            "SELECT node_id, branch_name, status, output_hash, cost_usd "
            "FROM invocation_ledger WHERE run_id = ? AND step_id = ?",
            (run_id, step_id),
        ).fetchone()
        if existing is not None:
            if _identity_match(existing):
                return  # identical replay — idempotent no-op
            raise _conflict_error(existing)

        # Attempt the insert. A plain INSERT lets the PK constraint catch a
        # concurrent writer whose row the SELECT above could not see.
        try:
            conn.execute(
                """
                INSERT INTO invocation_ledger
                (run_id, step_id, node_id, branch_name, status, output_hash,
                 cost_usd, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, step_id, node_id, branch_name, status, output_hash,
                 cost_usd, now),
            )
        except sqlite3.IntegrityError:
            # PK conflict — a concurrent writer won. Reload and compare.
            existing = conn.execute(
                "SELECT node_id, branch_name, status, output_hash, cost_usd "
                "FROM invocation_ledger WHERE run_id = ? AND step_id = ?",
                (run_id, step_id),
            ).fetchone()
            if existing is not None and _identity_match(existing):
                return  # identical concurrent replay — idempotent
            raise _conflict_error(existing) if existing else SideEffectIntegrityError(
                f"invocation conflict at (run={run_id}, step={step_id}): "
                f"PK violation but row vanished on reload"
            )

    def is_step_completed(self, run_id: str, step_id: int) -> bool:
        """Check if a step has already been completed (for idempotency).

        v3.5.1 (#13): filter status='completed' so a failed/pending/running/
        unknown row does NOT suppress resume/retry. Mirrors is_node_completed.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM invocation_ledger "
                "WHERE run_id = ? AND step_id = ? AND status = 'completed'",
                (run_id, step_id),
            )
            return cursor.fetchone() is not None

    def is_node_completed(self, run_id: str, node_id: str) -> bool:
        """Check if a node has already completed in this run."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM invocation_ledger WHERE run_id = ? AND node_id = ? AND status = 'completed'",
                (run_id, node_id),
            )
            return cursor.fetchone() is not None

    def get_completed_steps(self, run_id: str) -> dict[int, str]:
        """Get all completed step_id → node_id mappings for a run.

        v3.5.1 (#13): filter status='completed' so non-completed rows are not
        reported as completed.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT step_id, node_id FROM invocation_ledger "
                "WHERE run_id = ? AND status = 'completed' ORDER BY step_id",
                (run_id,),
            )
            return {row[0]: row[1] for row in cursor.fetchall()}

    def get_invocation_cost(
        self, run_id: str, node_ids: list[str] | None = None,
    ) -> float:
        """Get cumulative cost from invocation ledger.

        Args:
            run_id: Run to query.
            node_ids: If provided, only sum costs for these nodes.
                      If None, sum all invocations for the run.

        Returns:
            Cumulative cost_usd from invocation ledger.
        """
        with sqlite3.connect(self.db_path) as conn:
            if node_ids:
                placeholders = ",".join("?" for _ in node_ids)
                cursor = conn.execute(
                    f"SELECT COALESCE(SUM(cost_usd), 0.0) FROM invocation_ledger "
                    f"WHERE run_id = ? AND node_id IN ({placeholders})",
                    [run_id] + list(node_ids),
                )
            else:
                cursor = conn.execute(
                    "SELECT COALESCE(SUM(cost_usd), 0.0) FROM invocation_ledger "
                    "WHERE run_id = ?",
                    (run_id,),
                )
            return cursor.fetchone()[0]


class SideEffectLedgerStore:
    """Persistence for the side-effect ledger (side_effect_ledger table).

    Extracted from StateManager in v2.83. StateManager delegates all
    side-effect ledger operations here. ``update_side_effect_status`` performs
    a cross-table read of ``side_effect_recovery_decisions`` when validating
    unknown→terminal transitions; that read stays inline here (single
    connection, SELECT from the recovery decisions table) rather than routing
    through DecisionLogStore, matching the pre-extraction pattern.
    """

    # Legal side-effect status transitions. Unknown→terminal requires a
    # recovery decision record; the validator enforces this at update time.
    LEGAL_TRANSITIONS: dict[str, set[str]] = {
        "planned": {"started", "completed", "failed"},
        "started": {"completed", "failed", "unknown"},
        "unknown": {"completed", "failed", "retry_authorized"},
        "completed": set(),   # terminal
        "failed": set(),      # terminal
        # v3.5.0 (INV-008): retry_authorized→started removed. Retry execution
        # allocates a NEW child attempt via the SideEffectRetryCoordinator; the
        # original row stays retry_authorized as permanent historical truth.
        "retry_authorized": set(),  # terminal for this row (history only)
    }

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def validate_side_effect_transition(
        self, prior_status: str, new_status: str,
    ) -> bool:
        """v2.39.0: validate a side-effect status transition.

        Returns True if the transition is legal, False otherwise.
        Terminal states (completed/failed) cannot transition out.
        Unknown→terminal requires a recovery decision (enforced by caller).
        """
        allowed = self.LEGAL_TRANSITIONS.get(prior_status, set())
        return new_status in allowed

    def record_side_effect(
        self,
        run_id: str,
        step_id: int,
        node_id: str,
        side_effect_type: str,
        idempotency_key: str,
        branch_name: str | None = None,
        status: str = "planned",
        request_hash: str | None = None,
        response_hash: str | None = None,
        external_reference: str | None = None,
        retryable: bool = True,
        *,
        parent_side_effect_key: str | None = None,
        root_side_effect_key: str | None = None,
        retry_ordinal: int = 0,
        recovery_decision_id: str | None = None,
    ) -> None:
        """Record a side effect in the ledger.

        v2.38.1: collision detection. If a row with the same
        (run_id, idempotency_key) already exists, compares node_id,
        side_effect_type, and request_hash. Mismatch raises
        SideEffectCollisionError — same key with different identity is
        identity corruption, not idempotency.

        v3.5.0: lineage columns (parent_side_effect_key, root_side_effect_key,
        retry_ordinal, recovery_decision_id) for retry-authorized execution.
        These are keyword-only to avoid breaking existing callers. Original
        rows have NULL parent/root, ordinal 0, NULL decision_id.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            # v2.38.1: check for collision before INSERT OR IGNORE
            existing = conn.execute(
                """
                SELECT node_id, side_effect_type, request_hash, status
                FROM side_effect_ledger
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (run_id, idempotency_key),
            ).fetchone()

            if existing is not None:
                ex_node, ex_type, ex_req, ex_status = existing
                # Collision: same key, different identity fields
                if ex_node != node_id or ex_type != side_effect_type:
                    raise SideEffectCollisionError(
                        f"Side-effect key collision: idempotency_key={idempotency_key} "
                        f"already exists with node_id={ex_node}/type={ex_type}, "
                        f"attempted with node_id={node_id}/type={side_effect_type}"
                    )
                if request_hash and ex_req and request_hash != ex_req:
                    raise SideEffectCollisionError(
                        f"Side-effect key collision: idempotency_key={idempotency_key} "
                        f"existing request_hash={ex_req}, new request_hash={request_hash}"
                    )
                # Same identity — idempotent INSERT OR IGNORE (safe replay)
                return

            conn.execute(
                """
                INSERT INTO side_effect_ledger
                (run_id, step_id, node_id, branch_name, side_effect_type,
                 idempotency_key, status, request_hash, response_hash,
                 external_reference, retryable, timestamp,
                 parent_side_effect_key, root_side_effect_key,
                 retry_ordinal, recovery_decision_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, step_id, node_id, branch_name, side_effect_type,
                 idempotency_key, status, request_hash, response_hash,
                 external_reference, 1 if retryable else 0, now,
                 parent_side_effect_key, root_side_effect_key,
                 retry_ordinal, recovery_decision_id),
            )

    def update_side_effect_status(
        self,
        run_id: str,
        idempotency_key: str,
        status: str,
        response_hash: str | None = None,
        external_reference: str | None = None,
    ) -> None:
        """Update a side effect's status after completion/failure.

        v2.38.1: terminal dedup. If the row is already completed:
        - same response_hash/external_reference → no-op (safe replay)
        - different response_hash/external_reference → integrity error

        v2.39.1: runtime transition guard. Validates that the transition
        from prior_status to new_status is legal. Unknown→terminal requires
        a matching durable recovery decision. Raises SideEffectTransitionError
        on illegal transitions or missing recovery decisions.

        v2.39.2: recovery decisions are now semantically bound to the
        target transition (verified_completed → completed only,
        verified_failed/mark_unrecoverable → failed only, safe_to_retry →
        retry_authorized only). Duplicate validation removed.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                """
                SELECT status, response_hash, external_reference
                FROM side_effect_ledger
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (run_id, idempotency_key),
            ).fetchone()

            if existing is None:
                return  # missing row — no-op

            ex_status, ex_resp, ex_ext = existing

            # v3.5.0 ChatGPT T5 hardening: recovery child bypass guard.
            # A recovery child (has parent_side_effect_key) must NEVER be
            # transitioned through the ordinary generic API. Only the fenced
            # recovery methods (claim/heartbeat/complete/fail/reclaim) may
            # mutate recovery children. This prevents any caller from
            # bypassing fencing tokens.
            child_check = conn.execute(
                """SELECT parent_side_effect_key FROM side_effect_ledger
                   WHERE run_id = ? AND idempotency_key = ?""",
                (run_id, idempotency_key),
            ).fetchone()
            if child_check and child_check[0] is not None:
                raise SideEffectRecoveryError(
                    f"Recovery child {idempotency_key} cannot be mutated "
                    f"through ordinary update_side_effect_status. Use the "
                    f"fenced recovery transition API. "
                    f"RECOVERY_CHILD_REQUIRES_FENCED_TRANSITION",
                    code="RECOVERY_CHILD_REQUIRES_FENCED_TRANSITION",
                )

            # v3.5.0 (INV-003): parent immutability guard. Once a child
            # attempt is allocated, the parent row is permanently immutable.
            # Check for retry lineage inside this transaction.
            if ex_status == "retry_authorized":
                child_count = conn.execute(
                    """SELECT COUNT(*) FROM side_effect_ledger
                       WHERE run_id = ? AND parent_side_effect_key = ?""",
                    (run_id, idempotency_key),
                ).fetchone()[0]
                if child_count > 0:
                    # Check if any child is in-flight
                    in_flight = conn.execute(
                        """SELECT COUNT(*) FROM side_effect_ledger
                           WHERE run_id = ? AND parent_side_effect_key = ?
                           AND status IN ('planned', 'started')""",
                        (run_id, idempotency_key),
                    ).fetchone()[0]
                    if in_flight > 0:
                        raise SideEffectRecoveryError(
                            f"Cannot mutate parent {idempotency_key}: "
                            f"child attempt is in-flight (planned or started). "
                            f"RECOVERY_TARGET_IN_FLIGHT",
                            code="RECOVERY_TARGET_IN_FLIGHT",
                        )
                    else:
                        raise SideEffectRecoveryError(
                            f"Cannot mutate parent {idempotency_key}: "
                            f"retry lineage exists (child is terminal). "
                            f"Parent is permanently immutable. "
                            f"RECOVERY_TARGET_HAS_RETRY_LINEAGE",
                            code="RECOVERY_TARGET_HAS_RETRY_LINEAGE",
                        )

            # v2.38.1: terminal dedup — same-status completed replay
            if ex_status == "completed" and status == "completed":
                new_resp = response_hash or external_reference or ""
                old_resp = ex_resp or ex_ext or ""
                if old_resp and new_resp and old_resp != new_resp:
                    raise SideEffectIntegrityError(
                        f"Side-effect integrity violation: idempotency_key={idempotency_key} "
                        f"completed with response={old_resp}, "
                        f"re-attempted with response={new_resp}"
                    )
                if old_resp or not new_resp:
                    return  # safe no-op replay

            # v2.39.1: runtime transition guard (single pass)
            if not self.validate_side_effect_transition(ex_status, status):
                raise SideEffectTransitionError(
                    f"Illegal side-effect transition: {ex_status} → {status} "
                    f"for idempotency_key={idempotency_key} (run_id={run_id})"
                )

            # v2.39.2: unknown→terminal requires a semantically compatible
            # recovery decision (not just any recovery decision)
            if ex_status == "unknown" and status in ("completed", "failed", "retry_authorized"):
                # Cross-table read of side_effect_recovery_decisions (same
                # connection, single SELECT). Kept inline to match the
                # pre-extraction pattern.
                cursor = conn.execute(
                    "SELECT decision_id, run_id, idempotency_key, node_id, step_id, "
                    "side_effect_type, prior_status, decision, actor, reason, "
                    "external_reference, created_at, metadata_json, retention_status "
                    "FROM side_effect_recovery_decisions"
                    " WHERE run_id = ? AND idempotency_key = ? "
                    "ORDER BY created_at DESC",
                    (run_id, idempotency_key),
                )
                cols = [d[0] for d in cursor.description]
                recovery = [dict(zip(cols, row)) for row in cursor.fetchall()]
                if not recovery:
                    raise SideEffectTransitionError(
                        f"Unknown→{status} transition requires a recovery decision "
                        f"for idempotency_key={idempotency_key} (run_id={run_id}), "
                        f"but none exists"
                    )
                # v2.39.2: semantic binding
                recovery_decisions_set = {rd.get("decision", "") for rd in recovery}
                required: set[str]
                if status == "completed":
                    required = {"verified_completed"}
                elif status == "failed":
                    required = {"verified_failed", "mark_unrecoverable"}
                else:  # retry_authorized
                    required = {"safe_to_retry"}
                if not (required & recovery_decisions_set):
                    raise SideEffectTransitionError(
                        f"Unknown→{status} transition requires recovery decision "
                        f"in {required}, but found {recovery_decisions_set} "
                        f"for idempotency_key={idempotency_key} (run_id={run_id})"
                    )

            conn.execute(
                """
                UPDATE side_effect_ledger
                SET status = ?, response_hash = ?, external_reference = ?, timestamp = ?
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (status, response_hash, external_reference, now, run_id, idempotency_key),
            )

    def resolve_side_effect_recovery_decision_transactional(
        self,
        run_id: str,
        idempotency_key: str,
        decision: dict[str, Any],
        target_status: str,
        response_hash: str | None = None,
        external_reference: str | None = None,
    ) -> None:
        """v3.3.0: atomically record a recovery decision AND transition the
        side-effect ledger out of 'unknown' in ONE transaction.

        This is the production path for operator-initiated unknown-effect
        resolution. It avoids the dangerous partial state where a decision
        exists but the ledger is still 'unknown' (which would make the
        classifier think recovery exists while the run stays unresolved).

        Uses a plain INSERT (not INSERT OR REPLACE) so a duplicate decision_id
        raises sqlite3.IntegrityError, translated to SideEffectIntegrityError.
        The PRIMARY KEY constraint enforces uniqueness inside the transaction
        — no pre-check as the only defense.

        The gate logic mirrors update_side_effect_status (terminal dedup,
        transition guard, semantic binding) but runs on the same connection
        as the decision INSERT, so the freshly-inserted decision is visible
        to the gate's cross-table SELECT.

        Existing record_recovery_decision and update_side_effect_status are
        preserved unchanged for test-facing use.
        """
        now = datetime.now(timezone.utc).isoformat()

        decision_id = decision.get("decision_id", "")
        if not decision_id:
            raise SideEffectTransitionError(
                "resolve_side_effect_recovery_decision_transactional requires "
                "a non-empty decision_id"
            )

        with sqlite3.connect(self.db_path) as conn:
            # 1. INSERT the recovery decision (plain INSERT — PK enforces uniqueness).
            try:
                conn.execute(
                    """
                    INSERT INTO side_effect_recovery_decisions
                    (decision_id, run_id, idempotency_key, node_id, step_id,
                     side_effect_type, prior_status, decision, actor, reason,
                     external_reference, created_at, metadata_json, retention_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision_id,
                        decision.get("run_id", run_id),
                        decision.get("idempotency_key", idempotency_key),
                        decision.get("node_id", ""),
                        decision.get("step_id"),
                        decision.get("side_effect_type", ""),
                        decision.get("prior_status", "unknown"),
                        decision.get("decision", ""),
                        decision.get("actor", "operator"),
                        decision.get("reason", ""),
                        decision.get("external_reference", ""),
                        decision.get("created_at", now),
                        decision.get("metadata_json", ""),
                        decision.get("retention_status", "active"),
                    ),
                )
            except sqlite3.IntegrityError as e:
                raise SideEffectIntegrityError(
                    f"Duplicate recovery decision_id={decision_id!r} — "
                    f"an existing decision cannot be overwritten"
                ) from e

            # 2. Gate + UPDATE — mirror update_side_effect_status (lines 315-395).
            existing = conn.execute(
                """
                SELECT status, response_hash, external_reference
                FROM side_effect_ledger
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (run_id, idempotency_key),
            ).fetchone()

            if existing is None:
                # No ledger row — the INSERT above is NOT auto-rolled back by
                # a return. Raise to abort the transaction (the `with` block
                # rolls back on exception).
                raise SideEffectTransitionError(
                    f"Cannot resolve: no side-effect ledger row for "
                    f"idempotency_key={idempotency_key} (run_id={run_id})"
                )

            ex_status, ex_resp, ex_ext = existing

            if ex_status != "unknown":
                raise SideEffectTransitionError(
                    f"Cannot resolve: side effect {idempotency_key} has status "
                    f"{ex_status!r}, not 'unknown' (run_id={run_id})"
                )

            # Transition guard
            if not self.validate_side_effect_transition(ex_status, target_status):
                raise SideEffectTransitionError(
                    f"Illegal side-effect transition: {ex_status} → {target_status} "
                    f"for idempotency_key={idempotency_key} (run_id={run_id})"
                )

            # Semantic binding — the freshly-inserted decision is now visible.
            cursor = conn.execute(
                "SELECT decision FROM side_effect_recovery_decisions"
                " WHERE run_id = ? AND idempotency_key = ?",
                (run_id, idempotency_key),
            )
            recovery_decisions_set = {row[0] for row in cursor.fetchall()}

            required: set[str]
            if target_status == "completed":
                required = {"verified_completed"}
            elif target_status == "failed":
                required = {"verified_failed", "mark_unrecoverable"}
            else:  # retry_authorized
                required = {"safe_to_retry"}
            if not (required & recovery_decisions_set):
                raise SideEffectTransitionError(
                    f"Unknown→{target_status} requires recovery decision "
                    f"in {required}, but found {recovery_decisions_set} "
                    f"for idempotency_key={idempotency_key} (run_id={run_id})"
                )

            # 3. UPDATE the ledger row.
            conn.execute(
                """
                UPDATE side_effect_ledger
                SET status = ?, response_hash = ?, external_reference = ?, timestamp = ?
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (target_status, response_hash, external_reference, now, run_id, idempotency_key),
            )
            # The `with sqlite3.connect(...) as conn:` context commits on exit.

    def get_side_effects(self, run_id: str) -> list[dict]:
        """Get all side effects for a run.

        v3.5.0: includes lineage columns (parent_side_effect_key,
        root_side_effect_key, retry_ordinal, recovery_decision_id,
        capsule_id, capsule_status, execution_claim_id, dispatch_attempted_at).
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT id, step_id, node_id, branch_name, side_effect_type,
                       idempotency_key, status, request_hash, response_hash,
                       external_reference, retryable, timestamp,
                       parent_side_effect_key, root_side_effect_key,
                       retry_ordinal, recovery_decision_id,
                       capsule_id, capsule_status,
                       execution_claim_id, dispatch_attempted_at,
                       claim_acquired_at, claim_expires_at
                FROM side_effect_ledger WHERE run_id = ? ORDER BY id
                """,
                (run_id,),
            )
            return [
                {"id": r[0], "step_id": r[1], "node_id": r[2], "branch_name": r[3],
                 "side_effect_type": r[4], "idempotency_key": r[5], "status": r[6],
                 "request_hash": r[7], "response_hash": r[8],
                 "external_reference": r[9], "retryable": bool(r[10]), "timestamp": r[11],
                 "parent_side_effect_key": r[12],
                 "root_side_effect_key": r[13],
                 "retry_ordinal": r[14],
                 "recovery_decision_id": r[15],
                 "capsule_id": r[16],
                 "capsule_status": r[17],
                 "execution_claim_id": r[18],
                 "dispatch_attempted_at": r[19],
                 "claim_acquired_at": r[20],
                 "claim_expires_at": r[21]}
                for r in cursor.fetchall()
            ]

    def get_side_effect_by_key(self, run_id: str, idempotency_key: str) -> dict | None:
        """Get a specific side effect by its idempotency key."""
        effects = self.get_side_effects(run_id)
        for e in effects:
            if e["idempotency_key"] == idempotency_key:
                return e
        return None

    def is_side_effect_completed(self, run_id: str, idempotency_key: str) -> bool:
        """Check if a side effect has been completed."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT status FROM side_effect_ledger WHERE run_id = ? AND idempotency_key = ?",
                (run_id, idempotency_key),
            )
            row = cursor.fetchone()
            return row is not None and row[0] == "completed"

    def get_side_effects_by_status(self, run_id: str, status: str) -> list[dict]:
        """Get side effects filtered by status."""
        return [e for e in self.get_side_effects(run_id) if e["status"] == status]

    # ── v3.5.0: Recovery-only child transition API (INV-003, INV-011, INV-012) ──
    # These dedicated methods enforce fencing tokens and cannot be accidentally
    # acquired through ordinary execution paths. ChatGPT T5 gate #2: "introduce
    # a dedicated API rather than extending the ordinary transition method with
    # a permissive flag."

    def claim_recovery_attempt(
        self,
        run_id: str,
        child_key: str,
        execution_claim_id: str,
        action_id: str,
    ) -> str:
        """Atomically claim a recovery child: planned → started.

        ChatGPT T7 6th re-review: action_id is mandatory, not optional.
        The action CAS always runs. Both execution_claim_id and action_id
        must be non-empty.

        Returns the fencing token (same as execution_claim_id).
        """
        if not execution_claim_id:
            raise SideEffectRecoveryError(
                "claim_recovery_attempt requires non-empty execution_claim_id",
                code="CLAIM_MISSING_TOKEN",
            )
        if not action_id:
            raise SideEffectRecoveryError(
                "claim_recovery_attempt requires non-empty action_id",
                code="CLAIM_MISSING_ACTION_ID",
            )
        fencing_token = execution_claim_id  # Use caller-supplied token
        now = datetime.now(timezone.utc).isoformat()
        from datetime import timedelta
        lease_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Atomic CAS: only transition if still planned
            cursor = conn.execute(
                """UPDATE side_effect_ledger
                   SET status = 'started',
                       execution_claim_id = ?,
                       claim_acquired_at = ?,
                       claim_expires_at = ?
                   WHERE run_id = ? AND idempotency_key = ?
                   AND status = 'planned'
                   AND parent_side_effect_key IS NOT NULL""",
                (fencing_token, now, lease_expiry,
                 run_id, child_key),
            )
            if cursor.rowcount == 0:
                existing = conn.execute(
                    """SELECT status, execution_claim_id FROM side_effect_ledger
                       WHERE run_id = ? AND idempotency_key = ?""",
                    (run_id, child_key),
                ).fetchone()
                if existing is None:
                    raise SideEffectRecoveryError(
                        f"Recovery child not found: {child_key}",
                        code="RECOVERY_CHILD_NOT_FOUND",
                    )
                if existing[0] == "started":
                    raise SideEffectRecoveryError(
                        f"Recovery child {child_key} already claimed by "
                        f"{existing[1]}. CLAIM_ALREADY_HELD",
                        code="CLAIM_ALREADY_HELD",
                    )
                raise SideEffectRecoveryError(
                    f"Recovery child {child_key} is in status '{existing[0]}', "
                    f"cannot claim. CLAIM_INVALID_TARGET",
                    code="CLAIM_INVALID_TARGET",
                )
            # ChatGPT T7 4th-6th re-review: atomically transition the SPECIFIC
            # action row to 'claimed' in the same transaction. action_id is
            # mandatory. Unconditional CAS with rowcount check.
            act_cursor = conn.execute(
                """UPDATE recovery_execution_actions
                   SET execution_status = 'claimed',
                       execution_claim_id = ?,
                       started_at = COALESCE(started_at, ?)
                   WHERE action_id = ?
                   AND run_id = ?
                   AND retry_attempt_key = ?
                   AND execution_claim_id = ?
                   AND execution_status = 'created'""",
                (fencing_token, now, action_id, run_id, child_key,
                 execution_claim_id),
            )
            if act_cursor.rowcount != 1:
                raise SideEffectRecoveryError(
                    f"Action {action_id} not found or not in 'created' "
                    f"state for child {child_key}. Claim rolled back.",
                    code="CLAIM_ACTION_NOT_FOUND",
                )
        return fencing_token

    def heartbeat_recovery_attempt(
        self,
        run_id: str,
        child_key: str,
        fencing_token: str,
    ) -> bool:
        """Extend the lease on a recovery child.

        ChatGPT T5 gate #4: heartbeat succeeds only when fencing token matches,
        status is started, and lease owner matches. A stale worker must not
        extend the lease after another worker has reclaimed the child.
        """
        from datetime import timedelta
        new_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE side_effect_ledger
                   SET claim_expires_at = ?
                   WHERE run_id = ? AND idempotency_key = ?
                   AND status = 'started'
                   AND execution_claim_id = ?""",
                (new_expiry, run_id, child_key, fencing_token),
            )
            return cursor.rowcount > 0

    def complete_recovery_attempt(
        self,
        run_id: str,
        child_key: str,
        fencing_token: str,
        response_hash: str | None = None,
    ) -> bool:
        """Terminal CAS: complete a recovery child.

        ChatGPT T5 gate #4: the active fencing token must be required for
        completion. A worker that lost ownership must not alter authoritative
        execution state.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE side_effect_ledger
                   SET status = 'completed',
                       response_hash = COALESCE(?, response_hash)
                   WHERE run_id = ? AND idempotency_key = ?
                   AND status = 'started'
                   AND execution_claim_id = ?""",
                (response_hash, run_id, child_key, fencing_token),
            )
            return cursor.rowcount > 0

    def fail_recovery_attempt(
        self,
        run_id: str,
        child_key: str,
        fencing_token: str,
    ) -> bool:
        """Terminal CAS: fail a recovery child."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE side_effect_ledger
                   SET status = 'failed'
                   WHERE run_id = ? AND idempotency_key = ?
                   AND status = 'started'
                   AND execution_claim_id = ?""",
                (run_id, child_key, fencing_token),
            )
            return cursor.rowcount > 0

    def mark_recovery_dispatch_attempted(
        self,
        run_id: str,
        child_key: str,
        fencing_token: str,
    ) -> bool:
        """Fenced one-shot CAS: mark that the dispatch boundary was crossed.

        ChatGPT T5 hardening #2: the production protocol needs an authoritative
        method that atomically records dispatch_attempted_at. Only the worker
        holding the correct fencing token, with a valid lease, may cross this
        boundary — and only once.

        CAS predicate requires:
        - status = started
        - execution_claim_id = fencing_token (correct owner)
        - dispatch_attempted_at IS NULL (one-shot)
        - claim_expires_at > now (lease still valid)

        Returns True if the boundary was crossed. A duplicate call with the
        same token, a stale token, an expired lease, a terminal child, or an
        already-marked boundary returns False.

        This closes the race:
            worker A lease expires without dispatch
            worker B reclaims with new fence
            worker A attempts to cross boundary
            -> stale boundary CAS rejected
            -> worker A must not dispatch
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE side_effect_ledger
                   SET dispatch_attempted_at = ?
                   WHERE run_id = ? AND idempotency_key = ?
                   AND status = 'started'
                   AND execution_claim_id = ?
                   AND dispatch_attempted_at IS NULL
                   AND claim_expires_at > ?""",
                (now, run_id, child_key, fencing_token, now),
            )
            return cursor.rowcount > 0

    def reclaim_expired_recovery_attempt(
        self,
        run_id: str,
        child_key: str,
    ) -> str | None:
        """Reclaim a recovery child whose lease has expired.

        ChatGPT T5 gate #5 (MOST IMPORTANT): lease expiry does NOT authorize
        blind redispatch. If dispatch_attempted_at is set (boundary was crossed),
        the child transitions to unknown — NOT back to planned. Only children
        where dispatch was never attempted can be reclaimed.

        Returns new fencing token if reclaimed, None if child went to unknown.
        """
        now = datetime.now(timezone.utc).isoformat()
        import uuid as _uuid
        new_token = str(_uuid.uuid4())
        from datetime import timedelta
        new_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Check current state
            row = conn.execute(
                """SELECT status, dispatch_attempted_at, claim_expires_at,
                          execution_claim_id
                   FROM side_effect_ledger
                   WHERE run_id = ? AND idempotency_key = ?""",
                (run_id, child_key),
            ).fetchone()
            if row is None:
                raise SideEffectRecoveryError(
                    f"Recovery child not found: {child_key}",
                    code="RECOVERY_CHILD_NOT_FOUND",
                )
            status, dispatch_at, lease_expiry, observed_claim = row
            if status != "started":
                return None  # Already terminal

            # T5 gate #5: if dispatch boundary was crossed, go to unknown.
            # ChatGPT T7 2nd re-review fix 2: check lease actually expired
            # before transitioning. An unexpired live dispatch must not be
            # corrupted.
            from datetime import datetime as _dt
            if dispatch_at is not None:
                # Verify lease expired before transitioning
                if lease_expiry:
                    try:
                        if _dt.fromisoformat(lease_expiry) > datetime.now(timezone.utc):
                            return None  # Lease hasn't expired — don't touch
                    except (ValueError, TypeError):
                        pass
                conn.execute(
                    """UPDATE side_effect_ledger
                       SET status = 'unknown'
                       WHERE run_id = ? AND idempotency_key = ?
                       AND status = 'started'
                       AND claim_expires_at <= ?""",
                    (run_id, child_key, datetime.now(timezone.utc).isoformat()),
                )
                return None  # Went to unknown — no redispatch

            # Dispatch boundary was NOT crossed — safe to reclaim
            # ChatGPT T7 3rd re-review fix 3: CAS with expiry + claim predicates
            from datetime import datetime as _dt
            now_utc = datetime.now(timezone.utc)
            # Check lease actually expired
            if lease_expiry:
                try:
                    expiry_dt = _dt.fromisoformat(lease_expiry)
                    if expiry_dt > now_utc:
                        return None  # Lease hasn't expired yet
                except (ValueError, TypeError):
                    pass  # Can't parse — treat as expired

            now_iso = now_utc.isoformat()
            cursor = conn.execute(
                """UPDATE side_effect_ledger
                   SET execution_claim_id = ?,
                       claim_acquired_at = ?,
                       claim_expires_at = ?
                   WHERE run_id = ? AND idempotency_key = ?
                   AND status = 'started'
                   AND claim_expires_at <= ?
                   AND execution_claim_id = ?
                   AND dispatch_attempted_at IS NULL""",
                (new_token, now, new_expiry,
                 run_id, child_key, now_iso, observed_claim),
            )
            if cursor.rowcount > 0:
                return new_token
            return None

    def scan_expired_recovery_children(
        self,
        run_id: str,
    ) -> list[dict]:
        """v3.5.1 (#4): PURE read of expired started recovery children.

        Identical scan predicate to reconcile_expired_recovery_children, but
        performs NO mutation. Used by the read-only inspection path
        (build_snapshot / build_trace_health) so a read can REPORT that repair
        is required without performing it.

        Returns a list of detection records:
        [{"child_key": str, "would_action": "requeued" | "unknown"}]
        """
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        detected: list[dict] = []

        with sqlite3.connect(self.db_path) as conn:
            expired = conn.execute(
                """SELECT idempotency_key, dispatch_attempted_at
                   FROM side_effect_ledger
                   WHERE run_id = ?
                   AND status = 'started'
                   AND parent_side_effect_key IS NOT NULL
                   AND claim_expires_at <= ?""",
                (run_id, now),
            ).fetchall()

        for child_key, dispatch_at in expired:
            detected.append({
                "child_key": child_key,
                "would_action": "unknown" if dispatch_at is not None else "requeued",
            })
        return detected

    def reconcile_expired_recovery_children(
        self,
        run_id: str,
    ) -> list[dict]:
        """v3.5.0 T7: Batch-reconcile all expired started recovery children.

        v3.5.1 (#4): this is the EXPLICIT mutating owner. Read paths must
        call scan_expired_recovery_children; only the reconcile command (or
        an equivalent governed write) should call this.

        ChatGPT T7 fix 1: durable crash repair with expiry predicate in SQL CAS.

        For each started recovery child whose lease has expired:
        - dispatch_attempted_at IS NULL → requeue: started → planned, clear
          stale ownership, emit SIDE_EFFECT_RETRY_REQUEUED
        - dispatch_attempted_at IS NOT NULL → started → unknown, finalize
          the execution action as unknown

        A live, unexpired dispatched attempt is NEVER changed by this operation.

        Returns a list of reconciliation records:
        [{"child_key": str, "action": "requeued" | "unknown", "old_status": "started"}]

        ChatGPT T7 2nd re-review fix 1: each UPDATE repeats all authoritative
        predicates (status, expiry, claim) from the scan. rowcount is checked
        before appending results. A heartbeat renewal between scan and write
        causes the CAS to fail safely (no false repair).
        """
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        results: list[dict] = []

        with sqlite3.connect(self.db_path) as conn:
            # Find all expired started recovery children
            expired = conn.execute(
                """SELECT idempotency_key, dispatch_attempted_at,
                          recovery_decision_id, execution_claim_id
                   FROM side_effect_ledger
                   WHERE run_id = ?
                   AND status = 'started'
                   AND parent_side_effect_key IS NOT NULL
                   AND claim_expires_at <= ?""",
                (run_id, now),
            ).fetchall()

            for row in expired:
                child_key, dispatch_at, decision_id, old_claim = row

                if dispatch_at is not None:
                    # Boundary crossed → transition to unknown
                    # CAS: all authoritative predicates repeated in UPDATE
                    cursor = conn.execute(
                        """UPDATE side_effect_ledger
                           SET status = 'unknown'
                           WHERE run_id = ? AND idempotency_key = ?
                           AND status = 'started'
                           AND claim_expires_at <= ?
                           AND execution_claim_id = ?
                           AND dispatch_attempted_at IS NOT NULL""",
                        (run_id, child_key, now, old_claim),
                    )
                    if cursor.rowcount == 0:
                        continue  # CAS lost — lease was renewed or child changed
                    # Finalize execution action as unknown
                    # ChatGPT T7 3rd re-review fix 2: scope by claim + active status
                    conn.execute(
                        """UPDATE recovery_execution_actions
                           SET execution_status = 'unknown',
                               outcome_code = COALESCE(outcome_code, 'lease_expired_after_dispatch'),
                               finished_at = ?
                           WHERE run_id = ? AND retry_attempt_key = ?
                           AND execution_claim_id = ?
                           AND execution_status IN ('claimed', 'dispatch_started')""",
                        (now, run_id, child_key, old_claim),
                    )
                    results.append({
                        "child_key": child_key,
                        "action": "unknown",
                        "old_status": "started",
                    })
                else:
                    # No dispatch → requeue: started → planned, clear ownership
                    # CAS: all authoritative predicates repeated in UPDATE
                    cursor = conn.execute(
                        """UPDATE side_effect_ledger
                           SET status = 'planned',
                               execution_claim_id = NULL,
                               claim_acquired_at = NULL,
                               claim_expires_at = NULL,
                               dispatch_attempted_at = NULL
                           WHERE run_id = ? AND idempotency_key = ?
                           AND status = 'started'
                           AND claim_expires_at <= ?
                           AND execution_claim_id = ?
                           AND dispatch_attempted_at IS NULL""",
                        (run_id, child_key, now, old_claim),
                    )
                    if cursor.rowcount == 0:
                        continue  # CAS lost
                    # Update execution action
                    # ChatGPT T7 3rd re-review fix 2: scope by claim + active status
                    conn.execute(
                        """UPDATE recovery_execution_actions
                           SET execution_status = 'not_acquired',
                               outcome_code = COALESCE(outcome_code, 'lease_expired_before_dispatch'),
                               finished_at = ?
                           WHERE run_id = ? AND retry_attempt_key = ?
                           AND execution_claim_id = ?
                           AND execution_status IN ('claimed', 'dispatch_started')""",
                        (now, run_id, child_key, old_claim),
                    )
                    # ChatGPT T7 3rd re-review fix 5: emit durable event
                    # ChatGPT T7 4th re-review fix 4: use actual run revision
                    rev_row = conn.execute(
                        "SELECT revision FROM chain_states WHERE run_id = ?",
                        (run_id,),
                    ).fetchone()
                    run_revision = rev_row[0] if rev_row else 0
                    conn.execute(
                        """INSERT INTO state_events
                           (run_id, revision, event_type, node_id, step_id, payload, timestamp)
                           VALUES (?, ?, ?, NULL, NULL, ?, ?)""",
                        (run_id, run_revision, "side_effect_retry_requeued",
                         _json.dumps({"child_key": child_key, "action": "requeued"}), now),
                    )
                    results.append({
                        "child_key": child_key,
                        "action": "requeued",
                        "old_status": "started",
                        "execution_claim_id": old_claim,
                    })

        return results

    # ── v3.5.0: recovery_execution_actions lifecycle (INV-018, INV-020) ──

    def create_recovery_execution_action(
        self,
        action_id: str,
        operator_action_id: str | None,
        run_id: str,
        retry_attempt_key: str,
        execution_claim_id: str,
        metadata_json: str = "{}",
    ) -> None:
        """Create a recovery execution action row at status='created'.

        ChatGPT T6: the action row is an audit record for the operator request.
        It is NOT the authoritative side-effect state; the child ledger row
        remains authoritative. The action lifecycle:
            created → child_allocated → claimed → dispatch_started →
            completed | failed | unknown | not_acquired

        INV-018: this must be committed atomically with child allocation.
        The caller ensures both writes share one transaction.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO recovery_execution_actions
                   (action_id, operator_action_id, run_id, retry_attempt_key,
                    execution_status, execution_claim_id, started_at,
                    finished_at, outcome_code, metadata_json)
                   VALUES (?, ?, ?, ?, 'created', ?, NULL, NULL, NULL, ?)""",
                (action_id, operator_action_id, run_id, retry_attempt_key,
                 execution_claim_id, metadata_json),
            )

    def update_recovery_execution_status(
        self,
        action_id: str,
        execution_status: str,
        *,
        outcome_code: str | None = None,
        execution_claim_id: str | None = None,
    ) -> bool:
        """Update the execution_status of a recovery action row.

        Optional fields: outcome_code (for terminal states), execution_claim_id
        (updates the claim reference when the fence changes).
        """
        now = datetime.now(timezone.utc).isoformat()
        sets = ["execution_status = ?"]
        params: list = [execution_status]
        if outcome_code is not None:
            sets.append("outcome_code = ?")
            params.append(outcome_code)
        if execution_claim_id is not None:
            sets.append("execution_claim_id = ?")
            params.append(execution_claim_id)
        if execution_status in ("completed", "failed", "unknown", "not_acquired"):
            sets.append("finished_at = ?")
            params.append(now)
        if execution_status in ("claimed", "dispatch_started"):
            sets.append("started_at = COALESCE(started_at, ?)")
            params.append(now)
        params.append(action_id)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                f"""UPDATE recovery_execution_actions
                    SET {", ".join(sets)}
                    WHERE action_id = ?""",
                params,
            )
            return cursor.rowcount > 0

    def finalize_recovery_execution_action(
        self,
        action_id: str,
        outcome: str,
        *,
        outcome_code: str | None = None,
    ) -> bool:
        """Finalize a recovery action row with a terminal outcome.

        Terminal outcomes: completed, failed, unknown, not_acquired.
        """
        if outcome not in ("completed", "failed", "unknown", "not_acquired"):
            raise SideEffectRecoveryError(
                f"Invalid terminal outcome '{outcome}'; expected one of: "
                f"completed, failed, unknown, not_acquired",
                code="INVALID_OUTCOME",
            )
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE recovery_execution_actions
                   SET execution_status = ?,
                       outcome_code = COALESCE(?, outcome_code),
                       finished_at = ?
                   WHERE action_id = ?""",
                (outcome, outcome_code, now, action_id),
            )
            return cursor.rowcount > 0

    def get_recovery_execution_action(self, action_id: str) -> dict | None:
        """Load a recovery execution action row by action_id."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """SELECT action_id, operator_action_id, run_id, retry_attempt_key,
                          execution_status, execution_claim_id, started_at,
                          finished_at, outcome_code, metadata_json
                   FROM recovery_execution_actions WHERE action_id = ?""",
                (action_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "action_id": row[0], "operator_action_id": row[1],
            "run_id": row[2], "retry_attempt_key": row[3],
            "execution_status": row[4], "execution_claim_id": row[5],
            "started_at": row[6], "finished_at": row[7],
            "outcome_code": row[8], "metadata_json": row[9],
        }

    def get_recovery_execution_actions(
        self,
        *,
        run_id: str | None = None,
        retry_attempt_key: str | None = None,
    ) -> list[dict]:
        """List recovery execution action rows by run_id or retry_attempt_key.

        v3.5.0 T7: used by the lineage projection and reconciler to inspect
        the execution lifecycle of retry-authorized side effects.
        """
        clauses = []
        params = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if retry_attempt_key is not None:
            clauses.append("retry_attempt_key = ?")
            params.append(retry_attempt_key)
        where = " AND ".join(clauses) if clauses else "1=1"
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                f"""SELECT action_id, operator_action_id, run_id, retry_attempt_key,
                           execution_status, execution_claim_id, started_at,
                           finished_at, outcome_code, metadata_json
                    FROM recovery_execution_actions WHERE {where}
                    ORDER BY started_at""",
                params,
            ).fetchall()
        cols = [
            "action_id", "operator_action_id", "run_id", "retry_attempt_key",
            "execution_status", "execution_claim_id", "started_at",
            "finished_at", "outcome_code", "metadata_json",
        ]
        return [dict(zip(cols, row)) for row in rows]


class CapsuleStore:
    """v3.5.0: Persistence for replay capsules (side_effect_replay_capsules table).

    Stores encrypted capsule payloads inline in SQLite (DEC-001). The plaintext
    is never persisted — only AES-256-GCM ciphertext under the per-run DEK.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def persist_capsule(
        self,
        capsule_id: str,
        run_id: str,
        side_effect_key: str,
        capsule_digest: str,
        capsule_schema_version: int,
        canonicalization_version: str,
        encrypted_payload: bytes,
        nonce: bytes,
        key_version: int,
        payload_sensitivity: str,
        source_binding_json: str,
        created_at: str,
    ) -> None:
        """Insert a replay capsule row."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO side_effect_replay_capsules
                (capsule_id, run_id, side_effect_key, capsule_digest,
                 capsule_schema_version, canonicalization_version,
                 encrypted_payload, nonce, key_version, payload_sensitivity,
                 serialization_version, source_binding_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '1', ?, ?)
                """,
                (capsule_id, run_id, side_effect_key, capsule_digest,
                 capsule_schema_version, canonicalization_version,
                 encrypted_payload, nonce, key_version, payload_sensitivity,
                 source_binding_json, created_at),
            )

    def load_capsule(self, capsule_id: str) -> dict | None:
        """Load a capsule by ID. Returns the encrypted payload + nonce + metadata."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT capsule_id, run_id, side_effect_key, capsule_digest,
                       capsule_schema_version, canonicalization_version,
                       encrypted_payload, nonce, key_version, payload_sensitivity,
                       source_binding_json, created_at
                FROM side_effect_replay_capsules WHERE capsule_id = ?
                """,
                (capsule_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "capsule_id": row[0], "run_id": row[1], "side_effect_key": row[2],
            "capsule_digest": row[3], "capsule_schema_version": row[4],
            "canonicalization_version": row[5], "encrypted_payload": row[6],
            "nonce": row[7], "key_version": row[8], "payload_sensitivity": row[9],
            "source_binding_json": row[10], "created_at": row[11],
        }


class RunKeyStore:
    """v3.5.0: Persistence for per-run encryption keys (run_encryption_keys table).

    Stores KEK-wrapped DEKs. The DEK is generated once per run and never
    replaced (INV-016). Race-safe via UNIQUE(run_id) — concurrent first-use
    attempts resolve to the persisted winner.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def get_or_create_run_dek(
        self,
        run_id: str,
        kek: bytes,
    ) -> tuple[bytes, int]:
        """Get the per-run DEK, creating it if this is the first encrypted op.

        ChatGPT guardrail #4: race-safe. If two side effects are the first
        encrypted operation for the same run concurrently, the UNIQUE(run_id)
        constraint ensures only one DEK exists. The loser loads the winner's DEK.

        Returns (dek, key_version).
        """
        from nodechain.core.capsule_crypto import generate_dek, wrap_dek, unwrap_dek

        # Try to load existing first
        existing = self._load_wrapped_dek(run_id)
        if existing is not None:
            wrapped_dek, nonce, key_version = existing
            dek = unwrap_dek(kek, wrapped_dek, nonce)
            return dek, key_version

        # Race-safe create: generate candidate, wrap, INSERT
        dek = generate_dek()
        wrapped_dek, nonce = wrap_dek(kek, dek)
        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO run_encryption_keys
                    (run_id, encrypted_dek, key_version, nonce, created_at, purged_at)
                    VALUES (?, ?, 1, ?, ?, NULL)
                    """,
                    (run_id, wrapped_dek, nonce, now),
                )
            return dek, 1
        except sqlite3.IntegrityError:
            # Another writer won — load their DEK
            existing = self._load_wrapped_dek(run_id)
            if existing is not None:
                wrapped_dek, nonce, key_version = existing
                dek = unwrap_dek(kek, wrapped_dek, nonce)
                return dek, key_version
            raise  # Shouldn't happen, but fail safely

    def _load_wrapped_dek(
        self, run_id: str,
    ) -> tuple[bytes, bytes, int] | None:
        """Load the wrapped DEK for a run. Returns (wrapped_dek, nonce, key_version)."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT encrypted_dek, nonce, key_version
                FROM run_encryption_keys WHERE run_id = ? AND purged_at IS NULL
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return row[0], row[1], row[2]

    def purge_run_key(self, run_id: str) -> None:
        """Mark a run's DEK as purged (after run data is deleted).

        ChatGPT guardrail #9: delete data first, then key. This method marks
        the key as purged (soft delete for audit), not hard delete.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE run_encryption_keys SET purged_at = ? WHERE run_id = ?",
                (now, run_id),
            )


class RecoveryMetricStore:
    """v3.5.0 T9: Persistence for recovery metric events.

    Observability projection — never execution truth. Strict idempotency:
    a reused source_event_key with a different payload raises
    MetricSourceKeyConflict (detects bugs, not just dedupes). Post-purge
    resurrection guard: inserts for a run_id with an existing tombstone
    in run_purge_audit raise MetricRunPurged.
    """

    class MetricSourceKeyConflict(Exception):
        pass

    class MetricRunPurged(Exception):
        pass

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def insert(
        self,
        *,
        metric_event_id: str,
        emitted_at: str,
        metric_name: str,
        metric_kind: str,
        value: float,
        run_id: str | None,
        retry_attempt_key: str | None,
        recovery_action_id: str | None,
        labels_json: str,
        source_event_key: str,
        conn: "sqlite3.Connection | None" = None,
    ) -> bool:
        """Insert a metric event with strict idempotency + resurrection guard.

        Returns True if inserted, False if a duplicate with identical payload
        was already present (true idempotent re-emission).

        Raises MetricSourceKeyConflict if source_event_key exists with a
        different payload. Raises MetricRunPurged if run_id has a tombstone.
        Pass a connection (conn=) to participate in a caller's transaction;
        otherwise opens its own.
        """
        own_conn = conn is None
        if conn is None:
            conn = sqlite3.connect(self.db_path)

        try:
            # Resurrection guard: reject if run already purged
            if run_id is not None:
                tombstone = conn.execute(
                    "SELECT 1 FROM run_purge_audit WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if tombstone is not None:
                    raise self.MetricRunPurged(
                        f"cannot emit metric for purged run {run_id}"
                    )

            # Strict idempotency: check existing row by source_event_key
            existing = conn.execute(
                """SELECT metric_name, metric_kind, value, run_id,
                          retry_attempt_key, recovery_action_id, labels_json
                   FROM recovery_metric_events WHERE source_event_key = ?""",
                (source_event_key,),
            ).fetchone()
            if existing is not None:
                payload = (
                    metric_name, metric_kind, value, run_id,
                    retry_attempt_key, recovery_action_id, labels_json,
                )
                if tuple(existing) != payload:
                    raise self.MetricSourceKeyConflict(
                        f"source_event_key {source_event_key!r} reused with "
                        f"different payload: existing={tuple(existing)} "
                        f"new={payload}"
                    )
                return False  # identical duplicate — true idempotent re-emit

            conn.execute(
                """INSERT INTO recovery_metric_events
                   (metric_event_id, emitted_at, metric_name, metric_kind, value,
                    run_id, retry_attempt_key, recovery_action_id, labels_json,
                    source_event_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (metric_event_id, emitted_at, metric_name, metric_kind, value,
                 run_id, retry_attempt_key, recovery_action_id, labels_json,
                 source_event_key),
            )
            return True
        finally:
            if own_conn:
                conn.commit()

    def query_recent(
        self, *, metric_name: str | None = None, run_id: str | None = None,
        since: str | None = None, limit: int = 1000,
    ) -> list[dict]:
        """Query recent metric events for the dashboard."""
        clauses = []
        params: list = []
        if metric_name is not None:
            clauses.append("metric_name = ?")
            params.append(metric_name)
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if since is not None:
            clauses.append("emitted_at >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                f"""SELECT metric_event_id, emitted_at, metric_name, metric_kind,
                           value, run_id, retry_attempt_key, recovery_action_id,
                           labels_json, source_event_key
                    FROM recovery_metric_events {where}
                    ORDER BY emitted_at DESC LIMIT ?""",
                params,
            ).fetchall()
        cols = ["metric_event_id", "emitted_at", "metric_name", "metric_kind",
                "value", "run_id", "retry_attempt_key", "recovery_action_id",
                "labels_json", "source_event_key"]
        return [dict(zip(cols, row)) for row in rows]


class DecisionLogStore:
    """Persistence for the durable decision logs.

    Extracted from StateManager in v2.83. Each method operates on a single
    decision table (INSERT OR REPLACE for writes, SELECT for reads). The
    decision tables covered:
      - operator_action_log
      - review_decision_attempts
      - memory_decisions
      - side_effect_blocked_attempts
      - side_effect_recovery_decisions
      - memory_read_decisions
      - tool_access_decisions
      - adapter_access_decisions
      - package_trust_decisions
      - registry_admission_decisions
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def record_operator_action(self, action: dict) -> None:
        """Persist one operator recovery action admission row (v2.46.0).

        Called once per recovery action ATTEMPT — admitted OR blocked. This is
        an admission ledger: it records that an operator asked to do X and
        whether the OperatorActionPolicy allowed it, plus the resulting run
        status and the trace_event_id binding it to the authoritative Chain
        Trace. It is NOT an execution record; the Chain Trace stays source of
        truth. Idempotent on action_id (re-recording replaces).
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO operator_action_log
                    (action_id, run_id, action, actor_identity, requested_at,
                     admitted, rejection_reason, target_step_id, target_node_id,
                     resulting_state, trace_event_id, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action["action_id"],
                    action.get("run_id", ""),
                    action.get("action", ""),
                    action.get("actor_identity", ""),
                    action.get("requested_at", datetime.now(timezone.utc).isoformat()),
                    1 if action.get("admitted") else 0,
                    action.get("rejection_reason"),
                    action.get("target_step_id"),
                    action.get("target_node_id"),
                    action.get("resulting_state"),
                    action.get("trace_event_id"),
                    _json.dumps(action.get("metadata") or {})
                    if action.get("metadata") is not None else None,
                ),
            )

    def get_operator_actions(
        self,
        *,
        run_id: str | None = None,
        admitted: bool | None = None,
    ) -> list[dict]:
        """Query the operator recovery action admission ledger (v2.46.0).

        Returns rows newest-first (by requested_at). Optional ``run_id`` scopes
        to one run; optional ``admitted`` filters to allowed/blocked attempts.
        Both admitted and blocked attempts are always persisted, so the audit
        trail of every intervention (and why it was refused) is inspectable.
        """
        clauses: list[str] = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if admitted is not None:
            clauses.append("admitted = ?"); params.append(1 if admitted else 0)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT action_id, run_id, action, actor_identity, requested_at, "
                "admitted, rejection_reason, target_step_id, target_node_id, "
                "resulting_state, trace_event_id, metadata_json "
                "FROM operator_action_log" + where + " ORDER BY requested_at DESC",
                params,
            )
            rows: list[dict] = []
            for r in cursor.fetchall():
                md_raw = r[11]
                try:
                    md = _json.loads(md_raw) if md_raw else {}
                except (ValueError, TypeError):
                    md = {}
                rows.append({
                    "action_id": r[0],
                    "run_id": r[1],
                    "action": r[2],
                    "actor_identity": r[3],
                    "requested_at": r[4],
                    "admitted": bool(r[5]),
                    "rejection_reason": r[6],
                    "target_step_id": r[7],
                    "target_node_id": r[8],
                    "resulting_state": r[9],
                    "trace_event_id": r[10],
                    "metadata": md,
                })
            return rows

    def record_review_attempt(self, attempt: dict) -> None:
        """Persist one review decision attempt row (v2.25.0).

        Called once after every ReviewVerifier.verify() — admitted OR rejected.
        The audit trail of every decision attempt; closes HR-046.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO review_decision_attempts
                    (review_attempt_id, run_id, chain_id, step_id, request_id,
                     request_digest, subject_type, subject_id,
                     attempted_decision_type, attempted_outcome,
                     reviewer_identity, required_reviewer_role, admitted,
                     rejection_reason, verifier_checks, policy_digest,
                     graph_digest, created_at, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt["review_attempt_id"],
                    attempt.get("run_id", ""),
                    attempt.get("chain_id", ""),
                    attempt.get("step_id", 0),
                    attempt.get("request_id", ""),
                    attempt.get("request_digest", ""),
                    attempt.get("subject_type", ""),
                    attempt.get("subject_id", ""),
                    attempt.get("attempted_decision_type", ""),
                    attempt.get("attempted_outcome", ""),
                    attempt.get("reviewer_identity", ""),
                    attempt.get("required_reviewer_role", ""),
                    1 if attempt.get("admitted") else 0,
                    attempt.get("rejection_reason", ""),
                    _json.dumps(attempt.get("verifier_checks") or {}),
                    attempt.get("policy_digest", ""),
                    attempt.get("graph_digest", ""),
                    attempt.get("created_at", datetime.now(timezone.utc).isoformat()),
                    attempt.get("retention_status", "active"),
                ),
            )

    def get_review_attempts(
        self,
        *,
        run_id: str | None = None,
        admitted: bool | None = None,
        rejection_reason: str | None = None,
    ) -> list[dict]:
        """Query durable review decision attempts (v2.25.0).

        Filters are AND-combined. Returns rows as dicts (newest first).
        """
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if admitted is not None:
            clauses.append("admitted = ?"); params.append(1 if admitted else 0)
        if rejection_reason is not None:
            clauses.append("rejection_reason = ?"); params.append(rejection_reason)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT review_attempt_id, run_id, chain_id, step_id, request_id, "
                "request_digest, subject_type, subject_id, attempted_decision_type, "
                "attempted_outcome, reviewer_identity, required_reviewer_role, admitted, "
                "rejection_reason, verifier_checks, policy_digest, graph_digest, "
                "created_at, retention_status "
                "FROM review_decision_attempts" + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_memory_decision(self, decision: dict) -> None:
        """Persist one memory write candidate decision row (v2.28.0).

        Records every candidate decision (allow/deny/skip/error) so blocked
        writes leave a durable audit trail even when no Chroma write occurs.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_decisions
                    (memory_decision_id, run_id, chain_id, step_id, node_id,
                     candidate_id, subject, subject_digest, candidate_digest,
                     confidence, sensitivity, policy_id, rule_id, decision,
                     reason_code, write_ref, created_at, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision["memory_decision_id"],
                    decision.get("run_id", ""),
                    decision.get("chain_id", ""),
                    decision.get("step_id", 0),
                    decision.get("node_id", ""),
                    decision.get("candidate_id", ""),
                    decision.get("subject", ""),
                    decision.get("subject_digest", ""),
                    decision.get("candidate_digest", ""),
                    decision.get("confidence", 0.0),
                    decision.get("sensitivity", ""),
                    decision.get("policy_id", ""),
                    decision.get("rule_id", ""),
                    decision.get("decision", ""),
                    decision.get("reason_code", ""),
                    decision.get("write_ref", ""),
                    decision.get("created_at", datetime.now(timezone.utc).isoformat()),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_memory_decisions(
        self,
        *,
        run_id: str | None = None,
        decision: str | None = None,
        rule_id: str | None = None,
    ) -> list[dict]:
        """Query durable memory decisions (v2.28.0). Filters AND-combined."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        if rule_id is not None:
            clauses.append("rule_id = ?"); params.append(rule_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT memory_decision_id, run_id, chain_id, step_id, node_id, "
                "candidate_id, subject, subject_digest, candidate_digest, "
                "confidence, sensitivity, policy_id, rule_id, decision, "
                "reason_code, write_ref, created_at, retention_status "
                "FROM memory_decisions" + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_side_effect_block(self, attempt: dict) -> None:
        """Record a durable side-effect blocked attempt (v2.34.0).

        Called when the SIDE_EFFECT runtime gate denies a node before
        execution. One row per declared side-effect.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO side_effect_blocked_attempts
                (attempt_id, run_id, chain_id, step_id, node_id,
                 side_effect_type, effect_target, policy_id, rule_id,
                 decision, denial_reason, created_at, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.get("attempt_id", ""),
                    attempt.get("run_id", ""),
                    attempt.get("chain_id"),
                    attempt.get("step_id"),
                    attempt.get("node_id", ""),
                    attempt.get("side_effect_type", ""),
                    attempt.get("effect_target"),
                    attempt.get("policy_id"),
                    attempt.get("rule_id"),
                    attempt.get("decision", "deny"),
                    attempt.get("denial_reason"),
                    attempt.get("created_at", now),
                    attempt.get("retention_status", "active"),
                ),
            )

    def get_side_effect_blocks(
        self,
        *,
        run_id: str | None = None,
        decision: str | None = None,
        rule_id: str | None = None,
    ) -> list[dict]:
        """Query durable side-effect blocked attempts (v2.34.0)."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        if rule_id is not None:
            clauses.append("rule_id = ?"); params.append(rule_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT attempt_id, run_id, chain_id, step_id, node_id, "
                "side_effect_type, effect_target, policy_id, rule_id, "
                "decision, denial_reason, created_at, retention_status "
                "FROM side_effect_blocked_attempts"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_recovery_decision(self, decision: dict) -> None:
        """Record a durable recovery decision for an unknown side effect (v2.39.0)."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO side_effect_recovery_decisions
                (decision_id, run_id, idempotency_key, node_id, step_id,
                 side_effect_type, prior_status, decision, actor, reason,
                 external_reference, created_at, metadata_json, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("decision_id", ""),
                    decision.get("run_id", ""),
                    decision.get("idempotency_key", ""),
                    decision.get("node_id", ""),
                    decision.get("step_id"),
                    decision.get("side_effect_type", ""),
                    decision.get("prior_status", "unknown"),
                    decision.get("decision", ""),
                    decision.get("actor", "operator"),
                    decision.get("reason", ""),
                    decision.get("external_reference", ""),
                    decision.get("created_at", now),
                    decision.get("metadata_json", ""),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_recovery_decisions(
        self,
        *,
        run_id: str | None = None,
        idempotency_key: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable recovery decisions (v2.39.0)."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if idempotency_key is not None:
            clauses.append("idempotency_key = ?"); params.append(idempotency_key)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT decision_id, run_id, idempotency_key, node_id, step_id, "
                "side_effect_type, prior_status, decision, actor, reason, "
                "external_reference, created_at, metadata_json, retention_status "
                "FROM side_effect_recovery_decisions"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_memory_read_decision(self, decision: dict) -> None:
        """Record a durable memory-read policy decision (v2.40.0)."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_read_decisions
                (decision_id, run_id, step_id, node_id, actor, policy_id,
                 rule_id, decision, purpose, source, query_digest,
                 memory_namespace, requested_item_count, exposed_item_count,
                 exposed_to_node, reason_codes, created_at, metadata_json,
                 retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("decision_id", ""),
                    decision.get("run_id", ""),
                    decision.get("step_id"),
                    decision.get("node_id", ""),
                    decision.get("actor", "runtime"),
                    decision.get("policy_id"),
                    decision.get("rule_id"),
                    decision.get("decision", ""),
                    decision.get("purpose", ""),
                    decision.get("source", ""),
                    decision.get("query_digest", ""),
                    decision.get("memory_namespace", ""),
                    decision.get("requested_item_count", 0),
                    decision.get("exposed_item_count", 0),
                    1 if decision.get("exposed_to_node", False) else 0,
                    decision.get("reason_codes", ""),
                    decision.get("created_at", now),
                    decision.get("metadata_json", ""),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_memory_read_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable memory-read decisions (v2.40.0)."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if node_id is not None:
            clauses.append("node_id = ?"); params.append(node_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT decision_id, run_id, step_id, node_id, actor, "
                "policy_id, rule_id, decision, purpose, source, query_digest, "
                "memory_namespace, requested_item_count, exposed_item_count, "
                "exposed_to_node, reason_codes, created_at, metadata_json, "
                "retention_status "
                "FROM memory_read_decisions"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_tool_access_decision(self, decision: dict) -> None:
        """Record a durable tool-access policy decision (v2.42.0)."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_access_decisions
                (decision_id, run_id, step_id, node_id, tool_name,
                 policy_id, rule_id, decision, reason, created_at,
                 metadata_json, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("decision_id", ""),
                    decision.get("run_id", ""),
                    decision.get("step_id"),
                    decision.get("node_id", ""),
                    decision.get("tool_name", ""),
                    decision.get("policy_id"),
                    decision.get("rule_id"),
                    decision.get("decision", ""),
                    decision.get("reason", ""),
                    decision.get("created_at", now),
                    decision.get("metadata_json", ""),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_tool_access_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable tool-access decisions (v2.42.0)."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if node_id is not None:
            clauses.append("node_id = ?"); params.append(node_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT decision_id, run_id, step_id, node_id, tool_name, "
                "policy_id, rule_id, decision, reason, created_at, "
                "metadata_json, retention_status "
                "FROM tool_access_decisions"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_adapter_access_decision(self, decision: dict) -> None:
        """Record a durable adapter-access policy decision (v2.43.0)."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO adapter_access_decisions
                (decision_id, run_id, step_id, node_id, adapter_type,
                 adapter_name, tool_name, policy_id, rule_id, decision,
                 reason, created_at, metadata_json, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("decision_id", ""),
                    decision.get("run_id", ""),
                    decision.get("step_id"),
                    decision.get("node_id", ""),
                    decision.get("adapter_type", ""),
                    decision.get("adapter_name", ""),
                    decision.get("tool_name", ""),
                    decision.get("policy_id"),
                    decision.get("rule_id"),
                    decision.get("decision", ""),
                    decision.get("reason", ""),
                    decision.get("created_at", now),
                    decision.get("metadata_json", ""),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_adapter_access_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable adapter-access decisions (v2.43.0)."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if node_id is not None:
            clauses.append("node_id = ?"); params.append(node_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT decision_id, run_id, step_id, node_id, adapter_type, "
                "adapter_name, tool_name, policy_id, rule_id, decision, "
                "reason, created_at, metadata_json, retention_status "
                "FROM adapter_access_decisions"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_package_trust_decision(self, decision: dict) -> None:
        """Record a durable package-trust policy decision (v2.44.0)."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO package_trust_decisions
                (decision_id, run_id, step_id, node_id, package_name,
                 package_version, package_digest, origin,
                 observed_trust_level, required_trust_level,
                 signature_status, lockfile_status, is_privileged,
                 trust_source, decision, reason, created_at,
                 metadata_json, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("decision_id", ""),
                    decision.get("run_id", ""),
                    decision.get("step_id"),
                    decision.get("node_id", ""),
                    decision.get("package_name", ""),
                    decision.get("package_version", ""),
                    decision.get("package_digest", ""),
                    decision.get("origin", ""),
                    decision.get("observed_trust_level", ""),
                    decision.get("required_trust_level", ""),
                    decision.get("signature_status", ""),
                    decision.get("lockfile_status", ""),
                    1 if decision.get("is_privileged", False) else 0,
                    decision.get("trust_source", ""),
                    decision.get("decision", ""),
                    decision.get("reason", ""),
                    decision.get("created_at", now),
                    decision.get("metadata_json", ""),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_package_trust_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable package-trust decisions (v2.44.0)."""
        clauses = []
        params: list = []
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        if node_id is not None:
            clauses.append("node_id = ?"); params.append(node_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT decision_id, run_id, step_id, node_id, package_name, "
                "package_version, package_digest, origin, observed_trust_level, "
                "required_trust_level, signature_status, lockfile_status, "
                "is_privileged, trust_source, decision, reason, created_at, "
                "metadata_json, retention_status "
                "FROM package_trust_decisions"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def record_registry_admission(self, decision: dict) -> None:
        """Record a durable registry admission decision (v2.45.0)."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO registry_admission_decisions
                (admission_id, node_id, package_name, package_version,
                 package_digest, origin, manifest_hash, contract_hash,
                 decision, reason, rule_id, policy_id, declared_privileged,
                 created_at, metadata_json, retention_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.get("admission_id", ""),
                    decision.get("node_id", "unknown"),
                    decision.get("package_name", ""),
                    decision.get("package_version", ""),
                    decision.get("package_digest", "unknown"),
                    decision.get("origin", "local_registry"),
                    decision.get("manifest_hash", ""),
                    decision.get("contract_hash", ""),
                    decision.get("decision", ""),
                    decision.get("reason", ""),
                    decision.get("rule_id", ""),
                    decision.get("policy_id", ""),
                    1 if decision.get("declared_privileged", False) else 0,
                    decision.get("created_at", now),
                    decision.get("metadata_json", ""),
                    decision.get("retention_status", "active"),
                ),
            )

    def get_registry_admissions(
        self,
        *,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable registry admission decisions (v2.45.0)."""
        clauses = []
        params: list = []
        if node_id is not None:
            clauses.append("node_id = ?"); params.append(node_id)
        if decision is not None:
            clauses.append("decision = ?"); params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT admission_id, node_id, package_name, package_version, "
                "package_digest, origin, manifest_hash, contract_hash, "
                "decision, reason, rule_id, policy_id, declared_privileged, "
                "created_at, metadata_json, retention_status "
                "FROM registry_admission_decisions"
                + where + " ORDER BY created_at DESC",
                params,
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
