"""v3.5.0 T9: Run deletion/purge service — INV-016.

Gated run deletion consuming T7's lineage closure projection. The deletion
gate is NOT just lineage closure — it also requires run existence and
terminal chain status. Full purge is one locked transaction (BEGIN IMMEDIATE)
so a retry allocation racing with deletion has a deterministic outcome.

Key material is invalidated (X'') not hard-deleted, preserving the audit
tombstone. The global run_purge_audit table is excluded from purge and
also prevents post-purge metric resurrection (UNIQUE(run_id) + insert-time
guard in RecoveryMetricStore).
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from nodechain.runtime.recovery_classifier import (
    CLOSED_RETRY_LINEAGE_STATES,
    OPEN_RETRY_LINEAGE_STATES,
    RecoveryState,
    RetryLineageProjection,
    classify_retry_lineages,
)

# Chain statuses that permit deletion (must be terminal).
_TERMINAL_CHAIN_STATUSES = frozenset({"completed", "failed", "cancelled"})

# Gate failure codes.
RUN_NOT_FOUND = "RUN_NOT_FOUND"
RUN_DELETION_BLOCKED_NON_TERMINAL = "RUN_DELETION_BLOCKED_NON_TERMINAL"
RUN_DELETION_BLOCKED_OPEN_LINEAGE = "RUN_DELETION_BLOCKED_OPEN_LINEAGE"
RUN_DELETION_BLOCKED_UNCLASSIFIED_LINEAGE = "RUN_DELETION_BLOCKED_UNCLASSIFIED_LINEAGE"

# Exact purge ordering per ChatGPT final lock: child/evidence tables first,
# materialized state last. run_encryption_keys is NOT in this list — it is
# invalidated (soft) after these hard deletes, then the tombstone is inserted.
_PURGE_TABLE_ORDER = [
    "recovery_metric_events",
    "recovery_execution_actions",
    "side_effect_replay_capsules",
    "side_effect_recovery_decisions",
    "side_effect_blocked_attempts",
    "review_decision_attempts",
    "operator_action_log",
    "memory_decisions",
    "memory_read_decisions",
    "tool_access_decisions",
    "adapter_access_decisions",
    "package_trust_decisions",
    "invocation_ledger",
    "state_events",
    "side_effect_ledger",
    "chain_states",
]


class DeletionBlocked(Exception):
    """Raised when delete_run() finds the gate blocks deletion."""

    def __init__(self, blocking_reasons: tuple[str, ...]) -> None:
        self.blocking_reasons = blocking_reasons
        super().__init__(f"run deletion blocked: {'; '.join(blocking_reasons)}")


@dataclass(frozen=True)
class DeletionAssessment:
    """Advisory assessment — separate facts, not a single allowed blob.

    can_delete() returns this as a preview. delete_run() does NOT trust it;
    it recomputes under BEGIN IMMEDIATE.
    """
    allowed: bool
    run_exists: bool
    run_terminal: bool
    retry_lineage_closed: bool
    chain_status: str | None = None
    blocking_reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    parent_states: tuple[RetryLineageProjection, ...] = ()
    legacy_not_replayable_count: int = 0


@dataclass(frozen=True)
class RunPurgeRecord:
    """Audit record of a completed purge (mirrors run_purge_audit row)."""
    purge_id: str
    run_id: str
    actor_identity: str
    reason: str
    requested_at: str
    completed_at: str
    chain_status_before_purge: str | None
    lineage_summary_json: str
    legacy_not_replayable_count: int
    deleted_row_counts_json: str
    key_purged: int


class RunDeletionService:
    """Gated run deletion + full purge. INV-016 primary enforcement."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    # ── Advisory preview ────────────────────────────────────────────────

    def can_delete(self, run_id: str) -> DeletionAssessment:
        """Advisory assessment. NOT used as authorization by delete_run()."""
        with sqlite3.connect(self.db_path) as conn:
            return self._assess_locked(conn, run_id)

    # ── Atomic purge ────────────────────────────────────────────────────

    def delete_run(
        self, run_id: str, *, actor_identity: str, reason: str,
    ) -> RunPurgeRecord:
        """Full gated purge in one locked transaction.

        Validates actor_identity/reason (nonblank), acquires BEGIN IMMEDIATE,
        recomputes the assessment, aborts if blocked, purges 16 tables in
        order, invalidates the key, inserts the tombstone, commits.
        """
        if not actor_identity or not actor_identity.strip():
            raise ValueError("actor_identity must be a nonblank string")
        if not reason or not reason.strip():
            raise ValueError("reason must be a nonblank string")

        requested_at = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")  # acquire write lock
            try:
                assessment = self._assess_locked(conn, run_id)
                if not assessment.allowed:
                    raise DeletionBlocked(assessment.blocking_reasons)

                # Hard-delete 16 tables in exact order
                deleted_counts: dict[str, int] = {}
                for table in _PURGE_TABLE_ORDER:
                    cur = conn.execute(
                        f"DELETE FROM {table} WHERE run_id = ?", (run_id,)
                    )
                    deleted_counts[table] = cur.rowcount

                # Invalidate key material (soft — preserves tombstone row).
                # X'' keeps NOT NULL constraint satisfied while clearing
                # active wrapped-key material. Application-level invalidation,
                # not guaranteed physical erasure.
                key_cur = conn.execute(
                    """UPDATE run_encryption_keys
                       SET encrypted_dek = X'', nonce = X'', purged_at = ?
                       WHERE run_id = ? AND purged_at IS NULL""",
                    (datetime.now(timezone.utc).isoformat(), run_id),
                )
                key_purged = key_cur.rowcount  # 1 if live key invalidated, 0 if none

                completed_at = datetime.now(timezone.utc).isoformat()
                record = RunPurgeRecord(
                    purge_id=f"purge-{uuid.uuid4().hex[:16]}",
                    run_id=run_id,
                    actor_identity=actor_identity,
                    reason=reason,
                    requested_at=requested_at,
                    completed_at=completed_at,
                    chain_status_before_purge=assessment.chain_status,
                    lineage_summary_json=json.dumps([
                        {"parent": p.parent_side_effect_key, "state": p.state.value}
                        for p in assessment.parent_states
                    ], sort_keys=True),
                    legacy_not_replayable_count=assessment.legacy_not_replayable_count,
                    deleted_row_counts_json=json.dumps(deleted_counts, sort_keys=True),
                    key_purged=key_purged,
                )
                self._insert_tombstone_locked(conn, record)
                conn.execute("COMMIT")
                return record
            except Exception:
                conn.execute("ROLLBACK")
                raise

    # ── Connection-bound helpers (all use the caller's conn) ────────────

    def _assess_locked(
        self, conn: sqlite3.Connection, run_id: str,
    ) -> DeletionAssessment:
        """Recompute the assessment through the given connection.

        Reads chain state, side effects, decisions, and classifies lineage.
        Three independent gates: existence, terminal status, lineage closure.
        """
        # Gate 1: run existence
        row = conn.execute(
            "SELECT state_json FROM chain_states WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return DeletionAssessment(
                allowed=False, run_exists=False, run_terminal=False,
                retry_lineage_closed=True,  # vacuously — no lineage
                chain_status=None,
                blocking_reasons=(RUN_NOT_FOUND,),
            )

        # Extract chain status from state_json
        import json as _json
        try:
            state_dict = _json.loads(row[0])
            chain_status = state_dict.get("status", "unknown")
        except (ValueError, TypeError):
            chain_status = "unknown"

        # Gate 2: terminal chain status
        run_terminal = chain_status in _TERMINAL_CHAIN_STATUSES

        # Gate 3: retry lineage closure — fail-closed.
        # A lineage is closed ONLY if every projection belongs to
        # CLOSED_RETRY_LINEAGE_STATES. Open states block. Any state in
        # NEITHER set (a future unclassified state) also blocks — deletion
        # can never silently pass on an unknown classification.
        side_effects = self._load_side_effects(conn, run_id)
        retry_parents = [se for se in side_effects
                         if se.get("status") == "retry_authorized"]
        recovery_decisions = self._load_recovery_decisions(conn, run_id)
        projections = classify_retry_lineages(
            retry_parents, side_effects, recovery_decisions,
        )
        open_parents = [p for p in projections
                        if p.state in OPEN_RETRY_LINEAGE_STATES]
        unclassified = [
            p for p in projections
            if p.state not in OPEN_RETRY_LINEAGE_STATES
            and p.state not in CLOSED_RETRY_LINEAGE_STATES
        ]
        retry_lineage_closed = not open_parents and not unclassified
        legacy_count = sum(
            1 for p in projections
            if p.state is RecoveryState.LEGACY_NOT_REPLAYABLE
        )

        # Assemble blocking reasons + warnings
        blocking: list[str] = []
        if not run_terminal:
            blocking.append(RUN_DELETION_BLOCKED_NON_TERMINAL)
        if open_parents:
            blocking.append(RUN_DELETION_BLOCKED_OPEN_LINEAGE)
        if unclassified:
            blocking.append(RUN_DELETION_BLOCKED_UNCLASSIFIED_LINEAGE)

        warnings: list[str] = []
        if legacy_count > 0:
            warnings.append(
                f"{legacy_count} unreplayable legacy recovery parent(s) "
                f"will be deleted"
            )

        return DeletionAssessment(
            allowed=len(blocking) == 0,
            run_exists=True,
            run_terminal=run_terminal,
            retry_lineage_closed=retry_lineage_closed,
            chain_status=chain_status,
            blocking_reasons=tuple(blocking),
            warnings=tuple(warnings),
            parent_states=tuple(projections),
            legacy_not_replayable_count=legacy_count,
        )

    @staticmethod
    def _load_side_effects(
        conn: sqlite3.Connection, run_id: str,
    ) -> list[dict[str, Any]]:
        """Load all side effects for a run through the given connection."""
        rows = conn.execute(
            """SELECT idempotency_key, run_id, step_id, node_id, status,
                      side_effect_type, request_hash, parent_side_effect_key,
                      root_side_effect_key, retry_ordinal, recovery_decision_id,
                      capsule_id, capsule_status, execution_claim_id,
                      dispatch_attempted_at, claim_acquired_at, claim_expires_at
               FROM side_effect_ledger WHERE run_id = ?""",
            (run_id,),
        ).fetchall()
        cols = ["idempotency_key", "run_id", "step_id", "node_id", "status",
                "side_effect_type", "request_hash", "parent_side_effect_key",
                "root_side_effect_key", "retry_ordinal", "recovery_decision_id",
                "capsule_id", "capsule_status", "execution_claim_id",
                "dispatch_attempted_at", "claim_acquired_at", "claim_expires_at"]
        return [dict(zip(cols, r)) for r in rows]

    @staticmethod
    def _load_recovery_decisions(
        conn: sqlite3.Connection, run_id: str,
    ) -> list[dict[str, Any]]:
        """Load recovery decisions for a run through the given connection."""
        rows = conn.execute(
            """SELECT decision_id, run_id, idempotency_key, node_id, step_id,
                      side_effect_type, prior_status, decision, actor, reason,
                      external_reference, created_at, retention_status
               FROM side_effect_recovery_decisions WHERE run_id = ?""",
            (run_id,),
        ).fetchall()
        cols = ["decision_id", "run_id", "idempotency_key", "node_id", "step_id",
                "side_effect_type", "prior_status", "decision", "actor", "reason",
                "external_reference", "created_at", "retention_status"]
        return [dict(zip(cols, r)) for r in rows]

    @staticmethod
    def _insert_tombstone_locked(
        conn: sqlite3.Connection, record: RunPurgeRecord,
    ) -> None:
        """Insert the global purge audit row (same transaction)."""
        conn.execute(
            """INSERT INTO run_purge_audit
               (purge_id, run_id, actor_identity, reason, requested_at,
                completed_at, chain_status_before_purge, lineage_summary_json,
                legacy_not_replayable_count, deleted_row_counts_json, key_purged)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record.purge_id, record.run_id, record.actor_identity,
             record.reason, record.requested_at, record.completed_at,
             record.chain_status_before_purge, record.lineage_summary_json,
             record.legacy_not_replayable_count,
             record.deleted_row_counts_json, record.key_purged),
        )
