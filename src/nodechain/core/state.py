"""Chain State — mutable state accumulated during chain execution."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class SideEffectCollisionError(RuntimeError):
    """Same idempotency_key with different identity (node/type/request_hash).

    This is identity corruption, not idempotency. Raised by record_side_effect
    when a key already exists but the new record claims a different node_id,
    side_effect_type, or request_hash.
    """


class SideEffectIntegrityError(RuntimeError):
    """Same completed key re-attempted with different response material.

    Raised by update_side_effect_status when a row is already completed but
    the new response_hash/external_reference differs from the stored value.
    """


class SideEffectTransitionError(RuntimeError):
    """Illegal side-effect status transition at write time.

    Raised by update_side_effect_status when the transition from prior_status
    to new_status is not in LEGAL_TRANSITIONS, or when an unknown→terminal
    transition is attempted without a matching recovery decision.
    """


class SideEffectRecoveryError(Exception):
    """v3.3.0: a recovery-decision resolution was rejected with a precise code.

    Used by StateManager.resolve_side_effect_recovery_decision to surface clean
    errors (not raw store exceptions) for invalid decisions, missing evidence,
    not-unknown status, already-resolved effects, etc.

    Attributes:
        code: a stable machine-readable error code (see the
            SIDE_EFFECT_* vocabulary in the v3.3 plan).
    """

    def __init__(self, message: str, *, code: str = "") -> None:
        super().__init__(message)
        self.code = code


class LoopState(BaseModel):
    """State for an active loop."""

    iteration: int = 0
    entered_at: str = ""
    reason: str = ""


class HumanReviewState(BaseModel):
    """State for human review gate."""

    requested: bool = False
    decision: str | None = None
    reviewer: str | None = None
    decided_at: str | None = None
    timeout_at: str | None = None


class ChainState(BaseModel):
    """
    Mutable chain execution state. Persisted for pause/resume.
    Every field change is a state transition with trace.
    """

    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    status: str = "initialized"
    current_node: str = ""
    step: int = 0
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    paused_at: str | None = None
    completed_at: str | None = None
    outputs: dict[str, Any] = Field(default_factory=dict)
    loop_state: dict[str, LoopState] = Field(default_factory=dict)
    cost_accumulated_usd: float = 0.0
    human_review: HumanReviewState = Field(default_factory=HumanReviewState)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Branch/join execution state
    branch_outputs: dict[str, dict[str, Any]] = Field(default_factory=dict)  # branch_name → {node_id: output}
    join_inputs: dict[str, dict[str, Any]] = Field(default_factory=dict)  # join_id → {branch_name: output}
    skipped_nodes: list[dict[str, Any]] = Field(default_factory=list)  # [{branch, nodes, reason}]
    routing_decisions: list[dict[str, Any]] = Field(default_factory=list)  # [{selected, skipped, from_node}]
    branch_states: dict[str, str] = Field(default_factory=dict)  # branch_name → pending/running/completed/failed/cancelled/ignored/skipped

    # Durable state — idempotency and resume
    revision: int = 0  # Monotonic counter, incremented on every state save
    completed_steps: dict[int, str] = Field(default_factory=dict)  # step_id → node_id (already executed)
    side_effects: list[dict[str, Any]] = Field(default_factory=list)  # [{type, target, step_id, idempotency_key}]
    is_resumed: bool = False  # True if this run was resumed from a previous state

    # Recovery integrity — guard against blueprint drift
    blueprint_version: str = ""  # Blueprint version/tag at run start
    execution_order_hash: str = ""  # SHA-256 of initial execution order for resume verification

    model_config = {"extra": "forbid"}


class RunSummary(BaseModel):
    """Read-only summary of one persisted run for operator surfaces (v2.46.0).

    A lightweight projection of ``chain_states`` used by the recovery console's
    list view and the dashboard. Carries only the fields an operator needs to
    triage the backlog without loading a full ChainState per row. Derived from
    durable state; never mutated by the operator.
    """

    run_id: str
    chain_id: str = ""
    status: str = ""
    step: int = 0
    current_node: str = ""
    updated_at: str = ""
    revision: int = 0

    model_config = {"extra": "forbid"}


class StateManager:
    """
    Manages chain state persistence using SQLite.
    Supports save/restore for pause/resume workflows.

    Three tables:
    - chain_states: latest materialized snapshot (for fast resume)
    - state_events: append-only event log (for replay and audit)
    - invocation_ledger: completed node invocations (for idempotency)
    """

    def __init__(
        self,
        db_path: str | Path = "data/chain_state.db",
        *,
        kek_manager: Any = None,
    ) -> None:
        """Initialize the durable state manager.

        v3.5.1 (#8) B3: the KEK operating mode is resolved at the composition
        boundary (CLI/API/runtime entrypoint), which constructs a KekManager
        and injects it via ``kek_manager=``. When no manager is injected,
        StateManager uses a DETERMINISTIC PRODUCTION-default manager — it
        never reads NODECHAIN_DEV_MODE. A read-only command may construct
        this default safely because KEK loading remains lazy (only resolved
        when a governed side effect actually starts).
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if kek_manager is not None:
            self._kek_manager = kek_manager
        else:
            # Deterministic production default — no environment read.
            from nodechain.core.capsule_crypto import KekManager as _KM
            self._kek_manager = _KM(local_dev=False)
        self._init_db()
        # v2.82/v2.83: extracted persistence stores (internal implementation
        # detail). StateManager remains the public facade; these hold the
        # moved logic.
        from nodechain.core.stores import (
            CapsuleStore,
            DecisionLogStore,
            EventLogStore,
            InvocationLedgerStore,
            RunKeyStore,
            SideEffectLedgerStore,
        )
        self._event_log = EventLogStore(self.db_path)
        self._invocation_ledger = InvocationLedgerStore(self.db_path)
        self._side_effect_ledger = SideEffectLedgerStore(self.db_path)
        self._decision_log = DecisionLogStore(self.db_path)
        self._capsule_store = CapsuleStore(self.db_path)
        self._run_key_store = RunKeyStore(self.db_path)

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_states (
                    run_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS state_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    node_id TEXT,
                    step_id INTEGER,
                    payload TEXT,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_run
                ON state_events (run_id, revision)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS invocation_ledger (
                    run_id TEXT NOT NULL,
                    step_id INTEGER NOT NULL,
                    node_id TEXT NOT NULL,
                    branch_name TEXT,
                    status TEXT NOT NULL DEFAULT 'completed',
                    output_hash TEXT,
                    cost_usd REAL NOT NULL DEFAULT 0.0,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (run_id, step_id)
                )
            """)
            # Migration: add cost_usd column if missing (older DBs)
            try:
                conn.execute("ALTER TABLE invocation_ledger ADD COLUMN cost_usd REAL NOT NULL DEFAULT 0.0")
            except sqlite3.OperationalError:
                pass  # Column already exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS side_effect_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    step_id INTEGER NOT NULL,
                    node_id TEXT NOT NULL,
                    branch_name TEXT,
                    side_effect_type TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    semantic_cache_key TEXT,
                    status TEXT NOT NULL DEFAULT 'planned',
                    request_hash TEXT,
                    response_hash TEXT,
                    external_reference TEXT,
                    retryable INTEGER NOT NULL DEFAULT 1,
                    timestamp TEXT NOT NULL,
                    UNIQUE(run_id, idempotency_key)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_side_effects_run
                ON side_effect_ledger (run_id, step_id)
            """)
            # v3.5.0: lineage columns for retry-authorized side-effect execution.
            # Added via ALTER TABLE (same pattern as cost_usd migration above)
            # so existing databases upgrade in place without recreation.
            for _col, _type in [
                ("parent_side_effect_key", "TEXT"),
                ("root_side_effect_key", "TEXT"),
                ("retry_ordinal", "INTEGER NOT NULL DEFAULT 0"),
                ("recovery_decision_id", "TEXT"),
                ("capsule_id", "TEXT"),
                ("capsule_status", "TEXT NOT NULL DEFAULT 'legacy_unavailable'"),
                ("execution_claim_id", "TEXT"),
                ("dispatch_attempted_at", "TEXT"),
                ("claim_acquired_at", "TEXT"),
                ("claim_expires_at", "TEXT"),
            ]:
                try:
                    conn.execute(
                        f"ALTER TABLE side_effect_ledger ADD COLUMN {_col} {_type}"
                    )
                except sqlite3.OperationalError:
                    pass  # Column already exists
            # v3.5.0: lineage indexes. UNIQUE INDEX for recovery_decision_id
            # (SQLite treats NULL as distinct, so original rows with NULL
            # recovery_decision_id don't conflict). Root/parent indexes for
            # lineage traversal.
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_se_recovery_decision
                ON side_effect_ledger (run_id, recovery_decision_id)
                WHERE recovery_decision_id IS NOT NULL
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_se_root_ordinal
                ON side_effect_ledger (root_side_effect_key, retry_ordinal)
                WHERE root_side_effect_key IS NOT NULL
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_se_parent
                ON side_effect_ledger (parent_side_effect_key)
                WHERE parent_side_effect_key IS NOT NULL
            """)
            # v3.5.0: replay capsule storage (inline SQLite, AES-256-GCM).
            # Written proactively at SIDE_EFFECT_STARTED time (INV-004).
            conn.execute("""
                CREATE TABLE IF NOT EXISTS side_effect_replay_capsules (
                    capsule_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    side_effect_key TEXT NOT NULL,
                    capsule_digest TEXT NOT NULL,
                    capsule_schema_version INTEGER NOT NULL,
                    canonicalization_version TEXT NOT NULL,
                    encrypted_payload BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    key_version INTEGER NOT NULL DEFAULT 1,
                    payload_sensitivity TEXT,
                    serialization_version TEXT NOT NULL DEFAULT '1',
                    source_binding_json TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, side_effect_key)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_capsules_run
                ON side_effect_replay_capsules (run_id)
            """)
            # v3.5.0 migration: add nonce column if missing (DBs created before
            # the column existed have the table but not the column).
            try:
                conn.execute(
                    "ALTER TABLE side_effect_replay_capsules ADD COLUMN nonce BLOB"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists
            # v3.5.0: recovery execution action lifecycle (INV-018, INV-009).
            # Separate from operator_action_log (which is a final admission
            # record). This table tracks the pre-durable execution lifecycle
            # of EXECUTE_RETRY_AUTHORIZED actions.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_execution_actions (
                    action_id TEXT PRIMARY KEY,
                    operator_action_id TEXT,
                    run_id TEXT NOT NULL,
                    retry_attempt_key TEXT NOT NULL,
                    execution_status TEXT NOT NULL DEFAULT 'planned',
                    execution_claim_id TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    outcome_code TEXT,
                    metadata_json TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rex_run
                ON recovery_execution_actions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rex_attempt
                ON recovery_execution_actions (retry_attempt_key)
            """)
            # v3.5.0: per-run encryption keys (KEK-wrapped DEKs). Used for
            # capsule encryption (INV-004, INV-016). Key retained until run
            # deletion is permitted (lineage closure).
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_encryption_keys (
                    run_id TEXT PRIMARY KEY,
                    encrypted_dek BLOB NOT NULL,
                    key_version INTEGER NOT NULL DEFAULT 1,
                    nonce BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    purged_at TEXT
                )
            """)
            # v2.25.0: durable review decision attempt log. One row per
            # ReviewVerifier.verify() call (admitted OR rejected), enabling
            # HR-046 (unauthorized_attempts) and an audit trail of every
            # decision attempt. retention_status is a forward-compatible
            # lifecycle field; v2.25.0 records it but does not enforce purge.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS review_decision_attempts (
                    review_attempt_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    chain_id TEXT,
                    step_id INTEGER,
                    request_id TEXT,
                    request_digest TEXT,
                    subject_type TEXT,
                    subject_id TEXT,
                    attempted_decision_type TEXT,
                    attempted_outcome TEXT,
                    reviewer_identity TEXT,
                    required_reviewer_role TEXT,
                    admitted INTEGER NOT NULL DEFAULT 0,
                    rejection_reason TEXT,
                    verifier_checks TEXT,
                    policy_digest TEXT,
                    graph_digest TEXT,
                    created_at TEXT NOT NULL,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rda_run
                ON review_decision_attempts (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rda_admitted
                ON review_decision_attempts (admitted)
            """)
            # v2.46.0: operator recovery action ADMISSION ledger.
            # One row per operator recovery action ATTEMPT (admitted OR blocked),
            # recording intent, authorization result, action params, resulting
            # status, and the trace_event_id that binds it to the authoritative
            # Chain Trace. This is NOT a competing execution record — the Chain
            # Trace remains the source of truth for what executed.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS operator_action_log (
                    action_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor_identity TEXT,
                    requested_at TEXT NOT NULL,
                    admitted INTEGER NOT NULL DEFAULT 0,
                    rejection_reason TEXT,
                    target_step_id INTEGER,
                    target_node_id TEXT,
                    resulting_state TEXT,
                    trace_event_id TEXT,
                    metadata_json TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_oal_run
                ON operator_action_log (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_oal_admitted
                ON operator_action_log (admitted)
            """)
            # v2.28.0: durable memory decision log. One row per memory write
            # candidate decision (allowed OR blocked), recording why it was
            # allowed/denied/skipped/errored. Mirrors review_decision_attempts.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_decisions (
                    memory_decision_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    chain_id TEXT,
                    step_id INTEGER,
                    node_id TEXT,
                    candidate_id TEXT,
                    subject TEXT,
                    subject_digest TEXT,
                    candidate_digest TEXT,
                    confidence REAL,
                    sensitivity TEXT,
                    policy_id TEXT,
                    rule_id TEXT,
                    decision TEXT NOT NULL,
                    reason_code TEXT,
                    write_ref TEXT,
                    created_at TEXT NOT NULL,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_md_run
                ON memory_decisions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_md_decision
                ON memory_decisions (decision)
            """)

            # v2.34.0: side-effect blocked attempts (runtime gate denials)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS side_effect_blocked_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    chain_id TEXT,
                    step_id INTEGER,
                    node_id TEXT NOT NULL,
                    side_effect_type TEXT NOT NULL,
                    effect_target TEXT,
                    policy_id TEXT,
                    rule_id TEXT,
                    decision TEXT NOT NULL,
                    denial_reason TEXT,
                    created_at TEXT NOT NULL,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_seba_run_id
                ON side_effect_blocked_attempts (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_seba_node_id
                ON side_effect_blocked_attempts (node_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_seba_decision
                ON side_effect_blocked_attempts (decision)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_seba_rule_id
                ON side_effect_blocked_attempts (rule_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_seba_retention
                ON side_effect_blocked_attempts (retention_status)
            """)

            # v2.39.0: side-effect recovery decision log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS side_effect_recovery_decisions (
                    decision_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    step_id INTEGER,
                    side_effect_type TEXT,
                    prior_status TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'operator',
                    reason TEXT,
                    external_reference TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_serd_run_id
                ON side_effect_recovery_decisions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_serd_key
                ON side_effect_recovery_decisions (idempotency_key)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_serd_decision
                ON side_effect_recovery_decisions (decision)
            """)

            # v2.40.0: memory read decisions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_read_decisions (
                    decision_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    step_id INTEGER,
                    node_id TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'runtime',
                    policy_id TEXT,
                    rule_id TEXT,
                    decision TEXT NOT NULL,
                    purpose TEXT,
                    source TEXT,
                    query_digest TEXT,
                    memory_namespace TEXT,
                    requested_item_count INTEGER DEFAULT 0,
                    exposed_item_count INTEGER DEFAULT 0,
                    exposed_to_node INTEGER NOT NULL DEFAULT 0,
                    reason_codes TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mrd_run_id
                ON memory_read_decisions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mrd_node_id
                ON memory_read_decisions (node_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mrd_decision
                ON memory_read_decisions (decision)
            """)

            # v2.42.0: tool access decisions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_access_decisions (
                    decision_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    step_id INTEGER,
                    node_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    policy_id TEXT,
                    rule_id TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tad_run_id
                ON tool_access_decisions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tad_node_id
                ON tool_access_decisions (node_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tad_decision
                ON tool_access_decisions (decision)
            """)

            # v2.43.0: adapter access decisions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS adapter_access_decisions (
                    decision_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    step_id INTEGER,
                    node_id TEXT NOT NULL,
                    adapter_type TEXT,
                    adapter_name TEXT NOT NULL,
                    tool_name TEXT,
                    policy_id TEXT,
                    rule_id TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_aad_run_id
                ON adapter_access_decisions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_aad_node_id
                ON adapter_access_decisions (node_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_aad_decision
                ON adapter_access_decisions (decision)
            """)

            # v2.44.0: package trust decisions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS package_trust_decisions (
                    decision_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    step_id INTEGER,
                    node_id TEXT NOT NULL,
                    package_name TEXT,
                    package_version TEXT,
                    package_digest TEXT,
                    origin TEXT,
                    observed_trust_level TEXT,
                    required_trust_level TEXT,
                    signature_status TEXT,
                    lockfile_status TEXT,
                    is_privileged INTEGER NOT NULL DEFAULT 0,
                    trust_source TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ptd_run_id
                ON package_trust_decisions (run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ptd_node_id
                ON package_trust_decisions (node_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ptd_decision
                ON package_trust_decisions (decision)
            """)

            # v2.45.0: registry admission decisions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS registry_admission_decisions (
                    admission_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    package_name TEXT,
                    package_version TEXT,
                    package_digest TEXT,
                    origin TEXT,
                    manifest_hash TEXT,
                    contract_hash TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    rule_id TEXT,
                    policy_id TEXT,
                    declared_privileged INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    retention_status TEXT NOT NULL DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rad_node_id
                ON registry_admission_decisions (node_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rad_decision
                ON registry_admission_decisions (decision)
            """)

            # v3.5.0 T9: recovery metrics events (observability projection).
            # Append-only event rows consumed by the dashboard. Idempotent via
            # UNIQUE(source_event_key). Guarded against post-purge resurrection
            # by the insert-time run_purge_audit check in RecoveryMetricStore.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_metric_events (
                    metric_event_id TEXT PRIMARY KEY,
                    emitted_at TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_kind TEXT NOT NULL,
                    value REAL NOT NULL,
                    run_id TEXT,
                    retry_attempt_key TEXT,
                    recovery_action_id TEXT,
                    labels_json TEXT DEFAULT '{}',
                    source_event_key TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rme_source
                ON recovery_metric_events (source_event_key)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rme_name_time
                ON recovery_metric_events (metric_name, emitted_at)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rme_run_time
                ON recovery_metric_events (run_id, emitted_at)
            """)

            # v3.5.0 T9: global run-purge audit tombstone (INV-016).
            # NOT run-scoped — excluded from run purge. Records each completed
            # purge so that (a) purge events survive the deletion of run-local
            # tables, and (b) the UNIQUE(run_id) prevents post-purge metric
            # resurrection (recovery_metric_events inserts check this table).
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_purge_audit (
                    purge_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    actor_identity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    chain_status_before_purge TEXT,
                    lineage_summary_json TEXT,
                    legacy_not_replayable_count INTEGER DEFAULT 0,
                    deleted_row_counts_json TEXT,
                    key_purged INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_run_purge_audit_run
                ON run_purge_audit (run_id)
            """)

    def save(self, state: ChainState) -> None:
        """Persist current chain state with revision increment."""
        state.revision += 1
        now = datetime.now(timezone.utc).isoformat()
        state_json = state.model_dump_json()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO chain_states (run_id, state_json, revision, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (state.run_id, state_json, state.revision, now),
            )

    def save_with_invocation(
        self,
        state: ChainState,
        step_id: int,
        node_id: str,
        branch_name: str | None = None,
        invocation_status: str = "completed",
        event_type: str | None = None,
        event_payload: dict | None = None,
        cost_usd: float = 0.0,
    ) -> None:
        """Atomic transaction: increment revision, save state, record invocation, append event.

        This is the core write boundary. All three writes happen in a single
        SQLite transaction, ensuring crash consistency.

        v3.5.1 (#13) B2: state.revision is advanced ONLY after the transaction
        commits — a rolled-back integrity error leaves the caller's in-memory
        ChainState unchanged. Invocation insertion uses the shared
        _insert_invocation_checked helper (same conflict detection as
        record_invocation).
        """
        import json as _json
        now = datetime.now(timezone.utc).isoformat()
        # v3.5.1 (#13) B2: advance the in-memory revision BEFORE serializing so
        # the persisted state_json carries the correct revision, but remember
        # the original so we can restore it if the transaction rolls back.
        original_revision = state.revision
        state.revision = original_revision + 1
        state_json = state.model_dump_json()

        try:
            with sqlite3.connect(self.db_path) as conn:
                # 1. Save materialized state at the new revision.
                conn.execute(
                    """
                    INSERT OR REPLACE INTO chain_states (run_id, state_json, revision, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (state.run_id, state_json, state.revision, now),
                )
                # 2. Record invocation via the shared checked helper.
                self._invocation_ledger._insert_invocation_checked(
                    conn,
                    run_id=state.run_id, step_id=step_id, node_id=node_id,
                    branch_name=branch_name, status=invocation_status,
                    output_hash=None, cost_usd=cost_usd, now=now,
                )
                # 3. Append event to log (if provided)
                if event_type:
                    conn.execute(
                        """
                        INSERT INTO state_events (run_id, revision, event_type, node_id, step_id, payload, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (state.run_id, state.revision, event_type, node_id, step_id,
                         _json.dumps(event_payload) if event_payload else None, now),
                )
                conn.commit()
        except Exception:
            # Transaction rolled back — restore the original in-memory revision
            # so the caller's ChainState reflects that nothing was committed.
            state.revision = original_revision
            raise

    def save_with_event(
        self,
        state: ChainState,
        event_type: str,
        event_payload: dict | None = None,
    ) -> None:
        """Atomic transaction: increment revision, save state, append ONE event.

        Sibling of ``save_with_invocation`` for operator terminal actions
        (cancel/fail) that are NOT node invocations. The state transition and
        the outcome event land in a single SQLite transaction, so there is no
        crash window where a run is terminal but its outcome event is missing.
        (v2.46.0)
        """
        import json as _json
        state.revision += 1
        now = datetime.now(timezone.utc).isoformat()
        state_json = state.model_dump_json()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO chain_states (run_id, state_json, revision, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (state.run_id, state_json, state.revision, now),
            )
            conn.execute(
                """
                INSERT INTO state_events (run_id, revision, event_type, node_id, step_id, payload, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (state.run_id, state.revision, event_type, None, None,
                 _json.dumps(event_payload) if event_payload else None, now),
            )
            conn.commit()

    def append_event(
        self,
        run_id: str,
        revision: int,
        event_type: str,
        node_id: str | None = None,
        step_id: int | None = None,
        payload: dict | None = None,
    ) -> None:
        """Append a state event to the append-only log.

        v2.82: delegates to EventLogStore. Behavior unchanged.
        """
        self._event_log.append_event(
            run_id, revision, event_type, node_id, step_id, payload,
        )

    def record_invocation(
        self,
        run_id: str,
        step_id: int,
        node_id: str,
        branch_name: str | None = None,
        status: str = "completed",
        output_hash: str | None = None,
    ) -> None:
        """Record a completed node invocation in the ledger.

        v2.82: delegates to InvocationLedgerStore. Behavior unchanged.
        """
        self._invocation_ledger.record_invocation(
            run_id, step_id, node_id, branch_name, status, output_hash,
        )

    def is_step_completed(self, run_id: str, step_id: int) -> bool:
        """Check if a step has already been completed (for idempotency).

        v2.82: delegates to InvocationLedgerStore. Behavior unchanged.
        """
        return self._invocation_ledger.is_step_completed(run_id, step_id)

    def is_node_completed(self, run_id: str, node_id: str) -> bool:
        """Check if a node has already completed in this run.

        v2.82: delegates to InvocationLedgerStore. Behavior unchanged.
        """
        return self._invocation_ledger.is_node_completed(run_id, node_id)

    def get_completed_steps(self, run_id: str) -> dict[int, str]:
        """Get all completed step_id → node_id mappings for a run.

        v2.82: delegates to InvocationLedgerStore. Behavior unchanged.
        """
        return self._invocation_ledger.get_completed_steps(run_id)

    def get_invocation_cost(
        self, run_id: str, node_ids: list[str] | None = None,
    ) -> float:
        """Get cumulative cost from invocation ledger.

        v2.82: delegates to InvocationLedgerStore. Behavior unchanged.
        """
        return self._invocation_ledger.get_invocation_cost(run_id, node_ids)

    def get_events(self, run_id: str) -> list[dict]:
        """Get all events for a run (for replay).

        v2.82: delegates to EventLogStore. Behavior unchanged.
        """
        return self._event_log.get_events(run_id)

    def load(self, run_id: str) -> ChainState | None:
        """Restore chain state for pause/resume."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state_json FROM chain_states WHERE run_id = ?",
                (run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return ChainState.model_validate_json(row[0])

    def get_run_updated_at(self, run_id: str) -> str | None:
        """Return the persistence-freshness timestamp (``chain_states.updated_at``)
        for one run, or None if the run is not persisted (v2.46.0).

        This is the DB write time — distinct from the lifecycle ``started_at``
        / ``completed_at`` carried inside the state JSON, which stay fixed once
        set. Operator surfaces use this to show true persistence freshness.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT updated_at FROM chain_states WHERE run_id = ?",
                (run_id,),
            )
            row = cursor.fetchone()
            return row[0] if row is not None else None

    def list_all_runs(self) -> list[RunSummary]:
        """Return a read-only summary of every persisted run (v2.46.0).

        Unifies over all statuses — completed, failed, paused, running,
        waiting_for_review — so the recovery console can show the full backlog,
        not just the review-gated subset returned by ``list_all_review_states``.

        Rows with corrupt state_json are skipped (not crashed on) so the
        operator still sees the rest of the backlog. Ordered by most recently
        updated first, matching ``list_all_review_states``.
        """
        results: list[RunSummary] = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state_json, revision, updated_at "
                "FROM chain_states ORDER BY updated_at DESC",
            )
            for state_json, revision, updated_at in cursor.fetchall():
                try:
                    state = ChainState.model_validate_json(state_json)
                except Exception:
                    continue
                results.append(
                    RunSummary(
                        run_id=state.run_id,
                        chain_id=state.chain_id,
                        status=state.status,
                        step=state.step,
                        current_node=state.current_node,
                        updated_at=updated_at,
                        revision=revision,
                    )
                )
        return results

    def record_operator_action(self, action: dict) -> None:
        """Persist one operator recovery action admission row (v2.46.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_operator_action(action)

    def get_operator_actions(
        self,
        *,
        run_id: str | None = None,
        admitted: bool | None = None,
    ) -> list[dict]:
        """Query the operator recovery action admission ledger (v2.46.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_operator_actions(run_id=run_id, admitted=admitted)

    def list_all_review_states(self) -> list[ChainState]:
        """Return all chain states that carry governed-review metadata.

        Scoped to runs with at least one of: governed_review_request,
        governed_decision_receipt, governed_review_failure. Intentionally NOT
        a generic list-all-runs method — review-governance scans only.

        Used by the dashboard collector (v2.24.0) to derive live review-health
        counters from durable state without a separate review-decision log.
        """
        results: list[ChainState] = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state_json FROM chain_states ORDER BY updated_at DESC",
            )
            for (state_json,) in cursor.fetchall():
                try:
                    state = ChainState.model_validate_json(state_json)
                except Exception:
                    continue
                md = state.metadata or {}
                if (
                    md.get("governed_review_request")
                    or md.get("governed_decision_receipt")
                    or md.get("governed_review_failure")
                ):
                    results.append(state)
        return results

    def record_review_attempt(self, attempt: dict) -> None:
        """Persist one review decision attempt row (v2.25.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_review_attempt(attempt)

    def get_review_attempts(
        self,
        *,
        run_id: str | None = None,
        admitted: bool | None = None,
        rejection_reason: str | None = None,
    ) -> list[dict]:
        """Query durable review decision attempts (v2.25.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_review_attempts(
            run_id=run_id, admitted=admitted, rejection_reason=rejection_reason,
        )

    def record_memory_decision(self, decision: dict) -> None:
        """Persist one memory write candidate decision row (v2.28.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_memory_decision(decision)

    def get_memory_decisions(
        self,
        *,
        run_id: str | None = None,
        decision: str | None = None,
        rule_id: str | None = None,
    ) -> list[dict]:
        """Query durable memory decisions (v2.28.0). Filters AND-combined.

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_memory_decisions(
            run_id=run_id, decision=decision, rule_id=rule_id,
        )

    def record_side_effect_block(self, attempt: dict) -> None:
        """Record a durable side-effect blocked attempt (v2.34.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_side_effect_block(attempt)

    def get_side_effect_blocks(
        self,
        *,
        run_id: str | None = None,
        decision: str | None = None,
        rule_id: str | None = None,
    ) -> list[dict]:
        """Query durable side-effect blocked attempts (v2.34.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_side_effect_blocks(
            run_id=run_id, decision=decision, rule_id=rule_id,
        )

    # ── Recovery decisions (v2.39.0) ───────────────────────────────────

    # Legal side-effect status transitions. v2.83: the authoritative copy now
    # lives on SideEffectLedgerStore; this alias is kept for backward
    # compatibility with any code referencing StateManager.LEGAL_TRANSITIONS.
    LEGAL_TRANSITIONS = {
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

    def validate_side_effect_transition(
        self, prior_status: str, new_status: str,
    ) -> bool:
        """v2.39.0: validate a side-effect status transition.

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        """
        return self._side_effect_ledger.validate_side_effect_transition(
            prior_status, new_status,
        )

    def record_recovery_decision(self, decision: dict) -> None:
        """Record a durable recovery decision for an unknown side effect (v2.39.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_recovery_decision(decision)

    def get_recovery_decisions(
        self,
        *,
        run_id: str | None = None,
        idempotency_key: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable recovery decisions (v2.39.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_recovery_decisions(
            run_id=run_id, idempotency_key=idempotency_key, decision=decision,
        )

    # ── Memory read decisions (v2.40.0) ───────────────────────────────

    def record_memory_read_decision(self, decision: dict) -> None:
        """Record a durable memory-read policy decision (v2.40.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_memory_read_decision(decision)

    def get_memory_read_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable memory-read decisions (v2.40.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_memory_read_decisions(
            run_id=run_id, node_id=node_id, decision=decision,
        )

    # ── Tool access decisions (v2.42.0) ────────────────────────────────

    def record_tool_access_decision(self, decision: dict) -> None:
        """Record a durable tool-access policy decision (v2.42.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_tool_access_decision(decision)

    def get_tool_access_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable tool-access decisions (v2.42.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_tool_access_decisions(
            run_id=run_id, node_id=node_id, decision=decision,
        )

    # ── Adapter access decisions (v2.43.0) ────────────────────────────

    def record_adapter_access_decision(self, decision: dict) -> None:
        """Record a durable adapter-access policy decision (v2.43.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_adapter_access_decision(decision)

    def get_adapter_access_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable adapter-access decisions (v2.43.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_adapter_access_decisions(
            run_id=run_id, node_id=node_id, decision=decision,
        )

    # ── Package trust decisions (v2.44.0) ─────────────────────────────

    def record_package_trust_decision(self, decision: dict) -> None:
        """Record a durable package-trust policy decision (v2.44.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_package_trust_decision(decision)

    def get_package_trust_decisions(
        self,
        *,
        run_id: str | None = None,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable package-trust decisions (v2.44.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_package_trust_decisions(
            run_id=run_id, node_id=node_id, decision=decision,
        )

    # ── Registry admission decisions (v2.45.0) ────────────────────────

    def record_registry_admission(self, decision: dict) -> None:
        """Record a durable registry admission decision (v2.45.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        self._decision_log.record_registry_admission(decision)

    def get_registry_admissions(
        self,
        *,
        node_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict]:
        """Query durable registry admission decisions (v2.45.0).

        v2.83: delegates to DecisionLogStore. Behavior unchanged.
        """
        return self._decision_log.get_registry_admissions(
            node_id=node_id, decision=decision,
        )

    def delete(self, run_id: str) -> None:
        """Remove chain state after completion."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM chain_states WHERE run_id = ?", (run_id,)
            )

    def replay_state(self, run_id: str) -> ChainState | None:
        """Reconstruct ChainState by replaying the event log.

        Returns None if no events exist for the run.
        This is the authoritative state — if it differs from the
        materialized snapshot, the snapshot is stale.
        """
        import json as _json
        events = self.get_events(run_id)
        if not events:
            return None

        # Start from invocation ledger (source of truth for completed work)
        completed_steps = self.get_completed_steps(run_id)

        # Build state from the ledger
        state = ChainState(run_id=run_id)
        state.completed_steps = completed_steps
        state.step = max(completed_steps.keys()) if completed_steps else 0
        state.status = "completed" if completed_steps else "initialized"

        # Determine current_node from last completed step
        if completed_steps:
            last_step = max(completed_steps.keys())
            state.current_node = completed_steps[last_step]

        # Extract branch information from events
        for event in events:
            payload = event.get("payload")
            if isinstance(payload, str):
                try:
                    payload = _json.loads(payload)
                except (_json.JSONDecodeError, TypeError):
                    payload = {}
            if not isinstance(payload, dict):
                payload = {}

            if event["event_type"] == "routing_decision":
                metadata = payload.get("metadata", {})
                state.routing_decisions.append({
                    "from_node": metadata.get("from_node", ""),
                    "selected": metadata.get("selected", []),
                    "skipped": metadata.get("skipped", []),
                    "available": metadata.get("available", []),
                })

            elif event["event_type"] == "node_skipped":
                metadata = payload.get("metadata", {})
                state.skipped_nodes.append({
                    "branch": metadata.get("branch", ""),
                    "nodes": metadata.get("nodes", []),
                    "reason": "not_selected",
                })

        # Set revision to the maximum found anywhere (snapshot or events)
        state.revision = max(
            events[-1]["revision"] if events else 0,
            max(completed_steps.keys(), default=0),
        )

        return state

    # ── Side-effect ledger ─────────────────────────────────────────────

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

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        v3.5.0: lineage columns forwarded for retry-authorized execution.
        """
        self._side_effect_ledger.record_side_effect(
            run_id, step_id, node_id, side_effect_type, idempotency_key,
            branch_name, status, request_hash, response_hash,
            external_reference, retryable,
            parent_side_effect_key=parent_side_effect_key,
            root_side_effect_key=root_side_effect_key,
            retry_ordinal=retry_ordinal,
            recovery_decision_id=recovery_decision_id,
        )

    def start_side_effect_with_capsule(
        self,
        run_id: str,
        step_id: int,
        node_id: str,
        side_effect_type: str,
        idempotency_key: str,
        request_hash: str,
        capsule_operation: dict[str, Any],
        *,
        operation_name: str = "",
        adapter_id: str = "",
        adapter_version: str = "",
        node_version: str = "",
        contract_id: str = "",
        contract_version: str = "",
        original_invocation_id: str = "",
        capsule_id: str | None = None,
        external_idempotency_key_reference: str | None = None,
        payload_sensitivity: str = "standard",
        kek: bytes | None = None,
    ) -> str:
        """v3.5.0: Authoritative operation for starting a governed side effect.

        Atomically persists a replay capsule AND transitions the side-effect
        row to 'started' in ONE SQLite transaction (INV-004). If capsule
        construction or persistence fails, the side effect does NOT become
        started.

        This is the sole production path to 'started'. Both _journal_one paths
        (existing-planned-update and new-row-insert) route through this method.

        ChatGPT guardrail: the transaction establishes:
        - side-effect identity (insert or update to started)
        - encrypted capsule persisted in side_effect_replay_capsules
        - capsule_status = 'available' on the side-effect row
        - started lifecycle state
        All committed before execution approaches the adapter boundary.

        Args:
            capsule_operation: the canonical operation dict (e.g.
                {terms, max_results, filters, adapter} for search).
            kek: master key for DEK wrapping. If None, uses KekManager in
                local-dev mode. Production callers MUST supply the KEK.
            capsule_id: explicit capsule ID. If None, generated from content hash.

        Returns the capsule_id.
        Raises CapsuleEncryptionError on encryption/key failures.
        Raises SideEffectTransitionError if the row cannot transition to started.
        """
        from nodechain.core.side_effect_utils import (
            MAX_CAPSULE_SIZE_BYTES,
            canonicalize_capsule_payload,
            compute_canonical_request_digest,
            make_capsule_id,
            capsules_logically_equivalent,
        )
        from nodechain.core.capsule_crypto import (
            KekManager,
            encrypt_capsule_payload,
        )

        # 1. Canonicalize and validate capsule payload OUTSIDE the transaction.
        canonical_bytes = canonicalize_capsule_payload(capsule_operation)
        if len(canonical_bytes) > MAX_CAPSULE_SIZE_BYTES:
            raise ValueError(
                f"REPLAY_CAPSULE_OVERSIZED: canonical payload is "
                f"{len(canonical_bytes)} bytes (max {MAX_CAPSULE_SIZE_BYTES})"
            )
        canonical_digest = compute_canonical_request_digest(canonical_bytes)

        # 2. Get or create the per-run DEK.
        # v3.5.1 (#8) blocker A: resolve the KEK from the injected manager
        # (composition-root-controlled mode). The manager was constructed at
        # the composition boundary (StateManager init); no env read happens
        # inside this persistence path.
        if kek is None:
            kek = self._kek_manager.get_kek()
        dek, key_version = self._run_key_store.get_or_create_run_dek(run_id, kek)

        # 3. Generate capsule ID if not provided.
        # ChatGPT revised T6 blocker 3: attempt-scoped ID, not content-only.
        # Same operation under different runs/keys → different capsule IDs.
        # Changed operation under same attempt → same ID, different digest → conflict.
        # ChatGPT T6 re-review fix 4: explicit capsule_id must match the
        # attempt-scoped derivation — no cross-attempt aliasing.
        expected_id = make_capsule_id(run_id, idempotency_key)
        if capsule_id is None:
            capsule_id = expected_id
        elif capsule_id != expected_id:
            raise SideEffectRecoveryError(
                f"Explicit capsule_id {capsule_id} does not match attempt-scoped "
                f"derivation {expected_id}. Cross-attempt capsule aliasing is "
                f"not permitted.",
                code="CAPSULE_ID_SCOPE_VIOLATION",
            )

        # 4. Encrypt capsule payload.
        ciphertext, nonce = encrypt_capsule_payload(
            dek, canonical_bytes,
            run_id=run_id,
            capsule_id=capsule_id,
            side_effect_key=idempotency_key,
            capsule_schema_version=1,
            canonicalization_version="1",
        )

        # 5. Build source binding JSON.
        source_binding = {
            "node_id": node_id,
            "node_version": node_version,
            "contract_id": contract_id,
            "contract_version": contract_version,
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "operation_name": operation_name,
        }
        import json as _json
        source_binding_json = _json.dumps(source_binding, sort_keys=True)

        now = datetime.now(timezone.utc).isoformat()

        # 6. Atomic transaction: persist capsule + transition side effect.
        with sqlite3.connect(self.db_path) as conn:
            # Check if the side-effect row exists
            existing = conn.execute(
                """SELECT status, capsule_status FROM side_effect_ledger
                   WHERE run_id = ? AND idempotency_key = ?""",
                (run_id, idempotency_key),
            ).fetchone()

            if existing is not None:
                ex_status, ex_capsule_status = existing
                if ex_status == "started" and ex_capsule_status == "available":
                    # ChatGPT revised T6 blocker 2: load and compare the persisted
                    # capsule before returning. Do NOT silently accept a different
                    # operation under the same key.
                    # ChatGPT T6 3rd re-review fix 3: use shared equivalence function.
                    existing_cap = conn.execute(
                        """SELECT capsule_id, capsule_digest, source_binding_json,
                                  capsule_schema_version, canonicalization_version,
                                  payload_sensitivity, serialization_version,
                                  key_version
                           FROM side_effect_replay_capsules
                           WHERE run_id = ? AND side_effect_key = ?""",
                        (run_id, idempotency_key),
                    ).fetchone()
                    if existing_cap:
                        existing_dict = {
                            "capsule_digest": existing_cap[1],
                            "source_binding_json": existing_cap[2],
                            "capsule_schema_version": existing_cap[3],
                            "canonicalization_version": existing_cap[4],
                            "payload_sensitivity": existing_cap[5],
                            "serialization_version": existing_cap[6],
                            "key_version": existing_cap[7],
                        }
                        candidate_dict = {
                            "capsule_digest": canonical_digest,
                            "source_binding_json": source_binding_json,
                            "capsule_schema_version": 1,
                            "canonicalization_version": "1",
                            "payload_sensitivity": payload_sensitivity,
                            "serialization_version": "1",
                            "key_version": key_version,
                        }
                        if not capsules_logically_equivalent(existing_dict, candidate_dict):
                            raise SideEffectRecoveryError(
                                f"REPLAY_CAPSULE_CONFLICT: side effect "
                                f"{idempotency_key} is already started with a "
                                f"capsule that has different content. The original "
                                f"attempt's replay material must not be overwritten.",
                                code="REPLAY_CAPSULE_CONFLICT",
                            )
                        # Identical — return the PERSISTED capsule_id, not the
                        # newly computed one (they should match, but use the
                        # authoritative stored value).
                        return existing_cap[0]
                    # Capsule row missing but ledger says available — data
                    # inconsistency. Fail closed.
                    raise SideEffectRecoveryError(
                        f"CAPSULE_DATA_INCONSISTENT: side effect {idempotency_key} "
                        f"has capsule_status=available but no capsule row found.",
                        code="CAPSULE_DATA_INCONSISTENT",
                    )
                if ex_status == "planned":
                    # Transition planned → started + set capsule
                    allowed = self._side_effect_ledger.LEGAL_TRANSITIONS.get(
                        "planned", set(),
                    )
                    if "started" not in allowed:
                        raise SideEffectTransitionError(
                            f"Cannot transition planned→started for {idempotency_key}"
                        )
                elif ex_status in ("completed", "failed", "unknown", "retry_authorized"):
                    raise SideEffectTransitionError(
                        f"Cannot start side effect in terminal/state-locked status "
                        f"'{ex_status}' for {idempotency_key}"
                    )
                # Persist capsule (ChatGPT revised T6: never INSERT OR REPLACE —
                # capsules bind future retries to the original operation and must
                # not be silently overwritten. Use ON CONFLICT DO NOTHING, then
                # load and compare. Fail closed on mismatch.)
                cursor = conn.execute(
                    """INSERT INTO side_effect_replay_capsules
                       (capsule_id, run_id, side_effect_key, capsule_digest,
                        capsule_schema_version, canonicalization_version,
                        encrypted_payload, nonce, key_version, payload_sensitivity,
                        serialization_version, source_binding_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '1', ?, ?)
                       ON CONFLICT(capsule_id) DO NOTHING""",
                    (capsule_id, run_id, idempotency_key, canonical_digest,
                     1, "1", ciphertext, nonce, key_version, payload_sensitivity,
                     source_binding_json, now),
                )
                if cursor.rowcount == 0:
                    # Capsule already exists — load and compare for convergence
                    # ChatGPT T6 4th re-review fix 2: use shared equivalence function
                    existing_cap = conn.execute(
                        """SELECT capsule_digest, source_binding_json,
                                  capsule_schema_version, canonicalization_version,
                                  payload_sensitivity, serialization_version,
                                  key_version
                           FROM side_effect_replay_capsules WHERE capsule_id = ?""",
                        (capsule_id,),
                    ).fetchone()
                    if existing_cap:
                        existing_dict = {
                            "capsule_digest": existing_cap[0],
                            "source_binding_json": existing_cap[1],
                            "capsule_schema_version": existing_cap[2],
                            "canonicalization_version": existing_cap[3],
                            "payload_sensitivity": existing_cap[4],
                            "serialization_version": existing_cap[5],
                            "key_version": existing_cap[6],
                        }
                        candidate_dict = {
                            "capsule_digest": canonical_digest,
                            "source_binding_json": source_binding_json,
                            "capsule_schema_version": 1,
                            "canonicalization_version": "1",
                            "payload_sensitivity": payload_sensitivity,
                            "serialization_version": "1",
                            "key_version": key_version,
                        }
                        if not capsules_logically_equivalent(existing_dict, candidate_dict):
                            raise SideEffectRecoveryError(
                                f"REPLAY_CAPSULE_CONFLICT: capsule {capsule_id} "
                                f"exists with different content. The original "
                                f"attempt's replay material must not be silently "
                                f"overwritten. If the operation changed, use a "
                                f"new attempt identity and side-effect key.",
                                code="REPLAY_CAPSULE_CONFLICT",
                            )
                        # Same content — converge silently
                # Transition to started + set capsule linkage
                conn.execute(
                    """UPDATE side_effect_ledger
                       SET status = 'started', capsule_id = ?,
                           capsule_status = 'available'
                       WHERE run_id = ? AND idempotency_key = ?""",
                    (capsule_id, run_id, idempotency_key),
                )
            else:
                # New row: insert directly at started with capsule
                # ChatGPT revised T6: ON CONFLICT DO NOTHING + compare, never
                # INSERT OR REPLACE (deletes + reinserts, destroying evidence).
                # Two conflict surfaces: capsule_id (PK) and (run_id, side_effect_key) (UNIQUE).
                try:
                    cursor = conn.execute(
                        """INSERT INTO side_effect_replay_capsules
                           (capsule_id, run_id, side_effect_key, capsule_digest,
                            capsule_schema_version, canonicalization_version,
                            encrypted_payload, nonce, key_version, payload_sensitivity,
                            serialization_version, source_binding_json, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '1', ?, ?)
                           ON CONFLICT(capsule_id) DO NOTHING""",
                        (capsule_id, run_id, idempotency_key, canonical_digest,
                         1, "1", ciphertext, nonce, key_version, payload_sensitivity,
                         source_binding_json, now),
                    )
                except sqlite3.IntegrityError:
                    # UNIQUE(run_id, side_effect_key) conflict — a capsule exists
                    # under the same key with different content (different capsule_id).
                    raise SideEffectRecoveryError(
                        f"REPLAY_CAPSULE_CONFLICT: a capsule already exists for "
                        f"(run_id={run_id}, side_effect_key={idempotency_key}) "
                        f"with different content. The original attempt's replay "
                        f"material must not be overwritten. If the operation "
                        f"changed, use a new attempt identity and side-effect key.",
                        code="REPLAY_CAPSULE_CONFLICT",
                    )
                if cursor.rowcount == 0:
                    # Capsule exists with same capsule_id — load and compare
                    # ChatGPT T6 4th re-review fix 2: use shared equivalence function
                    existing_cap = conn.execute(
                        """SELECT capsule_digest, source_binding_json,
                                  capsule_schema_version, canonicalization_version,
                                  payload_sensitivity, serialization_version,
                                  key_version
                           FROM side_effect_replay_capsules WHERE capsule_id = ?""",
                        (capsule_id,),
                    ).fetchone()
                    if existing_cap:
                        existing_dict = {
                            "capsule_digest": existing_cap[0],
                            "source_binding_json": existing_cap[1],
                            "capsule_schema_version": existing_cap[2],
                            "canonicalization_version": existing_cap[3],
                            "payload_sensitivity": existing_cap[4],
                            "serialization_version": existing_cap[5],
                            "key_version": existing_cap[6],
                        }
                        candidate_dict = {
                            "capsule_digest": canonical_digest,
                            "source_binding_json": source_binding_json,
                            "capsule_schema_version": 1,
                            "canonicalization_version": "1",
                            "payload_sensitivity": payload_sensitivity,
                            "serialization_version": "1",
                            "key_version": key_version,
                        }
                        if not capsules_logically_equivalent(existing_dict, candidate_dict):
                            raise SideEffectRecoveryError(
                                f"REPLAY_CAPSULE_CONFLICT: capsule {capsule_id} "
                                f"exists with different content. Cannot overwrite "
                                f"original attempt's replay material.",
                                code="REPLAY_CAPSULE_CONFLICT",
                            )
                # Insert side-effect row at started
                conn.execute(
                    """INSERT INTO side_effect_ledger
                       (run_id, step_id, node_id, side_effect_type,
                        idempotency_key, status, request_hash, retryable,
                        timestamp, capsule_id, capsule_status)
                       VALUES (?, ?, ?, ?, ?, 'started', ?, 1, ?, ?, 'available')""",
                    (run_id, step_id, node_id, side_effect_type,
                     idempotency_key, request_hash, now, capsule_id),
                )

        return capsule_id

    def update_side_effect_status(
        self,
        run_id: str,
        idempotency_key: str,
        status: str,
        response_hash: str | None = None,
        external_reference: str | None = None,
    ) -> None:
        """Update a side effect's status after completion/failure.

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        """
        self._side_effect_ledger.update_side_effect_status(
            run_id, idempotency_key, status, response_hash, external_reference,
        )

    def get_side_effects(self, run_id: str) -> list[dict]:
        """Get all side effects for a run.

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        """
        return self._side_effect_ledger.get_side_effects(run_id)

    def get_side_effect_by_key(self, run_id: str, idempotency_key: str) -> dict | None:
        """Get a specific side effect by its idempotency key.

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        """
        return self._side_effect_ledger.get_side_effect_by_key(run_id, idempotency_key)

    # ── v3.5.0: Recovery-only child transition passthroughs (INV-003, INV-011) ──

    def claim_recovery_attempt(self, run_id: str, child_key: str, execution_claim_id: str, action_id: str) -> str:
        """Delegate to SideEffectLedgerStore.claim_recovery_attempt."""
        return self._side_effect_ledger.claim_recovery_attempt(
            run_id, child_key, execution_claim_id, action_id,
        )

    def heartbeat_recovery_attempt(self, run_id: str, child_key: str, fencing_token: str) -> bool:
        """Delegate to SideEffectLedgerStore.heartbeat_recovery_attempt."""
        return self._side_effect_ledger.heartbeat_recovery_attempt(
            run_id, child_key, fencing_token,
        )

    def complete_recovery_attempt(
        self, run_id: str, child_key: str, fencing_token: str,
        response_hash: str | None = None,
    ) -> bool:
        """Delegate to SideEffectLedgerStore.complete_recovery_attempt."""
        return self._side_effect_ledger.complete_recovery_attempt(
            run_id, child_key, fencing_token, response_hash,
        )

    def fail_recovery_attempt(self, run_id: str, child_key: str, fencing_token: str) -> bool:
        """Delegate to SideEffectLedgerStore.fail_recovery_attempt."""
        return self._side_effect_ledger.fail_recovery_attempt(
            run_id, child_key, fencing_token,
        )

    def mark_recovery_dispatch_attempted(
        self, run_id: str, child_key: str, fencing_token: str,
    ) -> bool:
        """Delegate to SideEffectLedgerStore.mark_recovery_dispatch_attempted."""
        return self._side_effect_ledger.mark_recovery_dispatch_attempted(
            run_id, child_key, fencing_token,
        )

    def reclaim_expired_recovery_attempt(self, run_id: str, child_key: str) -> str | None:
        """Delegate to SideEffectLedgerStore.reclaim_expired_recovery_attempt."""
        return self._side_effect_ledger.reclaim_expired_recovery_attempt(
            run_id, child_key,
        )

    def reconcile_expired_recovery_children(self, run_id: str) -> list[dict]:
        """Delegate to SideEffectLedgerStore. v3.5.0 T7. EXPLICIT mutating op (#4)."""
        return self._side_effect_ledger.reconcile_expired_recovery_children(run_id)

    def scan_expired_recovery_children(self, run_id: str) -> list[dict]:
        """v3.5.1 (#4): PURE read delegation for expired-child detection."""
        return self._side_effect_ledger.scan_expired_recovery_children(run_id)

    # ── v3.5.0: recovery_execution_actions passthroughs (INV-018) ──

    def create_recovery_execution_action(
        self, action_id: str, operator_action_id: str | None, run_id: str,
        retry_attempt_key: str, execution_claim_id: str,
        metadata_json: str = "{}",
    ) -> None:
        """Delegate to SideEffectLedgerStore."""
        return self._side_effect_ledger.create_recovery_execution_action(
            action_id, operator_action_id, run_id, retry_attempt_key,
            execution_claim_id, metadata_json,
        )

    def update_recovery_execution_status(
        self, action_id: str, execution_status: str,
        *, outcome_code: str | None = None, execution_claim_id: str | None = None,
    ) -> bool:
        """Delegate to SideEffectLedgerStore."""
        return self._side_effect_ledger.update_recovery_execution_status(
            action_id, execution_status,
            outcome_code=outcome_code, execution_claim_id=execution_claim_id,
        )

    def finalize_recovery_execution_action(
        self, action_id: str, outcome: str, *, outcome_code: str | None = None,
    ) -> bool:
        """Delegate to SideEffectLedgerStore."""
        return self._side_effect_ledger.finalize_recovery_execution_action(
            action_id, outcome, outcome_code=outcome_code,
        )

    def get_recovery_execution_action(self, action_id: str) -> dict | None:
        """Delegate to SideEffectLedgerStore."""
        return self._side_effect_ledger.get_recovery_execution_action(action_id)

    def get_recovery_execution_actions(
        self, *, run_id: str | None = None, retry_attempt_key: str | None = None,
    ) -> list[dict]:
        """Delegate to SideEffectLedgerStore. v3.5.0 T7."""
        return self._side_effect_ledger.get_recovery_execution_actions(
            run_id=run_id, retry_attempt_key=retry_attempt_key,
        )

    def is_side_effect_completed(self, run_id: str, idempotency_key: str) -> bool:
        """Check if a side effect has been completed.

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        """
        return self._side_effect_ledger.is_side_effect_completed(run_id, idempotency_key)

    def get_side_effects_by_status(self, run_id: str, status: str) -> list[dict]:
        """Get side effects filtered by status.

        v2.83: delegates to SideEffectLedgerStore. Behavior unchanged.
        """
        return self._side_effect_ledger.get_side_effects_by_status(run_id, status)

    def resolve_side_effect_recovery_decision(
        self,
        run_id: str,
        idempotency_key: str,
        decision: str,
        *,
        reason: str = "",
        actor: str = "operator",
        response_hash: str = "",
        external_reference: str = "",
    ) -> str:
        """v3.3.0: resolve an unknown side effect via a governed recovery decision.

        Validates the decision value, checks evidence requirements, generates
        a unique decision_id, pre-checks the ledger row is unknown (for a clean
        error), then delegates to the atomic store method that records the
        decision + transitions the ledger in one transaction.

        Returns the resulting ledger status (completed/failed/retry_authorized).

        Raises SideEffectRecoveryError (or matching existing error style) with
        a precise code for each rejection case.
        """
        # 1. Validate decision value + map to target status.
        DECISION_TO_STATUS = {
            "verified_completed": "completed",
            "verified_failed": "failed",
            "mark_unrecoverable": "failed",
            "safe_to_retry": "retry_authorized",
        }
        if decision not in DECISION_TO_STATUS:
            raise SideEffectRecoveryError(
                f"Invalid recovery decision {decision!r}; expected one of "
                f"{sorted(DECISION_TO_STATUS)}",
                code="INVALID_RECOVERY_DECISION",
            )
        target_status = DECISION_TO_STATUS[decision]

        # 2. Validate evidence requirements.
        if decision == "verified_completed":
            if not external_reference and not response_hash:
                raise SideEffectRecoveryError(
                    "verified_completed requires external_reference or response_hash",
                    code="MISSING_REQUIRED_EVIDENCE",
                )
        else:  # verified_failed, mark_unrecoverable, safe_to_retry
            if not reason:
                raise SideEffectRecoveryError(
                    f"{decision} requires a reason",
                    code="MISSING_REQUIRED_EVIDENCE",
                )

        # 3. Pre-check the ledger row (clean error; the store re-checks atomically).
        existing = self._side_effect_ledger.get_side_effect_by_key(run_id, idempotency_key)
        if existing is None:
            raise SideEffectRecoveryError(
                f"No side-effect ledger row for idempotency_key={idempotency_key} "
                f"(run_id={run_id})",
                code="SIDE_EFFECT_NOT_FOUND",
            )
        prior_status = existing.get("status", "")
        if prior_status in ("completed", "failed"):
            raise SideEffectRecoveryError(
                f"Side effect {idempotency_key} already resolved (status={prior_status!r})",
                code="SIDE_EFFECT_ALREADY_RESOLVED",
            )
        if prior_status != "unknown":
            raise SideEffectRecoveryError(
                f"Side effect {idempotency_key} has status {prior_status!r}, not 'unknown'",
                code="SIDE_EFFECT_NOT_UNKNOWN",
            )

        # 4. Generate decision_id + build the decision dict.
        decision_id = f"rec:{uuid.uuid4()}"
        decision_record = {
            "decision_id": decision_id,
            "run_id": run_id,
            "idempotency_key": idempotency_key,
            "node_id": existing.get("node_id", ""),
            "step_id": existing.get("step_id"),
            "side_effect_type": existing.get("side_effect_type", ""),
            "prior_status": "unknown",
            "decision": decision,
            "actor": actor,
            "reason": reason,
            "external_reference": external_reference,
            "metadata_json": "",
            "retention_status": "active",
        }

        # 5. Delegate to the atomic store method.
        self._side_effect_ledger.resolve_side_effect_recovery_decision_transactional(
            run_id=run_id,
            idempotency_key=idempotency_key,
            decision=decision_record,
            target_status=target_status,
            response_hash=response_hash or None,
            external_reference=external_reference or None,
        )

        return target_status
