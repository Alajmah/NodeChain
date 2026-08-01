"""v3.5.0 Task 1 tests — Schema migration, legacy classification, dead transition.

Tests the schema changes that land in Task 1:
- Lineage columns added to side_effect_ledger
- New tables: side_effect_replay_capsules, recovery_execution_actions, run_encryption_keys
- Indexes: UNIQUE(run_id, recovery_decision_id), root+ordinal, parent
- retry_authorized→started removed from LEGAL_TRANSITIONS (INV-008)
- Legacy rows classified capsule_status=legacy_unavailable
- record_side_effect accepts lineage columns
- get_side_effects returns lineage columns

Protects: INV-001, INV-007, INV-008, INV-015
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from nodechain.core.state import StateManager
from nodechain.core.stores import SideEffectLedgerStore


# ── Fresh DB schema tests ─────────────────────────────────────────────


class TestFreshSchemaHasV35Columns:
    """Fresh databases get all v3.5 columns and tables on init."""

    def test_side_effect_ledger_has_lineage_columns(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(side_effect_ledger)")}
        for expected in [
            "parent_side_effect_key", "root_side_effect_key", "retry_ordinal",
            "recovery_decision_id", "capsule_id", "capsule_status",
            "execution_claim_id", "dispatch_attempted_at",
            "claim_acquired_at", "claim_expires_at",
        ]:
            assert expected in cols, f"missing v3.5 lineage column: {expected}"

    def test_capsule_table_exists(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        assert "side_effect_replay_capsules" in tables

    def test_recovery_execution_actions_table_exists(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        assert "recovery_execution_actions" in tables

    def test_run_encryption_keys_table_exists(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        assert "run_encryption_keys" in tables


class TestLineageIndexes:
    """Lineage indexes are created on fresh DBs."""

    def test_recovery_decision_unique_index(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            indexes = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='side_effect_ledger'"
            )}
        assert "idx_se_recovery_decision" in indexes

    def test_root_ordinal_index(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            indexes = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='side_effect_ledger'"
            )}
        assert "idx_se_root_ordinal" in indexes

    def test_parent_index(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "fresh.db"))
        with sqlite3.connect(sm.db_path) as conn:
            indexes = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='side_effect_ledger'"
            )}
        assert "idx_se_parent" in indexes


# ── Legacy DB migration tests ─────────────────────────────────────────


class TestLegacyDatabaseMigration:
    """Pre-v3.5 databases upgrade in place with ALTER TABLE."""

    def _create_v34_db(self, db_path: str):
        """Create a DB that looks like a pre-v3.5 database (no lineage columns)."""
        with sqlite3.connect(db_path) as conn:
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
                CREATE TABLE IF NOT EXISTS chain_states (
                    run_id TEXT PRIMARY KEY, state_json TEXT,
                    revision INTEGER, updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS state_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT, revision INTEGER, event_type TEXT,
                    node_id TEXT, step_id INTEGER, payload TEXT, timestamp TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS invocation_ledger (
                    run_id TEXT, step_id INTEGER, node_id TEXT, branch_name TEXT,
                    status TEXT, output_hash TEXT, timestamp TEXT,
                    PRIMARY KEY (run_id, step_id)
                )
            """)
            # Insert a legacy retry_authorized row (from v3.3 path)
            conn.execute("""
                INSERT INTO side_effect_ledger
                (run_id, step_id, node_id, side_effect_type, idempotency_key,
                 status, request_hash, retryable, timestamp)
                VALUES ('r1', 1, 'search_tool', 'external_call',
                        'se:legacy-1', 'retry_authorized', 'rh-old', 1, '2026-07-01T00:00:00Z')
            """)

    def test_v34_db_migrates_lineage_columns(self, tmp_path):
        """ALTER TABLE adds lineage columns to pre-existing DB."""
        db_path = str(tmp_path / "v34.db")
        self._create_v34_db(db_path)
        # Now init StateManager — triggers migration
        sm = StateManager(db_path=db_path)
        with sqlite3.connect(db_path) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(side_effect_ledger)")}
        for expected in [
            "parent_side_effect_key", "root_side_effect_key", "retry_ordinal",
            "recovery_decision_id", "capsule_id", "capsule_status",
            "execution_claim_id", "dispatch_attempted_at",
        ]:
            assert expected in cols, f"migration failed to add column: {expected}"

    def test_v34_legacy_row_classified_legacy_unavailable(self, tmp_path):
        """Pre-existing retry_authorized rows get capsule_status=legacy_unavailable."""
        db_path = str(tmp_path / "v34.db")
        self._create_v34_db(db_path)
        sm = StateManager(db_path=db_path)
        se = sm.get_side_effect_by_key("r1", "se:legacy-1")
        assert se is not None
        assert se["status"] == "retry_authorized"
        assert se["capsule_status"] == "legacy_unavailable", (
            "legacy rows must be classified legacy_unavailable (INV-015)"
        )
        assert se["parent_side_effect_key"] is None
        assert se["root_side_effect_key"] is None
        assert se["retry_ordinal"] == 0

    def test_v34_db_gets_v35_tables(self, tmp_path):
        """New tables created on migrated DB."""
        db_path = str(tmp_path / "v34.db")
        self._create_v34_db(db_path)
        sm = StateManager(db_path=db_path)
        with sqlite3.connect(db_path) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        assert "side_effect_replay_capsules" in tables
        assert "recovery_execution_actions" in tables
        assert "run_encryption_keys" in tables


# ── Dead transition removal (INV-008) ─────────────────────────────────


class TestDeadTransitionRemoved:
    """retry_authorized→started is rejected after v3.5."""

    def test_store_rejects_retry_authorized_to_started(self, tmp_path):
        store = SideEffectLedgerStore(str(tmp_path / "dt.db"))
        # Initialize the DB via StateManager first (creates schema)
        StateManager(db_path=str(tmp_path / "dt.db"))
        assert not store.validate_side_effect_transition("retry_authorized", "started"), (
            "INV-008: retry_authorized→started must be rejected"
        )

    def test_state_manager_rejects_retry_authorized_to_started(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "dt.db"))
        assert not sm.validate_side_effect_transition("retry_authorized", "started"), (
            "INV-008: retry_authorized→started must be rejected via StateManager"
        )

    def test_retry_authorized_is_terminal_for_transition_purposes(self, tmp_path):
        """retry_authorized has no legal outgoing transitions — it's terminal
        for this row (INV-008). The row stays as permanent history."""
        store = SideEffectLedgerStore(str(tmp_path / "dt.db"))
        StateManager(db_path=str(tmp_path / "dt.db"))
        for target in ["started", "completed", "failed", "unknown", "planned"]:
            assert not store.validate_side_effect_transition("retry_authorized", target), (
                f"retry_authorized→{target} must be rejected (terminal for this row)"
            )


# ── Lineage column round-trip (INV-001) ──────────────────────────────


class TestLineageColumnRoundTrip:
    """record_side_effect accepts lineage columns; get_side_effects returns them."""

    def test_record_with_lineage_columns(self, tmp_path):
        """A child retry attempt row can be recorded with lineage metadata."""
        sm = StateManager(db_path=str(tmp_path / "rt.db"))
        sm.record_side_effect(
            run_id="r1", step_id=2, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="retry:child-1",
            status="planned",
            request_hash="rh-target",
            parent_side_effect_key="se:original-1",
            root_side_effect_key="se:original-1",
            retry_ordinal=1,
            recovery_decision_id="rd-v35-001",
        )
        se = sm.get_side_effect_by_key("r1", "retry:child-1")
        assert se is not None
        assert se["parent_side_effect_key"] == "se:original-1"
        assert se["root_side_effect_key"] == "se:original-1"
        assert se["retry_ordinal"] == 1
        assert se["recovery_decision_id"] == "rd-v35-001"

    def test_original_row_has_null_lineage(self, tmp_path):
        """Original (non-retry) rows have NULL lineage and ordinal 0."""
        sm = StateManager(db_path=str(tmp_path / "rt.db"))
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="se:original-1",
            status="started", request_hash="rh-1",
        )
        se = sm.get_side_effect_by_key("r1", "se:original-1")
        assert se["parent_side_effect_key"] is None
        assert se["root_side_effect_key"] is None
        assert se["retry_ordinal"] == 0
        assert se["recovery_decision_id"] is None

    def test_recovery_decision_unique_constraint(self, tmp_path):
        """UNIQUE(run_id, recovery_decision_id) prevents two children from
        the same decision (INV-001, INV-002)."""
        sm = StateManager(db_path=str(tmp_path / "uc.db"))
        # First child with this decision
        sm.record_side_effect(
            run_id="r1", step_id=2, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="retry:child-a",
            status="planned",
            recovery_decision_id="rd-shared",
        )
        # Second child with the same decision must be rejected
        with pytest.raises(sqlite3.IntegrityError):
            sm.record_side_effect(
                run_id="r1", step_id=3, node_id="search_tool",
                side_effect_type="external_call",
                idempotency_key="retry:child-b",
                status="planned",
                recovery_decision_id="rd-shared",
            )
