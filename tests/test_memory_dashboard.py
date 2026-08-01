"""v2.30.0 — Memory Governance Dashboard.

Verifies that collect_memory_status derives 9 counters from the durable
memory_decisions table, that MEM-001..005 health rules fire from real data,
and that MEM-005 (ChromaDB health) is correctly unavailable.
"""

from __future__ import annotations

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager
from nodechain.cli.dashboard import collect_memory_status


def _record(sm, *, decision="allow", write_ref="mem_x", rule_id="memory.allow_write",
            md_id="md1", run_id="r1"):
    sm.record_memory_decision({
        "memory_decision_id": md_id, "run_id": run_id, "chain_id": "c",
        "step_id": 11, "node_id": "memory_write_decision",
        "candidate_id": "c1", "subject": "s", "subject_digest": "sd",
        "candidate_digest": "cd", "confidence": 0.9, "sensitivity": "LOW",
        "policy_id": "research.memory_write.v1", "rule_id": rule_id,
        "decision": decision, "reason_code": "", "write_ref": write_ref,
        "created_at": "2026-06-20T01:00:00+00:00", "retention_status": "active",
    })


# ── Counter derivation ───────────────────────────────────────────────────────


class TestCounterDerivation:
    def test_all_counters_zero_on_empty_db(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "empty.db"))
        r = collect_memory_status(state_manager=sm)
        assert r["memory_total_decisions"] == 0
        assert r["memory_allowed_count"] == 0
        assert r["memory_denied_count"] == 0

    def test_allowed_with_write_ref(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "ok.db"))
        _record(sm, decision="allow", write_ref="mem_abc")
        r = collect_memory_status(state_manager=sm)
        assert r["memory_allowed_count"] == 1
        assert r["memory_committed_write_count"] == 1
        assert r["memory_uncommitted_allowed_count"] == 0

    def test_allowed_without_write_ref(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "unc.db"))
        _record(sm, decision="allow", write_ref="")
        r = collect_memory_status(state_manager=sm)
        assert r["memory_uncommitted_allowed_count"] == 1
        assert r["memory_committed_write_count"] == 0

    def test_denied_low_confidence(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "lc.db"))
        _record(sm, decision="deny", write_ref="", rule_id="memory.block_low_confidence")
        r = collect_memory_status(state_manager=sm)
        assert r["memory_denied_count"] == 1
        assert r["memory_denied_low_confidence_count"] == 1

    def test_denied_high_sensitivity(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "hs.db"))
        _record(sm, decision="deny", write_ref="", rule_id="memory.block_high_sensitivity")
        r = collect_memory_status(state_manager=sm)
        assert r["memory_denied_high_sensitivity_count"] == 1

    def test_skip_counted(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "sk.db"))
        _record(sm, decision="skip", write_ref="")
        r = collect_memory_status(state_manager=sm)
        assert r["memory_skipped_count"] == 1

    def test_error_counted(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "err.db"))
        _record(sm, decision="error", write_ref="")
        r = collect_memory_status(state_manager=sm)
        assert r["memory_error_count"] == 1

    def test_chromadb_health_unavailable(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "ch.db"))
        r = collect_memory_status(state_manager=sm)
        assert r["chromadb_health_available"] is False
        assert r["chromadb_health_source"] == "excluded_network_dependency"


# ── Health rule firing ───────────────────────────────────────────────────────


class TestHealthRuleFiring:
    def test_mem001_fires_on_errors(self, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "e.db"))
        _record(sm, decision="error", write_ref="", md_id="e1")
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "e.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "MEM-001" in fired

    def test_mem002_fires_on_uncommitted_allowed(self, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "u.db"))
        _record(sm, decision="allow", write_ref="", md_id="u1")
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "u.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "MEM-002" in fired
        # MEM-002 is CRITICAL
        mem002 = [i for i in data["issues"] if i["rule_id"] == "MEM-002"][0]
        assert mem002["severity"] == "critical"

    def test_mem003_fires_on_high_sensitivity_denied(self, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "hs.db"))
        _record(sm, decision="deny", write_ref="",
                rule_id="memory.block_high_sensitivity", md_id="hs1")
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "hs.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "MEM-003" in fired

    def test_mem005_never_fires(self, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "m5.db"))
        _record(sm, decision="error", write_ref="", md_id="m1")
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "m5.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        fired = {i["rule_id"] for i in data["issues"]}
        assert "MEM-005" not in fired

    def test_clean_memory_does_not_fire_mem_rules(self, tmp_path, monkeypatch):
        sm = StateManager(db_path=str(tmp_path / "clean.db"))
        _record(sm, decision="allow", write_ref="mem_ok", md_id="ok1")
        monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "clean.db"))
        from nodechain.cli.dashboard_health import collect_dashboard_v2
        data = collect_dashboard_v2()
        mem_fired = {i["rule_id"] for i in data["issues"] if i["rule_id"].startswith("MEM")}
        assert mem_fired == set()
