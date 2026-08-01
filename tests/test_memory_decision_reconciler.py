"""v2.29.0 — Memory Decision Reconciler.

Verifies that MEMORY_WRITE_ALLOWED/BLOCKED trace events bind to durable
memory_decisions rows (candidate_digest, write_ref, rule_id, decision).
The durable row is canonical; the trace is the audit projection.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler


def _make_trace(run_id, events=None):
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


def _allowed_event(run_id, step, metadata=None):
    return TraceEvent(
        run_id=run_id, chain_id="test-chain", node_id="memory_write_decision",
        step_id=step, event_type=EventType.MEMORY_WRITE_ALLOWED,
        actor=Actor.RUNTIME, decision="write_committed",
        metadata=metadata or {},
    )


def _blocked_event(run_id, step, metadata=None):
    return TraceEvent(
        run_id=run_id, chain_id="test-chain", node_id="memory_write_decision",
        step_id=step, event_type=EventType.MEMORY_WRITE_BLOCKED,
        actor=Actor.RUNTIME, decision="write_blocked",
        metadata=metadata or {},
    )


def _record_decision(sm, *, run_id, candidate_digest, decision="allow",
                     write_ref="mem_abc", rule_id="memory.allow_write",
                     policy_id="research.memory_write.v1", md_id="md1"):
    sm.record_memory_decision({
        "memory_decision_id": md_id, "run_id": run_id, "chain_id": "test-chain",
        "step_id": 11, "node_id": "memory_write_decision",
        "candidate_id": "c1", "subject": "s", "subject_digest": "sd",
        "candidate_digest": candidate_digest, "confidence": 0.9,
        "sensitivity": "LOW", "policy_id": policy_id, "rule_id": rule_id,
        "decision": decision, "reason_code": "",
        "write_ref": write_ref, "created_at": "2026-06-20T01:00:00+00:00",
        "retention_status": "active",
    })


# ── Clean binding ─────────────────────────────────────────────────────────────


class TestCleanBinding:
    def test_allowed_event_binds_to_allow_row(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "ok.db"))
        cd = "a" * 64
        _record_decision(sm, run_id="r1", candidate_digest=cd,
                         decision="allow", write_ref="mem_abc")
        trace = _make_trace("r1", [_allowed_event("r1", 11, metadata={
            "candidate_digest": cd, "write_ref": "mem_abc",
            "rule_id": "memory.allow_write",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        mem_errors = [i for i in report.errors if i.check.startswith("memory_")]
        assert mem_errors == [], f"unexpected errors: {mem_errors}"

    def test_blocked_event_binds_to_deny_row(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "deny.db"))
        cd = "b" * 64
        _record_decision(sm, run_id="r2", candidate_digest=cd,
                         decision="deny", write_ref="", rule_id="memory.block_low_confidence")
        trace = _make_trace("r2", [_blocked_event("r2", 11, metadata={
            "candidate_digest": cd, "rule_id": "memory.block_low_confidence",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        mem_errors = [i for i in report.errors if i.check.startswith("memory_")]
        assert mem_errors == [], f"unexpected errors: {mem_errors}"


# ── Missing / mismatch detection ─────────────────────────────────────────────


class TestMismatchDetection:
    def test_missing_durable_row_is_error(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "miss.db"))
        trace = _make_trace("r3", [_allowed_event("r3", 11, metadata={
            "candidate_digest": "c" * 64, "write_ref": "x",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_decision_log_missing" for i in report.errors)

    def test_decision_type_mismatch_is_error(self, tmp_path):
        """Trace says ALLOWED but durable row says deny."""
        sm = StateManager(db_path=str(tmp_path / "tm.db"))
        cd = "d" * 64
        _record_decision(sm, run_id="r4", candidate_digest=cd, decision="deny", write_ref="")
        trace = _make_trace("r4", [_allowed_event("r4", 11, metadata={
            "candidate_digest": cd, "write_ref": "x",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_decision_type_mismatch" for i in report.errors)

    def test_allow_with_empty_write_ref_is_error(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "wr.db"))
        cd = "e" * 64
        _record_decision(sm, run_id="r5", candidate_digest=cd, decision="allow", write_ref="")
        trace = _make_trace("r5", [_allowed_event("r5", 11, metadata={
            "candidate_digest": cd, "write_ref": "",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_decision_allow_missing_write_ref" for i in report.errors)

    def test_blocked_with_nonempty_write_ref_is_error(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "bwr.db"))
        cd = "f" * 64
        _record_decision(sm, run_id="r6", candidate_digest=cd, decision="deny", write_ref="mem_leak")
        trace = _make_trace("r6", [_blocked_event("r6", 11, metadata={
            "candidate_digest": cd,
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_decision_blocked_has_write_ref" for i in report.errors)

    def test_write_ref_mismatch_is_error(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "wrm.db"))
        cd = "g" * 64
        _record_decision(sm, run_id="r7", candidate_digest=cd, decision="allow", write_ref="mem_real")
        trace = _make_trace("r7", [_allowed_event("r7", 11, metadata={
            "candidate_digest": cd, "write_ref": "mem_fake",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_write_ref_mismatch" for i in report.errors)

    def test_rule_id_mismatch_is_error(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "rm.db"))
        cd = "h" * 64
        _record_decision(sm, run_id="r8", candidate_digest=cd,
                         decision="deny", write_ref="", rule_id="memory.block_low_confidence")
        trace = _make_trace("r8", [_blocked_event("r8", 11, metadata={
            "candidate_digest": cd, "rule_id": "memory.block_high_sensitivity",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_rule_id_mismatch" for i in report.errors)


# ── Targeted regression tests (the reviewer's checks 8-10) ────────────────────────


class TestTargetedPolicyBinding:
    def test_low_confidence_binds_to_block_low_confidence(self, tmp_path):
        """Implicit check 8: trace.rule_id == durable.rule_id == memory.block_low_confidence."""
        sm = StateManager(db_path=str(tmp_path / "lc.db"))
        cd = "i" * 64
        _record_decision(sm, run_id="r9", candidate_digest=cd,
                         decision="deny", write_ref="", rule_id="memory.block_low_confidence")
        trace = _make_trace("r9", [_blocked_event("r9", 11, metadata={
            "candidate_digest": cd, "rule_id": "memory.block_low_confidence",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        mem_errors = [i for i in report.errors if i.check.startswith("memory_")]
        assert mem_errors == []

    def test_high_sensitivity_binds_to_block_high_sensitivity(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "hs.db"))
        cd = "j" * 64
        _record_decision(sm, run_id="r10", candidate_digest=cd,
                         decision="deny", write_ref="", rule_id="memory.block_high_sensitivity")
        trace = _make_trace("r10", [_blocked_event("r10", 11, metadata={
            "candidate_digest": cd, "rule_id": "memory.block_high_sensitivity",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        mem_errors = [i for i in report.errors if i.check.startswith("memory_")]
        assert mem_errors == []

    def test_structural_skip_binds_as_skip_not_deny(self, tmp_path):
        """Check 10: structural validation failures bind as decision=skip."""
        sm = StateManager(db_path=str(tmp_path / "sk.db"))
        cd = "k" * 64
        _record_decision(sm, run_id="r11", candidate_digest=cd,
                         decision="skip", write_ref="", rule_id="",
                         policy_id="research.memory_write.v1")
        trace = _make_trace("r11", [_blocked_event("r11", 11, metadata={
            "candidate_digest": cd, "rule_id": "",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        # skip is a valid blocked decision — should NOT produce a type_mismatch
        type_errors = [i for i in report.errors if i.check == "memory_decision_type_mismatch"]
        assert type_errors == []


# ── Duplicate detection ──────────────────────────────────────────────────────


class TestDuplicateDetection:
    def test_equivalent_duplicates_are_warning(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "dup.db"))
        cd = "l" * 64
        _record_decision(sm, run_id="r12", candidate_digest=cd, md_id="md1")
        _record_decision(sm, run_id="r12", candidate_digest=cd, md_id="md2")
        trace = _make_trace("r12", [_allowed_event("r12", 11, metadata={
            "candidate_digest": cd, "write_ref": "mem_abc",
            "rule_id": "memory.allow_write",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_decision_duplicate" and i.severity == "warning"
                   for i in report.issues)

    def test_conflicting_duplicates_are_error(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "conf.db"))
        cd = "m" * 64
        _record_decision(sm, run_id="r13", candidate_digest=cd, md_id="md1",
                         decision="allow", write_ref="mem_abc")
        _record_decision(sm, run_id="r13", candidate_digest=cd, md_id="md2",
                         decision="deny", write_ref="")  # conflicts
        trace = _make_trace("r13", [_allowed_event("r13", 11, metadata={
            "candidate_digest": cd, "write_ref": "mem_abc",
        })])
        report = TraceReconciler(sm).reconcile(trace)
        assert any(i.check == "memory_decision_duplicate_conflict" for i in report.errors)


# ── Digest consistency between trace and durable row ─────────────────────────


class TestDigestConsistency:
    def test_same_digest_in_trace_and_durable(self, tmp_path):
        """The node-owned candidate_digest must be identical in both surfaces."""
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.nodes.memory_write import MemoryWriteDecisionNode
        from nodechain.core.envelope import InvocationEnvelope

        sm = StateManager(db_path=str(tmp_path / "dig.db"))
        eng = PolicyEngine()
        for p in DEFAULT_POLICIES:
            eng.register(p)
        node = MemoryWriteDecisionNode(
            policy_engine=eng, record_memory_decision=sm.record_memory_decision,
        )
        envelope = InvocationEnvelope(
            run_id="dig-run", chain_id="test", node_id="memory_write_decision",
            step_id=11,
            payload={
                "recommendation": "Test", "executive_summary": "Summary",
                "confidence_statement": {"numeric": 0.9, "label": "HIGH"},
            },
        )
        result = asyncio.run(node.execute(envelope))
        cand = result.output["candidates"][0]
        trace_digest = cand.get("candidate_digest", "")
        durable = sm.get_memory_decisions()[0]
        assert trace_digest == durable["candidate_digest"]
        assert trace_digest != ""
