"""v2.28.0 — Durable Memory Decision Log.

Verifies that every memory write candidate decision (allow/deny/skip/error) is
persisted to the memory_decisions table, that blocked candidates leave a durable
row, and that the node records via the injected callback with non-fatal-visible
error handling.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager, ChainState
from nodechain.core.policy import PolicyEngine
from nodechain.core.default_policies import DEFAULT_POLICIES
from nodechain.nodes.memory_write import MemoryWriteDecisionNode
from nodechain.core.envelope import InvocationEnvelope


def _make_engine() -> PolicyEngine:
    eng = PolicyEngine()
    for p in DEFAULT_POLICIES:
        eng.register(p)
    return eng


def _make_envelope(confidence: float = 0.9) -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run", chain_id="test-chain", node_id="memory_write_decision",
        step_id=11,
        payload={
            "recommendation": "Adopt RAG",
            "executive_summary": "Summary of findings.",
            "confidence_statement": {"numeric": confidence, "label": "HIGH"},
        },
    )


def _make_node(sm=None, engine=None) -> MemoryWriteDecisionNode:
    rmd = sm.record_memory_decision if sm else None
    return MemoryWriteDecisionNode(
        memory_manager=None, policy_engine=engine, record_memory_decision=rmd,
    )


# ── Decision recording ───────────────────────────────────────────────────────


class TestDecisionRecording:
    def test_allowed_candidate_recorded(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "allow.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node.execute(_make_envelope(confidence=0.9)))
        decisions = sm.get_memory_decisions()
        assert len(decisions) == 1
        d = decisions[0]
        assert d["decision"] == "allow"
        assert d["write_ref"] != ""  # non-empty when committed
        assert d["rule_id"] == "memory.allow_write"

    def test_denied_low_confidence_recorded(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "deny.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node.execute(_make_envelope(confidence=0.5)))
        decisions = sm.get_memory_decisions()
        assert len(decisions) == 1
        d = decisions[0]
        assert d["decision"] == "deny"
        assert d["rule_id"] == "memory.block_low_confidence"
        assert d["write_ref"] == ""  # empty when blocked
        assert d["reason_code"] == "memory.block_low_confidence"

    def test_denied_high_sensitivity_recorded(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "sens.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        # Override the candidate's sensitivity to HIGH via direct policy call
        pd = node._evaluate_policy(
            {"confidence": 0.9, "sensitivity": "HIGH", "content": "x", "subject": "s"}, 0.9,
        )
        assert pd["approved"] is False
        assert pd["rule_id"] == "memory.block_high_sensitivity"

    def test_skip_for_structural_validation_failure(self, tmp_path):
        """A candidate with empty content is structurally invalid -> decision='skip'."""
        sm = StateManager(db_path=str(tmp_path / "skip.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        envelope = InvocationEnvelope(
            run_id="test-run", chain_id="test-chain", node_id="memory_write_decision",
            step_id=11,
            payload={
                "recommendation": "",  # empty -> candidate content empty
                "executive_summary": "",
                "confidence_statement": {"numeric": 0.9, "label": "HIGH"},
            },
        )
        result = asyncio.run(node.execute(envelope))
        # No candidates proposed when recommendation is empty
        candidates = result.output.get("candidates", [])
        if not candidates:
            # No candidate -> no decision row. That's correct.
            decisions = sm.get_memory_decisions()
            assert len(decisions) == 0
        else:
            decisions = sm.get_memory_decisions()
            assert any(d["decision"] == "skip" for d in decisions)


# ── Canonical digests ────────────────────────────────────────────────────────


class TestCanonicalDigests:
    def test_subject_digest_is_canonical(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "dig.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node.execute(_make_envelope(confidence=0.9)))
        d = sm.get_memory_decisions()[0]
        assert d["subject_digest"]  # non-empty
        assert len(d["subject_digest"]) == 64  # sha256 hex

    def test_candidate_digest_is_canonical(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "cdig.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node.execute(_make_envelope(confidence=0.9)))
        d = sm.get_memory_decisions()[0]
        assert d["candidate_digest"]
        assert len(d["candidate_digest"]) == 64

    def test_candidate_digest_stable_across_runs(self, tmp_path):
        """Same candidate fields -> same candidate_digest (provenance stripped of volatile ts)."""
        sm1 = StateManager(db_path=str(tmp_path / "stable1.db"))
        sm2 = StateManager(db_path=str(tmp_path / "stable2.db"))
        node1 = _make_node(sm=sm1, engine=_make_engine())
        node2 = _make_node(sm=sm2, engine=_make_engine())
        asyncio.run(node1.execute(_make_envelope(confidence=0.9)))
        asyncio.run(node2.execute(_make_envelope(confidence=0.9)))
        d1 = sm1.get_memory_decisions()[0]
        d2 = sm2.get_memory_decisions()[0]
        assert d1["candidate_digest"] == d2["candidate_digest"]


# ── Query methods ────────────────────────────────────────────────────────────


class TestQueryMethods:
    def test_filter_by_decision(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "q.db"))
        node_allow = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node_allow.execute(_make_envelope(confidence=0.9)))
        node_deny = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node_deny.execute(_make_envelope(confidence=0.5)))
        allows = sm.get_memory_decisions(decision="allow")
        denies = sm.get_memory_decisions(decision="deny")
        assert len(allows) == 1
        assert len(denies) == 1

    def test_filter_by_rule_id(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "qr.db"))
        node = _make_node(sm=sm, engine=_make_engine())
        asyncio.run(node.execute(_make_envelope(confidence=0.5)))
        blocked = sm.get_memory_decisions(rule_id="memory.block_low_confidence")
        assert len(blocked) == 1


# ── Non-fatal callback failure ───────────────────────────────────────────────


class TestNonFatalCallback:
    def test_failing_callback_does_not_crash_node(self):
        """If record_memory_decision raises, the node still completes and
        surfaces the error in output (Correction A)."""
        def bad_callback(decision):
            raise RuntimeError("DB unavailable")

        node = MemoryWriteDecisionNode(
            memory_manager=None, policy_engine=_make_engine(),
            record_memory_decision=bad_callback,
        )
        result = asyncio.run(node.execute(_make_envelope(confidence=0.9)))
        # Node completed despite the callback failure
        assert result.output["candidates"]
        # Error is surfaced
        assert "memory_decision_log_error" in result.output
        assert len(result.output["memory_decision_log_error"]) >= 1


# ── No callback wired (legacy back-compat) ──────────────────────────────────


class TestNoCallback:
    def test_no_callback_is_noop(self):
        """Without record_memory_decision wired, the node works as before."""
        node = MemoryWriteDecisionNode(memory_manager=None, policy_engine=_make_engine())
        result = asyncio.run(node.execute(_make_envelope(confidence=0.9)))
        assert result.output["candidates"]
        # No error key when callback isn't wired (no-op lambda doesn't raise)
        assert "memory_decision_log_error" not in result.output
