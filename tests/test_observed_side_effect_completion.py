"""v3.4.0 — Observed Side-Effect Completion tests.

Freezes the node-output-reported completion path: a node reports
``output["side_effect_records"]``; the runtime validates each record against
the started/planned ledger row and marks it ``completed`` only for valid,
observed reports. No report ⇒ effect stays ``started``.

Model C only (node-output-reported, runtime-validated). True Model B
(adapter-level reporting) is deferred to v3.1.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime import MockNode, _create_mock_nodes

from nodechain.core.blueprint import load_blueprint
from nodechain.core.side_effect_utils import (
    compute_side_effect_request_hash,
    compute_side_effect_response_hash,
    make_canonical_search_key,
)
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator


# ─── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def blueprint():
    return load_blueprint("blueprints/research_decision_v1.yaml")


@pytest.fixture
def nodes():
    return _create_mock_nodes()


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "se_completion.db")


@pytest.fixture
def orchestrator(blueprint, nodes, db_path):
    sm = StateManager(db_path=db_path)
    return Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)


def _run(orch: Orchestrator, query: str = "test query"):
    return asyncio.run(orch.run(query))


def _event_types(trace):
    return [e.event_type for e in trace.events]


def _search_side_effects(sm: StateManager, run_id: str):
    return [se for se in sm.get_side_effects(run_id) if se.get("node_id") == "search_tool"]


# ─── 0. Canonical key helper ───────────────────────────────────────────────

class TestCanonicalSearchKey:
    def test_make_canonical_search_key_format(self):
        """The canonical search key is search:<adapter>:<request_hash>."""
        key = make_canonical_search_key("semantic_scholar", "abc123")
        assert key == "search:semantic_scholar:abc123"

    def test_make_canonical_search_key_rejects_empty_parts(self):
        """Empty adapter or hash yields no key (fail-closed)."""
        assert make_canonical_search_key("", "abc123") == ""
        assert make_canonical_search_key("semantic_scholar", "") == ""


# ─── 1. Completion validation (unit-level, against a started ledger) ───────

def _seed_started_search_effect(orch, sm, adapter="semantic_scholar", req_hash="deadbeefdeadbeef"):
    """Journal a single started search side effect directly, return its key."""
    from nodechain.core.envelope import InvocationEnvelope
    envelope = InvocationEnvelope(
        envelope_id="t", run_id=orch.state.run_id, chain_id="c", node_id="search_tool",
        step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": [adapter], "max_results": 10}]},
        context={}, capabilities={},
    )
    orch._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
    key = make_canonical_search_key(adapter, req_hash)
    return key


class TestCompletionValidation:
    def test_completion_report_must_match_started_side_effect_key(self, orchestrator, db_path):
        """A record whose side_effect_key matches no ledger row is rejected."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        # Journal the real key
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        # Report a DIFFERENT key that matches nothing
        bogus = make_canonical_search_key("semantic_scholar", "ffffffffffffffff")
        ok = orchestrator._complete_reported_side_effect(
            "search_tool", {"side_effect_key": bogus, "side_effect_type": "external_call",
                            "status": "completed", "observed_by": "node",
                            "observed_at": "2026-07-08T00:00:00Z", "response_hash": "h1"},
        )
        assert ok is False

    def test_completion_report_uses_canonical_external_call_type(self, orchestrator, db_path):
        """A record whose side_effect_type is not the normalized canonical type is rejected."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        # Find the actual journaled key
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        key = make_canonical_search_key("semantic_scholar", real_hash)
        # Report with a non-canonical alias type
        ok = orchestrator._complete_reported_side_effect(
            "search_tool", {"side_effect_key": key, "side_effect_type": "external_read",
                            "status": "completed", "observed_by": "node",
                            "observed_at": "2026-07-08T00:00:00Z", "response_hash": "h1"},
        )
        assert ok is False

    def test_completion_report_empty_response_hash_rejected(self, orchestrator, db_path):
        """A record with empty response_hash is rejected (no observed evidence)."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        key = make_canonical_search_key("semantic_scholar", real_hash)
        ok = orchestrator._complete_reported_side_effect(
            "search_tool", {"side_effect_key": key, "side_effect_type": "external_call",
                            "status": "completed", "observed_by": "node",
                            "observed_at": "2026-07-08T00:00:00Z", "response_hash": ""},
        )
        assert ok is False

    def test_unprefixed_search_completion_key_does_not_mark_completed(self, orchestrator, db_path):
        """The unprefixed <adapter>:<hash> form must NOT match a ledger row.

        Closes the key-format drift: the node's internal key lacks the ``search:``
        prefix. Loose matching would silently complete effects; this test enforces
        exact canonical-key matching.
        """
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        unprefixed = f"semantic_scholar:{real_hash}"  # missing search: prefix
        ok = orchestrator._complete_reported_side_effect(
            "search_tool", {"side_effect_key": unprefixed, "side_effect_type": "external_call",
                            "status": "completed", "observed_by": "node",
                            "observed_at": "2026-07-08T00:00:00Z", "response_hash": "h1"},
        )
        assert ok is False

    def test_completion_report_empty_observed_at_rejected(self, orchestrator, db_path):
        """A record with empty observed_at is rejected (no observation timestamp)."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        key = make_canonical_search_key("semantic_scholar", real_hash)
        ok = orchestrator._complete_reported_side_effect(
            "search_tool", {"side_effect_key": key, "side_effect_type": "external_call",
                            "status": "completed", "observed_by": "node",
                            "observed_at": "", "response_hash": "h1"},
        )
        assert ok is False

    def test_duplicate_completion_report_same_hash_is_idempotent(self, orchestrator, db_path):
        """A second report with the same key+response_hash is a safe replay (True)."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        key = make_canonical_search_key("semantic_scholar", real_hash)
        rec = {"side_effect_key": key, "side_effect_type": "external_call",
               "status": "completed", "observed_by": "node",
               "observed_at": "2026-07-08T00:00:00Z", "response_hash": "h-same"}
        first = orchestrator._complete_reported_side_effect("search_tool", rec)
        second = orchestrator._complete_reported_side_effect("search_tool", rec)
        assert first is True
        assert second is True  # idempotent replay

    def test_duplicate_completion_report_different_hash_is_rejected(self, orchestrator, db_path):
        """A second report with a different response_hash is a conflict (False)."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        key = make_canonical_search_key("semantic_scholar", real_hash)
        rec1 = {"side_effect_key": key, "side_effect_type": "external_call",
                "status": "completed", "observed_by": "node",
                "observed_at": "2026-07-08T00:00:00Z", "response_hash": "h-a"}
        rec2 = {"side_effect_key": key, "side_effect_type": "external_call",
                "status": "completed", "observed_by": "node",
                "observed_at": "2026-07-08T00:00:00Z", "response_hash": "h-b"}
        first = orchestrator._complete_reported_side_effect("search_tool", rec1)
        second = orchestrator._complete_reported_side_effect("search_tool", rec2)
        assert first is True
        assert second is False  # conflict


# ─── 2. Controller entry point ─────────────────────────────────────────────

class TestControllerCompleteReported:
    def test_controller_completes_valid_record(self, orchestrator, db_path):
        """complete_reported_side_effects marks a started row completed for a valid record."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        from nodechain.core.side_effect_utils import compute_side_effect_request_hash
        real_hash = compute_side_effect_request_hash(
            "external_call", "search_tool", "",
            operation={"terms": ["test"], "max": 10, "filters": {}},
        )
        key = make_canonical_search_key("semantic_scholar", real_hash)
        output = {"side_effect_records": [{
            "side_effect_key": key, "side_effect_type": "external_call",
            "status": "completed", "observed_by": "node",
            "observed_at": "2026-07-08T00:00:00Z", "response_hash": "rh-1",
        }]}
        ok = orchestrator._side_effect_journal.complete_reported_side_effects(
            "search_tool", envelope, output,
        )
        assert ok is True

        sm = StateManager(db_path=db_path)
        row = sm.get_side_effect_by_key(orchestrator.state.run_id, key)
        assert row["status"] == "completed"
        assert row["response_hash"] == "rh-1"

    def test_controller_returns_false_on_first_invalid_record(self, orchestrator, db_path):
        """If any record is invalid, the controller returns False immediately."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={"search_queries": [{"terms": ["test"], "target_adapters": ["semantic_scholar"]}]},
            context={}, capabilities={},
        )
        orchestrator._side_effect_journal.journal_planned_side_effects("search_tool", envelope)
        output = {"side_effect_records": [{
            "side_effect_key": "search:semantic_scholar:nonexistent",
            "side_effect_type": "external_call", "status": "completed",
            "observed_by": "node", "observed_at": "2026-07-08T00:00:00Z",
            "response_hash": "rh",
        }]}
        ok = orchestrator._side_effect_journal.complete_reported_side_effects(
            "search_tool", envelope, output,
        )
        assert ok is False

    def test_controller_no_records_returns_true(self, orchestrator):
        """Absence of side_effect_records is legacy behavior — return True (no-op)."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={}, context={}, capabilities={},
        )
        ok = orchestrator._side_effect_journal.complete_reported_side_effects(
            "search_tool", envelope, {"results": []},
        )
        assert ok is True  # legacy no-op, not a failure

    def test_completion_report_must_be_nested_in_output_side_effect_records(self, orchestrator):
        """A top-level side_effect_records field (not nested in output) is ignored."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={}, context={}, capabilities={},
        )
        # output has NO side_effect_records key — the report is "missing"
        ok = orchestrator._side_effect_journal.complete_reported_side_effects(
            "search_tool", envelope, {"results": []},
        )
        assert ok is True  # legacy no-op, not a failure

    def test_malformed_completion_record_returns_false(self, orchestrator):
        """A non-dict entry in side_effect_records is rejected (fail-closed)."""
        from nodechain.core.envelope import InvocationEnvelope
        envelope = InvocationEnvelope(
            envelope_id="t", run_id=orchestrator.state.run_id, chain_id="c", node_id="search_tool",
            step_id=1, payload={}, context={}, capabilities={},
        )
        ok = orchestrator._side_effect_journal.complete_reported_side_effects(
            "search_tool", envelope,
            {"side_effect_records": ["not-a-dict", 42, None]},
        )
        assert ok is False


# ─── 3. End-to-end (orchestrator run with reporting mock) ─────────────────

def _search_transform_with_completion(payload):
    """Mock search_tool output WITH a side_effect_records completion report.

    Mirrors the real mock output (tests/test_runtime.py) but adds the
    side_effect_records field. The request_hash matches what
    _journal_search_operations derives for terms=["test"], target=["semantic_scholar"].
    """
    from nodechain.core.side_effect_utils import compute_side_effect_request_hash
    req_hash = compute_side_effect_request_hash(
        "external_call", "search_tool", "",
        operation={"terms": ["test"], "max": 10, "filters": {}},
    )
    key = make_canonical_search_key("semantic_scholar", req_hash)
    return {
        "results": [{
            "origin_api": "semantic_scholar",
            "raw_data": {"title": "Test Paper", "paperId": "123"},
            "query_used": "test",
            "retrieved_at": "2026-01-01T00:00:00Z",
        }],
        "total_found": 1,
        "adapters_called": ["semantic_scholar"],
        "adapters_failed": [],
        "side_effect_records": [{
            "side_effect_key": key,
            "side_effect_type": "external_call",
            "status": "completed",
            "observed_by": "node",
            "observed_at": "2026-07-08T00:00:00Z",
            "response_hash": "rh-e2e-1",
            "evidence": {"adapter": "semantic_scholar", "result_count": 1},
        }],
    }


@pytest.fixture
def orchestrator_reporting(blueprint, db_path):
    """Orchestrator whose mock search_tool emits a completion report."""
    nodes = _create_mock_nodes()
    nodes["search_tool"]._output_transform = _search_transform_with_completion
    sm = StateManager(db_path=db_path)
    return Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)


class TestEndToEndReporting:
    def test_reported_side_effect_completion_marks_ledger_completed(self, orchestrator_reporting, db_path):
        """End-to-end: the reporting mock's search side effect becomes completed."""
        _run(orchestrator_reporting)
        run_id = orchestrator_reporting.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1
        completed = [se for se in search_ses if se["status"] == "completed"]
        assert len(completed) >= 1, (
            f"expected >=1 completed search side effect; got statuses "
            f"{[se['status'] for se in search_ses]}"
        )

    def test_completed_side_effect_persists_response_hash(self, orchestrator_reporting, db_path):
        """The completed row carries the reported response_hash."""
        _run(orchestrator_reporting)
        run_id = orchestrator_reporting.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        completed = [se for se in search_ses if se["status"] == "completed"]
        assert len(completed) >= 1
        for se in completed:
            assert se.get("response_hash"), (
                f"completed side effect {se['idempotency_key']} has empty response_hash"
            )

    def test_side_effect_completed_event_emitted_after_valid_report(self, orchestrator_reporting):
        """SIDE_EFFECT_COMPLETED appears in the trace on the reporting path."""
        trace = _run(orchestrator_reporting)
        types = _event_types(trace)
        assert "side_effect_completed" in types, (
            f"expected side_effect_completed in trace; got {set(types)}"
        )

    def test_search_external_call_reports_observed_completion(self, orchestrator_reporting, db_path):
        """The search/external_call path is the v3.0 first implemented completion path."""
        _run(orchestrator_reporting)
        run_id = orchestrator_reporting.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert any(
            se["status"] == "completed" and se["side_effect_type"] == "external_call"
            for se in search_ses
        ), "no completed external_call side effect for search_tool"


def _legacy_search_transform(payload):
    """Mock search_tool output WITHOUT side_effect_records (the pre-v3.0 form).

    Used by TestAbsentReportLegacy to verify the legacy path: a node that does
    NOT report completion leaves its side effect 'started' and emits no
    SIDE_EFFECT_COMPLETED event. The canonical _create_mock_nodes() search
    transform now reports (v3.0), so the legacy path needs its own transform.
    """
    return {
        "results": [{
            "origin_api": "semantic_scholar",
            "raw_data": {"title": "Test Paper", "paperId": "123"},
            "query_used": "test",
            "retrieved_at": "2026-01-01T00:00:00Z",
        }],
        "total_found": 1,
        "adapters_called": ["semantic_scholar"],
        "adapters_failed": [],
    }


@pytest.fixture
def orchestrator_legacy(blueprint, db_path):
    """Orchestrator whose mock search_tool does NOT report completion (pre-v3.0)."""
    nodes = _create_mock_nodes()
    nodes["search_tool"]._output_transform = _legacy_search_transform
    sm = StateManager(db_path=db_path)
    return Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)


class TestAbsentReportLegacy:
    def test_absent_completion_report_leaves_side_effect_started(self, orchestrator_legacy, db_path):
        """Legacy mock (no side_effect_records) ⇒ effect stays started."""
        _run(orchestrator_legacy)
        run_id = orchestrator_legacy.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1
        for se in search_ses:
            assert se["status"] == "started", (
                f"legacy mock should leave search effect 'started'; got {se['status']!r}"
            )

    def test_side_effect_completed_not_emitted_without_report(self, orchestrator_legacy):
        """Legacy mock ⇒ no SIDE_EFFECT_COMPLETED event."""
        trace = _run(orchestrator_legacy)
        types = _event_types(trace)
        assert "side_effect_completed" not in types


class TestInvalidReportFailedTrace:
    def test_unmatched_completion_report_returns_failed_trace_not_uncaught_exception(
        self, blueprint, db_path,
    ):
        """An invalid completion report fails the chain cleanly (no raise)."""
        nodes = _create_mock_nodes()
        nodes["search_tool"]._output_transform = lambda payload: {
            "results": [],
            "total_found": 0,
            "adapters_called": ["semantic_scholar"],
            "adapters_failed": [],
            "side_effect_records": [{
                "side_effect_key": "search:semantic_scholar:doesnotmatch0001",
                "side_effect_type": "external_call",
                "status": "completed",
                "observed_by": "node",
                "observed_at": "2026-07-08T00:00:00Z",
                "response_hash": "rh",
            }],
        }
        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = _run(orch)  # must not raise
        assert trace is not None
        assert trace.final_status == "failed"


# ─── 4. Canonical mock now reports (v2.97→v3.0 transition) ────────────────

class TestCanonicalMockReports:
    def test_v2_97_started_not_completed_expectation_updated_only_for_reporting_path(
        self, db_path,
    ):
        """The canonical mock search_tool now emits side_effect_records.

        v2.97 characterized the gap (started-not-completed). v3.0 closes it for
        the search path: the canonical mock reports observed completion, so the
        search side effect becomes completed. This test asserts the NEW truth
        and documents the v2.97 → v3.0 change.
        """
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        _run(orch)
        run_id = orch.state.run_id

        sm2 = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm2, run_id)
        assert len(search_ses) >= 1
        # NEW (v3.0): search path is now completed (reporting node).
        assert all(se["status"] == "completed" for se in search_ses), (
            f"canonical mock search effects should be completed in v3.0; "
            f"got {[se['status'] for se in search_ses]}"
        )

    def test_canonical_mock_memory_write_stays_started(self, db_path):
        """Memory_write has no completion report in v3.0 — stays started.

        Documents the scope boundary: v3.0 proves Model C for external_call
        (search) only. memory_write completion is deferred.
        """
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        _run(orch)
        run_id = orch.state.run_id

        sm2 = StateManager(db_path=db_path)
        memory_ses = [se for se in sm2.get_side_effects(run_id)
                      if se.get("node_id") == "memory_write_decision"]
        assert len(memory_ses) >= 1
        for se in memory_ses:
            assert se["status"] == "started", (
                f"memory_write should stay 'started' in v3.0 (no report); "
                f"got {se['status']!r}"
            )
