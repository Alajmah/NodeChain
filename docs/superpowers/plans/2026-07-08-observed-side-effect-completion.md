# Observed Side-Effect Completion (v3.0.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the first observed side-effect completion path: a node reports completion records in its output, the runtime validates them against the planned/started ledger, and marks the matching ledger entry `completed` (persisting `response_hash`) and emits `SIDE_EFFECT_COMPLETED` — only for validated, observed reports. No report ⇒ effect stays `started`. Node success never implies completion.

**Architecture:** Model C (node-output-reported, runtime-validated). A new `SideEffectJournalController.complete_reported_side_effects(node_id, envelope, output)` method reads `output["side_effect_records"]`, validates each record against the started ledger row (exact key match, canonical type match, status, observed_by authority, non-empty response_hash), then calls `persistence.update_side_effect_status(..., "completed", response_hash=...)` + `emitter.side_effect_completed(...)`. Invalid reports emit `CONTRACT_VIOLATION` and return `False` so the orchestrator's existing `_fail_chain` path produces a failed trace — no new exception types, no new event types. The reporting node is the mock search node in the characterization chain, which is updated to emit one valid `side_effect_records` entry for the `semantic_scholar` adapter.

**Tech Stack:** Python 3.11+, asyncio, SQLite (via `SideEffectLedgerStore`/`StateManager`), pytest, existing `nodechain.core` + `nodechain.runtime` modules.

---

## Design constraints (locked, do not violate)

```text
1. Completed means observed. Node success does NOT imply side-effect completion.
2. No completion report ⇒ side effect remains "started". No inferred completion.
3. Completion keys must be canonical and prefixed: search:<adapter>:<request_hash>.
4. side_effect_type must be the canonical "external_call", not aliases.
5. Completion reports must be nested inside output["side_effect_records"].
6. response_hash persistence is mandatory on the completed transition.
7. Invalid/unmatched reports use the existing failed-trace / CONTRACT_VIOLATION path.
   No new exception types. No SIDE_EFFECT_REJECTED event in v3.0.
8. Legacy nodes that don't emit side_effect_records are unaffected.
```

## File structure

**Create:**
- `tests/test_observed_side_effect_completion.py` — focused v3.0 completion test suite (11+ tests). Owns the greenfield test surface for the reporting path.

**Modify:**
- `src/nodechain/core/side_effect_utils.py` — add `make_canonical_search_key(adapter_name, request_hash)` helper (DRY source of the `search:<adapter>:<hash>` convention; closes the key-format drift between `search_tool.py:262` and the journal).
- `src/nodechain/runtime/side_effect_journal_controller.py` — add `complete_reported_side_effects(node_id, envelope, output) -> bool`. The public controller entry point for post-call completion.
- `src/nodechain/runtime/side_effect_journal.py` — add `_complete_reported_side_effect(...)` mixin method holding the validation + ledger update + emission logic (mirrors the `_journal_one` pattern: controller delegates, mixin owns the logic).
- `src/nodechain/runtime/orchestrator.py` — wire `complete_reported_side_effects` into the post-call seam at line ~483 (after `_emit_node_detail_events`, before semantic validators). Returns False ⇒ `_fail_chain`.
- `tests/test_runtime.py` — update the mock `search_tool` transform to emit a valid `side_effect_records` entry (the reporting path).
- `tests/test_side_effect_journaling_characterization.py` — narrowly update v2.97 assertions: the search reporting path now reaches `completed`; memory_write (no report) stays `started`.
- `docs/design/side-effect-completion.md` — add "v3.0.0 implementation status" section.
- `CHANGELOG.md` — add `[3.0.0]` entry.
- `pyproject.toml` — version bump `2.99.0` → `3.0.0`.

---

## Task 1: Canonical search-key helper

**Files:**
- Modify: `src/nodechain/core/side_effect_utils.py` (add at end)
- Test: `tests/test_observed_side_effect_completion.py` (new file, first test)

- [ ] **Step 1: Write the failing test (creates the new test file)**

Create `tests/test_observed_side_effect_completion.py`:

```python
"""v3.0.0 — Observed Side-Effect Completion tests.

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestCanonicalSearchKey -v`
Expected: FAIL with `ImportError: cannot import name 'make_canonical_search_key'`

- [ ] **Step 3: Add the helper to `side_effect_utils.py`**

Append to `src/nodechain/core/side_effect_utils.py` (after `compute_side_effect_response_hash`):

```python
def make_canonical_search_key(adapter_name: str, request_hash: str) -> str:
    """Build the canonical ledger/emitter key for a search side effect.

    The canonical form is ``search:<adapter_name>:<request_hash>`` — the same
    format used by ``SideEffectJournalMixin._journal_search_operations`` and
    the trace emitter's SIDE_EFFECT_STARTED/SIDE_EFFECT_COMPLETED events.

    v3.0.0: introduced to close the key-format drift between the search node's
    internal ``<adapter>:<hash>`` key and the ledger's ``search:<adapter>:<hash>``
    key. Both journaling and node-reported completion MUST use this helper so a
    completion record's ``side_effect_key`` exactly matches its ledger row.

    Returns "" if either part is empty (fail-closed — no partial key).
    """
    if not adapter_name or not request_hash:
        return ""
    return f"search:{adapter_name}:{request_hash}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestCanonicalSearchKey -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/nodechain/core/side_effect_utils.py tests/test_observed_side_effect_completion.py
git commit -m "feat(v3.0): add make_canonical_search_key helper + test file"
```

---

## Task 2: Completion validation logic (mixin method)

This is the core validation. It runs **before** any ledger mutation or emission. It returns `bool` (`True` = valid and applied, or a valid idempotent replay; `False` = invalid, with `CONTRACT_VIOLATION` already emitted). This task writes the validation logic as a mixin method and tests it via direct orchestrator-style construction.

**Files:**
- Modify: `src/nodechain/runtime/side_effect_journal.py` (add `_complete_reported_side_effect`)
- Test: `tests/test_observed_side_effect_completion.py` (add validation tests)

- [ ] **Step 1: Write the failing validation tests**

Append to `tests/test_observed_side_effect_completion.py`:

```python
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
        ok = orchestrator._side_effect_journal._complete_reported_side_effect(
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
        ok = orchestrator._side_effect_journal._complete_reported_side_effect(
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
        ok = orchestrator._side_effect_journal._complete_reported_side_effect(
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
        ok = orchestrator._side_effect_journal._complete_reported_side_effect(
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
        ok = orchestrator._side_effect_journal._complete_reported_side_effect(
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
        first = orchestrator._side_effect_journal._complete_reported_side_effect("search_tool", rec)
        second = orchestrator._side_effect_journal._complete_reported_side_effect("search_tool", rec)
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
        first = orchestrator._side_effect_journal._complete_reported_side_effect("search_tool", rec1)
        second = orchestrator._side_effect_journal._complete_reported_side_effect("search_tool", rec2)
        assert first is True
        assert second is False  # conflict
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestCompletionValidation -v`
Expected: FAIL with `AttributeError: ... has no attribute '_complete_reported_side_effect'`

- [ ] **Step 3: Add `_complete_reported_side_effect` to the mixin**

Add to `src/nodechain/runtime/side_effect_journal.py`, inside `class SideEffectJournalMixin` (after `_reconcile_side_effects_on_resume`, at the end of the class):

```python
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
        if canonical is None or canonical != existing.get("side_effect_type"):
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestCompletionValidation -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/nodechain/runtime/side_effect_journal.py tests/test_observed_side_effect_completion.py
git commit -m "feat(v3.0): add _complete_reported_side_effect validation+transition"
```

---

## Task 3: Controller method `complete_reported_side_effects`

The controller delegates per-record to the mixin. This is the public entry point the orchestrator will call.

**Files:**
- Modify: `src/nodechain/runtime/side_effect_journal_controller.py` (add imports for `EventType`, `Actor`; add the method)
- Test: `tests/test_observed_side_effect_completion.py` (add controller tests)

- [ ] **Step 1: Write the failing controller tests**

Append to `tests/test_observed_side_effect_completion.py`:

```python
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
        assert ok is True

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

    def test_malformed_completion_record_returns_failed_trace(self, blueprint, db_path):
        """A non-dict entry in side_effect_records fails the chain cleanly.

        Fail-closed: a present-but-malformed record is a CONTRACT_VIOLATION,
        not silently skipped. Protects the completion path from garbage input.
        """
        nodes = _create_mock_nodes()
        nodes["search_tool"]._output_transform = lambda payload: {
            "results": [],
            "total_found": 0,
            "adapters_called": ["semantic_scholar"],
            "adapters_failed": [],
            "side_effect_records": ["not-a-dict", 42, None],
        }
        sm = StateManager(db_path=db_path)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = _run(orch)  # must not raise
        assert trace is not None
        assert trace.final_status == "failed"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestControllerCompleteReported -v`
Expected: FAIL with `AttributeError: 'SideEffectJournalController'/'SideEffectJournalMixin' object has no attribute 'complete_reported_side_effects'`

- [ ] **Step 3: Add `complete_reported_side_effects` to the controller**

First, extend the imports at the top of `src/nodechain/runtime/side_effect_journal_controller.py`. The current imports are:

```python
from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.side_effect_journal import SideEffectJournalMixin
```

Change to:

```python
from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.trace import EventType, Actor
from nodechain.runtime.side_effect_journal import SideEffectJournalMixin
```

Then add the method inside `class SideEffectJournalController` (after `journal_planned_side_effects`):

```python
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
```

Also update the controller module docstring's "does NOT own" note — completion is now owned. In `side_effect_journal_controller.py`, change the docstring block at lines 17-18 from:

```text
What this controller does NOT own (stays on Orchestrator / mixin):
  - Side-effect completion (currently unimplemented — no callers wire it)
```

to:

```text
What this controller does NOT own (stays on Orchestrator / mixin):
  - Resume reconciliation (_reconcile_side_effects_on_resume stays on mixin)
```

And add to the "owns" list after `journal_planned_side_effects`:

```text
  - Post-call observed-completion coordination (complete_reported_side_effects, v3.0)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestControllerCompleteReported -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/nodechain/runtime/side_effect_journal_controller.py tests/test_observed_side_effect_completion.py
git commit -m "feat(v3.0): add complete_reported_side_effects controller entry point"
```

---

## Task 4: Wire the orchestrator post-call seam

The orchestrator calls `complete_reported_side_effects` right after `_emit_node_detail_events`. This is the existing post-call seam (orchestrator.py:483). The call returns False ⇒ `_fail_chain("undeclared_side_effect", ...)`, mirroring the existing pattern.

**Files:**
- Modify: `src/nodechain/runtime/orchestrator.py` (around line 483-487)
- Test: `tests/test_observed_side_effect_completion.py` (add end-to-end + event tests)

- [ ] **Step 1: Write the failing end-to-end + event tests**

Append to `tests/test_observed_side_effect_completion.py`:

```python
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


class TestAbsentReportLegacy:
    def test_absent_completion_report_leaves_side_effect_started(self, orchestrator, db_path):
        """Legacy mock (no side_effect_records) ⇒ effect stays started."""
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        search_ses = _search_side_effects(sm, run_id)
        assert len(search_ses) >= 1
        for se in search_ses:
            assert se["status"] == "started", (
                f"legacy mock should leave search effect 'started'; got {se['status']!r}"
            )

    def test_side_effect_completed_not_emitted_without_report(self, orchestrator):
        """Legacy mock ⇒ no SIDE_EFFECT_COMPLETED event."""
        trace = _run(orchestrator)
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestEndToEndReporting tests/test_observed_side_effect_completion.py::TestAbsentReportLegacy tests/test_observed_side_effect_completion.py::TestInvalidReportFailedTrace -v`
Expected: FAIL — the reporting-mock tests will fail because the orchestrator doesn't call `complete_reported_side_effects` yet (so effects stay `started` even with a report). The absent-report tests should PASS already (legacy behavior).

- [ ] **Step 3: Wire the orchestrator post-call seam**

In `src/nodechain/runtime/orchestrator.py`, find the post-call block (around line 482-487):

```python
                # Emit node-specific detail events (tool calls, model usage, memory)
                if not self._emit_node_detail_events(node_id, node, response, envelope):
                    self._fail_chain("undeclared_side_effect", [
                        "post-call side-effect declaration violation",
                    ])
                    return self.trace
```

Add immediately AFTER that block (before the "Run semantic validators" comment):

```python
                # v3.0.0: observed side-effect completion (Model C). The node may
                # report completion records in output["side_effect_records"]; the
                # runtime validates each against the started/planned ledger and
                # marks completed only for valid observed reports. Absent records
                # are legacy (no-op). Invalid records fail the chain cleanly.
                if not self._side_effect_journal.complete_reported_side_effects(
                    node_id, envelope, response.output,
                ):
                    self._fail_chain("undeclared_side_effect", [
                        "post-call side-effect completion validation violation",
                    ])
                    return self.trace
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_observed_side_effect_completion.py -v`
Expected: PASS (all tests in the file — canonical key, validation, controller, e2e, absent-report, invalid-report)

- [ ] **Step 5: Commit**

```bash
git add src/nodechain/runtime/orchestrator.py tests/test_observed_side_effect_completion.py
git commit -m "feat(v3.0): wire observed side-effect completion into post-call seam"
```

---

## Task 5: Make the mock search node a reporting node (characterization fixture)

The v2.97 characterization tests run the legacy mock (no report) and assert effects stay `started`. For v3.0 we add a reporting path to the canonical mock chain so the full orchestrator characterization suite exercises completion end-to-end. This is the deliberate, narrow change to `tests/test_runtime.py`.

**Decision point:** the canonical mock search node should emit a completion report, so the orchestrator characterization suite reflects the new truth. But this means v2.97 tests that assert "started not completed" must be narrowed (Task 6). The alternative — leaving the canonical mock non-reporting and only testing completion in `test_observed_side_effect_completion.py` — would leave the characterization suite not actually characterizing the new behavior. We choose the former: the canonical mock reports, and v2.97 assertions are narrowed to the memory_write path (which has no report).

**Files:**
- Modify: `tests/test_runtime.py` (the `search_tool` transform)
- Test: `tests/test_observed_side_effect_completion.py` (verify the canonical mock now reports)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_observed_side_effect_completion.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestCanonicalMockReports -v`
Expected: FAIL — `test_v2_97_started_not_completed_expectation_updated_only_for_reporting_path` fails because the canonical mock doesn't report yet (effects stay `started`). `test_canonical_mock_memory_write_stays_started` should PASS already.

- [ ] **Step 3: Update the canonical mock search transform**

In `tests/test_runtime.py`, find the `search_tool` transform (around lines 122-132):

```python
        "search_tool": lambda p: {
            "results": [{
                "origin_api": "semantic_scholar",
                "raw_data": {"title": "Test Paper", "paperId": "123"},
                "query_used": "test",
                "retrieved_at": "2026-01-01T00:00:00Z",
            }],
            "total_found": 1,
            "adapters_called": ["semantic_scholar"],
            "adapters_failed": [],
        },
```

Replace with (adds the `side_effect_records` field — the request_hash is computed to match what `_journal_search_operations` derives for the context_selector's query `terms=["test"], target_adapters=["semantic_scholar"], max_results=10`):

```python
        "search_tool": lambda p: {
            "results": [{
                "origin_api": "semantic_scholar",
                "raw_data": {"title": "Test Paper", "paperId": "123"},
                "query_used": "test",
                "retrieved_at": "2026-01-01T00:00:00Z",
            }],
            "total_found": 1,
            "adapters_called": ["semantic_scholar"],
            "adapters_failed": [],
            # v3.0.0: observed side-effect completion report (Model C). The
            # canonical mock now reports completion for the semantic_scholar
            # external_call. The side_effect_key matches the ledger key derived
            # by _journal_search_operations for terms=["test"], adapter=
            # "semantic_scholar". This closes the v2.97-characterized gap.
            "side_effect_records": _mock_search_completion_records(),
        },
```

Add a module-level helper above the `transforms` dict in `tests/test_runtime.py` (after the imports, before `transforms = {`):

```python
def _mock_search_completion_records():
    """v3.0.0: build the canonical mock's side_effect_records completion report.

    The request_hash must match what SideEffectJournalMixin._journal_search_operations
    derives from the context_selector's query (terms=["test"], target_adapters=
    ["semantic_scholar"], max_results=10, filters={}). Both use
    compute_side_effect_request_hash with the same operation dict.
    """
    from nodechain.core.side_effect_utils import (
        compute_side_effect_request_hash, compute_side_effect_response_hash, make_canonical_search_key,
    )
    req_hash = compute_side_effect_request_hash(
        "external_call", "search_tool", "",
        operation={"terms": ["test"], "max": 10, "filters": {}},
    )
    key = make_canonical_search_key("semantic_scholar", req_hash)
    response_hash = compute_side_effect_response_hash(
        results=[{"raw_data": {"title": "Test Paper", "paperId": "123"}}],
    )
    return [{
        "side_effect_key": key,
        "side_effect_type": "external_call",
        "status": "completed",
        "observed_by": "node",
        "observed_at": "2026-07-08T00:00:00Z",
        "response_hash": response_hash,
        "evidence": {"adapter": "semantic_scholar", "result_count": 1},
    }]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestCanonicalMockReports -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add tests/test_runtime.py tests/test_observed_side_effect_completion.py
git commit -m "feat(v3.0): canonical mock search_tool reports observed completion"
```

---

## Task 6: Narrow the v2.97 characterization tests

The canonical mock now reports completion for search. v2.97 assertions that "search effects stay started" / "no SIDE_EFFECT_COMPLETED" must be updated to reflect the new truth, while preserving the characterization of memory_write (no report ⇒ started) and the legacy fixture (the dedicated non-reporting path).

**Files:**
- Modify: `tests/test_side_effect_journaling_characterization.py`

- [ ] **Step 1: Update the v2.97 assertions that characterize the search gap**

In `tests/test_side_effect_journaling_characterization.py`:

**(a)** `TestDeclaredSideEffectLifecycle.test_side_effects_have_valid_status` (lines ~112-138): change the search-status assertion from `started` to `completed`. Replace the block:

```python
            # Observed behavior: mock chain leaves side effects as 'started'.
            # Assert the actual observable status, not the ideal 'completed'.
            assert se["status"] == "started", (
                f"expected 'started' (mock never completes), got {se['status']!r} "
                f"for key {se.get('idempotency_key')}"
            )
```

with:

```python
            # v3.0.0: the canonical mock search_tool now reports observed
            # completion, so search side effects are 'completed'. (Previously
            # v2.97 characterized the gap as 'started'.) Memory_write effects
            # remain 'started' — they have no completion report in v3.0.
            assert se["status"] == "completed", (
                f"expected 'completed' (canonical mock reports completion in v3.0), "
                f"got {se['status']!r} for key {se.get('idempotency_key')}"
            )
```

**(b)** `TestTraceEventOrdering.test_no_side_effect_completed_in_mock_chain` (lines ~390-403): this test asserted the gap ("no SIDE_EFFECT_COMPLETED"). The gap is now closed for search. Rename and flip the assertion. Replace the whole method:

```python
    def test_no_side_effect_completed_in_mock_chain(self, orchestrator):
        """The mock chain does NOT emit SIDE_EFFECT_COMPLETED.

        Observed: the mock search_tool doesn't perform real external calls,
        and the success path never calls ``update_side_effect_status`` with
        ``"completed"``. So no SIDE_EFFECT_COMPLETED trace event is emitted.
        This characterizes the gap — completion must be wired by real adapters.
        """
        trace = _run(orchestrator)
        types = _event_types(trace)
        assert "side_effect_completed" not in types, (
            "mock chain should not emit side_effect_completed "
            "(no real external calls are performed)"
        )
```

with:

```python
    def test_side_effect_completed_emitted_in_mock_chain(self, orchestrator):
        """v3.0.0: the canonical mock chain DOES emit SIDE_EFFECT_COMPLETED.

        The canonical mock search_tool now reports observed completion via
        output["side_effect_records"], so SIDE_EFFECT_COMPLETED is emitted.
        (v2.97 characterized the gap as absent; v3.0 closes it for search.)
        """
        trace = _run(orchestrator)
        types = _event_types(trace)
        assert "side_effect_completed" in types, (
            "canonical mock chain should emit side_effect_completed in v3.0 "
            f"(search reports observed completion); got {set(types)}"
        )
```

**(c)** `TestResumeVisibleLedgerState.test_completed_side_effects_absent_after_mock_run` (lines ~430-446): the completed set is now non-empty for search. Replace the whole method:

```python
    def test_completed_side_effects_absent_after_mock_run(self, orchestrator, db_path):
        """After a successful mock run, NO side effects are 'completed'.

        Observed gap: the mock success path journals 'started' pre-call but
        never advances to 'completed'. So the completed set is empty. This
        characterizes the current behavior — real adapters must wire
        completion for the completed set to be non-empty.
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        completed = sm.get_side_effects_by_status(run_id, "completed")
        assert len(completed) == 0, (
            f"mock chain should leave 0 completed side effects; got {len(completed)}: "
            f"{completed}"
        )
```

with:

```python
    def test_search_completed_side_effects_present_after_mock_run(self, orchestrator, db_path):
        """v3.0.0: after a successful mock run, search side effects ARE completed.

        The canonical mock search_tool reports observed completion, so the
        completed set is non-empty for search_tool. memory_write effects
        remain 'started' (no report in v3.0).
        """
        _run(orchestrator)
        run_id = orchestrator.state.run_id

        sm = StateManager(db_path=db_path)
        completed = sm.get_side_effects_by_status(run_id, "completed")
        search_completed = [se for se in completed if se.get("node_id") == "search_tool"]
        assert len(search_completed) >= 1, (
            "expected >=1 completed search side effect in v3.0; "
            f"got {len(search_completed)} (all completed: {completed})"
        )
```

**(d)** `TestResumeVisibleLedgerState.test_started_side_effects_visible_by_status` (lines ~411-428): this asserts search effects are visible under `started`. Now they're `completed`. Update to assert memory_write is the one that stays visible under `started`. Replace:

```python
        search_started = [se for se in started if se.get("node_id") == "search_tool"]
        assert len(search_started) >= 1, (
            "expected >=1 started side effect for search_tool; "
            f"got {len(search_started)}"
        )
```

with:

```python
        # v3.0.0: search_tool effects are now completed; memory_write has no
        # completion report and remains started. Assert memory_write is the
        # node that stays visible under the 'started' query.
        memory_started = [se for se in started if se.get("node_id") == "memory_write_decision"]
        assert len(memory_started) >= 1, (
            "expected >=1 started side effect for memory_write_decision (no report in v3.0); "
            f"got {len(memory_started)}"
        )
```

**(e)** `TestResumeVisibleLedgerState.test_ledger_includes_memory_write_side_effect` (lines ~471-495): the memory_write assertion `se["status"] == "started"` stays correct — keep it. Add a comment clarifying why it's still started:

Find:

```python
            # Observed: also left as 'started' (mock doesn't perform real writes
            # in a way that triggers completion).
            assert se["status"] == "started"
```

Replace with:

```python
            # v3.0.0: still 'started' — memory_write has no completion report
            # path in v3.0 (deferred). Only external_call (search) reports.
            assert se["status"] == "started"
```

- [ ] **Step 2: Run the v2.97 characterization suite**

Run: `python -m pytest tests/test_side_effect_journaling_characterization.py -v`
Expected: PASS (17 tests) — the updated assertions reflect the new search-completed truth; memory_write characterization preserved.

- [ ] **Step 3: Run the full v3.0 test file to confirm no regression**

Run: `python -m pytest tests/test_observed_side_effect_completion.py -v`
Expected: PASS (all)

- [ ] **Step 4: Commit**

```bash
git add tests/test_side_effect_journaling_characterization.py
git commit -m "test(v3.0): narrow v2.97 characterization for search completion"
```

---

## Task 7: Regression sweep — orchestrator + state + validation characterization

Verify the wiring doesn't break the broader characterization suites. These suites freeze the public observable surface; if the search completion changes event ordering or final status, they'll catch it.

**Files:** none (verification only)

- [ ] **Step 1: Run orchestrator characterization**

Run: `python -m pytest tests/test_orchestrator_characterization.py -v`
Expected: PASS. If any test fails on event ordering (e.g. a test that counts events or asserts SIDE_EFFECT_STARTED is the last side-effect event), investigate: the new SIDE_EFFECT_COMPLETED event appears after NODE_SUCCEEDED for search_tool. Fix the characterization assertion to reflect the new ordering only if it's asserting a stale gap; do not weaken safety assertions.

- [ ] **Step 2: Run validation-failure characterization**

Run: `python -m pytest tests/test_validation_failure_characterization.py -v`
Expected: PASS.

- [ ] **Step 3: Run policy-gate characterization**

Run: `python -m pytest tests/test_policy_gate_characterization.py -v`
Expected: PASS.

- [ ] **Step 4: Run state-manager characterization**

Run: `python -m pytest tests/test_state_manager_characterization.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full affected-area suite together**

Run: `python -m pytest tests/test_observed_side_effect_completion.py tests/test_side_effect_journaling_characterization.py tests/test_orchestrator_characterization.py tests/test_validation_failure_characterization.py tests/test_policy_gate_characterization.py tests/test_state_manager_characterization.py -v`
Expected: PASS (all).

- [ ] **Step 6: Commit (only if any characterization files needed updates beyond Task 6)**

If Step 1 surfaced a needed fix in `test_orchestrator_characterization.py` (or another characterization file), commit it:

```bash
git add tests/test_orchestrator_characterization.py
git commit -m "test(v3.0): update orchestrator characterization for completion event"
```

If no files changed, skip this step and note "no regression-sweep changes required" in the commit message of Task 8.

---

## Task 8: Docs, CHANGELOG, version bump

**Files:**
- Modify: `docs/design/side-effect-completion.md`
- Modify: `CHANGELOG.md`
- Modify: `pyproject.toml`

- [ ] **Step 1: Add implementation-status section to the design doc**

In `docs/design/side-effect-completion.md`, append a new section at the end:

```markdown

---

## v3.0.0 — Implementation Status

**Implemented:** Model C (node-output-reported observed completion), first path.

- Nodes may include `output["side_effect_records"]`: a list of completion
  records, each with `side_effect_key`, `side_effect_type`, `status`,
  `observed_by`, `observed_at`, `response_hash`, and optional `evidence`.
- `SideEffectJournalController.complete_reported_side_effects(node_id, envelope, output)`
  validates each record against the started/planned ledger row and, for valid
  records, transitions the ledger to `completed` (persisting `response_hash`)
  and emits `SIDE_EFFECT_COMPLETED`.
- The canonical mock `search_tool` now reports observed completion for its
  `semantic_scholar` external_call, closing the v2.97-characterized gap.

**Validation rules (v3.0):**

1. `side_effect_key` exactly matches a `started` ledger row for the current run.
2. `side_effect_type` matches the canonical type (e.g. `external_call`).
3. `status == "completed"`.
4. `observed_by` is an accepted authority (`node` in v3.0; `adapter`/`executor` deferred to v3.1).
5. `response_hash` is non-empty.
6. `observed_at` is non-empty.
7. The record is nested under `output["side_effect_records"]` and is itself a dict (malformed ⇒ fail closed).

Idempotency: same key + `completed` + same `response_hash` ⇒ safe replay (`True`); different `response_hash` ⇒ `CONTRACT_VIOLATION` (`False`).

Invalid/unmatched/malformed reports emit `CONTRACT_VIOLATION` (`decision="invalid_completion_report"`)
and fail the chain via the existing soft-fail path. No new exception or event
type was introduced.

**Not implemented in v3.0:**
- Model B (adapter/executor-reported completion via `BaseSearchAdapter`).
- memory_write / code_execution / external_write completion paths.
- A dedicated `SIDE_EFFECT_REJECTED` event type (uses `CONTRACT_VIOLATION`).

**Guardrail preserved:**
```
Completed means observed.
Node success does not imply side-effect completion.
No completion report ⇒ the side effect remains started.
```
```

- [ ] **Step 2: Add the CHANGELOG entry**

In `CHANGELOG.md`, insert a new section at the top (above the `[2.99.0]` entry):

```markdown
## [3.0.0] — Observed Side-Effect Completion (Model C, first path)

**Release type:** narrow behavior implementation (first behavior change in the
2.9x→3.x transition; prior 2.9x releases were characterization or
behavior-preserving extraction).

v3.0.0 implements the first observed side-effect completion path: nodes may
report completion records in `output["side_effect_records"]`, and the runtime
validates each record against the planned/started ledger before marking it
`completed`. This closes the gap characterized in v2.97 (side effects stayed
`started` because no caller wired the completion emitter).

**What changed**
- `SideEffectJournalController.complete_reported_side_effects(node_id, envelope, output)`
  validates node-reported completion records and transitions matching ledger
  rows to `completed` (persisting `response_hash`), emitting
  `SIDE_EFFECT_COMPLETED` only for validated observed reports.
- New helper `make_canonical_search_key(adapter_name, request_hash)` in
  `nodechain.core.side_effect_utils` — single source of truth for the
  `search:<adapter>:<hash>` key format.
- The canonical mock `search_tool` now reports observed completion for its
  `semantic_scholar` external_call.

**What did NOT change**
- No completion is inferred from node success.
- No adapter-level (Model B) completion reporting.
- No memory_write / code_execution / external_write completion paths.
- No policy, sandbox, recovery, or Docker behavior changes.
- No new exception types; no new trace event types (invalid reports reuse the
  existing `CONTRACT_VIOLATION` soft-fail path).

**Tests**
- New: `tests/test_observed_side_effect_completion.py` (focused completion suite).
- Updated: `tests/test_side_effect_journaling_characterization.py` (search path
  now reaches `completed`; memory_write stays `started`).
- Green: orchestrator, validation-failure, policy-gate, state-manager
  characterization suites.

**Version bump:** 2.99.0 → 3.0.0.
```

- [ ] **Step 3: Bump the version**

In `pyproject.toml`, change `version = "2.99.0"` to `version = "3.0.0"`.

- [ ] **Step 4: Commit**

```bash
git add docs/design/side-effect-completion.md CHANGELOG.md pyproject.toml
git commit -m "docs(v3.0): observed side-effect completion — design status, changelog, version bump"
```

---

## Task 9: Final verification sweep

**Files:** none

- [ ] **Step 1: Run the complete affected-area suite once more**

Run: `python -m pytest tests/test_observed_side_effect_completion.py tests/test_side_effect_journaling_characterization.py tests/test_orchestrator_characterization.py tests/test_validation_failure_characterization.py tests/test_policy_gate_characterization.py tests/test_state_manager_characterization.py -v`
Expected: PASS (all).

- [ ] **Step 2: Verify the guardrail with a targeted check**

Run: `python -m pytest tests/test_observed_side_effect_completion.py::TestAbsentReportLegacy -v`
Expected: PASS — confirms "no report ⇒ started" and "no SIDE_EFFECT_COMPLETED without report".

- [ ] **Step 3: Confirm version and git state**

Run: `git log --oneline -10` and verify the v3.0 commits are present.
Run: `python -c "import nodechain; print(nodechain.__version__)" 2>/dev/null || grep version pyproject.toml`
Expected: `3.0.0`.

- [ ] **Step 4: Report**

Report:
- Linux/WSL full-suite status: note explicitly whether run or deferred.
- Windows targeted v3.0 affected-area: state PASS/FAIL with evidence.
- Optional sandbox verifier: state run/explicit-unsupported-skip.
- Explicitly list anything NOT completed (e.g., "Linux full suite not run — Windows targeted only").

---

## Self-review notes (completed before handoff)

**Spec coverage check** (against the corrected spec's required tests):
- `test_reported_side_effect_completion_marks_ledger_completed` → Task 4 `TestEndToEndReporting`
- `test_absent_completion_report_leaves_side_effect_started` → Task 4 `TestAbsentReportLegacy`
- `test_completion_report_must_match_started_side_effect_key` → Task 2 `TestCompletionValidation`
- `test_unprefixed_search_completion_key_does_not_mark_completed` → Task 2 `TestCompletionValidation`
- `test_unmatched_completion_report_returns_failed_trace_not_uncaught_exception` → Task 4 `TestInvalidReportFailedTrace`
- `test_completion_report_uses_canonical_external_call_type` → Task 2 `TestCompletionValidation`
- `test_side_effect_completed_event_emitted_after_valid_report` → Task 4 `TestEndToEndReporting`
- `test_side_effect_completed_not_emitted_without_report` → Task 4 `TestAbsentReportLegacy`
- `test_completed_side_effect_persists_response_hash` → Task 4 `TestEndToEndReporting`
- `test_completion_report_must_be_nested_in_output_side_effect_records` → Task 3 `TestControllerCompleteReported`
- `test_search_or_mock_external_call_reports_observed_completion` → Task 4 `TestEndToEndReporting`
- All 11 spec-required tests mapped. ✓

**Spec rules check:**
1. Model C only (no Model B) → Task 3 controller + Task 4 wiring. ✓
2. Canonical prefixed keys → Task 1 `make_canonical_search_key`. ✓
3. response_hash persistence → Task 2 `_complete_reported_side_effect` passes `response_hash` to `update_side_effect_status`. ✓
4. `external_call` canonical type → Task 2 type-mismatch validation. ✓
5. Nested `output["side_effect_records"]` → Task 3 controller reads only that key. ✓
6. Invalid ⇒ failed trace / `CONTRACT_VIOLATION` → Task 2 + Task 4 `_fail_chain`. ✓
7. `observed_at` required → Task 2 empty-observed_at validation. ✓
8. Idempotent same-hash replay, conflict on different hash → Task 2 idempotency branch + 2 tests. ✓
9. Malformed (non-dict) records fail closed → Task 3 controller + `test_malformed_completion_record_returns_failed_trace`. ✓

**Type/signature consistency check:**
- `make_canonical_search_key(adapter_name, request_hash) -> str` — used consistently in Tasks 1, 2, 4, 5. ✓
- `_complete_reported_side_effect(node_id, record) -> bool` — defined Task 2, called Task 3. ✓
- `complete_reported_side_effects(node_id, envelope, output) -> bool` — defined Task 3, called Task 4. ✓
- `persistence.update_side_effect_status(run_id, key, status, response_hash=...)` — matches facade signature at persistence.py:199. ✓
- `emitter.side_effect_completed(node_id, effect_type, key, request_hash=, response_hash=)` — matches trace_emitter.py:271. ✓

**Placeholder scan:** no TBD/TODO; every code step has full code. ✓
