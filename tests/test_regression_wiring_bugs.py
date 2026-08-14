"""Regression tests for discovered wiring bugs (v2.48.0 #18).

Two latent bugs were found during v2.46.0/v2.47.0 follow-up work. These tests
prove the fixes hold and guard against regression — exactly the kind of issue
CI should catch before merge.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.cli.dashboard import collect_trust_status


# --- Bug 1: collect_trust_status read "entries" instead of "keys" ------------

def test_trust_status_reads_keys_not_entries(tmp_path, monkeypatch) -> None:
    """REGRESSION: collect_trust_status was reading ts.get('entries', {}) but the
    trust store schema uses 'keys'. This made total_keys always 0 in production
    dashboards, even when the store had real keys."""
    store = {
        "schema_version": "1", "type": "trust_store",
        "keys": {
            "k1": {"purpose": "signing"},
            "k2": {"purpose": "verification"},
        },
        "snapshot_signature": {"sig": "abc"},
    }
    p = tmp_path / "trust.json"
    p.write_text(json.dumps(store))
    monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(p))

    status = collect_trust_status()

    # The bug: total_keys was always 0 because it read "entries" not "keys".
    assert status["total_keys"] == 2  # would be 0 with the old bug
    assert status["trust_store_exists"] is True


def test_trust_status_purposes_populated_from_keys(tmp_path, monkeypatch) -> None:
    """REGRESSION companion: purposes classification was empty because it
    iterated over an empty 'entries' dict."""
    store = {
        "schema_version": "1", "type": "trust_store",
        "keys": {"k1": {"purpose": "signing"}},
        "snapshot_signature": {"sig": "abc"},
    }
    p = tmp_path / "trust.json"
    p.write_text(json.dumps(store))
    monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(p))

    status = collect_trust_status()

    assert status["purposes"] == {"signing": 1}  # would be {} with the old bug


# --- Bug 2: orchestrator never persisted last_failure metadata ---------------

def test_record_last_failure_persists_durable_metadata() -> None:
    """REGRESSION: the orchestrator's _fail_chain never wrote last_failure
    metadata, so the recovery classifier's FAILED_RETRYABLE/FAILED_NON_RETRYABLE
    branches were unreachable in production — failed runs fell through to
    CRASH_RECOVERABLE."""
    from nodechain.core.state import ChainState, StateManager
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.runtime.recovery_classifier import RecoveryState, classify

    sm = StateManager(db_path=Path("/tmp/test_regression_sm.db"))
    state = ChainState(run_id="r1", chain_id="c", status="running")
    sm.save(state)

    class _StubOrch(Orchestrator):
        def __init__(self):
            pass

    from nodechain.runtime.persistence import PersistenceCoordinator
    from nodechain.core.trace import ChainTrace
    orch = _StubOrch()
    orch.state = state
    orch.state_manager = sm
    orch.persistence = PersistenceCoordinator(sm)
    orch.trace = ChainTrace(run_id="r1", chain_id="c")
    orch._step = 4

    # H0.5: _record_last_failure builds the proposal; the failing lifecycle
    # transition commits it atomically with the failed status.
    from nodechain.runtime.failure_manager import FailureType
    proposal = orch._record_last_failure(
        FailureType.MODEL_TIMEOUT, "flaky_node", 4,
        "connection timeout", retryable=True,
    )
    orch._fail_chain(
        "node_execution_failed:model_timeout",
        ["Node 'flaky_node' failed: connection timeout"],
        metadata=proposal,
    )

    # The DURABLE metadata must carry last_failure (stronger than the old
    # in-memory-only assertion — this is what the classifier reads).
    fresh = sm.load("r1")
    md = fresh.metadata
    assert fresh.status == "failed"
    assert "last_failure" in md
    assert md["last_failure"]["failure_type"] == "model_timeout"
    assert md["last_failure"]["node_id"] == "flaky_node"
    assert md["last_failure"]["step_id"] == 4
    assert md["last_failure"]["retryable"] is True

    # And the classifier must reach FAILED_RETRYABLE (not CRASH_RECOVERABLE)
    result = classify(fresh, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.FAILED_RETRYABLE
