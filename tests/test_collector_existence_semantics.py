"""Tests for collector existence semantics — absent vs present-but-noncompliant (#15).

Regression coverage for the HR-001/HR-013 collector semantics fix. The principle
(agreed with review): absence or synthesized emptiness is NOT the same as a
non-compliant configured trust root / registry. A missing temp path must not
report exists=True, which would make a synthesized empty structure look like a
real unsigned store and fire HR-001/HR-013 on a clean environment.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.cli.dashboard import collect_trust_status, collect_registry_status


@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path, monkeypatch):
    """Point every durable path at temp dirs so collectors read only what the
    test writes."""
    monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(tmp_path / "trust.json"))
    monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "registry.json"))
    monkeypatch.setenv("NODECHAIN_DB_PATH", str(tmp_path / "empty.db"))
    trace = tmp_path / "traces"
    trace.mkdir()
    monkeypatch.setenv("NODECHAIN_TRACE_DIR", str(trace))
    yield


# --- trust store: absent vs synthesized vs real-unsigned ---------------------

def test_missing_trust_store_reports_not_exists() -> None:
    """A trust store path that does not exist must report trust_store_exists=False.
    load_trust_store() synthesizes an empty store, but the collector must not
    treat that synthesized object as a real existing store."""
    status = collect_trust_status()
    assert status["trust_store_exists"] is False


def test_empty_trust_store_file_reports_not_initialized(tmp_path, monkeypatch) -> None:
    """A real trust store file that exists on disk but has zero entries and no
    signature is 'exists but uninitialized'. Per agreed semantics, it should not
    trigger HR-001 (no material content to be 'unsigned'). The file's presence
    is honest, but it's operationally empty."""
    p = tmp_path / "empty_ts.json"
    p.write_text(json.dumps({"schema_version": "1", "type": "trust_store", "keys": {}}))
    monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(p))
    status = collect_trust_status()
    # File exists but has no material content → exists is False (no entries, no
    # signature) → HR-001 does not fire. This is the refined semantics pin.
    assert status["trust_store_exists"] is False
    assert status["snapshot_signed"] is False
    assert status["total_keys"] == 0


def test_real_unsigned_trust_store_with_entries_reports_exists(tmp_path, monkeypatch) -> None:
    """A real trust store WITH entries but no snapshot signature is a genuine
    present-but-noncompliant trust root — HR-001 SHOULD fire on this. The fix
    must not weaken this case."""
    store = {
        "schema_version": "1", "type": "trust_store",
        "keys": {"k1": {"purpose": "signing"}},
        # no snapshot_signature → unsigned
    }
    p = tmp_path / "real_ts.json"
    p.write_text(json.dumps(store))
    monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(p))

    status = collect_trust_status()
    assert status["trust_store_exists"] is True
    assert status["snapshot_signed"] is False  # genuinely unsigned → HR-001 fires
    assert status["total_keys"] == 1


def test_real_signed_trust_store_reports_exists_and_signed(tmp_path, monkeypatch) -> None:
    """A real signed trust store is the healthy case."""
    store = {
        "schema_version": "1", "type": "trust_store",
        "keys": {"k1": {"purpose": "signing"}},
        "snapshot_signature": {"sig": "abc", "digest": "def"},
    }
    p = tmp_path / "signed_ts.json"
    p.write_text(json.dumps(store))
    monkeypatch.setenv("NODECHAIN_TRUST_STORE", str(p))

    status = collect_trust_status()
    assert status["trust_store_exists"] is True
    assert status["snapshot_signed"] is True


# --- registry: absent vs synthesized vs real --------------------------------

def test_missing_registry_reports_not_exists() -> None:
    """A registry path that does not exist must report registry_exists=False."""
    status = collect_registry_status()
    assert status["registry_exists"] is False


def test_empty_registry_file_reports_not_initialized(tmp_path, monkeypatch) -> None:
    """A real registry file that exists but has zero entries is operationally
    empty — not a real unready registry. Per agreed semantics, it should not
    trigger HR-013."""
    p = tmp_path / "empty_reg.json"
    p.write_text(json.dumps({"type": "certified_registry", "entries": {}}))
    monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(p))
    status = collect_registry_status()
    assert status["registry_exists"] is False
    assert status["total_entries"] == 0


def test_real_registry_with_entries_reports_exists(tmp_path, monkeypatch) -> None:
    """A real registry with entries reports exists=True. The fix must not
    weaken this — a real registry is a real configured artifact."""
    reg = {
        "entries": {"pkg-1": {"registry_status": "active"}},
    }
    p = tmp_path / "real_reg.json"
    p.write_text(json.dumps(reg))
    monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(p))

    status = collect_registry_status()
    assert status["registry_exists"] is True
    assert status["total_entries"] == 1
    assert status["active"] == 1
