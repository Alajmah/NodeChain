"""Registry lockfile enforcement tests (v2.67.3).

Tests the fail-closed lockfile enforcement for registry-resolved nodes.
Every denial condition must block execution with a clear error.

The enforcement helper (enforce_lockfile_for_nodes) checks:
  1. lockfile missing on disk
  2. node entry missing from lockfile
  3. version mismatch
  4. origin != "local_registry"
  5. content_digest missing from lockfile entry
  6. content_digest mismatch (tampered)
  7. package not currently admitted by registry
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.registry.local_registry import RegistryIndex
from nodechain.sdk.lockfile import enforce_lockfile_for_nodes, generate_lockfile


SHARED_NODE_IDS = ["shared_risk_classifier", "shared_trace_collector"]


@pytest.fixture
def scanned_registry() -> RegistryIndex:
    """A freshly scanned local registry."""
    reg = RegistryIndex()
    reg.scan()
    return reg


@pytest.fixture
def valid_lockfile(tmp_path, scanned_registry) -> Path:
    """A valid lockfile pinned to the current shared node packages."""
    lf_path = tmp_path / "test.lock.json"
    generate_lockfile(registry=scanned_registry, output_path=lf_path)
    return lf_path


def _load_lockfile(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_lockfile(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ── Valid lockfile passes ─────────────────────────────────────────────────

class TestValidLockfilePasses:
    """A correct, current lockfile must pass enforcement."""

    def test_valid_lockfile_passes(self, valid_lockfile, scanned_registry):
        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is True
        assert errors == []


# ── Denial condition 1: lockfile missing ──────────────────────────────────

class TestLockfileMissingDenied:
    def test_missing_lockfile_denied(self, tmp_path, scanned_registry):
        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS,
            lockfile_path=tmp_path / "nonexistent.json",
            registry=scanned_registry,
        )
        assert ok is False
        assert any("not found" in e or "missing" in e.lower() for e in errors)


# ── Denial condition 2: node entry missing ────────────────────────────────

class TestEntryMissingDenied:
    def test_missing_entry_denied(self, valid_lockfile, scanned_registry):
        lf = _load_lockfile(valid_lockfile)
        lf["packages"] = [e for e in lf["packages"] if e["node_id"] != "shared_risk_classifier"]
        _write_lockfile(valid_lockfile, lf)

        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is False
        assert any("shared_risk_classifier" in e and "missing" in e for e in errors)


# ── Denial condition 3: version mismatch ──────────────────────────────────

class TestVersionMismatchDenied:
    def test_version_mismatch_denied(self, valid_lockfile, scanned_registry):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] == "shared_risk_classifier":
                e["version"] = "9.9.9"
        _write_lockfile(valid_lockfile, lf)

        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is False
        assert any("version mismatch" in e for e in errors)


# ── Denial condition 4: origin mismatch ───────────────────────────────────

class TestOriginMismatchDenied:
    def test_origin_mismatch_denied(self, valid_lockfile, scanned_registry):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] == "shared_risk_classifier":
                e["origin"] = "untrusted_remote"
        _write_lockfile(valid_lockfile, lf)

        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is False
        assert any("origin mismatch" in e for e in errors)


# ── Denial condition 5: content_digest missing from entry ─────────────────

class TestDigestMissingDenied:
    def test_digest_field_missing_denied(self, valid_lockfile, scanned_registry):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] == "shared_risk_classifier":
                e.pop("content_digest", None)
        _write_lockfile(valid_lockfile, lf)

        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is False
        assert any("content_digest missing" in e for e in errors)


# ── Denial condition 6: content_digest mismatch (tampered) ────────────────

class TestDigestTamperDenied:
    def test_tampered_digest_denied(self, valid_lockfile, scanned_registry):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] == "shared_risk_classifier":
                e["content_digest"] = "0" * 64  # tampered
        _write_lockfile(valid_lockfile, lf)

        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is False
        assert any("content_digest mismatch" in e for e in errors)

    def test_error_names_the_tampered_node(self, valid_lockfile, scanned_registry):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] == "shared_trace_collector":
                e["content_digest"] = "f" * 64
        _write_lockfile(valid_lockfile, lf)

        ok, errors = enforce_lockfile_for_nodes(
            SHARED_NODE_IDS, lockfile_path=valid_lockfile, registry=scanned_registry,
        )
        assert ok is False
        assert any("shared_trace_collector" in e for e in errors)


# ── Denial condition 7: package not admitted by registry ──────────────────

class TestPackageNotAdmittedDenied:
    def test_unadmitted_node_denied(self, valid_lockfile, scanned_registry):
        """A node that is in the lockfile but not currently admitted by the
        registry must be denied."""
        ok, errors = enforce_lockfile_for_nodes(
            ["shared_risk_classifier", "definitely_not_a_real_node"],
            lockfile_path=valid_lockfile,
            registry=scanned_registry,
        )
        assert ok is False
        assert any("definitely_not_a_real_node" in e for e in errors)


# ── Digest length guards (prevent regression to truncated digest) ─────────

class TestDigestLengthGuards:
    """The enforcement digest must be full-length; guard against regression."""

    def test_lockfile_contains_full_length_digests(self, valid_lockfile):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] in SHARED_NODE_IDS:
                digest = e.get("content_digest")
                assert digest is not None, f"{e['node_id']}: content_digest missing"
                assert len(digest) == 64, \
                    f"{e['node_id']}: content_digest must be 64 chars, got {len(digest)}"

    def test_display_hash_is_shorter_than_enforcement_digest(self, valid_lockfile):
        lf = _load_lockfile(valid_lockfile)
        for e in lf["packages"]:
            if e["node_id"] in SHARED_NODE_IDS:
                assert len(e["content_hash"]) < len(e["content_digest"]), \
                    f"{e['node_id']}: content_hash must be shorter than content_digest"
