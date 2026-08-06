"""Unit tests for the QualifiedSourceLinkerNode.

Each test exercises one exact acceptance or rejection condition.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import pytest

from nodechain.core.envelope import InvocationEnvelope, Capabilities
from nodechain.research.qualified_source_linker import (
    QualifiedSourceLinkageError,
    QualifiedSourceLinkerNode,
)


def _run_linker(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute the linker synchronously with the given payload."""
    linker = QualifiedSourceLinkerNode()
    envelope = InvocationEnvelope(
        run_id="test-run",
        chain_id="test-chain",
        node_id="qualified_source_linker",
        step_id=7,
        payload=payload,
        capabilities=Capabilities(),
    )
    result = asyncio.run(linker.execute(envelope))
    return result.output


def _make_source(source_id: str, title: str = "Test") -> dict[str, Any]:
    """Create a valid ingested source with artifact_ref."""
    fields = {
        "source_id": source_id,
        "title": title,
        "authors": ["Author"],
        "abstract": "Abstract.",
        "doi": "",
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        **fields,
        "source_hash": h,
        "artifact_ref": f"ingested:{source_id}:{h}",
        "origin_api": "fixture",
    }


def _make_qualified(source_id: str, included: bool = True) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "quality_score": 0.8,
        "included": included,
    }


# --------------------------------------------------------------------------- #
# Positive tests
# --------------------------------------------------------------------------- #


def test_valid_two_source_linkage() -> None:
    s1 = _make_source("src-1")
    s2 = _make_source("src-2")
    payload = {
        "qualified_sources": [_make_qualified("src-1"), _make_qualified("src-2")],
        "sources": [s1, s2],
        "quality_summary": "ok",
        "loop_required": False,
    }
    output = _run_linker(payload)
    linked = output["linked_sources"]
    assert len(linked) == 2
    for l in linked:
        assert l.get("artifact_ref", "").startswith("ingested:")
        assert l["source_hash"]
        assert l["source_hash"] == next(
            s for s in [s1, s2] if s["source_id"] == l["source_id"]
        )["source_hash"]


def test_excluded_source_not_linked() -> None:
    s1 = _make_source("src-1")
    s2 = _make_source("src-2")
    payload = {
        "qualified_sources": [
            _make_qualified("src-1", included=True),
            _make_qualified("src-2", included=False),
        ],
        "sources": [s1, s2],
    }
    output = _run_linker(payload)
    assert len(output["linked_sources"]) == 1
    assert output["linked_sources"][0]["source_id"] == "src-1"
    assert len(output["excluded_sources"]) == 1
    assert output["excluded_sources"][0]["source_id"] == "src-2"


def test_empty_qualified_set() -> None:
    payload = {
        "qualified_sources": [],
        "sources": [_make_source("src-1")],
    }
    output = _run_linker(payload)
    assert output["linked_sources"] == []
    assert output["linkage_verified"] is True


# --------------------------------------------------------------------------- #
# Negative tests — each asserts exact reason_code
# --------------------------------------------------------------------------- #


def test_unknown_qualified_source_id_rejected() -> None:
    payload = {
        "qualified_sources": [_make_qualified("src-unknown")],
        "sources": [_make_source("src-1")],
    }
    with pytest.raises(QualifiedSourceLinkageError, match="QUALIFIED_SOURCE_NOT_INGESTED"):
        _run_linker(payload)


def test_missing_ingested_source_hash_rejected() -> None:
    source = _make_source("src-1")
    del source["source_hash"]
    payload = {
        "qualified_sources": [_make_qualified("src-1")],
        "sources": [source],
    }
    with pytest.raises(QualifiedSourceLinkageError, match="INGESTED_SOURCE_HASH_MISSING"):
        _run_linker(payload)


def test_missing_artifact_ref_rejected() -> None:
    source = _make_source("src-1")
    del source["artifact_ref"]
    payload = {
        "qualified_sources": [_make_qualified("src-1")],
        "sources": [source],
    }
    with pytest.raises(QualifiedSourceLinkageError, match="INGESTED_SOURCE_REF_MISSING"):
        _run_linker(payload)


def test_missing_source_id_rejected() -> None:
    payload = {
        "qualified_sources": [{"quality_score": 0.8, "included": True}],  # no source_id
        "sources": [_make_source("src-1")],
    }
    with pytest.raises(QualifiedSourceLinkageError, match="QUALIFIED_SOURCE_MISSING_ID"):
        _run_linker(payload)


def test_artifact_ref_mismatch_rejected() -> None:
    source = _make_source("src-1")
    source["artifact_ref"] = "ingested:src-2:wronghash"  # wrong ref
    payload = {
        "qualified_sources": [_make_qualified("src-1")],
        "sources": [source],
    }
    with pytest.raises(QualifiedSourceLinkageError, match="INGESTED_SOURCE_REF_MISMATCH"):
        _run_linker(payload)


def test_duplicate_ingested_ids_rejected() -> None:
    s1 = _make_source("src-1")
    payload = {
        "qualified_sources": [_make_qualified("src-1")],
        "sources": [s1, dict(s1)],  # exact duplicate
    }
    with pytest.raises(QualifiedSourceLinkageError, match="DUPLICATE_INGESTED_SOURCE_ID"):
        _run_linker(payload)


def test_duplicate_qualified_ids_rejected() -> None:
    s1 = _make_source("src-1")
    payload = {
        "qualified_sources": [_make_qualified("src-1"), _make_qualified("src-1")],
        "sources": [s1],
    }
    with pytest.raises(QualifiedSourceLinkageError, match="DUPLICATE_QUALIFIED_SOURCE_ID"):
        _run_linker(payload)
