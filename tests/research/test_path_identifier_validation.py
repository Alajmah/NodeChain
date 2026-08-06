"""Path identifier validation tests for the per-run workspace layout.

Proves that run_id and review_id are validated before filesystem use and
that unsafe identifiers are rejected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.run_descriptor import (
    _validate_identifier,
    run_dir,
    descriptor_path,
    review_path,
    outcome_path,
)


# --------------------------------------------------------------------------- #
# Identifier validation
# --------------------------------------------------------------------------- #


def test_valid_uuid_accepted() -> None:
    assert _validate_identifier("abc123-def4-5678-9abc-def012345678") == \
        "abc123-def4-5678-9abc-def012345678"


def test_simple_alphanumeric_accepted() -> None:
    assert _validate_identifier("src-1") == "src-1"


@pytest.mark.parametrize("bad_id", [
    "",
    "..",
    "../etc/passwd",
    "/etc/passwd",
    "foo/bar",
    "foo\\bar",
    "C:\\Users",
    "\\\\server\\share",
    "foo;rm -rf /",
    "foo\x00bar",
])
def test_unsafe_identifiers_rejected(bad_id: str) -> None:
    with pytest.raises((ValueError, TypeError)):
        _validate_identifier(bad_id)


# --------------------------------------------------------------------------- #
# Path construction uses validated identifiers
# --------------------------------------------------------------------------- #


def test_run_dir_stays_under_workspace() -> None:
    import os
    ws = "/tmp/test_workspace"
    rd = run_dir(ws, "abc-123")
    # Verify the resolved path is under the workspace
    assert str(rd.resolve()).startswith(str(Path(ws).resolve()))
    assert "runs" in str(rd)
    assert "abc-123" in str(rd)


def test_descriptor_path_uses_run_dir() -> None:
    p = descriptor_path("/tmp/ws", "run-1")
    assert p.name == "descriptor.json"
    assert "runs" in str(p)
    assert "run-1" in str(p)


def test_review_path_uses_reviews_subdir() -> None:
    p = review_path("/tmp/ws", "run-1", "rev-1")
    assert p.name == "rev-1.json"
    assert "reviews" in str(p)


def test_outcome_path_uses_outcomes_subdir() -> None:
    p = outcome_path("/tmp/ws", "run-1", "rev-1")
    assert p.name == "rev-1.json"
    assert "outcomes" in str(p)


def test_traversal_run_id_rejected_in_run_dir() -> None:
    with pytest.raises((ValueError, TypeError)):
        run_dir("/tmp/ws", "../../etc")


def test_traversal_review_id_rejected() -> None:
    with pytest.raises((ValueError, TypeError)):
        review_path("/tmp/ws", "run-1", "../../etc")
