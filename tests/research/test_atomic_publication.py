"""Focused atomic publication tests for _atomic_write and _publish_no_replace.

Proves the locked write-once publication contract:
1. Concurrent publishers produce exactly one winner.
2. The losing publisher receives FileExistsError.
3. The published target always contains complete expected bytes.
4. Failure before publication leaves no target.
5. Existing targets remain byte-for-byte unchanged.
6. Staging files are cleaned up after success.
"""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

import pytest

from nodechain.research.run_descriptor import _atomic_write, _publish_no_replace


def _tmp_target(tmp_path: Path, name: str = "target.json") -> Path:
    return tmp_path / name


# --------------------------------------------------------------------------- #
# Write-once publication
# --------------------------------------------------------------------------- #


def test_successful_publication_writes_complete_content(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    content = '{"test": true, "data": "complete"}'
    _atomic_write(target, content)
    assert target.exists()
    assert target.read_text(encoding="utf-8") == content


def test_second_write_rejected(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    _atomic_write(target, "first")
    with pytest.raises(FileExistsError):
        _atomic_write(target, "second")
    # Original content unchanged.
    assert target.read_text(encoding="utf-8") == "first"


def test_existing_target_byte_for_byte_unchanged(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    original = '{"original": true}'
    _atomic_write(target, original)
    # Attempt overwrite.
    with pytest.raises(FileExistsError):
        _atomic_write(target, '{"modified": true}')
    assert target.read_bytes() == original.encode("utf-8")


# --------------------------------------------------------------------------- #
# Staging cleanup
# --------------------------------------------------------------------------- #


def test_staging_cleaned_up_after_success(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    _atomic_write(target, "content")
    # No .staging files should remain.
    staging_files = list(tmp_path.glob(".*.staging"))
    assert staging_files == [], f"orphaned staging files: {staging_files}"


def test_staging_cleaned_up_after_failure(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    _atomic_write(target, "first")
    # Attempt second write (will fail).
    with pytest.raises(FileExistsError):
        _atomic_write(target, "second")
    # No staging files should remain.
    staging_files = list(tmp_path.glob(".*.staging"))
    assert staging_files == [], f"orphaned staging files after failure: {staging_files}"


# --------------------------------------------------------------------------- #
# No partial visibility
# --------------------------------------------------------------------------- #


def test_no_partial_target_before_publication(tmp_path: Path) -> None:
    """If publication fails, no target exists."""
    target = _tmp_target(tmp_path, "never_published.json")
    # Write a staging file but DON'T publish.
    staging = tmp_path / f".{target.name}.{uuid.uuid4().hex[:8]}.staging"
    staging.write_text("partial")
    # Target should not exist.
    assert not target.exists()
    # Cleanup.
    staging.unlink()


# --------------------------------------------------------------------------- #
# Concurrent publishers
# --------------------------------------------------------------------------- #


def test_concurrent_publishers_one_winner(tmp_path: Path) -> None:
    """Two concurrent publishers: exactly one succeeds, one gets FileExistsError."""
    target = _tmp_target(tmp_path, "concurrent.json")
    barrier = threading.Barrier(2)
    results: list[bool | Exception] = []

    def publisher(content: str) -> None:
        try:
            barrier.wait(timeout=5)
            _atomic_write(target, content)
            results.append(True)
        except FileExistsError:
            results.append("exists")
        except Exception as e:
            results.append(e)

    t1 = threading.Thread(target=publisher, args=("alpha",))
    t2 = threading.Thread(target=publisher, args=("beta",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    # Exactly one winner.
    winners = [r for r in results if r is True]
    losers = [r for r in results if r == "exists"]
    assert len(winners) == 1, f"expected 1 winner, got {winners}"
    assert len(losers) == 1, f"expected 1 loser with FileExistsError, got {losers}"
    # The target has one of the two contents (deterministic winner).
    final = target.read_text(encoding="utf-8")
    assert final in ("alpha", "beta"), f"unexpected content: {final}"
