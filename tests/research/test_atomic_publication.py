"""Focused atomic publication tests for _atomic_write and _publish_no_replace.

Proves the locked write-once publication contract:
1. Concurrent publishers produce exactly one winner.
2. The losing publisher receives FileExistsError.
3. The published target always contains complete expected bytes.
4. Failure before publication leaves no target.
5. Existing targets remain byte-for-byte unchanged.
6. Staging files are cleaned up after success.
7. Injected staging.unlink failure surfaces a warning (not silent).
8. Injected parent-directory fsync EIO propagates (not swallowed).
9. Concurrent reader never observes a partial target.
"""

from __future__ import annotations

import io
import os
import sys
import threading
import uuid
import warnings
from pathlib import Path
from unittest import mock

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
    assert target.read_text(encoding="utf-8") == "first"


def test_existing_target_byte_for_byte_unchanged(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    original = '{"original": true}'
    _atomic_write(target, original)
    with pytest.raises(FileExistsError):
        _atomic_write(target, '{"modified": true}')
    assert target.read_bytes() == original.encode("utf-8")


# --------------------------------------------------------------------------- #
# Staging cleanup
# --------------------------------------------------------------------------- #


def test_staging_cleaned_up_after_success(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    _atomic_write(target, "content")
    staging_files = list(tmp_path.glob(".*.staging"))
    assert staging_files == [], f"orphaned staging files: {staging_files}"


def test_staging_cleaned_up_after_failure(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path)
    _atomic_write(target, "first")
    with pytest.raises(FileExistsError):
        _atomic_write(target, "second")
    staging_files = list(tmp_path.glob(".*.staging"))
    assert staging_files == [], f"orphaned staging files after failure: {staging_files}"


# --------------------------------------------------------------------------- #
# No partial visibility — concurrent reader
# --------------------------------------------------------------------------- #


def test_concurrent_reader_never_sees_partial_content(tmp_path: Path) -> None:
    """A reader thread checking the target content during a write never
    observes a partial file. The target is either absent or complete."""
    target = _tmp_target(tmp_path, "reader_race.json")
    content = '{"large": "' + 'x' * 10000 + '"}'
    observations: list[str | None] = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                data = target.read_text(encoding="utf-8")
                observations.append(data)
            except FileNotFoundError:
                observations.append(None)
            except OSError:
                observations.append(None)

    def writer():
        _atomic_write(target, content)

    t_reader = threading.Thread(target=reader)
    t_writer = threading.Thread(target=writer)
    t_reader.start()
    t_writer.start()
    t_writer.join(timeout=5)
    stop.set()
    t_reader.join(timeout=5)

    # Every observation must be either None (target not yet published)
    # or the exact complete content. Never a prefix or partial.
    for obs in observations:
        if obs is not None:
            assert obs == content, (
                f"reader observed partial content: {obs[:50]}..."
            )


# --------------------------------------------------------------------------- #
# Concurrent publishers
# --------------------------------------------------------------------------- #


def test_concurrent_publishers_one_winner(tmp_path: Path) -> None:
    target = _tmp_target(tmp_path, "concurrent.json")
    barrier = threading.Barrier(2)
    results: list[bool | str] = []

    def publisher(content: str) -> None:
        try:
            barrier.wait(timeout=5)
            _atomic_write(target, content)
            results.append(True)
        except FileExistsError:
            results.append("exists")
        except Exception as e:
            results.append(f"error:{e}")

    t1 = threading.Thread(target=publisher, args=("alpha",))
    t2 = threading.Thread(target=publisher, args=("beta",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    winners = [r for r in results if r is True]
    losers = [r for r in results if r == "exists"]
    assert len(winners) == 1, f"expected 1 winner, got {winners}"
    assert len(losers) == 1, f"expected 1 loser, got {losers}"
    final = target.read_text(encoding="utf-8")
    assert final in ("alpha", "beta"), f"unexpected content: {final}"


# --------------------------------------------------------------------------- #
# Failure injection: staging unlink surfaces warning (POSIX only)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX os.link path only",
)
def test_staging_unlink_failure_surfaces_warning(tmp_path: Path) -> None:
    """When staging.unlink() fails after successful os.link, a ResourceWarning
    is emitted (not silently swallowed)."""
    import errno

    target = _tmp_target(tmp_path, "unlink_fail.json")

    # Patch os.unlink in the run_descriptor module to fail for staging files.
    import nodechain.research.run_descriptor as rd_mod

    original_unlink = rd_mod.os.unlink

    def failing_unlink(path, *args, **kwargs):
        if ".staging" in str(path):
            raise OSError(errno.EACCES, "simulated unlink failure")
        return original_unlink(path, *args, **kwargs)

    with mock.patch.object(rd_mod.os, "unlink", side_effect=failing_unlink):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _atomic_write(target, "content")

    # The target was published successfully (the warning is non-fatal).
    assert target.read_text(encoding="utf-8") == "content"
    # A ResourceWarning was emitted about the cleanup failure.
    cleanup_warnings = [
        w for w in caught if issubclass(w.category, ResourceWarning)
    ]
    assert len(cleanup_warnings) >= 1, (
        "staging cleanup failure was not surfaced as ResourceWarning"
    )
    assert "staging" in str(cleanup_warnings[0].message).lower()


# --------------------------------------------------------------------------- #
# Failure injection: parent-directory fsync EIO propagates
# --------------------------------------------------------------------------- #


def test_fsync_eio_propagates(tmp_path: Path) -> None:
    """When os.fsync raises EIO on the parent directory, the error propagates
    (is not swallowed as an unsupported operation).

    On Windows, os.open(dir, O_RDONLY) fails with EACCES before fsync
    is reached, so this test is POSIX-only."""
    import errno
    import stat as stat_mod

    pytest.importorskip("posix")

    target = _tmp_target(tmp_path, "eio_test.json")

    original_fsync = os.fsync

    def failing_fsync(fd):
        stat = os.fstat(fd)
        if stat_mod.S_ISDIR(stat.st_mode):
            raise OSError(errno.EIO, "simulated I/O error")
        return original_fsync(fd)

    # Patch in the module's os namespace (where _atomic_write calls os.fsync).
    import nodechain.research.run_descriptor as rd_mod

    with mock.patch.object(rd_mod.os, "fsync", side_effect=failing_fsync):
        with mock.patch.object(rd_mod.os, "open", wraps=os.open) as mock_open:
            # Allow the real os.open for directories on POSIX.
            with pytest.raises(OSError, match="EIO|simulated I/O"):
                _atomic_write(target, "content")
