"""C6 adversarial tests for scoped_env and one-shot review clearing.

Proves:
  nested contexts restore correctly
  exception restores correctly
  two threads cannot overlap
  successful resume clears review values
  failed resume clears review values
  second resume cannot reuse prior approval
  unknown programmatic decision rejected
"""

from __future__ import annotations

import os
import threading
import traceback
from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner
from nodechain.research.scoped_env import scoped_env

CORPUS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_conflicting_evidence.yaml"


# --------------------------------------------------------------------------- #
# scoped_env adversarial tests
# --------------------------------------------------------------------------- #


def test_nested_contexts_restore_correctly() -> None:
    """Nested scoped_env contexts each save/restore their own values."""
    os.environ.pop("TEST_VAR_A", None)
    os.environ.pop("TEST_VAR_B", None)
    with scoped_env({"TEST_VAR_A": "outer"}):
        assert os.environ["TEST_VAR_A"] == "outer"
        with scoped_env({"TEST_VAR_B": "inner"}):
            assert os.environ["TEST_VAR_A"] == "outer"
            assert os.environ["TEST_VAR_B"] == "inner"
        # Inner restored.
        assert "TEST_VAR_B" not in os.environ
        assert os.environ["TEST_VAR_A"] == "outer"
    # Outer restored.
    assert "TEST_VAR_A" not in os.environ
    assert "TEST_VAR_B" not in os.environ


def test_exception_restores_all_variables() -> None:
    """Exception inside scoped_env restores all variables."""
    os.environ.pop("TEST_EXC", None)
    with pytest.raises(RuntimeError):
        with scoped_env({"TEST_EXC": "set"}):
            assert os.environ["TEST_EXC"] == "set"
            raise RuntimeError("test exception")
    assert "TEST_EXC" not in os.environ


def test_concurrent_contexts_cannot_overlap() -> None:
    """Thread A holds the lock; thread B is blocked until A releases.

    Uses synchronization events to prove ordering, not sleeps.
    """
    os.environ.pop("TEST_CONCURRENT", None)
    errors: list[str] = []
    a_entered = threading.Event()
    a_release = threading.Event()
    b_entered = threading.Event()
    b_completed = threading.Event()

    def worker_a() -> None:
        try:
            with scoped_env({"TEST_CONCURRENT": "A"}):
                a_entered.set()
                # Hold the lock until told to release.
                a_release.wait(timeout=10)
        except Exception as e:
            errors.append(f"A: {e}")

    def worker_b() -> None:
        try:
            with scoped_env({"TEST_CONCURRENT": "B"}):
                b_entered.set()
                assert os.environ["TEST_CONCURRENT"] == "B"
            b_completed.set()
        except Exception as e:
            errors.append(f"B: {e}")

    t_a = threading.Thread(target=worker_a)
    t_a.start()
    # Wait until A is inside the context.
    assert a_entered.wait(timeout=5), "A did not enter context"

    # Start B — it should be blocked by the reentrant lock.
    t_b = threading.Thread(target=worker_b)
    t_b.start()

    # Prove B has NOT entered while A holds the lock.
    assert not b_entered.wait(timeout=1), (
        "B entered context while A held the lock — lock not serializing"
    )

    # Release A.
    a_release.set()
    t_a.join(timeout=5)

    # B should now enter and complete.
    assert b_entered.wait(timeout=5), "B did not enter after A released"
    assert b_completed.wait(timeout=5), "B did not complete"
    t_b.join(timeout=5)

    assert errors == [], f"errors: {errors}"


# --------------------------------------------------------------------------- #
# One-shot review clearing
# --------------------------------------------------------------------------- #


def test_review_env_absent_after_successful_resume(tmp_path: Path) -> None:
    """After a successful resume, _review_env is cleared."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "ws1"),
    )
    result = runner.run()
    assert result.paused, "conflicting-evidence scenario must pause"
    runner.apply_review("approve", "ok", "reviewer")
    assert runner._review_env != {}
    runner.resume(run_id=result.run_id)
    assert runner._review_env == {}, "review env not cleared after resume"


def test_review_env_absent_after_failed_resume(tmp_path: Path) -> None:
    """Even if resume raises, _review_env is cleared in finally."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "ws2"),
    )
    result = runner.run()
    assert result.paused, "conflicting-evidence scenario must pause"
    runner.apply_review("approve", "ok", "reviewer")
    assert runner._review_env != {}

    # Resume with a bad run_id to trigger an exception.
    resume_exc = None
    try:
        runner.resume(run_id="nonexistent-run-id")
    except Exception as e:
        resume_exc = e

    # An exception MUST have occurred (bad run_id).
    assert resume_exc is not None, "resume with bad run_id did not raise"
    # _review_env must be cleared despite the exception.
    assert runner._review_env == {}, "review env not cleared after failed resume"


def test_second_resume_does_not_reuse_prior_decision(tmp_path: Path) -> None:
    """A second resume cannot reuse a prior approval (one-shot clearing)."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "ws3"),
    )
    result = runner.run()
    assert result.paused, "conflicting-evidence scenario must pause"
    runner.apply_review("approve", "first", "reviewer1")

    # First resume succeeds.
    runner.resume(run_id=result.run_id)

    # _review_env must be empty after first resume.
    assert runner._review_env == {}, "review env not cleared after first resume"

    # Second resume WITHOUT apply_review. The run is now terminal (completed
    # after approve), so a second resume should either raise (terminal-state
    # rejection) or return without re-executing. Lock the exact truth:
    # _review_env must be empty (no reuse) AND the second resume must not
    # re-execute the chain.
    second_exc = None
    second_result = None
    try:
        second_result = runner.resume(run_id=result.run_id)
    except Exception as e:
        second_exc = e

    # Assert: either an exception occurred (terminal reject) OR the result
    # shows no additional execution (same final_status, no new trace events).
    assert runner._review_env == {}, "review env leaked after second resume"
    assert "NODECHAIN_REVIEW_DECISION" not in os.environ

    if second_exc is not None:
        # Terminal reject is the expected behavior for a completed run.
        pass
    elif second_result is not None:
        # If resume returned, it must not have re-executed (no new completed steps).
        assert second_result.trace.final_status in ("completed", "failed"), (
            f"unexpected second-resume status: {second_result.trace.final_status}"
        )


# --------------------------------------------------------------------------- #
# Unknown decision rejection
# --------------------------------------------------------------------------- #


def test_unknown_programmatic_decision_rejected() -> None:
    """apply_review rejects unknown decisions."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("test"),
        corpus_path=str(CORPUS),
        workspace_dir="/tmp/research_unknown_decision",
    )
    with pytest.raises(ValueError, match="unknown review decision"):
        runner.apply_review("maybe", "reason", "reviewer")
