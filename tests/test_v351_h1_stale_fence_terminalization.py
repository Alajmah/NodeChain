"""v3.5.1 H1 — Fix #6: stale-fence terminalization must be child-truth driven.

v3.5.0 defect: when complete_recovery_attempt lost the fence, _terminalize
re-read the child but fell through to finalize the action as
``completed / adapter_confirmed_completion`` whenever the child was already
``failed``, ``unknown``, or missing — exactly the cases that indicate a
stale worker whose nominal adapter result must NOT override the
authoritative child ledger.

v3.5.1 contract (from the locked plan):

    child completed, compatible outcome  -> idempotent completed
    child failed                         -> action unknown/not_acquired, NEVER completed
    child unknown                        -> action unknown, NEVER completed
    child planned/started under another  -> action unknown/not_acquired
    child missing                        -> integrity failure (conservative), NEVER completed

The nominal adapter result must not override the child ledger.

These tests are written FIRST (RED) and watch the current code fail before
the child-truth fix lands.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone, timedelta

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.side_effect_retry_coordinator import (
    SideEffectRetryCoordinator,
)
from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    SearchQuery,
    SearchAdapterResult,
)


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture()
def kek(tmp_path):
    from nodechain.core.capsule_crypto import KekManager, CapsuleEncryptionError
    path = tmp_path / "h1_kek.bin"
    # Caller-level retry for OS write anomalies (manager hard-fails post-
    # publication; operator removes corrupt file and retries).
    for _ in range(8):
        try:
            return KekManager(kek_path=path, local_dev=True).get_kek()
        except CapsuleEncryptionError:
            if path.exists():
                path.unlink(missing_ok=True)
    pytest.fail("could not provision KEK fixture after 8 attempts")


class _FakeAdapter(BaseSearchAdapter):
    adapter_name = "semantic_scholar"
    adapter_version = "1.0.0"

    def build_url(self, query): return "https://fake.test/s"

    def build_params(self, query): return {"q": "+".join(query.terms)}

    def normalize_response(self, raw, query):
        return [SearchAdapterResult(
            origin_api="fake", raw_data=raw,
            query_used="+".join(query.terms),
            retrieved_at=datetime.now(timezone.utc).isoformat(),
        )]

    async def search(self, query):
        return self.normalize_response({"count": 1}, query)[:1]


def _make_coord(sm, kek):
    def factory(name): return _FakeAdapter()
    def trust(ad): return type(ad) is _FakeAdapter
    return SideEffectRetryCoordinator(
        sm, kek=kek, adapter_factory=factory, adapter_trust_validator=trust,
    )


def _setup_started_child(sm, run_id, parent_key, child_key, *, claim_id="claim-A"):
    """Stand up a started recovery child with the given claim."""
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id="search_tool",
        side_effect_type="external_call", idempotency_key=parent_key,
        status="retry_authorized", request_hash="rh",
    )
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id="search_tool",
        side_effect_type="external_call", idempotency_key=child_key,
        status="started", request_hash="rh",
    )
    now = datetime.now(timezone.utc)
    future = (now + timedelta(hours=1)).isoformat()
    with sqlite3.connect(sm.db_path) as conn:
        conn.execute(
            "UPDATE side_effect_ledger SET capsule_status='available', "
            "parent_side_effect_key=?, root_side_effect_key=?, retry_ordinal=1, "
            "execution_claim_id=?, claim_acquired_at=?, claim_expires_at=? "
            "WHERE run_id=? AND idempotency_key=?",
            (parent_key, parent_key, claim_id, now.isoformat(), future,
             run_id, child_key),
        )
        conn.execute(
            "UPDATE side_effect_ledger SET capsule_status='available' "
            "WHERE run_id=? AND idempotency_key=?",
            (run_id, parent_key),
        )
        conn.commit()
    sm.create_recovery_execution_action(
        action_id="act-stale", operator_action_id="oal-1", run_id=run_id,
        retry_attempt_key=child_key, execution_claim_id=claim_id,
    )
    sm.save(ChainState(run_id=run_id, chain_id="c", revision=0,
                       status="crashed", step=1))


# ── the truth table ────────────────────────────────────────────────────────


class TestStaleFenceTerminalizationCompleted:
    """outcome='completed' + lost fence: action must follow CHILD truth, never
    the stale worker's nominal adapter result."""

    def test_lost_fence_child_failed_never_completed(self, tmp_path, kek):
        """Stale worker reports completed, but authoritative child is failed.
        The action must NOT be finalized as completed."""
        db_path = str(tmp_path / "sf1.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        # Another worker reclaimed and FAILED the child under a different claim.
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET status='failed', "
                "execution_claim_id='claim-B' "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        # Stale worker A attempts to terminalize as completed; its fence CAS
        # must fail (claim is now B), and the action must NOT become completed.
        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="rh", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"stale worker finalized action as completed while child is failed; "
            f"got {action['execution_status']!r} / {action['outcome_code']!r}"
        )
        assert action["execution_status"] in ("unknown", "not_acquired"), (
            f"expected unknown/not_acquired for failed child, got {action['execution_status']!r}"
        )

    def test_lost_fence_child_unknown_never_completed(self, tmp_path, kek):
        """Stale worker reports completed, but authoritative child is unknown."""
        db_path = str(tmp_path / "sf2.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET status='unknown', "
                "execution_claim_id='claim-B' "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="rh", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"stale worker finalized action as completed while child is unknown; "
            f"got {action['execution_status']!r}"
        )

    def test_lost_fence_child_missing_never_completed(self, tmp_path, kek):
        """Stale worker reports completed, but the child row is gone (integrity
        failure). The action must be represented conservatively, never
        completed."""
        db_path = str(tmp_path / "sf3.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "DELETE FROM side_effect_ledger "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="rh", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"stale worker finalized action as completed while child is missing; "
            f"got {action['execution_status']!r}"
        )

    def test_lost_fence_child_reclaimed_in_flight_never_completed(self, tmp_path, kek):
        """Stale worker reports completed, but child was reclaimed and is
        started under another claim (in-flight). Action must not complete."""
        db_path = str(tmp_path / "sf4.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        # Another worker reclaimed and is dispatching under claim-B.
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET execution_claim_id='claim-B' "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="rh", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"stale worker finalized action as completed while child is in-flight "
            f"under another claim; got {action['execution_status']!r}"
        )

    def test_idempotent_completion_matching_nonempty_hashes(self, tmp_path, kek):
        """v3.5.1 (#6) B1: lost-fence child completed AND both response hashes
        are nonempty AND equal → idempotent completed. The ONLY non-conservative
        branch."""
        db_path = str(tmp_path / "sf5.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET status='completed', "
                "execution_claim_id='claim-B', response_hash='rh' "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="rh", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] == "completed", (
            f"matching hashes should converge completed; got {action['execution_status']!r}"
        )

    def test_completed_child_hash_mismatch_never_completed(self, tmp_path, kek):
        """v3.5.1 (#6) B1: child completed but stored hash differs from the
        stale worker's hash → unknown, never completed."""
        db_path = str(tmp_path / "sf6.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET status='completed', "
                "execution_claim_id='claim-B', response_hash='child-hash' "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="worker-hash", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"hash mismatch must not finalize completed; got {action['execution_status']!r}"
        )
        assert action["execution_status"] == "unknown"

    def test_completed_child_stored_hash_missing_never_completed(self, tmp_path, kek):
        """v3.5.1 (#6) B1: child completed but stored response_hash is absent
        → unknown (unverifiable), never completed."""
        db_path = str(tmp_path / "sf7.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET status='completed', "
                "execution_claim_id='claim-B', response_hash=NULL "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash="worker-hash", error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"missing stored hash must not finalize completed; got {action['execution_status']!r}"
        )

    def test_completed_child_worker_hash_missing_never_completed(self, tmp_path, kek):
        """v3.5.1 (#6) B1: child completed with a stored hash, but the stale
        worker's hash is absent → unknown (unverifiable), never completed."""
        db_path = str(tmp_path / "sf8.db")
        sm = StateManager(db_path=db_path)
        coord = _make_coord(sm, kek)
        run_id, parent, child = "r1", "se:parent", "retry:child1"
        _setup_started_child(sm, run_id, parent, child, claim_id="claim-A")

        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE side_effect_ledger SET status='completed', "
                "execution_claim_id='claim-B', response_hash='child-hash' "
                "WHERE run_id=? AND idempotency_key=?",
                (run_id, child),
            )
            conn.commit()

        coord._terminalize(
            run_id, child, "claim-A", "act-stale", "completed",
            response_hash=None, error=None,
        )
        action = sm.get_recovery_execution_action("act-stale")
        assert action["execution_status"] != "completed", (
            f"missing worker hash must not finalize completed; got {action['execution_status']!r}"
        )
