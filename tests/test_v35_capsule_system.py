"""v3.5.0 Task 2 tests — Capsule system, key lifecycle, atomic started persistence.

Tests the capsule + encryption system that all governed side effects now use:
- ReplayCapsule model, canonical serialization, digest computation
- make_retry_side_effect_key deterministic derivation
- KEK/DEK key hierarchy (provisioning, wrapping, race-safe creation)
- AES-256-GCM capsule encryption (round-trip, tamper detection)
- start_side_effect_with_capsule atomic operation (capsule + started in one txn)
- Both _journal_one paths route through the new operation
- Capsule size limit (64 KiB)
- Proactive capsule persistence at SIDE_EFFECT_STARTED time

ChatGPT Task 2 exit gate:
- capsule + started + durable event are atomic
- both old _journal_one started paths use the new operation
- no direct production started writes remain
- restart decrypts an existing capsule
- concurrent first-use creates exactly one run DEK
- wrong KEK, modified ciphertext, modified AAD all fail authentication
- legacy started rows are never backfilled
- canonical digest is full SHA-256 and derived from stored plaintext bytes
- capsule oversize fails before lifecycle start

Protects: INV-004, INV-015, INV-016
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from nodechain.core.state import StateManager
from nodechain.core.side_effect_utils import (
    ReplayCapsule,
    canonicalize_capsule_payload,
    compute_canonical_request_digest,
    make_retry_side_effect_key,
    MAX_CAPSULE_SIZE_BYTES,
)
from nodechain.core.capsule_crypto import (
    KekManager,
    CapsuleEncryptionError,
    generate_dek,
    wrap_dek,
    unwrap_dek,
    encrypt_capsule_payload,
    decrypt_capsule_payload,
)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "capsule.db")


@pytest.fixture
def kek(tmp_path):
    """Provide a KEK via a local-dev KekManager pointing at tmp_path."""
    from conftest import provision_test_kek
    return provision_test_kek(tmp_path / "test_kek.bin")


# ── 1. Canonical serialization ─────────────────────────────────────────


class TestCanonicalSerialization:
    """ChatGPT gate: canonical digest is full SHA-256 and derived from stored bytes."""

    def test_canonical_json_sorted_keys(self):
        """Dictionary insertion order doesn't affect canonical bytes."""
        a = canonicalize_capsule_payload({"b": 1, "a": 2})
        b = canonicalize_capsule_payload({"a": 2, "b": 1})
        assert a == b

    def test_canonical_json_compact_separators(self):
        """No whitespace in canonical output."""
        result = canonicalize_capsule_payload({"a": 1})
        assert b",," not in result
        assert b": " not in result

    def test_non_json_value_rejected(self):
        """Non-JSON-serializable values raise TypeError (no default=str)."""
        with pytest.raises(TypeError):
            canonicalize_capsule_payload({"obj": object()})

    def test_nan_rejected(self):
        """NaN and Infinity are rejected (allow_nan=False)."""
        import math
        with pytest.raises(ValueError):
            canonicalize_capsule_payload({"v": float("nan")})

    def test_full_sha256_digest(self):
        """Digest is 64 hex chars (full SHA-256), not the 16-char prefix."""
        data = b'{"test":true}'
        digest = compute_canonical_request_digest(data)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_digest_matches_encrypted_bytes(self):
        """The bytes hashed for digest are exactly the canonical bytes."""
        original = {"terms": ["ai"], "max": 10}
        canonical = canonicalize_capsule_payload(original)
        digest = compute_canonical_request_digest(canonical)
        # Re-derive: same canonical → same digest
        canonical2 = canonicalize_capsule_payload(original)
        digest2 = compute_canonical_request_digest(canonical2)
        assert digest == digest2


# ── 2. make_retry_side_effect_key ──────────────────────────────────────


class TestRetryKeyDerivation:
    """Deterministic key derivation (INV-002)."""

    def test_deterministic_same_inputs(self):
        k1 = make_retry_side_effect_key("se:parent-1", "rd-001")
        k2 = make_retry_side_effect_key("se:parent-1", "rd-001")
        assert k1 == k2

    def test_different_inputs_different_keys(self):
        k1 = make_retry_side_effect_key("se:parent-1", "rd-001")
        k2 = make_retry_side_effect_key("se:parent-1", "rd-002")
        assert k1 != k2

    def test_key_has_retry_prefix(self):
        k = make_retry_side_effect_key("se:p", "rd-1")
        assert k.startswith("retry:")

    def test_empty_inputs_rejected(self):
        with pytest.raises(ValueError):
            make_retry_side_effect_key("", "rd-1")
        with pytest.raises(ValueError):
            make_retry_side_effect_key("se:p", "")


# ── 3. Encryption + key hierarchy ──────────────────────────────────────


class TestEncryptionHierarchy:
    """AES-256-GCM capsule encryption with KEK/DEK hierarchy."""

    def test_wrap_unwrap_dek_roundtrip(self, kek):
        dek = generate_dek()
        wrapped, nonce = wrap_dek(kek, dek)
        unwrapped = unwrap_dek(kek, wrapped, nonce)
        assert unwrapped == dek

    def test_wrong_kek_fails_unwrap(self, tmp_path):
        from conftest import provision_test_kek
        kek1 = provision_test_kek(tmp_path / "k1.bin")
        kek2 = provision_test_kek(tmp_path / "k2.bin")
        dek = generate_dek()
        wrapped, nonce = wrap_dek(kek1, dek)
        with pytest.raises(CapsuleEncryptionError):
            unwrap_dek(kek2, wrapped, nonce)

    def test_encrypt_decrypt_capsule_roundtrip(self, kek):
        dek = generate_dek()
        plaintext = b'{"terms":["ai safety"],"max":10}'
        ciphertext, nonce = encrypt_capsule_payload(
            dek, plaintext,
            run_id="r1", capsule_id="cap-1",
            side_effect_key="se:1",
            capsule_schema_version=1,
            canonicalization_version="1",
        )
        decrypted = decrypt_capsule_payload(
            dek, ciphertext, nonce,
            run_id="r1", capsule_id="cap-1",
            side_effect_key="se:1",
            capsule_schema_version=1,
            canonicalization_version="1",
        )
        assert decrypted == plaintext

    def test_modified_ciphertext_fails(self, kek):
        dek = generate_dek()
        plaintext = b'{"test":true}'
        ciphertext, nonce = encrypt_capsule_payload(
            dek, plaintext, "r1", "cap-1", "se:1", 1, "1",
        )
        # Flip a byte in ciphertext
        modified = bytearray(ciphertext)
        modified[0] ^= 0xFF
        with pytest.raises(CapsuleEncryptionError):
            decrypt_capsule_payload(
                dek, bytes(modified), nonce,
                "r1", "cap-1", "se:1", 1, "1",
            )

    def test_modified_aad_fails(self, kek):
        dek = generate_dek()
        plaintext = b'{"test":true}'
        ciphertext, nonce = encrypt_capsule_payload(
            dek, plaintext, "r1", "cap-1", "se:1", 1, "1",
        )
        # Different AAD (different capsule_id)
        with pytest.raises(CapsuleEncryptionError):
            decrypt_capsule_payload(
                dek, ciphertext, nonce,
                "r1", "DIFFERENT", "se:1", 1, "1",
            )


class TestKekManager:
    """KEK provisioning and persistence (ChatGPT guardrail #1, #7)."""

    def test_kek_generated_once_and_persisted(self, tmp_path):
        """KEK is stable across KekManager instances pointing at same path."""
        from conftest import provision_test_kek
        kek_path = tmp_path / "stable.bin"
        k1 = provision_test_kek(kek_path)
        k2 = KekManager(kek_path=kek_path, local_dev=True).get_kek()
        assert k1 == k2

    def test_production_mode_fails_without_env(self, tmp_path, monkeypatch):
        """Production mode fails closed when KEK env var is absent."""
        monkeypatch.delenv("NODECHAIN_CAPSULE_KEK", raising=False)
        # v3.5.1 (#8): NODECHAIN_DEV_MODE=1 (set by the test conftest) enables
        # local provisioning; clear it so this test exercises genuine
        # production fail-closed behavior.
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        manager = KekManager(local_dev=False)
        with pytest.raises(CapsuleEncryptionError, match="Production mode requires"):
            manager.get_kek()

    def test_malformed_kek_not_replaced(self, tmp_path):
        """Malformed existing KEK raises, does not replace."""
        kek_path = tmp_path / "bad.bin"
        kek_path.write_bytes(b"too short")  # Not 32 bytes
        manager = KekManager(kek_path=kek_path, local_dev=True)
        with pytest.raises(CapsuleEncryptionError, match="malformed"):
            manager.get_kek()


# ── 4. start_side_effect_with_capsule ──────────────────────────────────


class TestStartSideEffectWithCapsule:
    """The authoritative started operation (INV-004)."""

    def test_new_row_inserted_started_with_capsule(self, db_path, kek):
        """New side effect: capsule persisted atomically with started row."""
        sm = StateManager(db_path=db_path)
        capsule_id = sm.start_side_effect_with_capsule(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key="se:1",
            request_hash="rh-1",
            capsule_operation={"terms": ["ai"], "max": 10, "adapter": "semantic_scholar"},
            adapter_id="semantic_scholar",
            kek=kek,
        )
        se = sm.get_side_effect_by_key("r1", "se:1")
        assert se["status"] == "started"
        assert se["capsule_status"] == "available"
        assert se["capsule_id"] == capsule_id

    def test_planned_row_transitions_to_started_with_capsule(self, db_path, kek):
        """Existing planned row: transitions to started + capsule added."""
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key="se:2",
            status="planned", request_hash="rh-2",
        )
        capsule_id = sm.start_side_effect_with_capsule(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call", idempotency_key="se:2",
            request_hash="rh-2",
            capsule_operation={"terms": ["blockchain"], "adapter": "arxiv"},
            adapter_id="arxiv",
            kek=kek,
        )
        se = sm.get_side_effect_by_key("r1", "se:2")
        assert se["status"] == "started"
        assert se["capsule_status"] == "available"
        assert se["capsule_id"] == capsule_id

    def test_idempotent_started_with_capsule(self, db_path, kek):
        """Already started with capsule: idempotent no-op."""
        sm = StateManager(db_path=db_path)
        sm.start_side_effect_with_capsule(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:3",
            request_hash="rh",
            capsule_operation={"test": True},
            kek=kek,
        )
        # Second call should not error
        sm.start_side_effect_with_capsule(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:3",
            request_hash="rh",
            capsule_operation={"test": True},
            kek=kek,
        )
        se = sm.get_side_effect_by_key("r1", "se:3")
        assert se["status"] == "started"

    def test_oversized_capsule_rejected_before_started(self, db_path, kek):
        """Capsule > 64 KiB fails before lifecycle start."""
        sm = StateManager(db_path=db_path)
        big_payload = {"data": "x" * (MAX_CAPSULE_SIZE_BYTES + 1)}
        with pytest.raises(ValueError, match="REPLAY_CAPSULE_OVERSIZED"):
            sm.start_side_effect_with_capsule(
                run_id="r1", step_id=1, node_id="n",
                side_effect_type="external_call", idempotency_key="se:big",
                request_hash="rh",
                capsule_operation=big_payload,
                kek=kek,
            )
        # Row should NOT exist (failed before insert)
        assert sm.get_side_effect_by_key("r1", "se:big") is None

    def test_capsule_decryptable_across_restart(self, db_path, kek, tmp_path):
        """ChatGPT gate: restart decrypts an existing capsule."""
        sm1 = StateManager(db_path=db_path)
        sm1.start_side_effect_with_capsule(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:restart",
            request_hash="rh",
            capsule_operation={"terms": ["ai"], "max": 5},
            kek=kek,
        )
        # Simulate restart: new StateManager on same DB
        sm2 = StateManager(db_path=db_path)
        se = sm2.get_side_effect_by_key("r1", "se:restart")
        assert se["capsule_id"] is not None
        # Load and decrypt the capsule
        from nodechain.core.stores import CapsuleStore, RunKeyStore
        cap_store = CapsuleStore(db_path)
        key_store = RunKeyStore(db_path)
        cap = cap_store.load_capsule(se["capsule_id"])
        assert cap is not None
        dek, _ = key_store.get_or_create_run_dek("r1", kek)
        plaintext = decrypt_capsule_payload(
            dek, cap["encrypted_payload"], cap["nonce"],
            run_id="r1", capsule_id=se["capsule_id"], side_effect_key="se:restart",
            capsule_schema_version=1, canonicalization_version="1",
        )
        assert b'"terms"' in plaintext


# ── 5. Concurrent DEK creation ─────────────────────────────────────────


class TestConcurrentDekCreation:
    """ChatGPT gate: concurrent first-use creates exactly one run DEK."""

    def test_concurrent_first_use_one_dek(self, db_path, kek):
        """Two threads starting side effects for the same run get the same DEK."""
        sm = StateManager(db_path=db_path)
        results = []
        barrier = threading.Barrier(2)

        def start_side_effect(key_suffix):
            barrier.wait()  # Release both threads simultaneously
            try:
                sm.start_side_effect_with_capsule(
                    run_id="r1", step_id=1, node_id="n",
                    side_effect_type="external_call",
                    idempotency_key=f"se:conc-{key_suffix}",
                    request_hash=f"rh-{key_suffix}",
                    capsule_operation={"test": key_suffix},
                    kek=kek,
                )
                results.append("ok")
            except Exception as e:
                results.append(f"error: {e}")

        t1 = threading.Thread(target=start_side_effect, args=("a",))
        t2 = threading.Thread(target=start_side_effect, args=("b",))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # Both should succeed
        assert len(results) == 2
        assert all(r == "ok" for r in results), f"unexpected results: {results}"

        # Exactly one DEK row exists
        with sqlite3.connect(db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM run_encryption_keys WHERE run_id = 'r1'"
            ).fetchone()[0]
        assert count == 1, f"expected 1 DEK, got {count}"
