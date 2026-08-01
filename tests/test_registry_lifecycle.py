"""Registry Lifecycle Governance Tests (v2.21.3).

Tests governed lifecycle transitions: publish, deprecate, revoke,
signer rotation, and publisher authority changes.

Coverage:
    AC-1:  Lifecycle state machine (active→deprecated→revoked, terminal)
    AC-2:  Governed revocation (authorization required)
    AC-3:  Governed deprecation (authorization required)
    AC-4:  Signer rotation (LG-001 identity continuity, LG-002 auth)
    AC-5:  Publisher authority add/revoke (LG-007 auth, LG-010 preserve)
    AC-6:  Transition log append-only integrity (LG-008)
    AC-7:  Signed lifecycle receipts (LG-003)
    AC-8:  Generation advancement (LG-004)
    AC-9:  Key continuity chain (LG-009)
    AC-10: Multiple rotations preserve continuity
    AC-11: Unauthorized operations fail closed
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from nodechain.sdk.reference_registry_server import (
    RegistryState,
    ReferenceRegistryServer,
    ImmutablePackageRecord,
    PackageConflictError,
    UnauthorizedPublisherError,
    PackageRevokedError,
)
from nodechain.sdk.registry_lifecycle import (
    LifecycleGovernor,
    TransitionLog,
    LifecycleTransition,
    LifecycleReceipt,
    KeyContinuityRecord,
    LifecycleError,
    UnauthorizedRotationError,
    InvalidTransitionError,
    TerminalPackageError,
    TRANSITION_PUBLISH,
    TRANSITION_REVOKE,
    TRANSITION_DEPRECATE,
    TRANSITION_SIGNER_ROTATION,
    TRANSITION_PUBLISHER_ADD,
    TRANSITION_PUBLISHER_REVOKE,
    LIFECYCLE_TRANSITIONS,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

REGISTRY_ID = "reg-gov-001"
SIGNER_FP = "fp-signer-original"
PUBLISHER_FP = "fp-publisher"


@pytest.fixture
def state(tmp_path):
    s = RegistryState(tmp_path / "state.json")
    s.set_registry_identity(REGISTRY_ID, SIGNER_FP)
    s.approve_publisher("pub-001", PUBLISHER_FP, [])
    return s


@pytest.fixture
def server(tmp_path, state):
    return ReferenceRegistryServer(
        state_path=state.state_path,
        artifact_dir=tmp_path / "artifacts",
        registry_id=REGISTRY_ID,
        registry_signer_fingerprint=SIGNER_FP,
    )


@pytest.fixture
def transition_log(tmp_path):
    log = TransitionLog(tmp_path / "transition_log.json")
    log.set_registry_id(REGISTRY_ID)
    return log


@pytest.fixture
def governor(state, transition_log):
    return LifecycleGovernor(state, transition_log)


@pytest.fixture
def populated_governor(governor, server):
    """Governor with a published package."""
    server.publish("pkg_a", "1.0.0", b"data", publisher_fingerprint=PUBLISHER_FP)
    return governor


# ── AC-1: Lifecycle state machine ───────────────────────────────────────────

class TestAC1StateMachine:
    """1. Lifecycle state machine: active→deprecated→revoked, terminal."""

    def test_active_to_deprecated_allowed(self):
        assert "deprecated" in LIFECYCLE_TRANSITIONS["active"]

    def test_active_to_revoked_allowed(self):
        assert "revoked" in LIFECYCLE_TRANSITIONS["active"]

    def test_deprecated_to_revoked_allowed(self):
        assert "revoked" in LIFECYCLE_TRANSITIONS["deprecated"]

    def test_deprecated_to_active_forbidden(self):
        assert "active" not in LIFECYCLE_TRANSITIONS["deprecated"]

    def test_revoked_is_terminal(self):
        assert LIFECYCLE_TRANSITIONS["revoked"] == set()

    def test_revoked_cannot_transition(self, populated_governor):
        """LG-005: Revoked packages cannot transition."""
        populated_governor.govern_revoke(
            "pkg_a", "1.0.0", "security issue", SIGNER_FP,
        )
        # Cannot deprecate a revoked package
        with pytest.raises(TerminalPackageError):
            populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)

    def test_revoked_cannot_re_revoke(self, populated_governor):
        populated_governor.govern_revoke(
            "pkg_a", "1.0.0", "reason 1", SIGNER_FP,
        )
        with pytest.raises(TerminalPackageError):
            populated_governor.govern_revoke(
                "pkg_a", "1.0.0", "reason 2", SIGNER_FP,
            )

    def test_deprecated_then_revoke(self, populated_governor):
        """Deprecated → revoked is allowed."""
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        populated_governor.govern_revoke(
            "pkg_a", "1.0.0", "escalation", SIGNER_FP,
        )
        record = populated_governor.state.get_package("pkg_a", "1.0.0")
        assert record.lifecycle == "revoked"


# ── AC-2: Governed revocation ───────────────────────────────────────────────

class TestAC2GovernedRevocation:
    """2. Governed revocation requires authorization."""

    def test_revocation_requires_signer_auth(self, populated_governor):
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_revoke(
                "pkg_a", "1.0.0", "test", "fp-WRONG",
            )

    def test_revocation_with_correct_auth(self, populated_governor):
        receipt = populated_governor.govern_revoke(
            "pkg_a", "1.0.0", "security", SIGNER_FP,
        )
        assert receipt.transition_type == TRANSITION_REVOKE
        assert receipt.registry_id == REGISTRY_ID

    def test_revocation_sets_lifecycle(self, populated_governor):
        populated_governor.govern_revoke(
            "pkg_a", "1.0.0", "security", SIGNER_FP,
        )
        record = populated_governor.state.get_package("pkg_a", "1.0.0")
        assert record.lifecycle == "revoked"

    def test_revocation_unknown_package(self, governor):
        with pytest.raises(KeyError):
            governor.govern_revoke(
                "nonexistent", "1.0.0", "test", SIGNER_FP,
            )


# ── AC-3: Governed deprecation ──────────────────────────────────────────────

class TestAC3GovernedDeprecation:
    """3. Governed deprecation requires authorization."""

    def test_deprecation_requires_signer_auth(self, populated_governor):
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_deprecate("pkg_a", "1.0.0", "fp-WRONG")

    def test_deprecation_with_correct_auth(self, populated_governor):
        receipt = populated_governor.govern_deprecate(
            "pkg_a", "1.0.0", SIGNER_FP,
        )
        assert receipt.transition_type == TRANSITION_DEPRECATE

    def test_deprecation_sets_lifecycle(self, populated_governor):
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        record = populated_governor.state.get_package("pkg_a", "1.0.0")
        assert record.lifecycle == "deprecated"


# ── AC-4: Signer rotation ───────────────────────────────────────────────────

class TestAC4SignerRotation:
    """4. Signer rotation: LG-001 identity continuity, LG-002 auth."""

    def test_rotation_preserves_registry_id(self, populated_governor):
        """LG-001: registry_id stays the same."""
        populated_governor.govern_signer_rotation(
            "fp-new-key", SIGNER_FP,
        )
        assert populated_governor.state.get_registry_id() == REGISTRY_ID

    def test_rotation_changes_signer(self, populated_governor):
        populated_governor.govern_signer_rotation(
            "fp-new-key", SIGNER_FP,
        )
        assert populated_governor.state.get_signer_fingerprint() == "fp-new-key"

    def test_rotation_requires_current_signer(self, populated_governor):
        """LG-002: Only current signer can authorize."""
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_signer_rotation(
                "fp-new-key", "fp-imposter",
            )

    def test_rotation_same_key_rejected(self, populated_governor):
        with pytest.raises(LifecycleError, match="same"):
            populated_governor.govern_signer_rotation(
                SIGNER_FP, SIGNER_FP,
            )

    def test_rotation_advances_generation(self, populated_governor):
        gen_before = populated_governor.state.get_generation()
        populated_governor.govern_signer_rotation("fp-new", SIGNER_FP)
        gen_after = populated_governor.state.get_generation()
        assert gen_after == gen_before + 1

    def test_post_rotation_operations_use_new_signer(self, populated_governor):
        """After rotation, the new signer is required for privileged ops."""
        populated_governor.govern_signer_rotation("fp-new", SIGNER_FP)

        # Old signer can no longer authorize
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_revoke(
                "pkg_a", "1.0.0", "test", SIGNER_FP,
            )

        # New signer can
        populated_governor.govern_revoke(
            "pkg_a", "1.0.0", "test", "fp-new",
        )


# ── AC-5: Publisher authority changes ───────────────────────────────────────

class TestAC5PublisherAuthority:
    """5. Publisher authority add/revoke: LG-007 auth, LG-010 preserve."""

    def test_add_publisher_requires_signer(self, governor):
        with pytest.raises(UnauthorizedRotationError):
            governor.govern_publisher_add(
                "pub-002", "fp-new-pub", [], "fp-WRONG",
            )

    def test_add_publisher_with_auth(self, governor):
        receipt = governor.govern_publisher_add(
            "pub-002", "fp-new-pub", ["pkg_b"], SIGNER_FP,
        )
        assert receipt.transition_type == TRANSITION_PUBLISHER_ADD
        assert governor.state.is_publisher_authorized("fp-new-pub", "pkg_b")

    def test_revoke_publisher_requires_signer(self, governor):
        governor.govern_publisher_add("pub-002", "fp-new-pub", [], SIGNER_FP)
        with pytest.raises(UnauthorizedRotationError):
            governor.govern_publisher_revoke("fp-new-pub", "fp-WRONG")

    def test_revoke_publisher_with_auth(self, governor):
        governor.govern_publisher_add("pub-002", "fp-new-pub", [], SIGNER_FP)
        receipt = governor.govern_publisher_revoke("fp-new-pub", SIGNER_FP)
        assert receipt.transition_type == TRANSITION_PUBLISHER_REVOKE
        assert not governor.state.is_publisher_authorized("fp-new-pub", "anything")

    def test_publisher_revoke_preserves_packages(self, populated_governor, server):
        """LG-010: Revoking publisher doesn't revoke published packages."""
        # Revoke publisher
        populated_governor.govern_publisher_revoke(PUBLISHER_FP, SIGNER_FP)

        # Package still exists and is active
        record = populated_governor.state.get_package("pkg_a", "1.0.0")
        assert record is not None
        assert record.lifecycle == "active"

    def test_revoked_publisher_cannot_publish(self, populated_governor, server):
        """After publisher revocation, that publisher can't publish new packages."""
        populated_governor.govern_publisher_revoke(PUBLISHER_FP, SIGNER_FP)
        with pytest.raises(UnauthorizedPublisherError):
            server.publish(
                "pkg_b", "1.0.0", b"data2",
                publisher_fingerprint=PUBLISHER_FP,
            )


# ── AC-6: Transition log integrity ──────────────────────────────────────────

class TestAC6TransitionLog:
    """6. Transition log is append-only (LG-008)."""

    def test_log_grows_on_each_transition(self, populated_governor, transition_log):
        assert len(transition_log.get_transitions()) == 0

        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        assert len(transition_log.get_transitions()) == 1

        populated_governor.govern_revoke("pkg_a", "1.0.0", "reason", SIGNER_FP)
        assert len(transition_log.get_transitions()) == 2

    def test_sequences_are_monotonic(self, populated_governor, server, transition_log):
        for i in range(3):
            server.publish(f"pkg_{i}", "1.0.0", f"data{i}".encode(),
                           publisher_fingerprint=PUBLISHER_FP)
            populated_governor.govern_deprecate(f"pkg_{i}", "1.0.0", SIGNER_FP)

        transitions = transition_log.get_transitions()
        for i, t in enumerate(transitions):
            assert t.sequence == i + 1

    def test_log_verify_integrity(self, populated_governor, transition_log):
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        populated_governor.govern_revoke("pkg_a", "1.0.0", "reason", SIGNER_FP)
        assert transition_log.verify_integrity()

    def test_log_persists_across_reload(self, populated_governor, tmp_path):
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)

        log2 = TransitionLog(tmp_path / "transition_log.json")
        transitions = log2.get_transitions()
        assert len(transitions) == 1
        assert transitions[0].transition_type == TRANSITION_DEPRECATE

    def test_transition_digests_verify(self, populated_governor, transition_log):
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        transitions = transition_log.get_transitions()
        for t in transitions:
            assert t.transition_digest == t.compute_digest()

    def test_generation_continuity_in_log(self, populated_governor, transition_log):
        """Each transition's generation_before = previous generation_after."""
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        populated_governor.govern_revoke("pkg_a", "1.0.0", "reason", SIGNER_FP)

        transitions = transition_log.get_transitions()
        assert transitions[1].generation_before == transitions[0].generation_after


# ── AC-7: Signed lifecycle receipts ─────────────────────────────────────────

class TestAC7LifecycleReceipts:
    """7. Every transition produces a signed receipt (LG-003)."""

    def test_receipt_has_all_fields(self, populated_governor):
        receipt = populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        assert receipt.receipt_id != ""
        assert receipt.transition_type == TRANSITION_DEPRECATE
        assert receipt.registry_id == REGISTRY_ID
        assert receipt.generation > 0
        assert receipt.authorized_by == SIGNER_FP
        assert receipt.timestamp != ""
        assert receipt.receipt_digest != ""

    def test_receipt_digest_deterministic(self, populated_governor):
        receipt = populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        # Recompute digest
        import hashlib, json
        expected = hashlib.sha256(json.dumps({
            "receipt_id": receipt.receipt_id,
            "transition_type": receipt.transition_type,
            "registry_id": receipt.registry_id,
            "generation": receipt.generation,
            "authorized_by": receipt.authorized_by,
            "timestamp": receipt.timestamp,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert receipt.receipt_digest == expected

    def test_receipt_to_dict(self, populated_governor):
        receipt = populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        d = receipt.to_dict()
        assert "receipt_id" in d
        assert "transition_type" in d
        assert "receipt_digest" in d


# ── AC-8: Generation advancement ────────────────────────────────────────────

class TestAC8GenerationAdvancement:
    """8. Lifecycle transitions advance generation (LG-004)."""

    def test_revoke_advances_generation(self, populated_governor):
        gen_before = populated_governor.state.get_generation()
        populated_governor.govern_revoke("pkg_a", "1.0.0", "test", SIGNER_FP)
        gen_after = populated_governor.state.get_generation()
        assert gen_after == gen_before + 1

    def test_deprecate_advances_generation(self, populated_governor):
        gen_before = populated_governor.state.get_generation()
        populated_governor.govern_deprecate("pkg_a", "1.0.0", SIGNER_FP)
        gen_after = populated_governor.state.get_generation()
        assert gen_after == gen_before + 1

    def test_signer_rotation_advances_generation(self, populated_governor):
        gen_before = populated_governor.state.get_generation()
        populated_governor.govern_signer_rotation("fp-new", SIGNER_FP)
        gen_after = populated_governor.state.get_generation()
        assert gen_after == gen_before + 1

    def test_publisher_change_does_not_advance(self, governor):
        """Publisher authority changes don't advance generation."""
        gen_before = governor.state.get_generation()
        governor.govern_publisher_add("pub-002", "fp-new", [], SIGNER_FP)
        gen_after = governor.state.get_generation()
        assert gen_before == gen_after


# ── AC-9: Key continuity chain ──────────────────────────────────────────────

class TestAC9KeyContinuity:
    """9. Signer rotation emits key-continuity receipt (LG-009)."""

    def test_key_continuity_record_created(self, populated_governor, transition_log):
        populated_governor.govern_signer_rotation("fp-new", SIGNER_FP)

        continuity = transition_log.get_key_continuity()
        assert len(continuity) == 1
        assert continuity[0].registry_id == REGISTRY_ID
        assert continuity[0].old_signer_fingerprint == SIGNER_FP
        assert continuity[0].new_signer_fingerprint == "fp-new"

    def test_continuity_preserves_registry_id(self, populated_governor):
        """LG-001: Same registry_id after rotation."""
        reg_id_before = populated_governor.state.get_registry_id()
        populated_governor.govern_signer_rotation("fp-new", SIGNER_FP)
        reg_id_after = populated_governor.state.get_registry_id()
        assert reg_id_before == reg_id_after


# ── AC-10: Multiple rotations ───────────────────────────────────────────────

class TestAC10MultipleRotations:
    """10. Multiple rotations preserve continuity chain."""

    def test_three_rotations(self, populated_governor, transition_log):
        """Rotate: fp-signer → fp-key2 → fp-key3 → fp-key4."""
        populated_governor.govern_signer_rotation("fp-key2", SIGNER_FP)
        populated_governor.govern_signer_rotation("fp-key3", "fp-key2")
        populated_governor.govern_signer_rotation("fp-key4", "fp-key3")

        continuity = transition_log.get_key_continuity()
        assert len(continuity) == 3
        assert continuity[0].old_signer_fingerprint == SIGNER_FP
        assert continuity[1].old_signer_fingerprint == "fp-key2"
        assert continuity[2].old_signer_fingerprint == "fp-key3"
        assert continuity[2].new_signer_fingerprint == "fp-key4"

        assert populated_governor.state.get_signer_fingerprint() == "fp-key4"
        assert populated_governor.state.get_registry_id() == REGISTRY_ID

    def test_rotation_chain_can_verify(self, populated_governor, transition_log):
        populated_governor.govern_signer_rotation("fp-key2", SIGNER_FP)
        populated_governor.govern_signer_rotation("fp-key3", "fp-key2")
        assert transition_log.verify_integrity()

    def test_intermediate_key_cannot_rotate_after_superseded(self, populated_governor):
        """Once rotated away, old key can no longer authorize."""
        populated_governor.govern_signer_rotation("fp-key2", SIGNER_FP)

        # Original signer can no longer rotate
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_signer_rotation("fp-key3", SIGNER_FP)

        # But new key can
        populated_governor.govern_signer_rotation("fp-key3", "fp-key2")


# ── AC-11: Unauthorized operations fail closed ──────────────────────────────

class TestAC11UnauthorizedFailClosed:
    """11. All unauthorized operations fail closed."""

    def test_unauthorized_revoke(self, populated_governor):
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_revoke("pkg_a", "1.0.0", "test", "fp-imposter")

    def test_unauthorized_deprecate(self, populated_governor):
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_deprecate("pkg_a", "1.0.0", "fp-imposter")

    def test_unauthorized_rotation(self, populated_governor):
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_signer_rotation("fp-new", "fp-imposter")

    def test_unauthorized_publisher_add(self, governor):
        with pytest.raises(UnauthorizedRotationError):
            governor.govern_publisher_add("pub", "fp", [], "fp-imposter")

    def test_unauthorized_publisher_revoke(self, governor):
        with pytest.raises(UnauthorizedRotationError):
            governor.govern_publisher_revoke(PUBLISHER_FP, "fp-imposter")

    def test_empty_signer_fingerprint_rejected(self, populated_governor):
        with pytest.raises(UnauthorizedRotationError):
            populated_governor.govern_revoke("pkg_a", "1.0.0", "test", "")
