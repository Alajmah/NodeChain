"""Shared test fixtures."""

import os
import platform
import sys
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from nodechain.core.envelope import InvocationEnvelope, compile_envelope
from nodechain.adapters.model_adapter import ModelResponse


def provision_test_kek(path, *, attempts=8):
    """Provision a dev-mode KEK with caller-level retry.

    v3.5.1 (#8): the manager hard-fails if a post-publication reload detects
    a malformed key (immutable post-publication authority — never repair).
    This helper performs test-fixture cleanup after a validation failure:
    it removes the failed fixture and retries provisioning. This is test-only
    behavior, not production recovery guidance.
    """
    from nodechain.core.capsule_crypto import KekManager, CapsuleEncryptionError
    path = Path(path)
    for _ in range(attempts):
        try:
            return KekManager(kek_path=path, local_dev=True).get_kek()
        except CapsuleEncryptionError:
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
    pytest.fail(f"could not provision KEK at {path} after {attempts} attempts")

# v2.31 code-review fix: mark test mode so the memory_write node's fallback
# policy path is available for legacy tests that don't inject a PolicyEngine.
os.environ.setdefault("NODECHAIN_TEST_MODE", "1")


# v3.5.1 (#8) B3: the test suite IS a local-dev composition root. StateManager
# without explicit injection defaults to PRODUCTION (no env read). Tests that
# exercise governed side effects need a dev-mode KEK, so this autouse fixture
# patches the StateManager default to inject a dev-mode manager for the test
# process only. This is the composition-boundary decision for the test suite,
# equivalent to run_chain's explicit injection for production.
@pytest.fixture(autouse=True)
def _test_dev_kek_manager(monkeypatch):
    from nodechain.core.capsule_crypto import KekManager
    _dev_manager = KekManager(
        kek_path=Path("data/test_capsule_kek.bin"), local_dev=True,
    )
    import nodechain.core.state as _state_mod
    _orig_init = _state_mod.StateManager.__init__

    def _patched_init(self, db_path="data/chain_state.db", *, kek_manager=None,
                      read_only=False):
        _orig_init(self, db_path, kek_manager=kek_manager or _dev_manager,
                   read_only=read_only)

    monkeypatch.setattr(_state_mod.StateManager, "__init__", _patched_init)
    yield


# v3.5.0: clean up the default persistent DB before orchestrator integration
# tests. These tests construct StateManager() without an explicit db_path,
# sharing data/chain_state.db. Without cleanup, side-effect rows accumulate
# across tests and cause UNIQUE constraint violations or stale-data failures.
_ORCHESTRATOR_TEST_CLASSES = {
    "TestOrchestrator",
    "TestReviewInOrchestrator",
    "TestPolicyGateInOrchestrator",
    "TestReviewResumeIntegration",
    "TestOrchestratorIntegration",
}


@pytest.fixture(autouse=True)
def _clean_default_db(request):
    """Clean the default chain_state.db before orchestrator integration tests.

    Forces garbage collection first so SQLite connections from the previous
    test are released (Windows file locking prevents deletion while a
    connection is open).
    """
    import gc
    cls = getattr(request.node, "cls", None)
    if cls is not None and cls.__name__ in _ORCHESTRATOR_TEST_CLASSES:
        gc.collect()  # Release SQLite connections from the previous test
        db = Path("data/chain_state.db")
        try:
            if db.exists():
                db.unlink()
        except PermissionError:
            pass  # File locked — best effort, test may still pass
    yield


# ─── v2.77 native sandbox three-tier gate ─────────────────────────────────
# Impossible-to-misread enforcement of the v2.77 verification contract.
#
#   Default host (any platform, including dev Linux):
#     native_sandbox tests SKIP. Reason: local portability.
#
#   NODECHAIN_NATIVE_RUNNER=1 + Linux + root (uid 0):
#     native_sandbox tests RUN and enforcement failures fail the suite.
#
#   NODECHAIN_NATIVE_RUNNER=1 + non-root OR non-Linux:
#     the tests STILL RUN, and hard-fail at the in-test capability check.
#     This is the deliberate "unsupported runner" failure — a green-looking
#     run that didn't actually verify anything is impossible.
#
#   GHA runner (gha-runner, non-root, flag unset): same as default → skip.
#   v2.77 does not assert native enforcement inside the GHA job context.
_NATIVE_RUNNERRequested = os.environ.get("NODECHAIN_NATIVE_RUNNER", "") == "1"


def _native_runner_privilege_ok() -> bool:
    """True iff this process is on Linux AND running as root (uid 0).

    The v2.76 native_os_sandbox backend requires CAP_SYS_ADMIN/CAP_SYS_CHROOT,
    which the GHA runner user does not have. Enforcement verification therefore
    runs under a privileged (root) profile only.
    """
    return platform.system() == "Linux" and os.geteuid() == 0


def pytest_collection_modifyitems(config, items):
    """Apply the Tier-1 skip for native_sandbox tests.

    Tier 1 (default): skip for portability.
    Tier 2 + Tier 3 (flag set): let the tests run. Each native_sandbox test
    begins with a capability check (assert_native_runner_privilege) that
    hard-fails if the privilege profile is wrong, so a misconfigured runner
    can never look green.
    """
    skip_native_default = pytest.mark.skip(
        reason=(
            "native_sandbox test: skipped (default). Set NODECHAIN_NATIVE_RUNNER=1 "
            "AND run as root on Linux to enforce. See "
            "scripts/run_native_sandbox_verification.sh and "
            "docs/native_sandbox_verification.md."
        )
    )
    for item in items:
        if "native_sandbox" in item.keywords and not _NATIVE_RUNNERRequested:
            item.add_marker(skip_native_default)


# v2.77: helper used by every native_sandbox test to fail fast on a misconfigured
# runner. Imported by tests as `from conftest import assert_native_runner_privilege`.
def assert_native_runner_privilege() -> None:
    """Hard-fail if the verification-runner privilege profile is not met.

    Called at the top of every native_sandbox enforcement test. When
    NODECHAIN_NATIVE_RUNNER=1 is set but the process is not root on Linux,
    this raises AssertionError with a precise reason — making a green-looking
    run on an unsupported host impossible. This is the Tier-3 contract.
    """
    if _NATIVE_RUNNERRequested and not _native_runner_privilege_ok():
        raise AssertionError(
            f"NODECHAIN_NATIVE_RUNNER=1 set but verification runner privilege "
            f"profile not met (platform={platform.system()!r}, uid={os.geteuid()}; "
            f"requires Linux + root for the v2.76 native_os_sandbox backend). "
            f"This is an unsupported-runner failure, not a portable skip."
        )


@pytest.fixture
def mock_model_response():
    """Create a mock model response."""
    return ModelResponse(
        content='{"primary_question": "test", "research_domain": "general"}',
        structured_output={
            "primary_question": "test query",
            "research_domain": "general",
            "success_criteria": ["answer the question"],
            "domain_classification": [],
            "depth_required": "moderate",
        },
        model="claude-test",
        usage={"input_tokens": 100, "output_tokens": 50},
        cost_usd=0.005,
        latency_ms=500,
    )


@pytest.fixture
def mock_model_adapter(mock_model_response):
    """Create a mock model adapter."""
    adapter = MagicMock()
    adapter.complete.return_value = mock_model_response
    return adapter


@pytest.fixture
def sample_envelope():
    """Create a sample invocation envelope."""
    return compile_envelope(
        run_id="test-run-001",
        chain_id="research-decision-v1",
        node_id="test_node",
        step_id=1,
        payload={"query": "What is the impact of AI on healthcare?"},
    )
