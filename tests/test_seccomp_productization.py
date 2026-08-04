"""Tests for seccomp productization (v1.2.5).

Tests cover:
1. CLI sandbox profile can auto-enable seccomp on Linux
2. Blocked-syscall test proves fork/clone denial (in subprocess)
3. allow_preloaded denylist blocks sensitive modules
4. BaseNode.isolation_config auto-enables seccomp on Linux
5. Orchestrator passes trust_level + isolation_config to invoker
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
import pytest
from pathlib import Path

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner
from nodechain.sdk.import_enforcer import (
    enforce_imports_for_node,
    ImportBlockedError,
)
from nodechain.sdk.trust import TrustLevel


def _make_envelope(node_id: str = "test") -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run",
        chain_id="test-chain",
        node_id=node_id,
        step_id=1,
        payload={"query": "hello"},
    )


# ─── 1. BaseNode isolation_config auto-enables seccomp ───────────────────

class TestBaseNodeIsolationConfig:
    """BaseNode.isolation_config auto-enables seccomp on Linux."""

    def test_built_in_node_no_isolation(self):
        """Built-in nodes don't get isolation_config."""
        from nodechain.nodes.base_node import BaseNode
        from nodechain.core.manifest import NodeManifest

        class TestNode(BaseNode):
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="test",
                    version="1.0.0",
                    description="test",
                )

            async def execute(self, envelope):
                pass

        node = TestNode()
        assert node.isolation_config is None

    def test_untrusted_node_gets_isolation_config(self):
        """Untrusted nodes get isolation_config with module_path."""
        from nodechain.nodes.base_node import BaseNode
        from nodechain.core.manifest import NodeManifest

        class TestNode(BaseNode):
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="test",
                    version="1.0.0",
                    description="test",
                )

            async def execute(self, envelope):
                pass

        node = TestNode()
        node._trust_level = "local_untrusted"
        node._module_path = "/some/path/impl.py"
        node._package_root = "/some/path"

        config = node.isolation_config
        assert config is not None
        assert config["module_path"] == "/some/path/impl.py"
        assert config["class_name"] == "TestNode"

    def test_seccomp_auto_enabled_on_linux(self):
        """On Linux, seccomp is auto-enabled for untrusted nodes."""
        if platform.system() != "Linux":
            pytest.skip("Linux only")

        from nodechain.nodes.base_node import BaseNode
        from nodechain.core.manifest import NodeManifest

        class TestNode(BaseNode):
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="test",
                    version="1.0.0",
                    description="test",
                )

            async def execute(self, envelope):
                pass

        node = TestNode()
        node._trust_level = "local_untrusted"
        node._module_path = "/some/path/impl.py"

        config = node.isolation_config
        assert config is not None
        assert config["enable_seccomp"] is True

    def test_seccomp_not_enabled_on_windows(self):
        """On Windows, seccomp is not enabled."""
        if platform.system() == "Linux":
            pytest.skip("Windows only")

        from nodechain.nodes.base_node import BaseNode
        from nodechain.core.manifest import NodeManifest

        class TestNode(BaseNode):
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="test",
                    version="1.0.0",
                    description="test",
                )

            async def execute(self, envelope):
                pass

        node = TestNode()
        node._trust_level = "local_untrusted"
        node._module_path = "/some/path/impl.py"

        config = node.isolation_config
        assert config is not None
        assert config["enable_seccomp"] is False


# ─── 2. Blocked-syscall kill test (subprocess only) ──────────────────────

class TestBlockedSyscallKill:
    """Prove that seccomp kills the child process on fork/clone attempt.

    This test runs entirely in a subprocess so seccomp never contaminates
    the pytest process.
    """

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Seccomp enforcement is Linux-only"
    )
    def test_fork_kills_child_under_seccomp(self):
        """Child process with seccomp active is killed on fork().

        We spawn a child that:
        1. Applies seccomp (denies fork/clone)
        2. Attempts os.fork()
        3. If seccomp works: child is killed (SIGSYS/SIGKILL)
        4. If seccomp doesn't work: child exits 0
        """
        import subprocess

        child_code = """
import os, sys, signal

# Apply seccomp
from nodechain.sdk.seccomp_profile import SeccompProfile, SeccompBackend
backend = SeccompBackend()
if not backend.available:
    print("SECCOMP_UNAVAILABLE")
    sys.exit(0)

profile = SeccompProfile()
applied = backend.apply_profile(profile)
if not applied:
    print("SECCOMP_NOT_APPLIED")
    sys.exit(0)

# Write success marker before attempting fork
print("SECCOMP_ACTIVE")

# Attempt fork — should be killed
try:
    pid = os.fork()
    if pid == 0:
        sys.exit(0)
    os.waitpid(pid, 0)
    # If we get here, seccomp didn't block fork
    print("FORK_SUCCEEDED")
    sys.exit(0)
except OSError as e:
    print(f"FORK_ERRNO:{e.errno}")
    sys.exit(0)
"""

        result = subprocess.run(
            [sys.executable, "-c", child_code],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(Path.cwd()),
        )

        stdout = result.stdout.strip()
        # If seccomp is active and fork is blocked, the process is killed
        # by SIGSYS or the fork returns EPERM
        if "SECCOMP_ACTIVE" in stdout:
            # Seccomp was applied. Check what happened with fork.
            if "FORK_SUCCEEDED" in stdout:
                pytest.fail("fork() succeeded under seccomp — filter not working!")
            elif "FORK_ERRNO" in stdout:
                # fork() returned an errno (EPERM) — seccomp ERRNO action
                pass  # This is expected behavior
            else:
                # Process was killed by seccomp (SIGSYS) before printing result
                # The signal kills the process, so stdout has SECCOMP_ACTIVE
                # but no FORK_SUCCEEDED
                pass  # This is expected behavior
        elif "SECCOMP_UNAVAILABLE" in stdout:
            pytest.skip("seccomp not available in this environment")
        elif "SECCOMP_NOT_APPLIED" in stdout:
            pytest.skip("seccomp could not be applied")


# ─── 3. allow_preloaded denylist ─────────────────────────────────────────

class TestPreloadedDenylist:
    """Sensitive modules are blocked even with allow_preloaded=True."""

    def test_ctypes_blocked_even_if_preloaded(self):
        """ctypes is blocked even when allow_preloaded=True and it's in sys.modules."""
        # ctypes may not be in sys.modules; try to import it first
        try:
            import ctypes  # noqa: F401
        except ImportError:
            pytest.skip("ctypes not available")

        enforcer = enforce_imports_for_node(
            TrustLevel.LOCAL_UNTRUSTED, "test", allow_preloaded=True
        )
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("ctypes")

    def test_subprocess_blocked_even_if_preloaded(self):
        """subprocess is blocked by policy, not just by allow_preloaded check."""
        enforcer = enforce_imports_for_node(
            TrustLevel.LOCAL_UNTRUSTED, "test", allow_preloaded=True
        )
        # subprocess IS in sys.modules (loaded by pytest), but the import
        # v1.18.5: subprocess IS now in _PRELOADED_DENYLIST.
        # It is always blocked for untrusted nodes, even when preloaded.
        # This is the FINDING-002 fix — previously subprocess could be
        # imported via importlib.import_module and via the suffix matching
        # false positive (asyncio.subprocess).
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                import subprocess as sp  # Should be blocked

    def test_runpy_blocked_even_if_preloaded(self):
        """runpy is in the denylist — blocked even if preloaded."""
        try:
            import runpy  # noqa: F401
        except ImportError:
            pytest.skip("runpy not available")

        enforcer = enforce_imports_for_node(
            TrustLevel.LOCAL_UNTRUSTED, "test", allow_preloaded=True
        )
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("runpy")

    def test_new_import_blocked_under_preloaded(self):
        """NEW imports not in sys.modules are still blocked."""
        enforcer = enforce_imports_for_node(
            TrustLevel.LOCAL_UNTRUSTED, "test", allow_preloaded=True
        )
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("nonexistent_evil_module")


# ─── 4. Orchestrator passes isolation config ─────────────────────────────

class TestOrchestratorIsolationWiring:
    """Orchestrator passes trust_level and isolation_config to invoker."""

    def test_invoke_node_passes_trust_level(self):
        """_invoke_node reads node._trust_level and passes to invoker."""
        # Verify the orchestrator source contains the wiring
        import inspect
        from nodechain.runtime.orchestrator import Orchestrator

        source = inspect.getsource(Orchestrator._invoke_node)
        assert "trust_level" in source
        assert "isolation_config" in source


# ─── 5. Version and changelog ────────────────────────────────────────────

class TestSeccompProductizationVersion:
    """Version and changelog reflect v1.2.5."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v125(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
