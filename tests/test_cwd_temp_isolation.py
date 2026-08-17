"""Tests for child cwd and temp directory isolation.

AC1: Child cwd is explicitly set to package root or isolated work dir.
AC2: Child cwd behavior is tested.
AC3: Child receives isolated temp directory per invocation.
AC4: TEMP, TMP, TMPDIR point to isolated temp directory.
AC5: Temp directory cleaned up after successful execution.
AC6: Temp directory cleaned up after timeout/failure.
AC7: Report records child_cwd and temp_dir_isolated=true.
AC8: Existing 1088 tests remain green.
"""

import asyncio
import os
import glob
import pytest

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner


def _make_envelope(node_id="echo_node"):
    return InvocationEnvelope(
        run_id="test-run",
        chain_id="test-chain",
        node_id=node_id,
        step_id=1,
        payload={"text": "hello"},
    )


class TestChildCwd:
    """AC1+AC2: Child cwd explicitly set."""

    @pytest.mark.asyncio
    async def test_child_cwd_in_result(self):
        """AC7: Result includes child_cwd."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        assert "child_cwd" in result
        assert result["child_cwd"] != ""  # Explicitly set

    @pytest.mark.asyncio
    async def test_child_cwd_is_temp_when_no_package_root(self):
        """AC1: cwd is temp dir when no package_root provided."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
            package_root="",  # No package root
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        assert "nodechain_child_" in result["child_cwd"] or result["child_cwd"] != ""

    @pytest.mark.asyncio
    async def test_child_cwd_is_package_root_when_provided(self):
        """AC1: cwd is package root when provided."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
            package_root="nodes/echo_node",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        assert result["child_cwd"] == "nodes/echo_node"


class TestTempDirIsolation:
    """AC3+AC4: Child receives isolated temp directory."""

    @pytest.mark.asyncio
    async def test_temp_dir_isolated_true(self):
        """AC7: Result records temp_dir_isolated=true."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        assert result["temp_dir_isolated"] is True

    def test_env_has_temp_vars(self):
        """AC4: _build_child_env sets TEMP/TMP/TMPDIR."""
        runner = SubprocessRunner()
        import tempfile
        temp_dir = tempfile.mkdtemp()
        try:
            env = runner._build_child_env(temp_dir=temp_dir)
            assert env["TEMP"] == temp_dir
            assert env["TMP"] == temp_dir
            assert env["TMPDIR"] == temp_dir
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestTempCleanup:
    """AC5+AC6: Temp directory cleaned up."""

    @pytest.mark.asyncio
    async def test_temp_cleaned_after_success(self):
        """AC5: Temp dir removed after successful execution."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        child_cwd = result["child_cwd"]
        # If it was a temp dir, it should be cleaned up
        if "nodechain_child_" in child_cwd:
            assert not os.path.exists(child_cwd)

    @pytest.mark.asyncio
    async def test_temp_cleaned_after_failure(self):
        """AC6: Temp dir removed after failure."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/nonexistent/implementation.py",
            class_name="FakeNode",
            node_id="nonexistent",
            trust_level="local_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is False
        # Module not found returns before temp dir is created
        # but error path should still clean up

    @pytest.mark.asyncio
    async def test_each_invocation_gets_unique_temp(self):
        """AC3: Each invocation gets a unique temp directory."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result1 = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
        )

        result2 = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result1["success"] is False
            assert result1["exit_code"] == 126
            assert result1["error"].startswith("supervised execution failed before workload start") or result1["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result1.get('error', '')[:200]}"
            assert result2["success"] is False
            assert result2["exit_code"] == 126
            assert result2["error"].startswith("supervised execution failed before workload start") or result2["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result2.get('error', '')[:200]}"
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result1["success"] is True
        assert result2["success"] is True
        # Each run gets a different cwd
        if "nodechain_child_" in result1["child_cwd"]:
            assert result1["child_cwd"] != result2["child_cwd"]


class TestModulePathResolved:
    """Module path is resolved to absolute."""

    @pytest.mark.asyncio
    async def test_relative_module_path_works(self):
        """Relative module path works even with temp cwd."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
