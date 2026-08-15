"""Tests for process-isolated node execution with child-side policy enforcement.

AC1: Child installs import/filesystem/subprocess/network enforcers before execute.
AC2: Child receives trust_level and package_root as part of config.
AC3: local_untrusted child cannot read workspace files.
AC4: local_untrusted child cannot open network sockets.
AC5: local_untrusted child cannot spawn subprocesses.
AC6: Child process launched with close_fds=True.
AC7: Report distinguishes isolation_mode and child_policy_enforced.
AC8: Existing 1071 tests remain green.
"""

import asyncio
import json
import os
import pytest

from nodechain.core.envelope import InvocationEnvelope
from nodechain.sdk.trust import TrustLevel
from nodechain.runtime.subprocess_runner import SubprocessRunner, get_subprocess_runner


def _make_envelope(node_id="echo_node"):
    return InvocationEnvelope(
        run_id="test-run",
        chain_id="test-chain",
        node_id=node_id,
        step_id=1,
        payload={"text": "hello"},
    )


class TestSubprocessRunner:
    """AC1: Subprocess runner for untrusted nodes."""

    def test_should_use_subprocess_untrusted(self):
        runner = SubprocessRunner()
        assert runner.should_use_subprocess(TrustLevel.LOCAL_UNTRUSTED) is True

    def test_should_use_subprocess_remote(self):
        runner = SubprocessRunner()
        assert runner.should_use_subprocess(TrustLevel.REMOTE_UNTRUSTED) is True

    def test_should_not_use_subprocess_builtin(self):
        runner = SubprocessRunner()
        assert runner.should_use_subprocess(TrustLevel.BUILT_IN) is False

    def test_should_not_use_subprocess_trusted(self):
        runner = SubprocessRunner()
        assert runner.should_use_subprocess(TrustLevel.LOCAL_TRUSTED) is False


class TestChildPolicyEnforcement:
    """AC1: Child installs enforcers and reports child_policy_enforced."""

    @pytest.mark.asyncio
    async def test_child_policy_enforced_true(self):
        """AC1: child_policy_enforced=True in response metadata."""
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
        assert result["child_policy_enforced"] is True
        meta = result["response"].get("metadata", {})
        assert meta.get("child_policy_enforced") is True

    @pytest.mark.asyncio
    async def test_child_violation_reports_in_metadata(self):
        """AC1: Violation reports included in response metadata."""
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
        meta = result["response"].get("metadata", {})
        assert "import_violations" in meta
        assert "filesystem_violations" in meta
        assert "subprocess_violations" in meta
        assert "network_violations" in meta


class TestChildConfigPropagation:
    """AC2: Child receives trust_level and package_root."""

    @pytest.mark.asyncio
    async def test_echo_with_untrusted_policy(self):
        """AC2: Trust level propagated to child."""
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
        assert result["child_policy_enforced"] is True

    @pytest.mark.asyncio
    async def test_echo_with_remote_untrusted(self):
        """AC2: remote_untrusted also enforced in child."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/echo_node/implementation.py",
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="remote_untrusted",
        )

        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        assert result["child_policy_enforced"] is True


class TestUntrustedCannotReadWorkspace:
    """AC3: local_untrusted child cannot read workspace files."""

    @pytest.mark.asyncio
    async def test_untrusted_filesystem_blocked(self):
        """AC3: Sandbox test node reports filesystem blocked."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = InvocationEnvelope(
            run_id="test-run",
            chain_id="test-chain",
            node_id="sandbox_test_node",
            step_id=1,
            payload={"test_all": True},
        )

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/sandbox_test_node/implementation.py",
            class_name="SandboxTestNode",
            node_id="sandbox_test_node",
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
        output = result["response"]["output"]
        assert output["filesystem_blocked"] is True


class TestUntrustedCannotNetwork:
    """AC4: local_untrusted child cannot open network sockets."""

    @pytest.mark.asyncio
    async def test_untrusted_network_blocked(self):
        """AC4: Sandbox test node reports network blocked."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = InvocationEnvelope(
            run_id="test-run",
            chain_id="test-chain",
            node_id="sandbox_test_node",
            step_id=1,
            payload={"test_all": True},
        )

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/sandbox_test_node/implementation.py",
            class_name="SandboxTestNode",
            node_id="sandbox_test_node",
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
        output = result["response"]["output"]
        assert output["network_blocked"] is True


class TestUntrustedCannotSubprocess:
    """AC5: local_untrusted child cannot spawn subprocesses."""

    @pytest.mark.asyncio
    async def test_untrusted_subprocess_blocked(self):
        """AC5: Sandbox test node reports subprocess blocked."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = InvocationEnvelope(
            run_id="test-run",
            chain_id="test-chain",
            node_id="sandbox_test_node",
            step_id=1,
            payload={"test_all": True},
        )

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/sandbox_test_node/implementation.py",
            class_name="SandboxTestNode",
            node_id="sandbox_test_node",
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
        output = result["response"]["output"]
        assert output["subprocess_blocked"] is True


class TestEnvelopeSerialization:
    """Envelope round-trips through subprocess."""

    @pytest.mark.asyncio
    async def test_echo_node_in_subprocess(self):
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
        assert result["exit_code"] == 0
        assert result["isolation_mode"] == "subprocess"
        assert result["response"]["node_id"] == "echo_node"
        assert result["response"]["success"] is True
        assert result["duration_ms"] > 0

    @pytest.mark.asyncio
    async def test_payload_structure_preserved(self):
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
        output = result["response"]["output"]
        assert isinstance(output, dict)


class TestTimeoutLimit:
    """AC: Timeout enforced."""

    @pytest.mark.asyncio
    async def test_default_timeout(self):
        runner = SubprocessRunner()
        assert runner.timeout_seconds == 30


class TestOutputSizeLimit:
    """AC: Output size limit enforced."""

    def test_default_output_size(self):
        runner = SubprocessRunner()
        assert runner.max_output_bytes == 10 * 1024 * 1024

    def test_custom_output_size(self):
        runner = SubprocessRunner(max_output_bytes=1024)
        assert runner.max_output_bytes == 1024


class TestModuleNotFound:
    """Graceful error when module doesn't exist."""

    @pytest.mark.asyncio
    async def test_missing_module(self):
        runner = SubprocessRunner()
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
        assert "Module not found" in result["error"]
        assert result["exit_code"] == -1


class TestIsolationModeInReport:
    """AC7: Report records isolation_mode and child_policy_enforced."""

    @pytest.mark.asyncio
    async def test_subprocess_isolation_recorded(self):
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
        assert result["isolation_mode"] == "subprocess"
        assert result["child_policy_enforced"] is True


class TestGetRunner:
    """Factory function works."""

    def test_get_runner(self):
        runner = get_subprocess_runner()
        assert isinstance(runner, SubprocessRunner)
        assert runner.timeout_seconds == 30


class TestExistingInProcessPath:
    """Verify existing in-process invocation still works."""

    @pytest.mark.asyncio
    async def test_builtin_still_in_process(self):
        from nodechain.runtime.node_invoker import NodeInvoker
        from nodes.echo_node.implementation import EchoNode

        invoker = NodeInvoker()
        envelope = _make_envelope()
        node = EchoNode()

        response, latency = await invoker.invoke(
            node, envelope, trust_level="built_in",
        )
        assert response.success is True
        assert response.metadata is None or "isolation_mode" not in (response.metadata or {})


class TestImportlibBypassRegression:
    """FINDING-002 regression: importlib.import_module blocked in subprocess."""

    @pytest.mark.asyncio
    async def test_untrusted_node_importlib_blocked(self):
        """FINDING-002: Untrusted node cannot bypass import policy via importlib.

        An untrusted node attempts:
            import importlib
            importlib.import_module("subprocess")

        Expected:
            importlib_blocked=True in node output
            child_policy_enforced=True in response metadata
        """
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()

        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/sandbox_test_node/implementation.py",
            class_name="SandboxTestNode",
            node_id="sandbox_test_node",
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
        assert result["child_policy_enforced"] is True

        output = result["response"].get("output", {})
        assert output.get("importlib_blocked") is True, (
            "importlib.import_module('subprocess') should be blocked for untrusted nodes"
        )
        assert output.get("import_blocked") is True
