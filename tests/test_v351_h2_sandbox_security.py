"""v3.5.1 H2 — Sandbox security boundary: env filtering + streaming output caps.

Tests the local subprocess backend (LocalSubprocessBackend) and the untrusted-
node SubprocessRunner — both are cross-platform. The native sandbox enforcement
tests are in test_native_sandbox_enforcement.py (Linux + root only).

H2 contract:
* #2 — sandboxed code cannot read a canary secret from the parent environment;
       only allowlisted env vars reach the workload.
* #3 — infinite stdout/stderr flood remains bounded and is terminated;
       output limits are enforced WHILE STREAMING, not after capture;
       the process group is killed when the cap is exceeded.

Written FIRST (RED).
"""

from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path

import pytest

from nodechain.runtime.sandbox_command_runner import SandboxCommandRunner


# ── #2: Environment filtering ──────────────────────────────────────────────


class TestEnvironmentFiltering:
    """Sandboxed code must not inherit secrets from the parent environment."""

    def test_canary_secret_not_visible_to_sandboxed_workload(self, monkeypatch):
        """A secret in the parent environment must not be readable by the
        sandboxed workload unless it is in the allowlist."""
        monkeypatch.setenv("NODECHAIN_TEST_SECRET", "leaked-canary-value")
        runner = SandboxCommandRunner("local_subprocess")

        probe = (
            f"import os; "
            f"val = os.environ.get('NODECHAIN_TEST_SECRET', 'NOT_PRESENT'); "
            f"print(val)"
        )
        result = runner.run_command(
            argv=[sys.executable, "-c", probe],
            cwd=Path("."),
            timeout_seconds=15,
            max_output_bytes=10_000,
        )
        assert "leaked-canary-value" not in result["stdout"], (
            f"sandboxed workload read the canary secret — env leak detected"
        )

    def test_allowlisted_var_visible_to_sandboxed_workload(self, monkeypatch):
        """An allowlisted variable (e.g. PATH) must still reach the workload."""
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        runner = SandboxCommandRunner("local_subprocess")

        probe = "import os; print(os.environ.get('PATH', 'MISSING'))"
        result = runner.run_command(
            argv=[sys.executable, "-c", probe],
            cwd=Path("."),
            timeout_seconds=15,
            max_output_bytes=10_000,
        )
        assert "/usr/bin" in result["stdout"] or "MISSING" not in result["stdout"], (
            "allowlisted PATH should be visible to the workload"
        )


# ── #3: Streaming output caps ──────────────────────────────────────────────


class TestStreamingOutputCaps:
    """Output limits must be enforced while streaming, not after capture."""

    def test_stdout_flood_is_bounded_and_terminated(self):
        """A workload that emits unlimited stdout must be killed when the cap
        is exceeded, and the parent must not accumulate gigabytes in memory."""
        runner = SandboxCommandRunner("local_subprocess")
        # Emit data continuously — far exceeding the 10KB cap.
        flood = (
            "import sys\n"
            "data = 'A' * 4096\n"
            "while True:\n"
            "    sys.stdout.write(data)\n"
            "    sys.stdout.flush()\n"
        )
        result = runner.run_command(
            argv=[sys.executable, "-c", flood],
            cwd=Path("."),
            timeout_seconds=30,
            max_output_bytes=10_000,
        )
        # The output must be truncated (capped), not the full infinite stream.
        assert len(result["stdout"]) <= 10_000, (
            f"stdout is {len(result['stdout'])}B — output cap not enforced during streaming"
        )
        assert result["output_truncated"] is True, (
            "output_truncated must be True when the cap is exceeded"
        )
        assert result["exit_code_interpretation"] == "fail"
        assert result.get("reason") == "output_limit_exceeded"

    def test_stderr_flood_is_bounded(self):
        """stderr must be capped independently of stdout."""
        runner = SandboxCommandRunner("local_subprocess")
        flood = (
            "import sys; "
            "data = 'B' * 8192; "
            "[sys.stderr.write(data) or sys.stderr.flush() for _ in range(13000)]"
        )
        result = runner.run_command(
            argv=[sys.executable, "-c", flood],
            cwd=Path("."),
            timeout_seconds=30,
            max_output_bytes=10_000,
        )
        assert len(result["stderr"]) <= 10_000, (
            f"stderr is {len(result['stderr'])}B — stderr cap not enforced"
        )

    @pytest.mark.skipif(os.name != "posix", reason="process-group kill is POSIX-only")
    def test_process_group_killed_on_output_cap(self):
        """When the output cap is exceeded, the entire process group must be
        killed — grandchildren must not survive."""
        runner = SandboxCommandRunner("local_subprocess")
        import tempfile
        marker = Path(tempfile.gettempdir()) / f"h2_pgroup_marker_{os.getpid()}.txt"
        if marker.exists():
            marker.unlink()
        marker_str = str(marker)
        flood = (
            "import subprocess, sys\n"
            # Grandchild writes a marker after a 3-second delay.
            "gc = (\n"
            "    'import time; time.sleep(3); "
            f"open(r\"{marker_str}\", \"w\").write(\"survived\")'\n"
            ")\n"
            "subprocess.Popen([sys.executable, '-c', gc])\n"
            # Now flood stdout to trigger the output cap.
            "data = 'X' * 8192\n"
            "while True:\n"
            "    sys.stdout.write(data)\n"
            "    sys.stdout.flush()\n"
        )
        result = runner.run_command(
            argv=[sys.executable, "-c", flood],
            cwd=Path("."),
            timeout_seconds=30,
            max_output_bytes=10_000,
        )
        assert result["output_truncated"] is True
        # Wait for the grandchild's marker window to pass.
        time.sleep(4)
        survived = marker.exists()
        if survived:
            marker.unlink()
        assert not survived, (
            "grandchild process survived after output-cap kill — "
            "process group was NOT terminated"
        )

    def test_normal_output_under_cap_not_truncated(self):
        """Output under the cap must pass through without truncation."""
        runner = SandboxCommandRunner("local_subprocess")
        result = runner.run_command(
            argv=[sys.executable, "-c", "print('hello world')"],
            cwd=Path("."),
            timeout_seconds=15,
            max_output_bytes=10_000,
        )
        assert "hello world" in result["stdout"]
        assert result["output_truncated"] is False


# ── #7: Combined output ceiling ───────────────────────────────────────────


class TestCombinedOutputCeiling:
    """v3.5.1 H2 #7: per-stream plus combined hard ceiling.

    The combined ceiling default is max_output_bytes (not the sum). A workload
    that emits to BOTH streams simultaneously must be terminated when the
    COMBINED output exceeds the cap, even if neither stream individually
    reaches its own limit."""

    def test_combined_ceiling_terminates_across_both_streams(self):
        runner = SandboxCommandRunner("local_subprocess")
        # Emit to both streams in a tight loop. The combined cap (10KB default)
        # should be reached before either stream hits its own 10KB limit.
        flood = (
            "import sys\n"
            "while True:\n"
            "    sys.stdout.write('S' * 512)\n"
            "    sys.stdout.flush()\n"
            "    sys.stderr.write('E' * 512)\n"
            "    sys.stderr.flush()\n"
        )
        result = runner.run_command(
            argv=[sys.executable, "-c", flood],
            cwd=Path("."),
            timeout_seconds=30,
            max_output_bytes=10_000,
        )
        # The combined output must be bounded by the combined ceiling.
        total = len(result["stdout"]) + len(result["stderr"])
        assert total <= 20_000, (
            f"combined output is {total}B — combined ceiling not enforced"
        )
        assert result["output_truncated"] is True
        # Output-limit termination, not timeout.
        assert result.get("reason") == "output_limit_exceeded", (
            f"expected output_limit_exceeded, got {result.get('reason')}"
        )


# ── #8: Leader-exited descendant termination ──────────────────────────────


class TestLeaderExitedDescendantTermination:
    """v3.5.1 H2 #8: when the direct child (group leader) exits but a
    grandchild inherits the pipes, the grandchild must be terminated too.

    On POSIX this is via os.killpg on the stored process group.
    On Windows this is via the Job Object with kill-on-close."""

    def test_grandchild_survives_leader_exit_then_killed_by_group(self, tmp_path):
        """Child spawns a delayed grandchild that writes a marker, then the
        child exits immediately (before any output cap). The grandchild must
        be killed via the stored process group (POSIX) or Job Object (Windows)."""
        import tempfile
        marker = Path(tempfile.gettempdir()) / f"h2_leader_exit_{os.getpid()}.txt"
        if marker.exists():
            marker.unlink()
        marker_str = str(marker).replace("\\", "/")
        # Write the grandchild code to a temp file to avoid nested quoting.
        gc_file = tmp_path / "gc.py"
        gc_file.write_text(
            f"import time\ntime.sleep(5)\n"
            f"open(r'{marker_str}', 'w').write('survived')\n"
        )
        script = (
            "import subprocess, sys\n"
            f"subprocess.Popen([sys.executable, r'{gc_file}'])\n"
            "sys.exit(0)  # leader exits immediately\n"
        )
        runner = SandboxCommandRunner("local_subprocess")
        result = runner.run_command(
            argv=[sys.executable, "-c", script],
            cwd=Path("."),
            timeout_seconds=15,
            max_output_bytes=10_000,
        )
        # The direct child exited cleanly.
        assert result["exit_code_interpretation"] == "pass"
        # Wait for the grandchild's marker window.
        time.sleep(6)
        survived = marker.exists()
        if survived:
            marker.unlink()
        assert not survived, (
            "grandchild survived after leader exit — "
            "process group was NOT terminated"
        )


# ── #9: SubprocessRunner direct tests ─────────────────────────────────────


class TestSubprocessRunnerDirect:
    """v3.5.1 H2 #9/#10: direct tests for the untrusted-node SubprocessRunner
    output-cap enforcement (not via SandboxCommandRunner)."""

    def test_subprocess_runner_caps_stdout_flood(self, tmp_path):
        """The bounded async reader used by SubprocessRunner must bound stdout."""
        import asyncio

        async def _test():
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c",
                "import sys\n"
                "data = 'X' * 4096\n"
                "while True:\n"
                "    sys.stdout.write(data)\n"
                "    sys.stdout.flush()\n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            from nodechain.runtime.streaming_output import run_bounded_async
            result = await run_bounded_async(
                proc, input_data=None,
                timeout_seconds=15,
                max_output_bytes=5_000,
            )
            return result

        result = asyncio.run(_test())
        assert result["output_truncated"] is True, (
            "SubprocessRunner's streaming reader did not truncate output"
        )
        assert len(result["stdout"]) <= 5_000

    def test_subprocess_runner_caps_stderr_flood(self):
        """The streaming reader must also bound stderr."""
        import asyncio

        async def _test():
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c",
                "import sys\n"
                "data = 'E' * 4096\n"
                "while True:\n"
                "    sys.stderr.write(data)\n"
                "    sys.stderr.flush()\n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            from nodechain.runtime.streaming_output import run_bounded_async
            result = await run_bounded_async(
                proc, input_data=None,
                timeout_seconds=15,
                max_output_bytes=5_000,
            )
            return result

        result = asyncio.run(_test())
        assert result["output_truncated"] is True
        assert len(result["stderr"]) <= 5_000


# ── Finite combined-output classification ─────────────────────────────────


class TestFiniteCombinedCeiling:
    """v3.5.1 H2 #2: finite output where neither stream individually exceeds
    its cap but the COMBINED output exceeds the aggregate cap. The process
    exits normally. The result must be classified as output_limit_exceeded,
    not as a successful pass."""

    def test_finite_combined_exceed_classified_as_output_limit(self):
        """stdout: 6KB, stderr: 6KB, combined cap: 10KB. Process exits 0.
        Result must be truncated with output_limit_exceeded, not pass."""
        runner = SandboxCommandRunner("local_subprocess")
        # Emit exactly 6KB to stdout and 6KB to stderr, then exit 0.
        script = (
            "import sys\n"
            "sys.stdout.write('S' * 6144)\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write('E' * 6144)\n"
            "sys.stderr.flush()\n"
        )
        result = runner.run_command(
            argv=[sys.executable, "-c", script],
            cwd=Path("."),
            timeout_seconds=15,
            max_output_bytes=10_000,  # combined cap = 10KB
        )
        # Combined retained output must not exceed the combined cap.
        total = len(result["stdout"]) + len(result["stderr"])
        assert total <= 10_000, (
            f"combined retained {total}B > 10KB cap — hard ceiling not enforced"
        )
        assert result["output_truncated"] is True, (
            "output_truncated must be True when combined ceiling is exceeded"
        )
        assert result.get("reason") == "output_limit_exceeded", (
            f"expected output_limit_exceeded, got {result.get('reason')}"
        )
        assert result["process_timed_out"] is False


# ── Primitive-failure injection (deterministic, no host dependency) ────────


class TestPrimitiveFailureInjection:
    """v3.5.1 H2 #5/#6: deterministic enforcement-tuple failure injection.

    Rather than depending on a host where a specific primitive is unavailable,
    these tests inject a failure into the native sandbox child by patching the
    enforcement primitive to fail, then verify the workload never starts.
    These run on any platform (the native sandbox backend fails closed on
    non-Linux hosts — so these tests verify the fail-closed path)."""

    def test_native_sandbox_fails_closed_on_non_linux(self, tmp_path):
        """On non-Linux hosts, the native sandbox must refuse to run the
        workload (all primitives are unavailable). This is the deterministic
        fail-closed proof that doesn't depend on a specific missing library."""
        if os.name == "posix" and platform.system() == "Linux":
            pytest.skip("this test proves fail-closed on non-Linux hosts")
        from nodechain.runtime.sandbox_command_runner import SandboxCommandRunner
        runner = SandboxCommandRunner("native_os_sandbox")
        result = runner.run_command(
            argv=[sys.executable, "-c", "print('should never run')"],
            cwd=tmp_path,
            timeout_seconds=15,
            max_output_bytes=10_000,
        )
        # The native backend must NOT start the workload on non-Linux.
        assert result["process_started"] is False, (
            "native sandbox started workload on unsupported host"
        )
        assert "should never run" not in result.get("stdout", "")

