"""v3.5.1 H2 — SubprocessRunner.run_isolated integration tests.

These tests construct real temporary node modules and call the production
SubprocessRunner.run_isolated() path — not the helper directly. They exercise
child-script construction, env creation, Job Object assignment, payload
serialization, production result mapping, and temp-dir cleanup.

Runs on both Windows and Linux.
"""

from __future__ import annotations

import asyncio
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner


def _make_node_module(tmp_path: Path, name: str, body: str) -> Path:
    """Write a minimal node module to a temp file. The body is inserted
    at the method-body indent level (8 spaces)."""
    # Indent each line of the body to 8 spaces.
    indented_body = "\n".join("        " + line for line in body.splitlines())
    module = tmp_path / f"{name}.py"
    module.write_text(
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "\n"
        "class TestNode:\n"
        "    async def execute(self, envelope):\n"
        f"{indented_body}\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id,\n"
        "            run_id=envelope.run_id,\n"
        "            chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id,\n"
        "            step_id=envelope.step_id,\n"
        '            output={"status": "ok"},\n'
        '            output_type="result",\n'
        "        )\n"
    )
    return module


def _make_envelope(node_id: str = "test_node") -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run",
        chain_id="test-chain",
        node_id=node_id,
        step_id=1,
        payload={"query": "test"},
    )


class TestSubprocessRunnerRunIsolated:
    """Real production-path integration tests."""

    def test_normal_execution_succeeds(self, tmp_path):
        """A normal node that returns a result should succeed."""
        module = _make_node_module(tmp_path, "normal_node", 'pass')
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=50_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "normal_node",
            trust_level="local_trusted",
        ))
        assert result["success"], f"normal execution failed: {result.get('error', '')}"

    def test_infinite_stdout_flood_bounded(self, tmp_path):
        """A node that floods stdout infinitely must be bounded."""
        module = _make_node_module(tmp_path, "flood_node",
            "import sys\nwhile True:\n    sys.stdout.write('A' * 4096)\n    sys.stdout.flush()")
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=5_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "flood_node",
            trust_level="local_trusted",
        ))
        assert not result["success"]
        assert "Output exceeded" in result.get("error", "") or result.get("exit_code") == 3

    def test_infinite_stderr_flood_bounded(self, tmp_path):
        """A node that floods stderr infinitely must be bounded."""
        module = _make_node_module(tmp_path, "flood_err_node",
            "import sys\nwhile True:\n    sys.stderr.write('E' * 4096)\n    sys.stderr.flush()")
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=5_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "flood_err_node",
            trust_level="local_trusted",
        ))
        assert not result["success"]

    def test_timeout_terminates_hanging_child(self, tmp_path):
        """A node that hangs indefinitely must be terminated by timeout."""
        module = _make_node_module(tmp_path, "timeout_node",
            "import time\ntime.sleep(999)")
        runner = SubprocessRunner(timeout_seconds=3, max_output_bytes=50_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "timeout_node",
            trust_level="local_trusted",
        ))
        assert not result["success"]
        assert "Timeout" in result.get("error", "")

    def _run_descendant_test(self, tmp_path):
        """Shared descendant test logic: spawns grandchild, asserts containment."""
        import tempfile
        spawned_marker = Path(tempfile.gettempdir()) / f"h2_sr_spawned_{os.getpid()}.txt"
        survived_marker = Path(tempfile.gettempdir()) / f"h2_sr_survived_{os.getpid()}.txt"
        for m in [spawned_marker, survived_marker]:
            if m.exists(): m.unlink()
        spawned_str = str(spawned_marker).replace("\\", "/")
        survived_str = str(survived_marker).replace("\\", "/")
        gc_file = tmp_path / "gc2.py"
        gc_file.write_text(
            f"import time\ntime.sleep(5)\n"
            f"open(r'{survived_str}', 'w').write('survived')\n"
        )
        module = _make_node_module(tmp_path, "exit_node",
            f"import subprocess, sys\n"
            f"subprocess.Popen([sys.executable, r'{gc_file}'])\n"
            f"open(r'{spawned_str}', 'w').write('spawned')")
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=50_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "exit_node",
            trust_level="built_in",
        ))
        time.sleep(6)
        assert spawned_marker.exists(), (
            "spawned marker missing — grandchild was never created; "
            "test does not prove process-tree containment"
        )
        spawned_marker.unlink(missing_ok=True)
        survived = survived_marker.exists()
        if survived:
            survived_marker.unlink()
        assert not survived, (
            "grandchild survived after child exit in SubprocessRunner — "
            "process-tree containment failed"
        )

    def test_child_exit_with_delayed_grandchild(self, tmp_path):
        """A node that spawns a delayed grandchild then exits normally — the
        grandchild must be killed by the containment mechanism.

        v3.5.1 H2 #3/#4 (Windows): TWO canaries — spawned marker (grandchild
        was created) and survived marker (it was killed).

        POSIX + T3 (H0.2) dual truth for the untrusted spawn attempt:
          - unprivileged host: the supervised topology fails closed BEFORE
            the workload starts (process_started=False);
          - privileged host: the node genuinely executes under the
            supervised stack and the import enforcer BLOCKS 'subprocess'
            for untrusted nodes — process creation is refused by policy,
            so no uncontrolled grandchild can exist.
        Either way no untrusted grandchild runs."""
        if os.name != "nt":
            gc_file = tmp_path / "gc_fail.py"
            gc_file.write_text("import time\ntime.sleep(5)\n")
            module = _make_node_module(tmp_path, "fail_node",
                "import subprocess, sys\n"
                f"subprocess.Popen([sys.executable, r'{gc_file}'])\n")
            runner = SubprocessRunner(timeout_seconds=30, max_output_bytes=100_000)
            result = asyncio.run(runner.run_isolated(
                _make_envelope(), module, "TestNode", "fail_node",
                trust_level="local_untrusted",  # NOT built_in — must not spawn
            ))
            assert not result["success"]
            sup = result.get("supervised_execution", {})
            if sup.get("process_started") is False:
                # Unprivileged: refused before workload start.
                return
            # Privileged: the node ran and the import policy blocked
            # 'subprocess' — stronger than killing a grandchild: none can
            # be created.
            assert "IMPORT_POLICY_BLOCKED" in result.get("error", "") or \
                "subprocess" in result.get("error", ""), (
                f"expected import-policy block, got: {result.get('error', '')[:300]}"
            )
            return
        self._run_descendant_test(tmp_path)

    def test_stdout_flood_classified_as_output_limit(self, tmp_path):
        """Explicit output-limit classification (not just success=False)."""
        module = _make_node_module(tmp_path, "flood_out",
            "import sys\nwhile True:\n    sys.stdout.write('A' * 4096)\n    sys.stdout.flush()")
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=5_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "flood_out",
            trust_level="local_trusted",
        ))
        assert not result["success"]
        assert "Output exceeded" in result.get("error", "")

    def test_stderr_flood_classified_as_output_limit(self, tmp_path):
        """Explicit output-limit classification for stderr."""
        module = _make_node_module(tmp_path, "flood_err",
            "import sys\nwhile True:\n    sys.stderr.write('E' * 4096)\n    sys.stderr.flush()")
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=5_000)
        result = asyncio.run(runner.run_isolated(
            _make_envelope(), module, "TestNode", "flood_err",
            trust_level="local_trusted",
        ))
        assert not result["success"]
        assert "Output exceeded" in result.get("error", "")
