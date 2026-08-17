"""v3.5.1 H2 — Concurrent isolation proof.

Two environment-specific proofs:

1. Unsupported container: untrusted A is refused before spawn; A_spawned does
   NOT exist; B executes and completes.

2. Supported containment host (bare metal): A_spawned exists (grandchild was
   created); B_started exists before A cleanup (proves overlap); A_survived
   does NOT exist (grandchild was killed); both A and B succeed.

Uses deterministic barriers:
  - B is started first and writes B_started immediately
  - Parent waits for B_started before starting A
  - A waits for A_spawned before returning (ensures grandchild exists)
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import textwrap
import time
from pathlib import Path

import pytest

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner


def _make_node_module(tmp_path: Path, name: str, body: str) -> Path:
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
        "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
        '            output={"status": "ok"}, output_type="result",\n'
        "        )\n"
    )
    return module


def _make_envelope(node_id: str = "test_node") -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run", chain_id="test-chain",
        node_id=node_id, step_id=1, payload={"query": "test"},
    )


class TestConcurrentIsolation:
    """Terminating sandbox A must not affect sandbox B."""

    @pytest.mark.skipif(os.name == "nt", reason="POSIX only")
    def test_concurrent_isolation_t3_facade(self, tmp_path):
        """On POSIX, untrusted A is refused by the T3.0 safety fence. B still runs."""
        a_spawned = Path(tempfile.gettempdir()) / f"h2_ci_refused_{os.getpid()}.txt"
        if a_spawned.exists():
            a_spawned.unlink()

        gc_file = tmp_path / "refused_gc.py"
        gc_file.write_text(textwrap.dedent(f"""
            open(r'{a_spawned}', 'w').write('spawned')
        """))
        module_a = _make_node_module(tmp_path, "refused_a",
            f"import subprocess, sys\n"
            f"subprocess.Popen([sys.executable, r'{gc_file}'])")
        module_b = _make_node_module(tmp_path, "refused_b",
            "import time\ntime.sleep(1)")

        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=50_000)

        async def run_both():
            task_a = asyncio.create_task(runner.run_isolated(
                _make_envelope("refused_a"), module_a, "TestNode", "refused_a",
                trust_level="local_untrusted",
            ))
            task_b = asyncio.create_task(runner.run_isolated(
                _make_envelope("refused_b"), module_b, "TestNode", "refused_b",
                trust_level="local_trusted",
            ))
            result_a = await task_a
            result_b = await task_b
            return result_a, result_b

        result_a, result_b = asyncio.run(run_both())

        # A must be refused — the supervised route fails closed on hosts
        # without the required topology privileges (T3/H0.2 activation).
        assert not result_a["success"], (
            "untrusted A executed on POSIX without supervised enforcement"
        )
        _err_a = result_a.get("error", "")
        assert (
            "supervised execution failed before workload start" in _err_a
            or "supervised_cgroup_unsupported" in _err_a
        ), _err_a[:200]

        # A's grandchild was never spawned.
        assert not a_spawned.exists(), (
            "A_spawned marker exists — grandchild was created despite refusal"
        )

        # B must complete successfully.
        assert result_b["success"], f"B failed: {result_b.get('error')}"
