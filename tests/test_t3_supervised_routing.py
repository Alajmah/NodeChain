"""T3 (H0.2) mapping/unit qualification — supervised routing for POSIX
untrusted nodes.

Covers the frozen mapping layer while the production fence remains in
place (activation is the final production edit):
  - every frozen outcome-matrix row via the pure translator
  - no synthetic enforcement flags; PID-ns derived from evidence only
  - adapter workload-equivalence inputs (argv/stdin/cwd/env split)
  - supervisor/workload environment separation
  - temp-dir ownership + cleanup (including on failure)
  - cgroup-request refusal BEFORE any start
  - cancellation propagation (no response mapping)
  - containment config construction
  - supervised child-script shape (node-local policy only)
  - bootstrap containment block (fail-closed slot filled)
  - NodeInvoker evidence projection on success and failure
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner


def _envelope() -> InvocationEnvelope:
    return InvocationEnvelope(
        envelope_id=str(uuid.uuid4()), run_id="r", chain_id="c",
        node_id="n", step_id=1, payload={},
    )


def _sup_result(**over) -> dict:
    """A well-formed supervised result, overridable per row."""
    base = {
        "process_started": True,
        "process_exit_code": 0,
        "process_timed_out": False,
        "stdout": "",
        "stderr": "",
        "output_truncated": False,
        "exit_code_interpretation": "pass",
        "reason": None,
        "backend": "native_os_sandbox",
        "sandbox_metadata": {},
        "sandbox_event_log": [],
    }
    base.update(over)
    return base


def _ok_stdout() -> str:
    return json.dumps({
        "request_envelope_id": "e", "run_id": "r", "chain_id": "c",
        "node_id": "n", "step_id": 1, "output": {"ok": True},
        "output_type": "dict", "metadata": {"child_policy_enforced": True},
    })


_R = SubprocessRunner()


# ---------------------------------------------------------------------------
# 1. Frozen outcome matrix — every row through the pure translator
# ---------------------------------------------------------------------------


class TestOutcomeMatrix:
    def test_setup_failure_not_started(self):
        out = _R._translate_supervised_result(
            _sup_result(process_started=False, exit_code_interpretation="error",
                        reason="supervisor_spawn_failed: boom",
                        process_exit_code=None),
            child_cwd="/w", duration_ms=3,
        )
        assert out["success"] is False
        assert out["exit_code"] == -1 or out["exit_code"] == 126
        assert out["supervised_execution"]["process_started"] is False
        assert "supervisor_spawn_failed" in out["error"]

    def test_exec_never_confirmed_126(self):
        out = _R._translate_supervised_result(
            _sup_result(process_started=False,
                        exit_code_interpretation="error",
                        reason="enforcement_failed",
                        stderr="containment unavailable: seccomp"),
            child_cwd="/w", duration_ms=3,
        )
        assert out["success"] is False
        assert out["exit_code"] == 126
        assert out["child_policy_enforced"] is False
        assert out["supervised_execution"]["process_started"] is False

    def test_exec_confirmed_success(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout()),
            child_cwd="/w", duration_ms=5,
        )
        assert out["success"] is True
        assert out["response"]["node_id"] == "n"
        assert out["child_policy_enforced"] is True
        assert out["supervised_execution"]["process_started"] is True

    def test_nonzero_exit_retained(self):
        out = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail", reason=None,
                        process_exit_code=7, stderr="boom"),
            child_cwd="/w", duration_ms=5,
        )
        assert out["success"] is False
        assert out["exit_code"] == 7
        assert out["error"] == "boom"

    def test_signal_negative_retained(self):
        out = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail", reason="signal_15",
                        process_exit_code=-15),
            child_cwd="/w", duration_ms=5,
        )
        assert out["success"] is False
        assert out["exit_code"] == -15
        assert "signal 15" in out["error"]

    def test_sigsys_classified_seccomp(self):
        out = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail",
                        reason="seccomp_sigsys_kill", process_exit_code=-31),
            child_cwd="/w", duration_ms=5,
        )
        assert out["success"] is False
        assert out["exit_code"] == -31
        assert "SIGSYS" in out["error"]

    def test_timeout_row(self):
        out = _R._translate_supervised_result(
            _sup_result(process_timed_out=True,
                        exit_code_interpretation="timeout", reason="timeout",
                        process_exit_code=None),
            child_cwd="/w", duration_ms=99,
        )
        assert out["success"] is False
        assert out["exit_code"] == 2
        assert "Timeout" in out["error"]
        assert out["supervised_execution"]["process_timed_out"] is True

    def test_output_cap_row(self):
        out = _R._translate_supervised_result(
            _sup_result(output_truncated=True,
                        exit_code_interpretation="fail",
                        reason="output_limit_exceeded"),
            child_cwd="/w", duration_ms=9,
        )
        assert out["success"] is False
        assert out["exit_code"] == 3
        assert "Output exceeded" in out["error"]
        assert out["supervised_execution"]["output_truncated"] is True

    def test_cleanup_failure_dominates(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout(),
                        exit_code_interpretation="error",
                        reason="cleanup_failed"),
            child_cwd="/w", duration_ms=9,
        )
        assert out["success"] is False
        assert "cleanup_failed" in out["error"]

    def test_malformed_json_exit0(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout="not-json{", process_exit_code=0),
            child_cwd="/w", duration_ms=9,
        )
        assert out["success"] is False
        assert "Invalid JSON response" in out["error"]
        # execution occurred — started truth retained
        assert out["supervised_execution"]["process_started"] is True
        assert out["supervised_execution"]["process_exit_code"] == 0

    def test_exit10_policy_convention_preserved_not_assumed(self):
        out = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail", reason=None,
                        process_exit_code=10, stderr=""),
            child_cwd="/w", duration_ms=5,
        )
        # exit 10 → child_policy_enforced=True preserved as existing
        # convention; other nonzero exits are NOT assumed policy failures.
        assert out["child_policy_enforced"] is True
        out2 = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail", reason=None,
                        process_exit_code=11, stderr=""),
            child_cwd="/w", duration_ms=5,
        )
        assert out2["child_policy_enforced"] is False


# ---------------------------------------------------------------------------
# 2. No synthetic flags; PID-ns derived from evidence only
# ---------------------------------------------------------------------------


class TestMetadataTruth:
    def test_absent_evidence_stays_false(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout(), sandbox_metadata={}),
            child_cwd="/w", duration_ms=5,
        )
        assert out["network_namespace_enforced"] is False
        assert out["mount_namespace_enforced"] is False
        assert out["mount_confinement_enforced"] is False
        assert out["seccomp_enforced"] is False
        assert out["seccomp_available"] is False

    def test_pid_namespace_derived_from_verification(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout(),
                        sandbox_metadata={"enforcement": "pid_namespace_verified"}),
            child_cwd="/w", duration_ms=5,
        )
        assert out["pid_namespace_enforced"] is True

    def test_pid_namespace_absent_without_evidence(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout(), sandbox_metadata={}),
            child_cwd="/w", duration_ms=5,
        )
        assert out["pid_namespace_enforced"] is False

    def test_supervisor_seccomp_evidence_propagates(self):
        out = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout(),
                        sandbox_metadata={"seccomp_enforced": True,
                                          "seccomp_available": True}),
            child_cwd="/w", duration_ms=5,
        )
        assert out["seccomp_enforced"] is True


# ---------------------------------------------------------------------------
# 3. Containment config + cgroup refusal
# ---------------------------------------------------------------------------


class TestContainmentConfig:
    def test_no_controls_requested(self):
        r = SubprocessRunner()
        assert r._supervised_containment_config("/pkg", "/tmp") is None

    def test_full_request_shape(self):
        r = SubprocessRunner(
            enable_network_namespace=True,
            enable_mount_confinement=True, enable_procfs_isolation=True,
        )
        cfg = r._supervised_containment_config(
            "/pkg", "/tmp/t1", enable_seccomp=True,
        )
        assert cfg == {
            "network_namespace": True,
            "mount_confinement": True,
            "package_root": "/pkg",
            "temp_dir": "/tmp/t1",
            "procfs_isolation": True,
            "seccomp": True,
        }

    def test_mount_namespace_without_confinement(self):
        r = SubprocessRunner(enable_mount_namespace=True)
        cfg = r._supervised_containment_config("/pkg", "/tmp/t1")
        assert cfg == {"mount_namespace": True}

    def test_confinement_subsumes_mount_namespace(self):
        r = SubprocessRunner(enable_mount_namespace=True,
                             enable_mount_confinement=True)
        cfg = r._supervised_containment_config("/pkg", "/tmp/t1")
        assert "mount_namespace" not in cfg
        assert cfg["mount_confinement"] is True


# ---------------------------------------------------------------------------
# 4. Adapter: workload equivalence, env separation, temp, cancellation
# ---------------------------------------------------------------------------


def _make_module(tmp_path: Path) -> Path:
    mod = tmp_path / "t3_node_mod.py"
    mod.write_text(
        "class TNode:\n"
        "    async def execute(self, envelope):\n"
        "        from nodechain.core.envelope import EnvelopeResponse\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id,\n"
        "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
        "            output={'ran': True}, output_type='dict',\n"
        "            metadata={'child_policy_enforced': True},\n"
        "        )\n",
        encoding="utf-8",
    )
    return mod


class TestAdapter:
    @pytest.mark.asyncio
    async def test_workload_contract_and_env_split(self, tmp_path, monkeypatch):
        mod = _make_module(tmp_path)
        monkeypatch.setenv("NODECHAIN_TEST_SECRET_X", "leak-me")
        monkeypatch.setenv("AN_INNOCENT_VAR", "keep-me")
        captured = {}

        async def fake_supervised(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", fake_supervised):
            r = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        assert out["success"] is True
        # argv: python -I -c <script> — isolated startup: no cwd on
        # sys.path, PYTHON* env ignored, no user site (R7 startup
        # boundary), then the trusted child script.
        assert captured["argv"][0] == sys.executable
        assert captured["argv"][1] == "-I"
        assert captured["argv"][2] == "-c"
        # payload: {config, envelope}
        payload = json.loads(captured["workload_stdin"].decode())
        assert payload["config"]["trust_level"] == "local_untrusted"
        assert payload["config"]["node_id"] == "t3n"
        assert payload["envelope"]["node_id"] == "n"
        # env separation: supervisor minimal (PATH+PYTHONPATH, no secrets)
        assert set(captured["supervisor_env"]) <= {"PATH", "PYTHONPATH"}
        assert "NODECHAIN_TEST_SECRET_X" not in captured["supervisor_env"]
        # workload env: secret filtered, innocents kept, TEMP redirected
        wenv = captured["workload_env"]
        assert "NODECHAIN_TEST_SECRET_X" not in wenv
        assert wenv.get("AN_INNOCENT_VAR") == "keep-me"
        tempdir = wenv["TMPDIR"]
        assert wenv["TEMP"] == tempdir and wenv["TMP"] == tempdir
        # temp dir cleaned after return
        assert not Path(tempdir).exists()
        # containment None (nothing requested) passed through
        assert captured["containment"] is None

    @pytest.mark.asyncio
    async def test_cgroup_request_refused_before_start(self, tmp_path):
        mod = _make_module(tmp_path)
        spawned = []

        async def fake_supervised(**kw):
            spawned.append(kw)
            return _sup_result(stdout=_ok_stdout())

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", fake_supervised):
            r = SubprocessRunner(enable_cgroup=True)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        assert spawned == [], "supervisor spawned despite cgroup refusal"
        assert out["success"] is False
        assert out["exit_code"] == 126
        assert "supervised_cgroup_unsupported" in out["error"]
        assert out["cgroup_limits_requested"] is True
        assert out["cgroup_limits_enforced"] is False

    @pytest.mark.asyncio
    async def test_cancellation_propagates_and_temp_cleaned(self, tmp_path):
        mod = _make_module(tmp_path)
        tempdirs = []

        async def cancelling_supervised(**kw):
            # Record the temp dir the adapter redirected into the env.
            tempdirs.append(kw["workload_env"]["TMPDIR"])
            raise asyncio.CancelledError()

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", cancelling_supervised):
            r = SubprocessRunner()
            with pytest.raises(asyncio.CancelledError):
                await r._run_supervised_untrusted(
                    _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
                )
        assert not Path(tempdirs[0]).exists(), "temp dir leaked on cancellation"

    @pytest.mark.asyncio
    async def test_temp_cleaned_on_translated_failure(self, tmp_path):
        mod = _make_module(tmp_path)
        tempdirs = []

        async def failing_supervised(**kw):
            tempdirs.append(kw["workload_env"]["TMPDIR"])
            return _sup_result(process_started=False,
                               exit_code_interpretation="error",
                               reason="supervisor_spawn_failed: x",
                               process_exit_code=None)

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", failing_supervised):
            r = SubprocessRunner()
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        assert out["success"] is False
        assert not Path(tempdirs[0]).exists()

    @pytest.mark.asyncio
    async def test_confinement_passes_chrooted_module_path(self, tmp_path):
        mod = _make_module(tmp_path)
        captured = {}

        async def fake_supervised(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", fake_supervised):
            r = SubprocessRunner(enable_mount_confinement=True)
            await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted",
                str(tmp_path), enable_seccomp=True,
            )
        payload = json.loads(captured["workload_stdin"].decode())
        assert payload["config"]["workload_module_path"] == f"/package/{mod.name}"
        assert captured["containment"]["mount_confinement"] is True
        assert captured["containment"]["package_root"] == str(tmp_path)

    @pytest.mark.asyncio
    async def test_oversize_payload_maps_to_setup_failure(self, tmp_path):
        mod = _make_module(tmp_path)

        async def fake_supervised(**kw):
            return _sup_result(
                process_started=False, exit_code_interpretation="error",
                reason="workload_input_oversized", process_exit_code=None,
            )

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", fake_supervised):
            r = SubprocessRunner()
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        assert out["success"] is False
        assert out["supervised_execution"]["process_started"] is False
        assert out["supervised_execution"]["reason"] == "workload_input_oversized"


# ---------------------------------------------------------------------------
# 5. Script shapes
# ---------------------------------------------------------------------------


class TestScriptShapes:
    def test_supervised_child_script_policy_only(self):
        r = SubprocessRunner()
        script = r._build_supervised_child_script(
            "/m/path.py", "TNode", "local_untrusted", "/pkg",
            enable_seccomp=True,
        )
        # Node-local policy present
        for needle in (
            "enforce_imports_for_node", "enforce_filesystem_for_node",
            "enforce_subprocess_for_node", "enforce_network_for_node",
            "importlib.util.spec_from_file_location",
        ):
            assert needle in script
        # OS containment phases ABSENT
        for banned in (
            "apply_pid_namespace_two_stage", "remount_procfs",
            "apply_network_namespace", "apply_mount_namespace",
            "apply_mount_confinement", "SeccompBackend", "SeccompProfile",
        ):
            assert banned not in script, f"supervised script leaks {banned}"

    def test_legacy_child_script_unchanged(self):
        r = SubprocessRunner(enable_pid_namespace=True)
        script = r._build_child_script(
            "/m/path.py", "TNode", "local_untrusted", "/pkg",
            enable_seccomp=True,
        )
        # The non-supervised form keeps its containment phases.
        assert "apply_pid_namespace_two_stage" in script
        assert "SeccompBackend" in script

    def test_bootstrap_contains_fail_closed_containment(self):
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        src = _build_bootstrap_script()
        assert "containment" in src
        assert "_META_ENFORCEMENT_FAILED" in src
        assert "apply_network_namespace" in src
        assert "apply_mount_confinement" in src
        assert "SeccompBackend" in src
        assert "failed_primitives" in src

    def test_supervised_argv_forwards_containment(self):
        import inspect
        from nodechain.runtime.supervised_argv import run_supervised_argv_async
        sig = inspect.signature(run_supervised_argv_async)
        assert "containment" in sig.parameters


# ---------------------------------------------------------------------------
# 6. Routing activation: untrusted POSIX reaches the supervised adapter
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX routing behavior")
class TestRouting:
    @pytest.mark.asyncio
    async def test_routes_to_supervised_adapter(self, tmp_path, monkeypatch):
        """POSIX untrusted routes to _run_supervised_untrusted and returns
        its translated result — never the legacy refusal, never the legacy
        spawn body."""
        mod = _make_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        called = {}

        async def fake_adapter(self, **kw):
            called.update(kw)
            return {"success": False, "error": "marker",
                    "exit_code": 126, "isolation_mode": "subprocess",
                    "duration_ms": 0, "child_policy_enforced": False,
                    "child_cwd": "", "temp_dir_isolated": False}

        monkeypatch.setattr(SubprocessRunner, "_run_supervised_untrusted",
                            fake_adapter)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "route_node",
            trust_level="local_untrusted", package_root="/pkg",
            enable_seccomp=True,
        )
        assert result["error"] == "marker"
        assert called["trust_level"] == "local_untrusted"
        assert called["package_root"] == "/pkg"
        assert called["enable_seccomp"] is True
        assert called["class_name"] == "TNode"

    @pytest.mark.asyncio
    async def test_legacy_spawn_unreachable_for_untrusted(self, tmp_path, monkeypatch):
        """The legacy POSIX spawn body must never execute for untrusted
        trust levels: create_subprocess_exec explodes if reached."""
        mod = _make_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)

        async def exploding_spawn(*a, **kw):
            raise AssertionError("legacy spawn body reached for untrusted")

        async def fake_adapter(self, **kw):
            return {"success": False, "error": "routed", "exit_code": 126,
                    "isolation_mode": "subprocess", "duration_ms": 0,
                    "child_policy_enforced": False, "child_cwd": "",
                    "temp_dir_isolated": False}

        monkeypatch.setattr(SubprocessRunner, "_run_supervised_untrusted",
                            fake_adapter)
        import nodechain.runtime.subprocess_runner as srm
        with patch.object(srm.asyncio, "create_subprocess_exec",
                          exploding_spawn):
            result = await r.run_isolated(
                _envelope(), mod, "TNode", "route_node",
                trust_level="remote_untrusted",
            )
        assert result["error"] == "routed"

    @pytest.mark.asyncio
    async def test_real_supervised_run_of_simple_node(self, tmp_path):
        """Real integration: a simple node executes through the actual
        supervised stack and returns its response. On a POSIX host without
        the privileges the topology needs (hosted CI), the run fails CLOSED
        before workload start — the honest T3 behavior there."""
        mod = _make_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=30, max_output_bytes=100_000)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "integ_node",
            trust_level="local_untrusted",
        )
        if result["success"]:
            assert result["response"]["output"] == {"ran": True}
            assert result["supervised_execution"]["process_started"] is True
        else:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            err = result.get("error", "")
            assert err.startswith(
                "supervised execution failed before workload start"
            ) or err.startswith("supervised_cgroup_unsupported"), err[:200]


# ---------------------------------------------------------------------------
# 7. NodeInvoker evidence projection
# ---------------------------------------------------------------------------


class TestNodeInvokerProjection:
    def _isolation_config(self, module: Path) -> dict:
        return {
            "module_path": str(module),
            "class_name": "TNode",
        }

    @pytest.mark.asyncio
    async def test_failure_carries_projection(self, tmp_path):
        from nodechain.runtime.node_invoker import NodeInvoker
        from nodechain.nodes.base_node import BaseNode

        class _N(BaseNode):
            def manifest(self):
                from nodechain.core.manifest import NodeManifest
                return NodeManifest(node_id="n", node_type="model",
                                    name="n", version="1")

            def contract(self):
                from nodechain.core.contract import NodeContract
                return NodeContract(contract_id="x", node_id="n", version="1",
                                    entry={}, exit={})

            async def execute(self, envelope):
                raise AssertionError("must not run")

        async def fake_run_isolated(self, **kw):
            return None  # pragma: no cover - unused

        mod = _make_module(tmp_path)
        inv = NodeInvoker()
        sup_fail = {
            "success": False,
            "error": "supervised execution failed before workload start (x)",
            "exit_code": 126,
            "isolation_mode": "subprocess",
            "duration_ms": 4,
            "child_policy_enforced": False,
            "child_cwd": "/w",
            "temp_dir_isolated": True,
            "supervised_execution": {
                "backend": "native_os_sandbox",
                "process_started": False,
                "process_timed_out": False,
                "output_truncated": False,
                "exit_code_interpretation": "error",
                "reason": "x",
                "process_exit_code": None,
                "sandbox_metadata": {},
            },
        }
        with patch(
            "nodechain.runtime.subprocess_runner.get_subprocess_runner",
            lambda config=None: _FakeRunner(sup_fail),
        ):
            resp, _ = await inv.invoke(
                _N(), _envelope(), trust_level="local_untrusted",
                isolation_config=self._isolation_config(mod),
            )
        assert resp.success is False
        assert resp.metadata["supervised_execution"]["process_started"] is False
        assert resp.metadata["exit_code"] == 126

    @pytest.mark.asyncio
    async def test_cancellation_not_consumed(self, tmp_path):
        from nodechain.runtime.node_invoker import NodeInvoker
        from nodechain.nodes.base_node import BaseNode

        class _CN(BaseNode):
            def manifest(self):
                from nodechain.core.manifest import NodeManifest
                return NodeManifest(node_id="n", node_type="model",
                                    name="n", version="1")

            def contract(self):
                from nodechain.core.contract import NodeContract
                return NodeContract(contract_id="x", node_id="n", version="1",
                                    entry={}, exit={})

            async def execute(self, envelope):
                raise asyncio.CancelledError()

        inv = NodeInvoker()
        mod = _make_module(tmp_path)
        with pytest.raises(asyncio.CancelledError):
            await inv.invoke(
                _CN(), _envelope(), trust_level="built_in",
                isolation_config=None,
            )


class _FakeRunner:
    """Duck-typed runner returning a canned result (bypasses class lookup)."""

    def __init__(self, result):
        self._result = result

    def should_use_subprocess(self, trust_level):
        return True

    async def run_isolated(self, **kw):
        return self._result


# ---------------------------------------------------------------------------
# 8. Requested-containment behavior (fail-closed everywhere; enforcement
#    proven where the host provides the capability)
# ---------------------------------------------------------------------------


def _can_unshare_pid_ns() -> bool:
    if os.name != "posix":
        return False
    # Probe in a SUBPROCESS: an in-process unshare(CLONE_NEWPID) moves the
    # pytest process into a new PID ns for future children, after which the
    # supervised launcher's outer-/proc topology proof can no longer resolve
    # the launcher's own pid (it lives only in the invisible child ns). The
    # sacrificial probe process keeps the test process unpoisoned.
    import subprocess as _sp
    probe = (
        "import ctypes, sys\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "rc = libc.unshare(0x20000000)\n"
        "sys.exit(0 if rc == 0 else 1)\n"
    )
    try:
        return _sp.run(
            [sys.executable, "-c", probe],
            capture_output=True, timeout=30,
        ).returncode == 0
    except Exception:
        return False


def _seccomp_available() -> bool:
    try:
        import seccomp  # noqa: F401
        return True
    except ImportError:
        try:
            import pyseccomp  # noqa: F401
            return True
        except ImportError:
            return False


@pytest.mark.skipif(os.name != "posix", reason="POSIX containment behavior")
class TestRequestedContainment:
    @pytest.mark.asyncio
    async def test_unprivileged_requested_containment_fails_closed(self, tmp_path):
        """Where the host cannot provide a requested control, the run fails
        BEFORE the node executes — never a weak fallback. On hosts that CAN
        provide it, this test skips (the enforced variant below runs)."""
        if _can_unshare_pid_ns():
            pytest.skip("host can unshare PID ns — fail-closed variant n/a")
        mod = _make_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=20, max_output_bytes=100_000,
                             enable_network_namespace=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "req_node",
            trust_level="local_untrusted",
        )
        assert result["success"] is False
        assert result["supervised_execution"]["process_started"] is False

    @pytest.mark.asyncio
    async def test_privileged_requested_pid_ns_derives_evidence(self, tmp_path):
        """On a host where the supervised topology runs, the structural PID
        namespace verification derives pid_namespace_enforced from trusted
        evidence (never synthesized). Hosts that cannot unshare skip —
        the topology fails closed there and nothing can be derived."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        mod = _make_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=30, max_output_bytes=100_000)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "req_node",
            trust_level="local_untrusted",
        )
        # Even on a host where bare unshare(CLONE_NEWPID) succeeds, the
        # full supervised topology may fail for another reason; only derive
        # evidence when the run actually completed.
        if result["success"]:
            assert result["pid_namespace_enforced"] is True
            ev = result["supervised_execution"]["sandbox_metadata"]
            assert ev.get("enforcement") == "pid_namespace_verified"
        else:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            reason = sup.get("reason") or ""
            assert reason.startswith("unshare_failed") or \
                reason == "enforcement_failed" or \
                result.get("error", "").startswith(
                    "supervised execution failed before workload start"), reason

    @pytest.mark.asyncio
    async def test_requested_seccomp_enforced_or_fail_closed(self, tmp_path):
        """Requested seccomp: enforced with real evidence where the filter
        library exists; refused before workload start where it does not.
        Either way — no synthetic enforcement flag."""
        mod = _make_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=30, max_output_bytes=100_000)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "sec_node",
            trust_level="local_untrusted", enable_seccomp=True,
        )
        if _seccomp_available() and _can_unshare_pid_ns():
            assert result["success"], f"seccomp run failed: {result}"
            assert result["seccomp_enforced"] is True
            assert result["seccomp_available"] is True
        else:
            # Fail-closed family: the topology itself may be unavailable
            # (unprivileged host: unshare_failed before any containment
            # runs), or the requested seccomp control could not be enforced
            # (enforcement_failed). Either way: never started, never a weak
            # fallback, no synthetic flags.
            assert result["success"] is False
            assert result["supervised_execution"]["process_started"] is False
            reason = result["supervised_execution"]["reason"] or ""
            assert (
                reason == "enforcement_failed"
                or reason.startswith("unshare_failed")
                or result.get("error", "").startswith(
                    "supervised execution failed before workload start")
            ), f"unexpected fail-closed reason: {reason}"


# ---------------------------------------------------------------------------
# 9. Review-finding regressions (Codex P1x2 + P2x2 at 9ad1d78)
# ---------------------------------------------------------------------------


class TestReviewRegressions:
    def test_confinement_root_never_host_root(self, tmp_path):
        """P1-1: mount confinement with no explicit package_root must derive
        the confinement root from the module's parent — never "/" (which
        would bind the host root at /package and defeat confinement)."""
        r = SubprocessRunner(enable_mount_confinement=True)
        cfg = r._supervised_containment_config(
            "", "/tmp/t9", module_parent=str(tmp_path),
        )
        assert cfg["mount_confinement"] is True
        assert cfg["package_root"] == str(tmp_path)
        assert cfg["package_root"] != "/"

    def test_confinement_root_explicit_package_root_wins(self, tmp_path):
        r = SubprocessRunner(enable_mount_confinement=True)
        cfg = r._supervised_containment_config(
            "/pkg/explicit", "/tmp/t9", module_parent=str(tmp_path),
        )
        assert cfg["package_root"] == "/pkg/explicit"

    def test_supervised_script_uses_workload_fs_root(self):
        """P1-2: the child enforcers must receive the workload-visible root
        (config workload_fs_root), not the host path."""
        r = SubprocessRunner()
        script = r._build_supervised_child_script(
            "/m/path.py", "TNode", "local_untrusted", "/host/pkg",
        )
        assert "workload_fs_root" in script
        assert "fs_policy_root or None" in script

    def test_adapter_resolves_relative_module_path(self, tmp_path):
        """P2-1: a relative module path is resolved at the adapter before
        the workload cwd changes; missing modules fail with the legacy
        module-not-found shape."""
        import asyncio
        async def _no_spawn(**kw):
            raise AssertionError("spawned for missing module")
        import nodechain.runtime.supervised_argv as sa
        rel = tmp_path / "rel_node.py"
        rel.write_text("class T:\n    pass\n", encoding="utf-8")
        r = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        captured = {}
        async def capture(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())
        with patch.object(sa, "run_supervised_argv_async", capture):
            out = asyncio.run(r._run_supervised_untrusted(
                _envelope(), rel, "T", "relnode", "local_untrusted", "",
            ))
        assert out["success"] is True
        payload = json.loads(captured["workload_stdin"].decode())
        resolved = str(rel.resolve())
        got = payload["config"]["workload_module_path"]
        assert Path(got).is_absolute(), f"module path not resolved: {got}"
        assert Path(got) == Path(resolved), f"{got} != {resolved}"

    def test_missing_module_fails_without_spawn(self, tmp_path):
        import asyncio
        import nodechain.runtime.supervised_argv as sa
        r = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        async def explode(**kw):
            raise AssertionError("spawned for missing module")
        missing = tmp_path / "does_not_exist.py"
        with patch.object(sa, "run_supervised_argv_async", explode):
            out = asyncio.run(r._run_supervised_untrusted(
                _envelope(), missing, "T", "mnode", "local_untrusted", "",
            ))
        assert out["success"] is False
        assert "Module not found" in out["error"]
        assert out["exit_code"] == -1

    def test_bootstrap_confinement_precedes_procfs(self):
        """P2-2: in the generated bootstrap, the mount-confinement block
        must appear BEFORE the procfs-isolation block (confinement creates
        a fresh mount ns + chroot that would discard an earlier remount)."""
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        src = _build_bootstrap_script()
        confine_idx = src.index('if _containment.get("mount_confinement"):')
        procfs_idx = src.index('if _containment.get("procfs_isolation"):')
        assert confine_idx < procfs_idx, (
            "procfs isolation runs before mount confinement — an earlier "
            "procfs remount would be discarded by the confinement chroot"
        )


# ---------------------------------------------------------------------------
# 10. Second review round (852bf6d blockers) — frozen-contract exactness
# ---------------------------------------------------------------------------


class TestNotStartedMatrixExact:
    """Frozen matrix: parent/setup failures → -1; supervisor-existed but
    exec never confirmed → 126. No either-or assertion."""

    def test_setup_family_minus_one_exactly(self):
        for reason in (
            "supervisor_spawn_failed: boom",
            "pipe_creation_failed: x",
            "config_serialize_failed: y",
            "config_oversized",
            "workload_input_oversized",
            "supervisor_env_failed: z",
        ):
            key = reason.split(":")[0].strip()
            out = _R._translate_supervised_result(
                _sup_result(process_started=False,
                            exit_code_interpretation="error",
                            reason=reason, process_exit_code=None),
                child_cwd="/w", duration_ms=2,
            )
            assert out["exit_code"] == -1, f"{key}: {out['exit_code']}"
            assert out["success"] is False
            assert out["supervised_execution"]["process_started"] is False

    def test_bootstrap_family_126_exactly(self):
        for reason in (
            "enforcement_failed", "bootstrap_failed",
            "unshare_failed: unshare_clone_newpid_failed: errno=1",
            "protocol_eof_before_terminal",
        ):
            key = reason.split(":")[0].strip()
            out = _R._translate_supervised_result(
                _sup_result(process_started=False,
                            exit_code_interpretation="error",
                            reason=reason, process_exit_code=None),
                child_cwd="/w", duration_ms=2,
            )
            assert out["exit_code"] == 126, f"{key}: {out['exit_code']}"
            assert out["success"] is False

    def test_prestart_timeout_is_bootstrap_126_not_workload_2(self):
        out = _R._translate_supervised_result(
            _sup_result(process_started=False, process_timed_out=True,
                        exit_code_interpretation="timeout",
                        reason="bootstrap_timeout", process_exit_code=None),
            child_cwd="/w", duration_ms=2,
        )
        assert out["exit_code"] == 126
        assert "bootstrap timeout" in out["error"]


class TestNoSynthesizedPolicyFlag:
    def test_output_cap_does_not_invent_policy_flag(self):
        out = _R._translate_supervised_result(
            _sup_result(output_truncated=True,
                        exit_code_interpretation="fail",
                        reason="output_limit_exceeded"),
            child_cwd="/w", duration_ms=9,
        )
        assert out["success"] is False
        assert out["exit_code"] == 3
        assert out["child_policy_enforced"] is False, (
            "output truncation proves nothing about Python enforcers"
        )

    def test_sigsys_does_not_invent_policy_flag(self):
        out = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail",
                        reason="seccomp_sigsys_kill", process_exit_code=-31),
            child_cwd="/w", duration_ms=9,
        )
        assert out["success"] is False
        assert out["exit_code"] == -31
        assert out["child_policy_enforced"] is False, (
            "SIGSYS proves supervisor seccomp only — not the node-local "
            "Python enforcers"
        )

    def test_exit10_convention_preserved(self):
        out = _R._translate_supervised_result(
            _sup_result(exit_code_interpretation="fail", reason=None,
                        process_exit_code=10, stderr=""),
            child_cwd="/w", duration_ms=5,
        )
        assert out["child_policy_enforced"] is True


class TestTempCleanupVisibility:
    @pytest.mark.asyncio
    async def test_cleanup_failure_converts_success(self, tmp_path):
        import asyncio
        import shutil as _sh
        mod = _make_module(tmp_path)

        async def ok_supervised(**kw):
            return _sup_result(stdout=_ok_stdout())

        import nodechain.runtime.supervised_argv as sa
        real_rmtree = _sh.rmtree
        def failing_rmtree(path, *a, **k):
            raise OSError("disk full during rmtree")
        with patch.object(sa, "run_supervised_argv_async", ok_supervised), \
             patch.object(_sh, "rmtree", failing_rmtree):
            r = SubprocessRunner()
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        assert out["success"] is False
        assert "temp_cleanup_failed" in out["error"]
        assert out["exit_code"] == -1

    @pytest.mark.asyncio
    async def test_cleanup_failure_notes_but_preserves_supervisor_failure(
        self, tmp_path,
    ):
        import asyncio
        import shutil as _sh
        mod = _make_module(tmp_path)

        async def fail_supervised(**kw):
            return _sup_result(process_started=False,
                               exit_code_interpretation="error",
                               reason="enforcement_failed",
                               process_exit_code=None)

        import nodechain.runtime.supervised_argv as sa
        def failing_rmtree(path, *a, **k):
            raise OSError("rmtree failed")
        with patch.object(sa, "run_supervised_argv_async", fail_supervised), \
             patch.object(_sh, "rmtree", failing_rmtree):
            r = SubprocessRunner()
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        # The stronger supervisor failure stays primary...
        assert out["exit_code"] == 126
        assert "before workload start" in out["error"]
        # ...with the cleanup failure noted, not swallowed.
        assert "temp_cleanup_failed" in out["error"]

    @pytest.mark.asyncio
    async def test_confinement_reports_workload_visible_cwd(self, tmp_path):
        import asyncio
        import nodechain.runtime.supervised_argv as sa
        mod = _make_module(tmp_path)
        captured = {}

        async def ok_supervised(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        with patch.object(sa, "run_supervised_argv_async", ok_supervised):
            r = SubprocessRunner(enable_mount_confinement=True)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted",
                str(tmp_path),
            )
        # The host cwd is delivered for the bootstrap chdir/bind, but the
        # RESULT metadata reports the workload-visible post-chroot cwd.
        assert captured["workload_cwd"] == str(tmp_path)
        assert out["child_cwd"] == "/package"


class TestBootstrapConfinementCwdAndProcfs:
    def test_visible_cwd_reestablish_present(self):
        """The bootstrap consumes the adapter-supplied workload_visible_cwd
        (single derivation) and fails closed when absent/invalid — it never
        re-derives the cwd independently. Failures join the containment
        enforcement_failed family (post-TRACEME region; bootstrap_failed is
        structurally forbidden there)."""
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        src = _build_bootstrap_script()
        assert "workload_cwd_visible" in src
        assert '_containment.get("workload_visible_cwd")' in src
        assert "workload_visible_cwd_absent_or_invalid" in src
        assert '"workload_visible_cwd"' in src  # joins _failed family

    def test_proc_mountpoint_created_inside_chroot(self):
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        src = _build_bootstrap_script()
        assert '_os.mkdir("/proc", 0o755)' in src


# ---------------------------------------------------------------------------
# 11. Privileged confinement proofs (dual-truth: skip where unavailable)
# ---------------------------------------------------------------------------


def _make_cwd_module(tmp_path: Path) -> Path:
    mod = tmp_path / "cwd_node.py"
    mod.write_text(
        "import os\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TNode:\n"
        "    async def execute(self, envelope):\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id,\n"
        "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
        '            output={"cwd": os.getcwd()},\n'
        '            output_type="result",\n'
        "        )\n",
        encoding="utf-8",
    )
    return mod


@pytest.mark.skipif(os.name != "posix", reason="POSIX containment behavior")
class TestPrivilegedConfinementProofs:
    @pytest.mark.asyncio
    async def test_confinement_workload_reports_visible_cwd(self, tmp_path):
        """Real privileged proof: under mount confinement the node observes
        its own cwd from inside the chroot — must be the workload-visible
        /package (or /tmp), never a host path. Skips where the topology
        cannot run."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        mod = _make_cwd_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000,
                             enable_mount_confinement=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "cwd_node",
            trust_level="local_untrusted", package_root=str(tmp_path),
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(f"containment unavailable on this host: "
                        f"{(sup.get('reason') or '')[:120]}")
        observed = result["response"]["output"].get("cwd", "")
        assert observed in ("/package", "/tmp"), (
            f"workload cwd is not confinement-visible: {observed}"
        )
        assert not str(tmp_path) in observed, (
            "host path leaked as workload cwd inside the chroot"
        )
        assert result["child_cwd"] == observed

    @pytest.mark.asyncio
    async def test_confinement_plus_procfs_enforced_or_refused(self, tmp_path):
        """Combined mount-confinement + procfs isolation: on a privileged
        host both must be enforced together (the /proc mountpoint is
        created inside the confinement root); elsewhere the run must fail
        closed BEFORE the workload starts. Never a partial claim."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        mod = _make_cwd_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000,
                             enable_mount_confinement=True,
                             enable_procfs_isolation=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "cp_node",
            trust_level="local_untrusted", package_root=str(tmp_path),
        )
        if result["success"]:
            assert result["mount_confinement_enforced"] is True
            assert result["procfs_namespace_view_enforced"] is True, (
                "success claimed without the requested procfs view"
            )
        else:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result


# ---------------------------------------------------------------------------
# 12. Third review round (24123e5 narrow misses)
# ---------------------------------------------------------------------------


class TestSingleVisibleCwdDerivation:
    def test_no_explicit_package_root_reports_package(self, tmp_path):
        """R3-1: with package_root omitted, the containment config still
        binds the module parent at /package and the adapter's single
        derivation reports /package — metadata and bootstrap can no longer
        disagree."""
        mod = _make_module(tmp_path)
        r = SubprocessRunner(enable_mount_confinement=True)
        cfg = r._supervised_containment_config(
            "", "/tmp/t12", module_parent=str(tmp_path),
            visible_cwd="/package",
        )
        assert cfg["package_root"] == str(tmp_path)   # bind root: module parent
        assert cfg["workload_visible_cwd"] == "/package"  # visible cwd: explicit choice

    def test_temp_cwd_case_visible_tmp(self):
        r = SubprocessRunner(enable_mount_confinement=True)
        cfg = r._supervised_containment_config(
            "", "/tmp/t12", module_parent="/m", visible_cwd="/tmp",
        )
        assert cfg["workload_visible_cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_adapter_reports_single_derivation(self, tmp_path):
        """The adapter's result child_cwd under confinement comes from the
        same workload_visible_cwd it passes to the containment config."""
        import asyncio
        import nodechain.runtime.supervised_argv as sa
        mod = _make_module(tmp_path)
        captured = {}

        async def capture(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        with patch.object(sa, "run_supervised_argv_async", capture):
            r = SubprocessRunner(enable_mount_confinement=True)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted",
                "",  # NO package_root — module parent becomes the bind root
            )
        assert out["success"] is True
        # No explicit package_root → visible cwd is /tmp per the frozen
        # pre-confinement semantics... EXCEPT the confinement bind root is
        # the module parent, so the adapter chose /package? No: the frozen
        # rule is explicit-root→/package, temp-cwd→/tmp. No explicit root
        # means the temp-cwd case → /tmp.
        assert out["child_cwd"] == "/tmp", out["child_cwd"]
        conf = captured["containment"]
        assert conf["workload_visible_cwd"] == "/tmp"


class TestCleanupTruthAllPaths:
    @pytest.mark.asyncio
    async def test_cgroup_refusal_cleanup_failure_annotated(self, tmp_path):
        """R3-2: cgroup refusal flows through the cleanup owner — an rmtree
        failure on that path is noted on the refusal, not swallowed."""
        import asyncio
        import shutil as _sh
        mod = _make_module(tmp_path)

        def failing_rmtree(path, *a, **k):
            raise OSError("disk full")

        with patch.object(_sh, "rmtree", failing_rmtree):
            r = SubprocessRunner(enable_cgroup=True)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
            )
        assert out["success"] is False
        assert "supervised_cgroup_unsupported" in out["error"]
        assert "temp_cleanup_failed" in out["error"], (
            "cleanup failure swallowed on the cgroup-refusal path"
        )
        assert out["exit_code"] == 126

    @pytest.mark.asyncio
    async def test_missing_module_creates_no_temp_dir(self, tmp_path):
        """R3-2: module resolution precedes temp-dir creation — the
        missing-module failure leaves nothing to clean and cannot swallow
        a cleanup failure."""
        import asyncio
        import shutil as _sh
        mkdir_calls = []
        import tempfile as _tf
        real_mkdtemp = _tf.mkdtemp

        def spying_mkdtemp(*a, **k):
            mkdir_calls.append(1)
            return real_mkdtemp(*a, **k)

        missing = tmp_path / "nope.py"
        with patch.object(_tf, "mkdtemp", spying_mkdtemp):
            r = SubprocessRunner()
            out = await r._run_supervised_untrusted(
                _envelope(), missing, "T", "mnode", "local_untrusted", "",
            )
        assert out["success"] is False
        assert "Module not found" in out["error"]
        assert mkdir_calls == [], "temp dir created before module check"

    @pytest.mark.asyncio
    async def test_cgroup_refusal_normal_cleanup_still_primary(self, tmp_path):
        """Normal cleanup on the cgroup path: the refusal remains the
        primary truth, no cleanup note appears."""
        import asyncio
        mod = _make_module(tmp_path)
        r = SubprocessRunner(enable_cgroup=True)
        out = await r._run_supervised_untrusted(
            _envelope(), mod, "TNode", "t3n", "local_untrusted", "",
        )
        assert out["success"] is False
        assert out["exit_code"] == 126
        assert "temp_cleanup_failed" not in out["error"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX containment behavior")
class TestNoPackageRootConfinementCwd:
    @pytest.mark.asyncio
    async def test_no_package_root_confinement_runs_from_tmp(self, tmp_path):
        """R3-1 privileged proof, previously-missing case: confinement with
        NO explicit package_root. The bind root is the module parent; the
        workload-visible cwd is /tmp (temp-cwd semantics); the node
        observes that cwd from inside the chroot and the metadata agrees."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        mod = _make_cwd_module(tmp_path)
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000,
                             enable_mount_confinement=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "cwd_node",
            trust_level="local_untrusted",
            # NO package_root — the temp-cwd case
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(
                f"containment unavailable: {(sup.get('reason') or '')[:120]}"
            )
        observed = result["response"]["output"].get("cwd", "")
        assert observed == "/tmp", (
            f"no-package-root confinement cwd: {observed} (expected /tmp)"
        )
        assert result["child_cwd"] == "/tmp"
        assert result["mount_confinement_enforced"] is True


# ---------------------------------------------------------------------------
# 13. Fourth review round (exact-head Codex findings) — read-only T3 bind
#     mounts + parent-resolved package_root
# ---------------------------------------------------------------------------


class TestReadOnlyConfinementWiring:
    """R4-1: the T3 confinement contract requires /package and every runtime
    extra mount to be bind-remounted read-only; /tmp stays writable; a
    remount that cannot be established fails confinement closed."""

    def test_mount_confinement_signature_has_read_only_targets(self):
        import inspect
        from nodechain.sdk.namespace_profile import apply_mount_confinement
        sig = inspect.signature(apply_mount_confinement)
        assert "read_only_targets" in sig.parameters
        assert sig.parameters["read_only_targets"].default is None

    def test_bootstrap_requests_read_only_package_and_extras(self):
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        src = _build_bootstrap_script()
        # The RO list starts at /package and covers exactly the extras;
        # /tmp is never added (it stays writable by contract).
        assert '_ro = ["/package"]' in src
        assert "_ro.extend(_t for _s, _t in _extra)" in src
        assert "read_only_targets=_ro" in src
        # Enforcement evidence carries the remounted list.
        assert '_enf["read_only_mounts"]' in src

    def test_translator_propagates_read_only_evidence(self):
        out = _R._translate_supervised_result(
            _sup_result(
                stdout=_ok_stdout(),
                sandbox_metadata={
                    "mount_confinement_enforced": True,
                    "read_only_mounts": ["/package", "/usr"],
                },
            ),
            child_cwd="/package", duration_ms=2,
        )
        assert out["success"] is True
        assert out["mount_confinement_enforced"] is True
        assert out["read_only_mounts"] == ["/package", "/usr"]
        # Absent evidence stays empty — never synthesized.
        out2 = _R._translate_supervised_result(
            _sup_result(stdout=_ok_stdout()), child_cwd="/w", duration_ms=2,
        )
        assert out2["read_only_mounts"] == []

    @pytest.mark.asyncio
    async def test_adapter_resolves_relative_package_root(self, tmp_path,
                                                           monkeypatch):
        """R4-2: a relative package_root is resolved ONCE in the parent
        (legacy subprocess-cwd semantics); workload cwd, containment config
        and metadata all use that single absolute host value."""
        pkg = tmp_path / "rel_pkg"
        pkg.mkdir()
        mod = _make_module(pkg)
        monkeypatch.chdir(tmp_path)
        captured = {}

        async def capture(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", capture):
            r = SubprocessRunner(enable_mount_confinement=True)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "rel_root", "local_untrusted",
                "rel_pkg",
            )
        expected = str(pkg.resolve())
        assert out["success"] is True
        assert captured["workload_cwd"] == expected, (
            "relative package_root reached the workload cwd unresolved"
        )
        conf = captured["containment"]
        assert conf["package_root"] == expected
        assert conf["workload_visible_cwd"] == "/package"
        assert out["child_cwd"] == "/package"


def _make_ro_probe_module(tmp_path: Path) -> Path:
    """A plain confined node for the e2e read-only proof. Untrusted nodes
    run under FilesystemPolicy.NONE (deny-all file I/O at the policy
    layer), so in-node write probes prove nothing about the kernel mount —
    the kernel-level EROFS/writable-tmp proofs live in the sacrificial
    primitive test. What this node proves by SUCCEEDING: the read-only
    confinement configuration still executes a real workload, and the
    host package files are untouched."""
    return _make_module(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX containment behavior")
class TestPrivilegedReadOnlyProofs:
    @pytest.mark.asyncio
    async def test_package_read_only_tmp_writable(self, tmp_path):
        """R4-1 privileged e2e proof: a real confined run with the T3
        read-only contract EXECUTES a workload successfully, reports
        truthful read-only evidence, and leaves the host package files
        untouched. (Kernel-level EROFS + writable-/tmp proofs against
        private fixtures are in the primitive test below — untrusted nodes
        are deny-all at the policy layer, so in-node probes see only the
        policy, never the mount.)"""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        mod = _make_ro_probe_module(tmp_path)
        before = mod.read_bytes()
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000,
                             enable_mount_confinement=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "ro_node",
            trust_level="local_untrusted", package_root=str(tmp_path),
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            if sup.get("process_started"):
                pytest.fail(f"node failed under confinement: {result}")
            pytest.skip(
                f"containment unavailable: {(sup.get('reason') or '')[:120]}"
            )
        assert result["response"]["output"] == {"ran": True}
        assert result["mount_confinement_enforced"] is True
        assert "/package" in result["read_only_mounts"], result
        assert mod.read_bytes() == before, "host package file was modified"

    def test_ro_extra_mount_cannot_modify_host_source(self, tmp_path):
        """R4-1 primitive proof in a sacrificial subprocess (the call
        chroots its caller): a read-only extra bind denies writes with
        EROFS and the host source stays untouched; a required-RO target
        that was never mounted fails confinement closed."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        pkg = tmp_path / "probe_pkg"
        pkg.mkdir()
        (pkg / "mod.py").write_text("x = 1\n", encoding="utf-8")
        fixture = tmp_path / "ro_fixture"
        fixture.mkdir()
        sentinel = fixture / "sentinel.txt"
        sentinel.write_text("original\n", encoding="utf-8")
        fixname = fixture.name

        child = (
            "import json, os, sys, tempfile\n"
            "from nodechain.sdk.namespace_profile import apply_mount_confinement\n"
            "out = {}\n"
            "tmpa = tempfile.mkdtemp(prefix='ro_a_')\n"
            "a = apply_mount_confinement(package_root=sys.argv[1], temp_dir=tmpa,\n"
            "                            read_only_targets=['/never_mounted'])\n"
            "out['fail_closed'] = (\n"
            "    not a.get('mount_confinement_enforced')\n"
            "    and 'read_only target not mounted' in a.get('mount_confinement_error', ''))\n"
            "if not out['fail_closed']:\n"
            "    print(json.dumps(out)); sys.exit(0)\n"
            "tmpb = tempfile.mkdtemp(prefix='ro_b_')\n"
            "b = apply_mount_confinement(package_root=sys.argv[1], temp_dir=tmpb,\n"
            "                            extra_mounts=[(sys.argv[2], sys.argv[3])],\n"
            "                            read_only_targets=['/package', '/' + sys.argv[3]])\n"
            "if not b.get('mount_confinement_enforced'):\n"
            "    out['enforced'] = False\n"
            "    out['error'] = b.get('mount_confinement_error', '')\n"
            "    print(json.dumps(out)); sys.exit(0)\n"
            "out['enforced'] = True\n"
            "out['ro_mounts'] = b.get('read_only_mounts', [])\n"
            "try:\n"
            "    fd = os.open('/' + sys.argv[3] + '/sentinel.txt', os.O_WRONLY)\n"
            "    os.write(fd, b'X'); os.close(fd)\n"
            "    out['write'] = 'ALLOWED'\n"
            "except OSError as e:\n"
            "    out['write'] = 'DENIED'\n"
            "    out['errno'] = e.errno\n"
            "try:\n"
            "    fd = os.open('/tmp/ro_probe_w.txt',\n"
            "                 os.O_WRONLY | os.O_CREAT, 0o600)\n"
            "    os.write(fd, b'w'); os.close(fd)\n"
            "    out['tmp_write'] = 'ALLOWED'\n"
            "except OSError as e:\n"
            "    out['tmp_write'] = 'DENIED'\n"
            "    out['tmp_errno'] = e.errno\n"
            "print(json.dumps(out))\n"
        )
        import subprocess as _sp
        proc = _sp.run(
            [sys.executable, "-c", child,
             str(pkg), str(fixture), fixname],
            capture_output=True, text=True, timeout=60,
        )
        import json as _json
        report = _json.loads(proc.stdout.strip().splitlines()[-1])
        assert report.get("fail_closed") is True, (
            "required-RO target missing did not fail confinement closed"
        )
        assert report.get("enforced") is True, report
        assert report.get("write") == "DENIED", report
        import errno as _errno
        assert report.get("errno") == _errno.EROFS, report
        assert report.get("tmp_write") == "ALLOWED", (
            f"/tmp is not writable inside the confinement: {report}"
        )
        assert sorted(report.get("ro_mounts", [])) == \
            sorted(["/package", f"/{fixname}"]), report
        assert sentinel.read_text(encoding="utf-8") == "original\n", (
            "host fixture source was modified through the read-only bind"
        )

    @pytest.mark.asyncio
    async def test_relative_package_root_runs_confined(self, tmp_path,
                                                       monkeypatch):
        """R4-2 privileged proof: a REAL run with a relative package_root
        executes successfully, the workload cwd is /package, and the
        confinement evidence (including the read-only list) is truthful."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        pkg = tmp_path / "rel_pkg"
        pkg.mkdir()
        mod = _make_module(pkg)
        monkeypatch.chdir(tmp_path)
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000,
                             enable_mount_confinement=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "rel_root_node",
            trust_level="local_untrusted", package_root="rel_pkg",
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(
                f"containment unavailable: {(sup.get('reason') or '')[:120]}"
            )
        assert result["response"]["output"] == {"ran": True}
        assert result["child_cwd"] == "/package"
        assert result["mount_confinement_enforced"] is True
        assert "/package" in result["read_only_mounts"], result


# ---------------------------------------------------------------------------
# 14. Fifth review round (exact-head Codex P2s at 4255c1c) — workload
#     equivalence under confinement + trusted seccomp metadata
# ---------------------------------------------------------------------------


class TestR5WorkloadEquivalence:
    def test_nested_module_path_preserved(self, tmp_path):
        """R5-1: an explicit package_root that is an ANCESTOR of the module
        keeps the subtree — /pkg/impls/node.py bound from /pkg is visible
        as /package/impls/node.py, never basename-flattened."""
        pkg = tmp_path / "pkg"
        impls = pkg / "impls"
        impls.mkdir(parents=True)
        mod = _make_module(impls)
        captured = {}

        async def capture(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        import asyncio
        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", capture):
            r = SubprocessRunner(enable_mount_confinement=True)
            out = asyncio.run(r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "nested_node",
                "local_untrusted", str(pkg),
            ))
        assert out["success"] is True
        payload = json.loads(captured["workload_stdin"].decode())
        assert payload["config"]["workload_module_path"] == \
            "/package/impls/t3_node_mod.py"

    def test_module_outside_root_fails_closed_before_start(self, tmp_path):
        """R5-1: an explicit package_root that does NOT contain the module
        is a configuration error — the parent fails closed BEFORE any
        supervisor start or preparation resource."""
        import asyncio
        import tempfile as _tf
        import nodechain.runtime.supervised_argv as sa
        mod = _make_module(tmp_path)
        other_root = tmp_path / "elsewhere"
        other_root.mkdir()
        mkdir_calls = []
        real_mkdtemp = _tf.mkdtemp

        def spying_mkdtemp(*a, **k):
            mkdir_calls.append(1)
            return real_mkdtemp(*a, **k)

        async def explode(**kw):
            raise AssertionError("spawned despite outside-root module")

        with patch.object(sa, "run_supervised_argv_async", explode), \
                patch.object(_tf, "mkdtemp", spying_mkdtemp):
            r = SubprocessRunner(enable_mount_confinement=True)
            out = asyncio.run(r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "orphan_node",
                "local_untrusted", str(other_root),
            ))
        assert out["success"] is False
        assert out["exit_code"] == -1
        assert "outside confinement root" in out["error"]
        assert mkdir_calls == [], "temp dir created for a config failure"

    @pytest.mark.asyncio
    async def test_confined_temp_env_advertises_tmp(self, tmp_path):
        """R5-2: under confinement the workload env advertises the
        workload-visible /tmp; the HOST temp dir remains the trusted
        bootstrap's bind source in the containment config."""
        mod = _make_module(tmp_path)
        captured = {}

        async def capture(**kw):
            captured.update(kw)
            return _sup_result(stdout=_ok_stdout())

        import nodechain.runtime.supervised_argv as sa
        with patch.object(sa, "run_supervised_argv_async", capture):
            r = SubprocessRunner(enable_mount_confinement=True)
            out = await r._run_supervised_untrusted(
                _envelope(), mod, "TNode", "tmpenv_node",
                "local_untrusted", str(tmp_path),
            )
        assert out["success"] is True
        wenv = captured["workload_env"]
        assert wenv["TEMP"] == "/tmp"
        assert wenv["TMP"] == "/tmp"
        assert wenv["TMPDIR"] == "/tmp"
        host_temp = captured["containment"]["temp_dir"]
        assert host_temp and host_temp != "/tmp", (
            "containment bind source lost the host temp dir"
        )

    def test_seccomp_metadata_from_trusted_result(self, tmp_path):
        """R5-3 (unit): a successful supervised result carrying trusted
        seccomp flags projects them into EnvelopeResponse.metadata."""
        from nodechain.runtime.node_invoker import NodeInvoker
        from nodechain.nodes.base_node import BaseNode

        class _N(BaseNode):
            def manifest(self):
                from nodechain.core.manifest import NodeManifest
                return NodeManifest(node_id="n", node_type="model",
                                    name="n", version="1")

            def contract(self):
                from nodechain.core.contract import NodeContract
                return NodeContract(contract_id="x", node_id="n", version="1",
                                    entry={}, exit={})

            async def execute(self, envelope):
                raise AssertionError("must not run in-process")

        mod = _make_module(tmp_path)
        ok_stdout = json.dumps({
            "request_envelope_id": "e", "run_id": "r", "chain_id": "c",
            "node_id": "n", "step_id": 1, "output": {"ok": True},
            "output_type": "dict", "metadata": {},
        })
        sup_ok = {
            "success": True,
            "response": json.loads(ok_stdout),
            "exit_code": 0,
            "isolation_mode": "subprocess",
            "duration_ms": 5,
            "child_policy_enforced": True,
            "child_cwd": "/w",
            "temp_dir_isolated": True,
            "seccomp_enforced": True,
            "seccomp_available": True,
            "supervised_execution": {
                "backend": "native_os_sandbox",
                "process_started": True,
                "process_timed_out": False,
                "output_truncated": False,
                "exit_code_interpretation": "pass",
                "reason": None,
                "process_exit_code": 0,
                "sandbox_metadata": {"seccomp_enforced": True},
            },
        }
        inv = NodeInvoker()
        with patch(
            "nodechain.runtime.subprocess_runner.get_subprocess_runner",
            lambda config=None: _FakeRunner(sup_ok),
        ):
            resp, _ = asyncio.run(inv.invoke(
                _N(), _envelope(), trust_level="local_untrusted",
                isolation_config={"module_path": str(mod),
                                  "class_name": "TNode"},
            ))
        assert resp.success is not False
        assert resp.metadata["seccomp_enforced"] is True
        assert resp.metadata["seccomp_available"] is True
        assert resp.metadata["supervised_execution"]["process_started"] is True


def _make_nested_env_module(pkg: Path) -> Path:
    """A node one level below the confinement root reporting its cwd and
    the env-advertised temp variables from inside the chroot."""
    impls = pkg / "impls"
    impls.mkdir(parents=True, exist_ok=True)
    mod = impls / "nested_env_node.py"
    mod.write_text(
        "import os\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TNode:\n"
        "    async def execute(self, envelope):\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id,\n"
        "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
        "            output={\n"
        "                'cwd': os.getcwd(),\n"
        "                'tmpdir_env': os.environ.get('TMPDIR', ''),\n"
        "                'temp_env': os.environ.get('TEMP', ''),\n"
        "                'tmp_env': os.environ.get('TMP', ''),\n"
        "            },\n"
        "            output_type='dict',\n"
        "            metadata={'child_policy_enforced': True},\n"
        "        )\n",
        encoding="utf-8",
    )
    return mod


@pytest.mark.skipif(os.name != "posix", reason="POSIX containment behavior")
class TestPrivilegedR5Proofs:
    @pytest.mark.asyncio
    async def test_nested_module_and_tmp_env_confined(self, tmp_path):
        """R5 privileged proof: a module nested one level under the
        confinement root EXECUTES (subtree preserved), the workload
        observes cwd /package, and the env advertises /tmp for
        TEMP/TMP/TMPDIR from inside the chroot."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        mod = _make_nested_env_module(pkg)
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000,
                             enable_mount_confinement=True)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "nested_env_node",
            trust_level="local_untrusted", package_root=str(pkg),
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(
                f"containment unavailable: {(sup.get('reason') or '')[:120]}"
            )
        out = result["response"]["output"]
        assert result["child_cwd"] == "/package"
        assert out["cwd"] == "/package", out
        assert out["tmpdir_env"] == "/tmp", out
        assert out["temp_env"] == "/tmp", out
        assert out["tmp_env"] == "/tmp", out
        assert result["mount_confinement_enforced"] is True
        assert "/package" in result["read_only_mounts"], result

    @pytest.mark.asyncio
    async def test_real_seccomp_metadata_reaches_response(self, tmp_path):
        """R5-3/R6 privileged proof: a REAL seccomp-enabled supervised
        invocation delivers the full chain — seccomp_available=True →
        seccomp_enforced=True → enforcement_verified → exec_confirmed →
        valid response — with the trusted seccomp truth projected into
        EnvelopeResponse.metadata (never inferred, never from workload
        JSON)."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        if not _seccomp_available():
            pytest.skip("seccomp filter library unavailable")
        from nodechain.runtime.node_invoker import NodeInvoker
        from nodechain.nodes.base_node import BaseNode

        class _N(BaseNode):
            def manifest(self):
                from nodechain.core.manifest import NodeManifest
                return NodeManifest(node_id="n", node_type="model",
                                    name="n", version="1")

            def contract(self):
                from nodechain.core.contract import NodeContract
                return NodeContract(contract_id="x", node_id="n", version="1",
                                    entry={}, exit={})

            async def execute(self, envelope):
                raise AssertionError("must not run in-process")

        mod = _make_module(tmp_path)
        inv = NodeInvoker()
        resp, _ = await inv.invoke(
            _N(), _envelope(), trust_level="local_untrusted",
            isolation_config={"module_path": str(mod),
                              "class_name": "TNode",
                              "enable_seccomp": True},
        )
        assert resp.success is not False, resp.metadata
        assert resp.metadata.get("seccomp_enforced") is True, (
            f"trusted seccomp truth absent from response metadata: "
            f"{resp.metadata.get('supervised_execution')}"
        )
        assert resp.metadata.get("seccomp_available") is True
        sup = resp.metadata["supervised_execution"]
        assert sup["process_started"] is True
        assert sup["sandbox_metadata"].get("seccomp_enforced") is True

    @pytest.mark.asyncio
    async def test_real_seccomp_denial_kills_fork_node(self, tmp_path):
        """R6 denial proof: a workload that performs a syscall denied by
        the REAL installed profile (os.fork — explicitly NOT covered by
        the Python subprocess enforcer, so only the kernel filter can
        stop it) terminates through the filter and produces the truthful
        SIGSYS / seccomp_sigsys_kill classification. Not a mocked
        result."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        if not _seccomp_available():
            pytest.skip("seccomp filter library unavailable")
        mod = tmp_path / "fork_node.py"
        mod.write_text(
            "import os\n"
            "from nodechain.core.envelope import EnvelopeResponse\n"
            "class TNode:\n"
            "    async def execute(self, envelope):\n"
            "        pid = os.fork()  # denied syscall: kernel SIGSYS\n"
            "        if pid == 0:\n"
            "            os._exit(0)\n"
            "        os.waitpid(pid, 0)\n"
            "        return EnvelopeResponse(\n"
            "            request_envelope_id=envelope.envelope_id,\n"
            "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
            "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
            "            output={'forked': True},\n"
            "            output_type='dict',\n"
            "            metadata={'child_policy_enforced': True},\n"
            "        )\n",
            encoding="utf-8",
        )
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "fork_node",
            trust_level="local_untrusted", enable_seccomp=True,
        )
        assert result["success"] is False, (
            f"denied syscall did not terminate the workload: {result}"
        )
        assert result["exit_code"] == -31, result
        assert "SIGSYS" in result["error"], result
        sup = result["supervised_execution"]
        assert sup["process_started"] is True, (
            "the workload must have started (and then been killed by the "
            f"filter), not failed before start: {sup}"
        )
        assert sup["exit_code_interpretation"] == "fail"
        # On failure rows the trusted seccomp truth lives in the evidence
        # projection's sandbox_metadata (top-level flags are success-path
        # only by design).
        assert sup["sandbox_metadata"].get("seccomp_enforced") is True, sup


# ---------------------------------------------------------------------------
# 16. R7 security proofs — durable capability boundary + startup isolation
# ---------------------------------------------------------------------------


def _make_escape_probe_module(tmp_path: Path) -> Path:
    """A sacrificial workload attempting the classic second-chroot escape:
    chroot to a fresh directory then chdir("..") to walk out of the
    original root. Reports the raw syscall results (os.chroot is outside
    every Python enforcer — only the kernel capability boundary can stop
    it)."""
    mod = tmp_path / "escape_probe_node.py"
    mod.write_text(
        "import os\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TNode:\n"
        "    async def execute(self, envelope):\n"
        "        probes = {}\n"
        "        try:\n"
        "            os.mkdir('/tmp/escape_cell')\n"
        "            os.chroot('/tmp/escape_cell')\n"
        "            for _ in range(64):\n"
        "                os.chdir('..')\n"
        "            probes['chroot_escape'] = os.getcwd()\n"
        "        except OSError as e:\n"
        "            probes['chroot_escape'] = 'DENIED:%s' % (e.errno,)\n"
        "        except BaseException as e:\n"
        "            probes['chroot_escape'] = 'DENIED:%s' % type(e).__name__\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id,\n"
        "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
        "            output=probes,\n"
        "            output_type='dict',\n"
        "            metadata={'child_policy_enforced': True},\n"
        "        )\n",
        encoding="utf-8",
    )
    return mod


def _libcap():
    """Load libcap with the minimal typed surface the seeding proofs
    need, or return None when unavailable (tests skip)."""
    import ctypes
    try:
        lc = ctypes.CDLL("libcap.so.2", use_errno=True)
    except OSError:
        return None
    lc.cap_init.restype = ctypes.c_void_p
    lc.cap_set_proc.argtypes = [ctypes.c_void_p]
    lc.cap_set_proc.restype = ctypes.c_int
    lc.cap_free.argtypes = [ctypes.c_void_p]
    lc.cap_set_flag.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                ctypes.c_int,
                                ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    lc.cap_set_flag.restype = ctypes.c_int
    return lc


def _seed_inheritable_and_ambient(lc, caps=(18, 21)):
    """Seed the CALLING process with the dangerous capabilities in the
    inheritable AND ambient sets (keeping CAP_SETPCAP so restoration is
    possible) — the R8 adversarial environment. Returns a restore fn."""
    import ctypes
    cap_t = lc.cap_init()
    if not cap_t:
        return None
    arr = (ctypes.c_int * len(caps))(*caps)
    keep = (8,) + tuple(caps)            # CAP_SETPCAP survives for restore
    arr_keep = (ctypes.c_int * len(keep))(*keep)
    for flag in (0, 1):                  # effective, permitted
        lc.cap_set_flag(cap_t, flag, len(keep), arr_keep, 1)
    lc.cap_set_flag(cap_t, 2, len(caps), arr, 1)   # inheritable: seed only
    ok = lc.cap_set_proc(cap_t) == 0
    lc.cap_free(cap_t)
    if not ok:
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    for c in caps:
        libc.prctl(39, 2, c, 0, 0)       # PR_CAP_AMBIENT, RAISE

    def _restore():
        full = tuple(range(0, 41))
        arr_full = (ctypes.c_int * len(full))(*full)
        rt = lc.cap_init()
        lc.cap_set_flag(rt, 0, len(full), arr_full, 1)
        lc.cap_set_flag(rt, 1, len(full), arr_full, 1)
        # inheritable restored to empty (the common root default)
        lc.cap_set_proc(rt)
        lc.cap_free(rt)
        libc.prctl(39, 4, 0, 0, 0)       # PR_CAP_AMBIENT CLEAR_ALL
    return _restore


def _make_sitecustomize_module(pkg: Path) -> Path:
    """A node package whose root also contains an adversarial
    sitecustomize.py (the pre-enforcement startup injection vector). The
    node reports whether the hook ran (env marker + marker file)."""
    (pkg / "sitecustomize.py").write_text(
        "import os\n"
        "os.environ['T3_PWNED_SITECUSTOMIZE'] = '1'\n"
        "try:\n"
        "    with open('/tmp/t3_pwned_marker', 'w') as f:\n"
        "        f.write('x')\n"
        "except OSError:\n"
        "    pass\n",
        encoding="utf-8",
    )
    mod = pkg / "startup_node.py"
    mod.write_text(
        "import os\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TNode:\n"
        "    async def execute(self, envelope):\n"
        "        marker_file = False\n"
        "        try:\n"
        "            marker_file = os.path.exists('/tmp/t3_pwned_marker')\n"
        "        except OSError:\n"
        "            pass\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id,\n"
        "            run_id=envelope.run_id, chain_id=envelope.chain_id,\n"
        "            node_id=envelope.node_id, step_id=envelope.step_id,\n"
        "            output={\n"
        "                'ran': True,\n"
        "                'pwned_env': os.environ.get(\n"
        "                    'T3_PWNED_SITECUSTOMIZE', ''),\n"
        "                'pwned_env2': os.environ.get(\n"
        "                    'T3_PWNED_PYTHONPATH', ''),\n"
        "                'pwned_marker_file': marker_file,\n"
        "            },\n"
        "            output_type='dict',\n"
        "            metadata={'child_policy_enforced': True},\n"
        "        )\n",
        encoding="utf-8",
    )
    return mod


@pytest.mark.skipif(os.name != "posix", reason="POSIX containment behavior")
class TestPrivilegedR7Proofs:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("with_seccomp", [True, False])
    async def test_second_chroot_escape_kernel_denied(self, tmp_path,
                                                      with_seccomp):
        """R7 proof: the classic double-chroot escape is kernel-denied —
        os.chroot requires CAP_SYS_CHROOT, which the bounding-set drop
        removed irreversibly across exec. Proven BOTH with requested
        seccomp and with mount confinement alone (the boundary must not
        depend on the optional filter)."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        if with_seccomp and not _seccomp_available():
            pytest.skip("seccomp filter library unavailable")
        mod = _make_escape_probe_module(tmp_path)
        r = SubprocessRunner(
            timeout_seconds=60, max_output_bytes=100_000,
            enable_mount_confinement=True,
        )
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "escape_node",
            trust_level="local_untrusted", package_root=str(tmp_path),
            enable_seccomp=with_seccomp,
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(
                f"containment unavailable: {(sup.get('reason') or '')[:120]}"
            )
        out = result["response"]["output"]
        escape = out.get("chroot_escape", "MISSING")
        assert escape.startswith("DENIED"), (
            f"chroot escape was NOT denied: {escape}"
        )
        # Trusted boundary evidence from the bootstrap — the capability
        # drop is what makes the denial kernel-durable (the kernel-level
        # EPERM is proven directly in the sacrificial probe below).
        md = result["supervised_execution"]["sandbox_metadata"]
        assert md.get("capability_boundary_dropped") is True, md
        assert md.get("capability_boundary_verified") is True, md
        assert 18 in md.get("capability_boundary_caps", []), md   # SYS_CHROOT
        assert 21 in md.get("capability_boundary_caps", []), md   # SYS_ADMIN

    def test_kernel_chroot_denied_after_capdrop(self, tmp_path):
        """R7 kernel-level proof in a sacrificial subprocess: confinement
        plus the bootstrap's bounding-set capability drop, then an EXEC
        (the workload transition), then a raw libc chroot attempt in the
        post-exec process — refused with EPERM. The bounding set is the
        regain boundary ACROSS exec (a same-process drop intentionally
        leaves effective caps in place for the trusted bootstrap's
        remaining work), so the exec is the load-bearing step."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        pkg = tmp_path / "cap_pkg"
        pkg.mkdir()
        (pkg / "m.py").write_text("x = 1\n", encoding="utf-8")
        stage2 = (
            "import ctypes, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "ctypes.set_errno(0)\n"
            "rc = libc.chroot(b'/tmp')\n"
            "err = ctypes.get_errno()\n"
            "print('chroot rc=%d errno=%d' % (rc, err))\n"
            "sys.exit(0 if rc != 0 else 7)\n"
        )
        child = (
            "import ctypes, os, sys, tempfile\n"
            "from nodechain.sdk.namespace_profile import apply_mount_confinement\n"
            "tmpd = tempfile.mkdtemp(prefix='cap_')\n"
            "r = apply_mount_confinement(package_root=sys.argv[1], temp_dir=tmpd,\n"
            "                            extra_mounts=[(d, d) for d in ('/usr','/lib','/lib64') if os.path.isdir(d)],\n"
            "                            read_only_targets=['/package','/usr','/lib','/lib64'])\n"
            "if not r.get('mount_confinement_enforced'):\n"
            "    print('confinement_failed'); sys.exit(3)\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "dropped = []\n"
            "for cap in (8, 16, 17, 18, 19, 21, 22, 25, 26, 27, 31, 34, 38, 39, 40):\n"
            "    ctypes.set_errno(0)\n"
            "    rc = libc.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP\n"
            "    if rc == 0:\n"
            "        dropped.append(cap)\n"
            "    elif ctypes.get_errno() != 22:\n"
            "        print('capdrop_failed'); sys.exit(4)\n"
            "ok = 18 in dropped and 21 in dropped\n"
            "import sysconfig\n"
            "_ld = sysconfig.get_config_var('LIBDIR') or ''\n"
            "os.execve(sys.executable,\n"
            "          [sys.executable, '-c', sys.argv[2]],\n"
            "          {'PATH': '/usr/bin:/bin', 'CAPS_DROPPED': str(ok),\n"
            "           'LD_LIBRARY_PATH': _ld})\n"
        )
        import subprocess as _sp
        proc = _sp.run(
            [sys.executable, "-c", child, str(pkg), stage2],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, (
            f"sacrificial probe failed: rc={proc.returncode} "
            f"{proc.stdout.strip()[-200:]}"
        )
        out = proc.stdout.strip().splitlines()[-1]
        assert "errno=1" in out, out        # EPERM from the kernel

    @pytest.mark.asyncio
    async def test_seeded_capabilities_cleared_across_exec(self, tmp_path):
        """R8 adversarial proof: the process tree is DELIBERATELY seeded
        with CAP_SYS_CHROOT + CAP_SYS_ADMIN in the inheritable AND ambient
        sets (the kernel's exec-survival vectors that a bounding-set drop
        alone does not prune) before the supervised bootstrap runs. The
        trusted boundary evidence must still prove the five-set verified
        state, and the workload must execute normally."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        lc = _libcap()
        if lc is None:
            pytest.skip("libcap unavailable")
        restore = _seed_inheritable_and_ambient(lc, caps=(18, 21))
        if restore is None:
            pytest.skip("capability seeding unavailable on this host")
        try:
            mod = _make_module(tmp_path)
            r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000)
            result = await r.run_isolated(
                _envelope(), mod, "TNode", "seeded_node",
                trust_level="local_untrusted",
            )
        finally:
            restore()
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(
                f"supervised topology unavailable: "
                f"{(sup.get('reason') or '')[:120]}"
            )
        md = result["supervised_execution"]["sandbox_metadata"]
        assert md.get("capability_boundary_verified") is True, md
        assert md.get("capability_boundary_dropped") is True, md
        assert 18 in md.get("capability_boundary_caps", []), md
        assert 21 in md.get("capability_boundary_caps", []), md

    def test_kernel_chroot_denied_with_seeded_caps(self, tmp_path):
        """R8 kernel-level adversarial proof: the sacrificial child seeds
        inheritable+ambient CAP_SYS_CHROOT/CAP_SYS_ADMIN AFTER confinement
        but BEFORE the boundary sequence (bounding drops → ambient clear →
        empty cap_set_proc), then execs — the seeded capabilities must not
        survive: the raw libc chroot in the post-exec process is EPERM."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        pkg = tmp_path / "seed_pkg"
        pkg.mkdir()
        (pkg / "m.py").write_text("x = 1\n", encoding="utf-8")
        stage2 = (
            "import ctypes, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "ctypes.set_errno(0)\n"
            "rc = libc.chroot(b'/tmp')\n"
            "err = ctypes.get_errno()\n"
            "print('chroot rc=%d errno=%d' % (rc, err))\n"
            "sys.exit(0 if rc != 0 else 7)\n"
        )
        child = (
            "import ctypes, os, sys, tempfile\n"
            "from nodechain.sdk.namespace_profile import apply_mount_confinement\n"
            "tmpd = tempfile.mkdtemp(prefix='seed_')\n"
            "r = apply_mount_confinement(package_root=sys.argv[1], temp_dir=tmpd,\n"
            "                            extra_mounts=[(d, d) for d in ('/usr','/lib','/lib64') if os.path.isdir(d)],\n"
            "                            read_only_targets=['/package','/usr','/lib','/lib64'])\n"
            "if not r.get('mount_confinement_enforced'):\n"
            "    print('confinement_failed'); sys.exit(3)\n"
            "# ADVERSARIAL SEED: inheritable + ambient SYS_CHROOT/SYS_ADMIN\n"
            "lc = ctypes.CDLL('libcap.so.2', use_errno=True)\n"
            "lc.cap_init.restype = ctypes.c_void_p\n"
            "lc.cap_set_proc.argtypes = [ctypes.c_void_p]\n"
            "lc.cap_free.argtypes = [ctypes.c_void_p]\n"
            "lc.cap_set_flag.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]\n"
            "seed = [18, 21]\n"
            "cap_t = lc.cap_init()\n"
            "arr_seed = (ctypes.c_int * len(seed))(*seed)\n"
            "full = list(range(0, 41))\n"
            "arr_full = (ctypes.c_int * len(full))(*full)\n"
            "for fl in (0, 1):\n"
            "    lc.cap_set_flag(cap_t, fl, len(full), arr_full, 1)\n"
            "lc.cap_set_flag(cap_t, 2, len(seed), arr_seed, 1)\n"
            "ok = lc.cap_set_proc(cap_t) == 0\n"
            "lc.cap_free(cap_t)\n"
            "if not ok:\n"
            "    print('seed_failed'); sys.exit(5)\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "for c in seed:\n"
            "    libc.prctl(39, 2, c, 0, 0)  # PR_CAP_AMBIENT RAISE\n"
            "# THE BOUNDARY (mirrors the bootstrap's R8 sequence)\n"
            "for cap in (8, 16, 17, 18, 19, 21, 22, 25, 26, 27, 31, 34, 38, 39, 40):\n"
            "    ctypes.set_errno(0)\n"
            "    rc = libc.prctl(24, cap, 0, 0, 0)\n"
            "    if rc != 0 and ctypes.get_errno() != 22:\n"
            "        print('capdrop_failed'); sys.exit(4)\n"
            "libc.prctl(39, 4, 0, 0, 0)     # PR_CAP_AMBIENT CLEAR_ALL\n"
            "empty = lc.cap_init()\n"
            "rc = lc.cap_set_proc(empty)\n"
            "lc.cap_free(empty)\n"
            "if rc != 0:\n"
            "    print('capset_failed'); sys.exit(6)\n"
            "import sysconfig\n"
            "_ld = sysconfig.get_config_var('LIBDIR') or ''\n"
            "os.execve(sys.executable,\n"
            "          [sys.executable, '-c', sys.argv[2]],\n"
            "          {'PATH': '/usr/bin:/bin', 'LD_LIBRARY_PATH': _ld})\n"
        )
        import subprocess as _sp
        proc = _sp.run(
            [sys.executable, "-c", child, str(pkg), stage2],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, (
            f"seeded sacrificial probe failed: rc={proc.returncode} "
            f"{proc.stdout.strip()[-200:]}"
        )
        out = proc.stdout.strip().splitlines()[-1]
        assert "errno=1" in out, out        # EPERM: seeded caps did not survive

    @pytest.mark.asyncio
    async def test_adversarial_sitecustomize_inert(self, tmp_path,
                                                   monkeypatch):
        """R7 proof: an adversarial sitecustomize.py in the untrusted
        package root AND a malicious startup hook on inherited PYTHONPATH
        both stay inert (isolated -I startup), while the intended node
        still executes under the four enforcers."""
        if not _can_unshare_pid_ns():
            pytest.skip("host cannot unshare PID ns")
        pkg = tmp_path / "startup_pkg"
        pkg.mkdir()
        mod = _make_sitecustomize_module(pkg)
        evil_dir = tmp_path / "evil_py"
        evil_dir.mkdir()
        (evil_dir / "sitecustomize.py").write_text(
            "import os\n"
            "os.environ['T3_PWNED_PYTHONPATH'] = '1'\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("PYTHONPATH", str(evil_dir))
        r = SubprocessRunner(timeout_seconds=60, max_output_bytes=100_000)
        result = await r.run_isolated(
            _envelope(), mod, "TNode", "startup_node",
            trust_level="local_untrusted", package_root=str(pkg),
        )
        if not result["success"]:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            pytest.skip(
                f"supervised topology unavailable: "
                f"{(sup.get('reason') or '')[:120]}"
            )
        out = result["response"]["output"]
        assert out.get("ran") is True, out
        assert out.get("pwned_env") == "", (
            f"package-root sitecustomize executed before enforcement: {out}"
        )
        assert out.get("pwned_env2") == "", (
            f"PYTHONPATH startup hook executed before enforcement: {out}"
        )
        assert out.get("pwned_marker_file") is False, out
