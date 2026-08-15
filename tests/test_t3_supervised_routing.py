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
        # argv: python -c <script>
        assert captured["argv"][0] == sys.executable
        assert captured["argv"][1] == "-c"
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
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        rc = libc.unshare(0x20000000)  # CLONE_NEWPID
        if rc == 0:
            # We now live in a new PID ns inside the test process — harmless
            # for a short-lived probe but disorienting; fork a probe instead
            # is cleaner. Accept the current behavior: the probe succeeded.
            return True
        return False
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
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        src = _build_bootstrap_script()
        assert "workload_cwd_visible" in src
        assert '"/package" if _containment.get("package_root")' in src

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
