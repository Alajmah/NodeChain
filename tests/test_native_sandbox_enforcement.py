"""v2.77 — Privileged Linux Native Sandbox Verification Harness.

These tests prove the **integrated v2.76 native_os_sandbox command-runner
chain** actually enforces confinement under the privileged execution profile
the current implementation requires (Linux + root). They do NOT duplicate the
primitive-level tests (test_namespace_confinement.py, test_mount_confinement.py,
test_seccomp_productization.py, etc.) — those validate the primitives in
isolation. This file validates the full seam:

    SandboxCommandRunner("native_os_sandbox").run_command(...)
      → native_sandbox_exec.run_isolated(...)
        → child bootstrap (PID ns → network ns → mount ns → mount confinement
                            → seccomp filter)
        → subprocess.run(argv, shell=False) UNDER enforcement
      → result.sandbox_metadata + child-observed evidence

Three-tier gate (see tests/conftest.py):
  - Default host: skipped for portability.
  - NODECHAIN_NATIVE_RUNNER=1 + non-root/non-Linux: hard-fails via
    assert_native_runner_privilege (Tier 3 — impossible to misread as green).
  - NODECHAIN_NATIVE_RUNNER=1 + Linux + root: runs and asserts enforcement.

Proof semantics (per ChatGPT review): metadata is necessary but NOT sufficient.
Each primitive that can produce child-observed evidence must do so.
"""
from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

from nodechain.runtime.sandbox_command_runner import SandboxCommandRunner

# pytest makes the test's directory importable; conftest is at tests/ root.
# This import works because pytest adds the test rootdir to sys.path.
from conftest import assert_native_runner_privilege


pytestmark = pytest.mark.native_sandbox


def _seccomp_available() -> bool:
    """Check whether seccomp enforcement is available on this host."""
    try:
        from nodechain.sdk.seccomp_profile import SeccompBackend
        return SeccompBackend().available
    except Exception:
        return False


requires_seccomp = pytest.mark.skipif(
    not _seccomp_available(),
    reason="seccomp backend unavailable on this host — fail-closed prevents workload",
)


def _run_native(argv: list[str], cwd: Path, timeout_seconds: int = 30) -> dict:
    """Helper: run argv through the native_os_sandbox backend."""
    runner = SandboxCommandRunner("native_os_sandbox")
    return runner.run_command(
        argv=argv, cwd=cwd,
        timeout_seconds=timeout_seconds, max_output_bytes=50_000,
    )


# ─── Mount confinement: child-observed sentinel proof ────────────────────

@requires_seccomp
def test_native_path_enforces_mount_confinement_with_sentinel(tmp_path):
    """Mount confinement must be proven by the child actually reading a
    sentinel file placed in the host workspace — not just by metadata.

    The v2.76 native path bind-mounts the host workspace at /workspace before
    chroot. If that actually works, the confined child can read
    /workspace/sentinel.txt (which exists in the host workspace, not in the
    chroot root, so success proves the bind mount took effect).
    """
    assert_native_runner_privilege()
    sentinel_content = "native-sandbox-workspace-visible"
    (tmp_path / "sentinel.txt").write_text(sentinel_content)

    probe = (
        "import sys; "
        f"assert open('/workspace/sentinel.txt').read() == {sentinel_content!r}, "
        "'sentinel mismatch or unreadable'; "
        "print('sentinel read OK')"
    )
    res = _run_native([sys.executable, "-c", probe], tmp_path)
    meta = res.get("sandbox_metadata", {})

    # Metadata claim.
    assert meta.get("mount_confinement_enforced") is True, (
        f"runner did not report mount_confinement_enforced=True; metadata={meta}"
    )
    assert "/workspace" in meta.get("allowed_mounts", []), (
        f"/workspace not in allowed_mounts: {meta.get('allowed_mounts')}"
    )
    # Child-observed proof: the sentinel read succeeded (exit 0, marker printed).
    assert res["exit_code_interpretation"] == "pass", (
        f"confined child failed to read /workspace/sentinel.txt; "
        f"interpretation={res['exit_code_interpretation']} "
        f"stderr={res['stderr'][:400]}"
    )
    assert "sentinel read OK" in res["stdout"]


# ─── Network namespace: host positive control + sandbox block ─────────────

@requires_seccomp
def test_native_path_blocks_outbound_network(tmp_path):
    """Network namespace must block outbound connections, AND the host must
    be able to reach the target unsandboxed — otherwise 'blocked' is
    meaningless (could just be a runner with no network).
    """
    assert_native_runner_privilege()
    target = os.environ.get("NODECHAIN_NATIVE_SANDBOX_NET_TARGET", "1.1.1.1:53")
    host, port_str = target.split(":", 1)
    port = int(port_str)

    # Positive control: host must reach the target unsandboxed.
    try:
        sock = socket.create_connection((host, port), timeout=3)
        sock.close()
    except OSError as e:
        pytest.fail(
            f"host positive-control FAILED: cannot reach {target} ({e}). "
            f"Runner is misconfigured for this test — 'blocked' would be "
            f"meaningless. Fix the host network or pick a reachable target "
            f"via NODECHAIN_NATIVE_SANDBOX_NET_TARGET."
        )

    # Adversarial: the same target must fail inside the native sandbox.
    probe = (
        "import socket, sys; "
        f"socket.create_connection(({host!r}, {port}), timeout=2); "
        "print('NETWORK_LEAK: connection succeeded inside sandbox'); "
        "sys.exit(0)"
    )
    res = _run_native([sys.executable, "-c", probe], tmp_path, timeout_seconds=30)
    meta = res.get("sandbox_metadata", {})

    assert meta.get("network_namespace_enforced") is True, (
        f"runner did not report network_namespace_enforced=True; metadata={meta}"
    )
    # The connection must NOT have succeeded.
    assert "NETWORK_LEAK" not in res["stdout"], (
        f"CRITICAL: outbound connection to {target} SUCCEEDED inside the native "
        f"sandbox — network namespace is NOT enforcing. stdout={res['stdout'][:300]}"
    )
    assert res["exit_code_interpretation"] != "pass", (
        f"sandbox exited cleanly; the connection probe should have failed. "
        f"interpretation={res['exit_code_interpretation']}"
    )


# ─── Seccomp: child-applied (v2.78) — metadata + SIGSYS canary ────────────
#
# v2.78 redesign: the child applies seccomp to itself after namespace/chroot
# setup, then os.execve's the workload in place. The filter survives execve
# (Linux guarantee), so the workload runs confined. These tests prove it.
#
# Canary semantics (per ChatGPT's correction): the NodeChain seccomp profile
# uses the KILL action (default), NOT ERRNO. So os.fork() inside the workload
# terminates the process via SIGSYS (signal 31) — it does NOT raise OSError.
# The parent sees this as a negative exit code (-31) and classifies it as
# seccomp_sigsys_kill. That is the correct proof for the current profile.


@requires_seccomp
def test_native_path_enforces_seccomp(tmp_path):
    """Seccomp must be applied by the child and active through the integrated path.

    v2.78: the child applies the filter to itself before execve. This test
    proves a minimal workload can run under the filter (Python -I -S startup
    doesn't trip it) AND the metadata reports seccomp_applied=True with the
    child_pre_exec mode.
    """
    assert_native_runner_privilege()
    # Use -I -S for minimal Python startup surface (ChatGPT's empirical-gating
    # recommendation). If this trips the filter, that's a blocker — see
    # docs/native_sandbox_verification.md.
    res = _run_native(
        [sys.executable, "-I", "-S", "-c", "print('child ran under seccomp')"],
        tmp_path,
    )
    meta = res.get("sandbox_metadata", {})

    # v2.78 metadata fields (per ChatGPT-agreed model).
    assert meta.get("seccomp_apply_mode") == "child_pre_exec", (
        f"seccomp_apply_mode not child_pre_exec; metadata={meta}"
    )
    assert meta.get("seccomp_applied") is True, (
        f"seccomp not applied by child; metadata={meta}"
    )
    # The minimal workload ran cleanly under the filter.
    assert res["exit_code_interpretation"] == "pass", (
        f"minimal Python workload did not run under seccomp; "
        f"interpretation={res['exit_code_interpretation']} "
        f"reason={res.get('reason')} stderr={res['stderr'][:400]}"
    )
    assert "child ran under seccomp" in res["stdout"]


@requires_seccomp
def test_native_path_seccomp_canary_blocks_fork(tmp_path):
    """Denied-syscall canary: 'fork' is in the NodeChain deny list.

    v2.78: the workload attempts os.fork() inside the confined execve'd child.
    With the default KILL profile, this terminates the process via SIGSYS
    (signal 31). The parent sees returncode -31 and classifies it as
    seccomp_sigsys_kill. That is the proof — not an OSError (ERRNO action).

    Per ChatGPT: do NOT change the production profile to ERRNO just to make
    the Python assertion nicer. Parent-side SIGSYS classification is stronger.
    """
    assert_native_runner_privilege()
    probe = "import os; os.fork()"  # minimal — should be killed by seccomp
    res = _run_native(
        [sys.executable, "-I", "-S", "-c", probe],
        tmp_path, timeout_seconds=30,
    )
    meta = res.get("sandbox_metadata", {})
    assert meta.get("seccomp_applied") is True, (
        f"seccomp not applied; metadata={meta}"
    )
    # The canary: fork must NOT succeed. With KILL action, the process is
    # terminated by SIGSYS (signal 31). The exit code may surface as either
    # -31 (waitstatus form) or 159 = 128+31 (POSIX/shell form). Both prove the kill.
    import signal as _sig
    rc = res["process_exit_code"]
    SIGSYS = _sig.SIGSYS
    # Resolve the actual signal number from either form.
    if rc is not None and rc < 0:
        sig = -rc
    elif rc is not None and rc > 128:
        sig = rc - 128
    else:
        sig = None
    assert sig is not None, (
        f"seccomp canary did NOT fire: process exited cleanly or timed out "
        f"(rc={rc}). os.fork() should have been killed by SIGSYS. "
        f"stdout={res['stdout'][:300]}"
    )
    assert sig == SIGSYS, (
        f"seccomp canary fired but via signal {sig}, not SIGSYS (31). "
        f"Investigate whether the seccomp binding's KILL action uses a "
        f"different signal on this kernel. stdout={res['stdout'][:200]}"
    )
    # The parent classifier should agree.
    assert res.get("reason") == "seccomp_sigsys_kill", (
        f"exited via SIGSYS but parent reason not classified as "
        f"seccomp_sigsys_kill: {res.get('reason')}"
    )


# ─── v3.5.1 H2: fail-closed enforcement + env filtering + output caps ──────


def test_native_sandbox_canary_secret_not_visible(tmp_path, monkeypatch):
    """H2 #2: the sandboxed workload must not read a canary secret from the
    parent environment. Only allowlisted env vars reach the workload."""
    assert_native_runner_privilege()
    monkeypatch.setenv("NODECHAIN_TEST_SECRET", "native-canary-leak")
    probe = (
        "import os; "
        "print(os.environ.get('NODECHAIN_TEST_SECRET', 'NOT_PRESENT'))"
    )
    res = _run_native([sys.executable, "-c", probe], tmp_path)
    assert "native-canary-leak" not in res["stdout"], (
        f"sandboxed workload read the canary secret — env leak in native backend"
    )


def test_native_sandbox_output_flood_is_bounded(tmp_path):
    """H2 #3: an infinite stdout flood must be bounded and terminated at the
    output limit, not at timeout."""
    assert_native_runner_privilege()
    flood = (
        "import sys\n"
        "data = 'A' * 4096\n"
        "while True:\n"
        "    sys.stdout.write(data)\n"
        "    sys.stdout.flush()\n"
    )
    res = _run_native([sys.executable, "-c", flood], tmp_path, timeout_seconds=30)
    # Output must be bounded.
    assert len(res["stdout"]) <= 50_000, (
        f"stdout is {len(res['stdout'])}B — not bounded"
    )
    # Must be truncated (output limit), not just timeout.
    assert res["output_truncated"] is True, (
        f"output_truncated is False — flood not terminated at the output limit; "
        f"reason={res.get('reason')}"
    )
    assert res.get("reason") == "output_limit_exceeded", (
        f"expected output_limit_exceeded, got {res.get('reason')}"
    )


def test_fail_closed_when_primitive_unavailable(tmp_path):
    """H2 #1: when a requested enforcement primitive is unavailable, the
    workload must NEVER start. This is the mandatory fail-closed contract.

    On hosts where seccomp is unavailable, this test proves the native
    sandbox refuses to run the workload. On hosts where seccomp IS available,
    it is skipped (nothing to prove — the primitive is present).
    """
    assert_native_runner_privilege()
    if _seccomp_available():
        pytest.skip("seccomp is available on this host — nothing to prove")
    res = _run_native(
        [sys.executable, "-c", "print('should never run')"],
        tmp_path, timeout_seconds=15,
    )
    meta = res.get("sandbox_metadata", {})
    # The workload must NOT have started.
    assert res["process_started"] is False, (
        "workload started despite a requested primitive being unavailable — "
        "fail-closed contract violated"
    )
    assert meta.get("enforcement_failed"), (
        f"enforcement_failed not reported in metadata: {meta}"
    )
    assert "seccomp" in meta["enforcement_failed"], (
        f"seccomp not in enforcement_failed: {meta['enforcement_failed']}"
    )
    # No workload output.
    assert "should never run" not in res.get("stdout", "")


# ─── Deterministic primitive-failure injection ─────────────────────────────


@pytest.fixture
def _force_seccomp_unavailable(monkeypatch):
    """Inject a deterministic seccomp failure: patch run_isolated to set
    _force_seccomp_unavailable in the child config. The child checks this flag
    and forces the seccomp backend to report unavailable."""
    from nodechain.runtime import native_sandbox_exec
    original_run_isolated = native_sandbox_exec.run_isolated

    def patched_run_isolated(**kwargs):
        # Inject the flag into the config.
        import asyncio as _asyncio
        config = {
            "argv": kwargs["argv"],
            "cwd": str(kwargs["cwd"]),
            "timeout_seconds": kwargs["timeout_seconds"],
            "max_output_bytes": kwargs["max_output_bytes"],
            "workspace_src": str(kwargs["cwd"]),
            "env_allowlist": sorted(kwargs["env_allowlist"]),
            "package_root": "/",
            "temp_dir": "/tmp",
            "enable_pid_namespace": True,
            "enable_procfs_isolation": True,
            "enable_network_namespace": True,
            "enable_mount_namespace": True,
            "enable_mount_confinement": True,
            "enable_seccomp": True,
            "_force_seccomp_unavailable": True,  # injection
        }
        backend_name = kwargs.get("backend_name", "native_os_sandbox")
        child_script = native_sandbox_exec._build_child_script()
        loop = _asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                native_sandbox_exec._run_child(child_script, config)
            )
        finally:
            loop.close()

    monkeypatch.setattr(native_sandbox_exec, "run_isolated", patched_run_isolated)


def test_injected_seccomp_failure_prevents_workload_start(tmp_path, _force_seccomp_unavailable):
    """H2 #5: deterministic injection — force seccomp to report unavailable.
    The native sandbox must refuse to start the workload.

    This test runs on the Linux enforcement host regardless of whether the
    real seccomp library is available, because it injects the failure."""
    assert_native_runner_privilege()
    res = _run_native(
        [sys.executable, "-I", "-S", "-c", "print('canary_should_not_print')"],
        tmp_path, timeout_seconds=30,
    )
    meta = res.get("sandbox_metadata", {})
    # Workload must NOT have started.
    assert res["process_started"] is False, (
        f"workload started despite injected seccomp failure — fail-closed violated"
    )
    assert "seccomp" in meta.get("enforcement_failed", []), (
        f"seccomp not in enforcement_failed: {meta.get('enforcement_failed')}"
    )
    assert res.get("reason") == "enforcement_verification_failed"
    # Canary must not appear in output.
    assert "canary_should_not_print" not in res.get("stdout", "")


# ─── Per-primitive failure injection matrix ────────────────────────────────


def _make_force_primitive_fixture(primitive_name: str):
    """Create a fixture that injects a failure for a specific primitive."""
    config_key = f"_force_{primitive_name}_unavailable"

    @pytest.fixture
    def fixture(monkeypatch):
        from nodechain.runtime import native_sandbox_exec
        import asyncio as _asyncio

        def patched_run_isolated(**kwargs):
            config = {
                "argv": kwargs["argv"],
                "cwd": str(kwargs["cwd"]),
                "timeout_seconds": kwargs["timeout_seconds"],
                "max_output_bytes": kwargs["max_output_bytes"],
                "workspace_src": str(kwargs["cwd"]),
                "env_allowlist": sorted(kwargs["env_allowlist"]),
                "package_root": "/",
                "temp_dir": "/tmp",
                "enable_pid_namespace": True,
                "enable_procfs_isolation": True,
                "enable_network_namespace": True,
                "enable_mount_namespace": True,
                "enable_mount_confinement": True,
                "enable_seccomp": True,
                config_key: True,  # injection
            }
            child_script = native_sandbox_exec._build_child_script()
            loop = _asyncio.new_event_loop()
            try:
                return loop.run_until_complete(
                    native_sandbox_exec._run_child(child_script, config)
                )
            finally:
                loop.close()

        monkeypatch.setattr(native_sandbox_exec, "run_isolated", patched_run_isolated)

    return fixture


# Create fixtures for each primitive.
_force_pid_ns = _make_force_primitive_fixture("pid_namespace")
_force_procfs = _make_force_primitive_fixture("procfs_isolation")
_force_net_ns = _make_force_primitive_fixture("network_namespace")
_force_mount_confine = _make_force_primitive_fixture("mount_confinement")


@pytest.mark.parametrize("fixture_name,expected_primitive", [
    ("_force_pid_ns", "pid_namespace"),
    ("_force_procfs", "procfs_isolation"),
    ("_force_net_ns", "network_namespace"),
    ("_force_mount_confine", "mount_confinement"),
    ("_force_seccomp_unavailable", "seccomp"),
])
def test_injected_primitive_failure_prevents_workload_start(
    tmp_path, request, fixture_name, expected_primitive,
):
    """H2 #5: for EACH requested primitive, injecting a failure must prevent
    the workload from starting. This test matrix runs on the Linux enforcement
    host without skips."""
    assert_native_runner_privilege()
    request.getfixturevalue(fixture_name)
    res = _run_native(
        [sys.executable, "-I", "-S", "-c", "print('canary_should_not_print')"],
        tmp_path, timeout_seconds=30,
    )
    meta = res.get("sandbox_metadata", {})
    assert res["process_started"] is False, (
        f"workload started despite injected {expected_primitive} failure"
    )
    assert expected_primitive in meta.get("enforcement_failed", []), (
        f"{expected_primitive} not in enforcement_failed: {meta.get('enforcement_failed')}"
    )
    assert res.get("reason") == "enforcement_verification_failed"
    assert "canary_should_not_print" not in res.get("stdout", "")
