"""S3.2 Task 3: launcher / namespace-init split tests.

Deterministic mocked tests for sequencing and failure injection. No real
``unshare(CLONE_NEWPID)`` or ``os.fork()`` in the pytest process — every
syscall surface is mocked.

Covers:
  * identity record validation (closed schema, bool rejection, dup keys)
  * identity frame trailing-bytes rejection
  * release gate (exact token + clean EOF; partial/wrong/extra rejected)
  * topology proof sequencing
  * protocol-writer handoff
  * pre-gate containment (exact reap, ECHILD proof)
  * wait-status decoding
  * bootstrap PID semantics
  * post-handoff failure window
  * static source authority (functions defined, delegation, no forbidden calls)
"""

from __future__ import annotations

import json
import signal
import struct
import sys
from unittest import mock

import pytest

from nodechain.runtime.exec_supervisor import (
    IdentityChannelError,
    _decode_wait_status,
    _RELEASE_TOKEN,
    _validate_identity,
    _IDENTITY_VERSION,
    _IDENTITY_MAX_PAYLOAD,
)
from nodechain.runtime.pid_namespace_topology import (
    PidNamespaceUnsupported as _PidNsUnsupported,
    PidNamespaceProofError as _PidNsProofError,
)


# ===========================================================================
# Identity record validation
# ===========================================================================

class TestIdentityValidation:
    """Closed-schema validation of the namespace-init identity record."""

    def test_valid_identity(self):
        """The exact schema {version:1, type:init_identity, pid:1, ppid:0}
        validates successfully."""
        pid, ppid = _validate_identity({
            "version": 1, "type": "init_identity", "pid": 1, "ppid": 0,
        })
        assert pid == 1
        assert ppid == 0

    def test_rejects_bool_pid(self):
        """Bool is a subclass of int — must be explicitly rejected."""
        with pytest.raises(IdentityChannelError, match="pid_invalid"):
            _validate_identity({"version": 1, "type": "init_identity",
                                "pid": True, "ppid": 0})

    def test_rejects_bool_ppid(self):
        with pytest.raises(IdentityChannelError, match="ppid_invalid"):
            _validate_identity({"version": 1, "type": "init_identity",
                                "pid": 1, "ppid": False})

    def test_rejects_bool_version(self):
        with pytest.raises(IdentityChannelError, match="version_invalid"):
            _validate_identity({"version": True, "type": "init_identity",
                                "pid": 1, "ppid": 0})

    def test_rejects_wrong_pid(self):
        with pytest.raises(IdentityChannelError, match="pid_invalid"):
            _validate_identity({"version": 1, "type": "init_identity",
                                "pid": 2, "ppid": 0})

    def test_rejects_wrong_ppid(self):
        with pytest.raises(IdentityChannelError, match="ppid_invalid"):
            _validate_identity({"version": 1, "type": "init_identity",
                                "pid": 1, "ppid": 1})

    def test_rejects_wrong_type(self):
        with pytest.raises(IdentityChannelError, match="type_invalid"):
            _validate_identity({"version": 1, "type": "not_identity",
                                "pid": 1, "ppid": 0})

    def test_rejects_unknown_fields(self):
        with pytest.raises(IdentityChannelError, match="unknown_fields"):
            _validate_identity({"version": 1, "type": "init_identity",
                                "pid": 1, "ppid": 0, "extra": "bad"})

    def test_rejects_missing_fields(self):
        with pytest.raises(IdentityChannelError, match="missing_fields"):
            _validate_identity({"version": 1, "type": "init_identity",
                                "pid": 1})  # ppid missing

    def test_rejects_wrong_version(self):
        with pytest.raises(IdentityChannelError, match="version_invalid"):
            _validate_identity({"version": 2, "type": "init_identity",
                                "pid": 1, "ppid": 0})


# ===========================================================================
# Identity frame: duplicate keys, trailing bytes
# ===========================================================================

class TestIdentityFrame:
    """Framing-level tests using mocked I/O."""

    def _make_frame(self, obj: dict) -> bytes:
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return struct.pack(">I", len(payload)) + payload

    def test_duplicate_keys_in_frame(self):
        """Duplicate JSON keys in the identity frame -> IdentityChannelError."""
        from nodechain.runtime.exec_supervisor import _read_identity_frame
        # Hand-craft a frame with duplicate "pid" keys.
        bad_payload = b'{"version":1,"type":"init_identity","pid":1,"pid":1,"ppid":0}'
        frame = struct.pack(">I", len(bad_payload)) + bad_payload
        # Mock _read_exact to return header, payload, then EOF.
        call_state = {"idx": 0}
        reads = [frame[:4], frame[4:], None]  # header, payload, eof
        def fake_read_exact(fd, count, **kw):
            idx = call_state["idx"]
            call_state["idx"] += 1
            if idx < len(reads):
                r = reads[idx]
                return r if r is not None else None  # None for allow_eof
            return None
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            with pytest.raises(IdentityChannelError, match="duplicate_key"):
                _read_identity_frame(99, deadline=999.0)

    def test_trailing_bytes_after_frame(self):
        """Extra bytes after the identity frame -> IdentityChannelError."""
        from nodechain.runtime.exec_supervisor import _read_identity_frame
        payload = json.dumps({"version": 1, "type": "init_identity",
                              "pid": 1, "ppid": 0}).encode()
        frame = struct.pack(">I", len(payload)) + payload + b"X"  # trailing byte
        call_state = {"idx": 0}
        reads = [frame[:4], frame[4:4+len(payload)], b"X"]  # header, payload, trailing
        def fake_read_exact(fd, count, **kw):
            idx = call_state["idx"]
            call_state["idx"] += 1
            if idx < len(reads):
                return reads[idx]
            return None
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            with pytest.raises(IdentityChannelError, match="trailing_bytes"):
                _read_identity_frame(99, deadline=999.0)


# ===========================================================================
# Release gate: exact token + clean EOF
# ===========================================================================

class TestReleaseGate:
    """The release gate requires exact token bytes + immediate clean EOF."""

    def test_exact_token_with_clean_eof_accepted(self):
        """Exact token followed by immediate EOF -> True (release authorized)."""
        from nodechain.runtime.exec_supervisor import _read_exact_token
        call_state = {"idx": 0}
        reads = [_RELEASE_TOKEN, None]  # token, then EOF
        def fake_read_exact(fd, count, **kw):
            idx = call_state["idx"]
            call_state["idx"] += 1
            return reads[idx] if idx < len(reads) else None
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            assert _read_exact_token(99, _RELEASE_TOKEN, deadline=999.0) is True

    def test_short_token_rejected(self):
        """Partial token (EOF before full length) -> False."""
        from nodechain.runtime.exec_supervisor import _read_exact_token
        call_state = {"idx": 0}
        reads = [_RELEASE_TOKEN[:5]]  # too short
        def fake_read_exact(fd, count, **kw):
            idx = call_state["idx"]
            call_state["idx"] += 1
            if idx < len(reads):
                return reads[idx]
            raise Exception("should not reach")
        # _read_exact would raise ConfigChannelError on partial; mock it.
        from nodechain.runtime.exec_supervisor import ConfigChannelError
        def fake_read_exact_err(fd, count, **kw):
            raise ConfigChannelError("partial_eof")
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact_err):
            assert _read_exact_token(99, _RELEASE_TOKEN, deadline=999.0) is False

    def test_wrong_token_rejected(self):
        """Full-length but wrong token -> False."""
        from nodechain.runtime.exec_supervisor import _read_exact_token
        wrong = b"X" * len(_RELEASE_TOKEN)
        call_state = {"idx": 0}
        reads = [wrong, None]
        def fake_read_exact(fd, count, **kw):
            idx = call_state["idx"]
            call_state["idx"] += 1
            return reads[idx] if idx < len(reads) else None
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            assert _read_exact_token(99, _RELEASE_TOKEN, deadline=999.0) is False

    def test_extra_bytes_after_token_rejected(self):
        """Exact token followed by extra bytes (not EOF) -> False."""
        from nodechain.runtime.exec_supervisor import _read_exact_token
        call_state = {"idx": 0}
        reads = [_RELEASE_TOKEN, b"X"]  # token, then extra byte
        def fake_read_exact(fd, count, **kw):
            idx = call_state["idx"]
            call_state["idx"] += 1
            return reads[idx] if idx < len(reads) else None
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            assert _read_exact_token(99, _RELEASE_TOKEN, deadline=999.0) is False

    def test_eof_before_token_rejected(self):
        """Immediate EOF (no token at all) -> False."""
        from nodechain.runtime.exec_supervisor import _read_exact_token
        from nodechain.runtime.exec_supervisor import ConfigChannelError
        def fake_read_exact(fd, count, **kw):
            raise ConfigChannelError("partial_eof")
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            assert _read_exact_token(99, _RELEASE_TOKEN, deadline=999.0) is False


# ===========================================================================
# Wait-status decoding
# ===========================================================================

@pytest.mark.skipif(sys.platform != "linux", reason="POSIX wait-status macros are Linux-only")
class TestWaitStatusDecoding:
    """_decode_wait_status must never return raw encoded status."""

    def test_clean_exit_zero(self):
        """WIFEXITED with exit 0 -> 0."""
        import signal as _sig
        status = 0  # exit(0) encodes as 0
        assert _decode_wait_status(status) == 0

    def test_clean_exit_nonzero(self):
        """WIFEXITED with exit 42 -> 42."""
        status = (42 << 8)  # WEXITSTATUS encoding
        assert _decode_wait_status(status) == 42

    def test_signaled(self):
        """WIFSIGNALED -> 128 + signal_num."""
        import signal as _sig
        status = _sig.SIGTERM  # WIFSIGNALED bit set
        assert _decode_wait_status(status) == 128 + _sig.SIGTERM

    def test_raw_status_never_returned(self):
        """The raw wait status is never the return value for signaled exits."""
        import signal as _sig
        status = _sig.SIGKILL
        result = _decode_wait_status(status)
        assert result != status  # must be decoded, not raw
        assert result == 128 + _sig.SIGKILL


# ===========================================================================
# Static source authority (supplementary to L7 characterization)
# ===========================================================================

class TestTask3StaticSource:
    """Static checks on exec_supervisor.py for Task 3 structural requirements."""

    def test_launcher_forks_exactly_one_child(self):
        """launch_pid_namespace_supervisor must have exactly one os.fork() call."""
        import ast
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        node = [n for n in ast.parse(src).body
                if isinstance(n, ast.FunctionDef) and n.name == "launch_pid_namespace_supervisor"][0]
        forks = [s for s in ast.walk(node) if isinstance(s, ast.Call)
                 and isinstance(s.func, ast.Attribute) and s.func.attr == "fork"]
        # Also count bare os.fork() — ast.Attribute handles os.fork().
        # Check for ast.Attribute where value is Name "os" and attr is "fork".
        fork_calls = [s for s in ast.walk(node) if isinstance(s, ast.Call)
                      and isinstance(s.func, ast.Attribute)
                      and s.func.attr == "fork"
                      and isinstance(s.func.value, ast.Name)
                      and s.func.value.id == "os"]
        assert len(fork_calls) == 1, (
            f"expected exactly 1 os.fork() in launcher, found {len(fork_calls)}"
        )

    def test_launcher_unshare_before_fork(self):
        """unshare_pid_namespace() must appear textually before os.fork()."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        launcher_start = src.index("def launch_pid_namespace_supervisor(")
        launcher_end = src.index("\ndef ", launcher_start + 1)
        launcher_src = src[launcher_start:launcher_end]
        unshare_pos = launcher_src.index("unshare_pid_namespace()")
        fork_pos = launcher_src.index("os.fork()")
        assert unshare_pos < fork_pos, (
            "unshare must occur before fork in the launcher"
        )

    def test_launcher_closes_protocol_before_gate_write(self):
        """S must close protocol_fd before writing the gate token."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        launcher_start = src.index("def launch_pid_namespace_supervisor(")
        launcher_end = src.index("\ndef ", launcher_start + 1)
        launcher_src = src[launcher_start:launcher_end]
        close_proto_pos = launcher_src.index("os.close(protocol_fd)")
        gate_write_pos = launcher_src.index("_RELEASE_TOKEN")
        assert close_proto_pos < gate_write_pos, (
            "S must close protocol_fd before the gate token write"
        )

    def test_namespace_init_uses_os_exit(self):
        """The I child branch must use os._exit, not return."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        launcher_start = src.index("def launch_pid_namespace_supervisor(")
        launcher_end = src.index("\ndef ", launcher_start + 1)
        launcher_src = src[launcher_start:launcher_end]
        assert "os._exit(rc" in launcher_src, (
            "namespace-init child must use os._exit, not return through stack"
        )

    def test_no_setsid_setpgid_in_task3_functions(self):
        """Neither launcher nor namespace-init may call setsid/setpgid."""
        import ast
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        for fname in ("launch_pid_namespace_supervisor", "namespace_init_supervisor_main"):
            node = [n for n in ast.parse(src).body
                    if isinstance(n, ast.FunctionDef) and n.name == fname][0]
            lines = src.splitlines()
            func_src = "\n".join(lines[node.lineno-1:node.end_lineno])
            for forbidden in ("setsid(", "os.setsid(", "setpgid(", "os.setpgid("):
                assert forbidden not in func_src, (
                    f"{fname} contains {forbidden}"
                )

    def test_supervisor_main_unchanged_signature(self):
        """supervisor_main must retain its stable signature.

        T2 added ``workload_input_fd`` (default None) so the parent-created
        workload-input read-end is forwarded through the namespace-init path.
        The security property this test guards is signature stability: callers
        must not be broken by a silent signature change, and any future
        argument addition must come with an explicit test update like this one.
        """
        import ast
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        node = [n for n in ast.parse(src).body
                if isinstance(n, ast.FunctionDef) and n.name == "supervisor_main"][0]
        args = [a.arg for a in node.args.args]
        assert args == ["config", "protocol_fd", "workload_input_fd"], (
            f"supervisor_main signature changed: {args}"
        )

    def test_bootstrap_spawned_pid_is_namespace_local(self):
        """Document the semantic boundary: bootstrap_spawned.pid is the
        I-visible namespace PID (normally 2), NOT a host PID.

        This is a characterization assertion per correction #7. The
        supervisor_main code emits PROTO_BOOTSTRAP_SPAWNED with the
        fork-returned pid, which inside the namespace is 2+."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        # The bootstrap_spawned emission is inside supervisor_main.
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        assert "PROTO_BOOTSTRAP_SPAWNED" in sm_src
        assert '"pid": bootstrap_pid' in sm_src or "'pid': bootstrap_pid" in sm_src, (
            "bootstrap_spawned must carry the namespace-local pid"
        )


# ===========================================================================
# Executable mocked authority tests — sequencing and failure injection
# ===========================================================================

class TestLauncherSequencing:
    """Mocked tests proving the launcher's gate sequence and failure paths.

    These tests mock os.fork, unshare_pid_namespace, build_topology_proof,
    emit_protocol, and the pipe/gate helpers to verify sequencing without
    real process creation.
    """

    def test_unshare_failure_does_not_fork(self):
        """If unshare fails, S must not fork I."""
        from nodechain.runtime import exec_supervisor as es
        fork_called = []
        with mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace",
                        side_effect=_PidNsUnsupported("test_unsupported")), \
             mock.patch.object(es.os, "fork", create=True, side_effect=lambda: fork_called.append(1) or 1), \
             mock.patch.object(es.os, "pipe", side_effect=[(100, 101), (102, 103), (104, 105)]), \
             mock.patch.object(es, "emit_protocol"), \
             mock.patch.object(es.os, "close"):
            es.launch_pid_namespace_supervisor({}, 999)
        assert len(fork_called) == 0, "fork must not be called on unshare failure"

    def test_pipe_failure_emits_failure_and_returns(self):
        """If os.pipe fails, S emits supervisor_failed and returns 1."""
        from nodechain.runtime import exec_supervisor as es
        emit_calls = []
        with mock.patch.object(es.os, "pipe", side_effect=OSError("pipe broke")), \
             mock.patch.object(es, "emit_protocol",
                               side_effect=lambda fd, r: emit_calls.append(r)), \
             mock.patch.object(es.os, "close"):
            rc = es.launch_pid_namespace_supervisor({}, 999)
        assert rc == 1
        assert any(r.get("type") == "supervisor_failed" for r in emit_calls)

    def test_fork_failure_emits_failure_and_returns(self):
        """If os.fork fails after unshare, S emits supervisor_failed."""
        from nodechain.runtime import exec_supervisor as es
        emit_calls = []
        with mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace"), \
             mock.patch.object(es.os, "pipe", side_effect=[(100, 101), (102, 103), (104, 105)]), \
             mock.patch.object(es.os, "fork", create=True, side_effect=OSError("fork failed")), \
             mock.patch.object(es, "emit_protocol",
                               side_effect=lambda fd, r: emit_calls.append(r)), \
             mock.patch.object(es.os, "close"):
            rc = es.launch_pid_namespace_supervisor({}, 999)
        assert rc == 1
        assert any(r.get("type") == "supervisor_failed" for r in emit_calls)
        assert any("fork_failed" in r.get("reason", "") for r in emit_calls
                    if r.get("type") == "supervisor_failed")

    def test_protocol_close_failure_denies_release(self):
        """If os.close(protocol_fd) fails, S must NOT release I."""
        from nodechain.runtime import exec_supervisor as es
        # Mock fork to return a nonzero PID (parent branch).
        close_calls = []
        def fake_close(fd):
            close_calls.append(fd)
            if fd == 999:  # protocol_fd
                raise OSError("bad close")
            return None
        gate_write_calls = []
        def track_writes(fd, *args, **kw):
            # Only track writes to the gate pipe (fd=101), not the proof pipe.
            if fd == 101:
                gate_write_calls.append(1)
        with mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace"), \
             mock.patch.object(es.os, "pipe", side_effect=[(100, 101), (102, 103), (104, 105)]), \
             mock.patch.object(es.os, "fork", create=True, return_value=55555), \
             mock.patch.object(es, "_read_identity_frame",
                               return_value={"version": 1, "type": "init_identity",
                                             "pid": 1, "ppid": 0}), \
             mock.patch("nodechain.runtime.pid_namespace_topology.build_topology_proof",
                        return_value=mock.MagicMock(child_pidns_dev=4, child_pidns_ino=99,
                                                    init_host_pid=55555)), \
             mock.patch.object(es.os, "close", side_effect=fake_close), \
             mock.patch.object(es, "_write_bounded_fd", side_effect=track_writes), \
             mock.patch.object(es, "_contain_init_child", return_value=True):
            rc = es.launch_pid_namespace_supervisor({}, 999)
        assert rc != 0, "must return nonzero on protocol-close failure"
        # The gate write must NOT have been called — I was not released.
        assert len(gate_write_calls) == 0, "gate token must not be written on close failure"

    def test_supervisor_main_called_only_after_successful_release(self):
        """namespace_init_supervisor_main must call supervisor_main only after
        a valid token + EOF."""
        from nodechain.runtime import exec_supervisor as es
        # Token matches -> supervisor_main is called. Mock proof read.
        with mock.patch.object(es, "_read_exact_token", return_value=True), \
             mock.patch.object(es, "_write_identity_frame"), \
             mock.patch.object(es, "_read_identity_frame",
                               return_value={"version":1,"type":"topology_proof",
                                             "child_pidns_dev":4,"child_pidns_ino":99,
                                             "init_host_pid":1}), \
             mock.patch.object(es, "supervisor_main", return_value=0) as sm, \
             mock.patch.object(es.os, "close"), \
             mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0):
            rc = es.namespace_init_supervisor_main({}, 999, 100, 101, 102)
        assert rc == 0
        sm.assert_called_once()

    def test_supervisor_main_not_called_on_gate_failure(self):
        """If the gate token is wrong/EOF, supervisor_main is NOT called."""
        from nodechain.runtime import exec_supervisor as es
        with mock.patch.object(es, "_read_exact_token", return_value=False), \
             mock.patch.object(es, "_write_identity_frame"), \
             mock.patch.object(es, "_read_identity_frame",
                               return_value={"version":1,"type":"topology_proof",
                                             "child_pidns_dev":4,"child_pidns_ino":99,
                                             "init_host_pid":1}), \
             mock.patch.object(es, "supervisor_main") as sm, \
             mock.patch.object(es.os, "close"), \
             mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0):
            rc = es.namespace_init_supervisor_main({}, 999, 100, 101, 102)
        assert rc != 0
        sm.assert_not_called()


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX waitpid/reap semantics")
class TestContainmentResult:
    """_contain_init_child must carry the actual reap result, not a default."""

    def test_exact_reap_followed_by_echild_is_success(self):
        """waitpid(init_pid) returns init_pid, then waitpid(-1) raises ECHILD
        -> containment returns True."""
        from nodechain.runtime import exec_supervisor as es
        call_count = {"n": 0}
        def fake_waitpid(pid, flags=0):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return (55555, 0)  # exact target reap
            if call_count["n"] == 2:
                raise ChildProcessError()  # ECHILD on waitpid(-1)
            raise ChildProcessError()
        with mock.patch.object(es.os, "kill"), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid):
            result = es._contain_init_child(55555)
        assert result is True

    def test_echild_before_exact_reap_is_failure(self):
        """ChildProcessError before any exact waitpid return -> containment False."""
        from nodechain.runtime import exec_supervisor as es
        def fake_waitpid(pid, flags=0):
            raise ChildProcessError()  # immediate ECHILD, no prior reap
        with mock.patch.object(es.os, "kill"), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid):
            result = es._contain_init_child(55555)
        assert result is False

    def test_waitpid_minus_one_returns_zero_zero_is_failure(self):
        """waitpid(-1, WNOHANG) returning (0, 0) means a child remains -> False."""
        from nodechain.runtime import exec_supervisor as es
        call_count = {"n": 0}
        def fake_waitpid(pid, flags=0):
            call_count["n"] += 1
            if call_count["n"] <= 1:
                return (55555, 0)  # exact reap OK
            return (0, 0)  # waitpid(-1) says child still exists
        with mock.patch.object(es.os, "kill"), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid):
            result = es._contain_init_child(55555)
        assert result is False

    def test_waitpid_returns_wrong_child_is_failure(self):
        """waitpid returns a PID that is NOT init_pid -> not exact reap -> False."""
        from nodechain.runtime import exec_supervisor as es
        call_count = {"n": 0}
        def fake_waitpid(pid, flags=0):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return (99999, 0)  # wrong PID
            raise ChildProcessError()  # ECHILD eventually
        with mock.patch.object(es.os, "kill"), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid):
            result = es._contain_init_child(55555)
        assert result is False


# ===========================================================================
# Parser initial-failure branch (#1 correction)
# ===========================================================================

class TestProtocolParserPreGateFailure:
    """The protocol parser must accept supervisor_failed as the initial record
    for pre-gate failure streams."""

    def test_initial_supervisor_failed_plus_cleanup_true_accepted(self):
        """supervisor_failed + cleanup_completed(true) + EOF → valid stream."""
        from nodechain.runtime.exec_supervisor import _ProtocolStreamParser
        import json
        p = _ProtocolStreamParser()
        p.feed((json.dumps({"version":1,"type":"supervisor_failed","reason":"test"}) + "\n").encode())
        p.feed((json.dumps({"version":1,"type":"cleanup_completed","cleanup_succeeded":True}) + "\n").encode())
        result = p.feed_eof()
        assert result.ok
        assert len(result.records) == 2
        assert result.records[0]["type"] == "supervisor_failed"
        assert result.records[1]["type"] == "cleanup_completed"

    def test_initial_supervisor_failed_plus_cleanup_false_accepted(self):
        """supervisor_failed + cleanup_completed(false) + EOF → records retained
        (ok=False is correct — cleanup failed; records ARE preserved)."""
        from nodechain.runtime.exec_supervisor import _ProtocolStreamParser
        import json
        p = _ProtocolStreamParser()
        p.feed((json.dumps({"version":1,"type":"supervisor_failed","reason":"cleanup_failed"}) + "\n").encode())
        p.feed((json.dumps({"version":1,"type":"cleanup_completed","cleanup_succeeded":False}) + "\n").encode())
        result = p.feed_eof()
        # ok=False is correct (cleanup failed), but records must be retained.
        assert len(result.records) == 2
        assert result.records[0]["type"] == "supervisor_failed"
        assert result.records[1]["type"] == "cleanup_completed"
        assert result.records[1]["cleanup_succeeded"] is False

    def test_initial_bootstrap_spawned_rejected(self):
        """bootstrap_spawned as first record → invalid initial state."""
        from nodechain.runtime.exec_supervisor import _ProtocolStreamParser
        import json
        p = _ProtocolStreamParser()
        result = p.feed((json.dumps({"version":1,"type":"bootstrap_spawned","pid":1}) + "\n").encode())
        assert result is not None
        assert not result.ok
        assert "initial" in result.reason

    def test_supervisor_started_after_failure_rejected(self):
        """supervisor_started after supervisor_failed → invalid transition."""
        from nodechain.runtime.exec_supervisor import _ProtocolStreamParser
        import json
        p = _ProtocolStreamParser()
        p.feed((json.dumps({"version":1,"type":"supervisor_failed","reason":"test"}) + "\n").encode())
        result = p.feed((json.dumps({"version":1,"type":"supervisor_started"}) + "\n").encode())
        assert result is not None
        assert not result.ok


# ===========================================================================
# End-to-end cleanup_failed mapping (#2 correction)
# ===========================================================================

class TestCleanupFailedMapping:
    """When containment fails, the caller-visible reason must be exactly
    'cleanup_failed' through parser → evidence → mapper."""

    def test_failed_cleanup_maps_to_cleanup_failed(self):
        """parser(supervisor_failed+cleanup(false)) → evidence → mapper
        → reason == 'cleanup_failed'."""
        from nodechain.runtime.exec_supervisor import (
            _ProtocolStreamParser, extract_supervisor_evidence,
        )
        from nodechain.runtime.native_sandbox_exec import map_supervisor_result
        import json
        p = _ProtocolStreamParser()
        p.feed((json.dumps({"version":1,"type":"supervisor_failed","reason":"cleanup_failed"}) + "\n").encode())
        p.feed((json.dumps({"version":1,"type":"cleanup_completed","cleanup_succeeded":False}) + "\n").encode())
        result = p.feed_eof()
        # ok=False is correct for cleanup failure; records are retained.
        evidence = extract_supervisor_evidence(result)
        assert evidence.cleanup_succeeded is False
        assert evidence.supervisor_failure_reason == "cleanup_failed"
        # The frozen mapper: supervisor_failure_reason takes precedence.
        # Pass a non-None bounded dict so the mapper reaches the evidence
        # mapping path (bounded=None triggers an early streaming_reader_error).
        mapped = map_supervisor_result(evidence, {})
        assert mapped.get("reason") == "cleanup_failed"
        assert mapped.get("exit_code_interpretation") == "error"


# ===========================================================================
# ECHILD does not lead to second signal (#3 correction)
# ===========================================================================

@pytest.mark.skipif(sys.platform != "linux", reason="SIGKILL is POSIX-only")
class TestContainmentNoSignalAfterECHILD:
    """ECHILD before exact reap must not cause a subsequent SIGKILL."""

    def test_immediate_echild_does_not_sigkill(self):
        """When waitpid raises ECHILD immediately on SIGTERM, the
        containment must NOT send SIGKILL (child authority lost)."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        def fake_kill(pid, sig):
            kill_calls.append(sig)
        def fake_waitpid(pid, flags=0):
            raise ChildProcessError()
        with mock.patch.object(es.os, "kill", side_effect=fake_kill), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid):
            result = es._contain_init_child(55555)
        assert result is False
        # Only SIGTERM should have been sent — NOT SIGKILL.
        assert signal.SIGTERM in kill_calls
        assert signal.SIGKILL not in kill_calls, (
            "SIGKILL must not be sent after ECHILD (child authority lost, "
            "numeric PID may have been recycled)"
        )


# ===========================================================================
# Child exception boundary (#4 correction)
# ===========================================================================

class TestChildExceptionBoundary:
    """The child branch must catch BaseException and os._exit(1)."""

    def test_child_exception_invokes_os_exit_not_propagate(self):
        """If namespace_init_supervisor_main raises, the child must
        os._exit(1) rather than propagating through the fork stack."""
        from nodechain.runtime import exec_supervisor as es
        exit_calls = []
        with mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace"), \
             mock.patch.object(es.os, "pipe", side_effect=[(100, 101), (102, 103), (104, 105)]), \
             mock.patch.object(es.os, "fork", return_value=0, create=True), \
             mock.patch.object(es, "namespace_init_supervisor_main",
                               side_effect=RuntimeError("unexpected")), \
             mock.patch.object(es.os, "_exit",
                               side_effect=lambda rc: exit_calls.append(rc)), \
             mock.patch.object(es.os, "close"):
            es.launch_pid_namespace_supervisor({}, 999)
        assert len(exit_calls) == 1, f"expected 1 os._exit call, got {exit_calls}"
        assert exit_calls[0] == 1, f"expected exit code 1, got {exit_calls[0]}"


# ===========================================================================
# Identity frame ConfigChannelError translation (#1 prior review)
# ===========================================================================

class TestIdentityFrameTranslation:
    """_read_identity_frame must translate all _read_exact ConfigChannelError
    outcomes into IdentityChannelError."""

    def test_identity_header_timeout_translated(self):
        from nodechain.runtime import exec_supervisor as es
        with mock.patch.object(es, "_read_exact",
                               side_effect=es.ConfigChannelError("identity_header_timeout")):
            with pytest.raises(IdentityChannelError, match="identity_header_failed"):
                es._read_identity_frame(99, deadline=999.0)

    def test_identity_payload_partial_eof_translated(self):
        from nodechain.runtime import exec_supervisor as es
        call_state = {"n": 0}
        def fake_read(fd, count, **kw):
            call_state["n"] += 1
            if call_state["n"] == 1:
                return b"\x00\x00\x00\x10"  # header: 16 bytes
            raise es.ConfigChannelError("identity_payload_partial_eof")
        with mock.patch.object(es, "_read_exact", side_effect=fake_read):
            with pytest.raises(IdentityChannelError, match="identity_payload_failed"):
                es._read_identity_frame(99, deadline=999.0)

    def test_identity_eof_check_timeout_translated(self):
        from nodechain.runtime import exec_supervisor as es
        call_state = {"n": 0}
        payload = b'{"version":1,"type":"init_identity","pid":1,"ppid":0}'
        def fake_read(fd, count, **kw):
            call_state["n"] += 1
            if call_state["n"] == 1:
                return struct.pack(">I", len(payload))
            if call_state["n"] == 2:
                return payload
            raise es.ConfigChannelError("identity_eof_timeout")
        with mock.patch.object(es, "_read_exact", side_effect=fake_read):
            with pytest.raises(IdentityChannelError, match="identity_eof_failed"):
                es._read_identity_frame(99, deadline=999.0)


# ===========================================================================
# Second pipe failure + topology proof failure (#3 prior review)
# ===========================================================================

class TestPipeAndProofFailures:
    """Pipe setup and topology proof failure paths."""

    def test_second_pipe_failure_closes_first(self):
        """If the second os.pipe() fails, the first pair must be closed."""
        from nodechain.runtime import exec_supervisor as es
        close_calls = []
        pipe_call_count = {"n": 0}
        def fake_pipe():
            pipe_call_count["n"] += 1
            if pipe_call_count["n"] == 1:
                return (100, 101)  # first succeeds
            raise OSError("second pipe failed")
        def fake_close(fd):
            close_calls.append(fd)
        with mock.patch.object(es.os, "pipe", side_effect=fake_pipe), \
             mock.patch.object(es, "emit_protocol"), \
             mock.patch.object(es.os, "close", side_effect=fake_close):
            rc = es.launch_pid_namespace_supervisor({}, 999)
        assert rc == 1
        # First pipe's FDs (100, 101) must have been closed.
        assert 100 in close_calls, "first pipe read end not closed on second pipe failure"
        assert 101 in close_calls, "first pipe write end not closed on second pipe failure"

    def test_topology_proof_failure_denies_release(self):
        """If build_topology_proof raises, I must not be released."""
        from nodechain.runtime import exec_supervisor as es
        gate_writes = []
        with mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace"), \
             mock.patch.object(es.os, "pipe", side_effect=[(100, 101), (102, 103), (104, 105)]), \
             mock.patch.object(es.os, "fork", return_value=55555, create=True), \
             mock.patch.object(es, "_read_identity_frame",
                               return_value={"version":1,"type":"init_identity","pid":1,"ppid":0}), \
             mock.patch("nodechain.runtime.pid_namespace_topology.build_topology_proof",
                        side_effect=_PidNsProofError("proof_failed")), \
             mock.patch.object(es, "_contain_and_fail") as caf, \
             mock.patch.object(es, "_write_bounded_fd",
                               side_effect=lambda *a, **kw: gate_writes.append(1)), \
             mock.patch.object(es.os, "close"):
            rc = es.launch_pid_namespace_supervisor({}, 999)
        assert rc == 1
        # _contain_and_fail must have been called (denies release).
        caf.assert_called_once()
        # Gate token must NOT have been written.
        assert len(gate_writes) == 0, "gate token must not be written on proof failure"
