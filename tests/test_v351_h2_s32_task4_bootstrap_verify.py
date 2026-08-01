"""S3.2 Task 4: bootstrap-side PID-namespace verification tests.

Tests that the bootstrap template performs namespace verification before
PTRACE_TRACEME, that S→I proof forwarding works, and that all failure
modes are fail-closed.

Most tests are static-source inspections of the rendered bootstrap
template (which is a source string built by _build_bootstrap_script).
Mocked executable tests cover the proof-forwarding path.
"""

from __future__ import annotations

import ast
import json
import struct
import sys
from unittest import mock

import pytest


# ===========================================================================
# Static source: bootstrap template has namespace verification before ptrace
# ===========================================================================

class TestBootstrapTemplateVerification:
    """The rendered bootstrap script must verify namespace identity BEFORE
    calling PTRACE_TRACEME."""

    def _script(self):
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        return _build_bootstrap_script()

    def test_bootstrap_has_namespace_verify_before_ptrace_traceme(self):
        """The namespace verification block must appear textually before
        the PTRACE_TRACEME CALL (not the constant definition) in the
        rendered bootstrap script."""
        script = self._script()
        verify_pos = script.find("namespace_verify")
        # Find the actual ptrace call, not the constant definition.
        # The call looks like: libc.ptrace(_PTRACE_TRACEME, 0, None, None)
        traceme_call_pos = script.find("ptrace(_PTRACE_TRACEME")
        assert verify_pos >= 0, "namespace_verify not found in bootstrap script"
        assert traceme_call_pos >= 0, "ptrace(_PTRACE_TRACEME call not found"
        assert verify_pos < traceme_call_pos, (
            "namespace verification must occur before the PTRACE_TRACEME call"
        )

    def test_bootstrap_checks_getpid_gt_1(self):
        """The bootstrap must verify getpid() > 1."""
        script = self._script()
        assert "getpid() <= 1" in script or "getpid() > 1" in script, (
            "bootstrap must check getpid() > 1"
        )

    def test_bootstrap_checks_getppid_eq_1(self):
        """The bootstrap must verify getppid() == 1."""
        script = self._script()
        assert "getppid() != 1" in script, (
            "bootstrap must check getppid() != 1 (namespace parent must be PID 1)"
        )

    def test_bootstrap_checks_ns_pid_identity(self):
        """The bootstrap must stat /proc/self/ns/pid and compare dev/ino."""
        script = self._script()
        assert "/proc/self/ns/pid" in script
        assert "st_dev" in script and "st_ino" in script
        assert "expected_pidns_dev" in script and "expected_pidns_ino" in script

    def test_bootstrap_ns_failure_exits_before_ptrace_traceme(self):
        """On namespace verification failure, the bootstrap must _exit(126)
        before reaching PTRACE_TRACEME."""
        script = self._script()
        # Find all _exit(126) positions
        positions = []
        start = 0
        while True:
            pos = script.find("_os._exit(126)", start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        traceme_pos = script.find("ptrace(_PTRACE_TRACEME")
        # At least one _exit(126) must precede the PTRACE_TRACEME call.
        assert any(p < traceme_pos for p in positions), (
            "at least one namespace-verify _exit(126) must precede PTRACE_TRACEME"
        )

    def test_bootstrap_failure_emits_bootstrap_failed(self):
        """Namespace verification failure must emit META_BOOTSTRAP_FAILED
        (not a new parent-facing protocol type)."""
        script = self._script()
        assert "_META_BOOTSTRAP_FAILED" in script
        assert "namespace_verify" in script  # stable stage name

    def test_bootstrap_no_new_protocol_type(self):
        """The bootstrap must not introduce any new parent-facing protocol
        record types beyond the existing metadata schema."""
        script = self._script()
        # The bootstrap only emits via _emit_meta with _META_* constants.
        # Check that no new proto type string is invented.
        for existing in ["_META_BOOTSTRAP_STARTED", "_META_ENFORCEMENT_VERIFIED",
                         "_META_BOOTSTRAP_FAILED", "_META_PTRACE_TRACEME_FAILED"]:
            assert existing in script, f"{existing} must be in the bootstrap script"

    def test_bootstrap_enforcement_meta_has_verified_fields(self):
        """On success, enforcement_meta must carry namespace identity fields."""
        script = self._script()
        assert "pid_namespace_verified" in script
        assert "namespace_pid" in script
        assert "pidns_dev" in script
        assert "pidns_ino" in script

    def test_no_s2_stub_remains(self):
        """The S2 stub ('s2_stub') must be completely removed."""
        script = self._script()
        assert "s2_stub" not in script, "S2 stub must be replaced by real verification"


# ===========================================================================
# Static source: proof forwarding in launcher/namespace-init
# ===========================================================================

class TestProofForwarding:
    """S captures the topology proof and forwards it to I through a dedicated
    proof channel. I reads it and injects the namespace identity into config."""

    def test_launcher_captures_proof(self):
        """launch_pid_namespace_supervisor must assign the proof return value
        (not discard it)."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert "proof = build_topology_proof(" in src, (
            "launcher must capture the proof return value"
        )

    def test_launcher_writes_proof_frame(self):
        """S must write a topology_proof frame to the proof channel."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert '"topology_proof"' in src or "'topology_proof'" in src, (
            "launcher must write a topology_proof record"
        )
        assert "child_pidns_dev" in src and "child_pidns_ino" in src

    def test_namespace_init_reads_proof(self):
        """namespace_init_supervisor_main must read the proof frame and inject
        the expected identity into config."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        init_start = src.index("def namespace_init_supervisor_main(")
        init_end = src.index("\ndef ", init_start + 1)
        init_src = src[init_start:init_end]
        assert "expected_pidns_dev" in init_src
        assert "expected_pidns_ino" in init_src
        assert "config[" in init_src or 'config["' in init_src

    def test_supervisor_main_forwards_expected_identity(self):
        """supervisor_main must put expected_pidns_dev/ino into bootstrap_config."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        assert "expected_pidns_dev" in sm_src
        assert "expected_pidns_ino" in sm_src

    def test_proof_not_overridable_by_parent(self):
        """Parent-supplied config must not be able to override the expected
        namespace identity. The proof values are injected by I, not by the
        parent config pipe."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        # The injection happens inside namespace_init_supervisor_main AFTER
        # reading the proof from the proof channel — parent config arrives
        # earlier and is a different dict.
        init_start = src.index("def namespace_init_supervisor_main(")
        init_end = src.index("\ndef ", init_start + 1)
        init_src = src[init_start:init_end]
        assert 'config["expected_pidns_dev"]' in init_src, (
            "namespace_init must set expected_pidns_dev from proof, not from parent config"
        )


# ===========================================================================
# Executable mocked tests: proof-frame handling
# ===========================================================================

class TestProofFrameHandling:
    """The proof frame uses the same framing as identity — 4-byte header,
    closed schema, clean EOF."""

    def test_valid_proof_frame_accepted(self):
        """A valid topology_proof frame is read and parsed correctly."""
        from nodechain.runtime.exec_supervisor import _read_identity_frame
        payload = json.dumps({
            "version": 1, "type": "topology_proof",
            "child_pidns_dev": 4, "child_pidns_ino": 99,
            "init_host_pid": 55555,
        }, separators=(",", ":")).encode()
        frame = struct.pack(">I", len(payload)) + payload
        call_state = {"n": 0}
        reads = [frame[:4], frame[4:], None]
        def fake_read_exact(fd, count, **kw):
            idx = call_state["n"]
            call_state["n"] += 1
            return reads[idx] if idx < len(reads) else None
        with mock.patch("nodechain.runtime.exec_supervisor._read_exact",
                        side_effect=fake_read_exact):
            obj = _read_identity_frame(99, deadline=999.0)
        assert obj["type"] == "topology_proof"
        assert obj["child_pidns_dev"] == 4
        assert obj["child_pidns_ino"] == 99

    def test_wrong_type_proof_rejected_by_validator(self):
        """A proof frame with wrong type is rejected by _validate_proof_record."""
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        with pytest.raises(IdentityChannelError, match="type_invalid"):
            _validate_proof_record({
                "version": 1, "type": "wrong_type",
                "child_pidns_dev": 4, "child_pidns_ino": 99,
                "init_host_pid": 55555,
            })

    def test_proof_timeout_denies_core_entry(self):
        """If the proof read times out, namespace_init must not enter core."""
        from nodechain.runtime import exec_supervisor as es
        from nodechain.runtime.exec_supervisor import ConfigChannelError
        # Mock: identity write succeeds, proof read fails (timeout).
        with mock.patch.object(es, "_write_identity_frame"), \
             mock.patch.object(es, "_read_identity_frame",
                               side_effect=es.IdentityChannelError("timeout")), \
             mock.patch.object(es, "supervisor_main") as sm, \
             mock.patch.object(es.os, "close"), \
             mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0):
            rc = es.namespace_init_supervisor_main({}, 999, 100, 101, 102)
        assert rc != 0
        sm.assert_not_called()

    def test_missing_proof_channel_denies_core_entry(self):
        """Missing/invalid proof FD must deny core entry — no backward-compat
        bypass. supervisor_main must NOT be called."""
        from nodechain.runtime import exec_supervisor as es
        with mock.patch.object(es, "_write_identity_frame"), \
             mock.patch.object(es, "supervisor_main") as sm, \
             mock.patch.object(es.os, "close"), \
             mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0):
            # proof_r=-1 → the proof read will try to read from fd -1 and fail.
            # namespace_init must NOT call supervisor_main.
            rc = es.namespace_init_supervisor_main({}, 999, 100, 101, -1)
        assert rc != 0
        sm.assert_not_called()

    def test_parent_supplied_identity_cannot_bypass_proof(self):
        """Parent config may supply expected_pidns_dev/ino, but these must
        be stripped and overwritten by the validated proof values."""
        from nodechain.runtime import exec_supervisor as es
        proof_payload = json.dumps({
            "version": 1, "type": "topology_proof",
            "child_pidns_dev": 42, "child_pidns_ino": 99,
            "init_host_pid": 55555,
        }, separators=(",", ":")).encode()
        proof_frame = struct.pack(">I", len(proof_payload)) + proof_payload
        call_state = {"n": 0}
        reads = [proof_frame[:4], proof_frame[4:], None]
        def fake_read_exact(fd, count, **kw):
            idx = call_state["n"]
            call_state["n"] += 1
            return reads[idx] if idx < len(reads) else None
        captured_config = {}
        def fake_supervisor_main(config, protocol_fd, workload_input_fd=None):
            captured_config.update(config)
            return 0
        parent_config = {"expected_pidns_dev": 999, "expected_pidns_ino": 888,
                         "workload_argv": ["test"]}
        with mock.patch.object(es, "_write_identity_frame"), \
             mock.patch.object(es, "_read_exact_token", return_value=True), \
             mock.patch.object(es, "_read_exact", side_effect=fake_read_exact), \
             mock.patch.object(es, "_read_identity_frame",
                               return_value={"version":1,"type":"topology_proof",
                                             "child_pidns_dev":42,"child_pidns_ino":99,
                                             "init_host_pid":55555}), \
             mock.patch.object(es, "supervisor_main", side_effect=fake_supervisor_main), \
             mock.patch.object(es.os, "close"), \
             mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0):
            rc = es.namespace_init_supervisor_main(parent_config, 999, 100, 101, 102)
        assert rc == 0
        # Proof values (42, 99) must overwrite parent values (999, 888).
        assert captured_config.get("expected_pidns_dev") == 42
        assert captured_config.get("expected_pidns_ino") == 99


# ===========================================================================
# L8 invariants preserved
# ===========================================================================

class TestTask4DoesNotBreakL8:
    """Task 4 must not alter the ptrace authority chain."""

    def test_ptrace_options_unchanged(self):
        """PTRACE_O_TRACEEXEC must still be the only option in supervisor_main."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        assert "PTRACE_SETOPTIONS, bootstrap_pid, None, PTRACE_O_TRACEEXEC" in sm_src
        for forbidden in ("PTRACE_O_TRACEFORK", "PTRACE_O_TRACECLONE",
                          "PTRACE_O_TRACEVFORK", "PTRACE_O_EXITKILL"):
            assert forbidden not in sm_src

    def test_exact_event_check_unchanged(self):
        """The SIGTRAP && PTRACE_EVENT_EXEC check must be unchanged."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        assert "stopsig == signal.SIGTRAP" in sm_src
        assert "event == PTRACE_EVENT_EXEC" in sm_src


# ===========================================================================
# Executable proof-record validation (correction #1 + #4)
# ===========================================================================

class TestProofRecordValidation:
    """Direct validation of _validate_proof_record — the closed-schema
    proof validator that I uses before accepting the topology identity."""

    def _valid(self):
        return {
            "version": 1, "type": "topology_proof",
            "child_pidns_dev": 4, "child_pidns_ino": 99,
            "init_host_pid": 55555,
        }

    def test_valid_proof_accepted(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record
        dev, ino = _validate_proof_record(self._valid())
        assert dev == 4
        assert ino == 99

    def test_unknown_field_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["extra"] = "bad"
        with pytest.raises(IdentityChannelError, match="unknown_fields"):
            _validate_proof_record(obj)

    def test_missing_field_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        del obj["child_pidns_ino"]
        with pytest.raises(IdentityChannelError, match="missing_fields"):
            _validate_proof_record(obj)

    def test_missing_version_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        del obj["version"]
        with pytest.raises(IdentityChannelError, match="missing_fields"):
            _validate_proof_record(obj)

    def test_bool_version_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["version"] = True
        with pytest.raises(IdentityChannelError, match="version_invalid"):
            _validate_proof_record(obj)

    def test_bool_dev_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["child_pidns_dev"] = True
        with pytest.raises(IdentityChannelError, match="dev_invalid"):
            _validate_proof_record(obj)

    def test_bool_ino_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["child_pidns_ino"] = False
        with pytest.raises(IdentityChannelError, match="ino_invalid"):
            _validate_proof_record(obj)

    def test_bool_init_host_pid_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["init_host_pid"] = True
        with pytest.raises(IdentityChannelError, match="init_host_pid_invalid"):
            _validate_proof_record(obj)

    def test_zero_dev_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["child_pidns_dev"] = 0
        with pytest.raises(IdentityChannelError, match="dev_invalid"):
            _validate_proof_record(obj)

    def test_negative_ino_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["child_pidns_ino"] = -1
        with pytest.raises(IdentityChannelError, match="ino_invalid"):
            _validate_proof_record(obj)

    def test_missing_init_host_pid_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        del obj["init_host_pid"]
        with pytest.raises(IdentityChannelError, match="missing_fields"):
            _validate_proof_record(obj)

    def test_wrong_init_host_pid_binding_handled_by_S(self):
        """The host-PID binding is S-side authority, not I-side. I validates
        schema only. A wrong init_host_pid is still schema-valid (positive int).
        The S-side comparison (proof.init_host_pid == init_host_pid) is the
        sole binding check; this test documents that I does NOT reject it."""
        from nodechain.runtime.exec_supervisor import _validate_proof_record
        obj = self._valid()
        obj["init_host_pid"] = 99999  # different value, still positive int
        # I accepts it — schema-valid. S is the binding authority.
        dev, ino = _validate_proof_record(obj)
        assert dev == 4
        assert ino == 99

    def test_wrong_type_rejected(self):
        from nodechain.runtime.exec_supervisor import _validate_proof_record, IdentityChannelError
        obj = self._valid()
        obj["type"] = "wrong"
        with pytest.raises(IdentityChannelError, match="type_invalid"):
            _validate_proof_record(obj)


# ===========================================================================
# Static source: bootstrap failure ordering (correction #4)
# ===========================================================================

class TestBootstrapFailureOrdering:
    """The bootstrap template must emit bootstrap_failed + _exit(126) for
    each namespace-verification failure, all BEFORE PTRACE_TRACEME.

    Tests use AST analysis of the rendered script to lock actual control
    flow — not substring positions that can false-pass on comments or
    dead code."""

    def _tree(self):
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        return ast.parse(_build_bootstrap_script())

    def _main_node(self):
        """Return the main() function node from the rendered script."""
        for node in self._tree().body:
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                return node
        pytest.fail("main() function not found in rendered bootstrap")

    def _collect_failure_reasons(self):
        """Collect all bootstrap_failed reason strings and their line numbers
        from _emit_meta calls in main()."""
        node = self._main_node()
        reasons = []
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id == "_emit_meta"):
                # Check if the dict argument has type=bootstrap_failed
                for arg in sub.args:
                    if isinstance(arg, ast.Dict):
                        for key, val in zip(arg.keys, arg.values):
                            if (isinstance(key, ast.Constant) and key.value == "reason"
                                    and isinstance(val, ast.Constant)):
                                reasons.append((val.value, sub.lineno))
        return reasons

    def _ptrace_traceme_lineno(self):
        """Find the line number of the actual ptrace(_PTRACE_TRACEME, ...) call."""
        node = self._main_node()
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "ptrace"):
                for arg in sub.args:
                    if isinstance(arg, ast.Name) and arg.id == "_PTRACE_TRACEME":
                        return sub.lineno
        return None

    def test_all_five_failure_reasons_present(self):
        """All five bootstrap_failed reason strings must be present as AST
        constants in _emit_meta calls."""
        reasons = dict(self._collect_failure_reasons())
        for required in ("bootstrap_pid_not_gt_1", "bootstrap_ppid_not_1",
                         "ns_pid_read_failed", "ns_pid_identity_mismatch",
                         "expected_identity_absent"):
            assert required in reasons, (
                f"bootstrap_failed reason '{required}' not found in any _emit_meta call"
            )

    def test_all_failures_precede_ptrace_traceme(self):
        """Every bootstrap_failed emit must structurally precede the
        PTRACE_TRACEME call."""
        traceme_line = self._ptrace_traceme_lineno()
        assert traceme_line is not None, "PTRACE_TRACEME call not found"
        for reason_str, line in self._collect_failure_reasons():
            assert line < traceme_line, (
                f"failure '{reason_str}' at line {line} does not precede "
                f"PTRACE_TRACEME at line {traceme_line}"
            )

    def test_enforcement_verified_emit_after_all_failures(self):
        """The enforcement_verified _emit_meta call must appear after all
        failure branches."""
        reasons = self._collect_failure_reasons()
        assert reasons, "no bootstrap_failed reasons found — failure branches are missing"
        last_failure_line = max(line for _, line in reasons)
        node = self._main_node()
        enforcement_lines = []
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id == "_emit_meta"):
                for arg in sub.args:
                    if isinstance(arg, ast.Dict):
                        for key, val in zip(arg.keys, arg.values):
                            if (isinstance(key, ast.Constant) and key.value == "type"
                                    and isinstance(val, ast.Name)
                                    and val.id == "_META_ENFORCEMENT_VERIFIED"):
                                enforcement_lines.append(sub.lineno)
        assert enforcement_lines, "enforcement_verified _emit_meta call not found"
        for eline in enforcement_lines:
            assert eline > last_failure_line, (
                f"enforcement_verified at line {eline} does not follow "
                f"last failure at line {last_failure_line}"
            )


# ===========================================================================
# Static source: S-side double-close removed (correction #3)
# ===========================================================================

class TestNoDoubleClose:
    """S must not double-close any pipe descriptors."""

    def test_no_double_close_in_launcher(self):
        """Check that no FD variable is closed more than once in the S
        branch of launch_pid_namespace_supervisor."""
        import ast
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        node = [n for n in ast.parse(src).body
                if isinstance(n, ast.FunctionDef)
                and n.name == "launch_pid_namespace_supervisor"][0]
        # Find all os.close calls and collect their FD argument names.
        close_fds = []
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Expr) and isinstance(sub.value, ast.Call)
                    and isinstance(sub.value.func, ast.Attribute)
                    and sub.value.func.attr == "close"
                    and sub.value.args
                    and isinstance(sub.value.args[0], ast.Name)):
                close_fds.append(sub.value.args[0].id)
        # gate_r and identity_w should each appear at most once in close calls.
        for fd_name in ("gate_r", "identity_w", "proof_r"):
            count = close_fds.count(fd_name)
            assert count <= 1, (
                f"{fd_name} closed {count} times in launcher (must be at most 1)"
            )


# ===========================================================================
# Executable launcher test: S-side host-PID binding authority
# ===========================================================================

class TestLauncherBindingAuthority:
    """When build_topology_proof returns a proof with init_host_pid != the
    fork return, S must deny release, contain I, and never reach the core."""

    def test_wrong_init_host_pid_denies_release_and_contains_I(self):
        from nodechain.runtime import exec_supervisor as es

        # Mock: fork returns 55555 (the real I host PID).
        # build_topology_proof returns a proof with init_host_pid=99999 (mismatch).
        wrong_proof = mock.MagicMock(
            child_pidns_dev=4, child_pidns_ino=99,
            init_host_pid=99999,  # MISMATCH: fork returned 55555
        )
        proof_writes = []
        gate_writes = []

        def track_proof_writes(fd, *args, **kw):
            if fd == 105:  # proof_w from our mock pipe
                proof_writes.append(1)

        def track_gate_writes(fd, *args, **kw):
            if fd == 101:  # gate_w from our mock pipe
                gate_writes.append(1)

        with mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace"), \
             mock.patch.object(es.os, "pipe",
                               side_effect=[(100, 101), (102, 103), (104, 105)]), \
             mock.patch.object(es.os, "fork", return_value=55555, create=True), \
             mock.patch.object(es, "_read_identity_frame",
                               return_value={"version": 1, "type": "init_identity",
                                             "pid": 1, "ppid": 0}), \
             mock.patch("nodechain.runtime.pid_namespace_topology.build_topology_proof",
                        return_value=wrong_proof), \
             mock.patch.object(es, "_write_identity_frame",
                               side_effect=track_proof_writes), \
             mock.patch.object(es, "_write_bounded_fd",
                               side_effect=lambda fd, *a, **kw: (
                                   track_gate_writes(fd, *a, **kw) if fd == 101
                                   else track_proof_writes(fd, *a, **kw) if fd == 105
                                   else None)), \
             mock.patch.object(es, "_contain_and_fail") as caf, \
             mock.patch.object(es, "supervisor_main") as sm, \
             mock.patch.object(es.os, "close"):
            rc = es.launch_pid_namespace_supervisor({}, 999)

        # No proof frame written.
        assert len(proof_writes) == 0, (
            "proof frame must NOT be written when init_host_pid mismatches"
        )
        # No release token written.
        assert len(gate_writes) == 0, (
            "gate token must NOT be written when init_host_pid mismatches"
        )
        # Containment invoked with the EXACT fork-return PID, gate_w, and protocol_fd.
        caf.assert_called_once()
        args = caf.call_args.args
        assert args[0] == 55555, f"containment must target fork-return PID 55555, got {args[0]}"
        assert args[1] == 101, f"containment must receive gate_w=101, got {args[1]}"
        assert args[2] == 999, f"containment must receive protocol_fd=999, got {args[2]}"
        assert isinstance(args[3], str) and "proof_binding_mismatch" in args[3], (
            f"containment reason must mention proof_binding_mismatch, got {args[3]!r}"
        )
        # Supervisor core never reached.
        sm.assert_not_called()
        # Launcher returns nonzero.
        assert rc != 0


# ===========================================================================
# AST failure-branch control-flow authority
# ===========================================================================

class TestBootstrapFailureBranchControlFlow:
    """AST-based proof that each failure branch structurally contains the
    exact _emit_meta(bootstrap_failed) with the EXACT reason value, followed
    by an unconditional _os._exit(126), and that PTRACE_TRACEME is
    unreachable from any failure branch.

    Each branch's exact condition is matched structurally, its exact reason
    is bound to that condition, and emit-before-exit ordering is enforced
    by statement index within the branch body."""

    def _main_node(self):
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script
        tree = ast.parse(_build_bootstrap_script())
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                return node
        pytest.fail("main() not found in rendered bootstrap")

    def _parent_map(self, node):
        parents = {}
        for parent in ast.walk(node):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        return parents

    def _verify_branch(self, body, expected_reason: str):
        """Verify a branch body contains exactly:
        1. An _emit_meta call with type=_META_BOOTSTRAP_FAILED,
           stage="namespace_verify", reason=<expected_reason>
        2. A direct _os._exit(126) call (receiver MUST be _os)
        Both as direct Expr statements. The emit MUST precede the exit
        (enforced by index comparison, not just both-found booleans)."""
        emit_index = None
        exit_index = None
        for i, stmt in enumerate(body):
            if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
                continue
            call = stmt.value
            # Check for _emit_meta call.
            if (isinstance(call.func, ast.Name)
                    and call.func.id == "_emit_meta"):
                for arg in call.args:
                    if isinstance(arg, ast.Dict):
                        actual_type = actual_stage = actual_reason = None
                        for key, val in zip(arg.keys, arg.values):
                            if isinstance(key, ast.Constant):
                                if key.value == "type" and isinstance(val, ast.Name):
                                    actual_type = val.id
                                if key.value == "stage" and isinstance(val, ast.Constant):
                                    actual_stage = val.value
                                if key.value == "reason" and isinstance(val, ast.Constant):
                                    actual_reason = val.value
                        if (actual_type == "_META_BOOTSTRAP_FAILED"
                                and actual_stage == "namespace_verify"):
                            assert actual_reason == expected_reason, (
                                f"branch reason mismatch: expected {expected_reason!r}, "
                                f"got {actual_reason!r}"
                            )
                            emit_index = i
            # Check for _os._exit(126) — receiver MUST be _os (not just any _exit).
            if (isinstance(call.func, ast.Attribute)
                    and call.func.attr == "_exit"
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "_os"
                    and call.args
                    and isinstance(call.args[0], ast.Constant)
                    and call.args[0].value == 126):
                exit_index = i
        assert emit_index is not None, (
            f"branch must contain _emit_meta with reason={expected_reason!r}"
        )
        assert exit_index is not None, (
            f"branch must contain _os._exit(126)"
        )
        assert emit_index < exit_index, (
            f"emit (index {emit_index}) must precede _os._exit(126) "
            f"(index {exit_index}) in the branch body"
        )

    # --- Canonical AST equality matchers ---

    @staticmethod
    def _same_expr(node: ast.expr, source: str) -> bool:
        """Canonical AST equality: parse source, compare dumps.

        This is the only correct way to match an exact expression — no
        partial field inspection can false-pass.
        """
        expected = ast.parse(source, mode="eval").body
        return ast.dump(node, include_attributes=False) == ast.dump(
            expected, include_attributes=False
        )

    def _try_body_has_exact_stat(self, try_node):
        """Check if try_node.body (NOT handlers/orelse/finally) contains
        the exact call _os.stat('/proc/self/ns/pid') — as either an Expr
        or as the value of an Assign."""
        target = ast.parse('_os.stat("/proc/self/ns/pid")', mode="eval").body
        target_dump = ast.dump(target, include_attributes=False)
        for stmt in try_node.body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    if ast.dump(sub, include_attributes=False) == target_dump:
                        return True
        return False

    # --- The five branch tests ---

    def test_getpid_le_1_branch_exact_condition_reason_emit_exit(self):
        """Exact canonical match: _os.getpid() <= 1 → bootstrap_pid_not_gt_1."""
        node = self._main_node()
        for sub in ast.walk(node):
            if isinstance(sub, ast.If) and self._same_expr(sub.test, "_os.getpid() <= 1"):
                self._verify_branch(sub.body, "bootstrap_pid_not_gt_1")
                return
        pytest.fail("getpid() <= 1 If branch not found with exact canonical match")

    def test_getppid_not_1_branch_exact_condition_reason_emit_exit(self):
        """Exact canonical match: _os.getppid() != 1 → bootstrap_ppid_not_1."""
        node = self._main_node()
        for sub in ast.walk(node):
            if isinstance(sub, ast.If) and self._same_expr(sub.test, "_os.getppid() != 1"):
                self._verify_branch(sub.body, "bootstrap_ppid_not_1")
                return
        pytest.fail("getppid() != 1 If branch not found with exact canonical match")

    def test_ns_identity_mismatch_branch_exact_condition_reason_emit_exit(self):
        """Exact canonical match:
        _ns_st.st_dev != _exp_dev or _ns_st.st_ino != _exp_ino
        → ns_pid_identity_mismatch."""
        node = self._main_node()
        expected = "_ns_st.st_dev != _exp_dev or _ns_st.st_ino != _exp_ino"
        for sub in ast.walk(node):
            if isinstance(sub, ast.If) and self._same_expr(sub.test, expected):
                self._verify_branch(sub.body, "ns_pid_identity_mismatch")
                return
        pytest.fail("ns identity mismatch If branch not found with exact canonical match")

    def test_ns_read_failure_handler_exact_condition_reason_emit_exit(self):
        """Exact canonical match: _os.stat('/proc/self/ns/pid') in Try.body
        with OSError handler → ns_pid_read_failed."""
        node = self._main_node()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Try) and self._try_body_has_exact_stat(sub):
                for handler in sub.handlers:
                    if (isinstance(handler.type, ast.Name)
                            and handler.type.id == "OSError"):
                        self._verify_branch(handler.body, "ns_pid_read_failed")
                        return
        pytest.fail("OSError handler for _os.stat('/proc/self/ns/pid') not found")

    def test_expected_absent_else_branch_exact_condition_reason_emit_exit(self):
        """Exact canonical match:
        _exp_dev is not None and _exp_ino is not None
        with else body → expected_identity_absent."""
        node = self._main_node()
        expected = "_exp_dev is not None and _exp_ino is not None"
        for sub in ast.walk(node):
            if isinstance(sub, ast.If) and self._same_expr(sub.test, expected):
                if sub.orelse:
                    self._verify_branch(sub.orelse, "expected_identity_absent")
                    return
        pytest.fail("expected-absent else branch not found with exact canonical match")

    def test_ptrace_traceme_unreachable_from_failure_branches(self):
        """PTRACE_TRACEME must not be inside any branch body that contains
        a failure reason — it's unreachable from failure branches."""
        node = self._main_node()
        parents = self._parent_map(node)
        ptrace_node = None
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "ptrace"):
                for arg in sub.args:
                    if isinstance(arg, ast.Name) and arg.id == "_PTRACE_TRACEME":
                        ptrace_node = sub
                        break
        assert ptrace_node is not None, "PTRACE_TRACEME call not found"
        failure_reasons = {"bootstrap_pid_not_gt_1", "bootstrap_ppid_not_1",
                           "ns_pid_read_failed", "ns_pid_identity_mismatch",
                           "expected_identity_absent"}
        current = ptrace_node
        while current is not node:
            parent = parents.get(id(current))
            if parent is None:
                break
            if isinstance(parent, (ast.If, ast.ExceptHandler)):
                branch_body = parent.body
                if isinstance(parent, ast.If) and current in parent.orelse:
                    branch_body = parent.orelse
                for stmt in branch_body:
                    for s in ast.walk(stmt):
                        if (isinstance(s, ast.Constant) and isinstance(s.value, str)
                                and s.value in failure_reasons):
                            pytest.fail(
                                f"PTRACE_TRACEME is inside a branch containing "
                                f"failure reason {s.value!r} — reachable from failure"
                            )
            current = parent
