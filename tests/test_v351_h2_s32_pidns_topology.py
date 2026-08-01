"""S3.2 Task 2: unit tests for pid_namespace_topology.py.

Deterministic, mocked system boundaries. Do NOT call real
``unshare(CLONE_NEWPID)`` in this pytest process — every syscall surface
(``os.stat``, ``os.getpgid``, ``open``, ``ctypes.CDLL``, ``platform.system``)
is patched where the test needs to control it.

Covers the 18 required cases from the Task 2 authorization.
"""

from __future__ import annotations

import dataclasses
import platform
from unittest import mock

import pytest

from nodechain.runtime.pid_namespace_topology import (
    PidNamespaceProofError,
    PidNamespaceTopologyProof,
    PidNamespaceUnsupported,
    build_topology_proof,
    read_host_pgid,
    read_nspid_chain,
    read_pid_for_children_namespace,
    read_pid_namespace,
    unshare_pid_namespace,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_stat_result(dev: int, ino: int):
    """Build a minimal stand-in for os.stat_result with st_dev/st_ino."""
    return mock.MagicMock(st_dev=dev, st_ino=ino)


def _patch_proc(*, ns_pid: dict, ns_pidfc: dict, status_text: str, stat_side_effect=None):
    """Build a patcher for os.stat + open that yields the given /proc data.

    ns_pid:    {pid: (dev, ino)} for /proc/<pid>/ns/pid
    ns_pidfc:  {pid: (dev, ino)} for /proc/<pid>/ns/pid_for_children
    status_text: full /proc/<pid>/status text returned for every pid
    """
    def fake_stat(path):
        if stat_side_effect is not None:
            err = stat_side_effect(path)
            if err is not None:
                raise err
        if path.endswith("/ns/pid"):
            for pid, ident in ns_pid.items():
                if path == f"/proc/{pid}/ns/pid":
                    return _fake_stat_result(*ident)
        if path.endswith("/ns/pid_for_children"):
            for pid, ident in ns_pidfc.items():
                if path == f"/proc/{pid}/ns/pid_for_children":
                    return _fake_stat_result(*ident)
        raise FileNotFoundError(path)
    return fake_stat


VALID_PID_NS = (4, 4026533624)        # child namespace
VALID_LAUNCHER_PID_NS = (4, 4026535412)  # launcher original namespace
VALID_LAUNCHER_PIDFC = VALID_PID_NS   # matches child (post-fork)


def _valid_status_text(init_pid: int, final_nspid: int = 1):
    return (
        "Name:\ttest\n"
        "Umask:\t0022\n"
        f"Pid:\t{init_pid}\n"
        f"NSpid:\t{init_pid}\t{final_nspid}\n"
    )


def _valid_topology_mocks(launcher_pid=1000, init_pid=1001):
    """Return a dict of mock side-effects that satisfy all proof relationships."""
    return {
        "ns_pid": {launcher_pid: VALID_LAUNCHER_PID_NS, init_pid: VALID_PID_NS},
        "ns_pidfc": {launcher_pid: VALID_LAUNCHER_PIDFC},
        "status_text": _valid_status_text(init_pid, final_nspid=1),
        "launcher_pgid": launcher_pid,  # session leader
        "init_pgid": launcher_pid,       # same group
    }


# ===========================================================================
# 1. Valid topology → exact frozen proof
# ===========================================================================

def test_valid_topology_produces_exact_frozen_proof():
    """Case 1: a fully-correct topology produces a populated frozen proof
    with every required field and no extras."""
    launcher_pid, init_pid = 1000, 1001
    topo = _valid_topology_mocks(launcher_pid, init_pid)
    fake_stat = _patch_proc(
        ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
        status_text=topo["status_text"],
    )
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=topo["status_text"])), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, side_effect=lambda p: {
             launcher_pid: topo["launcher_pgid"],
             init_pid: topo["init_pgid"],
         }[p]):
        proof = build_topology_proof(launcher_pid, init_pid)
    # Every required field populated, exact values.
    assert proof.launcher_host_pid == launcher_pid
    assert proof.launcher_host_pgid == launcher_pid
    assert proof.init_host_pid == init_pid
    assert proof.init_host_pgid == launcher_pid
    assert proof.launcher_pidns_dev == VALID_LAUNCHER_PID_NS[0]
    assert proof.launcher_pidns_ino == VALID_LAUNCHER_PID_NS[1]
    assert proof.child_pidns_dev == VALID_PID_NS[0]
    assert proof.child_pidns_ino == VALID_PID_NS[1]
    assert proof.pid_for_children_dev == VALID_PID_NS[0]
    assert proof.pid_for_children_ino == VALID_PID_NS[1]
    assert proof.init_namespace_pid == 1
    # Exactly 11 fields — no optional extras.
    assert len(dataclasses.fields(proof)) == 11


# ===========================================================================
# 2. Non-Linux invocation
# ===========================================================================

def test_unshare_non_linux_raises_unsupported():
    """Case 2: invoking unshare on non-Linux raises PidNamespaceUnsupported."""
    # Reset the lazy libc cache so the platform check is re-evaluated.
    import nodechain.runtime.pid_namespace_topology as mod
    with mock.patch.object(mod, "_libc", None), \
         mock.patch.object(mod, "_libc_load_attempted", False), \
         mock.patch("platform.system", return_value="Windows"):
        with pytest.raises(PidNamespaceUnsupported) as ei:
            unshare_pid_namespace()
    assert "linux" in ei.value.reason


# ===========================================================================
# 3. libc unavailable
# ===========================================================================

def test_unshare_libc_unavailable_raises_unsupported():
    """Case 3: libc load failure raises PidNamespaceUnsupported."""
    import nodechain.runtime.pid_namespace_topology as mod
    original_cdll = ctypes.CDLL if False else None  # placeholder
    with mock.patch.object(mod, "_libc", None), \
         mock.patch.object(mod, "_libc_load_attempted", False), \
         mock.patch("platform.system", return_value="Linux"), \
         mock.patch("ctypes.CDLL", side_effect=OSError("no libc")):
        with pytest.raises(PidNamespaceUnsupported) as ei:
            unshare_pid_namespace()
    assert "libc" in ei.value.reason


# ===========================================================================
# 4. unshare failure + preserved errno
# ===========================================================================

def test_unshare_failure_preserves_errno():
    """Case 4: when libc.unshare returns nonzero, the typed exception
    carries the exact errno."""
    import nodechain.runtime.pid_namespace_topology as mod
    fake_libc = mock.MagicMock()
    fake_libc.unshare.return_value = -1
    # Simulate the kernel setting errno to EPERM (1).
    def fake_unshare(_flags):
        ctypes.set_errno(1)
        return -1
    fake_libc.unshare.side_effect = fake_unshare
    fake_libc.unshare.argtypes = []
    fake_libc.unshare.restype = ctypes.c_int
    with mock.patch.object(mod, "_libc", fake_libc), \
         mock.patch.object(mod, "_libc_load_attempted", True), \
         mock.patch("platform.system", return_value="Linux"):
        ctypes.set_errno(0)
        with pytest.raises(PidNamespaceUnsupported) as ei:
            unshare_pid_namespace()
    assert ei.value.errno == 1


def test_unshare_success_returns_none():
    """Supplemental: successful unshare returns None (no exception)."""
    import nodechain.runtime.pid_namespace_topology as mod
    fake_libc = mock.MagicMock()
    fake_libc.unshare.return_value = 0
    fake_libc.unshare.argtypes = []
    fake_libc.unshare.restype = ctypes.c_int
    with mock.patch.object(mod, "_libc", fake_libc), \
         mock.patch.object(mod, "_libc_load_attempted", True), \
         mock.patch("platform.system", return_value="Linux"):
        assert unshare_pid_namespace() is None


# ===========================================================================
# 5. Invalid PID
# ===========================================================================

@pytest.mark.parametrize("bad_pid", [0, -1, -100])
def test_invalid_pid_raises_proof_error(bad_pid):
    """Case 5: non-positive PIDs are rejected at the reader entry."""
    with pytest.raises(PidNamespaceProofError, match="must be positive"):
        read_pid_namespace(bad_pid)
    with pytest.raises(PidNamespaceProofError, match="must be positive"):
        read_pid_for_children_namespace(bad_pid)
    with pytest.raises(PidNamespaceProofError, match="must be positive"):
        read_host_pgid(bad_pid)


def test_non_int_pid_raises_proof_error():
    """Supplemental: non-int PID (e.g. bool) is rejected."""
    with pytest.raises(PidNamespaceProofError, match="must be int"):
        read_pid_namespace(True)  # type: ignore[arg-type]


# ===========================================================================
# 6. Missing pid namespace
# ===========================================================================

def test_missing_pid_namespace_raises_proof_error():
    """Case 6: /proc/<pid>/ns/pid absent -> typed proof failure."""
    def stat_missing(path):
        if path == "/proc/1234/ns/pid":
            raise FileNotFoundError(2, "No such file", path)
        return _fake_stat_result(4, 99)
    with mock.patch("os.stat", side_effect=stat_missing):
        with pytest.raises(PidNamespaceProofError, match="pid_namespace_read_failed"):
            read_pid_namespace(1234)


# ===========================================================================
# 7. Missing pid_for_children
# ===========================================================================

def test_missing_pid_for_children_raises_proof_error():
    """Case 7: /proc/<pid>/ns/pid_for_children absent -> typed failure."""
    def stat_missing(path):
        if path == "/proc/1234/ns/pid_for_children":
            raise FileNotFoundError(2, "No such file", path)
        return _fake_stat_result(4, 99)
    with mock.patch("os.stat", side_effect=stat_missing):
        with pytest.raises(PidNamespaceProofError, match="pid_for_children_read_failed"):
            read_pid_for_children_namespace(1234)


# ===========================================================================
# 8. Malformed / empty / missing NSpid
# ===========================================================================

def test_malformed_nspid_non_integer_raises():
    """Case 8a: NSpid line with non-integer component -> typed failure."""
    status = "NSpid:\t1000\tnot_an_int\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_non_integer"):
            read_nspid_chain(1000)


def test_empty_nspid_raises():
    """Case 8b: NSpid header present but no numbers -> typed failure."""
    status = "NSpid:\t\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_empty"):
            read_nspid_chain(1000)


def test_missing_nspid_line_raises():
    """Case 8c: /proc/<pid>/status with no NSpid line at all -> typed failure."""
    status = "Name:\ttest\nPid:\t1000\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_line_missing"):
            read_nspid_chain(1000)


def test_status_file_missing_raises():
    """Supplemental: /proc/<pid>/status absent -> typed failure."""
    with mock.patch("builtins.open", side_effect=FileNotFoundError(2, "No such file")):
        with pytest.raises(PidNamespaceProofError, match="status_read_failed"):
            read_nspid_chain(1000)


def test_duplicate_nspid_lines_raises():
    """Stricter parser: two conflicting NSpid lines -> typed failure
    (do not silently pick the first)."""
    status = "NSpid:\t1001\t1\nNSpid:\t9999\t5\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_duplicate_lines"):
            read_nspid_chain(1001)


def test_zero_nspid_component_raises():
    """Stricter parser: a zero component is not a valid PID -> typed failure."""
    status = "NSpid:\t1001\t0\t1\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_non_positive"):
            read_nspid_chain(1001)


def test_negative_nspid_component_raises():
    """Stricter parser: a negative component is rejected (isdigit catches
    the leading '-', so it surfaces as nspid_non_integer)."""
    status = "NSpid:\t1001\t-1\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_non_integer"):
            read_nspid_chain(1001)


def test_valid_nested_positive_chain_accepted():
    """Stricter parser: a valid multi-level positive chain parses cleanly."""
    status = "NSpid:\t1001\t5\t1\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        chain = read_nspid_chain(1001)
    assert chain == [1001, 5, 1]


# --- Canonical ASCII-decimal validation (isdigit() was insufficient) -----

@pytest.mark.parametrize("label,unicode_digit", [
    ("superscript", "\u00b2"),     # ² — isdigit() True, int() raises ValueError
    ("arabic_indic", "\u0661"),    # ١ — isdigit() True, int() accepts (non-ASCII)
    ("full_width", "\uff11"),      # １ — isdigit() True, int() accepts (non-ASCII)
])
def test_unicode_digit_nspid_component_rejected(label, unicode_digit):
    """Canonical-ASCII parser: non-ASCII digit forms are rejected as
    nspid_non_integer, NOT accepted silently and NOT allowed to raise
    an untyped ValueError out of int()."""
    status = f"NSpid:\t1001\t{unicode_digit}\t1\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        with pytest.raises(PidNamespaceProofError, match="nspid_non_integer"):
            read_nspid_chain(1001)


def test_ordinary_ascii_nspid_accepted():
    """Canonical-ASCII parser: ordinary ASCII digits still parse cleanly
    (the stricter check must not over-reject valid /proc evidence)."""
    status = "NSpid:\t1001\t5\t1\n"
    with mock.patch("builtins.open", mock.mock_open(read_data=status)):
        chain = read_nspid_chain(1001)
    assert chain == [1001, 5, 1]


def test_unshare_symbol_unavailable_raises_unsupported():
    """Correction #1: libc loads but has no `unshare` symbol -> typed
    PidNamespaceUnsupported (NOT raw AttributeError), with a precise
    reason distinguishing symbol-absence from load-failure."""
    import nodechain.runtime.pid_namespace_topology as mod

    # A fake CDLL that loads successfully but has NO `unshare` attribute.
    class FakeLibcNoUnshare:
        pass

    with mock.patch.object(mod, "_libc", None), \
         mock.patch.object(mod, "_libc_load_attempted", False), \
         mock.patch.object(mod, "_libc_load_reason", None), \
         mock.patch("platform.system", return_value="Linux"), \
         mock.patch("ctypes.CDLL", return_value=FakeLibcNoUnshare()):
        with pytest.raises(PidNamespaceUnsupported) as ei:
            unshare_pid_namespace()
    # Precise reason — NOT the generic "libc_unavailable".
    assert ei.value.reason == "libc_unshare_symbol_unavailable"


def test_libc_load_failure_reason_is_distinct():
    """Supplemental: when CDLL itself raises OSError, the reason is
    'libc_unavailable' (distinct from symbol-unavailable)."""
    import nodechain.runtime.pid_namespace_topology as mod
    with mock.patch.object(mod, "_libc", None), \
         mock.patch.object(mod, "_libc_load_attempted", False), \
         mock.patch.object(mod, "_libc_load_reason", None), \
         mock.patch("platform.system", return_value="Linux"), \
         mock.patch("ctypes.CDLL", side_effect=OSError("no libc")):
        with pytest.raises(PidNamespaceUnsupported) as ei:
            unshare_pid_namespace()
    assert ei.value.reason == "libc_unavailable"


# ===========================================================================
# 9. Launcher namespace equals child namespace
# ===========================================================================

def test_launcher_namespace_equals_child_raises():
    """Case 9: launcher pid ns == init pid ns -> proof failure."""
    same_ns = (4, 4026535412)
    topo = _valid_topology_mocks(1000, 1001)
    # Override: launcher AND init in the SAME namespace.
    topo["ns_pid"] = {1000: same_ns, 1001: same_ns}
    topo["ns_pidfc"] = {1000: same_ns}
    fake_stat = _patch_proc(ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
                            status_text=topo["status_text"])
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=topo["status_text"])), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, return_value=1000):
        with pytest.raises(PidNamespaceProofError, match="launcher_pidns_equals_child"):
            build_topology_proof(1000, 1001)


# ===========================================================================
# 10. pid_for_children mismatch
# ===========================================================================

def test_pid_for_children_mismatch_raises():
    """Case 10: launcher pid_for_children != init pid ns -> proof failure."""
    other_ns = (4, 99999999)
    topo = _valid_topology_mocks(1000, 1001)
    # Override: pid_for_children points at a DIFFERENT namespace than init.
    topo["ns_pidfc"] = {1000: other_ns}
    fake_stat = _patch_proc(ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
                            status_text=topo["status_text"])
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=topo["status_text"])), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, return_value=1000):
        with pytest.raises(PidNamespaceProofError, match="pid_for_children_mismatch"):
            build_topology_proof(1000, 1001)


# ===========================================================================
# 11. init namespace mismatch (init's /proc ns alone is wrong)
# ===========================================================================

def test_init_namespace_mismatch_raises():
    """Case 11 (independent): launcher pid_for_children is VALID, but
    init's own /proc ns read disagrees with it.

    NOT the same as case 10 (pid_for_children mismatch). Here:
      * launcher current ns       = original (valid)
      * launcher pid_for_children = intended child ns (valid internally)
      * init /proc ns             = a DIFFERENT, third namespace

    The proof rejects because init's ns != launcher pid_for_children,
    proving init's /proc read is independently authoritative.
    """
    launcher_pid, init_pid = 1000, 1001
    intended_child_ns = VALID_PID_NS        # what launcher pid_for_children says
    wrong_init_ns = (4, 55555555)            # init is in a DIFFERENT ns

    def fake_stat(path):
        if path == f"/proc/{launcher_pid}/ns/pid":
            return _fake_stat_result(*VALID_LAUNCHER_PID_NS)
        if path == f"/proc/{init_pid}/ns/pid":
            return _fake_stat_result(*wrong_init_ns)
        if path == f"/proc/{launcher_pid}/ns/pid_for_children":
            return _fake_stat_result(*intended_child_ns)
        raise FileNotFoundError(path)
    status = _valid_status_text(init_pid, final_nspid=1)
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=status)), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True,
                    return_value=launcher_pid):
        with pytest.raises(PidNamespaceProofError, match="pid_for_children_mismatch"):
            build_topology_proof(launcher_pid, init_pid)


# ===========================================================================
# 12. NSpid outer PID mismatch
# ===========================================================================

def test_nspid_outer_pid_mismatch_raises():
    """Case 12: init NSpid first component != init_host_pid -> proof failure."""
    launcher_pid, init_pid = 1000, 1001
    topo = _valid_topology_mocks(launcher_pid, init_pid)
    # NSpid claims outer PID 9999, but caller passed init_pid=1001.
    status = _valid_status_text(9999, final_nspid=1)
    fake_stat = _patch_proc(ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
                            status_text=status)
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=status)), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, return_value=launcher_pid):
        with pytest.raises(PidNamespaceProofError, match="nspid_outer_mismatch"):
            build_topology_proof(launcher_pid, init_pid)


# ===========================================================================
# 13. init namespace PID != 1
# ===========================================================================

def test_init_namespace_pid_not_1_raises():
    """Case 13: init NSpid final component != 1 -> proof failure."""
    launcher_pid, init_pid = 1000, 1001
    topo = _valid_topology_mocks(launcher_pid, init_pid)
    status = _valid_status_text(init_pid, final_nspid=2)  # not namespace PID 1
    fake_stat = _patch_proc(ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
                            status_text=status)
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=status)), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, return_value=launcher_pid):
        with pytest.raises(PidNamespaceProofError, match="init_namespace_pid_not_1"):
            build_topology_proof(launcher_pid, init_pid)


# ===========================================================================
# 14. launcher PID != launcher PGID
# ===========================================================================

def test_launcher_pid_not_pgid_raises():
    """Case 14: launcher PGID != launcher PID -> not a session leader."""
    launcher_pid, init_pid = 1000, 1001
    topo = _valid_topology_mocks(launcher_pid, init_pid)
    fake_stat = _patch_proc(ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
                            status_text=topo["status_text"])
    # launcher PGID (5555) != launcher PID (1000).
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=topo["status_text"])), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, side_effect=lambda p: 5555 if p == launcher_pid else launcher_pid):
        with pytest.raises(PidNamespaceProofError, match="launcher_not_session_leader"):
            build_topology_proof(launcher_pid, init_pid)


# ===========================================================================
# 15. init PGID differs from launcher PGID
# ===========================================================================

def test_init_pgid_differs_from_launcher_raises():
    """Case 15: init PGID != launcher PGID -> separate process groups."""
    launcher_pid, init_pid = 1000, 1001
    topo = _valid_topology_mocks(launcher_pid, init_pid)
    fake_stat = _patch_proc(ns_pid=topo["ns_pid"], ns_pidfc=topo["ns_pidfc"],
                            status_text=topo["status_text"])
    # launcher PGID == launcher PID (OK), but init PGID is different (7777).
    def getpgid(p):
        if p == launcher_pid:
            return launcher_pid
        return 7777
    with mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=topo["status_text"])), \
         mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, side_effect=getpgid):
        with pytest.raises(PidNamespaceProofError, match="init_pgid_diverges"):
            build_topology_proof(launcher_pid, init_pid)


# ===========================================================================
# 16. Proof immutability
# ===========================================================================

def test_proof_is_immutable():
    """Case 16: the frozen dataclass cannot be mutated."""
    proof = PidNamespaceTopologyProof(
        launcher_host_pid=1, launcher_host_pgid=1,
        init_host_pid=2, init_host_pgid=1,
        launcher_pidns_dev=4, launcher_pidns_ino=10,
        child_pidns_dev=4, child_pidns_ino=20,
        pid_for_children_dev=4, pid_for_children_ino=20,
        init_namespace_pid=1,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.launcher_host_pid = 999  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.init_namespace_pid = 2  # type: ignore[misc]


# ===========================================================================
# 17. Module import safety (non-Linux)
# ===========================================================================

def test_module_import_safe_on_non_linux():
    """Case 17: the module imports without error regardless of platform.

    Importing must NOT raise on non-Linux. Only invoking the primitive
    fails closed. This test runs on the current host (whatever it is) and
    confirms the import side-effect-free contract by re-importing.

    IMPORTANT: must preserve the original module in sys.modules after
    re-import so downstream tests that reference pid_namespace_topology's
    class objects (e.g. PidNamespaceUnsupported) don't get a stale class
    reference that breaks isinstance checks."""
    import importlib
    import sys
    mod_name = "nodechain.runtime.pid_namespace_topology"
    original_mod = sys.modules.get(mod_name)
    # Drop from cache and re-import to exercise the module top-level again.
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    # Should not raise on any platform.
    mod = importlib.import_module(mod_name)
    assert hasattr(mod, "PidNamespaceTopologyProof")
    assert hasattr(mod, "unshare_pid_namespace")
    # Restore the ORIGINAL module so downstream tests keep their class references.
    # The re-import validated the import safety; we must not leave a new module
    # object that creates divergent class identities.
    if original_mod is not None:
        sys.modules[mod_name] = original_mod
    assert hasattr(mod, "PidNamespaceTopologyProof")
    assert hasattr(mod, "unshare_pid_namespace")


# ===========================================================================
# Supplemental: getpgid OSError surfaces as typed proof error
# ===========================================================================

def test_getpgid_oserror_raises_proof_error():
    """Supplemental: process gone / permission denied on getpgid -> typed."""
    with mock.patch("nodechain.runtime.pid_namespace_topology.os.getpgid", create=True, side_effect=ProcessLookupError(3, "No such process")):
        with pytest.raises(PidNamespaceProofError, match="pgid_read_failed"):
            read_host_pgid(1234)


# Need ctypes import for case 4 helper
import ctypes  # noqa: E402
