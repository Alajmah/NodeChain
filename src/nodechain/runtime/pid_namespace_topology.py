"""S3.2 Task 2: PID-namespace topology primitive and proof.

Standalone module providing the frozen proof type, the CLONE_NEWPID
unshare primitive, fail-closed ``/proc`` readers, and pure topology-proof
construction.

Scope (S3.2 Task 2 — narrow slice):

  * This module is imported by nothing in the supervised execution path.
  * It performs NO process creation, NO fork, NO setsid/setpgid.
  * The unshare primitive operates on the *calling* process only; it is
    the caller's responsibility (Task 3) to fork the namespace-init child
    afterward. Task 2 does not authorize that fork.
  * All ``/proc`` readers are fail-closed: malformed, missing, or
    inconsistent evidence raises a typed exception. No ``None`` fallback,
    no cached identity, no best-effort.

Platform contract:

  * Linux: full functionality via libc ``unshare`` and ``/proc`` reads.
  * Non-Linux: the module imports safely; invoking the unshare primitive
    raises :class:`PidNamespaceUnsupported`. ``/proc`` readers are not
    reachable on non-Linux in any authorized caller (the proof function
    requires a successful unshare first).

The proof type is EXACTLY the frozen ``PidNamespaceTopologyProof`` from
the locked S3.2 plan. Do not add optional fields or represent unknowns
with ``None``.
"""

from __future__ import annotations

import ctypes
import os
import platform
from dataclasses import dataclass

# linux/sched.h — CLONE_NEWPID. Matches namespace_profile.py:_CLONE_NEWPID.
_CLONE_NEWPID = 0x20000000


# ---------------------------------------------------------------------------
# Typed errors
# ---------------------------------------------------------------------------

class PidNamespaceError(Exception):
    """Base typed failure from the PID-namespace topology layer."""


class PidNamespaceUnsupported(PidNamespaceError):
    """The host platform or environment cannot create a PID namespace.

    Raised on non-Linux platforms, when libc cannot be loaded, or when
    ``unshare`` reports the kernel refuses the operation. No best-effort
    fallback: callers must treat this as a hard, fail-closed condition.
    """

    def __init__(self, reason: str, *, errno: int | None = None) -> None:
        self.reason = reason
        self.errno = errno
        super().__init__(reason)


class PidNamespaceProofError(PidNamespaceError):
    """A required topology relationship could not be proven.

    Raised when a ``/proc`` read fails, returns malformed evidence, or the
    captured identities do not satisfy the locked proof relationships. No
    partially populated proof object may escape — the proof function raises
    this before returning.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Frozen proof type — EXACTLY the locked S3.2 plan definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PidNamespaceTopologyProof:
    """Frozen topology proof captured by the trusted launcher.

    Every field is a positive integer or exact identity extracted from
    ``/proc``. There are no optional fields and no ``None`` sentinel — a
    proof object either exists fully populated or was never returned.

    Field semantics (see S3.2 plan §3, "Required topology proof"):

      ``launcher_host_pid``      — outer-visible PID of the launcher S
      ``launcher_host_pgid``     — outer-visible PGID of S
      ``init_host_pid``          — outer-visible PID of namespace-init I
      ``init_host_pgid``         — outer-visible PGID of I
      ``launcher_pidns_dev``     — st_dev of S's /proc/<S>/ns/pid
      ``launcher_pidns_ino``     — st_ino of S's /proc/<S>/ns/pid
      ``child_pidns_dev``        — st_dev of I's /proc/<I>/ns/pid
      ``child_pidns_ino``        — st_ino of I's /proc/<I>/ns/pid
      ``pid_for_children_dev``   — st_dev of S's /proc/<S>/ns/pid_for_children
      ``pid_for_children_ino``   — st_ino of S's /proc/<S>/ns/pid_for_children
      ``init_namespace_pid``     — final NSpid component of I (must be 1)
    """

    launcher_host_pid: int
    launcher_host_pgid: int
    init_host_pid: int
    init_host_pgid: int
    launcher_pidns_dev: int
    launcher_pidns_ino: int
    child_pidns_dev: int
    child_pidns_ino: int
    pid_for_children_dev: int
    pid_for_children_ino: int
    init_namespace_pid: int


# ---------------------------------------------------------------------------
# libc unshare primitive — lazy load, import-safe on non-Linux
# ---------------------------------------------------------------------------

# Lazy libc handle. Loaded on first call to ``unshare_pid_namespace``.
# Stays ``None`` on non-Linux or if libc cannot be loaded; the primitive
# raises ``PidNamespaceUnsupported`` in those cases rather than at import
# time, so the module is import-safe everywhere.
_libc: "ctypes.CDLL | None" = None
_libc_load_attempted = False
# Precise reason for libc-load failure (set by _load_libc). Used so the
# typed exception distinguishes "libc missing" from "unshare symbol missing".
_libc_load_reason: str | None = None


def _load_libc() -> "ctypes.CDLL | None":
    """Lazily load libc.so.6 and configure the unshare prototype.

    Returns the loaded CDLL or ``None`` if libc is unavailable. Cached
    after the first attempt. Never raises — failure is reported via the
    primitive's typed exception.
    """
    global _libc, _libc_load_attempted, _libc_load_reason
    if _libc_load_attempted:
        return _libc
    _libc_load_attempted = True
    _libc_load_reason = None
    if platform.system() != "Linux":
        return None
    try:
        lib = ctypes.CDLL("libc.so.6", use_errno=True)
        # Access the symbol BEFORE configuring it — if libc loads but the
        # `unshare` symbol is absent, `lib.unshare` raises AttributeError.
        # Catch it distinctly from CDLL load failure so the typed reason
        # is precise rather than conflated.
        unshare_sym = lib.unshare
        unshare_sym.argtypes = [ctypes.c_int]
        unshare_sym.restype = ctypes.c_int
        _libc = lib
    except OSError:
        _libc = None
        _libc_load_reason = "libc_unavailable"
    except AttributeError:
        # libc loaded but has no `unshare` symbol.
        _libc = None
        _libc_load_reason = "libc_unshare_symbol_unavailable"
    return _libc


def _libc_unavailable_reason() -> str:
    """Return the precise reason libc loading failed, for the typed exception."""
    # _libc_load_reason is set by _load_libc; default if not yet attempted.
    return _libc_load_reason if _libc_load_reason else "libc_unavailable"


def unshare_pid_namespace() -> None:
    """Call ``unshare(CLONE_NEWPID)`` in the calling process.

    This is the primitive the trusted launcher (Task 3) will call before
    forking the namespace-init child. It operates ONLY on the calling
    process's *future children* — the caller itself stays in its original
    PID namespace.

    Raises :class:`PidNamespaceUnsupported` on:
      * non-Linux platforms;
      * libc unavailable;
      * ``unshare`` returns nonzero (EPERM, EACCES, EINVAL, ENOSYS, ...).

    The exact errno is preserved on the exception's ``.errno`` attribute.
    No best-effort fallback, no silent skip.
    """
    lib = _load_libc()
    if lib is None:
        if platform.system() != "Linux":
            raise PidNamespaceUnsupported("pid_namespace_requires_linux")
        # Use the precise reason recorded by _load_libc so callers can
        # distinguish "libc missing" from "unshare symbol missing."
        raise PidNamespaceUnsupported(_libc_unavailable_reason())
    ctypes.set_errno(0)
    ret = lib.unshare(_CLONE_NEWPID)
    err = ctypes.get_errno()
    if ret != 0:
        # Kernel refused. Preserve the exact errno; fail closed.
        raise PidNamespaceUnsupported(
            f"unshare_clone_newpid_failed: errno={err}", errno=err
        )


# ---------------------------------------------------------------------------
# Fail-closed /proc readers
# ---------------------------------------------------------------------------

def _require_positivish_pid(pid: int) -> None:
    """Validate a PID is a plausible positive integer. Raises on invalid."""
    if not isinstance(pid, int) or isinstance(pid, bool):
        raise PidNamespaceProofError(f"pid must be int, got {type(pid).__name__}")
    if pid <= 0:
        raise PidNamespaceProofError(f"pid must be positive, got {pid}")


def read_pid_namespace(pid: int) -> tuple[int, int]:
    """Return ``(st_dev, st_ino)`` for ``/proc/<pid>/ns/pid``.

    Fail-closed: raises :class:`PidNamespaceProofError` on missing file,
    permission error, or any OSError. No ``None`` return, no caching.
    """
    _require_positivish_pid(pid)
    path = f"/proc/{pid}/ns/pid"
    try:
        st = os.stat(path)
    except OSError as e:
        raise PidNamespaceProofError(f"pid_namespace_read_failed: pid={pid} {e}") from e
    return (st.st_dev, st.st_ino)


def read_pid_for_children_namespace(pid: int) -> tuple[int, int]:
    """Return ``(st_dev, st_ino)`` for ``/proc/<pid>/ns/pid_for_children``.

    Fail-closed. Note: this read is meaningful ONLY after the process has
    forked its first child in the new PID namespace (Linux materializes
    the symlink then). Reading it before the first child exists is
    documented to return a dangling link; callers must ensure the
    lifecycle ordering.
    """
    _require_positivish_pid(pid)
    path = f"/proc/{pid}/ns/pid_for_children"
    try:
        st = os.stat(path)
    except OSError as e:
        raise PidNamespaceProofError(
            f"pid_for_children_read_failed: pid={pid} {e}"
        ) from e
    return (st.st_dev, st.st_ino)


def read_nspid_chain(pid: int) -> list[int]:
    """Parse the NSpid chain from ``/proc/<pid>/status``.

    Returns the list of namespace PIDs from outermost to innermost (the
    last element is the in-namespace PID).

    Fail-closed contract — the locked requirement is ONE nonempty,
    integer-only, all-positive chain. This parser rejects:

      * missing or unreadable ``/proc/<pid>/status``;
      * no ``NSpid:`` line at all;
      * MORE than one ``NSpid:`` line (conflicting evidence);
      * empty chain (``NSpid:`` with no numbers);
      * any non-canonical-integer component (non-numeric, leading +, etc.);
      * any non-positive component (zero or negative — PIDs are > 0).

    No silently-ignored duplicate, no partial acceptance.
    """
    _require_positivish_pid(pid)
    path = f"/proc/{pid}/status"
    try:
        with open(path, "r") as f:
            text = f.read()
    except OSError as e:
        raise PidNamespaceProofError(f"status_read_failed: pid={pid} {e}") from e
    # Collect ALL NSpid lines — exactly one is required.
    nspid_lines = [ln for ln in text.splitlines() if ln.startswith("NSpid:")]
    if not nspid_lines:
        raise PidNamespaceProofError(f"nspid_line_missing: pid={pid}")
    if len(nspid_lines) > 1:
        # Conflicting chains — do not silently pick the first.
        raise PidNamespaceProofError(
            f"nspid_duplicate_lines: pid={pid} count={len(nspid_lines)}"
        )
    parts = nspid_lines[0].split()[1:]
    if not parts:
        raise PidNamespaceProofError(f"nspid_empty: pid={pid}")
    nums: list[int] = []
    for p in parts:
        # Require a CANONICAL ASCII positive decimal. str.isdigit() is
        # insufficient — it accepts Unicode digit forms ("²", "١", "１")
        # some of which int() then rejects (untyped ValueError escaping
        # the typed surface) and some of which int() silently accepts as
        # non-canonical integers. An explicit ASCII byte-range check is
        # the only predicate that matches what /proc actually emits.
        if not p or any(ch < "0" or ch > "9" for ch in p):
            raise PidNamespaceProofError(
                f"nspid_non_integer: pid={pid} component={p!r}"
            )
        try:
            n = int(p)
        except ValueError as e:
            # Defensive: the ASCII check above should make this unreachable,
            # but if int() somehow disagrees, fail through the typed surface
            # rather than letting a raw ValueError escape.
            raise PidNamespaceProofError(
                f"nspid_non_integer: pid={pid} component={p!r}"
            ) from e
        if n <= 0:
            # Guards against "0" specifically (zero is not a valid PID).
            # Negative is already rejected by the ASCII range check.
            raise PidNamespaceProofError(
                f"nspid_non_positive: pid={pid} component={p!r}"
            )
        nums.append(n)
    return nums


def read_host_pgid(pid: int) -> int:
    """Return the host-visible PGID of ``pid`` via ``os.getpgid``.

    Fail-closed: raises on OSError (process gone, permission denied).
    """
    _require_positivish_pid(pid)
    try:
        return os.getpgid(pid)
    except OSError as e:
        raise PidNamespaceProofError(f"pgid_read_failed: pid={pid} {e}") from e


# ---------------------------------------------------------------------------
# Pure topology proof construction
# ---------------------------------------------------------------------------

def build_topology_proof(launcher_pid: int, init_pid: int) -> PidNamespaceTopologyProof:
    """Construct the frozen topology proof from outer ``/proc`` reads.

    Pure: performs NO process creation, NO fork, NO signal. Reads the
    required ``/proc`` entries for the launcher and the namespace-init,
    validates every locked relationship, and returns the populated proof.

    Caller responsibility (Task 3): ``init_pid`` must have been forked by
    ``launcher_pid`` after ``unshare_pid_namespace()`` and must remain
    blocked (alive) for the duration of this call. This function does not
    itself prove liveness — the reads will fail closed if init has exited.

    Locked relationships (all must hold; any mismatch raises
    :class:`PidNamespaceProofError`):

      * launcher current pid namespace != child pid namespace
      * launcher pid_for_children == child pid namespace
      * init /proc pid namespace == child pid namespace
      * init NSpid first component == init_host_pid
      * init NSpid final component == 1
      * launcher PGID == launcher host PID (session-leader invariant)
      * init PGID == launcher PGID (shared host process group)

    A ``getppid()==0`` namespace-local check is NOT performed here: that
    is a Task 3 runtime/protocol proof, not derivable from outer /proc.

    No partially populated proof object may escape — on any failure the
    exception is raised before the ``return``.
    """
    _require_positivish_pid(launcher_pid)
    _require_positivish_pid(init_pid)

    # --- Capture all identities first (any read failure -> proof fails). ---
    launcher_pid_ns = read_pid_namespace(launcher_pid)
    launcher_pidfc = read_pid_for_children_namespace(launcher_pid)
    init_pid_ns = read_pid_namespace(init_pid)
    init_nspid = read_nspid_chain(init_pid)
    launcher_pgid = read_host_pgid(launcher_pid)
    init_pgid = read_host_pgid(init_pid)

    # --- Validate every locked relationship. ---
    if launcher_pid_ns == init_pid_ns:
        raise PidNamespaceProofError(
            f"launcher_pidns_equals_child: launcher={launcher_pid_ns} "
            f"init={init_pid_ns} (must differ)"
        )
    if launcher_pidfc != init_pid_ns:
        raise PidNamespaceProofError(
            f"pid_for_children_mismatch: launcher_pidfc={launcher_pidfc} "
            f"init_pidns={init_pid_ns} (must match)"
        )
    # init's /proc pid namespace is init_pid_ns by construction (read above),
    # but the relationship is stated for clarity: it must equal child ns.
    # (init_pid_ns == launcher_pidfc already proven above implies this.)
    if not init_nspid:
        raise PidNamespaceProofError("init_nspid_empty")
    if init_nspid[0] != init_pid:
        raise PidNamespaceProofError(
            f"nspid_outer_mismatch: first={init_nspid[0]} "
            f"expected_init_pid={init_pid}"
        )
    if init_nspid[-1] != 1:
        raise PidNamespaceProofError(
            f"init_namespace_pid_not_1: final={init_nspid[-1]} (must be 1)"
        )
    if launcher_pgid != launcher_pid:
        raise PidNamespaceProofError(
            f"launcher_not_session_leader: pid={launcher_pid} "
            f"pgid={launcher_pgid} (must be equal)"
        )
    if init_pgid != launcher_pgid:
        raise PidNamespaceProofError(
            f"init_pgid_diverges: init_pgid={init_pgid} "
            f"launcher_pgid={launcher_pgid} (must match)"
        )

    # --- All relationships hold: return the fully-populated frozen proof. ---
    return PidNamespaceTopologyProof(
        launcher_host_pid=launcher_pid,
        launcher_host_pgid=launcher_pgid,
        init_host_pid=init_pid,
        init_host_pgid=init_pgid,
        launcher_pidns_dev=launcher_pid_ns[0],
        launcher_pidns_ino=launcher_pid_ns[1],
        child_pidns_dev=init_pid_ns[0],
        child_pidns_ino=init_pid_ns[1],
        pid_for_children_dev=launcher_pidfc[0],
        pid_for_children_ino=launcher_pidfc[1],
        init_namespace_pid=init_nspid[-1],
    )


__all__ = [
    "PidNamespaceTopologyProof",
    "PidNamespaceError",
    "PidNamespaceUnsupported",
    "PidNamespaceProofError",
    "unshare_pid_namespace",
    "read_pid_namespace",
    "read_pid_for_children_namespace",
    "read_nspid_chain",
    "read_host_pgid",
    "build_topology_proof",
]
