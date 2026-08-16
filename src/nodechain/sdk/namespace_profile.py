"""Linux namespace profile — detection and capability reporting.

v1.4.0: Adds namespace confinement as a sandbox enforcement layer.
Network namespace is the primary enforcement target: creating a new
network namespace with no interfaces makes network access physically
impossible at the kernel level.

Detection uses /proc/self/ns/ symlinks and trial unshare in subprocess.
Enforcement uses os.unshare(CLONE_NEWNET) in the child process bootstrap.

Platform support:
  - Linux: full detection + network namespace enforcement (Python 3.12+)
  - Linux < 3.12: detection only (ctypes fallback available but not used)
  - Windows/macOS: not available (detection_only)
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ─── Constants ───────────────────────────────────────────────────────────

# From linux/sched.h
_CLONE_NEWNS = 0x00020000    # Mount namespace
_CLONE_NEWUTS = 0x04000000   # UTS namespace
_CLONE_NEWIPC = 0x08000000   # IPC namespace
_CLONE_NEWPID = 0x20000000   # PID namespace
_CLONE_NEWNET = 0x40000000   # Network namespace
_CLONE_NEWUSER = 0x10000000  # User namespace

_NS_TYPES = {
    "mount": _CLONE_NEWNS,
    "uts": _CLONE_NEWUTS,
    "ipc": _CLONE_NEWIPC,
    "pid": _CLONE_NEWPID,
    "network": _CLONE_NEWNET,
    "user": _CLONE_NEWUSER,
}


@dataclass
class NamespaceCapabilities:
    """Namespace detection results for the current platform."""

    namespace_available: bool = False
    """True if any namespace creation is possible on this platform."""

    namespace_mode: str = "none"
    """Detection mode: none | detected | nested | created"""

    already_nested: bool = False
    """True if the process is already running inside a container namespace."""

    namespace_creation_allowed: bool = False
    """True if the process can create new namespaces (unshare)."""

    mount_namespace_available: bool = False
    pid_namespace_available: bool = False
    network_namespace_available: bool = False
    user_namespace_available: bool = False
    uts_namespace_available: bool = False
    ipc_namespace_available: bool = False

    network_namespace_enforced: bool = False
    """True if network namespace enforcement is active for this run."""

    backend_name: str = "none"
    """Backend: none | linux_namespace | detection_only"""

    platform: str = ""
    """Platform string: Linux | Windows | Darwin"""

    max_user_namespaces: int = 0
    """Max user namespaces from /proc/sys/user/max_user_namespaces (0 = N/A)"""


def detect_namespaces() -> NamespaceCapabilities:
    """Detect namespace capabilities on the current platform.

    On Linux:
    1. Checks if we are already in a container (nested namespaces)
    2. Tests if namespace creation is allowed via trial unshare
    3. Reports per-type availability

    On Windows/macOS:
    Returns namespace_available=False with detection_only mode.
    """
    caps = NamespaceCapabilities()
    caps.platform = platform.system()

    if caps.platform != "Linux":
        caps.namespace_mode = "none"
        caps.backend_name = "none"
        return caps

    # ── Check if already in a container namespace ──
    # In containers, /proc/self/ns/user often points to the host userns
    # (inode 4026531837) while other namespaces have container-specific inodes
    try:
        ns_dir = Path("/proc/self/ns")
        if ns_dir.exists():
            user_ns = (ns_dir / "user").resolve()
            # The host/initial user namespace has a well-known inode number
            # 4026531837 is the default for the initial user namespace
            user_ns_inum = str(user_ns).split("[")[-1].rstrip("]") if "[" in str(user_ns) else ""
            # Check if mount/pid/net namespaces differ from host defaults
            mnt_ns = (ns_dir / "mnt").resolve()
            pid_ns = (ns_dir / "pid").resolve()
            net_ns = (ns_dir / "net").resolve()

            # If mount/pid/net inodes are > 4026533000, we're likely in a container
            # (host defaults are typically in the 4026531830-4026531840 range)
            for ns_link in [mnt_ns, pid_ns, net_ns]:
                ns_str = str(ns_link)
                if "[" in ns_str:
                    inum = int(ns_str.split("[")[-1].rstrip("]"))
                    if inum > 4026533000:
                        caps.already_nested = True
                        break
    except Exception:
        pass

    # ── Read max_user_namespaces ──
    try:
        max_ns_path = Path("/proc/sys/user/max_user_namespaces")
        if max_ns_path.exists():
            caps.max_user_namespaces = int(max_ns_path.read_text().strip())
    except Exception:
        pass

    # ── Test namespace creation ──
    # We test by running unshare in a subprocess to not affect our own process
    caps.namespace_creation_allowed = _test_unshare_capability()
    caps.namespace_available = caps.namespace_creation_allowed

    if caps.namespace_available:
        caps.namespace_mode = "created" if not caps.already_nested else "nested"

        # Test each namespace type individually
        caps.mount_namespace_available = _test_ns_type("mount")
        caps.pid_namespace_available = _test_ns_type("pid")
        caps.network_namespace_available = _test_ns_type("network")
        caps.user_namespace_available = _test_ns_type("user")
        caps.uts_namespace_available = _test_ns_type("uts")
        caps.ipc_namespace_available = _test_ns_type("ipc")

        caps.backend_name = "linux_namespace"
    elif caps.already_nested:
        caps.namespace_mode = "nested"
        caps.backend_name = "detection_only"
    else:
        caps.namespace_mode = "detected"
        caps.backend_name = "detection_only"

    return caps


def _test_unshare_capability() -> bool:
    """Test if unshare() works by running it in a subprocess."""
    test_code = (
        "import ctypes,os,sys;"
        "libc=ctypes.CDLL('libc.so.6',use_errno=True);"
        f"ret=libc.unshare({_CLONE_NEWNET});"
        "sys.exit(0 if ret==0 else 1)"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", test_code],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _test_ns_type(ns_type: str) -> bool:
    """Test if a specific namespace type can be created."""
    flag = _NS_TYPES.get(ns_type)
    if flag is None:
        return False
    # pid and user namespaces need --fork for testing
    fork_arg = ""
    if ns_type in ("pid", "user"):
        fork_arg = "os.fork();"  # crude but works for testing
    test_code = (
        "import ctypes,sys;"
        "libc=ctypes.CDLL('libc.so.6',use_errno=True);"
        f"ret=libc.unshare({flag});"
        "sys.exit(0 if ret==0 else 1)"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", test_code],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def apply_network_namespace() -> bool:
    """Create a new network namespace in the current process.

    Must be called in the child process BEFORE importing the node module.
    After this call, the process has no network interfaces except lo (down).

    Uses os.unshare() on Python 3.12+, ctypes fallback for older versions.

    Returns True if the network namespace was successfully created.
    """
    if platform.system() != "Linux":
        return False

    try:
        # Python 3.12+ has os.unshare()
        if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNET"):
            os.unshare(os.CLONE_NEWNET)
            return True

        # Fallback: ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ret = libc.unshare(_CLONE_NEWNET)
        return ret == 0
    except Exception:
        return False


def apply_mount_namespace() -> bool:
    """Create a new mount namespace and make mounts private.

    v1.4.3: Prototype mount namespace isolation.

    After unshare(CLONE_NEWNS), mount propagation is set to "private"
    (MS_PRIVATE | MS_REC) so that mount/unmount events in the child
    do not propagate to the parent, and vice versa.

    This does NOT attempt pivot_root or bind mounts. It only isolates
    the mount tree so future operations are contained.

    Must be called in the child process BEFORE importing the node module.

    Returns True if mount namespace was successfully created and
    propagation made private.
    """
    if platform.system() != "Linux":
        return False

    try:
        # Step 1: Create mount namespace
        if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNS"):
            os.unshare(os.CLONE_NEWNS)
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.unshare(_CLONE_NEWNS)
            if ret != 0:
                return False

        # Step 2: Make all mounts private (MS_PRIVATE|MS_REC)
        # This prevents mount propagation between parent and child.
        # MS_PRIVATE = 0x40000, MS_REC = 0x40000
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        MS_PRIVATE = 0x40000
        MS_REC = 0x40000
        # mount("none", "/", NULL, MS_PRIVATE|MS_REC, 0)
        ret = libc.mount(None, b"/", None, MS_PRIVATE | MS_REC, None)
        if ret != 0:
            # Mount propagation failed, but namespace was created
            # Still report True — the namespace exists, just not fully private
            pass

        return True
    except Exception:
        return False


def apply_mount_confinement(
    package_root: str,
    temp_dir: str,
    *,
    workspace_src: str | None = None,
    workspace_target: str = "/workspace",
    extra_mounts: list[tuple[str, str]] | None = None,
    read_only_targets: list[str] | set[str] | None = None,
) -> dict:
    """Create mount namespace with chroot-based filesystem confinement.

    v1.4.5: Mount namespace temp-root confinement.
    v1.6.0 (v2.76): optional workspace bind mount for command-execution path.
    v1.6.1 (v2.77): optional extra_mounts for argv-binary visibility (e.g.
                    /usr, /lib so the python interpreter is reachable in chroot).
    v1.6.2 (H0.2/T3): optional read_only_targets — in-chroot mount names
                    that MUST be bind-remounted read-only before chroot.
                    A requested name that was not mounted, or a remount the
                    kernel refuses, aborts confinement (fail closed).

    This is stronger than apply_mount_namespace() — it restricts the
    child's filesystem view to only allowed directories.

    Flow:
      1. unshare(CLONE_NEWNS)
      2. Make mounts private (MS_PRIVATE|MS_REC)
      3. Create temp root inside temp_dir
      4. Bind-mount package_root → temp_root/package
      5. Bind-mount temp_dir → temp_root/tmp
      6. (v2.76) If workspace_src given, bind-mount it → temp_root/workspace
         BEFORE chroot so the patched workspace is visible to a confined
         command runner (e.g. pytest execution).
      7. (v2.77) For each (src, target) in extra_mounts, bind-mount
         src → temp_root/target BEFORE chroot. Used to make argv binaries
         (e.g. /usr/bin/python3) and their shared libs reachable post-chroot.
      7b. (v1.6.2) For each name in read_only_targets, remount that bind
         MS_REMOUNT|MS_BIND|MS_RDONLY BEFORE chroot. /tmp stays writable
         unless explicitly listed. A read-only requirement that cannot be
         established makes the whole confinement fail closed.
      8. chroot to temp_root
      9. chdir("/")

    After chroot, the child can only access:
      /package/   — the node module directory
      /tmp/       — the invocation temp directory
      /workspace/ — (v2.76, optional) the patched temp workspace
      <target>    — (v2.77, optional) each extra_mount target

    The child CANNOT access host paths like /etc/passwd (unless explicitly
    added via extra_mounts, which the caller must scope narrowly).

    Must be called in the child process BEFORE importing the node module,
    and AFTER all trusted SDK imports are complete (they remain in
    sys.modules and don't need filesystem access).

    Backward compatibility: ``workspace_src`` is optional and keyword-only.
    Existing two-argument callers are unaffected.

    Returns dict with:
      mount_confinement_enforced: bool
      temp_root_created: bool
      temp_root_path: str (path before chroot, for reporting)
      allowed_mounts: list[str]
      chrooted_module_prefix: str (e.g. "/package")
      chrooted_workspace_prefix: str (e.g. "/workspace", empty unless workspace_src given)
      read_only_mounts: list[str] (in-chroot names remounted read-only)
      mount_confinement_error: str
    """
    result = {
        "mount_confinement_enforced": False,
        "temp_root_created": False,
        "temp_root_path": "",
        "allowed_mounts": [],
        "chrooted_module_prefix": "",
        "chrooted_workspace_prefix": "",
        "read_only_mounts": [],
        "mount_confinement_error": "",
    }

    if platform.system() != "Linux":
        result["mount_confinement_error"] = "not Linux"
        return result

    try:
        MS_BIND = 0x1000
        MS_RDONLY = 0x1
        MS_REMOUNT = 0x20
        MS_PRIVATE = 0x40000
        MS_REC = 0x40000

        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        # Step 1: Create mount namespace + private propagation
        if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNS"):
            os.unshare(os.CLONE_NEWNS)
        else:
            ret = libc.unshare(_CLONE_NEWNS)
            if ret != 0:
                result["mount_confinement_error"] = "unshare(CLONE_NEWNS) failed"
                return result

        libc.mount(None, b"/", None, MS_PRIVATE | MS_REC, None)

        # Step 2: Create temp root inside temp_dir
        temp_root = os.path.join(temp_dir, "chroot_root")
        pkg_mnt = os.path.join(temp_root, "package")
        tmp_mnt = os.path.join(temp_root, "tmp")
        os.makedirs(pkg_mnt, exist_ok=True)
        os.makedirs(tmp_mnt, exist_ok=True)
        result["temp_root_created"] = True
        result["temp_root_path"] = temp_root
        # In-chroot name → pre-chroot mountpoint, for read-only remounts.
        mount_points: dict[str, str] = {}

        # Step 3: Bind-mount package root
        pkg_abs = os.path.abspath(package_root)
        ret = libc.mount(pkg_abs.encode(), pkg_mnt.encode(), None, MS_BIND, None)
        if ret != 0:
            errno = ctypes.get_errno()
            result["mount_confinement_error"] = f"bind mount package failed: errno={errno}"
            return result
        result["allowed_mounts"].append("/package")
        mount_points["/package"] = pkg_mnt

        # Step 4: Bind-mount temp dir
        ret = libc.mount(os.path.abspath(temp_dir).encode(), tmp_mnt.encode(), None, MS_BIND, None)
        if ret != 0:
            result["mount_confinement_error"] = "bind mount temp failed"
            return result
        result["allowed_mounts"].append("/tmp")
        mount_points["/tmp"] = tmp_mnt

        # Step 5 (v2.76): Bind-mount workspace BEFORE chroot, if requested.
        # The mount source must be resolved against the pre-chroot root, so this
        # MUST happen before the chroot() call below — afterward the source path
        # would be unreachable. See docs/native_sandbox_test_runner.md.
        if workspace_src is not None:
            ws_target_name = workspace_target.strip("/") or "workspace"
            ws_mnt = os.path.join(temp_root, ws_target_name)
            os.makedirs(ws_mnt, exist_ok=True)
            ws_abs = os.path.abspath(workspace_src)
            ret = libc.mount(ws_abs.encode(), ws_mnt.encode(), None, MS_BIND, None)
            if ret != 0:
                errno = ctypes.get_errno()
                result["mount_confinement_error"] = (
                    f"bind mount workspace failed: errno={errno}"
                )
                return result
            result["allowed_mounts"].append(f"/{ws_target_name}")
            mount_points[f"/{ws_target_name}"] = ws_mnt

        # Step 5b (v2.77): extra bind mounts BEFORE chroot, if requested.
        # Used to make argv binaries (python interpreter) and their shared
        # libraries reachable inside the chroot. Caller must scope narrowly.
        if extra_mounts:
            for src, target in extra_mounts:
                tgt_name = target.strip("/") or "mnt"
                mnt = os.path.join(temp_root, tgt_name)
                os.makedirs(mnt, exist_ok=True)
                src_abs = os.path.abspath(src)
                if not os.path.exists(src_abs):
                    result["mount_confinement_error"] = (
                        f"extra_mount src does not exist: {src_abs}"
                    )
                    return result
                ret = libc.mount(src_abs.encode(), mnt.encode(), None, MS_BIND, None)
                if ret != 0:
                    errno = ctypes.get_errno()
                    result["mount_confinement_error"] = (
                        f"bind mount extra {src}->{target} failed: errno={errno}"
                    )
                    return result
                result["allowed_mounts"].append(f"/{tgt_name}")
                mount_points[f"/{tgt_name}"] = mnt

        # Step 5c (v1.6.2): required read-only bind remounts BEFORE chroot.
        # A read-only requirement is a containment contract, not a
        # preference: a requested name that was never mounted, or a remount
        # the kernel refuses, aborts confinement entirely (enforced stays
        # False — the caller fails closed before workload exec).
        if read_only_targets:
            ro_done: list[str] = []
            for t in dict.fromkeys(str(x) for x in read_only_targets):
                name = "/" + t.strip("/")
                if not name.strip("/") or name not in mount_points:
                    result["mount_confinement_error"] = (
                        f"read_only target not mounted: {t}"
                    )
                    return result
                ret = libc.mount(None, mount_points[name].encode(), None,
                                 MS_BIND | MS_REMOUNT | MS_RDONLY, None)
                if ret != 0:
                    errno = ctypes.get_errno()
                    result["mount_confinement_error"] = (
                        f"read-only remount failed for {name}: errno={errno}"
                    )
                    return result
                ro_done.append(name)
            result["read_only_mounts"] = sorted(ro_done)

        # Step 6: chroot to temp root
        ret = libc.chroot(temp_root.encode())
        if ret != 0:
            errno = ctypes.get_errno()
            result["mount_confinement_error"] = f"chroot failed: errno={errno}"
            return result

        os.chdir("/")

        result["mount_confinement_enforced"] = True
        result["chrooted_module_prefix"] = "/package"
        if workspace_src is not None:
            ws_target_name = workspace_target.strip("/") or "workspace"
            result["chrooted_workspace_prefix"] = f"/{ws_target_name}"
        return result

    except Exception as e:
        result["mount_confinement_error"] = str(e)
        return result


# ─── PID Namespace (v1.5.0) ──────────────────────────────────────────────

# Return codes for apply_pid_namespace fork protocol
_PID_NS_SUCCESS = 0
_PID_NS_SKIP = 42  # Not enabled or not Linux — continue without fork
_PID_NS_FAIL = 43  # unshare failed — continue without PID ns


def apply_pid_namespace_two_stage() -> int:
    """Create a PID namespace using a two-stage fork.

    v1.5.0: PID namespace isolation.

    PID namespace semantics require that unshare(CLONE_NEWPID) only
    affects processes created AFTER the call. The calling process
    itself stays in the old namespace. So we need:

      1. unshare(CLONE_NEWPID)
      2. fork() — child is PID 1 in the new PID namespace
      3. Parent waits for child and exits with child's status
      4. Child continues execution

    This function is designed to be called at the TOP of the child
    bootstrap main(), BEFORE any other phases. After the fork, the
    child process continues normally; the parent exits.

    Must be called BEFORE seccomp (which blocks fork).

    Returns:
      _PID_NS_SUCCESS (0) — caller is the child in new PID namespace
      _PID_NS_SKIP (42) — PID namespace not enabled, caller continues
      _PID_NS_FAIL (43) — unshare failed, caller continues without PID ns
    """
    if platform.system() != "Linux":
        return _PID_NS_SKIP

    try:
        if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWPID"):
            os.unshare(os.CLONE_NEWPID)
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.unshare(_CLONE_NEWPID)
            if ret != 0:
                return _PID_NS_FAIL

        # Fork: child will be PID 1 in new PID namespace
        pid = os.fork()
        if pid > 0:
            # Parent: wait for child, exit with same status
            _, status = os.waitpid(pid, 0)
            if os.WIFEXITED(status):
                sys.exit(os.WEXITSTATUS(status))
            elif os.WIFSIGNALED(status):
                sys.exit(128 + os.WTERMSIG(status))
            else:
                sys.exit(1)

        # Child: we are PID 1 in the new PID namespace
        # Become session leader for clean signal handling
        os.setsid()
        return _PID_NS_SUCCESS

    except OSError:
        return _PID_NS_FAIL


def remount_procfs_for_pid_namespace() -> dict:
    """Remount /proc for the PID namespace.

    v1.5.1: Procfs namespace-local view.

    After unshare(CLONE_NEWPID) + fork(), the child is PID 1 in a new
    PID namespace. However, the host's /proc is still mounted and
    exposes host PID entries. This function remounts /proc so that
    only namespace-local PIDs are visible.

    Flow:
      1. unshare(CLONE_NEWNS) — need mount namespace to remount /proc
      2. MS_PRIVATE|MS_REC — isolate mount propagation
      3. umount /proc
      4. mount proc proc /proc

    Requirements:
      - Must be called AFTER PID namespace is active (post-fork)
      - Must be called BEFORE seccomp (which blocks mount/umount syscalls)
      - Requires CAP_SYS_ADMIN
      - If mount namespace is already active, step 1 is a no-op

    When used with mount confinement (chroot), this remount happens
    INSIDE the chroot's /proc.

    Returns dict:
      procfs_namespace_view_enforced: bool
      procfs_isolated: bool
      procfs_error: str
    """
    result = {
        "procfs_namespace_view_enforced": False,
        "procfs_isolated": False,
        "procfs_error": "",
    }

    if platform.system() != "Linux":
        result["procfs_error"] = "not Linux"
        return result

    try:
        MS_PRIVATE = 0x40000
        MS_REC = 0x40000
        MS_NOSUID = 0x2
        MS_NOEXEC = 0x8
        MS_NODEV = 0x4

        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        # Step 1: Ensure we have a private mount namespace
        # CRITICAL: We MUST verify we're in a new mount namespace before
        # touching /proc, otherwise we'll unmount the host's /proc!
        # We verify by checking mount namespace inode before and after.
        _mount_ns_ok = False
        try:
            _mnt_inode_before = os.readlink("/proc/self/ns/mnt")
        except OSError:
            _mnt_inode_before = ""

        try:
            if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNS"):
                os.unshare(os.CLONE_NEWNS)
            else:
                ret = libc.unshare(_CLONE_NEWNS)
                if ret != 0:
                    result["procfs_error"] = "unshare(CLONE_NEWNS) failed"
                    return result
        except OSError:
            result["procfs_error"] = "unshare(CLONE_NEWNS) raised OSError"
            return result

        # Verify we actually got a new mount namespace
        try:
            _mnt_inode_after = os.readlink("/proc/self/ns/mnt")
            if _mnt_inode_before and _mnt_inode_after and _mnt_inode_before == _mnt_inode_after:
                # Same inode — unshare did NOT create a new mount namespace!
                result["procfs_error"] = "mount namespace unchanged after unshare"
                return result
            _mount_ns_ok = True
        except OSError:
            # Can't read inode — assume we're in a new namespace
            _mount_ns_ok = True

        if not _mount_ns_ok:
            result["procfs_error"] = "could not verify mount namespace separation"
            return result

        # Step 2: Make ALL mounts private (prevents umount propagation)
        libc.mount(None, b"/", None, MS_PRIVATE | MS_REC, None)
        # Also make /proc specifically private
        libc.mount(None, b"/proc", None, MS_PRIVATE, None)

        # Step 3: Unmount old /proc
        ret = libc.umount2(b"/proc", 0)
        if ret != 0:
            # /proc might not be mounted, or might be busy
            # Try to mount anyway — some systems allow it
            pass

        # Step 4: Mount new procfs for this PID namespace
        # proc: hidepid=2 hides other namespace PIDs from non-root
        ret = libc.mount(
            b"proc", b"/proc", b"proc",
            MS_NOSUID | MS_NOEXEC | MS_NODEV,
            None,  # default options show namespace-local PIDs
        )
        if ret != 0:
            errno = ctypes.get_errno()
            result["procfs_error"] = f"mount proc failed: errno={errno}"
            return result

        result["procfs_namespace_view_enforced"] = True
        result["procfs_isolated"] = True
        return result

    except Exception as e:
        result["procfs_error"] = str(e)
        return result
