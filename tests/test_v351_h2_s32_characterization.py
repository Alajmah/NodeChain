"""S3.2 Task 1: Characterization lock for the accepted R3 invariants.

These tests freeze the production assumptions that S3.2 (supervisor-owned
PID namespace topology) depends on. They contain NO production changes:
they are pure characterization, scoped to the frozen R3 state.

Locks proven here (each maps to a numbered S3.2 plan condition):

  L1  ``start_new_session=True`` in the supervised spawn path
  L2  external supervisor PID == SID == PGID (session leader)
  L3  ``session.pgid == supervisor PID`` (captured at spawn)
  L4  bootstrap/workload inherit the supervisor PGID transitively
  L5  the supervised path never calls ``setsid`` / ``setpgid`` /
      ``apply_pid_namespace_two_stage``
  L6  protocol FD remains absent from bootstrap and workload
      (covered by ``test_v351_h2_s2_fd_isolation.py`` — run as part of
      the Task 1 regression gate, not duplicated here)
  L7  the supervised path has the PID-namespace launcher/init topology
      wired (Task 3 positive authority — replaced Task 1's negative
      characterization); native_sandbox spawn still does NOT call unshare
      (no ``namespace_init_supervisor_main``; supervised path does not
      invoke ``CLONE_NEWPID`` / ``unshare``). Note: the *module*
      ``pid_namespace_topology.py`` may appear in Task 2; this test does
      NOT assert its absence — only the execution topology in
      ``exec_supervisor.py``.
  L8  ``PTRACE_EVENT_EXEC`` remains the sole workload-start authority
  L9  cleanup failure still maps to caller-visible ``cleanup_failed``
  L10 R3 transport, terminal proof, deadline, shutdown unchanged

If any of these breaks, S3.2 implementation must pause: a plan
assumption has changed under us. Do NOT relax these assertions to make
a later task pass; amend the plan instead.

Provenance: the S3.2 plan was authored against R3 frozen at commit
``0ce63c63``. That SHA is recorded here for human reference only — it
is NOT asserted as ``HEAD`` (every subsequent commit would invalidate
such a test). The real locks are the structural and behavioral
properties below.

Task 3 (launcher / namespace-init split) is expected to *deliberately
replace* the L7 negative characterization with positive authority tests
for the new topology. That is the intended lifecycle for L7.
"""

from __future__ import annotations

import ast
import os
import re
import sys
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths and provenance
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = REPO_ROOT / "src" / "nodechain" / "runtime"
NATIVE_SANDBOX_EXEC = RUNTIME_DIR / "native_sandbox_exec.py"
EXEC_SUPERVISOR = RUNTIME_DIR / "exec_supervisor.py"
SUPERVISED_EXEC_SESSION = RUNTIME_DIR / "supervised_exec_session.py"
ASYNC_FD_TRANSPORT = RUNTIME_DIR / "async_fd_transport.py"
SUPERVISED_ARGV = RUNTIME_DIR / "supervised_argv.py"  # T1: new lifecycle module

# Provenance only — do NOT assert HEAD equality (see module docstring).
R3_FREEZE_SHA_PROVENANCE = "0ce63c63"


# ---------------------------------------------------------------------------
# Helpers: scoped source extraction
# ---------------------------------------------------------------------------

def _native_sandbox_source() -> str:
    """Read the native_sandbox_exec.py source text."""
    return NATIVE_SANDBOX_EXEC.read_text(encoding="utf-8")


def _exec_supervisor_source() -> str:
    """Read the exec_supervisor.py source text."""
    return EXEC_SUPERVISOR.read_text(encoding="utf-8")


def _extract_function_source(source: str, func_name: str) -> str:
    """Return the source slice of a top-level ``async def``/``def``.

    Uses AST line numbers so the slice is exact regardless of indentation.
    Raises if the function is absent, AND if it is ambiguous (more than
    one top-level match), AND if a match is only nested — the contract is
    strictly top-level, enforced by iterating ``tree.body`` (not
    ``ast.walk``, which would descend into nested defs and could silently
    select a wrong inner helper if an outer function were removed).
    """
    tree = ast.parse(source)
    matches = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == func_name
    ]
    assert len(matches) <= 1, (
        f"multiple top-level definitions of {func_name!r} found — "
        f"production structure is ambiguous; cannot lock reliably"
    )
    if not matches:
        raise AssertionError(
            f"top-level function {func_name!r} not found — production "
            f"structure changed"
        )
    node = matches[0]
    lines = source.splitlines()
    start = (node.lineno - 1)
    end = node.end_lineno  # 1-based inclusive
    return "\n".join(lines[start:end])


def _extract_function_node(source: str, func_name: str):
    """Return the AST node of a top-level function (for structural locks).

    Same top-level/unique contract as :func:`_extract_function_source`,
    but returns the node so callers can walk its body for Call/Assign
    nodes without re-parsing the source text.
    """
    tree = ast.parse(source)
    matches = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == func_name
    ]
    assert len(matches) <= 1, (
        f"multiple top-level definitions of {func_name!r}"
    )
    assert matches, f"top-level function {func_name!r} not found"
    return matches[0]


def _supervised_child_source() -> str:
    """Source slice of ``_run_supervised_child`` — the T1 thin wrapper.

    After T1, this function is a thin wrapper that delegates to
    ``run_supervised_argv_async`` in ``supervised_argv.py``. The actual
    lifecycle implementation lives in ``_supervised_lifecycle_source()``.
    """
    return _extract_function_source(_native_sandbox_source(), "_run_supervised_child")


def _supervised_argv_source() -> str:
    """Read the supervised_argv.py source text (T1 lifecycle module)."""
    return SUPERVISED_ARGV.read_text(encoding="utf-8")


def _supervised_lifecycle_source() -> str:
    """Source slice of ``run_supervised_argv_async`` — the T1 lifecycle.

    After T1, this is the actual parent-side supervised lifecycle
    implementation: spawn, config delivery, protocol transport, bounded
    output, shutdown, and result mapping.
    """
    return _extract_function_source(_supervised_argv_source(), "run_supervised_argv_async")


def _supervisor_main_source() -> str:
    """Source slice of ``supervisor_main`` — the external supervisor core."""
    return _extract_function_source(_exec_supervisor_source(), "supervisor_main")


# ---------------------------------------------------------------------------
# Static-source locks (cross-platform — run on every platform)
# ---------------------------------------------------------------------------

class TestStaticSourceLocks:
    """Lock the supervised-path source structure.

    These run on every platform (no Linux requirement) because they only
    inspect source text, not runtime process behavior. They are the
    cross-platform gate for the S3.2 invariants.
    """

    # ----- L1: start_new_session=True in the supervised spawn path -----

    def test_L1_supervised_spawn_uses_start_new_session(self):
        """L1: the supervised lifecycle spawns the external supervisor with
        ``start_new_session=True``.

        After T1, the lifecycle implementation moved from
        ``_run_supervised_child`` to ``run_supervised_argv_async`` in
        ``supervised_argv.py``. The invariant is unchanged — only the
        source location moved.

        This is the root of the host-PGID invariant.
        """
        lifecycle_src = _supervised_lifecycle_source()
        assert "start_new_session=True" in lifecycle_src, (
            "supervised lifecycle no longer sets start_new_session=True — "
            "the S3.2 host-PGID invariant is broken; amend the plan"
        )

    # ----- L5: supervised path never calls forbidden lifecycle mutators -----

    @pytest.mark.parametrize("forbidden", [
        "setsid(",
        "os.setsid(",
        "setpgid(",
        "os.setpgid(",
        "apply_pid_namespace_two_stage(",
        "_APPLY_PID_NS_TWO_STAGE(",
    ])
    def test_L5_supervised_path_has_no_forbidden_lifecycle_mutators(self, forbidden):
        """L5: the supervised wrapper + lifecycle + supervisor path never
        mutates session or process-group membership, and never invokes the
        legacy two-stage PID-namespace helper.

        After T1, scoped to the thin wrapper (``_run_supervised_child``),
        the lifecycle (``run_supervised_argv_async``), and ``supervisor_main``.
        The unsupervised path legitimately uses ``start_new_session`` and
        the legacy helper; a whole-file check would create false failures.
        """
        wrapper_src = _supervised_child_source()
        lifecycle_src = _supervised_lifecycle_source()
        supervisor_core = _supervisor_main_source()
        for label, src in (("wrapper", wrapper_src),
                           ("lifecycle", lifecycle_src),
                           ("supervisor_core", supervisor_core)):
            assert forbidden not in src, (
                f"forbidden call {forbidden!r} present in {label} — "
                f"supervised path must not mutate process group/session "
                f"or use the legacy two-stage PID helper"
            )

    def test_L5_supervisor_process_main_does_not_mutate_session(self):
        """L5 (extended): ``supervisor_process_main`` — the production
        entry point — also does not call ``setsid``/``setpgid``."""
        src = _extract_function_source(
            _exec_supervisor_source(), "supervisor_process_main"
        )
        for forbidden in ("setsid(", "os.setsid(", "setpgid(", "os.setpgid("):
            assert forbidden not in src, (
                f"supervisor_process_main calls {forbidden!r} — "
                f"supervised entry must not mutate session/group"
            )

    # ----- L7: PID-namespace launcher topology IS wired (Task 3 authority) -----

    def test_L7_launcher_topology_is_wired(self):
        """L7 (Task 3 replacement): the PID-namespace launcher/init split
        is now wired into the supervised entry path.

        This replaces the Task 1 negative characterization (which asserted
        the topology was ABSENT). Task 3 introduces it; this positive
        authority test locks the new structure.

        Assertions (via module AST):
          * ``launch_pid_namespace_supervisor`` and
            ``namespace_init_supervisor_main`` ARE top-level defs;
          * ``supervisor_process_main`` delegates to
            ``launch_pid_namespace_supervisor``;
          * ``launch_pid_namespace_supervisor`` calls ``unshare_pid_namespace``;
          * ``launch_pid_namespace_supervisor`` calls ``build_topology_proof``;
          * ``namespace_init_supervisor_main`` calls ``supervisor_main``
            (the existing core runs unchanged inside namespace-init I);
          * ``supervisor_main`` itself remains structurally present and
            unchanged (the L8 AST tests lock its internals separately).
        """
        import ast as _ast
        supervisor_src = _exec_supervisor_source()
        module_tree = _ast.parse(supervisor_src)
        top_level_funcs = {
            node.name for node in module_tree.body
            if isinstance(node, _ast.FunctionDef)
        }
        # Both Task 3 functions must be top-level defs.
        assert "launch_pid_namespace_supervisor" in top_level_funcs, (
            "launch_pid_namespace_supervisor not defined — Task 3 launcher "
            "must be a top-level function in exec_supervisor.py"
        )
        assert "namespace_init_supervisor_main" in top_level_funcs, (
            "namespace_init_supervisor_main not defined — Task 3 "
            "namespace-init must be a top-level function"
        )
        # supervisor_process_main delegates to the launcher.
        entry_src = _extract_function_source(supervisor_src, "supervisor_process_main")
        assert "launch_pid_namespace_supervisor" in entry_src, (
            "supervisor_process_main does not delegate to "
            "launch_pid_namespace_supervisor — the entry path must go "
            "through the PID-namespace launcher"
        )
        # The launcher calls unshare + build_topology_proof.
        launcher_src = _extract_function_source(supervisor_src, "launch_pid_namespace_supervisor")
        assert "unshare_pid_namespace" in launcher_src, (
            "launch_pid_namespace_supervisor does not call "
            "unshare_pid_namespace — must unshare before forking I"
        )
        assert "build_topology_proof" in launcher_src, (
            "launch_pid_namespace_supervisor does not call "
            "build_topology_proof — must verify topology before release"
        )
        # Namespace-init calls supervisor_main (the existing core).
        init_src = _extract_function_source(supervisor_src, "namespace_init_supervisor_main")
        assert "supervisor_main(" in init_src, (
            "namespace_init_supervisor_main does not call supervisor_main — "
            "the existing core must run unchanged inside namespace-init I"
        )
        # Legacy two-stage helper must NOT be used on this path.
        for forbidden in ("apply_pid_namespace_two_stage", "_APPLY_PID_NS_TWO_STAGE"):
            assert forbidden not in launcher_src, (
                f"launcher uses legacy {forbidden} — forbidden on the "
                f"supervised PID-namespace path"
            )
            assert forbidden not in init_src, (
                f"namespace-init uses legacy {forbidden} — forbidden"
            )

    def test_L7_native_sandbox_spawn_still_no_unshare(self):
        """L7 (preserved from Task 1): the parent-side supervised path
        must NOT invoke PID-namespace primitives directly. Namespace
        creation is owned by the launcher inside ``exec_supervisor.py``,
        not by the parent-side spawn code.

        After T1, scoped to both the thin wrapper and the lifecycle
        implementation.
        """
        for label, src in (("wrapper", _supervised_child_source()),
                           ("lifecycle", _supervised_lifecycle_source())):
            for token in ("CLONE_NEWPID", "os.unshare", "unshare("):
                assert token not in src, (
                    f"{label} invokes {token!r} — PID-namespace "
                    f"creation must live in the launcher, not the "
                    f"parent-side supervised path"
                )

    # ----- L8: PTRACE_EVENT_EXEC remains the sole workload-start authority -----

    def test_L8_ptrace_event_exec_constant_unchanged(self):
        """L8: the ``PTRACE_EVENT_EXEC`` constant retains its kernel value.

        The supervisor arms ``PTRACE_O_TRACEEXEC`` and recognizes exec as
        workload-start only when ``stopsig == SIGTRAP`` and
        ``event == PTRACE_EVENT_EXEC``. The constant value (4) is a Linux
        ABI stable value; locking it catches accidental redefinition.
        """
        src = _exec_supervisor_source()
        assert "PTRACE_EVENT_EXEC = 4" in src, (
            "PTRACE_EVENT_EXEC constant changed — exec authority "
            "recognition may be broken"
        )

    def test_L8_ptrace_options_set_only_traceexec(self):
        """L8 (complement, AST lock): the supervisor sets only
        ``PTRACE_O_TRACEEXEC``, and ``exec_confirmed=True`` is the sole
        workload-start authority.

        A substring check could be evaded by a second ptrace call using a
        numeric mask (e.g. ``ptrace(PTRACE_SETOPTIONS, pid, None,
        0x100000)``) or an aliased option. This AST lock cannot be evaded
        that way: it walks every ``libc.ptrace(...)`` call in
        ``supervisor_main`` and enforces:

          1. exactly one call whose first argument is the name
             ``PTRACE_SETOPTIONS``;
          2. that call's fourth argument is exactly the name
             ``PTRACE_O_TRACEEXEC`` (not a numeric constant, not an OR
             expression, not an alias);
          3. every ptrace call's first argument is one of the currently
             permitted request names (``PTRACE_SETOPTIONS`` or
             ``PTRACE_CONT``);
          4. exactly one assignment of ``exec_confirmed = True`` in
             ``supervisor_main``;
          5. that assignment is lexically inside the
             ``SIGTRAP && PTRACE_EVENT_EXEC`` branch (the sole start
             authority), verified by checking the enclosing ``If`` node's
             test contains both ``signal.SIGTRAP`` and
             ``PTRACE_EVENT_EXEC`` comparisons.

        S3.2 plan condition: no recursive ptrace options, no
        ``EXITKILL``, ``PTRACE_EVENT_EXEC`` remains the sole workload-
        start authority.
        """
        import ast as _ast
        node = _extract_function_node(_exec_supervisor_source(), "supervisor_main")

        # --- Collect every libc.ptrace(...) call inside supervisor_main ---
        ptrace_calls: list[_ast.Call] = []
        for sub in _ast.walk(node):
            if (isinstance(sub, _ast.Call)
                    and isinstance(sub.func, _ast.Attribute)
                    and sub.func.attr == "ptrace"):
                ptrace_calls.append(sub)

        def _arg_is_name(arg, name: str) -> bool:
            """True iff arg is exactly a bare Name with id == name."""
            return isinstance(arg, _ast.Name) and arg.id == name

        # --- Requirement 3 first: every ptrace call's request arg is a ---
        # --- permitted name. This also rejects numeric-mask evasion.    ---
        permitted_requests = {"PTRACE_SETOPTIONS", "PTRACE_CONT"}
        for call in ptrace_calls:
            assert call.args, (
                f"ptrace call at line {call.lineno} has no arguments"
            )
            req = call.args[0]
            assert isinstance(req, _ast.Name) and req.id in permitted_requests, (
                f"ptrace call at line {call.lineno} uses request "
                f"{_ast.dump(req)} — only symbolic names in "
                f"{permitted_requests} are permitted; numeric masks or "
                f"aliases are forbidden (would evade the no-EXITKILL / "
                f"no-recursive-trace lock)"
            )

        # --- Requirement 1: exactly one PTRACE_SETOPTIONS call ---
        setoptions_calls = [
            c for c in ptrace_calls if _arg_is_name(c.args[0], "PTRACE_SETOPTIONS")
        ]
        assert len(setoptions_calls) == 1, (
            f"expected exactly 1 PTRACE_SETOPTIONS call, found "
            f"{len(setoptions_calls)} — supervisor must set options "
            f"exactly once"
        )
        setoptions = setoptions_calls[0]

        # --- Requirement 2: fourth arg is exactly PTRACE_O_TRACEEXEC ---
        assert len(setoptions.args) >= 4, (
            f"PTRACE_SETOPTIONS call at line {setoptions.lineno} has "
            f"{len(setoptions.args)} args — expected 4 (request, pid, "
            f"None, options)"
        )
        opts_arg = setoptions.args[3]
        assert _arg_is_name(opts_arg, "PTRACE_O_TRACEEXEC"), (
            f"PTRACE_SETOPTIONS fourth argument is "
            f"{_ast.dump(opts_arg)} — must be exactly the bare name "
            f"PTRACE_O_TRACEEXEC (not a numeric mask, not an OR "
            f"expression, not an alias). S3.2 forbids combining "
            f"TRACEEXEC with TRACEFORK/CLONE/VFORK/EXITKILL."
        )

        # --- Requirements 4 & 5: exactly one exec_confirmed = True, ---
        # --- inside the SIGTRAP && PTRACE_EVENT_EXEC branch          ---
        exec_confirmed_true_assigns: list[_ast.Assign] = []
        for sub in _ast.walk(node):
            if (isinstance(sub, _ast.Assign)
                    and len(sub.targets) == 1
                    and isinstance(sub.targets[0], _ast.Name)
                    and sub.targets[0].id == "exec_confirmed"
                    and isinstance(sub.value, _ast.Constant)
                    and sub.value.value is True):
                exec_confirmed_true_assigns.append(sub)
        assert len(exec_confirmed_true_assigns) == 1, (
            f"expected exactly 1 'exec_confirmed = True' assignment, "
            f"found {len(exec_confirmed_true_assigns)} — workload-start "
            f"authority must be set in exactly one place"
        )
        assign_node = exec_confirmed_true_assigns[0]

        # --- Requirement 6 (exact): the assignment's DIRECT parent is an ---
        # --- If, the assignment is in If.body (not orelse), and If.test  ---
        # --- is exactly BoolOp(And, [stopsig==SIGTRAP, event==EXEC]).    ---
        # A line-range enclosure check is insufficient — it cannot reject
        # an assignment relocated to orelse (still within the If's line
        # span), and a name-substring check cannot reject `or` for `and`.
        # We build a real parent map and require exact AST structure.
        parent_map: dict[int, _ast.AST] = {}
        for parent in _ast.walk(node):
            for child in _ast.iter_child_nodes(parent):
                parent_map[id(child)] = parent

        direct_parent = parent_map.get(id(assign_node))
        assert isinstance(direct_parent, _ast.If), (
            f"exec_confirmed = True at line {assign_node.lineno} — direct "
            f"parent is {type(direct_parent).__name__ if direct_parent else 'None'}, "
            f"not ast.If. The assignment must be a direct statement of "
            f"the SIGTRAP && PTRACE_EVENT_EXEC branch body, not nested "
            f"inside a helper, a compound statement, or orelse."
        )
        # Assignment must be in If.body, NOT in If.orelse.
        assert assign_node in direct_parent.body, (
            f"exec_confirmed = True at line {assign_node.lineno} is in "
            f"If.orelse, not If.body — workload-start authority has been "
            f"inverted (would fire on the NON-exec branch)"
        )
        # If.test must be exactly BoolOp(And) with exactly 2 operands.
        test_node = direct_parent.test
        assert isinstance(test_node, _ast.BoolOp), (
            f"If.test at line {direct_parent.lineno} is "
            f"{type(test_node).__name__}, not BoolOp — exec authority "
            f"must be a conjunction (and), not a single comparison or "
            f"other expression"
        )
        assert isinstance(test_node.op, _ast.And), (
            f"If.test BoolOp uses {type(test_node.op).__name__}, not And "
            f"— disjunction (or) would fire exec_confirmed on EITHER "
            f"condition, relaxing workload-start authority"
        )
        assert len(test_node.values) == 2, (
            f"If.test BoolOp has {len(test_node.values)} operands, not 2 "
            f"— extra conjuncts or missing conditions change the "
            f"workload-start authority"
        )

        def _is_stopsig_sigtrap(cmp) -> bool:
            """True iff cmp is exactly: stopsig == signal.SIGTRAP."""
            return (
                isinstance(cmp, _ast.Compare)
                and len(cmp.ops) == 1
                and isinstance(cmp.ops[0], _ast.Eq)
                and isinstance(cmp.left, _ast.Name)
                and cmp.left.id == "stopsig"
                and len(cmp.comparators) == 1
                and isinstance(cmp.comparators[0], _ast.Attribute)
                and isinstance(cmp.comparators[0].value, _ast.Name)
                and cmp.comparators[0].value.id == "signal"
                and cmp.comparators[0].attr == "SIGTRAP"
            )

        def _is_event_exec(cmp) -> bool:
            """True iff cmp is exactly: event == PTRACE_EVENT_EXEC."""
            return (
                isinstance(cmp, _ast.Compare)
                and len(cmp.ops) == 1
                and isinstance(cmp.ops[0], _ast.Eq)
                and isinstance(cmp.left, _ast.Name)
                and cmp.left.id == "event"
                and len(cmp.comparators) == 1
                and isinstance(cmp.comparators[0], _ast.Name)
                and cmp.comparators[0].id == "PTRACE_EVENT_EXEC"
            )

        op0, op1 = test_node.values
        # Accept either ordering of the two operands (both are exact-eq,
        # so order has no semantic effect — but lock that BOTH are present
        # and they are EXACTLY these two, nothing else).
        operands_match = (
            (_is_stopsig_sigtrap(op0) and _is_event_exec(op1))
            or (_is_event_exec(op0) and _is_stopsig_sigtrap(op1))
        )
        assert operands_match, (
            f"If.test operands are not exactly "
            f"[stopsig==signal.SIGTRAP, event==PTRACE_EVENT_EXEC]. "
            f"Got: {_ast.dump(op0)[:60]} / {_ast.dump(op1)[:60]} — "
            f"workload-start authority has been altered (aliased names, "
            f"reversed comparisons, numeric constants, or extra conditions)"
        )

    def test_L8_exact_exec_check_unchanged(self):
        """L8: the exact-event recognition check is structurally unchanged.

        The two-condition check (SIGTRAP + PTRACE_EVENT_EXEC) is the
        sole workload-start authority. Locking the literal source guards
        against accidental relaxation (e.g. accepting any stop as exec).
        """
        src = _supervisor_main_source()
        assert "stopsig == signal.SIGTRAP" in src, (
            "exec-event stopsig check changed — start authority may be "
            "relaxed"
        )
        assert "event == PTRACE_EVENT_EXEC" in src, (
            "exec-event event check changed — start authority may be "
            "relaxed"
        )

    # ----- L9: cleanup failure maps to caller-visible cleanup_failed -----

    def test_L9_cleanup_failure_maps_to_cleanup_failed(self):
        """L9: every ``cleanup_succeeded is False`` outcome maps to the
        caller-visible reason ``cleanup_failed``.

        This is the frozen R3 result-mapping contract that S3.2 must not
        change. S3.2 may add protocol-local telemetry
        (``namespace_reap_timeout``) but the caller-visible classification
        remains exactly ``cleanup_failed``.

        Scoped to ``map_supervisor_result`` — the parent-side evidence→result
        mapper that ``_run_supervised_child`` delegates to.
        """
        src = _extract_function_source(_native_sandbox_source(), "map_supervisor_result")
        assert 'reason = "cleanup_failed"' in src, (
            "caller-visible cleanup-failure reason changed — S3.2 must "
            "preserve exactly 'cleanup_failed'"
        )

    def test_L9_supervised_child_delegates_to_mapper(self):
        """L9 (complement): the supervised lifecycle delegates to
        ``map_supervisor_result`` rather than inlining its own mapping.

        After T1, the lifecycle lives in ``run_supervised_argv_async``
        which delegates through ``_map_result()`` — a local bridge that
        must itself call ``map_supervisor_result()``.
        """
        lifecycle_src = _supervised_lifecycle_source()
        # The lifecycle uses _map_result as a local bridge.
        assert "_map_result(" in lifecycle_src, (
            "lifecycle no longer delegates to _map_result — "
            "the cleanup_failed mapping lock may no longer cover "
            "the actual mapping site"
        )
        # The bridge must call map_supervisor_result.
        bridge_src = _extract_function_source(
            _supervised_argv_source(), "_map_result"
        )
        assert "map_supervisor_result(" in bridge_src, (
            "_map_result no longer calls map_supervisor_result — "
            "the cleanup_failed mapping bridge is broken"
        )

    # ----- L10: R3 frozen surface unchanged (structural) -----

    def test_L10_supervised_exec_session_has_r3_invariants(self):
        """L10: ``SupervisedExecSession`` retains the R3 invariant fields
        and methods that S3.2 must not alter.

        S3.2 plan condition: R3 transport, ownership, deadlines, shutdown,
        terminal proof, and result mapping remain unchanged. This locks
        the structural surface (field/method names); behavioral locks
        live in the dedicated R3 test files run as part of the Task 1
        regression gate.
        """
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession,
            validate_terminal_proof,
        )
        fields = (
            SupervisedExecSession.__dataclass_fields__
            if hasattr(SupervisedExecSession, "__dataclass_fields__")
            else {}
        )
        for field in (
            "proc", "pgid", "proc_exit_task", "execution_deadline",
            "transport", "_shutdown_state", "config_task",
            "stdout_task", "stderr_task",
        ):
            assert field in fields or hasattr(SupervisedExecSession, field), (
                f"SupervisedExecSession missing R3 field {field!r} — "
                f"ownership/deadline surface changed"
            )
        for method in (
            "shutdown", "observe", "_signal_group",
            "_check_pgid_quiescent", "_check_process_terminal",
        ):
            assert hasattr(SupervisedExecSession, method), (
                f"SupervisedExecSession missing R3 method {method!r} — "
                f"shutdown/terminal/PGID surface changed"
            )
        assert validate_terminal_proof is not None

    def test_L10_r3_frozen_files_exist(self):
        """L10: the R3 files declared frozen by the S3.2 plan exist.

        Their behavioral invariants are covered by the dedicated R3 test
        suites run as part of the Task 1 regression gate (not duplicated
        here).
        """
        for path in (ASYNC_FD_TRANSPORT, SUPERVISED_EXEC_SESSION):
            assert path.exists(), f"frozen R3 file missing: {path.name}"


# ---------------------------------------------------------------------------
# Runtime locks (Linux-only — require process spawn + ptrace + fork)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: supervisor uses ptrace")
@pytest.mark.native_sandbox
class TestRuntimeProcessGroupLocks:
    """Runtime proofs of the process-group / session invariants.

    Linux-only: the supervised path uses ptrace + fork, so the supervisor
    only runs on Linux. These tests launch the real supervised path via
    ``run_isolated(use_supervisor=True)`` and capture production values
    through the ``SupervisedExecSession.observe`` seam.

    **S3.2 Task 3 plan amendment (L2/L3/L4):**

    After the PID-namespace split, the workload runs inside a child PID
    namespace. Processes in the child namespace cannot see the host
    session/group leader (it is in an ancestor namespace), so their
    ``getpgid(0)`` / ``getsid(0)`` return 0. This is correct kernel
    behavior, not a containment failure.

    The authoritative containment proof is therefore from the **parent/host
    namespace**: ``os.getpgid(descendant_host_pid) == supervisor_pid`` and
    ``os.getsid(descendant_host_pid) == supervisor_pid``, measured while
    the descendant is alive. The workload's namespace-local zeros are
    characterized as diagnostic-only (non-authoritative).

    The locked conditions proved here:

      L2  — S host PID == host SID == host PGID (parent-side proof)
      L3  — session.pgid == S host PID
      L4  — I/bootstrap/workload/descendants belong to S's host PGID,
            proven from the parent namespace; namespace-local SID/PGID
            may be 0 (diagnostic-only characterization)
    """

    def _run_with_observer(self, child_src: str, tmp_path):
        """Run a workload under the supervised path with an observer that
        captures the real supervisor PID and session.pgid."""
        from nodechain.runtime.native_sandbox_exec import run_isolated
        from nodechain.runtime.supervised_exec_session import SupervisedExecSession

        captures: dict[str, int] = {}
        original_observe = SupervisedExecSession.observe

        def _capturing_observe(self, state: str) -> None:
            original_observe(self, state)
            if state == "supervisor_spawned":
                pid = getattr(self.proc, "pid", None)
                pgid = self.pgid
                if pid is not None and pgid is not None:
                    captures.setdefault("supervisor_pid", pid)
                    captures.setdefault("session_pgid", pgid)
                    # Capture host PGID and SID while S is alive — after
                    # run_isolated returns the supervisor will be gone.
                    # All three values are mandatory (no optional skip).
                    try:
                        captures.setdefault("host_pgid", os.getpgid(pid))
                        captures.setdefault("host_sid", os.getsid(pid))
                    except OSError:
                        pass

        SupervisedExecSession.observe = _capturing_observe  # type: ignore[assignment]
        try:
            result = run_isolated(
                argv=[sys.executable, "-c", child_src],
                cwd=tmp_path, timeout_seconds=30,
                max_output_bytes=100000, env_allowlist={"PATH"},
                use_supervisor=True,
            )
        finally:
            SupervisedExecSession.observe = original_observe  # type: ignore[assignment]
        return captures, result

    def test_L2_L3_supervisor_pid_equals_sid_pgid_and_session_pgid(self, tmp_path):
        """L2 + L3 (parent-side proof): S is a session leader and
        ``session.pgid`` captures its PID.

        After the PID-namespace split, the workload cannot self-report its
        host SID/PGID from inside the namespace (returns 0). The
        authoritative proof is parent-side: ``os.getpgid(sup_pid)`` and
        ``os.getsid(sup_pid)`` measured from the NodeChain parent (which
        is in the host/ancestor namespace).

        The workload's namespace-local SID/PGID (0) is characterized as
        diagnostic-only.
        """
        captures, result = self._run_with_observer(
            "import os, sys; "
            "sys.stdout.write(f'PID={os.getpid()} "
            "PGID={os.getpgid(0)} SID={os.getsid(0)}\\n'); "
            "sys.stdout.flush()",
            tmp_path,
        )
        assert "supervisor_pid" in captures, (
            "observer never captured supervisor_spawned — run may have "
            f"failed early. Result: {result!r}"
        )
        sup_pid = captures["supervisor_pid"]
        session_pgid = captures["session_pgid"]

        # L3: session.pgid must equal the supervisor proc.pid.
        assert session_pgid == sup_pid, (
            f"session.pgid ({session_pgid}) != supervisor proc.pid "
            f"({sup_pid}) — R3 host-PGID containment is broken"
        )

        # L2 (parent-side proof): S's host PGID and SID must equal its PID.
        # All three values are mandatory — no optional assertion.
        host_pgid = captures.get("host_pgid")
        host_sid = captures.get("host_sid")
        assert host_pgid is not None, (
            "host_pgid was not captured by the observer — os.getpgid(sup_pid) "
            "failed at supervisor_spawned time; cannot prove S is a group leader"
        )
        assert host_sid is not None, (
            "host_sid was not captured — os.getsid(sup_pid) failed; "
            "cannot prove S is a session leader"
        )
        assert host_pgid == sup_pid, (
            f"S host PGID ({host_pgid}) != S PID ({sup_pid}) — S is not "
            f"a process-group leader; start_new_session may be broken"
        )
        assert host_sid == sup_pid, (
            f"S host SID ({host_sid}) != S PID ({sup_pid}) — S is not "
            f"a session leader"
        )

        # Diagnostic-only: characterize the workload's namespace-local
        # SID/PGID as 0 (the ancestor-namespace leader is invisible inside
        # the child PID namespace). This is NOT a containment failure.
        stdout = result.get("stdout", "") or ""
        pgid_m = re.search(r"PGID=(\d+)", stdout)
        sid_m = re.search(r"SID=(\d+)", stdout)
        if pgid_m and sid_m:
            wl_pgid = int(pgid_m.group(1))
            wl_sid = int(sid_m.group(1))
            # Characterize the namespace-local zeros without failing.
            # (If these are NOT zero, that's also fine — it means the
            # workload happened to be in the init namespace. Either way,
            # the parent-side proof above is authoritative.)

    def test_L4_grandchild_inherits_supervisor_pgid(self, tmp_path):
        """L4 (transitive, parent-side): the workload and its grandchild
        belong to S's host process group, proven from the host namespace.

        Design (locked amendment):
          * Exact S PID captured through observer (no global proc scan).
          * Workload forks one grandchild; both block behind a barrier file.
          * Parent traverses exact S -> I -> workload -> grandchild chain.
          * Parent asserts getpgid and getsid for I, workload, grandchild.
          * No skips. Finally releases the barrier and joins within a deadline.
        """
        import threading
        from pathlib import Path as _P
        from nodechain.runtime.native_sandbox_exec import run_isolated
        from nodechain.runtime.supervised_exec_session import SupervisedExecSession

        ready_file = tmp_path / "ready"
        release_file = tmp_path / "release"

        # Workload: forks a grandchild, signals ready, both block on release.
        child_src = (
            f"import os, sys\n"
            f"gc = os.fork()\n"
            f"if gc == 0:\n"
            f"    open({str(ready_file)!r},'w').close()\n"
            f"    while not os.path.exists({str(release_file)!r}): import time; time.sleep(0.05)\n"
            f"    sys.exit(0)\n"
            f"else:\n"
            f"    os.waitpid(gc, 0)\n"
        )
        captures: dict[str, int] = {}
        original_observe = SupervisedExecSession.observe
        def _cap(self, state):
            original_observe(self, state)
            if state == "supervisor_spawned":
                pid = getattr(self.proc, "pid", None)
                if pid is not None:
                    captures.setdefault("supervisor_pid", pid)
                    try:
                        captures.setdefault("supervisor_pgid", os.getpgid(pid))
                    except OSError: pass
        SupervisedExecSession.observe = _cap  # type: ignore
        result_box = [None]
        def _run():
            try:
                result_box[0] = run_isolated(
                    argv=[sys.executable, "-c", child_src],
                    cwd=tmp_path, timeout_seconds=30,
                    max_output_bytes=100000, env_allowlist={"PATH"},
                    use_supervisor=True,
                )
            except Exception as e:
                result_box[0] = {"error": str(e)}
        try:
            t = threading.Thread(target=_run, daemon=True)
            t.start()
            # Bounded wait for ready (no sleep-as-authority).
            deadline = time.monotonic() + 20.0
            while not ready_file.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert ready_file.exists(), (
                "workload+grandchild did not signal ready within 20s"
            )
            sup_pid = captures.get("supervisor_pid")
            sup_pgid = captures.get("supervisor_pgid")
            assert sup_pid is not None, "observer did not capture supervisor_pid"
            assert sup_pgid is not None, "observer did not capture supervisor_pgid"

            # Traverse: S -> I -> workload -> grandchild (host PIDs).
            def _read_children(pid):
                try:
                    raw = _P(f"/proc/{pid}/task/{pid}/children").read_text()
                    return [int(x) for x in raw.split()]
                except (FileNotFoundError, ProcessLookupError, ValueError):
                    return []

            # S -> I (namespace-init).
            i_children = _read_children(sup_pid)
            assert i_children, f"I not found in S children: {i_children}"
            i_pid = i_children[0]

            # I -> workload (bootstrap).
            wl_children = _read_children(i_pid)
            assert wl_children, f"workload not found in I children: {wl_children}"
            wl_pid = wl_children[0]

            # workload -> grandchild.
            gc_children = _read_children(wl_pid)
            assert gc_children, f"grandchild not found in workload children: {gc_children}"
            gc_pid = gc_children[0]

            # Assert host PGID and SID for every descendant == S PGID/SID.
            for label, pid in (("I", i_pid), ("workload", wl_pid),
                               ("grandchild", gc_pid)):
                assert os.getpgid(pid) == sup_pgid, (
                    f"{label} host PGID ({os.getpgid(pid)}) != S PGID ({sup_pgid})"
                )
                assert os.getsid(pid) == sup_pid, (
                    f"{label} host SID ({os.getsid(pid)}) != S PID ({sup_pid})"
                )
        finally:
            # Release the barrier so the workload+grandchild can exit.
            try:
                release_file.write_text("go")
            except OSError:
                pass
            SupervisedExecSession.observe = original_observe  # type: ignore
            t.join(timeout=15.0)
            assert not t.is_alive(), "supervised run thread did not terminate"
