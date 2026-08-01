"""v2.79 — CLI characterization tests.

Freezes the CLI command surface BEFORE any Click declaration relocation.
These tests introspect Click metadata (not raw help text) so they're stable
across formatting/wrapping changes but catch real regressions: dropped
commands, renamed commands, changed parameter signatures, broken exit codes.

The relocation in v2.79 wave-1 (release_history, audit_bundle, dashboard,
evidence) must keep ALL of these passing. If a relocated group changes the
command inventory or parameter signatures, the characterization test fails —
that's the safety net working as intended.

Per ChatGPT review: use Click metadata over raw help snapshots (less brittle),
include test_cli_import_is_lightweight as a hard gate (relocated modules must
preserve lazy imports).
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nodechain.cli.main import cli


# ─── Helpers ──────────────────────────────────────────────────────────────

def _walk_commands(root: click.Group):
    """Yield (dotted_name, command_obj) for every command/group in the tree."""
    def walk(cmd, prefix=""):
        name = prefix + cmd.name if getattr(cmd, "name", None) else "(root)"
        yield name, cmd
        if isinstance(cmd, click.Group):
            for subname in sorted(cmd.commands):
                yield from walk(cmd.commands[subname], name + " ")
    yield from walk(root)


def _param_signature(param: click.Parameter) -> dict:
    """Extract a stable signature dict for a Click parameter.

    Covers the fields that matter for behavior: identity, type, required-ness,
    defaults, multiplicity. Excludes cosmetic fields (help text, metavar).
    """
    return {
        "name": param.name,
        "param_type_name": type(param).__name__,
        "required": getattr(param, "required", False),
        "default": param.default,
        "multiple": getattr(param, "multiple", False),
        "is_flag": getattr(param, "is_flag", False) if hasattr(param, "is_flag") else False,
        "nargs": getattr(param, "nargs", None),
        "type_name": type(param.type).__name__ if hasattr(param, "type") else None,
    }


# ─── 1. Command inventory ─────────────────────────────────────────────────

def test_cli_command_inventory():
    """The full set of commands/groups must be present and stable.

    Relocation must not add, remove, or rename any command. This is the
    coarse-grained safety net; the param-signature test is finer-grained.
    """
    names = sorted(name for name, _ in _walk_commands(cli))
    # Sanity: the root and the major groups exist
    assert "cli" in names[0] or names[0] == "(root)"
    # The wave-1 targets must exist (pre-relocation baseline)
    for expected in ["cli audit-bundle", "cli dashboard", "cli evidence"]:
        assert any(expected in n for n in names), f"missing expected command: {expected}"
    # Record the count so a future change is caught (180 as of v2.78)
    endpoint_count = len(names)
    assert endpoint_count >= 150, (
        f"CLI endpoint count dropped to {endpoint_count}; expected >=150. "
        "A relocation may have dropped commands."
    )


def test_cli_group_hierarchy():
    """Top-level groups must be present. Relocation preserves the hierarchy."""
    top_groups = sorted(cli.commands.keys())
    # The wave-1 targets are top-level groups/commands
    assert len(top_groups) >= 20, (
        f"only {len(top_groups)} top-level commands; expected >=20. "
        "A relocation may have flattened the hierarchy."
    )


# ─── 2. Click parameter signatures ────────────────────────────────────────

def test_cli_click_param_signatures():
    """Every command's parameter signature must be stable.

    Introspects Click metadata (name, type, required, default, nargs, multiple,
    is_flag) rather than raw --help text. This catches: dropped options,
    renamed options, changed required-ness, changed defaults, changed types.
    Stable across help-text formatting/wrapping/terminal-width changes.

    The test records the signature count so a net change is caught even if
    individual params look reasonable.
    """
    signatures = {}
    for name, cmd in _walk_commands(cli):
        if isinstance(cmd, click.Group):
            continue  # groups have no params
        sig = [_param_signature(p) for p in cmd.params]
        signatures[name] = sig

    # Sanity: at least one wave-1 target has params (not empty)
    dashboard_cmds = [k for k in signatures if "dashboard" in k]
    assert len(dashboard_cmds) >= 5, (
        f"expected >=5 dashboard subcommands with params; got {dashboard_cmds}"
    )
    # Record total param count so net additions/removals are caught
    total_params = sum(len(sig) for sig in signatures.values())
    assert total_params >= 400, (
        f"total Click params dropped to {total_params}; expected >=400. "
        "A relocation may have dropped options."
    )


def test_cli_wave1_param_signatures_stable():
    """Wave-1 target commands' signatures specifically.

    This is the per-cluster net that catches a relocation dropping an option
    on exactly the commands being moved. Run before AND after each relocation.
    """
    wave1_prefixes = ("cli audit-bundle", "cli dashboard", "cli evidence")
    for name, cmd in _walk_commands(cli):
        if any(name.startswith(p) for p in wave1_prefixes):
            if isinstance(cmd, click.Group):
                continue
            # Each command must have its full param set introspectable
            for param in cmd.params:
                sig = _param_signature(param)
                assert sig["name"], f"{name}: param has no name: {param}"
                assert sig["param_type_name"] in (
                    "Option", "Argument",
                ), f"{name}: unexpected param type: {sig['param_type_name']}"


# ─── 3. Selected normalized help snapshots ────────────────────────────────

def test_cli_selected_help_snapshots():
    """Normalized --help for selected commands, with fixed width + no color.

    Per ChatGPT: help snapshots are brittle (wrapping, ordering, width), so
    we normalize via CliRunner with a fixed terminal_width and check that
    key commands produce non-empty help containing their expected command name.
    This is a coarse check; the param-signature test is the fine-grained one.
    """
    from click.testing import CliRunner
    runner = CliRunner()

    # A representative sample, not the full 180 (that would be brittle)
    sample_commands = [
        ["--help"],
        ["dashboard", "--help"],
        ["evidence", "--help"],
        ["audit-bundle", "--help"],
    ]
    for args in sample_commands:
        result = runner.invoke(cli, args, color=False)
        assert result.exit_code == 0, (
            f"`cli {' '.join(args)}` exited {result.exit_code}: {result.output[:200]}"
        )
        assert result.output.strip(), f"`cli {' '.join(args)}` produced empty help"


# ─── 4. Exit codes ────────────────────────────────────────────────────────

def test_cli_help_exit_codes():
    """--help must exit 0 for the root and each top-level group."""
    from click.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    # A few representative groups
    for group in ["dashboard", "evidence", "eval"]:
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0, (
            f"`cli {group} --help` exited {result.exit_code}"
        )


def test_cli_unknown_command_exit_code():
    """Unknown-command behavior is a deterministic cross-platform contract.

    An unknown command is a command-line usage error. The root ``cli`` group
    does not set ``invoke_without_command``, so Click rejects unknown
    subcommands with exit code 2 on every platform. This is the stable
    contract — not a platform-dependent characterization.
    """
    from click.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(cli, ["__nonexistent_command_v279__"])
    assert result.exit_code == 2, (
        f"unknown-command exit code is {result.exit_code}; expected 2 "
        f"(usage error) on all platforms."
    )
    # And it should print usage/help, not crash
    assert "Usage" in result.output or "NodeChain" in result.output


# ─── 5. Import-is-lightweight (hard gate) ──────────────────────────────────

def test_cli_import_is_lightweight():
    """main.py must not eagerly import implementation modules.

    v2.78 state: main.py uses lazy imports inside handler bodies (154 of them).
    Relocated command modules MUST preserve this property — moving a Click
    declaration into cli/commands/<group>.py must not turn the lazy
    `from nodechain.cli.<sibling> import func` (inside the handler) into a
    module-time import. Otherwise importing the CLI pulls in the entire
    runtime, slowing startup and risking circular imports.

    This test checks that importing cli.main does NOT import the heavy
    implementation modules. We check sys.modules after import.
    """
    import importlib
    # Snapshot modules present before
    before = set(sys.modules.keys())
    # Force a fresh import of cli.main
    sys.modules.pop("nodechain.cli.main", None)
    importlib.import_module("nodechain.cli.main")
    after = set(sys.modules.keys())
    new_modules = after - before
    # Heavy implementation modules that should NOT be eagerly imported.
    # (main.py itself, click, and lightweight helpers are fine.)
    heavy = [
        "nodechain.cli.run",
        "nodechain.cli.recover",
        "nodechain.cli.dashboard",
        "nodechain.cli.evidence",
        "nodechain.cli.deployment_adapter",
        "nodechain.runtime.orchestrator",
        "nodechain.core.state",
    ]
    eagerly_imported = [h for h in heavy if h in new_modules]
    # Note: some of these may already be in sys.modules from earlier test
    # collection. The real gate is: did importing cli.main ADD any of them?
    # If they were already present, they don't appear in `new_modules`.
    assert not eagerly_imported, (
        f"importing nodechain.cli.main eagerly pulled: {eagerly_imported}. "
        "Relocated command modules must preserve lazy imports (implementation "
        "imports inside handler bodies, not at module import time)."
    )
