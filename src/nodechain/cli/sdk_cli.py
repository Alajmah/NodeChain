"""CLI commands for registry and node operations."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from nodechain.cli.exit_codes import EXIT_NOT_FOUND
from rich.panel import Panel

from nodechain.registry.local_registry import RegistryIndex
from nodechain.sdk.package import NodePackage

console = Console()


def registry_list(extra_paths: list[str] | None = None) -> None:
    """List all registered node packages."""
    registry = RegistryIndex(extra_paths=extra_paths)
    packages = registry.list_packages()

    if not packages:
        console.print("[yellow]No node packages found in registry.[/yellow]")
        console.print("  Search paths: nodes/")
        sys.exit(0)

    table = Table(title="Node Registry", show_lines=False)
    table.add_column("Node ID", style="cyan", width=25)
    table.add_column("Name", style="green", width=25)
    table.add_column("Type", style="white", width=15)
    table.add_column("Version", style="yellow", width=10)
    table.add_column("Description", style="white", width=40)

    for pkg in packages:
        table.add_row(
            pkg["node_id"],
            pkg["name"],
            pkg["type"],
            pkg["version"],
            pkg["description"][:40],
        )

    console.print(table)
    console.print(f"\n  {len(packages)} packages registered")


def registry_inspect(node_id: str, extra_paths: list[str] | None = None) -> None:
    """Show detailed info about a registered node."""
    registry = RegistryIndex(extra_paths=extra_paths)
    info = registry.inspect(node_id)

    if info is None:
        console.print(f"[red]Node '{node_id}' not found in registry.[/red]")
        sys.exit(2)

    # Header
    console.print(Panel(
        f"[bold]Node ID:[/bold]       {info['node_id']}\n"
        f"[bold]Name:[/bold]          {info['name']}\n"
        f"[bold]Type:[/bold]          {info['type']}\n"
        f"[bold]Version:[/bold]       {info['version']}\n"
        f"[bold]Description:[/bold]   {info['description']}",
        title=f"[bold blue]{info['node_id']}[/bold blue]",
    ))

    # Contract
    contract = info["contract"]
    console.print(f"\n[bold]Contract:[/bold] {contract['contract_id']} v{contract['version']}")

    entry = contract["entry"]
    exit_c = contract["exit"]

    console.print(f"  [green]Entry:[/green]   {entry['input_type']}")
    console.print(f"    Required: {', '.join(entry['required_fields']) or 'none'}")
    console.print(f"    Schema:   {entry['schema_ref']}")

    console.print(f"  [green]Exit:[/green]    {exit_c['output_type']}")
    console.print(f"    Guaranteed: {', '.join(exit_c['guaranteed_fields']) or 'none'}")
    console.print(f"    Schema:     {exit_c['schema_ref']}")


def registry_lock(output_path: str | None = None, include_blocked: bool = False) -> None:
    """Generate a registry lockfile."""
    from nodechain.sdk.lockfile import generate_lockfile
    from rich.table import Table

    lockfile = generate_lockfile(output_path=output_path, include_blocked=include_blocked)

    console.print(f"[green]Lockfile generated:[/green] {output_path or 'registry.lock.json'}")
    console.print(f"  Packages: {lockfile['package_count']}")
    console.print(f"  Generated: {lockfile['generated_at']}")

    table = Table(title="Locked Packages")
    table.add_column("Node ID", style="cyan")
    table.add_column("Version")
    table.add_column("Hash", style="dim")

    for pkg in lockfile["packages"]:
        table.add_row(
            pkg["node_id"],
            pkg["version"],
            pkg["content_hash"],
        )

    console.print(table)


def registry_verify(lockfile_path: str | None = None) -> None:
    """Verify registry against lockfile."""
    from nodechain.sdk.lockfile import verify_lockfile

    result = verify_lockfile(lockfile_path)

    if not result.get("valid", False) and "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        sys.exit(2)

    if result["valid"]:
        console.print(f"[green]Registry CLEAN[/green] -- all {result['locked_count']} packages match lockfile")
    else:
        console.print(f"[red]Registry DRIFTED[/red]")

        for m in result.get("mismatches", []):
            console.print(f"  [yellow]MISMATCH[/yellow] {m['node_id']}: {m['field']}")
            console.print(f"    locked: {m.get('locked', '?')} current: {m.get('current', '?')}")
            console.print(f"    {m.get('reason', '')}")

        for m in result.get("missing", []):
            console.print(f"  [red]MISSING[/red] {m['node_id']} (v{m.get('locked_version', '?')})")
            console.print(f"    {m.get('reason', '')}")

        for e in result.get("extra", []):
            console.print(f"  [blue]NEW[/blue] {e['node_id']} (v{e.get('current_version', '?')})")

        sys.exit(1)  # Lockfile drift — EXIT_RECONCILE_ERRORS


def node_validate(path: str) -> None:
    """Validate a node package at the given path."""
    pkg_path = Path(path)

    if not pkg_path.exists():
        console.print(f"[red]Path not found: {path}[/red]")
        sys.exit(2)

    # Try multi-node package first (package.yaml), then single-node (node.yaml)
    is_multi = False
    if (pkg_path / "package.yaml").exists():
        from nodechain.sdk.multi_package import MultiNodePackage
        try:
            multi = MultiNodePackage.from_directory(pkg_path)
            is_multi = True
            issues = multi.validate_package()
            if issues:
                console.print(f"[red]Validation FAILED for {multi.package_id}:[/red]")
                for issue in issues:
                    console.print(f"  X {issue}")
                sys.exit(10)
            console.print(f"[green]Validation PASSED for {multi.package_id}[/green]")
            console.print(f"  Nodes: {', '.join(multi.node_ids)}")
            console.print(f"  Type:  multi-node package")
            _render_capabilities_and_deps(pkg_path)
            return
        except Exception as e:
            console.print(f"[red]Failed to load multi-node package: {e}[/red]")
            sys.exit(10)

    try:
        pkg = NodePackage.from_directory(pkg_path)
    except Exception as e:
        console.print(f"[red]Failed to load package: {e}[/red]")
        sys.exit(10)

    issues = pkg.validate_package()

    if issues:
        console.print(f"[red]Validation FAILED for {pkg.manifest.node_id}:[/red]")
        for issue in issues:
            console.print(f"  X {issue}")
        sys.exit(10)

    console.print(f"[green]Validation PASSED for {pkg.manifest.node_id}[/green]")
    console.print(f"  Name:    {pkg.manifest.name}")
    console.print(f"  Type:    {pkg.manifest.node_type}")
    console.print(f"  Version: {pkg.manifest.version}")
    console.print(f"  Entry:   {pkg.manifest.contract.entry.input_type}")
    console.print(f"  Exit:    {pkg.manifest.contract.exit.output_type}")

    # Content hash
    pkg_hash = pkg.content_hash()
    if pkg_hash:
        console.print(f"  Hash:    {pkg_hash}")

    # Semver check
    semver_issues = pkg.validate_semver()
    if semver_issues:
        console.print(f"  [yellow]Semver warnings:[/yellow]")
        for issue in semver_issues:
            console.print(f"    ! {issue}")

    # Trust warning
    console.print(f"  [yellow]Trust: local code execution -- do not load untrusted packages[/yellow]")

    # Capabilities and dependencies
    _render_capabilities_and_deps(pkg_path)


def _render_capabilities_and_deps(pkg_path: Path) -> None:
    """Render capabilities, dependencies, entrypoints from package yaml."""
    pkg_yaml_path = pkg_path / "node.yaml" if (pkg_path / "node.yaml").exists() else pkg_path / "package.yaml"
    if pkg_yaml_path.exists():
        try:
            import yaml as _yaml
            raw = _yaml.safe_load(pkg_yaml_path.read_text())

            caps = raw.get("capabilities", {})
            if caps:
                console.print(f"  [cyan]Capabilities:[/cyan]")
                for k, v in caps.items():
                    console.print(f"    {k}: {v}")

            deps = raw.get("dependencies", {})
            py_deps = deps.get("python", [])
            if py_deps:
                console.print(f"  [cyan]Dependencies:[/cyan]")
                for dep in py_deps:
                    if isinstance(dep, dict):
                        console.print(f"    {dep.get('package', '?')} {dep.get('version_constraint', '')}")
                    else:
                        console.print(f"    {dep}")

            entrypoint = raw.get("entrypoint")
            if entrypoint:
                console.print(f"  [cyan]Entrypoint:[/cyan] {entrypoint}")

            entrypoints = raw.get("entrypoints", [])
            if entrypoints:
                console.print(f"  [cyan]Entrypoints:[/cyan]")
                for ep in entrypoints:
                    se = ep.get("side_effects", [])
                    se_str = f", side_effects={se}" if se else ""
                    console.print(f"    {ep['node_id']}: {ep['implementation']}{se_str}")

            se = raw.get("side_effects", [])
            if se:
                console.print(f"  [cyan]Side effects:[/cyan] {', '.join(se)}")

            # AC7: Policy status
            min_ver = raw.get("nodechain_min_version", "")
            if min_ver:
                from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer
                enforcer = PackagePolicyEnforcer()
                ok, msg = enforcer.check_version(min_ver)
                status = "[green]PASS[/green]" if ok else "[red]BLOCK[/red]"
                console.print(f"  [cyan]Version gate:[/cyan] {status} ({msg})")

            if caps:
                strict_note = " (enforced in strict mode)" if os.environ.get("NODECHAIN_GOVERNANCE_STRICT") == "1" else " (declared, not enforced)"
                console.print(f"  [dim]Capabilities are declarations{strict_note}[/dim]")
        except Exception:
            pass


def node_test(path: str) -> None:
    """Run package-local tests for a node package."""
    import subprocess

    pkg_path = Path(path)

    if not pkg_path.exists():
        console.print(f"[red]Path not found: {path}[/red]")
        sys.exit(2)

    try:
        pkg = NodePackage.from_directory(pkg_path)
    except Exception as e:
        console.print(f"[red]Failed to load package: {e}[/red]")
        sys.exit(10)

    test_path = pkg.get_test_path()

    if test_path is None:
        console.print(f"[yellow]No tests found for {pkg.manifest.node_id}[/yellow]")
        console.print(f"  Expected: {pkg_path}/tests/test_*.py")
        sys.exit(0)

    console.print(f"Running tests for {pkg.manifest.node_id}...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
        capture_output=True,
        text=True,
    )

    console.print(result.stdout)
    if result.stderr:
        console.print(result.stderr)

    sys.exit(result.returncode)
