"""v2.79 — Click declarations for the release-history command group.

Relocated from cli/main.py (was inline at L3585-3772). The implementation
logic stays in cli/release_history.py; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.
"""
from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="release-history")
def release_history_group() -> None:
    """Manage release history and retention (v1.13.6)."""


@release_history_group.command(name="list")
@click.option("--target", default="", help="Filter by target")
@click.option("--limit", default=20, help="Maximum releases to show")
def release_history_list_cmd(target: str, limit: int) -> None:
    """List releases in the release history."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.release_history import ReleaseHistory

    history = ReleaseHistory()
    releases = history.list_releases(target=target, limit=limit)

    if not releases:
        console.print("[yellow]No releases in history.[/yellow]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)

    console.print(f"[bold]Release History[/bold] ({len(releases)} releases)")
    for r in releases:
        state_color = "green" if r.is_known_good else "red"
        state_label = "known-good" if r.is_known_good else r.final_deployment_state
        console.print(
            f"  [{state_color}]{r.release_id[:12]}[/{state_color}] "
            f"artifact={r.artifact_digest[:12]}... "
            f"state={state_label} "
            f"target={r.target} "
            f"created={r.created_at[:19]}"
        )
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@release_history_group.command(name="verify")
@click.option("--release-id", default="", help="Verify specific release")
@click.option("--require-chain", is_flag=True, default=False, help="Require assurance chain")
@click.option("--integrity", is_flag=True, default=False, help="Full integrity check (v1.13.7)")
def release_history_verify_cmd(release_id: str, require_chain: bool, integrity: bool) -> None:
    """Verify release retention and integrity."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.release_history import ReleaseHistory

    history = ReleaseHistory()

    # v1.13.7: Full integrity check
    if integrity:
        ir = history.verify_integrity()
        if ir["valid"]:
            console.print(f"[green]✅ Release history integrity verified[/green]")
            console.print(f"  schema_version: {history.schema_version}")
            console.print(f"  release_history_id: {history.release_history_id[:16]}...")
            console.print(f"  entries_digest: {history.entries_digest[:16]}...")
            console.print(f"  total releases: {len(history.releases)}")
            for check, val in ir.get("checks", {}).items():
                console.print(f"  {check}: {val}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_OK)
        else:
            console.print(f"[red]❌ Release history integrity check failed[/red]")
            for e in ir.get("errors", []):
                console.print(f"  ERROR: {e}")
            for w in ir.get("warnings", []):
                console.print(f"  WARN: {w}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_VALIDATION)

    result = history.verify_retention(release_id=release_id, require_chain=require_chain)

    if result["valid"]:
        console.print(f"[green]✅ Release retention verified: {release_id or 'all'}[/green]")
        for check, val in result.get("checks", {}).items():
            console.print(f"  {check}: {val}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
    else:
        console.print(f"[red]❌ Retention verification failed: {release_id or 'all'}[/red]")
        for e in result.get("errors", []):
            console.print(f"  ERROR: {e}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)


@release_history_group.command(name="latest-known-good")
@click.option("--target", default="", help="Target to filter by")
def release_history_latest_cmd(target: str) -> None:
    """Show the latest known-good release for a target."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_NOT_FOUND
    from nodechain.cli.release_history import ReleaseHistory

    history = ReleaseHistory()
    record = history.latest_known_good(target=target)

    if record:
        console.print(f"[green]Latest known-good release:[/green]")
        console.print(f"  Release ID:     {record.release_id}")
        console.print(f"  Artifact:       {record.artifact_digest}")
        console.print(f"  Target:         {record.target}")
        console.print(f"  State:          {record.final_deployment_state}")
        console.print(f"  Verified:       {record.activation_verified}")
        console.print(f"  Created:        {record.created_at}")
        console.print(f"  Receipt digest: {record.deployment_receipt_digest[:24]}...")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
    else:
        label = f" for target={target}" if target else ""
        console.print(f"[yellow]No known-good release found{label}.[/yellow]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)


@release_history_group.command(name="snapshot")
@click.option("--output", "-o", default="", help="Output snapshot JSON path")
@click.option("--sign", "sign_key", default="", help="Sign snapshot with private key PEM")
@click.option("--history-path", default="", help="Release history file path")
def release_history_snapshot_cmd(output: str, sign_key: str, history_path: str) -> None:
    """Create a snapshot of the release history (v1.13.8)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.release_history import create_release_history_snapshot

    try:
        snapshot = create_release_history_snapshot(
            output_path=output,
            private_key_path=sign_key,
            history_path=history_path,
        )
        console.print(f"[green]✅ Release history snapshot created[/green]")
        console.print(f"  Schema version:     {snapshot['schema_version']}")
        console.print(f"  History ID:         {snapshot['release_history_id'][:16]}...")
        console.print(f"  Entries digest:     {snapshot['entries_digest'][:16]}...")
        console.print(f"  Audit log digest:   {snapshot['audit_log_digest'][:16]}...")
        console.print(f"  Release count:      {snapshot['release_count']}")
        console.print(f"  Snapshot digest:    {snapshot['snapshot_digest'][:16]}...")
        if snapshot.get("snapshot_signature"):
            console.print(f"  Signed:             yes ({snapshot.get('snapshot_signer_fingerprint', '')[:16]}...)")
        else:
            console.print(f"  Signed:             no")
        if output:
            console.print(f"  Written to:         {output}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)


@release_history_group.command(name="verify-snapshot")
@click.option("--snapshot", "snapshot_path", required=True, help="Snapshot JSON path")
@click.option("--pubkey", "pubkey_path", default="", help="Public key PEM for signature verification")
@click.option("--check-live", is_flag=True, default=False, help="Compare against live release history")
@click.option("--history-path", default="", help="Release history file path")
def release_history_verify_snapshot_cmd(
    snapshot_path: str, pubkey_path: str, check_live: bool, history_path: str
) -> None:
    """Verify a release history snapshot (v1.13.8)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.release_history import verify_release_history_snapshot

    pubkey_pem = ""
    if pubkey_path:
        pubkey_pem = Path(pubkey_path).read_text(encoding="utf-8")

    result = verify_release_history_snapshot(
        snapshot_path=snapshot_path,
        public_key_pem=pubkey_pem,
        check_live_history=check_live,
        history_path=history_path,
    )

    if result["valid"]:
        console.print(f"[green]✅ Release history snapshot verified: {snapshot_path}[/green]")
        for check, val in result.get("details", {}).items():
            console.print(f"  {check}: {val}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
    else:
        console.print(f"[red]❌ Snapshot verification failed: {snapshot_path}[/red]")
        for e in result.get("errors", []):
            console.print(f"  ERROR: {e}")
        for w in result.get("warnings", []):
            console.print(f"  WARN: {w}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)


def register(cli: click.Group) -> None:
    """Wire the release-history group into the root CLI."""
    cli.add_command(release_history_group)
