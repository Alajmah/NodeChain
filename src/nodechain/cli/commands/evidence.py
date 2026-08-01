"""v2.79 — Click declarations for the evidence command group.

Relocated from cli/main.py (was inline at L4710-4833). The implementation
logic stays in cli/evidence.py; this module holds only the Click declaration
shell + lazy delegation. Behavior is identical to the pre-relocation code.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="evidence")
def evidence_group() -> None:
    """Evidence indexing, querying, and timelines (v1.17.0)."""


@evidence_group.command(name="index")
@click.option("--input", "input_path", required=True, help="Artifact file or directory")
@click.option("--output", "-o", default="", help="Output evidence index JSON")
def evidence_index_cmd(input_path: str, output: str) -> None:
    """Build an evidence index from artifacts (v1.17.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evidence import build_evidence_index

    try:
        out = output or "evidence_index.json"
        index = build_evidence_index(input_path, output_path=out)
        console.print(f"[green]\u2705 Evidence index built[/green]")
        console.print(f"  Entries: {index['entry_count']}")
        console.print(f"  Types:   {', '.join(index['artifact_types'])}")
        console.print(f"  Digest:  {index['evidence_index_digest'][:16]}...")
    except Exception as e:
        console.print(f"[red]\u274c Failed to build index: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@evidence_group.command(name="query")
@click.option("--index", "index_path", required=True, help="Evidence index JSON")
@click.option("--filter", "filters", multiple=True, help="Filter as key=value (repeatable)")
@click.option("--time-from", default="", help="ISO timestamp lower bound")
@click.option("--time-until", default="", help="ISO timestamp upper bound")
def evidence_query_cmd(index_path: str, filters: tuple, time_from: str, time_until: str) -> None:
    """Query evidence index with filters (v1.17.0)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.evidence import query_evidence

    filter_dict: dict[str, str] = {}
    for f in filters:
        if "=" in f:
            k, v = f.split("=", 1)
            filter_dict[k.strip()] = v.strip()

    results = query_evidence(index_path, filters=filter_dict, time_from=time_from, time_until=time_until)
    console.print(f"[green]Found {len(results)} matching entries[/green]")
    for r in results:
        console.print(f"  [{r['artifact_type']}] {r.get('target_ref', '')} ({r.get('artifact_digest', '')[:16]}...)")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@evidence_group.command(name="timeline")
@click.option("--index", "index_path", required=True, help="Evidence index JSON")
@click.option("--target", default="", help="Target reference to filter")
@click.option("--target-digest", default="", help="Target digest to filter")
@click.option("--output", "-o", default="", help="Output timeline JSON")
def evidence_timeline_cmd(index_path: str, target: str, target_digest: str, output: str) -> None:
    """Build an operational timeline for a target (v1.17.0)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.evidence import build_timeline

    timeline = build_timeline(index_path, target=target, target_digest=target_digest)

    if output:
        Path(output).write_text(json.dumps(timeline, indent=2, sort_keys=True), encoding="utf-8")

    console.print(f"[green]\u2705 Timeline built[/green]")
    console.print(f"  Events: {timeline['event_count']}")
    for event in timeline["events"]:
        console.print(f"  [{event['artifact_type']}] {event['summary']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@evidence_group.command(name="sign")
@click.option("--report", "report_path", required=True, help="Evidence report JSON")
@click.option("--key", "key_path", required=True, help="Private key PEM")
@click.option("--output", "-o", default="", help="Output signed report JSON")
def evidence_sign_cmd(report_path: str, key_path: str, output: str) -> None:
    """Sign an evidence report (v1.17.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evidence import sign_evidence_report

    try:
        out = output or report_path
        signed = sign_evidence_report(report_path, key_path, output_path=out)
        console.print(f"[green]\u2705 Evidence report signed[/green]")
        console.print(f"  Fingerprint: {signed.get('evidence_signer_fingerprint', '')}")
    except Exception as e:
        console.print(f"[red]\u274c Failed to sign: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@evidence_group.command(name="verify")
@click.option("--report", "report_path", required=True, help="Evidence report JSON")
@click.option("--pubkey", default="", help="Public key PEM")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
def evidence_verify_cmd(report_path: str, pubkey: str, ts_path: str) -> None:
    """Verify a signed evidence report (v1.17.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evidence import verify_evidence_report

    result = verify_evidence_report(report_path, public_key_pem=pubkey, trust_store_path=ts_path)
    if result["valid"]:
        console.print(f"[green]\u2705 Evidence report valid[/green]")
        console.print(f"  Trusted: {result['details']['signer_trusted']}")
    else:
        console.print(f"[red]\u274c Evidence report invalid[/red]")
        for err in result["errors"]:
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


def register(cli: click.Group) -> None:
    """Wire the evidence group into the root CLI."""
    cli.add_command(evidence_group)
