"""v2.79 — Click declaration for the audit-bundle command.

Relocated from cli/main.py (was inline at L1334-1401). The implementation
logic stays in cli/audit_bundle.py (and cli/bundle_signing.py); this module
holds only the Click declaration shell + lazy delegation. Behavior is
identical to the pre-relocation code.

This is a STANDALONE command (not a group), so register(cli) wires the
command directly into the root CLI.
"""
from __future__ import annotations

import click
from rich.console import Console

console = Console()


@click.command(name="audit-bundle")
@click.argument("run_id_or_zip", required=True)
@click.option("--db", "db_path", default="data/chain_state.db", help="Path to chain state database")
@click.option("--trace-dir", "-t", default="data/traces", help="Directory for trace files")
@click.option("--output", "-o", default="", help="Output ZIP file path")
@click.option("--strict", is_flag=True, default=False, help="Exit 15 if trust violations exist")
@click.option("--verify", "verify_path", default=None, help="Verify a bundle ZIP instead of generating")
@click.option("--sign", "sign_key", default="", help="Sign bundle with this private key PEM")
@click.option("--pubkey", "pubkey_path", default="", help="Public key PEM for signature verification")
@click.option("--generate-keys", "key_dir", default=None, help="Generate signing key pair in this directory")
@click.option("--require-signature", is_flag=True, default=False, help="Fail verification if bundle is not signed (CI mode)")
def audit_bundle_cmd(run_id_or_zip: str, db_path: str, trace_dir: str, output: str, strict: bool,
                 verify_path: str | None, sign_key: str, pubkey_path: str, key_dir: str | None,
                 require_signature: bool) -> None:
    """Generate or verify a portable sandbox audit bundle for a chain run.

    Generate:  nodechain audit-bundle <run_id> --output bundle.zip
    Verify:    nodechain audit-bundle <run_id> --verify bundle.zip
    Sign:      nodechain audit-bundle <run_id> --sign private.pem
    Verify+Sig: nodechain audit-bundle x --verify bundle.zip --pubkey public.pem
    Gen Keys:  nodechain audit-bundle x --generate-keys ~/.nodechain/keys

    Use --strict for CI mode (exit 15 on trust violations).
    """
    from nodechain.cli.audit_bundle import generate_audit_bundle, verify_audit_bundle
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION

    # Key generation mode
    if key_dir:
        from nodechain.cli.bundle_signing import generate_key_pair
        result = generate_key_pair(key_dir)
        console.print(f"[green]Key pair generated:[/green]")
        console.print(f"  Private: {result['private_key_path']}")
        console.print(f"  Public:  {result['public_key_path']}")
        console.print(f"  Fingerprint: {result['fingerprint']}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
        return

    if verify_path:
        result = verify_audit_bundle(verify_path, pubkey_path=pubkey_path, require_signature=require_signature)
        if result["valid"]:
            console.print(f"[green]✅ Bundle valid: {verify_path}[/green]")
            console.print(f"  Files checked: {result['files_checked']}")
            console.print(f"  Schema versions: {result['schema_versions']}")
            if result.get('manifest_entries'):
                console.print(f"  Manifest entries: {result['manifest_entries']}")
            console.print(f"  Signature: {result.get('signature_status', 'not_checked')}")
            if result.get('signature_reason'):
                console.print(f"  Signature reason: {result['signature_reason']}")
            if result["warnings"]:
                console.print(f"  Warnings: {len(result['warnings'])}")
                for w in result["warnings"]:
                    console.print(f"    - {w}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_OK)
        else:
            console.print(f"[red]❌ Bundle invalid: {verify_path}[/red]")
            for e in result["errors"]:
                console.print(f"  ERROR: {e}")
            for w in result["warnings"]:
                console.print(f"  WARN: {w}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_VALIDATION)
    else:
        code = generate_audit_bundle(run_id_or_zip, db_path, trace_dir, output, strict, sign_key=sign_key)
        ctx = click.get_current_context()
        ctx.exit(code)


def register(cli: click.Group) -> None:
    """Wire the audit-bundle command into the root CLI."""
    cli.add_command(audit_bundle_cmd)
