"""v2.80 — Click declarations for the console command group.

Relocated from cli/main.py (was inline at L4995-5166). The implementation
logic stays in cli/sdk/governance_console.py; this module holds only the
Click declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.
"""
from __future__ import annotations

from pathlib import Path

import click

@click.group(name="console")
def console_group() -> None:
    """Operator-facing governance console (v2.20.0).

    OC-001: Read-only operator surface over materialized artifacts.
    The console never mutates runtime state or makes policy decisions.
    """
    pass


@console_group.command(name="open")
@click.option("--graph", "-g", type=click.Path(exists=True), required=True,
              help="Path to graph JSON file (from 'nodechain graph export')")
@click.option("--mode", "-m", type=click.Choice(["terminal", "json", "html"]), default="terminal",
              help="Output mode (default: terminal)")
@click.option("--section", "-s", type=click.Choice([
    "summary", "warnings", "health", "capabilities", "branches", "receipts", "all",
]), default="all", help="Console section to display")
@click.option("--inspect", "-i", type=str, default=None,
              help="Inspect a specific node by ID")
@click.option("--nodes", "-n", type=str, default=None,
              help="List nodes by type group (e.g. package, capability, branch)")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (default: stdout)")
@click.pass_context
def console_open(
    ctx: click.Context,
    graph: str,
    mode: str,
    section: str,
    inspect: str | None,
    nodes: str | None,
    output: str | None,
) -> None:
    """Open the governance console over a graph artifact.

    OC-001: The console is strictly read-only. It loads graph JSON,
    validates its digest, and renders inspectable views.

    Examples:
      nodechain console open --graph graph.json
      nodechain console open --graph graph.json --mode json
      nodechain console open --graph graph.json --inspect node_id
      nodechain console open --graph graph.json --nodes package
      nodechain console open --graph graph.json --section health
      nodechain console open --graph graph.json --mode html -o console.html
    """
    from nodechain.sdk.governance_console import GovernanceConsole, OC_001

    console = GovernanceConsole()
    console.load_from_file(graph)

    if not console.validate():
        click.echo("Error: Graph digest validation failed — refusing to render", err=True)
        ctx.exit(10)

    # Determine output
    if inspect:
        try:
            view = console.inspect_node(inspect)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
            ctx.exit(2)
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif nodes:
        view = console.nodes_by_type(nodes)
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif section == "summary":
        view = console.summary()
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif section == "warnings":
        view = console.render_warnings()
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif section == "health":
        view = console.health_by_severity()
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif section == "capabilities":
        view = console.capability_candidates()
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif section == "branches":
        view = console.branch_results()
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif section == "receipts":
        view = console.receipts()
        content = view.terminal_text if mode == "terminal" else view.to_json()
    elif mode == "html":
        content = console.render_html()
    elif mode == "json":
        content = console.render_all_json()
    else:
        # terminal + all
        content = console.render_all_terminal()

    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Console output written to {output}")
    else:
        click.echo(content)


@console_group.command(name="serve")
@click.option("--graph", "-g", type=click.Path(exists=True), required=True,
              help="Path to graph JSON file")
@click.option("--port", "-p", type=int, default=8700,
              help="Port for local server (default: 8700)")
@click.option("--host", "-h", type=str, default="127.0.0.1",
              help="Host to bind (default: 127.0.0.1 — use --allow-remote-console for non-local)")
@click.option("--allow-remote-console", is_flag=True, default=False,
              help="Explicitly allow binding to non-localhost interfaces")
@click.pass_context
def console_serve(
    ctx: click.Context,
    graph: str,
    port: int,
    host: str,
    allow_remote_console: bool,
) -> None:
    """Serve the governance console as a local HTML page.

    OC-001: The console is read-only. The server serves a static HTML
    rendering generated from the graph JSON. No runtime mutation.

    Security: Binds to 127.0.0.1 by default (CONSOLE-002).
    Use --host 0.0.0.0 --allow-remote-console to expose externally.
    """
    import http.server
    import socketserver

    from nodechain.sdk.governance_console import GovernanceConsole

    # Security check: reject non-localhost binding without explicit flag (CONSOLE-002)
    safe_hosts = {"127.0.0.1", "localhost", "::1"}
    if host not in safe_hosts and not allow_remote_console:
        click.echo(
            f"Error: Refusing to bind to '{host}' without --allow-remote-console.\n"
            f"The governance console binds to 127.0.0.1 by default for security.\n"
            f"If you intentionally want to expose it, add --allow-remote-console.",
            err=True,
        )
        ctx.exit(10)

    console = GovernanceConsole()
    console.load_from_file(graph)

    if not console.validate():
        click.echo("Error: Graph digest validation failed", err=True)
        ctx.exit(10)

    html_content = console.render_html()

    class ConsoleHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # Content-Security-Policy: no scripts, no external resources (CONSOLE-001)
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none';",
            )
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))

        def log_message(self, format, *args):
            pass  # Suppress default logging

    click.echo(f"NodeChain Governance Console serving at http://{host}:{port}")
    click.echo("  Read-only (OC-001). Press Ctrl+C to stop.")
    with socketserver.TCPServer((host, port), ConsoleHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            click.echo("\nConsole server stopped.")


def register(cli: click.Group) -> None:
    """Wire the console group into the root CLI."""
    cli.add_command(console_group)
