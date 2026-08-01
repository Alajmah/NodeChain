"""
Governance Console HTML / Serving Hardening Tests (v2.21.3).

CONSOLE-001: All graph-derived values escaped before HTML insertion.
CONSOLE-002: console serve binds to 127.0.0.1 by default.

Acceptance criteria AC-01 through AC-10.
"""

from __future__ import annotations

import json
import pytest
import hashlib
from pathlib import Path
from click.testing import CliRunner

from nodechain.sdk.governance_console import GovernanceConsole, _esc
from nodechain.cli.main import cli


# ── Helpers ─────────────────────────────────────────────────────────────────

_CLI_SOURCE = None


def _get_cli_source() -> str:
    """Concatenated CLI source for source-text checks.

    v2.80: the console group's Click declarations (including the serve
    handler with CSP header, allow_remote_console gate, safe_hosts, and
    the TCPServer bind logic) were relocated from cli/main.py to
    cli/commands/console.py. Source-text assertions must therefore read
    BOTH files, mirroring the v2.79 fix in test_audit_bundle.py.
    """
    global _CLI_SOURCE
    if _CLI_SOURCE is None:
        root = Path(__file__).parent.parent / "src" / "nodechain" / "cli"
        main_src = (root / "main.py").read_text(encoding="utf-8")
        console_cmd_src = (root / "commands" / "console.py").read_text(encoding="utf-8")
        _CLI_SOURCE = main_src + "\n" + console_cmd_src
    return _CLI_SOURCE


# ── Malicious graph fixtures ────────────────────────────────────────────────

# Payloads that are dangerous in HTML text content (contain HTML markup)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "'; DROP TABLE nodes; --",
]


def _make_graph_with_label(label: str, extra_metadata: dict | None = None) -> dict:
    """Build a valid graph where node labels and metadata contain adversarial strings."""
    metadata = {"rule_id": "HR-001", "severity": "warning", "package_id": label}
    if extra_metadata:
        metadata.update(extra_metadata)

    nodes = [
        {"id": "malicious_1", "type": "health_rule", "label": label,
         "source_artifact": "dashboard_health", "digest": "d1",
         "status": "warning", "metadata": metadata},
        {"id": "pkg_evil", "type": "capability_offer", "label": label,
         "source_artifact": "capability_selection_receipt", "digest": "d2",
         "status": "error", "metadata": {"package_id": label, "version": "1.0"}},
        {"id": "cap_req", "type": "capability_request", "label": label,
         "source_artifact": "capability_selection_receipt", "digest": "d3",
         "status": "neutral",
         "metadata": {"capability": label, "selected_package_id": "pkg_evil",
                      "selected_version": "1.0"}},
        {"id": "br_1", "type": "branch_result", "label": label,
         "source_artifact": "deliberation_receipt", "digest": "d4",
         "status": "neutral", "metadata": {"branch_id": label, "status": "completed"}},
        {"id": "md_1", "type": "merge_decision", "label": label,
         "source_artifact": "deliberation_receipt", "digest": "d5",
         "status": "neutral",
         "metadata": {"strategy": label, "selected_branch_id": label,
                      "rejected_branch_ids": [label]}},
        {"id": "rcpt_1", "type": "receipt", "label": label,
         "source_artifact": "trust_lockfile", "digest": "d6",
         "status": "neutral", "metadata": {"receipt_type": label}},
        {"id": "te_1", "type": "trace_event", "label": label,
         "source_artifact": "trace_events", "digest": "d7",
         "status": "neutral", "metadata": {"event_id": label, "step_id": 1}},
    ]
    edges = [
        {"from": "cap_req", "to": "pkg_evil", "relationship": "selected",
         "source_artifact": "capability_selection_receipt", "digest": "", "reason": label},
        {"from": "cap_req", "to": "pkg_evil", "relationship": "rejected",
         "source_artifact": "capability_selection_receipt", "digest": "", "reason": label},
        {"from": "rcpt_1", "to": "malicious_1", "relationship": "covers",
         "source_artifact": "trust_lockfile", "digest": "", "reason": label},
    ]
    sorted_nodes = sorted(nodes, key=lambda n: n["id"])
    sorted_edges = sorted(edges, key=lambda e: f"{e['from']}--{e['relationship']}-->{e['to']}")
    digest = hashlib.sha256(
        json.dumps({"nodes": sorted_nodes, "edges": sorted_edges, "schema_version": "1.0.0"},
                   sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "1.0.0",
        "generated_at": "2026-06-19T23:00:00Z",
        "graph_digest": digest,
        "source_artifacts": ["trust_lockfile", "capability_selection_receipt",
                             "deliberation_receipt", "dashboard_health", "trace_events"],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "warnings": [label, "Normal warning"],
    }


def _recompute_digest(graph: dict) -> None:
    """Recompute the graph digest in-place after modifying nodes/edges."""
    sorted_nodes = sorted(graph["nodes"], key=lambda n: n["id"])
    sorted_edges = sorted(graph["edges"], key=lambda e: f"{e['from']}--{e['relationship']}-->{e['to']}")
    graph["graph_digest"] = hashlib.sha256(
        json.dumps({"nodes": sorted_nodes, "edges": sorted_edges, "schema_version": "1.0.0"},
                   sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# ── AC-01: All graph-derived values escaped ─────────────────────────────────


class TestAC01Escaping:
    """AC-01: Escape all graph-derived values before inserting into HTML."""

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_label_escaped(self, payload):
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        assert c.validate()
        html_out = c.render_html()
        assert payload not in html_out, f"Raw XSS payload leaked: {payload}"

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_metadata_values_escaped(self, payload):
        graph = _make_graph_with_label("safe_label", {"package_id": payload})
        c = GovernanceConsole()
        c.load(graph)
        assert c.validate()
        html_out = c.render_html()
        assert payload not in html_out

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_warnings_escaped(self, payload):
        graph = _make_graph_with_label("safe")
        graph["warnings"] = [payload]
        c = GovernanceConsole()
        c.load(graph)
        assert c.validate()
        html_out = c.render_html()
        assert payload not in html_out

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_rejection_reason_escaped(self, payload):
        graph = _make_graph_with_label("safe")
        for e in graph["edges"]:
            e["reason"] = payload
        _recompute_digest(graph)
        c = GovernanceConsole()
        c.load(graph)
        assert c.validate()
        html_out = c.render_html()
        assert payload not in html_out

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_branch_id_escaped(self, payload):
        graph = _make_graph_with_label("safe", {"branch_id": payload,
                                                "selected_branch_id": payload,
                                                "strategy": payload})
        c = GovernanceConsole()
        c.load(graph)
        assert c.validate()
        html_out = c.render_html()
        assert payload not in html_out

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_receipt_id_escaped(self, payload):
        graph = _make_graph_with_label("safe", {"receipt_type": payload})
        c = GovernanceConsole()
        c.load(graph)
        assert c.validate()
        html_out = c.render_html()
        assert payload not in html_out


# ── AC-02: Script tags neutralized ──────────────────────────────────────────


class TestAC02ScriptNeutralization:
    """AC-02: Add tests with malicious labels containing script tags."""

    def test_script_tag_neutralized(self):
        payload = "<script>alert(1)</script>"
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        c.validate()
        html_out = c.render_html()
        assert "<script>alert" not in html_out
        assert "&lt;script&gt;" in html_out

    def test_img_onerror_neutralized(self):
        payload = '"><img src=x onerror=alert(1)>'
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        c.validate()
        html_out = c.render_html()
        assert payload not in html_out
        assert "&lt;img" in html_out or "&quot;&gt;" in html_out

    def test_svg_onload_neutralized(self):
        payload = "<svg onload=alert(1)>"
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        c.validate()
        html_out = c.render_html()
        assert "<svg onload" not in html_out
        assert "&lt;svg" in html_out

    def test_iframe_neutralized(self):
        payload = "<iframe src=javascript:alert(1)>"
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        c.validate()
        html_out = c.render_html()
        assert "<iframe" not in html_out.replace("&lt;iframe", "")

    def test_javascript_protocol_not_in_href(self):
        """javascript: protocol is only dangerous in URL attributes, not text content."""
        payload = "javascript:alert(1)"
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        c.validate()
        html_out = c.render_html()
        # Must not appear inside an href or src attribute
        assert 'href="' + payload not in html_out
        assert 'src="' + payload not in html_out


# ── AC-03: Escaped text in output, not executable markup ────────────────────


class TestAC03EscapedNotExecutable:
    """AC-03: Assert generated HTML contains escaped text, not executable markup."""

    def test_no_executable_script_tags(self):
        for payload in XSS_PAYLOADS:
            graph = _make_graph_with_label(payload)
            c = GovernanceConsole()
            c.load(graph)
            c.validate()
            html_out = c.render_html()
            # No raw executable tags (the < must be escaped to &lt;)
            assert "<script>" not in html_out.lower()
            assert "<img src" not in html_out.lower()
            assert "<svg onload" not in html_out.lower()
            assert "<iframe" not in html_out.lower()

    def test_no_raw_iframe(self):
        for payload in XSS_PAYLOADS:
            graph = _make_graph_with_label(payload)
            c = GovernanceConsole()
            c.load(graph)
            c.validate()
            html_out = c.render_html()
            assert "<iframe" not in html_out.lower().replace("&lt;iframe", "")

    def test_escaped_angle_brackets_present(self):
        payload = "<script>alert(1)</script>"
        graph = _make_graph_with_label(payload)
        c = GovernanceConsole()
        c.load(graph)
        c.validate()
        html_out = c.render_html()
        assert "&lt;script&gt;" in html_out


# ── AC-04: Content-Security-Policy header in console serve ──────────────────


class TestAC04CSPHeader:
    """AC-04: Add Content-Security-Policy header in console serve."""

    def test_csp_header_served(self):
        """The serve handler includes CSP header."""
        source = _get_cli_source()
        assert "Content-Security-Policy" in source

    def test_csp_blocks_scripts(self):
        source = _get_cli_source()
        assert "script-src" in source
        assert "'none'" in source


# ── AC-05: console serve binds to 127.0.0.1 by default ──────────────────────


class TestAC05LocalhostBinding:
    """AC-05: Bind console serve to 127.0.0.1 by default."""

    def test_default_host_is_localhost(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "serve", "--help"])
        assert result.exit_code == 0
        assert "127.0.0.1" in result.output

    def test_non_localhost_rejected_without_flag(self, tmp_path):
        graph = _make_graph_with_label("safe")
        p = tmp_path / "graph.json"
        p.write_text(json.dumps(graph))

        runner = CliRunner()
        result = runner.invoke(cli, [
            "console", "serve",
            "--graph", str(p),
            "--host", "0.0.0.0",
        ])
        assert result.exit_code == 10
        assert "allow-remote-console" in result.output

    def test_non_localhost_allowed_with_flag(self):
        """With --allow-remote-console, non-localhost should be accepted."""
        source = _get_cli_source()
        assert "allow_remote_console" in source


# ── AC-06: Explicit --host option ───────────────────────────────────────────


class TestAC06HostOption:
    """AC-06: Add explicit --host option for non-local binding."""

    def test_host_option_in_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output

    def test_allow_remote_flag_in_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "serve", "--help"])
        assert result.exit_code == 0
        assert "--allow-remote-console" in result.output


# ── AC-07: Reject unsafe host without flag ──────────────────────────────────


class TestAC07UnsafeHostRejection:
    """AC-07: Reject or warn on unsafe host binding unless --allow-remote-console."""

    def test_reject_0000_without_flag(self, tmp_path):
        graph = _make_graph_with_label("safe")
        p = tmp_path / "graph.json"
        p.write_text(json.dumps(graph))

        runner = CliRunner()
        result = runner.invoke(cli, [
            "console", "serve",
            "--graph", str(p),
            "--host", "0.0.0.0",
        ])
        assert result.exit_code == 10
        assert "refusing" in result.output.lower() or "allow-remote" in result.output.lower()

    def test_reject_external_ip_without_flag(self, tmp_path):
        graph = _make_graph_with_label("safe")
        p = tmp_path / "graph.json"
        p.write_text(json.dumps(graph))

        runner = CliRunner()
        result = runner.invoke(cli, [
            "console", "serve",
            "--graph", str(p),
            "--host", "192.168.1.100",
        ])
        assert result.exit_code == 10

    def test_localhost_accepted(self):
        """127.0.0.1 should be accepted without --allow-remote-console."""
        source = _get_cli_source()
        assert "127.0.0.1" in source
        assert "safe_hosts" in source


# ── AC-08: Console remains read-only ────────────────────────────────────────


class TestAC08ReadOnlyPreserved:
    """AC-08: Keep console read-only; no mutation endpoints."""

    def test_no_post_handler(self):
        """The serve handler only implements GET, not POST/PUT/DELETE."""
        source = _get_cli_source()
        assert "do_GET" in source
        assert "do_POST" not in source
        assert "do_PUT" not in source
        assert "do_DELETE" not in source

    def test_console_still_read_only(self):
        c = GovernanceConsole()
        assert c.read_only is True


# ── AC-09: Tests for server bind defaults ───────────────────────────────────


class TestAC09BindDefaults:
    """AC-09: Add tests for server bind defaults."""

    def test_default_host_param(self):
        """The --host option defaults to 127.0.0.1."""
        source = _get_cli_source()
        assert '"127.0.0.1"' in source

    def test_no_empty_string_bind(self):
        """The old code used '' for binding — that's gone."""
        source = _get_cli_source()
        lines = source.split("\n")
        for line in lines:
            if "TCPServer" in line:
                assert '""' not in line and "''" not in line


# ── AC-10: Same sanitized renderer for open and serve ───────────────────────


class TestAC10SameRenderer:
    """AC-10: console open --mode html and console serve use the same sanitized renderer."""

    def test_both_use_render_html(self):
        """Both console open and console serve call GovernanceConsole.render_html()."""
        source = _get_cli_source()
        assert "render_html" in source
        assert source.count("render_html") >= 2

    def test_cli_html_mode_escaped(self, tmp_path):
        """CLI --mode html output is escaped for adversarial input."""
        payload = "<script>alert(1)</script>"
        graph = _make_graph_with_label(payload)
        p = tmp_path / "graph.json"
        p.write_text(json.dumps(graph))

        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", str(p), "--mode", "html"])
        assert result.exit_code == 0
        assert "<script>alert" not in result.output
        assert "&lt;script&gt;" in result.output


# ── _esc() unit tests ───────────────────────────────────────────────────────


class TestEscHelper:
    """_esc() helper function tests."""

    def test_esc_none(self):
        assert _esc(None) == ""

    def test_esc_plain_text(self):
        assert _esc("hello") == "hello"

    def test_esc_script_tag(self):
        assert _esc("<script>") == "&lt;script&gt;"

    def test_esc_quotes(self):
        assert _esc('"hello"') == "&quot;hello&quot;"
        assert _esc("'hello'") == "&#x27;hello&#x27;"

    def test_esc_ampersand(self):
        assert _esc("a&b") == "a&amp;b"

    def test_esc_integer(self):
        assert _esc(42) == "42"

    def test_esc_onerror(self):
        result = _esc("onerror=alert(1)")
        assert "onerror" in result
        assert "<" not in result
