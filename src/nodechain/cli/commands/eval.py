"""v2.80 — Click declarations for the eval command group.

Relocated from cli/main.py (was inline at L3846-4451). The implementation
logic stays in cli/evaluation.py, cli/eval_suite_registry.py, and
cli/certification.py; this module holds only the Click declaration shell +
lazy delegation. Behavior is identical to the pre-relocation code.

Includes nested groups: suite, certification (defined here, same module).
"""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="eval")
def eval_group() -> None:
    """Evaluation runner (v1.16.0)."""


@eval_group.command(name="run")
@click.option("--suite", "suite_path", required=True, help="Evaluation suite YAML or JSON")
@click.option("--output", "-o", default="", help="Output evaluation report JSON")
@click.option("--target-digest", default="", help="Digest of the target being evaluated")
@click.option("--require-suite-signature", is_flag=True, default=False, help="Require signed suite verified against trust store (v1.16.1)")
@click.option("--trust-store", "ts_path", default="", help="Trust store path for suite signature verification")
@click.option("--strict", is_flag=True, default=False, help="Strict mode: fail on missing artifacts and threshold failures")
def eval_run_cmd(suite_path: str, output: str, target_digest: str, require_suite_sig: bool, ts_path: str, strict: bool) -> None:
    """Run an evaluation suite."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION, EXIT_TRUST_VIOLATION
    from nodechain.cli.evaluation import run_evaluation

    report = run_evaluation(suite=suite_path, target_digest=target_digest, strict=strict,
                           require_suite_signature=require_suite_sig, trust_store_path=ts_path)

    if not report.get("valid", True):
        console.print(f"[red]\u274c Evaluation suite invalid[/red]")
        for err in report.get("errors", []):
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    if output:
        Path(output).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        console.print(f"  Written: {output}")

    if report["passed"]:
        console.print(f"[green]\u2705 Evaluation passed: {report['passed_cases']}/{report['total_cases']} cases[/green]")
    else:
        console.print(f"[red]\u274c Evaluation failed[/red]")
        if report["failed_cases"]:
            console.print(f"  Failed cases: {', '.join(report['failed_cases'])}")
        if report["threshold_failures"]:
            for tf in report["threshold_failures"]:
                console.print(f"  Threshold: {tf['metric']} = {tf['actual']:.3f} < {tf['threshold']}")
        if strict:
            ctx = click.get_current_context()
            ctx.exit(EXIT_TRUST_VIOLATION)

    console.print(f"  Suite:   {report['suite_id']}")
    console.print(f"  Eval ID: {report['eval_id']}")
    console.print(f"  Version: {report['nodechain_version']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_group.command(name="sign")
@click.option("--report", "report_path", required=True, help="Evaluation report JSON")
@click.option("--key", "key_path", required=True, help="Private key PEM")
@click.option("--output", "-o", default="", help="Output signed report (default: overwrite)")
def eval_sign_cmd(report_path: str, key_path: str, output: str) -> None:
    """Sign an evaluation report (v1.16.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evaluation import sign_evaluation_report

    try:
        signed = sign_evaluation_report(report_path, key_path, output_path=output)
        console.print(f"[green]\u2705 Evaluation report signed[/green]")
        console.print(f"  Digest:     {signed.get('report_digest', '')[:16]}...")
        console.print(f"  Fingerprint: {signed.get('report_signer_fingerprint', '')}")
    except Exception as e:
        console.print(f"[red]\u274c Failed to sign: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_group.command(name="verify")
@click.option("--report", "report_path", required=True, help="Signed evaluation report JSON")
@click.option("--pubkey", default="", help="Public key PEM")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
def eval_verify_cmd(report_path: str, pubkey: str, ts_path: str) -> None:
    """Verify a signed evaluation report (v1.16.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evaluation import verify_evaluation_report

    result = verify_evaluation_report(
        report_path=report_path, public_key_pem=pubkey, trust_store_path=ts_path,
    )
    if result["valid"]:
        console.print(f"[green]\u2705 Report signature valid[/green]")
        console.print(f"  Status:      {result['details']['signature_status']}")
        console.print(f"  Fingerprint: {result['details']['signer_fingerprint']}")
    else:
        console.print(f"[red]\u274c Report signature invalid[/red]")
        for err in result["errors"]:
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_group.group(name="suite")
def eval_suite_group() -> None:
    """Evaluation suite management (v1.16.1)."""


@eval_suite_group.command(name="sign")
@click.option("--suite", "suite_path", required=True, help="Evaluation suite YAML or JSON")
@click.option("--key", "key_path", required=True, help="Private key PEM")
@click.option("--output", "-o", default="", help="Output signed suite JSON")
def eval_suite_sign_cmd(suite_path: str, key_path: str, output: str) -> None:
    """Sign an evaluation suite (v1.16.1)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evaluation import sign_evaluation_suite

    try:
        signed = sign_evaluation_suite(suite_path, key_path, output_path=output)
        console.print(f"[green]\u2705 Evaluation suite signed[/green]")
        console.print(f"  Digest:     {signed.get('suite_digest', '')[:16]}...")
        console.print(f"  Fingerprint: {signed.get('suite_signer_fingerprint', '')}")
    except Exception as e:
        console.print(f"[red]\u274c Failed to sign suite: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_suite_group.command(name="verify")
@click.option("--suite", "suite_path", required=True, help="Signed evaluation suite JSON")
@click.option("--pubkey", default="", help="Public key PEM")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
def eval_suite_verify_cmd(suite_path: str, pubkey: str, ts_path: str) -> None:
    """Verify a signed evaluation suite (v1.16.1)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.evaluation import verify_evaluation_suite_signature

    result = verify_evaluation_suite_signature(
        suite_path=suite_path, public_key_pem=pubkey, trust_store_path=ts_path,
    )
    if result["valid"]:
        console.print(f"[green]\u2705 Suite signature valid[/green]")
        console.print(f"  Status:      {result['details']['signature_status']}")
        console.print(f"  Fingerprint: {result['details']['signer_fingerprint']}")
        console.print(f"  Trusted:     {result['details']['signer_trusted']}")
    else:
        console.print(f"[red]\u274c Suite signature invalid[/red]")
        for err in result["errors"]:
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_suite_group.command(name="register")
@click.option("--suite", "suite_path", required=True, help="Evaluation suite to register")
def eval_suite_register_cmd(suite_path: str) -> None:
    """Register an evaluation suite in the local registry (v1.16.2)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.eval_suite_registry import register_suite

    try:
        entry = register_suite(suite_path=suite_path)
        console.print(f"[green]\u2705 Suite registered[/green]")
        console.print(f"  ID:      {entry['suite_id']}")
        console.print(f"  Version: {entry['suite_version']}")
        console.print(f"  Digest:  {entry['suite_digest'][:16]}...")
        console.print(f"  Status:  {entry['suite_status']}")
    except Exception as e:
        console.print(f"[red]\u274c Failed to register suite: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_suite_group.command(name="list")
@click.option("--active-only", is_flag=True, default=False, help="Show only active suites")
def eval_suite_list_cmd(active_only: bool) -> None:
    """List registered evaluation suites (v1.16.2)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.eval_suite_registry import list_suites

    suites = list_suites(active_only=active_only)
    if not suites:
        console.print("[yellow]No suites registered[/yellow]")
    else:
        for s in suites:
            color = "green" if s.get("suite_status") == "active" else "red"
            console.print(f"  [{color}]{s['suite_status']}[/{color}] {s['suite_id']} v{s['suite_version']} ({s['suite_digest'][:16]}...)")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_suite_group.command(name="revoke")
@click.option("--digest", "suite_digest", required=True, help="Suite digest to revoke")
@click.option("--reason", default="", help="Revocation reason")
def eval_suite_revoke_cmd(suite_digest: str, reason: str) -> None:
    """Revoke a registered evaluation suite (v1.16.2)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.eval_suite_registry import revoke_suite

    try:
        entry = revoke_suite(suite_digest=suite_digest, reason=reason)
        console.print(f"[red]\u2705 Suite revoked[/red]")
        console.print(f"  ID:     {entry['suite_id']}")
        console.print(f"  Digest: {entry['suite_digest'][:16]}...")
    except KeyError as e:
        console.print(f"[red]\u274c {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_suite_group.command(name="verify-registry")
@click.option("--digest", "suite_digest", required=True, help="Suite digest to verify")
@click.option("--require-active", is_flag=True, default=True, help="Require suite to be active")
def eval_suite_verify_registry_cmd(suite_digest: str, require_active: bool) -> None:
    """Verify a suite is registered and active (v1.16.2)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.eval_suite_registry import verify_suite_in_registry

    result = verify_suite_in_registry(suite_digest, require_active=require_active)
    if result["valid"]:
        d = result["details"]
        console.print(f"[green]\u2705 Suite verified in registry[/green]")
        console.print(f"  ID:     {d['suite_id']}")
        console.print(f"  Status: {d['suite_status']}")
    else:
        console.print(f"[red]\u274c Suite not verified[/red]")
        for err in result["errors"]:
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_group.command(name="certify")
@click.option("--report", "report_path", required=True, help="Evaluation report JSON")
@click.option("--output", "-o", default="", help="Output certification JSON")
@click.option("--valid-from", default="", help="Certification validity start (ISO timestamp)")
@click.option("--valid-until", default="", help="Certification validity end (ISO timestamp)")
@click.option("--require-report-signature", is_flag=True, default=False, help="Require signed eval report")
@click.option("--require-suite-signature", is_flag=True, default=False, help="Require signed suite")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
@click.option("--strict", is_flag=True, default=False, help="Strict certification checks")
def eval_certify_cmd(report_path: str, output: str, valid_from: str, valid_until: str,
                     require_report_signature: bool, require_suite_signature: bool,
                     ts_path: str, strict: bool) -> None:
    """Create a certification from an evaluation report (v1.16.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certification import create_certification

    cert = create_certification(
        eval_report=report_path,
        valid_from=valid_from,
        valid_until=valid_until,
        require_report_signature=require_report_signature,
        require_suite_signature=require_suite_signature,
        trust_store_path=ts_path,
        strict=strict,
    )

    if output:
        Path(output).write_text(json.dumps(cert, indent=2, sort_keys=True), encoding="utf-8")

    if cert["certification_status"] == "certified":
        console.print(f"[green]\u2705 Target certified[/green]")
        console.print(f"  Certification ID: {cert['certification_id']}")
        console.print(f"  Target:           {cert['target_type']} ({cert['target_ref']})")
        console.print(f"  Suite:            {cert['suite_id']} v{cert['suite_version']}")
        console.print(f"  Status:           {cert['certification_status']}")
    else:
        console.print(f"[red]\u274c Certification denied[/red]")
        for err in cert.get("errors", []):
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_group.group(name="certification")
def eval_cert_group() -> None:
    """Certification management (v1.16.3)."""


@eval_cert_group.command(name="sign")
@click.option("--certification", "cert_path", required=True, help="Certification JSON")
@click.option("--key", "key_path", required=True, help="Private key PEM")
@click.option("--output", "-o", default="", help="Output signed certification JSON")
def eval_cert_sign_cmd(cert_path: str, key_path: str, output: str) -> None:
    """Sign a certification artifact (v1.16.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certification import sign_certification

    try:
        out = output or cert_path
        signed = sign_certification(cert_path, key_path, output_path=out)
        console.print(f"[green]\u2705 Certification signed[/green]")
        console.print(f"  Fingerprint: {signed.get('certifier_fingerprint', '')}")
    except Exception as e:
        console.print(f"[red]\u274c Failed to sign certification: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_cert_group.command(name="verify")
@click.option("--certification", "cert_path", required=True, help="Certification JSON")
@click.option("--pubkey", default="", help="Public key PEM")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
def eval_cert_verify_cmd(cert_path: str, pubkey: str, ts_path: str) -> None:
    """Verify a signed certification (v1.16.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certification import verify_certification

    result = verify_certification(
        certification=cert_path, public_key_pem=pubkey, trust_store_path=ts_path,
    )
    if result["valid"]:
        console.print(f"[green]\u2705 Certification valid[/green]")
        console.print(f"  Status:      {result['details']['signature_status']}")
        console.print(f"  Trusted:     {result['details']['certifier_trusted']}")
    else:
        console.print(f"[red]\u274c Certification invalid[/red]")
        for err in result["errors"]:
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_cert_group.command(name="revoke")
@click.option("--certification", "cert_path", required=True, help="Certification JSON")
@click.option("--reason", default="", help="Revocation reason")
@click.option("--output", "-o", default="", help="Output updated certification")
def eval_cert_revoke_cmd(cert_path: str, reason: str, output: str) -> None:
    """Revoke a certification (v1.16.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certification import revoke_certification

    try:
        out = output or cert_path
        revoked = revoke_certification(cert_path, reason=reason, output_path=out)
        console.print(f"[red]\u2705 Certification revoked[/red]")
        console.print(f"  ID:     {revoked.get('certification_id', '')}")
        console.print(f"  Reason: {reason or 'unspecified'}")
    except Exception as e:
        console.print(f"[red]\u274c Failed to revoke: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@eval_cert_group.command(name="inspect")
@click.option("--certification", "cert_path", required=True, help="Certification JSON")
def eval_cert_inspect_cmd(cert_path: str) -> None:
    """Inspect a certification artifact (v1.16.3)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.certification import inspect_certification

    summary = inspect_certification(cert_path)
    color = "green" if summary["certification_status"] == "certified" else "red"
    console.print(f"  [{color}]{summary['certification_status']}[/{color}] {summary['target_type']} → {summary['target_ref']}")
    console.print(f"  Suite:       {summary['suite_id']} v{summary['suite_version']}")
    console.print(f"  Signed:      {'yes' if summary['is_signed'] else 'no'}")
    console.print(f"  Cert ID:     {summary['certification_id']}")
    console.print(f"  Issued:      {summary['issued_at']}")
    if summary["errors"]:
        console.print(f"  Errors:      {summary['errors']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


# ── v2.56.0: Research Evaluation Harness ───────────────────────────────────

@eval_group.command(name="research")
@click.option("--output", "-o", default="", help="Output report JSON path")
@click.option("--json", "json_only", is_flag=True, help="Print JSON report to stdout")
def eval_research_cmd(output: str, json_only: bool) -> None:
    """Run the deterministic research evaluation harness (v2.56.0).

    Executes the research_decision_v1 chain through MockModelAdapter,
    computes quality metrics (citation validity, claim support rate,
    fabrication rate, schema compliance), and produces a machine-readable
    report suitable for release gating.
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.runtime.research_eval_runner import (
        get_golden_corpus, run_research_eval_case,
    )
    from nodechain.runtime.research_eval_metrics import (
        compute_all_metrics, check_invariants, check_thresholds,
        DEFAULT_THRESHOLDS,
    )
    from nodechain import __version__

    corpus = get_golden_corpus()
    case_results = []
    all_passed = True

    for case in corpus:
        result = run_research_eval_case(case)
        metrics = compute_all_metrics(result["node_outputs"])
        invariant_violations = check_invariants(result["node_outputs"])
        threshold_violations = check_thresholds(metrics)

        # Per-case risk-level enforcement (v2.56.0 follow-up)
        case_violations: list[str] = []
        if case.expected_risk_level:
            actual_risk = result["node_outputs"].get(
                "risk_classifier", {}
            ).get("risk_level", "")
            if actual_risk and actual_risk != case.expected_risk_level:
                case_violations.append(
                    f"risk_level {actual_risk} != expected {case.expected_risk_level}"
                )

        # Per-case citation expectation
        if case.expect_citations:
            citation_count = len(
                result["node_outputs"].get("response_generator", {}).get("citations", [])
            )
            if citation_count == 0:
                case_violations.append("expected citations but got 0")

        passed = (
            len(result["errors"]) == 0
            and len(invariant_violations) == 0
            and len(threshold_violations) == 0
            and len(case_violations) == 0
        )
        if not passed:
            all_passed = False

        case_results.append({
            "case_id": case.case_id,
            "description": case.description,
            "passed": passed,
            "metrics": metrics,
            "invariant_violations": invariant_violations,
            "threshold_violations": threshold_violations,
            "case_violations": case_violations,
            "execution_errors": result["errors"],
            "node_summary": {
                node_id: {
                    field: (str(value)[:100] if not isinstance(value, (list, dict))
                           else f"[{len(value)} items]" if isinstance(value, list)
                           else "{keys}")
                    for field, value in output.items()
                    if field in ("risk_level", "confidence", "recommendation",
                                 "total_claims", "claims", "validated_claims",
                                 "citations", "validation_summary")
                }
                for node_id, output in result["node_outputs"].items()
            },
        })

    report = {
        "report_type": "research_evaluation",
        "nodechain_version": __version__,
        "chain_id": "research_decision_v1",
        "eval_mode": "deterministic_mock",
        "generated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "total_cases": len(case_results),
        "passed_cases": sum(1 for c in case_results if c["passed"]),
        "passed": all_passed,
        "thresholds": DEFAULT_THRESHOLDS,
        "cases": case_results,
    }

    # Compute report digest
    import hashlib
    import json as json_mod
    canonical = json_mod.dumps(report, sort_keys=True, default=str)
    report["report_digest"] = hashlib.sha256(canonical.encode()).hexdigest()

    if json_only:
        click.echo(json_mod.dumps(report, indent=2, default=str))
    else:
        color = "green" if all_passed else "red"
        console.print(f"\n[{color}]\u2705 PASSED[/{color}]" if all_passed else f"\n[{color}]\u274c FAILED[/{color}]")
        console.print(f"  Cases: {report['passed_cases']}/{report['total_cases']} passed")
        console.print(f"  Mode:  {report['eval_mode']}")
        console.print(f"  Digest: {report['report_digest'][:16]}...")
        console.print()
        for cr in case_results:
            status = "[green]\u2713[/green]" if cr["passed"] else "[red]\u2717[/red]"
            console.print(f"  {status} {cr['case_id']}")
            for k, v in cr["metrics"].items():
                console.print(f"      {k}: {v}")
            for v in cr["invariant_violations"]:
                console.print(f"      [red]INV: {v}[/red]")
            for v in cr["threshold_violations"]:
                console.print(f"      [red]THR: {v}[/red]")
            for v in cr.get("case_violations", []):
                console.print(f"      [red]CASE: {v}[/red]")

    if output:
        from pathlib import Path
        Path(output).write_text(
            json_mod.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )
        if not json_only:
            console.print(f"\n  Report written to: {output}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if all_passed else EXIT_VALIDATION)


# ── v2.67.3: Node Quality Scorecards ──────────────────────────────────────

@eval_group.command(name="node-scorecard")
@click.option("--node", "node_id", default=None, help="Node ID to evaluate (e.g. shared_risk_classifier)")
@click.option("--all-shared", is_flag=True, help="Evaluate all shared deterministic nodes")
@click.option("--output", "-o", default="", help="Output report JSON path")
@click.option("--json", "json_only", is_flag=True, help="Print JSON report(s) to stdout")
def eval_node_scorecard_cmd(node_id: str, all_shared: bool, output: str, json_only: bool) -> None:
    """Run deterministic node quality scorecards (v2.67.3).

    Evaluates registry-resolved deterministic nodes for measurable quality:
    reproducibility, exact-match correctness, schema compliance, cost
    compliance, latency, and rule branch coverage.

    \b
    Examples:
      nodechain eval node-scorecard --node shared_risk_classifier
      nodechain eval node-scorecard --node shared_trace_collector
      nodechain eval node-scorecard --all-shared
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.runtime.node_quality_scorecard import run_registry_node_scorecard, get_shared_registry_node_ids

    if all_shared:
        node_ids = get_shared_registry_node_ids()
    elif node_id:
        node_ids = [node_id]
    else:
        console.print("[red]Error:[/red] Specify --node NODE_ID or --all-shared")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)
        return

    all_passed = True
    reports = []

    for nid in node_ids:
        console.print(f"\n[bold blue]Evaluating:[/bold blue] {nid}")
        report = run_registry_node_scorecard(nid)
        reports.append(report.to_dict())

        status = "[green]PASS[/green]" if report.passed else "[red]FAIL[/red]"
        console.print(f"  Result: {status}")
        console.print(f"  Profile: {report.profile}")
        console.print(f"  Content digest: {report.content_digest[:16]}...")
        console.print(f"  Metrics:")
        for k, v in report.metrics.items():
            console.print(f"    {k}: {v}")
        console.print(f"  Cases ({len(report.cases)}):")
        for c in report.cases:
            cstatus = "[green]\u2713[/green]" if c["passed"] else "[red]\u2717[/red]"
            console.print(f"    {cstatus} {c['case_id']}")
            if not c["passed"]:
                console.print(f"       reproducible={c['reproducible']} exact={c['exact_match']} schema={c['schema_ok']} cost={c['cost_ok']} branches={c['branches_covered']}")

        if not report.passed:
            all_passed = False

    if output:
        from pathlib import Path
        output_data = reports[0] if len(reports) == 1 else {"reports": reports}
        Path(output).write_text(
            json_mod.dumps(output_data, indent=2, default=str),
            encoding="utf-8",
        )
        if not json_only:
            console.print(f"\n  Report written to: {output}")

    if json_only:
        output_data = reports[0] if len(reports) == 1 else {"reports": reports}
        console.print(json_mod.dumps(output_data, indent=2, default=str))

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if all_passed else EXIT_VALIDATION)


def register(cli: click.Group) -> None:
    """Wire the eval group into the root CLI."""
    cli.add_command(eval_group)
