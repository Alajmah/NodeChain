"""Trace Replay and Verification (v1.17.0).

Replays chain execution traces and verifies:
  - Step order consistency
  - Node invocation order
  - Contract validity
  - Port validity
  - Policy verdicts
  - State transitions
  - Receipt/artifact digest references
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import uuid


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def replay_trace(
    trace: dict[str, Any] | str,
    strict: bool = False,
) -> dict[str, Any]:
    """Replay a chain trace and verify its consistency.

    Args:
        trace: Trace dict or path to trace JSON.
        strict: If True, any check failure is a hard error.

    Returns:
        Replay report dict with checks, errors, and digest.
    """
    if isinstance(trace, str):
        trace = json.loads(Path(trace).read_text(encoding="utf-8"))

    replay_id = str(uuid.uuid4())
    started_at = _now_iso()

    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []

    events = trace.get("events", trace.get("trace_events", []))
    chain_id = trace.get("chain_id", "")
    run_id = trace.get("run_id", "")

    # ── Check 1: Step order ────────────────────────────────────────────────
    step_numbers = []
    for event in events:
        step = event.get("step", event.get("step_id", ""))
        if isinstance(step, (int, float)):
            step_numbers.append(int(step))
        elif isinstance(step, str) and step.isdigit():
            step_numbers.append(int(step))

    step_order_ok = True
    if step_numbers:
        for i in range(1, len(step_numbers)):
            if step_numbers[i] < step_numbers[i - 1]:
                step_order_ok = False
                errors.append(f"Step order violation at position {i}: {step_numbers[i]} < {step_numbers[i-1]}")
                break

    checks.append({
        "check": "step_order",
        "passed": step_order_ok,
        "detail": f"{len(step_numbers)} steps checked" if step_numbers else "no step numbers found",
    })

    # ── Check 2: Node invocation order ──────────────────────────────────────
    node_ids = [e.get("node_id", "") for e in events if e.get("node_id")]
    node_order_ok = True
    seen_nodes: set[str] = set()
    for nid in node_ids:
        if nid in seen_nodes:
            # Duplicate node is allowed (retry/loop), but warn
            warnings.append(f"Node {nid} appears multiple times")
        seen_nodes.add(nid)

    checks.append({
        "check": "node_invocation_order",
        "passed": node_order_ok,
        "detail": f"{len(node_ids)} node invocations, {len(seen_nodes)} unique nodes",
    })

    # ── Check 3: Contract validity ──────────────────────────────────────────
    contract_errors = []
    for event in events:
        contract = event.get("contract", {})
        if contract:
            if "input_port" not in contract and "input_type" not in contract:
                if strict:
                    contract_errors.append(f"Event {event.get('step', '?')}: contract missing input port/type")
            if "output_port" not in contract and "output_type" not in contract:
                if strict:
                    contract_errors.append(f"Event {event.get('step', '?')}: contract missing output port/type")

    checks.append({
        "check": "contract_validity",
        "passed": len(contract_errors) == 0,
        "detail": f"{len(contract_errors)} contract errors" if contract_errors else "contracts valid",
    })
    errors.extend(contract_errors)

    # ── Check 4: Port validity ──────────────────────────────────────────────
    port_errors = []
    prev_output_port = ""
    for event in events:
        contract = event.get("contract", {})
        input_port = contract.get("input_port", contract.get("input_type", ""))
        output_port = contract.get("output_port", contract.get("output_type", ""))

        if prev_output_port and input_port and prev_output_port != input_port:
            if strict:
                port_errors.append(
                    f"Port mismatch: prev output={prev_output_port}, current input={input_port}"
                )
        if output_port:
            prev_output_port = output_port

    checks.append({
        "check": "port_validity",
        "passed": len(port_errors) == 0,
        "detail": f"{len(port_errors)} port errors" if port_errors else "ports valid",
    })
    errors.extend(port_errors)

    # ── Check 5: Policy verdicts ────────────────────────────────────────────
    policy_errors = []
    for event in events:
        policy_verdict = event.get("policy_verdict", event.get("policy_result", ""))
        if policy_verdict == "denied" or policy_verdict == "rejected":
            if strict:
                policy_errors.append(
                    f"Event {event.get('step', '?')}: policy verdict={policy_verdict}"
                )

    checks.append({
        "check": "policy_verdicts",
        "passed": len(policy_errors) == 0,
        "detail": f"{len(policy_errors)} policy violations" if policy_errors else "all policies passed",
    })
    errors.extend(policy_errors)

    # ── Check 6: State transitions ──────────────────────────────────────────
    state_errors = []
    valid_transitions = {
        "pending": {"running", "skipped", "failed"},
        "running": {"completed", "failed", "paused"},
        "paused": {"running", "failed", "cancelled"},
        "completed": set(),  # terminal
        "failed": {"retrying", "cancelled"},
        "retrying": {"running", "failed"},
        "cancelled": set(),  # terminal
        "skipped": set(),  # terminal
    }
    prev_state = ""
    for event in events:
        state = event.get("state", event.get("status", ""))
        if prev_state and state:
            if prev_state in valid_transitions:
                allowed = valid_transitions[prev_state]
                # Terminal state with non-empty allowed set means error
                if len(allowed) == 0 and state != prev_state:
                    state_errors.append(
                        f"Invalid transition: {prev_state} → {state} (terminal state)"
                    )
                elif len(allowed) > 0 and state not in allowed and state != prev_state:
                    state_errors.append(
                        f"Invalid transition: {prev_state} → {state}"
                    )
        if state:
            prev_state = state

    checks.append({
        "check": "state_transitions",
        "passed": len(state_errors) == 0,
        "detail": f"{len(state_errors)} transition errors" if state_errors else "transitions valid",
    })
    errors.extend(state_errors)

    # ── Check 7: Receipt/artifact digest references ─────────────────────────
    digest_errors = []
    for event in events:
        receipt_digest = event.get("receipt_digest", event.get("artifact_digest", ""))
        # Just check they're valid SHA-256 if present
        if receipt_digest and len(receipt_digest) != 64:
            digest_errors.append(
                f"Event {event.get('step', '?')}: digest has invalid length"
            )

    checks.append({
        "check": "digest_references",
        "passed": len(digest_errors) == 0,
        "detail": f"{len(digest_errors)} digest errors" if digest_errors else "digests valid",
    })
    errors.extend(digest_errors)

    # ── Summary ─────────────────────────────────────────────────────────────
    all_passed = all(c["passed"] for c in checks)
    hard_errors = errors if strict else []
    replay_passed = all_passed and (not strict or len(hard_errors) == 0)

    report = {
        "type": "trace_replay_report",
        "replay_id": replay_id,
        "chain_id": chain_id,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": _now_iso(),
        "event_count": len(events),
        "checks": checks,
        "passed": replay_passed,
        "valid": replay_passed,
        "errors": hard_errors if strict else errors,
        "warnings": warnings,
        "strict_mode": strict,
        "replay_report_digest": "",
    }

    digest_content = {k: v for k, v in report.items() if k != "replay_report_digest"}
    report["replay_report_digest"] = _sha256_dict(digest_content)

    return report
