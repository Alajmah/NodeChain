"""Operator Dashboard (v1.20.0).

Unified read-only operational view across all six platform spines:

    Runtime       — chain runs, paused reviews, failures
    Trust         — trust store keys, snapshots, signing status
    Operations    — release history, drift, remediations, deployments
    Evaluation    — suites, reports, certifications
    Explainability — evidence index, trace replay
    Ecosystem     — certified registry, consumption

Design principles:
  1. NEVER mutates state — read-only by default
  2. Every view has --json output
  3. Health model: healthy / warning / degraded / critical / unknown
  4. Links artifacts, doesn't duplicate them
  5. Deterministic with fixtures
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Health Model ────────────────────────────────────────────────────────────

HEALTHY = "healthy"
WARNING = "warning"
DEGRADED = "degraded"
CRITICAL = "critical"
UNKNOWN = "unknown"

HEALTH_ORDER = {HEALTHY: 0, WARNING: 1, UNKNOWN: 2, DEGRADED: 3, CRITICAL: 4}
HEALTH_COLORS = {
    HEALTHY: "green",
    WARNING: "yellow",
    DEGRADED: "dark_yellow",
    CRITICAL: "red",
    UNKNOWN: "dim",
}


def worst_health(*statuses: str) -> str:
    """Return the worst health status from a list."""
    if not statuses:
        return UNKNOWN
    return max(statuses, key=lambda s: HEALTH_ORDER.get(s, 4))


# ── Dashboard Sections ──────────────────────────────────────────────────────

def _get_db_path() -> str:
    return os.environ.get("NODECHAIN_DB_PATH", "data/chain_state.db")


def collect_runtime_status() -> dict[str, Any]:
    """Collect runtime status from SQLite persistence."""
    db_path = _get_db_path()
    result: dict[str, Any] = {
        "active_runs": 0,
        "recent_runs": [],
        "total_runs": 0,
        "failed_runs": 0,
        "paused_reviews": 0,
        "db_path": db_path,
        "db_exists": Path(db_path).exists(),
    }

    if not Path(db_path).exists():
        return result

    try:
        with sqlite3.connect(db_path) as conn:
            # Count total unique runs
            cursor = conn.execute("SELECT DISTINCT run_id FROM chain_states")
            all_runs = [row[0] for row in cursor.fetchall()]
            result["total_runs"] = len(all_runs)

            # Recent runs (last 12 by timestamp)
            cursor = conn.execute(
                "SELECT DISTINCT run_id, chain_id, status, updated_at "
                "FROM chain_states ORDER BY updated_at DESC LIMIT 12"
            )
            recent = []
            for row in cursor.fetchall():
                recent.append({
                    "run_id": row[0],
                    "chain_id": row[1],
                    "status": row[2],
                    "updated_at": row[3],
                })
            result["recent_runs"] = recent

            # Active runs (status = running)
            active = [r for r in recent if r["status"] == "running"]
            result["active_runs"] = len(active)

            # Failed runs
            failed = [r for r in recent if r["status"] == "failed"]
            result["failed_runs"] = len(failed)

            # Paused reviews
            paused = [r for r in recent if r["status"] == "paused"]
            result["paused_reviews"] = len(paused)

    except sqlite3.Error:
        pass

    return result


def collect_trust_status() -> dict[str, Any]:
    """Collect trust store status."""
    from nodechain.cli.trust_store import load_trust_store, _trust_store_path

    try:
        # Existence semantics (#15): distinguish absent/uninitialized from
        # present-but-noncompliant. load_trust_store() synthesizes an empty
        # store when the path is missing, collapsing the two states. We restore
        # the distinction: a store "exists" only when the file is on disk AND
        # has material content (entries or a signature). A synthesized empty
        # object must not masquerade as a real unsigned trust root (HR-001).
        store_file_exists = _trust_store_path().exists()
        ts = load_trust_store()
        # Trust stores key their entries under "keys" (see trust_store.py); the
        # prior code read "entries" and always saw an empty dict.
        entries = ts.get("keys", {})
        total_keys = len(entries)
        snapshot_signed = bool(ts.get("snapshot_signature"))
        has_material_content = total_keys > 0 or snapshot_signed
        trust_store_exists = store_file_exists and has_material_content

        # Classify by purpose
        purposes: dict[str, int] = {}
        legacy_count = 0
        for entry in entries.values():
            purpose = entry.get("purpose", "unknown")
            purposes[purpose] = purposes.get(purpose, 0) + 1
            if not entry.get("purpose"):
                legacy_count += 1

        entries_digest = ts.get("entries_digest", "")

        return {
            "trust_store_exists": trust_store_exists,
            "total_keys": total_keys,
            "legacy_keys": legacy_count,
            "purposes": purposes,
            "snapshot_signed": snapshot_signed,
            "entries_digest": entries_digest[:16] + "..." if entries_digest else "",
            "health": HEALTHY if legacy_count == 0 else WARNING,
        }
    except Exception:
        return {
            "trust_store_exists": False,
            "total_keys": 0,
            "legacy_keys": 0,
            "purposes": {},
            "snapshot_signed": False,
            "entries_digest": "",
            "health": UNKNOWN,
        }


def collect_registry_status() -> dict[str, Any]:
    """Collect certified registry status."""
    from nodechain.cli.certified_registry import load_registry, _get_registry_path

    try:
        # Existence semantics (#15): distinguish absent/uninitialized from
        # present-but-noncompliant. load_registry() synthesizes an empty
        # registry when the path is missing. A registry "exists" only when the
        # file is on disk AND has entries — a synthesized empty object must not
        # masquerade as a real unready registry (HR-013).
        registry_file_exists = Path(_get_registry_path()).exists()
        registry = load_registry()
        entries = registry.get("entries", {})
        registry_exists = registry_file_exists and len(entries) > 0

        active = sum(1 for e in entries.values() if e.get("registry_status") == "active")
        deprecated = sum(1 for e in entries.values() if e.get("registry_status") == "deprecated")
        revoked = sum(1 for e in entries.values() if e.get("registry_status") == "revoked")
        denied = sum(1 for e in entries.values() if e.get("registry_status") == "denied")

        certified = sum(1 for e in entries.values() if e.get("certification_status") == "certified")

        health = HEALTHY
        if revoked > 0:
            health = WARNING
        if denied > 0 and active == 0:
            health = DEGRADED

        return {
            "registry_exists": registry_exists,
            "total_entries": len(entries),
            "active": active,
            "deprecated": deprecated,
            "revoked": revoked,
            "denied": denied,
            "certified": certified,
            "health": health,
        }
    except Exception:
        return {
            "registry_exists": False,
            "total_entries": 0,
            "active": 0,
            "deprecated": 0,
            "revoked": 0,
            "denied": 0,
            "certified": 0,
            "health": UNKNOWN,
        }


def collect_evidence_status() -> dict[str, Any]:
    """Collect evidence index status."""
    evidence_dir = Path("data")
    artifacts: list[str] = []

    # Count known evidence artifact types
    evidence_patterns = [
        "*.json",
    ]

    evidence_types_found: dict[str, int] = {}
    if evidence_dir.exists():
        for pattern in evidence_patterns:
            for f in evidence_dir.glob(pattern):
                if f.name in ("trust_store.json", "certified_registry.json",
                              "release_history.json", "chain_state.db",
                              "release_history_audit.jsonl"):
                    continue
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    atype = data.get("type", "unknown")
                    evidence_types_found[atype] = evidence_types_found.get(atype, 0) + 1
                    artifacts.append(f.name)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

    total = len(artifacts)
    broken = sum(1 for a in artifacts if "audit" in a and "error" in a.lower())

    health = HEALTHY
    if broken > 0:
        health = WARNING

    return {
        "indexed_artifacts": total,
        "artifact_types": evidence_types_found,
        "broken_chains": broken,
        "replay_failures": 0,
        "health": health,
    }


def collect_operations_status() -> dict[str, Any]:
    """Collect operations status: releases, drift, remediations."""
    result: dict[str, Any] = {
        "known_good_releases": 0,
        "drift_detected": 0,
        "remediations": 0,
        "deployments": [],
        "health": HEALTHY,
    }

    # Release history
    try:
        from nodechain.cli.release_history import ReleaseHistory
        rh = ReleaseHistory()
        result["known_good_releases"] = len(rh.releases)
    except Exception:
        pass

    # Drift reports (from data directory)
    drift_dir = Path("data")
    drift_reports: list[dict[str, Any]] = []
    if drift_dir.exists():
        for f in drift_dir.glob("drift_report*.json"):
            try:
                report = json.loads(f.read_text(encoding="utf-8"))
                if report.get("drift_detected"):
                    drift_reports.append(report)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    result["drift_detected"] = len(drift_reports)

    # Remediation receipts
    rem_count = 0
    if drift_dir.exists():
        for f in drift_dir.glob("remediation_receipt*.json"):
            rem_count += 1
    result["remediations"] = rem_count

    # Health
    health = HEALTHY
    if result["drift_detected"] > 0 and result["remediations"] == 0:
        health = WARNING
    result["health"] = health

    return result


def collect_evaluation_status() -> dict[str, Any]:
    """Collect evaluation and certification status."""
    result: dict[str, Any] = {
        "trusted_suites": 0,
        "total_reports": 0,
        "passed_reports": 0,
        "failed_reports": 0,
        "certifications": 0,
        "expired_certs": 0,
        "denied_certs": 0,
        "health": UNKNOWN,
    }

    eval_dir = Path("data")
    suites_found = 0
    reports_found = 0
    passed = 0
    failed = 0
    certs = 0
    expired = 0
    denied = 0

    if eval_dir.exists():
        for f in eval_dir.glob("*.json"):
            if f.name in ("trust_store.json", "certified_registry.json", "release_history.json"):
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                atype = data.get("type", "")

                if atype == "evaluation_report":
                    reports_found += 1
                    if data.get("passed"):
                        passed += 1
                    else:
                        failed += 1

                elif atype == "evaluation_certification":
                    certs += 1
                    status = data.get("certification_status", "")
                    if status == "denied":
                        denied += 1
                    valid_until = data.get("valid_until", "")
                    if valid_until:
                        try:
                            expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                            if expiry < datetime.now(timezone.utc):
                                expired += 1
                        except (ValueError, TypeError):
                            pass

                elif atype == "signed_evaluation_suite":
                    suites_found += 1

            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    result["trusted_suites"] = suites_found
    result["total_reports"] = reports_found
    result["passed_reports"] = passed
    result["failed_reports"] = failed
    result["certifications"] = certs
    result["expired_certs"] = expired
    result["denied_certs"] = denied

    # Health
    health = HEALTHY
    if failed > 0:
        health = WARNING
    if expired > 0 or denied > 0:
        health = DEGRADED
    result["health"] = health

    return result


def collect_recovery_status(
    state_manager: Any | None = None,
    trace_dir: str = "data/traces",
) -> dict[str, Any]:
    """Collect operator recovery backlog for dashboard health rules (v2.46.0).

    Classifies every persisted run via RecoveryService and counts those in a
    non-terminal recovery state (anything except COMPLETED/CANCELLED). Drives
    HR-049 so an operator scanning the dashboard sees recovery work.
    """
    # Existence semantics (#15): a None state manager means the configured DB
    # does not exist (clean/fresh environment). Do NOT fall back to the default
    # production DB — that would read real runs and fire HR-049 on an empty
    # environment. Absence is not a recovery backlog.
    if state_manager is None:
        return {"actionable_run_count": 0, "runs": []}
    try:
        from nodechain.runtime.recovery_service import RecoveryService
        from nodechain.runtime.recovery_classifier import RecoveryState
        service = RecoveryService(state_manager=state_manager, trace_dir=trace_dir)
        terminal = {RecoveryState.COMPLETED.value, RecoveryState.CANCELLED.value}
        actionable: list[dict[str, Any]] = []
        for summary in service.list_runs():
            snapshot = service.build_snapshot(summary.run_id)
            if snapshot and snapshot.recovery_state not in terminal:
                actionable.append({
                    "run_id": summary.run_id,
                    "status": summary.status,
                    "recovery_state": snapshot.recovery_state,
                    "blocking_reason": snapshot.blocking_reason,
                    "updated_at": summary.updated_at,
                })
        return {
            "actionable_run_count": len(actionable),
            "runs": actionable,
        }
    except Exception:
        # Dashboard must never crash on a collector failure.
        return {"actionable_run_count": 0, "runs": []}


def collect_recovery_metrics_status() -> dict[str, Any]:
    """v3.5.0 T9: recovery retry metrics from recovery_metric_events.

    Fail-soft: missing table or DB → empty section. An empty table means
    'no samples', NOT unhealthy — does not degrade overall dashboard health.
    Aggregation: success rate derived (completed / (completed+failed+unknown),
    None when denominator zero). Adapter top-20 by count DESC, adapter_id ASC.
    Latency percentiles via nearest-rank (ceil(p*n)-1).

    Read-only: does NOT create the DB if absent (INV: dashboard never writes).

    Return schema is identical across all paths (success, missing-DB, exception):
    outcomes, total_outcomes, success_rate, rejections, latencies,
    adapter_top20, samples.
    """
    # Normalized empty result — identical schema across all return paths.
    empty = {
        "outcomes": {"completed": 0, "failed": 0, "unknown": 0},
        "total_outcomes": 0, "success_rate": None,
        "rejections": {}, "latencies": {},
        "adapter_top20": [], "samples": 0,
    }
    db_path = _get_db_path()
    # Read-only guard: never create a DB file just to read metrics.
    from pathlib import Path as _Path
    if not _Path(db_path).exists():
        return empty
    try:
        import sqlite3 as _sqlite3
        import json as _json
        from math import ceil as _ceil
        with _sqlite3.connect(db_path) as conn:
            # Outcome counts
            rows = conn.execute(
                """SELECT metric_name, SUM(value) FROM recovery_metric_events
                   WHERE metric_name IN ('retry_outcome_completed',
                         'retry_outcome_failed', 'retry_unknown_total')
                   GROUP BY metric_name"""
            ).fetchall()
            outcomes_raw = {r[0]: int(r[1] or 0) for r in rows}
            completed = outcomes_raw.get("retry_outcome_completed", 0)
            failed = outcomes_raw.get("retry_outcome_failed", 0)
            unknown = outcomes_raw.get("retry_unknown_total", 0)
            denom = completed + failed + unknown
            success_rate = (completed / denom) if denom > 0 else None

            # Rejection counters
            rej_rows = conn.execute(
                """SELECT metric_name, SUM(value) FROM recovery_metric_events
                   WHERE metric_name IN ('retry_policy_denied_total',
                         'retry_rejected_total', 'retry_material_unavailable_total',
                         'retry_legacy_ineligible_total', 'retry_no_operation_total',
                         'retry_requeued')
                   GROUP BY metric_name"""
            ).fetchall()
            rejections = {r[0]: int(r[1] or 0) for r in rej_rows}

            # Latency: nearest-rank percentiles (ceil(p*n) - 1)
            lat_rows = conn.execute(
                """SELECT metric_name, value FROM recovery_metric_events
                   WHERE metric_name IN ('retry_command_latency_ms',
                         'retry_attempt_latency_ms') ORDER BY value"""
            ).fetchall()
            latencies: dict[str, dict] = {}
            lat_by_name: dict[str, list[float]] = {}
            for name, val in lat_rows:
                lat_by_name.setdefault(name, []).append(val)
            for name, vals in lat_by_name.items():
                vals.sort()
                n = len(vals)
                latencies[name] = {
                    "count": n,
                    "p50": vals[_ceil(0.50 * n) - 1] if n else None,
                    "p95": vals[_ceil(0.95 * n) - 1] if n else None,
                }

            # Adapter top-20: extract adapter_id from labels_json on outcome
            # metrics, aggregate by count, sort count DESC then adapter_id ASC,
            # truncate to 20. Adapters beyond top-20 are NOT aggregated into
            # "other" here (the raw data is preserved; binning is display-only).
            adapter_counts: dict[str, int] = {}
            adapter_rows = conn.execute(
                """SELECT labels_json, SUM(value) FROM recovery_metric_events
                   WHERE metric_name IN ('retry_outcome_completed',
                         'retry_outcome_failed', 'retry_unknown_total')
                   GROUP BY labels_json"""
            ).fetchall()
            for labels_json, total in adapter_rows:
                try:
                    labels = _json.loads(labels_json or "{}")
                    aid = labels.get("adapter_id")
                    if aid:
                        adapter_counts[aid] = adapter_counts.get(aid, 0) + int(total or 0)
                except (ValueError, TypeError):
                    continue
            # Sort: count DESC, adapter_id ASC for deterministic ties.
            # Top 20 are listed individually; adapters beyond top-20 are
            # aggregated into an "other" bucket per the T9 verification matrix.
            sorted_adapters = sorted(
                adapter_counts.items(), key=lambda kv: (-kv[1], kv[0]),
            )
            top20 = sorted_adapters[:20]
            other_count = sum(cnt for _, cnt in sorted_adapters[20:])
            adapter_top20 = [
                {"adapter_id": aid, "count": cnt} for aid, cnt in top20
            ]
            if other_count > 0:
                adapter_top20.append({"adapter_id": "other", "count": other_count})
    except Exception:
        return empty

    return {
        "outcomes": {"completed": completed, "failed": failed, "unknown": unknown},
        "total_outcomes": denom,
        "success_rate": success_rate,
        "rejections": rejections,
        "latencies": latencies,
        "adapter_top20": adapter_top20,
        "samples": denom,
    }


def collect_review_workbench_status(
    review_queue: Any | None = None,
    state_manager: Any | None = None,
) -> dict[str, Any]:
    """Collect review workbench status for dashboard health rules.

    Populates the fields that HR-045 through HR-048 evaluate:
      stale_count            — pending requests older than 72h (HR-045)
      unauthorized_attempts  — unauthorized decision attempts (HR-046)
      stale_decision_count   — decisions referencing stale requests (HR-047)
      rejected_blocking_count — rejected decisions blocking workflows (HR-048)

    v2.24.0: derives stale_count, rejected_blocking_count, and
    stale_decision_count from durable chain state when a state_manager is
    provided (scans runs with governed-review metadata). The legacy
    review_queue path is still honored for back-compat.

    v2.25.0: unauthorized_attempts (HR-046) now derives from the durable
    review_decision_attempts log — counts only authorization/admissibility
    rejections (REJECT_UNAUTHORIZED, REJECT_DECISION_TYPE_MISMATCH,
    REJECT_SUBJECT_TYPE_MISMATCH, REJECT_NO_REQUEST), NOT every verifier
    failure. Digest/rationale/staleness failures are integrity issues, not
    unauthorized attempts.
    """
    stale_count = 0
    stale_decision_count = 0
    rejected_blocking_count = 0
    unauthorized_attempts = 0
    unauthorized_available = False
    pending_count = 0
    total_count = 0
    enabled = False

    # Primary source: durable chain state (v2.24.0) + attempt log (v2.25.0).
    if state_manager is not None:
        enabled = True
        try:
            from nodechain.sdk.review_workbench import ReviewRequest, ReviewSubject

            for state in state_manager.list_all_review_states():
                md = state.metadata or {}
                gov_req = md.get("governed_review_request")
                receipt = md.get("governed_decision_receipt")

                # HR-045: pending review older than 72h (run still waiting).
                if gov_req and state.status == "waiting_for_review":
                    pending_count += 1
                    total_count += 1
                    if _is_request_stale(gov_req):
                        stale_count += 1

                # HR-048: rejected decision blocking a workflow (terminal + reject).
                if receipt and state.status in ("failed", "rejected", "rejected_by_reviewer"):
                    outcome = (receipt.get("decision") or {}).get("outcome", "")
                    if outcome == "reject":
                        rejected_blocking_count += 1

                # HR-047: decision referencing a stale request. We have a real
                # decision timestamp (receipt.created_at == decision.decided_at),
                # so use "request age at decision time > 72h" (strict definition).
                if receipt and gov_req:
                    if _request_was_stale_at_decision(gov_req, receipt):
                        stale_decision_count += 1

            # v2.25.0: HR-046 — unauthorized_attempts from the durable decision
            # attempt log. Counts only authorization/admissibility rejections
            # (NOT every verifier failure — digest/rationale failures aren't
            # unauthorized). Precise per the strict classification.
            unauthorized_available = True
            for att in state_manager.get_review_attempts(admitted=False):
                if _is_authorization_rejection(att.get("rejection_reason", "")):
                    unauthorized_attempts += 1
        except Exception:
            # Defensive: never let dashboard collection crash on a malformed row.
            unauthorized_available = False

    # Legacy/in-memory source still honored if explicitly provided.
    if review_queue is not None:
        enabled = True
        pending = review_queue.list_pending()
        pending_count = len(pending)
        total_count = max(total_count, review_queue.total_count)
        stale_count = max(stale_count, len(review_queue.list_stale()))

    return {
        "enabled": enabled,
        "pending_count": pending_count,
        "total_count": total_count,
        "stale_count": stale_count,
        "unauthorized_attempts": unauthorized_attempts,
        # v2.25.0: HR-046 now derives from the durable review_decision_attempts
        # log when a state_manager is wired. When unavailable (no state_manager
        # or scan error), this surfaces honestly to consumers.
        "unauthorized_attempts_available": unauthorized_available,
        "unauthorized_attempts_source": (
            "review_decision_attempts_log" if unauthorized_available
            else "not_durable_until_review_decision_attempt_log"
        ),
        "stale_decision_count": stale_decision_count,
        "rejected_blocking_count": rejected_blocking_count,
        "health": WARNING if stale_count > 0 else HEALTHY,
    }


def _is_request_stale(gov_req: dict) -> bool:
    """A pending governed request is stale if created_at is older than 72h."""
    created_at = gov_req.get("created_at")
    if not created_at:
        return False
    try:
        created = datetime.fromisoformat(created_at)
        age = datetime.now(timezone.utc) - created
        return age.total_seconds() > 72 * 3600
    except (ValueError, TypeError):
        return False


def _request_was_stale_at_decision(gov_req: dict, receipt: dict) -> bool:
    """True if the governed request was already >72h old when decided.

    Uses the real decision timestamp: DecisionReceipt.created_at is set to
    OperatorDecision.decided_at at commit time, so this is a strict 'request
    age at decision time' measure (not a collection-time approximation).
    """
    created_at = gov_req.get("created_at")
    decided_at = receipt.get("created_at")
    if not created_at or not decided_at:
        return False
    try:
        created = datetime.fromisoformat(created_at)
        decided = datetime.fromisoformat(decided_at)
        return (decided - created).total_seconds() > 72 * 3600
    except (ValueError, TypeError):
        return False


# v2.25.0: HR-046 classification. Only authorization/admissibility rejections
# count as "unauthorized attempts" — data/integrity failures (digest mismatch,
# missing rationale, staleness) are NOT unauthorized. Keeps HR-046 precise.
_AUTHORIZATION_REJECTION_REASONS = frozenset({
    "reject_unauthorized_reviewer",
    "reject_decision_type_not_valid_for_subject",
    "reject_subject_type_mismatch",
    "reject_no_review_request",
})


def _is_authorization_rejection(reason: str) -> bool:
    """True iff the rejection reason is an authorization/admissibility failure
    (counts toward HR-046 unauthorized_attempts), not a data/integrity failure."""
    return reason in _AUTHORIZATION_REJECTION_REASONS


def collect_memory_status(state_manager: Any | None = None) -> dict[str, Any]:
    """Collect memory governance status for dashboard health rules (v2.30.0).

    Derives 9 counters from the durable memory_decisions table. ChromaDB
    health_check is excluded (network dependency — could hang the dashboard).
    """
    total = allowed = denied = skipped = errors = 0
    denied_low_conf = denied_high_sens = committed = uncommitted_allowed = 0
    available = False

    if state_manager is not None:
        available = True
        try:
            decisions = state_manager.get_memory_decisions()
            total = len(decisions)
            for d in decisions:
                dec = d.get("decision", "")
                wref = d.get("write_ref", "")
                rule = d.get("rule_id", "")
                if dec == "allow":
                    allowed += 1
                    if wref:
                        committed += 1
                    else:
                        uncommitted_allowed += 1
                elif dec == "deny":
                    denied += 1
                    if rule == "memory.block_low_confidence":
                        denied_low_conf += 1
                    elif rule == "memory.block_high_sensitivity":
                        denied_high_sens += 1
                elif dec == "skip":
                    skipped += 1
                elif dec == "error":
                    errors += 1
        except Exception:
            available = False

    health = HEALTHY
    if errors > 0:
        health = worst_health(health, DEGRADED)
    if uncommitted_allowed > 0:
        health = worst_health(health, CRITICAL)
    if denied_high_sens > 0:
        health = worst_health(health, WARNING)

    return {
        "enabled": available,
        "memory_total_decisions": total,
        "memory_allowed_count": allowed,
        "memory_denied_count": denied,
        "memory_skipped_count": skipped,
        "memory_error_count": errors,
        "memory_denied_low_confidence_count": denied_low_conf,
        "memory_denied_high_sensitivity_count": denied_high_sens,
        "memory_committed_write_count": committed,
        "memory_uncommitted_allowed_count": uncommitted_allowed,
        "chromadb_health_available": False,
        "chromadb_health_source": "excluded_network_dependency",
        "health": health,
    }


    """Collect evaluation/certification spine status."""



    """Collect evaluation and certification status."""
    result: dict[str, Any] = {
        "trusted_suites": 0,
        "total_reports": 0,
        "passed_reports": 0,
        "failed_reports": 0,
        "certifications": 0,
        "expired_certs": 0,
        "denied_certs": 0,
        "health": UNKNOWN,
    }

    eval_dir = Path("data")
    suites_found = 0
    reports_found = 0
    passed = 0
    failed = 0
    certs = 0
    expired = 0
    denied = 0

    if eval_dir.exists():
        for f in eval_dir.glob("*.json"):
            if f.name in ("trust_store.json", "certified_registry.json", "release_history.json"):
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                atype = data.get("type", "")

                if atype == "evaluation_report":
                    reports_found += 1
                    if data.get("passed"):
                        passed += 1
                    else:
                        failed += 1

                elif atype == "evaluation_certification":
                    certs += 1
                    status = data.get("certification_status", "")
                    if status == "denied":
                        denied += 1
                    valid_until = data.get("valid_until", "")
                    if valid_until:
                        try:
                            expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                            if expiry < datetime.now(timezone.utc):
                                expired += 1
                        except (ValueError, TypeError):
                            pass

                elif atype == "signed_evaluation_suite":
                    suites_found += 1

            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    result["trusted_suites"] = suites_found
    result["total_reports"] = reports_found
    result["passed_reports"] = passed
    result["failed_reports"] = failed
    result["certifications"] = certs
    result["expired_certs"] = expired
    result["denied_certs"] = denied

    # Health
    health = HEALTHY
    if failed > 0:
        health = WARNING
    if expired > 0 or denied > 0:
        health = DEGRADED
    result["health"] = health

    return result


def collect_memory_read_status(
    state_manager: Any | None = None,
) -> dict[str, Any]:
    """Collect memory-read governance dashboard status (v2.41.0).

    All counters come from real durable data (memory_read_decisions table
    and state_events). No stubs — if data is unavailable, enabled=False.

    Distinction:
      requested = MEMORY_READ_ALLOWED + MEMORY_READ_DENIED events (policy evaluated)
      allowed = durable allow decisions
      denied = durable deny decisions
      exposed = MEMORY_READ_EXPOSED events (actual context exposure, not just auth)
      without_decision = exposed events without matching durable decision
    """
    import sqlite3
    import json as _json
    enabled = False
    lookup_failed = False
    requested = allowed = denied = exposed = without_decision = mismatch = 0
    exposed_nodes: set[str] = set()
    decision_count = 0

    if state_manager is not None:
        db_path = getattr(state_manager, "db_path", None)
        if db_path:
            try:
                with sqlite3.connect(db_path) as conn:
                    # Decision counts from memory_read_decisions
                    cur = conn.execute(
                        "SELECT decision, COUNT(*), "
                        "SUM(CASE WHEN exposed_to_node=1 THEN 1 ELSE 0 END) "
                        "FROM memory_read_decisions GROUP BY decision",
                    )
                    for dec, cnt, exposed_cnt in cur.fetchall():
                        decision_count += cnt
                        if dec == "allow":
                            allowed = cnt
                        elif dec == "deny":
                            denied = cnt

                    # Build durable decision lookup for mismatch detection
                    # v2.41.2: include step_id for identity binding
                    # v2.41.3: include run_id for cross-run binding
                    cur_dec = conn.execute(
                        "SELECT decision_id, run_id, node_id, step_id, decision "
                        "FROM memory_read_decisions",
                    )
                    durable_decisions: dict[str, dict] = {}
                    for did, rid, nid, sid, dec in cur_dec.fetchall():
                        durable_decisions[did] = {
                            "run_id": rid, "node_id": nid,
                            "step_id": sid, "decision": dec,
                        }
                    allow_ids = {
                        did for did, info in durable_decisions.items()
                        if info["decision"] == "allow"
                    }

                    # Exposure events (actual memory in context)
                    # v2.41.1: parse _emit-shaped payload — metadata is nested
                    # v2.41.3: also load run_id from state_events
                    cur2 = conn.execute(
                        "SELECT run_id, payload FROM state_events "
                        "WHERE event_type LIKE '%memory_read_exposed%'",
                    )
                    for row in cur2.fetchall():
                        exposed += 1
                        evt_run_id = row[0]
                        try:
                            payload = _json.loads(row[1]) if row[1] else {}
                        except Exception:
                            payload = {}
                        # v2.41.1: metadata may be nested under "metadata" key
                        # (from _emit) OR at top level (from test fixtures)
                        meta = payload.get("metadata", payload)
                        node_id = meta.get("node_id", "")
                        if node_id:
                            exposed_nodes.add(node_id)
                        did = meta.get("decision_id", "")
                        evt_step_id = meta.get("step_id")

                        # v2.41.1 blocker 4: missing decision_id = without_decision
                        if not did:
                            without_decision += 1
                            continue

                        # v2.41.1 blocker 1: check against durable decisions
                        if did not in allow_ids:
                            # Not an allow — either deny, or doesn't exist
                            if did in durable_decisions:
                                # v2.41.1 blocker 3: durable decision exists
                                # but is deny — that's a policy mismatch
                                mismatch += 1
                            else:
                                without_decision += 1
                            continue

                        # v2.41.2: identity binding — the allow decision must
                        # match the exposure event's node_id and step_id
                        # v2.41.3: also match run_id
                        durable = durable_decisions.get(did, {})
                        if durable.get("node_id") and node_id and \
                           durable["node_id"] != node_id:
                            mismatch += 1
                            continue
                        if durable.get("step_id") is not None and \
                           evt_step_id is not None and \
                           durable["step_id"] != evt_step_id:
                            mismatch += 1
                            continue
                        if durable.get("run_id") and evt_run_id and \
                           durable["run_id"] != evt_run_id:
                            mismatch += 1
                            continue

                    requested = allowed + denied
                    enabled = True
            except Exception:
                enabled = False
                lookup_failed = True

    health = HEALTHY
    if without_decision > 0:
        health = worst_health(health, CRITICAL)
    if mismatch > 0:
        health = worst_health(health, CRITICAL)
    if denied > 0:
        health = worst_health(health, WARNING)

    return {
        "enabled": enabled,
        "lookup_failed": lookup_failed,  # v2.41.1: MR-005 signal
        "memory_read_requested_count": requested,
        "memory_read_allowed_count": allowed,
        "memory_read_denied_count": denied,
        "memory_read_without_decision_count": without_decision,
        "memory_read_policy_mismatch_count": mismatch,
        "memory_read_decision_count": decision_count,
        "nodes_with_memory_exposure": sorted(exposed_nodes),
        "memory_read_exposed_node_count": len(exposed_nodes),
        "health": health,
    }


def collect_workflow_recovery_status(
    state_manager: Any | None = None,
    *,
    contract_violation_count: int = 0,
    unreconciled_completed_count: int = 0,
) -> dict[str, Any]:
    """Collect workflow-recovery / side-effect lifecycle status (v2.33.0).

    Activates the previously-dormant ``workflow_recovery`` dashboard section
    that HR-022..025 evaluate. Derives counters from the durable
    ``side_effect_ledger`` so the reconciler's Check 4d (unknown side effects)
    and HR-025 (unresolved side-effect ambiguity) have real data to bind to.

    ``enabled`` is True only when a state_manager is wired and the ledger
    lookup succeeded — so absent data never masquerades as "all clear".
    """
    unknown = started = completed = failed = planned = 0
    blocked_count = denied_count = require_approval_count = 0
    recovery_decision_count = retry_authorized_count = unrecoverable_count = 0
    available = False
    ledger_lookup_failed = False  # v2.37.1: real signal for SE-005

    if state_manager is not None:
        # v2.40.4: _count_side_effects_by_status returns (counts, failed)
        rows, lookup_failed = _count_side_effects_by_status(state_manager)
        if lookup_failed:
            available = False
            ledger_lookup_failed = True
        else:
            unknown = rows.get("unknown", 0)
            started = rows.get("started", 0)
            completed = rows.get("completed", 0)
            failed = rows.get("failed", 0)
            planned = rows.get("planned", 0)
            available = True

        # v2.34.0: side-effect blocked-attempt counters (runtime gate denials)
        if available:
            try:
                blocks = state_manager.get_side_effect_blocks()
                blocked_count = len(blocks)
                for b in blocks:
                    dec = b.get("decision", "")
                    if dec == "deny":
                        denied_count += 1
                    elif dec == "require_approval":
                        require_approval_count += 1
            except Exception:
                pass

        # v2.39.0: recovery decision counters
        if available:
            try:
                rd_list = state_manager.get_recovery_decisions()
                recovery_decision_count = len(rd_list)
                for rd in rd_list:
                    dec = rd.get("decision", "")
                    if dec == "safe_to_retry":
                        retry_authorized_count += 1
                    elif dec == "mark_unrecoverable":
                        unrecoverable_count += 1
            except Exception:
                pass

        # v2.37.2: real trace-sourced counters from events table
        if available:
            # SE-003: count CONTRACT_VIOLATION events
            if contract_violation_count == 0:
                contract_violation_count = _count_events_by_type(
                    state_manager, "contract_violation",
                )
            # SE-006: key-level matching (v2.40.4) — count SIDE_EFFECT_COMPLETED
            # trace events whose idempotency_key has no matching completed
            # ledger row. Not aggregate subtraction.
            if unreconciled_completed_count == 0:
                unreconciled_completed_count = _count_unreconciled_completed(
                    state_manager,
                )

    total = unknown + started + completed + failed + planned

    health = HEALTHY
    if unknown > 0:
        health = worst_health(health, WARNING)
    if failed > 0:
        health = worst_health(health, DEGRADED)

    return {
        "enabled": available,
        "unknown_side_effect_count": unknown,
        "started_side_effect_count": started,
        "completed_side_effect_count": completed,
        "failed_side_effect_count": failed,
        "planned_side_effect_count": planned,
        "side_effect_total_count": total,
        "side_effect_blocked_count": blocked_count,
        "side_effect_denied_count": denied_count,
        "side_effect_require_approval_count": require_approval_count,
        "undeclared_side_effect_count": contract_violation_count,
        "unreconciled_completed_count": unreconciled_completed_count,
        # v2.38.0: idempotency/dedup counters (stubs — wired from reconciler
        # output when available; see the reviewer's v2.38.0 gate 6)
        "idempotency_collision_count": 0,
        "duplicate_completed_count": 0,
        "request_hash_mismatch_count": 0,
        "response_hash_mismatch_count": 0,
        # v2.39.0: recovery decision counters
        "recovery_decision_count": recovery_decision_count,
        "unresolved_unknown_count": unknown,
        "retry_authorized_count": retry_authorized_count,
        "unrecoverable_side_effect_count": unrecoverable_count,
        "needs_intervention": unknown > 0,
        "ledger_lookup_failed": ledger_lookup_failed,  # v2.37.1: SE-005 signal
        "restore_failed": False,
        "restore_error": None,
        "environment_binding_changes": 0,
        "health": health,
    }


def _count_side_effects_by_status(
    state_manager: Any,
) -> tuple[dict[str, int], bool]:
    """Return a ({status: count} map, lookup_failed flag) over the
    entire side_effect_ledger table (v2.40.4).

    The StateManager's public accessors are run-scoped; the dashboard needs a
    cross-run aggregate. This reads the table directly via sqlite3 using the
    manager's ``db_path``. Returns (counts, True) on failure so the caller
    can set ledger_lookup_failed for SE-005.
    """
    import sqlite3
    counts: dict[str, int] = {}
    try:
        db_path = getattr(state_manager, "db_path", None)
        if not db_path:
            return counts, True  # no db_path = can't look up
        with sqlite3.connect(db_path) as conn:
            cur = conn.execute(
                "SELECT status, COUNT(*) FROM side_effect_ledger GROUP BY status",
            )
            for status, n in cur.fetchall():
                counts[status] = n
    except Exception:
        return counts, True  # lookup failed
    return counts, False


def _count_unreconciled_completed(
    state_manager: Any,
) -> int:
    """Count SIDE_EFFECT_COMPLETED trace events whose idempotency_key has
    no matching completed ledger row (v2.40.4).

    Key-level matching, not aggregate subtraction. Reads state_events and
    side_effect_ledger directly via sqlite3.
    """
    import sqlite3
    try:
        db_path = getattr(state_manager, "db_path", None)
        if not db_path:
            return 0
        with sqlite3.connect(db_path) as conn:
            # Get completed trace event keys from payload JSON
            cur = conn.execute(
                "SELECT payload FROM state_events "
                "WHERE event_type LIKE '%side_effect_completed%'",
            )
            trace_keys: set[str] = set()
            for row in cur.fetchall():
                import json as _json
                try:
                    meta = _json.loads(row[0]) if row[0] else {}
                except Exception:
                    meta = {}
                key = meta.get("idempotency_key", "")
                if key:
                    trace_keys.add(key)

            if not trace_keys:
                return 0

            # Get completed ledger keys
            cur2 = conn.execute(
                "SELECT idempotency_key FROM side_effect_ledger "
                "WHERE status = 'completed'",
            )
            ledger_keys = {r[0] for r in cur2.fetchall()}

            # Count trace keys not in ledger
            return len(trace_keys - ledger_keys)
    except Exception:
        return 0


def _count_events_by_type(
    state_manager: Any,
    event_type_substring: str,
) -> int:
    """Count events matching a type substring across ALL runs (v2.37.2).

    The StateManager's get_events is run-scoped; the dashboard is cross-run.
    Reads the events table directly via sqlite3.
    """
    import sqlite3
    try:
        db_path = getattr(state_manager, "db_path", None)
        if not db_path:
            return 0
        with sqlite3.connect(db_path) as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM state_events WHERE event_type LIKE ?",
                (f"%{event_type_substring}%",),
            )
            return cur.fetchone()[0]
    except Exception:
        return 0


# ── v2.67.3: Reuse + Scorecards collectors ──────────────────────────────────


def collect_reuse_status() -> dict[str, Any]:
    """Collect registry-resolved reuse proof status (v2.67.3).

    Shows whether the shared deterministic nodes are:
    - Present in the local registry
    - Resolved with local_registry provenance
    - Pinned by lockfile with matching content_digest

    Health:
      HEALTHY   = all nodes registry-resolved + lockfile passes
      WARNING   = nodes resolved but lockfile missing (absence of enforcement)
      DEGRADED  = nodes not resolvable, OR lockfile present but mismatch (failed proof)
    """
    from nodechain.runtime.node_quality_scorecard import get_shared_registry_node_ids

    try:
        node_ids = get_shared_registry_node_ids()
        nodes_info: list[dict[str, Any]] = []
        all_resolved = True

        for nid in node_ids:
            try:
                from nodechain.sdk.loader import NodeLoader
                loader = NodeLoader()
                node = loader.load(nid)
                origin = getattr(node, "_node_origin", "unknown")
                package_root = getattr(node, "_package_root", "")
                module_path = getattr(node, "_module_path", "")

                # Get content_digest from registry
                pkg = loader.registry.get_package(nid)
                content_digest = pkg.content_digest() if pkg else ""

                nodes_info.append({
                    "node_id": nid,
                    "resolved": True,
                    "origin": origin,
                    "package_root": str(package_root) if package_root else "",
                    "module_path": str(module_path) if module_path else "",
                    "content_digest": content_digest,
                    "digest_len": len(content_digest) if content_digest else 0,
                })
            except Exception:
                all_resolved = False
                nodes_info.append({
                    "node_id": nid,
                    "resolved": False,
                    "origin": "unresolved",
                    "package_root": "",
                    "module_path": "",
                    "content_digest": "",
                    "digest_len": 0,
                })

        # Check lockfile
        from nodechain.sdk.lockfile import LOCKFILE_NAME, enforce_lockfile_for_nodes
        from pathlib import Path as _Path
        lockfile_path = _Path(LOCKFILE_NAME)
        lockfile_exists = lockfile_path.exists()

        lockfile_ok = False
        lockfile_errors: list[str] = []
        if lockfile_exists and all_resolved:
            ok, errors = enforce_lockfile_for_nodes(node_ids, registry=loader.registry if "loader" in dir() else None)
            lockfile_ok = ok
            lockfile_errors = errors
        elif lockfile_exists and not all_resolved:
            lockfile_ok = False
            lockfile_errors = ["cannot verify: nodes not resolved"]

        # Health computation
        if not all_resolved:
            health = DEGRADED
        elif not lockfile_exists:
            health = WARNING
        elif not lockfile_ok:
            health = DEGRADED
        else:
            health = HEALTHY

        return {
            "shared_nodes": len(node_ids),
            "nodes_resolved": sum(1 for n in nodes_info if n["resolved"]),
            "nodes": nodes_info,
            "lockfile": {
                "exists": lockfile_exists,
                "ok": lockfile_ok,
                "errors": lockfile_errors,
            },
            "health": health,
        }
    except Exception:
        return {
            "shared_nodes": 0,
            "nodes_resolved": 0,
            "nodes": [],
            "lockfile": {"exists": False, "ok": False, "errors": ["collector error"]},
            "health": UNKNOWN,
        }


def collect_scorecards_status() -> dict[str, Any]:
    """Collect cached node quality scorecard status (v2.67.3).

    Reads the scorecard cache. Does NOT run scorecards (use --refresh for that).

    Health precedence:
      UNKNOWN   = missing cache (never refreshed)
      DEGRADED  = invalid cache, OR any failing report, OR required nodes absent
      WARNING   = stale but passing, OR partial reports
      HEALTHY   = fresh and all passing
    """
    from nodechain.runtime.node_quality_scorecard import (
        DEFAULT_SCORECARD_CACHE_PATH, load_scorecard_cache,
        is_scorecard_cache_stale, get_shared_registry_node_ids,
    )

    try:
        cache_path = DEFAULT_SCORECARD_CACHE_PATH

        # Missing cache → UNKNOWN (correction #4)
        if not cache_path.exists():
            return {
                "cache_exists": False,
                "status": "missing",
                "health": UNKNOWN,
                "summary": {},
                "reports": [],
            }

        # Invalid cache → DEGRADED (correction #4)
        cache = load_scorecard_cache(cache_path)
        if cache is None:
            return {
                "cache_exists": True,
                "status": "invalid",
                "health": DEGRADED,
                "summary": {},
                "reports": [],
            }

        summary = cache.get("summary", {})
        reports = cache.get("reports", [])
        generated_at = cache.get("generated_at", "")

        # Check which required nodes are present
        required_ids = set(get_shared_registry_node_ids())
        present_ids = {r.get("node_id", "") for r in reports}
        missing_nodes = required_ids - present_ids

        # Check staleness
        try:
            from nodechain.registry.local_registry import RegistryIndex
            reg = RegistryIndex()
            reg.scan()
            stale, stale_reasons = is_scorecard_cache_stale(cache, reg)
        except Exception:
            stale = False
            stale_reasons = []

        # Any failing?
        any_failing = any(not r.get("passed", False) for r in reports)

        # Health computation
        if any_failing or missing_nodes:
            health = DEGRADED
        elif stale:
            health = WARNING
        elif len(reports) < len(required_ids):
            health = WARNING  # partial
        else:
            health = HEALTHY

        return {
            "cache_exists": True,
            "status": "stale" if stale else ("pass" if summary.get("status") == "pass" else "fail"),
            "health": health,
            "summary": summary,
            "generated_at": generated_at,
            "reports": reports,
            "stale": stale,
            "stale_reasons": stale_reasons,
            "missing_nodes": list(missing_nodes),
        }
    except Exception:
        return {
            "cache_exists": False,
            "status": "error",
            "health": UNKNOWN,
            "summary": {},
            "reports": [],
        }


# ── Aggregate Dashboard ─────────────────────────────────────────────────────

def collect_dashboard() -> dict[str, Any]:
    """Collect full dashboard status across all spines."""
    runtime = collect_runtime_status()
    trust = collect_trust_status()
    registry = collect_registry_status()
    evidence = collect_evidence_status()
    operations = collect_operations_status()
    evaluation = collect_evaluation_status()
    reuse = collect_reuse_status()
    scorecards = collect_scorecards_status()

    # Overall health
    overall = worst_health(
        trust.get("health", UNKNOWN),
        registry.get("health", UNKNOWN),
        evidence.get("health", UNKNOWN),
        operations.get("health", UNKNOWN),
        evaluation.get("health", UNKNOWN),
        reuse.get("health", UNKNOWN),
        scorecards.get("health", UNKNOWN),
    )

    # Detect issues for health classification
    issues: list[str] = []
    if trust.get("legacy_keys", 0) > 0:
        issues.append(f"{trust['legacy_keys']} legacy trust keys without purpose")
    if not trust.get("snapshot_signed"):
        issues.append("Trust store snapshot not signed")
    if registry.get("revoked", 0) > 0:
        issues.append(f"{registry['revoked']} revoked registry entries")
    if registry.get("denied", 0) > 0:
        issues.append(f"{registry['denied']} denied registry entries")
    if evidence.get("broken_chains", 0) > 0:
        issues.append(f"{evidence['broken_chains']} broken evidence chains")
    if operations.get("drift_detected", 0) > 0:
        issues.append(f"{operations['drift_detected']} unresolved drift(s)")
    if evaluation.get("failed_reports", 0) > 0:
        issues.append(f"{evaluation['failed_reports']} failed evaluation(s)")
    if evaluation.get("expired_certs", 0) > 0:
        issues.append(f"{evaluation['expired_certs']} expired certification(s)")
    if evaluation.get("denied_certs", 0) > 0:
        issues.append(f"{evaluation['denied_certs']} denied certification(s)")
    if runtime.get("paused_reviews", 0) > 0:
        issues.append(f"{runtime['paused_reviews']} paused human review(s)")
    # v2.67.3: reuse/scorecard health affects overall dashboard health
    if reuse.get("health") not in (HEALTHY, UNKNOWN):
        issues.append(f"reuse proof health: {reuse.get('health')}")
    if scorecards.get("health") not in (HEALTHY, UNKNOWN):
        issues.append(f"scorecard evidence health: {scorecards.get('health')}")

    if not issues:
        overall = HEALTHY
    elif overall == HEALTHY:
        overall = WARNING

    return {
        "type": "nodechain_dashboard",
        "version": "1.0.0",
        "timestamp": _now_iso(),
        "overall_health": overall,
        "issues": issues,
        "sections": {
            "runtime": runtime,
            "trust": trust,
            "registry": registry,
            "evidence": evidence,
            "operations": operations,
            "evaluation": evaluation,
            "review_workbench": collect_review_workbench_status(),
            "recovery": collect_recovery_status(),
            "recovery_metrics": collect_recovery_metrics_status(),
            "reuse": reuse,
            "scorecards": scorecards,
        },
    }


# ── Rendering ───────────────────────────────────────────────────────────────

def render_dashboard(dashboard: dict[str, Any], section: str = "") -> str:
    """Render dashboard as Rich-formatted text (plain text fallback)."""
    lines: list[str] = []

    if section:
        return _render_section(dashboard, section)

    # Full overview
    overall = dashboard.get("overall_health", UNKNOWN)
    health_color = HEALTH_COLORS.get(overall, "dim")

    lines.append("")
    lines.append(f"  [bold]NodeChain Operator Dashboard[/]")
    lines.append(f"  {'─' * 50}")
    lines.append(f"  Overall Health: [{health_color}]{overall.upper()}[/]")
    lines.append(f"  Timestamp: {dashboard.get('timestamp', '')}")
    lines.append("")

    issues = dashboard.get("issues", [])
    if issues:
        lines.append(f"  [yellow]Issues ({len(issues)}):[/]")
        for issue in issues:
            lines.append(f"    • {issue}")
        lines.append("")
    else:
        lines.append("  [green]No issues detected.[/]")
        lines.append("")

    sections = dashboard.get("sections", {})

    # Runtime
    rt = sections.get("runtime", {})
    lines.append(f"  [bold]Runtime[/]")
    lines.append(f"    Active runs:       {rt.get('active_runs', 0)}")
    lines.append(f"    Recent runs:       {len(rt.get('recent_runs', []))}")
    lines.append(f"    Failed runs:       {rt.get('failed_runs', 0)}")
    lines.append(f"    Paused reviews:    {rt.get('paused_reviews', 0)}")
    lines.append(f"    Total runs:        {rt.get('total_runs', 0)}")
    lines.append("")

    # Trust
    tr = sections.get("trust", {})
    lines.append(f"  [bold]Trust[/]")
    lines.append(f"    Store exists:      {tr.get('trust_store_exists', False)}")
    lines.append(f"    Trusted keys:      {tr.get('total_keys', 0)}")
    lines.append(f"    Legacy keys:       {tr.get('legacy_keys', 0)}")
    lines.append(f"    Snapshot signed:   {tr.get('snapshot_signed', False)}")
    lines.append("")

    # Registry
    rg = sections.get("registry", {})
    lines.append(f"  [bold]Registry[/]")
    lines.append(f"    Active packages:   {rg.get('active', 0)}")
    lines.append(f"    Deprecated:        {rg.get('deprecated', 0)}")
    lines.append(f"    Revoked:           {rg.get('revoked', 0)}")
    lines.append(f"    Certified:         {rg.get('certified', 0)}")
    lines.append("")

    # Evidence
    ev = sections.get("evidence", {})
    lines.append(f"  [bold]Evidence[/]")
    lines.append(f"    Indexed artifacts: {ev.get('indexed_artifacts', 0)}")
    lines.append(f"    Broken chains:     {ev.get('broken_chains', 0)}")
    lines.append(f"    Replay failures:   {ev.get('replay_failures', 0)}")
    lines.append("")

    # Operations
    ops = sections.get("operations", {})
    lines.append(f"  [bold]Operations[/]")
    lines.append(f"    Known-good:        {ops.get('known_good_releases', 0)}")
    lines.append(f"    Drift detected:    {ops.get('drift_detected', 0)}")
    lines.append(f"    Remediations:      {ops.get('remediations', 0)}")
    lines.append("")

    # Evaluation
    eval_sect = sections.get("evaluation", {})
    lines.append(f"  [bold]Evaluation[/]")
    lines.append(f"    Trusted suites:    {eval_sect.get('trusted_suites', 0)}")
    lines.append(f"    Total reports:     {eval_sect.get('total_reports', 0)}")
    lines.append(f"    Passed:            {eval_sect.get('passed_reports', 0)}")
    lines.append(f"    Certifications:    {eval_sect.get('certifications', 0)}")
    lines.append(f"    Expired certs:     {eval_sect.get('expired_certs', 0)}")
    lines.append("")

    # Recovery Metrics (v3.5.0 T9) — observability only, never affects health
    rm = sections.get("recovery_metrics", {})
    if rm.get("samples", 0) > 0 or rm.get("outcomes"):
        lines.append(f"  [bold]Recovery Metrics[/]")
        outcomes = rm.get("outcomes", {})
        sr = rm.get("success_rate")
        sr_str = f"{sr:.1%}" if sr is not None else "n/a"
        lines.append(f"    Success rate:      {sr_str}")
        lines.append(f"    Completed:         {outcomes.get('completed', 0)}")
        lines.append(f"    Failed:            {outcomes.get('failed', 0)}")
        lines.append(f"    Unknown:           {outcomes.get('unknown', 0)}")
        rejections = rm.get("rejections", {})
        if rejections:
            lines.append(f"    Policy denied:     {rejections.get('retry_policy_denied_total', 0)}")
            lines.append(f"    Rejected:          {rejections.get('retry_rejected_total', 0)}")
            lines.append(f"    No-operation:      {rejections.get('retry_no_operation_total', 0)}")
            lines.append(f"    Requeued:          {rejections.get('retry_requeued', 0)}")
            lines.append(f"    Mat. unavailable:  {rejections.get('retry_material_unavailable_total', 0)}")
            lines.append(f"    Legacy ineligible: {rejections.get('retry_legacy_ineligible_total', 0)}")
        latencies = rm.get("latencies", {})
        if latencies:
            for lname, ldata in sorted(latencies.items()):
                p50 = ldata.get("p50")
                p95 = ldata.get("p95")
                lines.append(
                    f"    {lname}: p50={p50:.1f}ms p95={p95:.1f}ms (n={ldata.get('count', 0)})"
                    if p50 is not None and p95 is not None
                    else f"    {lname}: n/a (n={ldata.get('count', 0)})"
                )
        adapter_top = rm.get("adapter_top20", [])
        if adapter_top:
            lines.append(f"    Top adapters:")
            for a in adapter_top[:5]:
                lines.append(f"      {a['adapter_id']}: {a['count']}")
        lines.append("")

    # Reuse (v2.67.3)
    ru = sections.get("reuse", {})
    ru_health = ru.get("health", UNKNOWN)
    ru_color = HEALTH_COLORS.get(ru_health, "dim")
    lines.append(f"  [bold]Reuse[/] [{ru_color}]{ru_health}[/]")
    lines.append(f"    Shared nodes:      {ru.get('shared_nodes', 0)}")
    lines.append(f"    Nodes resolved:    {ru.get('nodes_resolved', 0)}")
    lockfile = ru.get("lockfile", {})
    lines.append(f"    Lockfile:          {'present' if lockfile.get('exists') else 'missing'}")
    if lockfile.get("exists"):
        lines.append(f"    Lockfile ok:       {lockfile.get('ok', False)}")
    lines.append("")

    # Scorecards (v2.67.3)
    sc = sections.get("scorecards", {})
    sc_health = sc.get("health", UNKNOWN)
    sc_color = HEALTH_COLORS.get(sc_health, "dim")
    lines.append(f"  [bold]Scorecards[/] [{sc_color}]{sc_health}[/]")
    sc_summary = sc.get("summary", {})
    if sc.get("cache_exists"):
        lines.append(f"    Status:            {sc.get('status', '?')}")
        lines.append(f"    Evaluated:         {sc_summary.get('total', 0)}")
        lines.append(f"    Passing:           {sc_summary.get('passed', 0)}")
        lines.append(f"    Failing:           {sc_summary.get('failed', 0)}")
        if sc.get("stale"):
            lines.append(f"    [yellow]Stale: yes[/]")
    else:
        lines.append(f"    Status:            {sc.get('status', 'missing')}")
        lines.append(f"    [dim]Run 'nodechain dashboard scorecards --refresh' to evaluate[/]")
    lines.append("")

    return "\n".join(lines)


def _render_health(dashboard: dict[str, Any]) -> str:
    """Render health section."""
    overall = dashboard.get("overall_health", UNKNOWN)
    health_color = HEALTH_COLORS.get(overall, "dim")
    lines = [
        "",
        f"  [bold]Dashboard — Health[/]",
        f"  {'─' * 50}",
        f"    Overall: [{health_color}]{overall.upper()}[/]",
    ]
    issues = dashboard.get("issues", [])
    if issues:
        lines.append(f"    Issues:")
        for issue in issues:
            lines.append(f"      • {issue}")
    else:
        lines.append(f"    [green]No issues detected.[/]")
    lines.append("")
    return "\n".join(lines)


def _render_section(dashboard: dict[str, Any], section: str) -> str:
    """Render a single section in detail."""
    if section == "health":
        return _render_health(dashboard)

    sections = dashboard.get("sections", {})
    data = sections.get(section, {})

    if not data:
        return f"\n  No data for section '{section}'.\n"

    lines: list[str] = []
    lines.append("")
    lines.append(f"  [bold]Dashboard — {section.title()}[/]")
    lines.append(f"  {'─' * 50}")

    if section == "runtime":
        lines.append(f"    Active runs: {data.get('active_runs', 0)}")
        lines.append(f"    Total runs:  {data.get('total_runs', 0)}")
        lines.append(f"    Failed:      {data.get('failed_runs', 0)}")
        lines.append(f"    Paused:      {data.get('paused_reviews', 0)}")
        recent = data.get("recent_runs", [])
        if recent:
            lines.append(f"    Recent runs:")
            for r in recent[:5]:
                lines.append(f"      {r['run_id'][:8]}... {r['status']:10s} {r.get('chain_id', '')}")
    elif section == "trust":
        lines.append(f"    Store exists:    {data.get('trust_store_exists', False)}")
        lines.append(f"    Total keys:      {data.get('total_keys', 0)}")
        lines.append(f"    Legacy keys:     {data.get('legacy_keys', 0)}")
        lines.append(f"    Snapshot signed: {data.get('snapshot_signed', False)}")
        purposes = data.get("purposes", {})
        if purposes:
            lines.append(f"    Purposes:")
            for p, c in sorted(purposes.items()):
                lines.append(f"      {p}: {c}")
    elif section == "registry":
        lines.append(f"    Active:      {data.get('active', 0)}")
        lines.append(f"    Deprecated:  {data.get('deprecated', 0)}")
        lines.append(f"    Revoked:     {data.get('revoked', 0)}")
        lines.append(f"    Certified:   {data.get('certified', 0)}")
    elif section == "evidence":
        lines.append(f"    Indexed:        {data.get('indexed_artifacts', 0)}")
        lines.append(f"    Broken chains:  {data.get('broken_chains', 0)}")
        types = data.get("artifact_types", {})
        if types:
            lines.append(f"    Artifact types:")
            for t, c in sorted(types.items()):
                lines.append(f"      {t}: {c}")
    elif section == "deployments":
        ops = sections.get("operations", {})
        lines.append(f"    Known-good releases: {ops.get('known_good_releases', 0)}")
        lines.append(f"    Drift detected:      {ops.get('drift_detected', 0)}")
        lines.append(f"    Remediations:        {ops.get('remediations', 0)}")
    elif section == "drift":
        ops = sections.get("operations", {})
        lines.append(f"    Drift detected:  {ops.get('drift_detected', 0)}")
        lines.append(f"    Remediations:    {ops.get('remediations', 0)}")
    elif section == "evaluations":
        ev = sections.get("evaluation", {})
        lines.append(f"    Trusted suites:  {ev.get('trusted_suites', 0)}")
        lines.append(f"    Total reports:   {ev.get('total_reports', 0)}")
        lines.append(f"    Passed:          {ev.get('passed_reports', 0)}")
        lines.append(f"    Failed:          {ev.get('failed_reports', 0)}")
        lines.append(f"    Certifications:  {ev.get('certifications', 0)}")
        lines.append(f"    Expired certs:   {ev.get('expired_certs', 0)}")
    elif section == "reuse":
        ru = sections.get("reuse", {})
        health = ru.get("health", UNKNOWN)
        color = HEALTH_COLORS.get(health, "dim")
        lines.append(f"  Health:           [{color}]{health}[/]")
        lines.append(f"  Shared nodes:     {ru.get('shared_nodes', 0)}")
        lines.append(f"  Nodes resolved:   {ru.get('nodes_resolved', 0)}")
        lines.append("")
        lines.append(f"  [bold]Node Details:[/]")
        for node in ru.get("nodes", []):
            status = "[green]resolved[/]" if node.get("resolved") else "[red]unresolved[/]"
            digest = node.get("content_digest", "")
            digest_short = digest[:16] + "..." if len(digest) > 16 else digest or "none"
            lines.append(f"    {node['node_id']}:")
            lines.append(f"      Status:     {status}")
            lines.append(f"      Origin:     {node.get('origin', 'unknown')}")
            lines.append(f"      Digest:     {digest_short} ({node.get('digest_len', 0)} chars)")
        lockfile = ru.get("lockfile", {})
        lines.append("")
        lines.append(f"  [bold]Lockfile:[/]")
        lines.append(f"    Exists:       {lockfile.get('exists', False)}")
        if lockfile.get("exists"):
            lines.append(f"    OK:           {lockfile.get('ok', False)}")
            for err in lockfile.get("errors", []):
                lines.append(f"    [red]Error: {err}[/]")
    elif section == "scorecards":
        sc = sections.get("scorecards", {})
        health = sc.get("health", UNKNOWN)
        color = HEALTH_COLORS.get(health, "dim")
        lines.append(f"  Health:           [{color}]{health}[/]")
        lines.append(f"  Cache exists:     {sc.get('cache_exists', False)}")
        lines.append(f"  Status:           {sc.get('status', '?')}")
        if sc.get("generated_at"):
            lines.append(f"  Generated:        {sc.get('generated_at', '')}")
        if sc.get("stale"):
            lines.append(f"  [yellow]Stale: yes[/]")
            for reason in sc.get("stale_reasons", []):
                lines.append(f"    [yellow]• {reason}[/]")
        summary = sc.get("summary", {})
        if summary:
            lines.append(f"  Total:            {summary.get('total', 0)}")
            lines.append(f"  Passing:          {summary.get('passed', 0)}")
            lines.append(f"  Failing:          {summary.get('failed', 0)}")
        lines.append("")
        lines.append(f"  [bold]Reports:[/]")
        for rpt in sc.get("reports", []):
            rstatus = "[green]PASS[/]" if rpt.get("passed") else "[red]FAIL[/]"
            metrics = rpt.get("metrics", {})
            lines.append(f"    {rpt.get('node_id', '?')}: {rstatus}")
            lines.append(f"      Reproducibility:    {metrics.get('reproducibility', '?')}")
            lines.append(f"      Correctness:        {metrics.get('exact_match_correctness', '?')}")
            lines.append(f"      Schema:             {metrics.get('schema_compliance', '?')}")
            lines.append(f"      Cost:               {metrics.get('cost_compliance', '?')}")
            lines.append(f"      Latency p95:        {metrics.get('latency_ms_p95', '?')}ms")
            lines.append(f"      Branch coverage:    {metrics.get('rule_branch_coverage', '?')}")
        if not sc.get("cache_exists"):
            lines.append("")
            lines.append(f"  [dim]No scorecard cache. Run 'nodechain dashboard scorecards --refresh' to evaluate.[/]")
    elif section == "recovery_metrics":
        outcomes = data.get("outcomes", {})
        sr = data.get("success_rate")
        sr_str = f"{sr:.1%}" if sr is not None else "n/a"
        lines.append(f"    Success rate:      {sr_str}")
        lines.append(f"    Completed:         {outcomes.get('completed', 0)}")
        lines.append(f"    Failed:            {outcomes.get('failed', 0)}")
        lines.append(f"    Unknown:           {outcomes.get('unknown', 0)}")
        rejections = data.get("rejections", {})
        if rejections:
            lines.append(f"    Policy denied:     {rejections.get('retry_policy_denied_total', 0)}")
            lines.append(f"    Rejected:          {rejections.get('retry_rejected_total', 0)}")
            lines.append(f"    No-operation:      {rejections.get('retry_no_operation_total', 0)}")
            lines.append(f"    Requeued:          {rejections.get('retry_requeued', 0)}")
            lines.append(f"    Mat. unavailable:  {rejections.get('retry_material_unavailable_total', 0)}")
            lines.append(f"    Legacy ineligible: {rejections.get('retry_legacy_ineligible_total', 0)}")
        latencies = data.get("latencies", {})
        if latencies:
            for lname, ldata in sorted(latencies.items()):
                p50 = ldata.get("p50")
                p95 = ldata.get("p95")
                if p50 is not None and p95 is not None:
                    lines.append(
                        f"    {lname}: p50={p50:.1f}ms p95={p95:.1f}ms "
                        f"(n={ldata.get('count', 0)})"
                    )
                else:
                    lines.append(f"    {lname}: n/a (n={ldata.get('count', 0)})")
        adapter_top = data.get("adapter_top20", [])
        if adapter_top:
            lines.append(f"    Top adapters (top 20):")
            for a in adapter_top:
                lines.append(f"      {a['adapter_id']}: {a['count']}")

    lines.append("")
    return "\n".join(lines)
