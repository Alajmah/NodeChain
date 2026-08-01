"""v3.5.0 T9: Recovery metrics emitter — observability projection.

Metrics are an observability projection, NEVER execution truth. The emitter
validates names/labels against frozen allowlists, canonicalizes label JSON,
and delegates to RecoveryMetricStore for idempotent persistence.

Production wiring (coordinator/service/reconciler) should use
``failure_isolated()`` so a metrics failure never changes retry semantics.
Direct emitter calls in tests may raise for invalid names/labels/conflicts.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from nodechain.core.stores import RecoveryMetricStore

_log = logging.getLogger(__name__)

# ── Frozen metric vocabulary ────────────────────────────────────────────
# Count metrics increment by 1 per event. Duration metrics carry ms values.
METRIC_KINDS: dict[str, str] = {
    # Lifecycle (coordinator)
    "retry_attempt_created": "count",
    "retry_claim_acquired": "count",
    "retry_claim_not_acquired": "count",
    "retry_no_operation_total": "count",
    "retry_dispatch_boundary_crossed_total": "count",
    "retry_outcome_completed": "count",
    "retry_outcome_failed": "count",
    "retry_unknown_total": "count",
    "retry_requeued": "count",
    "retry_command_latency_ms": "duration_ms",
    "retry_attempt_latency_ms": "duration_ms",
    # Validation rejections (coordinator early returns)
    "retry_material_unavailable_total": "count",
    "retry_legacy_ineligible_total": "count",
    # Governed refusal (RecoveryService, before coordinator)
    "retry_rejected_total": "count",
    "retry_policy_denied_total": "count",
}
# retry_success_rate is DERIVED (computed on read by the dashboard), never emitted.

ALLOWED_LABEL_KEYS = frozenset({"side_effect_type", "outcome", "adapter_id"})
_LABEL_MAX_LEN = 128
_METRIC_NAME_MAX_LEN = 128

# Finite value sets for specific labels (others free-form but bounded).
_OUTCOME_VALUES = frozenset({"completed", "failed", "unknown"})


class RecoveryMetricsEmitter:
    """Emits recovery metric events with validation + canonicalization.

    Construct with a RecoveryMetricStore (or db_path). Inject into
    RecoveryService, SideEffectRetryCoordinator, and TraceReconciler so all
    three producers share one store instance.
    """

    def __init__(self, store: RecoveryMetricStore) -> None:
        self._store = store

    def emit(
        self,
        *,
        metric_name: str,
        value: float = 1.0,
        run_id: str | None = None,
        retry_attempt_key: str | None = None,
        recovery_action_id: str | None = None,
        source_event_key: str,
        labels: dict[str, str] | None = None,
        emitted_at: str | None = None,
        conn: "Any | None" = None,
    ) -> bool:
        """Emit one metric event. Returns True if inserted, False if duplicate.

        Raises ValueError on invalid name/labels. Raises
        MetricSourceKeyConflict on payload mismatch. Raises MetricRunPurged
        if the run has a tombstone. Use failure_isolated() in production to
        suppress these.
        """
        kind = self._validate(metric_name, value, labels)
        labels_json = self._canonical_labels(labels)
        return self._store.insert(
            metric_event_id=f"rme-{uuid.uuid4().hex[:16]}",
            emitted_at=emitted_at or datetime.now(timezone.utc).isoformat(),
            metric_name=metric_name,
            metric_kind=kind,
            value=float(value),
            run_id=run_id,
            retry_attempt_key=retry_attempt_key,
            recovery_action_id=recovery_action_id,
            labels_json=labels_json,
            source_event_key=source_event_key,
            conn=conn,
        )

    def failure_isolated(self, **kwargs: Any) -> None:
        """Production emit: logs and discards observability failures.

        A metrics-table write failure after the dispatch boundary must NOT
        convert a completed retry into unknown or fail the operator action.
        """
        try:
            self.emit(**kwargs)
        except (ValueError,
                RecoveryMetricStore.MetricSourceKeyConflict,
                RecoveryMetricStore.MetricRunPurged) as e:
            _log.warning("recovery metric emission discarded: %s", e)
        except Exception as e:  # noqa: BLE001 — never let metrics fail execution
            _log.warning("recovery metric emission failed (suppressed): %s", e)

    # ── validation + canonicalization ───────────────────────────────────

    def _validate(
        self, metric_name: str, value: float,
        labels: dict[str, str] | None,
    ) -> str:
        import math
        if metric_name not in METRIC_KINDS:
            raise ValueError(
                f"unknown metric name {metric_name!r}; allowlist: "
                f"{sorted(METRIC_KINDS)}"
            )
        if len(metric_name) > _METRIC_NAME_MAX_LEN:
            raise ValueError("metric name too long")
        kind = METRIC_KINDS[metric_name]
        # Reject non-finite values (NaN, +inf, -inf) — they evade < 0 checks
        # and can break dashboard aggregation (int(NaN) raises).
        if not math.isfinite(value):
            raise ValueError(
                f"metric {metric_name!r} value must be finite, got {value}"
            )
        if kind == "count":
            if value < 0:
                raise ValueError(f"count metric {metric_name!r} value must be >= 0")
        elif kind == "duration_ms":
            if value < 0:
                raise ValueError(f"duration metric {metric_name!r} value must be >= 0")
        if labels:
            for k, v in labels.items():
                if k not in ALLOWED_LABEL_KEYS:
                    raise ValueError(
                        f"label key {k!r} not in allowlist {sorted(ALLOWED_LABEL_KEYS)}"
                    )
                if not isinstance(v, str):
                    raise ValueError(f"label {k!r} value must be str, got {type(v).__name__}")
                if len(v) > _LABEL_MAX_LEN:
                    raise ValueError(f"label {k!r} value too long")
                if k == "outcome" and v not in _OUTCOME_VALUES:
                    raise ValueError(
                        f"outcome label {v!r} not in {sorted(_OUTCOME_VALUES)}"
                    )
        return kind

    @staticmethod
    def _canonical_labels(labels: dict[str, str] | None) -> str:
        if not labels:
            return "{}"
        return json.dumps(labels, sort_keys=True, separators=(",", ":"))


def make_emitter(db_path: str) -> RecoveryMetricsEmitter:
    """Construct an emitter backed by a new store at db_path."""
    return RecoveryMetricsEmitter(RecoveryMetricStore(db_path))
