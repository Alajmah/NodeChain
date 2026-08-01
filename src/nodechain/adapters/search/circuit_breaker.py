"""Circuit breaker for search adapters (v2.57.0).

Per-adapter circuit breaker that trips after N consecutive retryable
failures and blocks further requests for a cooldown period. After
cooldown, allows a half-open probe; if it succeeds, the breaker resets.
"""

from __future__ import annotations

import time
from typing import Any

from nodechain.adapters.search.failure_types import (
    SearchFailureType,
    AdapterFailure,
    RETRYABLE_FAILURE_TYPES,
)


class CircuitBreaker:
    """Per-adapter circuit breaker.

    States:
    - CLOSED: requests pass through. Failures increment the counter.
    - OPEN: requests blocked. Returns CIRCUIT_OPEN failure immediately.
    - HALF_OPEN: one probe request allowed. Success → CLOSED, failure → OPEN.
    """

    def __init__(
        self,
        adapter_name: str,
        failure_threshold: int = 5,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.adapter_name = adapter_name
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._consecutive_failures: int = 0
        self._state: str = "closed"  # closed, open, half_open
        self._opened_at: float = 0.0

    @property
    def state(self) -> str:
        """Current breaker state, accounting for cooldown expiry."""
        if self._state == "open":
            if time.time() - self._opened_at >= self._cooldown_seconds:
                self._state = "half_open"
        return self._state

    @property
    def is_open(self) -> bool:
        """True if the breaker is blocking requests."""
        return self.state == "open"

    def allow_request(self) -> bool:
        """Check if a request should be allowed through."""
        state = self.state
        return state in ("closed", "half_open")

    def record_success(self) -> None:
        """Record a successful request — resets the breaker."""
        self._consecutive_failures = 0
        self._state = "closed"

    def record_failure(self, failure_type: SearchFailureType) -> None:
        """Record a failure. Only retryable types trip the breaker."""
        if failure_type not in RETRYABLE_FAILURE_TYPES:
            return  # Non-retryable failures don't trip the breaker

        self._consecutive_failures += 1

        if self._state == "half_open":
            # Probe failed — back to open
            self._trip()
        elif self._consecutive_failures >= self._failure_threshold:
            self._trip()

    def _trip(self) -> None:
        self._state = "open"
        self._opened_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        """Serialize breaker state for reporting."""
        return {
            "adapter": self.adapter_name,
            "state": self.state,
            "consecutive_failures": self._consecutive_failures,
            "failure_threshold": self._failure_threshold,
            "cooldown_seconds": self._cooldown_seconds,
        }
